"""Exercise outbound window accounting with a strict in-memory HTTP/2 peer."""

import asyncio
import unittest
from collections import defaultdict
from unittest.mock import patch

from hyperframe.frame import DataFrame, Frame, GoAwayFrame, SettingsFrame, WindowUpdateFrame
from pymobiledevice3.exceptions import StreamClosedError
from pymobiledevice3.remote.remotexpc import RemoteXPCConnection
from pymobiledevice3.remote.xpc_message import XpcFlags, XpcWrapper

from remotexpc_flow_control import enable_flow_control_accounting, verify_flow_control_accounting


class StrictPeer:
    def __init__(self, window=65535):
        self.window = window
        self.connection_credit = window
        self.stream_credit = defaultdict(lambda: window)
        self.incoming = asyncio.Queue()
        self.sent = []

    def write(self, data):
        frame, size = Frame.parse_frame_header(memoryview(data[:9]))
        frame.parse_body(memoryview(data[9:9 + size]))
        self.sent.append(frame)
        if not isinstance(frame, DataFrame) or not frame.data:
            return
        size = len(frame.data)
        if size > min(self.connection_credit, self.stream_credit[frame.stream_id]):
            raise AssertionError("Sender exceeded peer's flow-control window")
        self.connection_credit -= size
        self.stream_credit[frame.stream_id] -= size
        if self.connection_credit == 0:
            self.connection_credit += self.window
            self.incoming.put_nowait(WindowUpdateFrame(stream_id=0, window_increment=self.window))
        if self.stream_credit[frame.stream_id] == 0:
            self.stream_credit[frame.stream_id] += self.window
            self.incoming.put_nowait(WindowUpdateFrame(stream_id=frame.stream_id,
                                                       window_increment=self.window))

    async def drain(self):
        pass


class FlowControlTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        enable_flow_control_accounting()

    def connection(self, window=65535):
        connection = RemoteXPCConnection(("unused", 0))
        peer = StrictPeer(window)
        connection._writer = peer
        connection._receive_frame = peer.incoming.get
        connection._outbound_connection_window = window
        connection._peer_initial_window_size = window
        return connection, peer

    async def test_large_transfer_after_requests(self):
        connection, peer = self.connection()
        await connection._send_frame(DataFrame(stream_id=1, data=b"handshake"))
        await connection._send_frame(DataFrame(stream_id=3, data=b"reply-channel handshake"))
        await connection.send_request({"request": "install"}, wanting_reply=True)
        peer.incoming.put_nowait(DataFrame(stream_id=3, data=b"early reply"))
        payload = b"x" * (4 * 65535 + 113)
        await asyncio.wait_for(connection.send_file_transfer(1, payload), 2)
        actual = b"".join(frame.data for frame in peer.sent
                          if isinstance(frame, DataFrame) and frame.stream_id == 5)
        preamble = XpcWrapper.build({
            "flags": XpcFlags.FILE_TX_STREAM_REQUEST | XpcFlags.ALWAYS_SET,
            "message": {"message_id": 1, "payload": None},
        })
        self.assertEqual(actual, preamble + payload)
        self.assertEqual(connection._buffered_data_frames[0].data, b"early reply")
        self.assertIn("END_STREAM", peer.sent[-1].flags)

    async def test_preamble_spans_remaining_window(self):
        connection, peer = self.connection(64)
        await connection._send_frame(DataFrame(stream_id=1, data=b"x" * 63))
        await asyncio.wait_for(connection.send_file_transfer(1, b"payload"), 2)
        actual = b"".join(frame.data for frame in peer.sent
                          if isinstance(frame, DataFrame) and frame.stream_id == 5)
        preamble = XpcWrapper.build({
            "flags": XpcFlags.FILE_TX_STREAM_REQUEST | XpcFlags.ALWAYS_SET,
            "message": {"message_id": 1, "payload": None},
        })
        self.assertEqual(actual, preamble + b"payload")

    async def test_settings_update_and_reply_are_preserved(self):
        connection, peer = self.connection()
        await connection._send_frame(DataFrame(stream_id=1, data=b"x" * 100))
        peer.incoming.put_nowait(SettingsFrame(settings={SettingsFrame.INITIAL_WINDOW_SIZE: 32768}))
        await connection._pump_one_frame()
        self.assertEqual(connection._outbound_stream_windows[1], 32768 - 100)
        self.assertEqual(connection._outbound_connection_window, 65535 - 100)
        self.assertIsInstance(peer.sent[-1], SettingsFrame)
        self.assertIn("ACK", peer.sent[-1].flags)

    async def test_goaway_still_fails(self):
        connection, peer = self.connection()
        peer.incoming.put_nowait(GoAwayFrame(stream_id=0, error_code=3))
        with self.assertRaises(StreamClosedError):
            await connection._pump_one_frame()

    def test_active_implementations_are_verified(self):
        self.assertTrue(verify_flow_control_accounting().endswith("remotexpc_flow_control.py"))
        async def replacement(*args):
            pass
        with patch.object(RemoteXPCConnection, "send_request", replacement):
            with self.assertRaisesRegex(RuntimeError, "inactive for send_request"):
                enable_flow_control_accounting()


if __name__ == "__main__":
    unittest.main()
