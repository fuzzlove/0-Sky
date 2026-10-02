"""Account for every outbound HTTP/2 DATA byte in the pinned device runtime."""


def verify_flow_control_accounting() -> str:
    """Verify the active implementations, returning their source file."""
    import pathlib

    from pymobiledevice3.remote.remotexpc import RemoteXPCConnection

    expected = pathlib.Path(__file__).resolve()
    for name in ("_send_flow_controlled", "_send_frame", "send_request", "_pump_one_frame"):
        method = getattr(RemoteXPCConnection, name)
        code = getattr(method, "__code__", None)
        if code is None or pathlib.Path(code.co_filename).resolve() != expected:
            raise RuntimeError(f"RemoteXPC correction is inactive for {name}")
    return str(expected)


def enable_flow_control_accounting() -> None:
    """Apply a process-local correction; leave the installed dependency untouched."""
    import asyncio

    from hyperframe.frame import DataFrame, SettingsFrame
    from pymobiledevice3.exceptions import ProtocolError
    from pymobiledevice3.remote import remotexpc
    from pymobiledevice3.remote.xpc_message import create_xpc_wrapper

    connection = remotexpc.RemoteXPCConnection
    if getattr(connection, "_poc_accounts_all_data", False):
        verify_flow_control_accounting()
        return
    required = ("_send_flow_controlled", "_outbound_budget", "_consume_outbound",
                "_pump_one_frame")
    if not all(hasattr(connection, name) for name in required):
        raise RuntimeError("Device runtime lacks the expected RemoteXPC flow-control API")
    raw_send_frame = connection._send_frame
    original_pump = connection._pump_one_frame

    async def pump_one_frame(self):
        frame = await original_pump(self)
        if isinstance(frame, DataFrame):
            # A reply read while waiting for credit must reach receive_response.
            self._buffered_data_frames.append(frame)
        elif isinstance(frame, SettingsFrame) and "ACK" not in frame.flags:
            await raw_send_frame(self, SettingsFrame(flags=["ACK"]))
        return frame

    async def send_flow_controlled(self, stream_id, data, offset, total):
        # Track the stream even before any DATA is sent so later SETTINGS deltas
        # apply to its actual window, including a partially consumed root stream.
        self._outbound_stream_windows.setdefault(stream_id, self._peer_initial_window_size)
        start = offset
        # The file-transfer caller submits its preamble only once. Complete it
        # even when the remaining window is smaller than that preamble.
        while offset < len(data):
            budget = self._outbound_budget(stream_id)
            while budget == 0:
                try:
                    await asyncio.wait_for(self._pump_one_frame(),
                                           remotexpc.FILE_TRANSFER_WINDOW_TIMEOUT)
                except asyncio.TimeoutError as error:
                    raise ProtocolError(
                        f"Timed out waiting for flow-control credit on stream {stream_id} "
                        f"after {offset}/{total} bytes"
                    ) from error
                budget = self._outbound_budget(stream_id)
            chunk = data[offset:offset + budget]
            await raw_send_frame(self, DataFrame(stream_id=stream_id, data=chunk))
            self._consume_outbound(stream_id, len(chunk))
            offset += len(chunk)
        return offset - start

    async def send_frame(self, frame):
        if not isinstance(frame, DataFrame) or not frame.data:
            await raw_send_frame(self, frame)
            return
        if "PADDED" in frame.flags:
            raise ProtocolError("The local RemoteXPC correction does not support padded DATA")
        offset = 0
        while offset < len(frame.data):
            offset += await self._send_flow_controlled(
                frame.stream_id, frame.data, offset, len(frame.data)
            )
        if "END_STREAM" in frame.flags:
            await raw_send_frame(self, DataFrame(stream_id=frame.stream_id,
                                                data=b"", flags=["END_STREAM"]))

    async def send_request(self, data, wanting_reply=False):
        wrapper = create_xpc_wrapper(
            data, message_id=self.next_message_id[remotexpc.ROOT_CHANNEL],
            wanting_reply=wanting_reply,
        )
        await self._send_frame(DataFrame(stream_id=remotexpc.ROOT_CHANNEL, data=wrapper))
        self.next_message_id[remotexpc.ROOT_CHANNEL] += 1

    connection._send_flow_controlled = send_flow_controlled
    connection._send_frame = send_frame
    connection.send_request = send_request
    connection._pump_one_frame = pump_one_frame
    connection._poc_accounts_all_data = True
    verify_flow_control_accounting()
