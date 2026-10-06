#!/usr/bin/env python3
"""Minimal, dependency-free usbmuxd device listing and exact-device forwarding."""
from __future__ import annotations
import argparse, os, plistlib, select, selectors, socket, struct, sys, threading

SOCKET = "/var/run/usbmuxd"
HEADER = struct.Struct("<IIII")
MESSAGE_PLIST = 8
_tag = 0


def mux_request(sock: socket.socket, message: dict) -> dict:
    global _tag
    _tag += 1
    body = plistlib.dumps({"BundleID": "com.liquidsky.0sky.bridge", "ClientVersionString": "0-Sky Bridge",
                           "ProgName": "0-Sky Bridge", "kLibUSBMuxVersion": 3, **message},
                          fmt=plistlib.FMT_XML)
    sock.sendall(HEADER.pack(HEADER.size + len(body), 1, MESSAGE_PLIST, _tag) + body)
    header = recv_exact(sock, HEADER.size)
    length, _version, kind, tag = HEADER.unpack(header)
    if length < HEADER.size or length > 16 * 1024 * 1024 or kind != MESSAGE_PLIST or tag != _tag:
        raise RuntimeError("invalid usbmuxd response")
    value = plistlib.loads(recv_exact(sock, length - HEADER.size))
    if not isinstance(value, dict): raise RuntimeError("invalid usbmuxd payload")
    return value


def recv_exact(sock: socket.socket, length: int) -> bytes:
    data = bytearray()
    while len(data) < length:
        block = sock.recv(length - len(data))
        if not block: raise RuntimeError("usbmuxd closed the connection")
        data.extend(block)
    return bytes(data)


def connect_mux() -> socket.socket:
    value = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    value.settimeout(10)
    value.connect(SOCKET)
    return value


def devices() -> list[dict]:
    with connect_mux() as mux:
        value = mux_request(mux, {"MessageType": "ListDevices"})
    answer = value.get("DeviceList", [])
    return answer if isinstance(answer, list) else []


def properties(item: dict) -> dict:
    value = item.get("Properties", {})
    return value if isinstance(value, dict) else {}


def select_device(udid: str) -> tuple[int, dict]:
    matches = [(int(item["DeviceID"]), properties(item)) for item in devices()
               if properties(item).get("SerialNumber") == udid]
    if len(matches) != 1: raise RuntimeError("exact selected device is not uniquely connected")
    return matches[0]


def connect_device(udid: str, port: int) -> socket.socket:
    device_id, _ = select_device(udid)
    mux = connect_mux()
    answer = mux_request(mux, {"MessageType": "Connect", "DeviceID": device_id,
                               "PortNumber": socket.htons(port)})
    if answer.get("Number") != 0:
        mux.close(); raise RuntimeError("usbmuxd rejected the selected device connection")
    mux.settimeout(None)
    return mux


def relay(left: socket.socket, right: socket.socket) -> None:
    def send_all(destination: socket.socket, data: bytes) -> None:
        pending = memoryview(data)
        while pending:
            try:
                written = destination.send(pending)
                if written <= 0:
                    raise RuntimeError("forwarding socket stopped accepting data")
                pending = pending[written:]
            except BlockingIOError:
                _, writable, _ = select.select([], [destination], [], 60)
                if not writable:
                    raise TimeoutError("forwarding socket write timed out")

    selector = selectors.DefaultSelector()
    try:
        for item in (left, right): item.setblocking(False); selector.register(item, selectors.EVENT_READ)
        while True:
            events = selector.select(timeout=60)
            if not events: continue
            for key, _ in events:
                source = key.fileobj; destination = right if source is left else left
                data = source.recv(65536)
                if not data: return
                send_all(destination, data)
    finally:
        selector.close(); left.close(); right.close()


def iproxy(argv: list[str]) -> int:
    if argv == ["--version"]:
        print("0-Sky usbmux compatibility 1.0")
        return 0
    parser = argparse.ArgumentParser(prog="iproxy")
    parser.add_argument("-s", "--source", default="127.0.0.1")
    parser.add_argument("-u", "--udid", required=True)
    parser.add_argument("mapping")
    args = parser.parse_args(argv)
    local, remote = (int(value) for value in args.mapping.split(":", 1))
    if not (0 < local < 65536 and 0 < remote < 65536): parser.error("invalid port")
    listener = socket.create_server((args.source, local), family=socket.AF_INET, backlog=16,
                                    reuse_port=False)
    while True:
        client, _ = listener.accept()
        try: target = connect_device(args.udid, remote)
        except Exception as error:
            client.close(); print(f"iproxy: {error}", file=sys.stderr); continue
        threading.Thread(target=relay, args=(client, target), daemon=True).start()


def idevice_id(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="idevice_id")
    parser.add_argument("-l", "--list", action="store_true")
    parser.add_argument("-n", "--network", action="store_true")
    parser.add_argument("-v", "--version", action="store_true")
    args = parser.parse_args(argv)
    if args.version: print("0-Sky usbmux compatibility 1.0"); return 0
    for item in devices():
        props = properties(item)
        connection = str(props.get("ConnectionType", "USB")).lower()
        if args.network and connection != "network": continue
        serial = props.get("SerialNumber")
        if isinstance(serial, str): print(serial)
    return 0


def main() -> int:
    name = os.path.basename(sys.argv[0])
    try:
        return iproxy(sys.argv[1:]) if name == "iproxy" else idevice_id(sys.argv[1:])
    except (OSError, RuntimeError, ValueError) as error:
        print(f"{name}: {error}", file=sys.stderr); return 2

if __name__ == "__main__": raise SystemExit(main())
