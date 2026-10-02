#!/usr/bin/env python3
"""Send bounded UI test events to an already enabled local SRD VNC server.

The VNC password is read and used only on the device. It never crosses SSH or
appears in command arguments, logs, or UAT artifacts.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import shlex

from repair_device_connection import profiles, usb_identity, worker_namespace


DEVICE_PROGRAM = r'''import ctypes,json,pathlib,plistlib,socket,struct,sys,time
request=json.loads(sys.argv[1])
config=plistlib.loads(pathlib.Path('/var/mobile/Library/Preferences/com.catvnc.server.plist').read_bytes())
if config.get('enabled') is not True:raise SystemExit('VNC is not enabled')
password=config.get('password')
if not isinstance(password,str) or not password:raise SystemExit('VNC credential is unavailable')
lib=ctypes.CDLL('/var/jb/usr/lib/libcrypto.3.dylib')
lib.DES_set_key_unchecked.argtypes=[ctypes.c_void_p,ctypes.c_void_p]
lib.DES_ecb_encrypt.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_int]
def read(sock,count):
 result=b''
 while len(result)<count:
  chunk=sock.recv(count-len(result))
  if not chunk:raise RuntimeError('VNC connection closed')
  result+=chunk
 return result
with socket.create_connection(('127.0.0.1',5900),3) as sock:
 sock.settimeout(5)
 if read(sock,12)!=b'RFB 003.008\n':raise RuntimeError('unsupported VNC protocol')
 sock.sendall(b'RFB 003.008\n')
 options=read(sock,read(sock,1)[0])
 if 2 not in options:raise RuntimeError('VNC authentication is unavailable')
 sock.sendall(b'\x02')
 challenge=read(sock,16)
 key=bytes(int(f'{value:08b}'[::-1],2) for value in password.encode('utf-8')[:8].ljust(8,b'\x00'))
 schedule=ctypes.create_string_buffer(128)
 lib.DES_set_key_unchecked(ctypes.create_string_buffer(key,8),schedule)
 response=bytearray()
 for start in (0,8):
  output=ctypes.create_string_buffer(8)
  lib.DES_ecb_encrypt(ctypes.create_string_buffer(challenge[start:start+8],8),output,schedule,1)
  response.extend(output.raw)
 sock.sendall(response)
 if struct.unpack('>I',read(sock,4))[0]!=0:raise RuntimeError('VNC authentication failed')
 sock.sendall(b'\x01')
 header=read(sock,24)
 width,height=struct.unpack('>HH',header[:4]);read(sock,struct.unpack('>I',header[20:24])[0])
 action=request['action']
 if action=='tap':
  x,y=request['x'],request['y']
  if not isinstance(x,int) or not isinstance(y,int) or not (0<=x<width and 0<=y<height):raise ValueError('tap outside display')
  sock.sendall(struct.pack('>BBHH',5,1,x,y));time.sleep(.08)
  sock.sendall(struct.pack('>BBHH',5,0,x,y))
 elif action=='drag':
  x,y,end_y=request['x'],request['y'],request['end_y']
  if (not all(isinstance(v,int) for v in (x,y,end_y)) or
      not (0<=x<width and 0<=y<height and 0<=end_y<height) or
      abs(end_y-y)>800):raise ValueError('drag outside bounded display range')
  sock.sendall(struct.pack('>BBHH',5,1,x,y))
  for step in range(1,9):
   time.sleep(.03)
   location=y+(end_y-y)*step//8
   sock.sendall(struct.pack('>BBHH',5,1,x,location))
  sock.sendall(struct.pack('>BBHH',5,0,x,end_y))
 elif action=='text':
  value=request['value']
  if not isinstance(value,str) or not value.isascii() or len(value)>80 or any(ord(c)<32 for c in value):raise ValueError('text input invalid')
  for char in value:
   keycode=ord(char)
   sock.sendall(struct.pack('>BBHI',4,1,0,keycode))
   sock.sendall(struct.pack('>BBHI',4,0,0,keycode))
   time.sleep(.08)
 elif action=='key':
  keycode=request['code']
  if keycode not in (0xff0d,0xff08):raise ValueError('key is not permitted')
  sock.sendall(struct.pack('>BBHI',4,1,0,keycode))
  sock.sendall(struct.pack('>BBHI',4,0,0,keycode))
 else:raise ValueError('unknown UI event')
 print(json.dumps({'result':'UI_EVENT_SENT','action':action,'display':[width,height]}))'''


def send(instance: str, udid: str, request: dict) -> dict:
    selected = profiles(instance_name=instance)
    if udid not in selected or asyncio.run(usb_identity(udid))["udid"] != udid:
        raise RuntimeError("EXACT_USB_PROFILE_MISMATCH")
    worker = worker_namespace(selected[udid][1])
    command = "/var/jb/usr/bin/python3 -c " + shlex.quote(DEVICE_PROGRAM) + " " + shlex.quote(json.dumps(request))
    result = worker["ssh"](command, timeout=15, check=False)
    if result.returncode:
        raise RuntimeError("VNC_UI_EVENT_FAILED: " + result.stderr.decode(errors="replace")[-400:])
    return json.loads(result.stdout)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("instance")
    parser.add_argument("udid")
    action = parser.add_subparsers(dest="action", required=True)
    tap = action.add_parser("tap")
    tap.add_argument("x", type=int)
    tap.add_argument("y", type=int)
    drag = action.add_parser("drag")
    drag.add_argument("x", type=int)
    drag.add_argument("y", type=int)
    drag.add_argument("end_y", type=int)
    typed = action.add_parser("text")
    typed.add_argument("value")
    key = action.add_parser("key")
    key.add_argument("code", type=lambda value: int(value, 0))
    args = parser.parse_args()
    payload = {"action": args.action}
    if args.action == "tap": payload.update(x=args.x, y=args.y)
    if args.action == "drag": payload.update(x=args.x, y=args.y, end_y=args.end_y)
    if args.action == "text": payload["value"] = args.value
    if args.action == "key": payload["code"] = args.code
    print(json.dumps(send(args.instance, args.udid, payload), sort_keys=True))
