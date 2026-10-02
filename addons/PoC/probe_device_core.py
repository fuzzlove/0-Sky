#!/usr/bin/env python3
"""Read a selected device's public local-bridge health over exact USB."""
import argparse
import asyncio
import http.client
import json
from pathlib import Path
import time

from device_python import ensure_device_python
from repair_device_connection import usb_identity, atomic_write


def request(sock,path="/health",method="GET",body=None):
    sock.settimeout(10)
    connection=http.client.HTTPConnection("device-local-bridge",timeout=10)
    connection.sock=sock
    try:
        connection.request(method,path,body=body,headers={"Connection":"close","Content-Type":"application/json"})
        response=connection.getresponse()
        body=response.read(65537)
        if len(body)>65536: raise RuntimeError("Bridge health response exceeds limit")
        return response.status,json.loads(body)
    finally:
        connection.close()


async def probe(udid):
    from pymobiledevice3.usbmux import select_device
    report={"device":await usb_identity(udid),"port":48654}
    device=await select_device(udid=udid,connection_type="USB")
    if device is None or device.serial!=udid:
        raise RuntimeError("USB device identity mismatch")
    try:
        sock=await asyncio.wait_for(device.connect(48654),timeout=10)
        status,body=await asyncio.to_thread(request,sock)
        report.update(http_status=status,health=body)
        # This sends no bridge token and cannot authorize an operation. A 403
        # confirms the Core route exists; a 404 identifies an older bridge.
        sock=await asyncio.wait_for(device.connect(48654),timeout=10)
        payload=json.dumps({"protocolVersion":1,"requestId":"core-route-probe",
            "timestamp":time.time(),"operation":"getStatus","parameters":{}})
        code,envelope=await asyncio.to_thread(request,sock,"/v1/core","POST",payload)
        report["core_route"]={"http_status":code,"success":envelope.get("success"),
            "errorCode":envelope.get("errorCode"),"message":envelope.get("stderr",envelope.get("errorMessage"))}
    except Exception as error:
        report.update(reachable=False,error=str(error))
    else:
        report["reachable"]=True
    return report


if __name__=="__main__":
    ensure_device_python()
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--udid",required=True)
    parser.add_argument("--output",type=Path)
    args=parser.parse_args()
    result=asyncio.run(probe(args.udid))
    if args.output:
        atomic_write(args.output,(json.dumps(result,indent=2)+"\n").encode())
    print(json.dumps(result,indent=2))
