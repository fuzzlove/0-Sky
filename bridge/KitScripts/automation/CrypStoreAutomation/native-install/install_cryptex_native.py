"""Build SDK-prepared APFS assets and install one exact SRD Cryptex."""
import argparse,asyncio,copy,hashlib,json,os,pathlib,plistlib,shutil,subprocess,sys,uuid

CTL='/System/Library/SecurityResearch/usr/bin/cryptexctl'

def run(argv,timeout=180):
    print('+',pathlib.Path(str(argv[0])).name,' '.join(str(a) for a in argv[1:3]),flush=True)
    subprocess.run([str(a) for a in argv],check=True,timeout=timeout)

def assets_from_manifest(path):
    path=pathlib.Path(path).resolve();manifest=plistlib.loads(path.read_bytes())
    identities=[v for v in manifest['BuildIdentities'] if v.get('Info',{}).get('Variant')=='research']
    if len(identities)!=1:raise ValueError('Expected one research identity')
    assets={}
    for key in ('Cryptex1,CryptexInfoPlist','Cryptex1,GenericDmg','Cryptex1,GenericTrustCache','Cryptex1,GenericVolume'):
        entry=identities[0]['Manifest'][key];source=(path.parent/entry['Info']['Path']).resolve()
        if not source.is_relative_to(path.parent) or not source.is_file():raise ValueError('Unsafe or missing Cryptex asset')
        h=hashlib.sha384()
        with source.open('rb') as f:
            for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
        if h.digest()!=entry['Digest']:raise ValueError('Cryptex asset digest mismatch: '+key)
        assets[key]=source
    return identities[0],assets

def der(tag,data):
    n=len(data);length=bytes([n]) if n<128 else bytes([0x80+(n.bit_length()+7)//8])+n.to_bytes((n.bit_length()+7)//8,'big')
    return bytes([tag])+length+data

def trust_payload(data):
    def length(offset):
        first=data[offset];offset+=1
        if first<128:return first,offset
        count=first&127;return int.from_bytes(data[offset:offset+count],'big'),offset+count
    if data[0]!=0x30:raise ValueError('Trust cache is not DER')
    size,offset=length(1);end=offset+size;found=None
    while offset<end:
        tag=data[offset];size,offset=length(offset+1);value=data[offset:offset+size];offset+=size
        if tag==4:found=value
    if found is None or offset!=end:raise ValueError('Invalid trust-cache envelope')
    return found

def image_type_index_for(product_version):
    """Select the measured GenericDmg slot for the connected SRD OS family."""
    try:
        parts=str(product_version).split('.')
        major=int(parts[0]);minor=int(parts[1]) if len(parts)>1 else 0
    except (TypeError,ValueError,IndexError) as error:
        raise RuntimeError('Device did not report a usable OS version for Cryptex installation') from error
    if major==26:return 9 if minor<=3 else 10
    if major==27:return 10
    raise RuntimeError('Unsupported SRD OS for Cryptex installation: '+str(product_version)+'; verified families are iOS 26 and iOS 27')

def build(root,identifier,version,work):
    root=pathlib.Path(root).resolve();work=pathlib.Path(work).resolve()
    if not root.is_dir():raise ValueError('Missing payload root')
    output=work/('sdk-cryptex-'+uuid.uuid4().hex);output.mkdir()
    size=sum(p.stat().st_size for p in root.rglob('*') if p.is_file() and not p.is_symlink())
    mib=max(64,((size//(1024*1024)+64+63)//64)*64)
    image=output/'source.dmg'
    run(['hdiutil','create','-size',str(mib)+'m','-fs','APFS','-layout','NONE','-srcfolder',root,'-format','UDRW',image],timeout=180)
    bundles=output/'bundles';bundles.mkdir()
    run([CTL,'create','--use-cryptex1-format','--identifier',identifier,'--version',version,'--variant','research','--output-directory',bundles,image],timeout=240)
    bundle=next(bundles.glob('*.cxbd'));manifest=bundle/'Restore/BuildManifest.plist'
    identity,assets=assets_from_manifest(manifest)
    generator=work/'generate_trust_cache.py'
    if generator.is_file():
        trust=output/'trust.der'
        command=[sys.executable,generator]
        if os.environ.get('SRDSH_TRUST_CACHE_MODE')=='apple-signed':command.append('--empty')
        run(command+[root,trust],timeout=120)
        raw=trust_payload(trust.read_bytes())
        wrapped=der(0x30,der(0x16,b'IM4P')+der(0x16,b'gtcd')+der(0x16,b'1')+der(4,raw))
        assets['Cryptex1,GenericTrustCache'].write_bytes(wrapped)
        value=plistlib.loads(manifest.read_bytes())
        for item in value['BuildIdentities']:
            if item.get('Info',{}).get('Variant')=='research':item['Manifest']['Cryptex1,GenericTrustCache']['Digest']=hashlib.sha384(wrapped).digest()
        manifest.write_bytes(plistlib.dumps(value))
        assets_from_manifest(manifest)
    # Preserve familiar filenames for diagnostics and bounded worker cleanup.
    record={'identifier':identifier,'version':version,'build_manifest':str(manifest),'assets':{k:str(v) for k,v in assets.items()}}
    (work/'sdk-assets.json').write_text(json.dumps(record,indent=2)+'\n')
    return manifest

async def install_with_rsd(rsd, identity, data, identifier, udid):
    from pymobiledevice3.remote.xpc_message import XpcUInt64Type
    from pymobiledevice3.restore.tss import TSSRequest
    from pymobiledevice3.services.cryptexd import CryptexdService
    identity=copy.deepcopy(identity)
    identity.update({'Cryptex1,UseProductClass':True,'Cryptex1,ChipID':'0xff10','Cryptex1,ProductClass':'0xf2','Cryptex1,Type':3,'Cryptex1,SubType':255,'Cryptex1,NonceDomain':3,'Cryptex1,Version':'999.999.999.999.999,999','Cryptex1,PreauthorizationVersion':'999.999.999.999.999,999'})
    for k,v in data.items():
        identity['Manifest'][k]['Digest']=hashlib.sha384(v).digest();identity['Manifest'][k].setdefault('Info',{})['Personalize']=True
    if str(rsd.udid)!=udid:raise RuntimeError('Exact-device identity mismatch')
    image_type_index=image_type_index_for(getattr(rsd,'product_version',None))
    print('Selected GenericDmg image index',image_type_index,'for iOS',rsd.product_version,flush=True)
    service=CryptexdService(rsd)
    identifiers=await service.read_personalization_identifiers();nonce=await service.cryptex_nonce(3)
    if not nonce:raise RuntimeError('Research nonce unavailable')
    request=TSSRequest();request.add_cryptex1_tags(identity,identifiers,nonce)
    response=await asyncio.wait_for(request.send_receive(),timeout=90)
    ticket=response.get('Cryptex1,Ticket')
    if not isinstance(ticket,bytes) or not ticket:raise RuntimeError('Apple did not authorize the Cryptex')
    print('Live Apple research authorization accepted for',udid,identifier,flush=True)
    existing=await asyncio.wait_for(service.copy_installed(),timeout=30)
    matches=[item for item in existing if item.identifier==identifier]
    if len(matches)>1:raise RuntimeError('Multiple generations claim this identifier')
    if matches:await asyncio.wait_for(service.uninstall(identifier),timeout=30)
    properties={'Cryptex1,UseProductClass':True,'MountedCryptex':False,'Cryptex1,SubType':XpcUInt64Type(255),'Cryptex1,NonceDomain':XpcUInt64Type(3),'Cryptex1,Version':identity['Cryptex1,Version'],'Cryptex1,PreauthVersion':identity['Cryptex1,PreauthorizationVersion']}
    await asyncio.wait_for(service.install(data['Cryptex1,GenericDmg'],data['Cryptex1,GenericTrustCache'],ticket,data['Cryptex1,CryptexInfoPlist'],data['Cryptex1,GenericVolume'],properties,image_type_index=image_type_index,persistence=2,nonce_persistence=1,auth=0),timeout=900)

async def install(manifest,identifier,udid):
    enable_flow_control_accounting()
    from pymobiledevice3.exceptions import ProtocolError, StreamClosedError
    from pymobiledevice3.remote.native_tunnel import NativeRemotedTunnel
    from pymobiledevice3.remote.userspace_tunnel import UserspaceRsdTunnel
    from pymobiledevice3.services.cryptexd import CryptexdService
    identity,paths=assets_from_manifest(manifest)
    data={k:p.read_bytes() for k,p in paths.items()}
    info=plistlib.loads(data['Cryptex1,CryptexInfoPlist'])
    if info.get('CFBundleIdentifier')!=identifier:raise ValueError('Cryptex identifier mismatch')
    # A paired userspace USB channel is already proven by the setup preflight.
    # Prefer it for the actual transfer on every host: Intel native remoted can
    # block inside ctypes/libffi callback allocation before asyncio can enforce
    # a timeout. This path never silently pairs and remains bound to the exact
    # selected UDID. Native remains an explicit recovery backend only.
    transport = os.environ.get("ZERO_SKY_CRYPTEX_TRANSPORT", "userspace")
    if transport not in {"userspace", "native"}:
        raise RuntimeError("ZERO_SKY_CRYPTEX_TRANSPORT must be userspace or native")
    if transport == "userspace":
        print("Cryptex transport: existing paired userspace USB", flush=True)
        try:
            async with UserspaceRsdTunnel(serial=udid, autopair=False) as rsd:
                await install_with_rsd(rsd,identity,data,identifier,udid)
        except ProtocolError as error:
            if "Timed out waiting for flow-control credit" not in str(error):
                raise
            # A newly opened paired USB RemoteXPC connection has repeatedly
            # resumed large Intel transfers that stopped receiving window
            # credit on their first connection. Retry this one diagnosed,
            # pre-commit transport failure once; do not loop or change trust.
            print("Userspace flow-control credit stalled; retrying once on a fresh exact-device paired USB connection",flush=True)
            await asyncio.sleep(3)
            async with UserspaceRsdTunnel(serial=udid, autopair=False) as rsd:
                if str(rsd.udid)!=udid:raise RuntimeError('Exact-device identity mismatch')
                existing=await asyncio.wait_for(CryptexdService(rsd).copy_installed(),timeout=30)
                matches=[item for item in existing if item.identifier==identifier]
                if len(matches)>1:raise RuntimeError('Multiple generations claim this identifier')
                if matches:
                    print('INSTALL COMMITTED before userspace credit timeout',identifier,flush=True)
                else:
                    await install_with_rsd(rsd,identity,data,identifier,udid)
        print('INSTALL SUCCESS',identifier,flush=True)
        return
    print("Cryptex transport: explicit macOS native remoted", flush=True)
    try:
        async with NativeRemotedTunnel(serial=udid) as rsd:
            await install_with_rsd(rsd,identity,data,identifier,udid)
    except StreamClosedError as error:
        # iOS can reset a large native RemoteXPC transfer after accepting all
        # bytes. Re-enter through the independent, paired userspace transport,
        # first checking whether the exact identifier committed. This is a
        # bounded one-time backend change, never a repeat of the failed method.
        print('Native RemoteXPC transfer reset; verifying through paired userspace transport',flush=True)
        async with UserspaceRsdTunnel(serial=udid,autopair=False) as rsd:
            if str(rsd.udid)!=udid:raise RuntimeError('Exact-device identity mismatch')
            existing=await asyncio.wait_for(CryptexdService(rsd).copy_installed(),timeout=30)
            matches=[item for item in existing if item.identifier==identifier]
            if len(matches)>1:raise RuntimeError('Multiple generations claim this identifier')
            if matches:
                print('INSTALL COMMITTED before native reset',identifier,flush=True)
            else:
                print('Retrying once with paired userspace transport',flush=True)
                await install_with_rsd(rsd,identity,data,identifier,udid)
    print('INSTALL SUCCESS',identifier,flush=True)

def main():
    if sys.argv[1:]==['--build-and-install']:
        udid=os.environ['CRYPTEXCTL_UDID'];identifier=os.environ['SRDSH_IDENTIFIER'];version=os.environ.get('SRDSH_VERSION','1.0.0')
        manifest=build(os.environ['SRDSH_ROOT'],identifier,version,pathlib.Path(__file__).parent)
        if os.environ.get('SRDSH_BUILD_ONLY')=='1':return
    else:
        if len(sys.argv)!=8:raise SystemExit('Expected --build-and-install or seven legacy asset arguments')
        identifier,_,_,_,version,udid,manifest=sys.argv[1:]
    asyncio.run(install(manifest,identifier,udid))


# Process-local flow-control correction for pinned pymobiledevice3.
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

if __name__=='__main__':main()
