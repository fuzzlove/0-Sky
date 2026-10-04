"""Install the verified SRD launch helper in an isolated research runtime."""
import argparse,asyncio,hashlib,json,plistlib,shutil,subprocess,uuid
from pathlib import Path
from repair_device_connection import HERE,usb_identity,atomic_write
from recover_device_ssh import install
from make_cryptex import inspect_bundle
from device_python import ensure_device_python

def install_for(udid):
 asyncio.run(usb_identity(udid))
 ref=hashlib.sha256(udid.encode()).hexdigest()[:16]
 output=HERE/'connection-repair'/ref/('launch-helper-'+uuid.uuid4().hex)
 # The device-specific evidence directory is not guaranteed to exist on a
 # newly enrolled Mac profile.  Create the confined parent chain before the
 # per-run directory; the random leaf still prevents accidental reuse.
 output.mkdir(parents=True,mode=0o700)
 source=HERE/'localfence-repair-v2/payload/launchctl-srd'
 expected=json.loads((HERE/'localfence-repair-v2/payload-sha256.json').read_text())['launchctl-srd']
 if hashlib.sha256(source.read_bytes()).hexdigest()!=expected:raise RuntimeError('Helper hash mismatch')
 root=output/'root';(root/'usr/bin').mkdir(parents=True)
 shutil.copy2(source,root/'usr/bin/launchctl-srd')
 subprocess.run(['/usr/bin/codesign','--verify','--strict',str(root/'usr/bin/launchctl-srd')],check=True,capture_output=True)
 image=output/'source.dmg'
 subprocess.run(['hdiutil','create','-size','64m','-fs','APFS','-layout','NONE','-srcfolder',str(root),'-format','UDRW',str(image)],check=True,capture_output=True,timeout=120)
 target=output/'cryptex';target.mkdir()
 identifier='com.liquidsky.launch-helper.recovery-'+ref
 subprocess.run(['/System/Library/SecurityResearch/usr/bin/cryptexctl','create','--use-cryptex1-format','--identifier',identifier,'--version','1.0','--variant','research','--output-directory',str(target),str(image)],check=True,capture_output=True,timeout=180)
 assets=inspect_bundle(next(target.glob('*.cxbd')),'research')
 asyncio.run(install(udid,identifier,assets))
 record={'udid':udid,'identifier':identifier,'assets':assets,'sha256':expected,'installed':True}
 atomic_write(output/'helper.json',json.dumps(record,indent=2).encode())
 return record

def main():
 ensure_device_python()
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--udid',required=True);a=p.parse_args()
 print(json.dumps(install_for(a.udid),indent=2))

if __name__=='__main__':main()
