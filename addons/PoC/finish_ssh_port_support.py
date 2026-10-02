"""Complete CLI propagation for configured remote SSH ports."""
import json,time
from repair_device_connection import HERE,atomic_write

root=HERE.parents[1]
path=root/'bridge/HostTools/pair.py'
text=path.read_text()
if '--remote-port' not in text:
 text=text.replace('        fields = shlex.split(line)\n','        try:\n            fields = shlex.split(line)\n        except ValueError:\n            continue\n')
 text=text.replace('    parser.add_argument("--port", default="2222")\n',
  '    parser.add_argument("--port", default="2222")\n    parser.add_argument("--remote-port", default=os.environ.get("CRYPSTORE_DEVICE_REMOTE_PORT", "22"))\n')
 text=text.replace('        repair_device_host_key=args.repair_device_host_key)',
  '        repair_device_host_key=args.repair_device_host_key,\n        remote_port=args.remote_port)')
 compile(text,str(path),'exec')
 backup=HERE/'connection-repair'/('pair-cli-before-'+str(time.time_ns())+'.py')
 atomic_write(backup,path.read_bytes());atomic_write(path,text.encode(),path.stat().st_mode & 0o777)
 print(json.dumps({'updated':str(path),'backup':str(backup)}))
