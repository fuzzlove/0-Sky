"""Trace TrollRecorder launch and filesystem checks using a temporary Frida attach."""
import argparse
import json
import pathlib
import time

import frida


JAVASCRIPT = r'''
const matches = p => /launchctl|trservices|thebootstrapped|TRCallMonitor|TRApp2|\.plist|\/var\/jb/.test(p);
function cstr(p) { try { return p.readUtf8String() || ''; } catch (e) { return ''; } }
for (const name of ['posix_spawn', 'posix_spawnp', 'execve', 'access', 'stat', 'lstat', 'open', 'openat']) {
  const address = Module.findGlobalExportByName(name);
  if (address === null) continue;
  Interceptor.attach(address, {
    onEnter(args) {
      this.path = cstr(args[name === 'openat' ? 1 : name.startsWith('posix_spawn') ? 1 : 0]);
      this.match = matches(this.path);
      if (this.match) send({kind:name,path:this.path,phase:'enter'});
    },
    onLeave(result) {
      if (this.match) send({kind:name,path:this.path,phase:'return',result:result.toInt32()});
    }
  });
}
send({kind:'trace-ready',pid:Process.id});
'''


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--udid', required=True)
    parser.add_argument('--seconds', type=int, default=25)
    args = parser.parse_args()
    device = frida.get_device(args.udid, timeout=10)
    events = []
    pid = device.spawn(['wiki.qaq.trapp'])
    session = device.attach(pid)
    script = session.create_script(JAVASCRIPT)

    def on_message(message, data):
        event = message.get('payload', message)
        events.append({'time':time.time(),'event':event})
        if isinstance(event, dict) and event.get('kind') in ('posix_spawn','posix_spawnp','execve'):
            print(json.dumps(event), flush=True)

    script.on('message', on_message)
    script.load()
    device.resume(pid)
    print('pid', pid, flush=True)
    try:
        time.sleep(args.seconds)
    finally:
        session.detach()
        output = pathlib.Path(__file__).parent / 'installer-verification/trollrecorder-spawn-trace.json'
        output.write_text(json.dumps({'udid':args.udid,'pid':pid,'events':events},indent=2))
        print(json.dumps({'pid':pid,'events':len(events),'output':str(output)}), flush=True)
