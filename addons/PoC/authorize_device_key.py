"""Authorize a public key using password-only root access and a hidden Mac dialog."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import uuid


PROGRAM = r'''import hashlib,json,os,sys
value=json.load(sys.stdin);key=value["public_key"].strip();state=value["state"]
directory="/var/root/.ssh";path=directory+"/authorized_keys"
if os.geteuid()!=0: raise SystemExit("root required")
if os.path.islink(directory) or os.path.islink(path): raise SystemExit("unsafe authorized-keys path")
os.makedirs(directory,mode=0o700,exist_ok=True)
os.mkdir(state,0o700)
before=None
if os.path.exists(path):
 if not os.path.isfile(path): raise SystemExit("authorized-keys is not a file")
 with open(path,"rb") as f: before=f.read()
 with open(state+"/before","xb") as f: f.write(before)
else: open(state+"/absent","xb").close()
original=before or b"";candidate=key.encode()
if candidate not in original.splitlines():
 updated=original+(b"\n" if original and not original.endswith(b"\n") else b"")+candidate+b"\n"
else: updated=original
temporary=path+".0sky-enroll-"+str(os.getpid())
fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,"wb") as f: f.write(updated);f.flush();os.fsync(f.fileno())
os.chown(temporary,0,0);os.chmod(directory,0o700);os.replace(temporary,path)
print(json.dumps({"enrolled":True,"device_backup":state,"enrolled_sha256":hashlib.sha256(updated).hexdigest()}))
'''

ROLLBACK = r'''import hashlib,json,os,sys
v=json.load(sys.stdin);p="/var/root/.ssh/authorized_keys";state=v["device_backup"]
with open(p,"rb") as f: current=f.read()
if hashlib.sha256(current).hexdigest()!=v["enrolled_sha256"]:
 raise SystemExit("Concurrent authorized-key change preserved; backup retained")
if os.path.exists(state+"/absent"): os.unlink(p)
else:
 temp=p+".rollback-"+str(os.getpid())
 fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with open(state+"/before","rb") as f: before=f.read()
 with os.fdopen(fd,"wb") as f: f.write(before);f.flush();os.fsync(f.fileno())
 os.chown(temp,0,0);os.replace(temp,p)
print("rolled-back")
'''


def authorize(udid,key,base,output):
    import pair
    public = subprocess.run(["/usr/bin/ssh-keygen","-y","-f",str(key)],check=True,
                            capture_output=True,text=True).stdout.strip()
    if not public.startswith("ssh-ed25519 ") or "\n" in public:
        raise RuntimeError("Expected one Ed25519 public key")
    transaction = uuid.uuid4().hex
    directory = output/("password-authorization-"+transaction)
    directory.mkdir(mode=0o700)
    askpass = directory/"askpass"
    invoked = directory/"dialog-invoked"
    # SSH captures this helper's stdout as its password response. The parent
    # captures only the SSH session's stdout; the password never reaches logs.
    prompt = "Enter the iOS DEVICE'S ROOT SSH PASSWORD for "+udid+". This is NOT your Mac password or iPhone unlock passcode. Authorize this Mac's public key."
    dialog = 'text returned of (display dialog '+json.dumps(prompt)+' default answer "" with hidden answer buttons {"Cancel", "Authorize Key"} default button "Authorize Key")'
    askpass.write_text("#!/bin/sh\n/usr/bin/touch "+shlex.quote(str(invoked))+"\nexec /usr/bin/osascript -e "+shlex.quote(dialog)+"\n")
    askpass.chmod(0o700)
    environment = {**os.environ,"SSH_ASKPASS":str(askpass),"SSH_ASKPASS_REQUIRE":"force","DISPLAY":"0sky-key-authorization"}
    password_base = [arg.replace("BatchMode=yes","BatchMode=no").replace("PasswordAuthentication=no","PasswordAuthentication=yes") for arg in base]
    password_base[1:1] = ["-o","PubkeyAuthentication=no","-o","PreferredAuthentications=password",
                         "-o","NumberOfPasswordPrompts=1","-o","ControlMaster=no","-o","ControlPersist=no"]
    state = "/private/var/db/0sky-key-authorization-"+transaction
    payload = json.dumps({"public_key":public,"state":state}).encode()
    proof = None
    try:
        result = subprocess.run(password_base+["/var/jb/usr/bin/python3 -c "+shlex.quote(PROGRAM)],
            input=payload,capture_output=True,env=environment,timeout=180)
        if result.returncode:
            raise RuntimeError("Password authorization failed or was cancelled (dialog invoked: "+str(invoked.exists())+"): "+result.stderr.decode(errors="replace")[-1200:])
        proof = json.loads(result.stdout)
        authenticated = pair.ssh(base,"id -u")
        if authenticated.stdout.strip()!=b"0": raise RuntimeError("Public-key session is not root")
        proof["public_key_login_verified"] = True
        return proof
    except Exception:
        if proof is not None:
            restored = subprocess.run(password_base+["/var/jb/usr/bin/python3 -c "+shlex.quote(ROLLBACK)],
                input=json.dumps(proof).encode(),capture_output=True,env=environment,timeout=180)
            proof["rolled_back"] = restored.returncode == 0
        raise
    finally:
        # Contains only dialog code; remove the temporary helper after use.
        askpass.unlink()
        (directory/"transaction.json").write_text(json.dumps(proof or {"authorized":False},indent=2)+"\n")
