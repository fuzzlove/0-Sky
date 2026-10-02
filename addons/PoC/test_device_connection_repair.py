"""Identity isolation and actual enrollment/rollback behavior on a temporary FS."""
import hashlib
import contextlib
import io
import json
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import repair_device_connection as connection
from recover_device_ssh import enrollment_script
from authorize_device_key import PROGRAM, ROLLBACK


class ConnectionTests(unittest.TestCase):
    def test_duplicate_live_profiles_rejected_stale_profile_ignored(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            worker = root / "crypstore_worker.py"
            worker.touch()
            definition = {"EnvironmentVariables":{"CRYPSTORE_DEVICE_UDID":"device-a"},
                          "ProgramArguments":["python",str(worker)]}
            first = root / "com.liquidskysecurity.crypstore-worker.a.plist"
            first.write_bytes(plistlib.dumps(definition))
            stale = dict(definition,ProgramArguments=["python",str(root/"missing/crypstore_worker.py")])
            second = root / "com.liquidskysecurity.crypstore-worker.b.plist"
            second.write_bytes(plistlib.dumps(stale))
            self.assertEqual(list(connection.profiles(root)),["device-a"])
            second.write_bytes(plistlib.dumps(definition))
            with self.assertRaisesRegex(ValueError,"Multiple active"):
                connection.profiles(root)
            self.assertEqual(connection.configured_instances(root),
                             [("device-a", "a"), ("device-a", "b")])

    def test_worker_environment_cannot_retain_other_device(self):
        with patch.dict(os.environ,{"CRYPSTORE_DEVICE_UDID":"old","CRYPSTORE_WIRELESS_HOST":"old-host"}):
            with patch.object(connection.runpy,"run_path",return_value={}) as run:
                connection.worker_namespace({"EnvironmentVariables":{"CRYPSTORE_DEVICE_UDID":"new"},
                    "ProgramArguments":["python","/new/crypstore_worker.py"]})
                self.assertEqual(os.environ["CRYPSTORE_DEVICE_UDID"],"new")
                self.assertNotIn("CRYPSTORE_WIRELESS_HOST",os.environ)
                run.assert_called_once()

    def test_atomic_write_does_not_follow_symlink(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            original = root/"original"
            original.write_bytes(b"original")
            link = root/"link"
            link.symlink_to(original)
            with self.assertRaises(RuntimeError): connection.atomic_write(link,b"changed")
            self.assertEqual(original.read_bytes(),b"original")

    def test_failed_worker_restart_restores_both_configuration_files(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            path = root/"worker.plist"
            config = root/"config.json"
            env = {"CRYPSTORE_DEVICE_HOST":"127.0.0.1","CRYPSTORE_DEVICE_PORT":"2227",
                   "CRYPSTORE_DEVICE_KEY":"/key","CRYPSTORE_DEVICE_KNOWN_HOSTS":"/pin"}
            original = plistlib.dumps({"Label":"worker","ProgramArguments":["/old/python","/worker"],
                                       "EnvironmentVariables":env})
            path.write_bytes(original)
            config.write_bytes(b'{"udid":"device","ssh_port":"2223"}')
            original_config = config.read_bytes()
            success = SimpleNamespace(returncode=0,stderr=b"")
            failure = SimpleNamespace(returncode=1,stderr=b"launch rejected")
            with patch.object(connection,"select_device_python",return_value="/new/python"),patch.object(connection,"interpreter_status",return_value={"ready":False}):
                with patch.object(connection.subprocess,"run",side_effect=[success,failure,failure,success]):
                    with self.assertRaisesRegex(RuntimeError,"Worker restart failed"):
                        connection.repair_host_profile(path,config,env,"alias",root)
            self.assertEqual(path.read_bytes(),original)
            self.assertEqual(config.read_bytes(),original_config)
            backup = next(root.glob("before-*"))
            self.assertEqual((backup/"config.json").read_bytes(),original_config)

    def test_host_repair_is_idempotent(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            path = root/"worker.plist"
            config = root/"config.json"
            env = {"CRYPSTORE_DEVICE_HOST":"127.0.0.1","CRYPSTORE_DEVICE_PORT":"2227",
                   "CRYPSTORE_DEVICE_KEY":"/key","CRYPSTORE_DEVICE_KNOWN_HOSTS":"/pin"}
            path.write_bytes(plistlib.dumps({"Label":"worker","ProgramArguments":["/old/python","/worker"],
                                            "EnvironmentVariables":env}))
            config.write_bytes(b'{"udid":"device","ssh_port":"2223"}')
            with patch.object(connection,"select_device_python",return_value="/new/python"),patch.object(connection,"interpreter_status",return_value={"ready":False}):
                with patch.object(connection.subprocess,"run",side_effect=[SimpleNamespace(returncode=0,stderr=b""),SimpleNamespace(returncode=1,stderr=b""),SimpleNamespace(returncode=0,stderr=b"")]):
                    self.assertTrue(connection.repair_host_profile(path,config,env,"alias",root)[0])
                with patch.object(connection.subprocess,"run") as run:
                    self.assertFalse(connection.repair_host_profile(path,config,env,"alias",root)[0])
                    run.assert_not_called()

    def test_unrelated_usb_listener_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            pair = SimpleNamespace(tcp_open=lambda host,port:True,exact_iproxy_present=lambda udid,port,remote_port:False)
            with patch.dict(sys.modules,{"pair":pair}):
                with self.assertRaisesRegex(RuntimeError,"unrelated listener"):
                    connection.ensure_persistent_tunnel(Path(folder)/"worker.plist",
                        {"CRYPSTORE_DEVICE_UDID":"device-a","CRYPSTORE_DEVICE_PORT":"2227"})


class EnrollmentTests(unittest.TestCase):
    def run_enrollment(self, commit=False, absent=False, concurrent=False, symlink=False):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            mount = root/"mount"
            (mount/"usr/bin").mkdir(parents=True)
            (mount/"etc").mkdir()
            (mount/"etc/public-key").write_text("ssh-ed25519 PUBLIC\n")
            directory = root/"ssh"
            directory.mkdir()
            keys = directory/"authorized_keys"
            original = b"ssh-ed25519 EXISTING old-host\n"
            if not absent: keys.write_bytes(original)
            if symlink:
                keys.unlink()
                target = root/"target"
                target.write_bytes(original)
                keys.symlink_to(target)
            # Exercise the real shell transaction. Emulate only platform tools
            # unavailable on macOS and shorten the deadline for the tests.
            toybox = mount/"usr/bin/toybox"
            toybox.write_text("#!"+sys.executable+"\n"+r'''
import hashlib, pathlib, subprocess, sys, time
args=sys.argv[1:]
if args[0]=='chown': sys.exit(0)
if args[0]=='sleep': time.sleep(.01); sys.exit(0)
if args[0]=='sha256sum':
 if args[1]=='-c':
  expected,path=pathlib.Path(args[2]).read_text().strip().split('  ',1)
  sys.exit(0 if hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()==expected else 1)
 print(hashlib.sha256(pathlib.Path(args[1]).read_bytes()).hexdigest()+'  '+args[1]);sys.exit(0)
sys.exit(subprocess.call(args))
''')
            toybox.chmod(0o755)
            state = root/"state"
            script = enrollment_script(str(state)).replace("DIR=/var/root/.ssh","DIR="+str(directory))
            script = script.replace('[ ! -L /var/root ] && ', '').replace('"$i" -lt 120','"$i" -lt 3')
            program = root/"enroll.sh"
            program.write_text(script)
            process = subprocess.Popen(["/bin/sh",str(program)],env={**os.environ,"CRYPTEX_MOUNT_PATH":str(mount)},stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:
                deadline=time.monotonic()+10
                while not (state/"ready").exists() and process.poll() is None and time.monotonic()<deadline:
                    time.sleep(.01)
                if commit: (state/"commit").touch()
                if concurrent: keys.write_bytes(keys.read_bytes()+b"concurrent-change\n")
                stdout,stderr=process.communicate(timeout=10)
                if symlink:
                    self.assertEqual(process.returncode,78)
                    self.assertEqual(target.read_bytes(),original)
                elif commit:
                    self.assertEqual(process.returncode,0,stderr)
                    self.assertEqual(keys.read_bytes(),original+b"\nssh-ed25519 PUBLIC\n")
                    self.assertEqual((state/"before").read_bytes(),original)
                    self.assertEqual(keys.stat().st_mode & 0o777,0o600)
                elif concurrent:
                    self.assertEqual(process.returncode,79,stderr)
                    self.assertIn(b"concurrent-change",keys.read_bytes())
                    self.assertTrue((state/"concurrent-change").exists())
                elif absent:
                    self.assertEqual(process.returncode,0,stderr)
                    self.assertFalse(keys.exists())
                else:
                    self.assertEqual(process.returncode,0,stderr)
                    self.assertEqual(keys.read_bytes(),original)
                    self.assertTrue((state/"rolled-back").exists())
            finally:
                if process.poll() is None: process.kill(); process.wait()

    def test_commit_preserves_existing_authorized_keys(self): self.run_enrollment(commit=True)
    def test_timeout_restores_original_bytes(self): self.run_enrollment()
    def test_timeout_restores_initial_absence(self): self.run_enrollment(absent=True)
    def test_concurrent_change_is_preserved(self): self.run_enrollment(concurrent=True)
    def test_symlink_is_rejected(self): self.run_enrollment(symlink=True)


class PasswordEnrollmentTests(unittest.TestCase):
    def test_append_backup_and_rollback_preserve_original_keys(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);directory=root/"ssh";directory.mkdir()
            path=directory/"authorized_keys";original=b"ssh-ed25519 OLD another-Mac\n"
            path.write_bytes(original)
            state=root/"state"
            program=PROGRAM.replace('directory="/var/root/.ssh"','directory='+repr(str(directory)))
            stdout=io.StringIO()
            with patch("sys.stdin",io.StringIO(json.dumps({"public_key":"ssh-ed25519 NEW","state":str(state)}))):
                with patch("os.geteuid",return_value=0),patch("os.chown"),contextlib.redirect_stdout(stdout):
                    exec(program,{})
            self.assertEqual(path.read_bytes(),original+b"ssh-ed25519 NEW\n")
            self.assertEqual((state/"before").read_bytes(),original)
            proof=json.loads(stdout.getvalue())
            rollback=ROLLBACK.replace('p="/var/root/.ssh/authorized_keys"','p='+repr(str(path)))
            with patch("sys.stdin",io.StringIO(json.dumps(proof))),patch("os.chown"),contextlib.redirect_stdout(io.StringIO()):
                exec(rollback,{})
            self.assertEqual(path.read_bytes(),original)

    def test_rollback_refuses_concurrent_key_change(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);path=root/"authorized_keys";state=root/"backup";state.mkdir()
            path.write_bytes(b"concurrent change")
            proof={"device_backup":str(state),"enrolled_sha256":hashlib.sha256(b"earlier").hexdigest()}
            rollback=ROLLBACK.replace('p="/var/root/.ssh/authorized_keys"','p='+repr(str(path)))
            with patch("sys.stdin",io.StringIO(json.dumps(proof))):
                with self.assertRaisesRegex(SystemExit,"Concurrent"):
                    exec(rollback,{})
            self.assertEqual(path.read_bytes(),b"concurrent change")


if __name__ == "__main__": unittest.main()
