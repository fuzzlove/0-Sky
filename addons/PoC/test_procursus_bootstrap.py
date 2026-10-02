"""Regression checks for the bundled Procursus archive filter."""

import io
import pathlib
import runpy
import tarfile
import tempfile
import unittest

from restore_srd_bootstrap import DEFAULT_SRDSH_KIT


BOOTSTRAP = runpy.run_path(str(DEFAULT_SRDSH_KIT / "bootstrap.py"),
                          run_name="poc_bootstrap_test")


class ProcursusFilterTests(unittest.TestCase):
    def localtime(self, target="/var/db/timezone/localtime"):
        member = tarfile.TarInfo("./var/jb/etc/localtime")
        member.type = tarfile.SYMTYPE
        member.linkname = target
        return member

    def test_timezone_entry_is_omitted(self):
        self.assertIsNone(BOOTSTRAP["_safe_member"](self.localtime()))

    def test_unexpected_timezone_entry_is_rejected(self):
        with self.assertRaises(BOOTSTRAP["ChainError"]):
            BOOTSTRAP["_safe_member"](self.localtime("/unexpected"))
        member = tarfile.TarInfo("var/jb/etc/localtime")
        with self.assertRaises(BOOTSTRAP["ChainError"]):
            BOOTSTRAP["_safe_member"](member)

    def test_existing_timezone_is_preserved_during_extraction(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary) / "procursus"
            (root / "etc").mkdir(parents=True)
            external = pathlib.Path(temporary) / "system-timezone"
            external.write_bytes(b"timezone")
            link = root / "etc/localtime"
            link.symlink_to(external)
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w") as archive:
                for member in (self.localtime(), tarfile.TarInfo("var/jb/package-file")):
                    filtered = BOOTSTRAP["_safe_member"](member)
                    if filtered is not None:
                        archive.addfile(filtered, io.BytesIO(b""))
            buffer.seek(0)
            with tarfile.open(fileobj=buffer) as archive:
                archive.extractall(root, filter="data")
            self.assertTrue(link.is_symlink())
            self.assertEqual(link.readlink(), external)
            self.assertEqual(external.read_bytes(), b"timezone")
            self.assertTrue((root / "package-file").is_file())

    def test_traversal_still_rejected(self):
        with self.assertRaises(BOOTSTRAP["ChainError"]):
            BOOTSTRAP["_safe_member"](tarfile.TarInfo("var/jb/../../outside"))


if __name__ == "__main__":
    unittest.main()
