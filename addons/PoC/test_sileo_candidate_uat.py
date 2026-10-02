"""Reject a Sileo IPA whose bundled dylibs cannot be read by the app."""
import hashlib
import json
from pathlib import Path
import plistlib
import tempfile
import unittest
import zipfile

import sileo_candidate_uat as candidate


class SileoCandidateIntegrityTests(unittest.TestCase):
    def test_unreadable_dylib_fails_before_install(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate.ipa"
            prefix = "Payload/Sileo.app/"
            info = plistlib.dumps({
                "CFBundleIdentifier": candidate.BUNDLE_ID,
                "CFBundleExecutable": candidate.EXECUTABLE,
                "CFBundleShortVersionString": candidate.VERSION,
            })
            libraries = ("liblzma.5.dylib", "libzstd.1.dylib",
                         "libiosexec.1.dylib")
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr(prefix + "Info.plist", info)
                archive.writestr(prefix + "Sileo", b"\xcf\xfa\xed\xfe")
                for name in libraries:
                    member = zipfile.ZipInfo(prefix + "Frameworks/" + name)
                    member.external_attr = (0o100600 if name == libraries[0]
                                            else 0o100644) << 16
                    archive.writestr(member, b"test library")
            receipt = {
                "artifact_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "bundle_id": candidate.BUNDLE_ID,
                "signature": "ad-hoc SRD test candidate",
                "bundled_runtime_libraries": {
                    name: {"signed_sha256": hashlib.sha256(b"test library").hexdigest()}
                    for name in libraries
                },
            }
            Path(str(path) + ".json").write_text(json.dumps(receipt))
            with self.assertRaisesRegex(RuntimeError, "LIBRARY_UNREADABLE"):
                candidate.checked_payload(path)


if __name__ == "__main__":
    unittest.main()
