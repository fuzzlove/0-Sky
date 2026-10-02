"""Real ZIP payload/metadata preservation and failure behavior."""
import gzip,pathlib,runpy,stat,tempfile,unittest,zipfile
from types import SimpleNamespace
from unittest.mock import patch
from repair_device_connection import HERE

WORKER=HERE.parents[1]/'bridge/KitScripts/automation/CrypStoreAutomation/crypstore_worker.py'

class ArchiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.worker=runpy.run_path(str(WORKER))

    def create(self,path,method):
        with zipfile.ZipFile(path,'w') as archive:
            archive.comment=b'archive metadata'
            for name,mode,data in [('Payload/Example.app/tool',stat.S_IFREG|0o755,b'executable bytes'*1000),
                                   ('Payload/Example.app/link',stat.S_IFLNK|0o777,b'tool')]:
                item=zipfile.ZipInfo(name,(2024,1,2,3,4,6));item.compress_type=method
                item.external_attr=mode<<16;item.create_system=3;item.comment=b'member metadata'
                archive.writestr(item,data)

    def test_lzma_and_bzip_preserve_contents_and_unix_metadata(self):
        for method in (zipfile.ZIP_LZMA,zipfile.ZIP_BZIP2):
            with self.subTest(method=method),tempfile.TemporaryDirectory() as folder:
                path=pathlib.Path(folder)/'input.tipa';self.create(path,method)
                with zipfile.ZipFile(path) as archive:
                    expected=[(i.filename,i.external_attr,i.date_time,i.comment,archive.read(i)) for i in archive.infolist()]
                self.assertTrue(self.worker['normalize_ipa_archive'](path))
                with zipfile.ZipFile(path) as archive:
                    self.assertEqual(archive.comment,b'archive metadata')
                    self.assertEqual([(i.filename,i.external_attr,i.date_time,i.comment,archive.read(i)) for i in archive.infolist()],expected)
                    self.assertTrue(all(i.compress_type==zipfile.ZIP_DEFLATED for i in archive.infolist()))
                self.assertFalse(self.worker['normalize_ipa_archive'](path))

    def test_existing_deflate_bytes_are_unchanged(self):
        with tempfile.TemporaryDirectory() as folder:
            path=pathlib.Path(folder)/'input.ipa';self.create(path,zipfile.ZIP_DEFLATED);before=path.read_bytes()
            self.assertFalse(self.worker['normalize_ipa_archive'](path));self.assertEqual(path.read_bytes(),before)

    def test_gzip_wrapped_lzma_archive(self):
        with tempfile.TemporaryDirectory() as folder:
            path=pathlib.Path(folder)/'input.tipa';self.create(path,zipfile.ZIP_LZMA)
            path.write_bytes(gzip.compress(path.read_bytes()))
            self.assertTrue(self.worker['normalize_ipa_archive'](path))
            with zipfile.ZipFile(path) as archive:self.assertIsNone(archive.testzip())

    def test_failed_recompression_preserves_source_and_cleans_temporary(self):
        with tempfile.TemporaryDirectory() as folder:
            path=pathlib.Path(folder)/'input.tipa';self.create(path,zipfile.ZIP_LZMA);before=path.read_bytes()
            with patch.object(zipfile.ZipFile,'open',side_effect=OSError('write failed')):
                with self.assertRaisesRegex(OSError,'write failed'):self.worker['normalize_zip_compression'](path)
            self.assertEqual(path.read_bytes(),before)
            self.assertEqual(list(path.parent.iterdir()),[path])

    def test_insufficient_space_preserves_original(self):
        with tempfile.TemporaryDirectory() as folder:
            path=pathlib.Path(folder)/'input.tipa';self.create(path,zipfile.ZIP_LZMA);before=path.read_bytes()
            with patch.object(self.worker['shutil'],'disk_usage',return_value=SimpleNamespace(free=0)):
                with self.assertRaisesRegex(RuntimeError,'Insufficient'):self.worker['normalize_zip_compression'](path)
            self.assertEqual(path.read_bytes(),before)

if __name__=='__main__':unittest.main()
