from pathlib import Path
import tempfile
import unittest

from tools.prune_release_artifacts import prune


class PruneReleaseArtifactsTests(unittest.TestCase):
    def test_removes_only_generated_bytecode_and_empty_caches(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cache = root / "module/__pycache__"
            cache.mkdir(parents=True)
            (cache / "example.cpython-312.pyc").write_bytes(b"generated")
            source = root / "module/example.py"
            source.write_text("value = 1\n")
            self.assertEqual(prune(root), {
                "bytecode_files": 1,
                "cache_directories": 1,
            })
            self.assertTrue(source.is_file())
            self.assertFalse(cache.exists())

    def test_refuses_unexpected_cache_content(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cache = root / "__pycache__"
            cache.mkdir()
            (cache / "keep.txt").write_text("unexpected")
            with self.assertRaisesRegex(ValueError, "unexpected"):
                prune(root)


if __name__ == "__main__":
    unittest.main()
