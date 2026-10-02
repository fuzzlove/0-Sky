import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from compat.ios27.build import load_recipe, run_reviewed_recipe, tree_hash


class ReviewedBuildTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "input.bin").write_bytes(b"deterministic artifact")
        self.recipe = self.root / "recipe.json"
        self.reviews = self.root / "reviews.json"

    def prepare(self, *, argv=None, source_hash=None):
        value = {"schema": 1, "component_id": "example.tool",
                 "source_rel": "source", "source_tree_sha256": source_hash or tree_hash(self.source),
                 "output_rel": "output.bin",
                 "expected_output_sha256": hashlib.sha256(b"deterministic artifact").hexdigest(),
                 "steps": [{"argv": argv or ["/bin/cp", "input.bin", "output.bin"],
                            "timeout": 10}]}
        self.recipe.write_text(json.dumps(value, sort_keys=True))
        self.reviews.write_text(json.dumps({"schema": 1, "recipes": {
            self.recipe.name: hashlib.sha256(self.recipe.read_bytes()).hexdigest()}}))

    def test_two_clean_builds_match_pinned_hash(self):
        self.prepare()
        output = self.root / "result.bin"
        evidence = run_reviewed_recipe(self.root, self.recipe, self.reviews, output)
        self.assertEqual(evidence["status"], "BUILD_VERIFIED")
        self.assertEqual(output.read_bytes(), b"deterministic artifact")
        self.assertEqual(evidence["repo_admission"], "BLOCKED")
        with self.assertRaises(FileExistsError):
            run_reviewed_recipe(self.root, self.recipe, self.reviews, output)

    def test_unreviewed_or_changed_recipe_rejected(self):
        self.prepare()
        self.reviews.write_text('{"schema":1,"recipes":{}}')
        with self.assertRaisesRegex(ValueError, "not been reviewed"):
            load_recipe(self.recipe, self.reviews)

    def test_source_hash_mismatch_and_unreviewed_command_rejected(self):
        self.prepare(source_hash="0" * 64)
        with self.assertRaisesRegex(ValueError, "source tree differs"):
            run_reviewed_recipe(self.root, self.recipe, self.reviews, self.root / "out")
        self.prepare(argv=["/bin/sh", "-c", "true"])
        with self.assertRaisesRegex(ValueError, "unreviewed command"):
            load_recipe(self.recipe, self.reviews)

    def test_symlink_source_rejected(self):
        (self.source / "escape").symlink_to("/etc/passwd")
        with self.assertRaisesRegex(ValueError, "symbolic link"):
            tree_hash(self.source)


if __name__ == "__main__":
    unittest.main()
