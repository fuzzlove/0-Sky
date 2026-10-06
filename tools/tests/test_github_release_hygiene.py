import unittest

from tools import verify_github_release_hygiene as hygiene


class GithubReleaseHygieneTests(unittest.TestCase):
    def fixture(self):
        status = {
            "current": {"tag": "v2", "installer": {
                "name": "0-Sky-Bridge-1.0.0-distribution-universal.pkg",
                "bytes": 100}},
            "deprecated": [{"tag": "v1"}],
        }
        releases = [{
            "tag_name": "v2", "name": hygiene.CURRENT_PREFIX + " 0-Sky v2",
            "body": hygiene.CURRENT_PREFIX + "\n\nVerified.",
            "draft": False, "prerelease": True,
            "assets": [{"name": name, "size": 100 if name.endswith(".pkg") else 1}
                       for name in hygiene.CURRENT_ASSETS],
        }, {
            "tag_name": "v1", "name": hygiene.DEPRECATED_PREFIX + " 0-Sky v1",
            "body": hygiene.DEPRECATED_WARNING + "\n\nDo not use.",
            "draft": False, "prerelease": True, "assets": [],
        }]
        return releases, status

    def test_clean_release_set_passes(self):
        releases, status = self.fixture()
        self.assertEqual(hygiene.verify(releases, status), [])

    def test_deprecated_binary_is_rejected(self):
        releases, status = self.fixture()
        releases[1]["assets"] = [{"name": "broken.pkg", "size": 4}]
        self.assertIn("DEPRECATED_BINARY_ASSET:v1:broken.pkg",
                      hygiene.verify(releases, status))

    def test_missing_warning_is_rejected(self):
        releases, status = self.fixture()
        releases[1]["body"] = "old notes"
        self.assertIn("DEPRECATED_BODY_INVALID:v1",
                      hygiene.verify(releases, status))


if __name__ == "__main__":
    unittest.main()
