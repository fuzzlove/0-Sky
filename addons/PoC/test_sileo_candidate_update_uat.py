"""The Sileo updater must verify a running app before claiming launch success."""
import json
import unittest
from unittest import mock

import sileo_candidate_update_uat as update


class SileoLaunchHealthTests(unittest.TestCase):
    APP = {"Path": "/private/var/containers/Bundle/Application/"
           "11111111-2222-3333-4444-555555555555/Sileo.app"}

    def test_stable_process_passes(self):
        worker = {"ssh": mock.Mock(side_effect=[
            mock.Mock(returncode=0),
            mock.Mock(returncode=0, stdout=json.dumps([123]).encode()),
            mock.Mock(returncode=0, stdout=json.dumps([123]).encode()),
        ])}
        self.assertEqual(update.launch_healthcheck(worker, self.APP, pause=lambda _: None),
                         "LAUNCH_PROCESS_STABLE_10_SECONDS")
        self.assertEqual(worker["ssh"].call_count, 3)

    def test_launch_crash_is_rejected(self):
        worker = {"ssh": mock.Mock(side_effect=[
            mock.Mock(returncode=0),
            mock.Mock(returncode=0, stdout=b"[]"),
        ])}
        with self.assertRaisesRegex(RuntimeError, "NOT_STABLE"):
            update.launch_healthcheck(worker, self.APP, pause=lambda _: None)

    def test_restarting_process_is_rejected(self):
        worker = {"ssh": mock.Mock(side_effect=[
            mock.Mock(returncode=0),
            mock.Mock(returncode=0, stdout=b"[123]"),
            mock.Mock(returncode=0, stdout=b"[456]"),
        ])}
        with self.assertRaisesRegex(RuntimeError, "RESTARTED"):
            update.launch_healthcheck(worker, self.APP, pause=lambda _: None)


if __name__ == "__main__":
    unittest.main()
