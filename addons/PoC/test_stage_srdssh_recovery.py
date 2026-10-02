"""An installed recovery Cryptex must not be installed again during boot."""

import unittest
from unittest.mock import AsyncMock, patch

import stage_srdssh_recovery as recovery


class ExistingRecoveryTests(unittest.TestCase):
    def test_absent_service_allows_fresh_install(self):
        with patch.object(recovery, "recovery_installed", new_callable=AsyncMock,
                          return_value=False), patch.object(
                              recovery, "port_open", new_callable=AsyncMock) as port:
            self.assertFalse(recovery.await_existing_recovery("test-udid", "test-id"))
            port.assert_not_called()

    def test_existing_service_is_reused_when_port_opens(self):
        with patch.object(recovery, "recovery_installed", new_callable=AsyncMock,
                          return_value=True), patch.object(
                              recovery, "port_open", new_callable=AsyncMock,
                              return_value=True):
            self.assertTrue(recovery.await_existing_recovery("test-udid", "test-id"))

    def test_existing_service_never_collides_with_fresh_install(self):
        with patch.object(recovery, "recovery_installed", new_callable=AsyncMock,
                          return_value=True), patch.object(
                              recovery, "port_open", new_callable=AsyncMock) as port:
            with self.assertRaisesRegex(RuntimeError, "did not open its port"):
                recovery.await_existing_recovery("test-udid", "test-id", timeout=0)
            port.assert_not_called()


if __name__ == "__main__":
    unittest.main()
