"""A successful immediate Cryptex install cannot satisfy the durability gate."""
from contextlib import asynccontextmanager
from types import SimpleNamespace
import unittest

import frida_cryptex_transaction as transaction


class DurabilityTests(unittest.IsolatedAsyncioTestCase):
    async def test_delayed_registration_requires_same_exact_generation(self):
        waited = []

        async def sleep(seconds):
            waited.append(seconds)

        async def identity(udid):
            return {"udid": udid}

        class Service:
            versions = ["6.0.test"]

            async def copy_installed(self):
                return [SimpleNamespace(identifier=transaction.IDENTIFIER,
                                        version=version) for version in self.versions]

        service = Service()

        @asynccontextmanager
        async def connect():
            yield service

        await transaction.verify_durable_registration(
            connect, "test-device", "6.0.test", settle_seconds=75,
            sleep=sleep, identity=identity)
        self.assertEqual(waited, [75])
        service.versions = []
        with self.assertRaisesRegex(RuntimeError, "POST_INSTALL_CRYPTEX_NOT_DURABLE"):
            await transaction.verify_durable_registration(
                connect, "test-device", "6.0.test", settle_seconds=0,
                sleep=sleep, identity=identity)
        service.versions = ["6.0.other"]
        with self.assertRaisesRegex(RuntimeError, "POST_INSTALL_CRYPTEX_NOT_DURABLE"):
            await transaction.verify_durable_registration(
                connect, "test-device", "6.0.test", settle_seconds=0,
                sleep=sleep, identity=identity)

    async def test_changed_usb_identity_blocks_durability(self):
        async def sleep(_seconds):
            return None

        async def identity(_udid):
            return {"udid": "other-device"}

        @asynccontextmanager
        async def connect():
            raise AssertionError("registration must not be queried on another device")
            yield

        with self.assertRaisesRegex(RuntimeError, "POST_INSTALL_USB_IDENTITY_CHANGED"):
            await transaction.verify_durable_registration(
                connect, "test-device", "6.0.test", settle_seconds=0,
                sleep=sleep, identity=identity)


if __name__ == "__main__":
    unittest.main()
