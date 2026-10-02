"""Failure injection for the owned Cryptex replacement state machine."""
import asyncio
from contextlib import asynccontextmanager
from types import SimpleNamespace
import unittest

from frida_cryptex_transaction_core import (IDENTIFIER, TransactionFailure,
                                             replace)


class FakeService:
    def __init__(self, version, *, fail_uninstall=False, fail_copy_at=None):
        self.version = version
        self.uninstalled = []
        self.fail_uninstall = fail_uninstall
        self.fail_copy_at = fail_copy_at
        self.copy_count = 0

    async def copy_installed(self):
        self.copy_count += 1
        if self.copy_count == self.fail_copy_at:
            raise ConnectionError("injected lost registration reply")
        return ([SimpleNamespace(identifier=IDENTIFIER, version=self.version)]
                if self.version is not None else [])

    async def uninstall(self, identifier):
        self.uninstalled.append(identifier)
        self.version = None
        if self.fail_uninstall and len(self.uninstalled) == 1:
            raise ConnectionError("injected retirement interruption")


class FakePayload:
    def __init__(self, version, *, fail=False):
        self.version = version
        self.fail = fail

    async def install(self, service, ticket):
        if self.fail:
            raise RuntimeError("injected install failure")
        service.version = self.version


class TransactionTests(unittest.IsolatedAsyncioTestCase):
    async def scenario(self, *, current="old", fail_new=False,
                       fail_health_new=False, fail_restore=False,
                       unexpected_during_rollback=False,
                       fail_uninstall=False, fail_copy_at=None,
                       deny_preauthorization=False, fail_second_channel=False):
        service = FakeService(current, fail_uninstall=fail_uninstall,
                              fail_copy_at=fail_copy_at)
        old = FakePayload("old", fail=fail_restore)
        new = FakePayload("new", fail=fail_new)
        tickets = []
        health_calls = []
        connections = 0

        @asynccontextmanager
        async def connect():
            nonlocal connections
            connections += 1
            if fail_second_channel and connections == 2:
                raise ConnectionError("injected transport interruption")
            yield service

        async def authorize(_service, payload):
            tickets.append(payload.version)
            if deny_preauthorization and len(tickets) == 2:
                return b""
            return b"approved"

        async def health(which):
            health_calls.append(which)
            if which == "proposed" and fail_health_new:
                if unexpected_during_rollback:
                    service.version = "unknown"
                raise RuntimeError("injected health failure")

        try:
            result = await replace(connect, authorize, health,
                                   previous=old, proposed=new)
            return result, service, tickets, health_calls
        except TransactionFailure as failure:
            return failure.result, service, tickets, health_calls

    async def test_success_requires_registration_and_health(self):
        result, service, tickets, health = await self.scenario()
        self.assertEqual(result.status, "INSTALLED_AND_VERIFIED")
        self.assertEqual(result.rollback_status, "NOT_NEEDED")
        self.assertEqual(service.version, "new")
        self.assertEqual(tickets, ["old", "new", "new"])
        self.assertEqual(health, ["proposed"])

    async def test_changed_active_generation_fails_before_mutation(self):
        result, service, tickets, _ = await self.scenario(current="other")
        self.assertEqual(result.status, "PRECHECK_FAILED")
        self.assertEqual(service.uninstalled, [])
        self.assertEqual(tickets, [])

    async def test_missing_second_ticket_fails_before_mutation(self):
        result, service, tickets, _ = await self.scenario(
            deny_preauthorization=True)
        self.assertEqual(result.status, "PRECHECK_FAILED")
        self.assertEqual(service.version, "old")
        self.assertEqual(service.uninstalled, [])
        self.assertEqual(tickets, ["old", "new"])

    async def test_failed_install_restores_previous_generation(self):
        result, service, tickets, health = await self.scenario(fail_new=True)
        self.assertEqual(result.rollback_status, "VERIFIED")
        self.assertEqual(service.version, "old")
        self.assertEqual(tickets, ["old", "new", "new", "old"])
        self.assertEqual(health, ["previous"])

    async def test_failed_health_retires_new_then_restores_old(self):
        result, service, tickets, health = await self.scenario(fail_health_new=True)
        self.assertEqual(result.rollback_status, "VERIFIED")
        self.assertEqual(service.version, "old")
        self.assertEqual(len(service.uninstalled), 2)
        self.assertEqual(health, ["proposed", "previous"])

    async def test_unknown_generation_is_preserved(self):
        result, service, _, _ = await self.scenario(
            fail_health_new=True, unexpected_during_rollback=True)
        self.assertEqual(result.rollback_status, "FAILED")
        self.assertEqual(service.version, "unknown")
        self.assertEqual(len(service.uninstalled), 1)

    async def test_failed_restore_is_reported(self):
        result, service, _, _ = await self.scenario(fail_new=True,
                                                    fail_restore=True)
        self.assertEqual(result.rollback_status, "FAILED")
        self.assertIsNone(service.version)

    async def test_interrupted_retirement_attempts_restore(self):
        result, service, _, health = await self.scenario(fail_uninstall=True)
        self.assertEqual(result.rollback_status, "VERIFIED")
        self.assertEqual(service.version, "old")
        self.assertEqual(health, ["previous"])

    async def test_transport_failure_after_retirement_attempts_restore(self):
        result, service, _, health = await self.scenario(
            fail_second_channel=True)
        self.assertEqual(result.rollback_status, "VERIFIED")
        self.assertEqual(service.version, "old")
        self.assertEqual(health, ["previous"])

    async def test_lost_registration_reply_attempts_restore(self):
        result, service, _, health = await self.scenario(fail_copy_at=2)
        self.assertEqual(result.rollback_status, "VERIFIED")
        self.assertEqual(service.version, "old")
        self.assertEqual(health, ["previous"])


if __name__ == "__main__":
    unittest.main()
