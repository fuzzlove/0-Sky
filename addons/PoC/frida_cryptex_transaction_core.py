"""Fail-closed state machine for replacing one owned research Cryptex."""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from typing import Any, Protocol


IDENTIFIER = "codes.openai.research.ellekitloader"


class Payload(Protocol):
    version: str

    async def install(self, service: Any, ticket: bytes) -> None: ...


@dataclass(frozen=True)
class TransactionResult:
    status: str
    events: tuple[str, ...]
    rollback_status: str


class TransactionFailure(RuntimeError):
    def __init__(self, result: TransactionResult, cause: BaseException):
        super().__init__("Cryptex replacement failed; rollback " + result.rollback_status)
        self.result = result
        self.__cause__ = cause


def installed_version(entries: list[Any]) -> str | None:
    matches = [str(item.version) for item in entries
               if str(item.identifier) == IDENTIFIER]
    if len(matches) > 1:
        raise RuntimeError("MULTIPLE_OWNED_CRYPTEX_GENERATIONS")
    return matches[0] if matches else None


async def replace(
    connect: Callable[[], AbstractAsyncContextManager[Any]],
    authorize: Callable[[Any, Payload], Awaitable[bytes]],
    health: Callable[[str], Awaitable[None]],
    *,
    previous: Payload,
    proposed: Payload,
) -> TransactionResult:
    """Authorize both images before mutation; refresh tickets after retirement.

    Each restore attempt opens a fresh RemoteXPC channel, because replacing a
    Cryptex can close the service connection. Unknown installed versions are
    never removed. A failed restore remains a surfaced transaction failure.
    """
    if previous.version == proposed.version:
        raise ValueError("replacement version must differ from active version")
    events: list[str] = []
    mutation_started = False
    try:
        async with connect() as service:
            current = installed_version(await asyncio.wait_for(
                service.copy_installed(), timeout=45))
            if current != previous.version:
                raise RuntimeError("ACTIVE_GENERATION_CHANGED")
            events.append("ACTIVE_GENERATION_VERIFIED")
            for payload in (previous, proposed):
                ticket = await authorize(service, payload)
                if not isinstance(ticket, bytes) or not ticket:
                    raise RuntimeError("TSS_PREAUTHORIZATION_FAILED")
            events.append("BOTH_TICKETS_PREAUTHORIZED")
            mutation_started = True
            await asyncio.wait_for(service.uninstall(IDENTIFIER), timeout=45)
            events.append("PREVIOUS_GENERATION_RETIRED")
        # Retirement may rotate the nonce. Authorize again on a fresh channel.
        async with connect() as service:
            ticket = await authorize(service, proposed)
            if not isinstance(ticket, bytes) or not ticket:
                raise RuntimeError("NEW_TICKET_UNAVAILABLE_AFTER_RETIREMENT")
            events.append("NEW_TICKET_REFRESHED")
            await proposed.install(service, ticket)
            events.append("NEW_GENERATION_INSTALLED")
            current = installed_version(await asyncio.wait_for(
                service.copy_installed(), timeout=45))
            if current != proposed.version:
                raise RuntimeError("NEW_GENERATION_REGISTRATION_FAILED")
            events.append("NEW_GENERATION_REGISTERED")
        await health("proposed")
        events.append("NEW_GENERATION_HEALTHY")
        return TransactionResult("INSTALLED_AND_VERIFIED", tuple(events), "NOT_NEEDED")
    except BaseException as original:
        if not mutation_started:
            result = TransactionResult("PRECHECK_FAILED", tuple(events), "NOT_NEEDED")
            raise TransactionFailure(result, original) from original
        try:
            async with connect() as service:
                current = installed_version(await asyncio.wait_for(
                    service.copy_installed(), timeout=45))
                if current == proposed.version:
                    await asyncio.wait_for(service.uninstall(IDENTIFIER), timeout=45)
                    events.append("FAILED_GENERATION_RETIRED")
                elif current not in (None, previous.version):
                    raise RuntimeError("UNEXPECTED_GENERATION_DURING_ROLLBACK")
            if current != previous.version:
                # Retiring the failed generation may close RemoteXPC and rotate
                # its nonce; reconnect before asking Apple for the restore ticket.
                async with connect() as service:
                    ticket = await authorize(service, previous)
                    if not isinstance(ticket, bytes) or not ticket:
                        raise RuntimeError("ROLLBACK_TICKET_UNAVAILABLE")
                    events.append("ROLLBACK_TICKET_REFRESHED")
                    await previous.install(service, ticket)
                    events.append("PREVIOUS_GENERATION_RESTORED")
                    restored = installed_version(await asyncio.wait_for(
                        service.copy_installed(), timeout=45))
                    if restored != previous.version:
                        raise RuntimeError("ROLLBACK_REGISTRATION_FAILED")
            await health("previous")
            events.append("ROLLBACK_HEALTHY")
            result = TransactionResult("FAILED", tuple(events), "VERIFIED")
        except BaseException as rollback_error:
            result = TransactionResult("FAILED", tuple(events), "FAILED")
            raise TransactionFailure(result, BaseExceptionGroup(
                "install and rollback failed", [original, rollback_error])) from original
        raise TransactionFailure(result, original) from original
