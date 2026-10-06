#!/usr/bin/env python3
"""Classify macOS signing identities without exposing certificate subjects."""
from __future__ import annotations

from dataclasses import dataclass
import re
import subprocess


@dataclass(frozen=True)
class Identity:
    fingerprint: str
    category: str


def classify(subject: str) -> str:
    for prefix in ("Developer ID Application:", "Developer ID Installer:",
                   "Apple Development:"):
        if subject.startswith(prefix):
            return prefix.removesuffix(":")
    return "other"


def parse_identities(output: str) -> list[Identity]:
    found: list[Identity] = []
    for line in output.splitlines():
        match = re.search(r'\b([A-Fa-f0-9]{40})\s+"([^"]+)"', line)
        if match:
            found.append(Identity(match.group(1).upper(), classify(match.group(2))))
    return found


def discover() -> list[Identity]:
    process = subprocess.run(
        ["/usr/bin/security", "find-identity", "-v", "-p", "basic"],
        capture_output=True, text=True, timeout=20, check=False,
    )
    if process.returncode:
        raise RuntimeError("SIGNING_IDENTITY_DISCOVERY_FAILED")
    return parse_identities(process.stdout)


def require_identity(value: str | None, category: str, identities: list[Identity]) -> str:
    if not value:
        raise RuntimeError("BLOCKED_MISSING_DISTRIBUTION_SIGNING_IDENTITY")
    matches = [identity for identity in identities
               if identity.fingerprint == value.upper() and identity.category == category]
    if len(matches) != 1:
        raise RuntimeError("BLOCKED_MISSING_DISTRIBUTION_SIGNING_IDENTITY")
    return matches[0].fingerprint


def resolve_identity(value: str | None, category: str,
                     identities: list[Identity]) -> str:
    """Validate an explicit fingerprint or select the sole valid identity.

    Automatic selection is deliberately limited to exactly one identity in the
    requested category. Machines with multiple release identities must make
    the choice explicit, preventing an accidental cross-team release.
    """
    if value:
        return require_identity(value, category, identities)
    matches = [identity for identity in identities
               if identity.category == category]
    if not matches:
        raise RuntimeError("BLOCKED_MISSING_DISTRIBUTION_SIGNING_IDENTITY")
    if len(matches) != 1:
        raise RuntimeError("BLOCKED_AMBIGUOUS_DISTRIBUTION_SIGNING_IDENTITY")
    return matches[0].fingerprint
