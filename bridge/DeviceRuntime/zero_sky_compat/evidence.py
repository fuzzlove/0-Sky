"""Immutable, bounded evidence helpers."""
from __future__ import annotations

import json
from pathlib import Path

from .transaction import atomic_json


def write_report(path, report):
    value = report.to_dict() if hasattr(report, 'to_dict') else report
    atomic_json(Path(path), value)


def read_events(path):
    value = json.loads(Path(path).read_text())
    events = value.get('evidence', [])
    if not isinstance(events, list):
        raise ValueError('compatibility evidence is malformed')
    return events


def has_concrete_blocker(report):
    state = report.compatibility_state
    return state.startswith('BLOCKED_BY_') or state in {
        'BROKEN_UPSTREAM', 'UNSAFE_TO_ADAPT'}
