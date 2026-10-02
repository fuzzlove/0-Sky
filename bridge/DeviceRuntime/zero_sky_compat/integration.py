"""Thin integration gates. They never invent compatibility or bypass rollback."""
import os
from pathlib import Path
from .engine import Engine
from .environment import detect, load
from .registry import Registry


class CompatibilityBlocked(RuntimeError):
    pass


def default_state():
    # Host workers provide their own per-device instance state explicitly.
    return Path('/var/jb/var/lib/0sky/compatibility')


def require_install_adapter(source, operation, state=None, environment=None):
    """Legacy backends cannot mutate until replaced by a transactional adapter.

    This is an admission stop, not an approval based on stale runtime evidence.
    Approval tokens from package metadata or request JSON are never accepted.
    """
    state = Path(state) if state else default_state()
    env = environment or detect()
    engine = Engine(state, env)
    try:
        report, root, work = engine.evaluate(source)
    except (OSError, ValueError, RuntimeError) as error:
        raise CompatibilityBlocked('Compatibility intake failed: ' + type(error).__name__) from error
    report.add('INSTALL_METHOD_UNKNOWN', operation,
               'legacy installation path lacks verified rollback and functional validation',
               'unknown')
    if report.compatibility_state in ('NATIVE_COMPATIBLE', 'TESTING'):
        report.set_compatibility('UNKNOWN', 'CLASSIFY',
                                 'installation method needs analysis and adapter discovery')
    report.status = 'UNKNOWN'
    engine.save(report, work)
    raise CompatibilityBlocked('Compatibility %s: %s. See the compatibility view for diagnostics.' %
                               (report.status, report.component))


def block_legacy_mutation(operation):
    raise CompatibilityBlocked('Compatibility UNKNOWN: %s has no transactional service adapter; no changes made.' % operation)


def registry_view(state=None):
    values = Registry((Path(state) if state else default_state()) / 'registry.sqlite3').list()
    fields = ('component', 'version', 'source_hash', 'environment_hash', 'status',
              'compatibility_state', 'pipeline_phase', 'adaptation_plan',
              'root_requirement', 'root_reasons', 'validation_timestamp', 'registry_key')
    summaries = []
    for value in values:
        summary = {field: value.get(field) for field in fields}
        summary['environment'] = value['environment']
        summary['issue_count'] = len(value['issues'])
        summary['issues'] = value['issues'][:20]
        summary['components'] = [{'kind': kind} for kind in sorted({item['kind'] for item in value['components']})]
        summary['runtime_validation'] = value['runtime_validation']
        summaries.append(summary)
    from .model import ENGINE_VERSION, STATES
    return {'engine_version': ENGINE_VERSION, 'components': summaries, 'limit': 500,
            'groups': {status: sum(v.get('compatibility_state', 'UNKNOWN') == status
                                   for v in summaries) for status in STATES}}


def registry_detail(key, state=None):
    import re
    if not isinstance(key, str) or not re.fullmatch('[a-f0-9]{64}', key):
        raise ValueError('invalid compatibility registry key')
    return Registry((Path(state) if state else default_state()) / 'registry.sqlite3').get(key)


def analyze_registry_entry(key, state=None):
    """Reclassify existing evidence without executing or modifying a package."""
    import re
    from .classification import legacy_status, static_state
    from .model import Report
    if not isinstance(key, str) or not re.fullmatch('[a-f0-9]{64}', key):
        raise ValueError('invalid compatibility registry key')
    registry = Registry((Path(state) if state else default_state()) / 'registry.sqlite3')
    value = registry.get(key)
    if value is None:
        raise ValueError('compatibility evidence was not found')
    allowed = Report.__dataclass_fields__
    report = Report(**{name: item for name, item in value.items() if name in allowed})
    report.set_compatibility('ANALYZING', 'ANALYZE',
                             'user requested evidence reclassification')
    runtime = report.runtime_validation
    if isinstance(runtime, dict) and runtime.get('result') == 'PASS':
        state_value = ('COMPATIBLE_WITH_ADAPTER' if runtime.get('functional') is True
                       and report.adaptations else
                       'COMPATIBLE' if runtime.get('functional') is True else
                       'PARTIALLY_COMPATIBLE')
    elif isinstance(runtime, dict) and runtime.get('result') == 'FAIL':
        state_value = ('BLOCKED_BY_PLATFORM' if runtime.get('failure_class') in {
            'CRYPTEX_INSTALL_TIMEOUT', 'CRYPTEX_SERVICE_UNRESPONSIVE'} else
            'ADAPTATION_REQUIRED')
    else:
        state_value = static_state(report)
    if state_value == 'NATIVE_COMPATIBLE' and any(
            issue.get('code') == 'FUNCTIONAL_AUDIT_PENDING' for issue in report.issues):
        state_value = 'UNKNOWN'
    report.set_compatibility(state_value, 'CLASSIFY',
                             'existing evidence reclassified under the current ruleset')
    report.status = legacy_status(state_value)
    registry.save(report)
    return report.to_dict()


def record_runtime_validation(key, evidence, state=None):
    """Attach current install/runtime evidence to an exact registry entry."""
    import re
    import time
    from .classification import legacy_status
    from .model import Report
    if (not isinstance(key, str) or not re.fullmatch('[a-f0-9]{64}', key) or
            not isinstance(evidence, dict)):
        raise ValueError('valid compatibility key and runtime evidence required')
    registry = Registry((Path(state) if state else default_state()) / 'registry.sqlite3')
    value = registry.get(key)
    if value is None:
        raise ValueError('compatibility evidence was not found')
    allowed = Report.__dataclass_fields__
    report = Report(**{name: item for name, item in value.items() if name in allowed})
    report.runtime_validation = evidence
    result = evidence.get('result')
    if result == 'PASS' and evidence.get('functional') is True:
        compatibility = ('COMPATIBLE_WITH_ADAPTER' if report.adaptations
                         else 'COMPATIBLE')
        phase, detail = 'TEST', 'controlled functional runtime probe passed'
        report.validation_timestamp = time.time()
    elif result == 'PASS':
        compatibility = 'PARTIALLY_COMPATIBLE'
        phase, detail = 'TEST', ('loader and target stability passed; package-specific '
                                 'functional UAT remains required')
        report.validation_timestamp = time.time()
    elif result == 'FAIL':
        if evidence.get('failure_class') in {
                'CRYPTEX_INSTALL_TIMEOUT', 'CRYPTEX_SERVICE_UNRESPONSIVE'}:
            compatibility = 'BLOCKED_BY_PLATFORM'
            detail = 'measured Apple Cryptex service is unavailable in this device state'
        else:
            compatibility = 'ADAPTATION_REQUIRED'
            detail = 'runtime failure recorded; repair strategy required'
        phase = 'DIAGNOSE'
    else:
        compatibility = 'TESTING'
        phase, detail = 'TEST', 'installed artifact awaits a runnable controlled target'
    report.set_compatibility(compatibility, phase, detail)
    report.status = legacy_status(compatibility)
    registry.save(report)
    return report.to_dict()


def existing_admission(component, action):
    # No launch adapter currently measures installed artifact identity,
    # environment, current registry state and functional freshness atomically.
    # Historical approval or a matching bundle ID cannot authorize execution.
    return {'allowed': False, 'status': 'UNKNOWN', 'component': component,
            'action': action, 'reason': 'supported current-artifact launch adapter unavailable'}
