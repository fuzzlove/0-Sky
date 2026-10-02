"""Evidence based compatibility classification for the v2 engineering pipeline."""
from __future__ import annotations


ADAPTABLE = {
    'BOOTSTRAP_PATH_FAILURE', 'LEGACY_SCRIPT_PATH', 'RPATH_INCORRECT',
    'SIGNATURE_MISSING', 'SIGNATURE_INVALID', 'LAUNCHCTL_ABI_INCOMPATIBLE',
    'MAINTAINER_SCRIPT_REVIEW_REQUIRED', 'INSTALL_ADAPTER_UNAVAILABLE',
    'OBSOLETE_REGISTRATION_COMMAND',
}
BUILD_RELATED = {'SOURCE_REBUILD_REQUIRED', 'UNSUPPORTED_API_SOURCE_PORT_REQUIRED'}
ARCHITECTURE = {'ARCHITECTURE_MISMATCH'}
ENTITLEMENT = {'MISSING_ENTITLEMENT'}
DEPENDENCY = {'DEPENDENCY_MISSING', 'EXECUTABLE_NOT_FOUND'}
PLATFORM = {'UNSUPPORTED_PLATFORM', 'UNSUPPORTED_API', 'ROOT_UNAVAILABLE'}
BROKEN = {'INTAKE_FAILED', 'INVALID_PACKAGE_METADATA', 'MACHO_INVALID',
          'SERVICE_PLIST_INVALID'}
UNSAFE = {'UNSUPPORTED_SECURITY_ASSUMPTION', 'ROLLBACK_FAILED',
          'REPEATED_FAILURE_QUARANTINE'}


def _codes(report, severity=None):
    return {item['code'] for item in report.issues
            if severity is None or item.get('severity') == severity}


def static_state(report):
    """Return a state supported by current static evidence.

    Unknown evidence never becomes a blocker. Concrete failure codes are
    deliberately separated from adaptable assumptions.
    """
    mandatory = _codes(report, 'mandatory')
    unknown = _codes(report, 'unknown')
    if mandatory & UNSAFE:
        return 'UNSAFE_TO_ADAPT'
    if mandatory & BROKEN:
        return 'BROKEN_UPSTREAM'
    if mandatory & ARCHITECTURE:
        return 'BLOCKED_BY_ARCHITECTURE'
    if mandatory & ENTITLEMENT:
        return 'BLOCKED_BY_ENTITLEMENT'
    # Layout, signing and service mechanism failures are investigated before
    # platform/dependency blocks because reviewed adapters may resolve them.
    if (mandatory | unknown) & ADAPTABLE:
        return 'ADAPTATION_REQUIRED'
    if mandatory & BUILD_RELATED:
        return 'BUILD_REQUIRED'
    if mandatory & DEPENDENCY:
        return 'BLOCKED_BY_DEPENDENCY'
    if mandatory & PLATFORM:
        return 'BLOCKED_BY_PLATFORM'
    if mandatory:
        # No rule establishes that this unfamiliar failure is permanent.
        return 'UNKNOWN'
    if unknown:
        return 'UNKNOWN'
    return 'NATIVE_COMPATIBLE'


def runtime_state(report, evidence):
    """Classify failed runtime evidence without turning an unknown into a block."""
    failures = [value for value in evidence.values()
                if isinstance(value, dict) and value.get('passed') is False]
    unknown = [value for value in evidence.values()
               if isinstance(value, dict) and value.get('passed') is not True]
    codes = _codes(report)
    if not failures:
        if unknown:
            return 'UNKNOWN'
        if any(issue.get('severity') == 'optional' for issue in report.issues):
            return 'PARTIALLY_COMPATIBLE'
        return 'COMPATIBLE_WITH_ADAPTER' if report.adaptations else 'COMPATIBLE'
    if codes & UNSAFE:
        return 'UNSAFE_TO_ADAPT'
    if codes & ARCHITECTURE:
        return 'BLOCKED_BY_ARCHITECTURE'
    if codes & ENTITLEMENT:
        return 'BLOCKED_BY_ENTITLEMENT'
    if codes & DEPENDENCY:
        return 'BLOCKED_BY_DEPENDENCY'
    if codes & PLATFORM:
        return 'BLOCKED_BY_PLATFORM'
    # A crash or failed probe with no diagnosed cause remains actionable.
    return 'ADAPTATION_REQUIRED'


def legacy_status(state):
    """Map v2 states for v1 callers while the deployed IPC schema migrates."""
    if state == 'COMPATIBLE':
        return 'PASS'
    if state == 'COMPATIBLE_WITH_ADAPTER':
        return 'ADAPTED'
    if state == 'PARTIALLY_COMPATIBLE':
        return 'DEGRADED'
    if state.startswith('BLOCKED_BY_') or state in {
            'BROKEN_UPSTREAM', 'UNSAFE_TO_ADAPT'}:
        return 'BLOCKED'
    return 'UNKNOWN'
