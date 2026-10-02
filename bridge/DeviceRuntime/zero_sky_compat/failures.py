"""Deterministic failure taxonomy; fingerprints contain no developer/device PII."""
import re
from .model import digest

PATTERNS = (
    ('LAUNCHCTL_ABI_INCOMPATIBLE', r'launchctl.*(?:symbol not found|missing symbol)|_launch_active_user_switch'),
    ('DYLD_FAILURE', r'dyld.*(?:symbol not found|missing symbol)'),
    ('DEPENDENCY_MISSING', r'library not loaded|cannot open shared object|image not found'),
    ('SANDBOX_DENIED', r'sandbox.*deny|operation not permitted.*sandbox'),
    ('XPC_REGISTRATION_FAILED', r'xpc.*(?:registration failed|connection invalid|connection interrupted)'),
    ('SERVICE_REGISTRATION_FAILED', r'bootstrap failed|service.*registration failed'),
    ('MISSING_ENTITLEMENT', r'missing.*entitlement|required entitlement'),
    ('ARCHITECTURE_MISMATCH', r'bad cpu type|wrong architecture|architecture mismatch'),
    ('SIGNATURE_INVALID', r'code signature invalid|invalid code signature'),
    ('PERMISSION_FAILURE', r'permission denied'),
    ('EXECUTABLE_NOT_FOUND', r'no such file or directory|executable not found'),
)


def fingerprint(text, phase='runtime'):
    lowered = str(text).lower()
    codes = sorted({code for code, pattern in PATTERNS if re.search(pattern, lowered)})
    if not codes:
        codes = ['UNCLASSIFIED_FAILURE']
    return {'codes': codes, 'phase': phase, 'fingerprint': digest([phase, codes])}
