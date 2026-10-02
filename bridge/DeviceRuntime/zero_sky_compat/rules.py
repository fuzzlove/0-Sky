"""Reusable compatibility rules. Suggestions never authorize privileged execution."""
RULES = {
    'BOOTSTRAP_PATH_FAILURE': {'adapter': 'rootless-v1', 'requires': ['owned-payload-paths', 'verified-bootstrap']},
    'LEGACY_SCRIPT_PATH': {'adapter': 'filesystem-mapper-v1', 'requires': ['typed-script-review', 'runtime-path-discovery']},
    'RPATH_INCORRECT': {'adapter': 'reviewed-source-rebuild', 'requires': ['source-provenance', 'link-validation', 'loader-smoke']},
    'OBSOLETE_REGISTRATION_COMMAND': {'adapter': 'application-registration-backend', 'requires': ['registration', 'discovery', 'launch', 'removal']},
    'MAINTAINER_SCRIPT_REVIEW_REQUIRED': {'adapter': 'maintainer-script-translator', 'requires': ['exact-script-hash', 'typed-operations', 'rollback']},
    'LAUNCHCTL_ABI_INCOMPATIBLE': {'adapter': 'reviewed-service-backend', 'requires': ['rollback', 'endpoint-health', 'restart-validation']},
    'SIGNATURE_INVALID': {'adapter': 'apple-authorized-research-signing', 'requires': ['exact-code-hashes', 'live-device-authorization', 'runtime-signature-check']},
    'DEPENDENCY_MISSING': {'adapter': 'dependency-provider', 'requires': ['version-satisfaction', 'exact-hashes', 'dependency-functional-validation']},
    'XPC_REGISTRATION_FAILED': {'adapter': None, 'requires': ['supported-xpc-endpoint', 'client-communication-test']},
    'SANDBOX_DENIED': {'adapter': None, 'requires': ['supported-api-or-service-contract']},
    'MISSING_ENTITLEMENT': {'adapter': None, 'requires': ['platform-authorized-entitlement']},
}


def suggestions(issues):
    return [{'failure': code, **RULES[code]} for code in sorted({i['code'] for i in issues}) if code in RULES]
