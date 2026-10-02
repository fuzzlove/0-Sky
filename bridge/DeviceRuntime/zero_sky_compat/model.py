"""Versioned compatibility evidence. Unknown is never equivalent to healthy."""
from dataclasses import asdict, dataclass, field
import hashlib
import json
from pathlib import Path

ENGINE_VERSION = '2.0'
RULESET_HASH = hashlib.sha256(b''.join(p.name.encode() + b'\0' + hashlib.sha256(p.read_bytes()).digest() for p in sorted(Path(__file__).parent.glob('*.py')))).hexdigest()
# ``status`` is retained as the transaction result for compatibility with
# deployed v1 clients.  ``compatibility_state`` is the authoritative v2 state.
# An unfamiliar method or environment is always UNKNOWN until evidence moves it.
STATES = (
    'UNKNOWN', 'ANALYZING', 'NATIVE_COMPATIBLE', 'ADAPTATION_REQUIRED',
    'ADAPTING', 'BUILD_REQUIRED', 'TESTING', 'COMPATIBLE',
    'COMPATIBLE_WITH_ADAPTER', 'PARTIALLY_COMPATIBLE',
    'BLOCKED_BY_DEPENDENCY', 'BLOCKED_BY_PLATFORM',
    'BLOCKED_BY_ENTITLEMENT', 'BLOCKED_BY_ARCHITECTURE',
    'BROKEN_UPSTREAM', 'UNSAFE_TO_ADAPT',
)

PIPELINE = ('DISCOVER', 'ANALYZE', 'PLAN', 'ADAPT', 'BUILD', 'INSTALL',
            'TEST', 'DIAGNOSE', 'REPAIR', 'RETEST', 'CLASSIFY')


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


@dataclass
class Environment:
    ios_version: str = 'unknown'
    build_version: str = 'unknown'
    device_model: str = 'unknown'
    architecture: str = 'unknown'
    bootstrap_type: str = 'unknown'
    bootstrap_prefix: str = '/var/jb'
    uid: object = None
    gid: object = None
    capabilities: dict = field(default_factory=dict)
    packages: dict = field(default_factory=dict)
    libraries: list = field(default_factory=list)
    frameworks: list = field(default_factory=list)
    evidence: dict = field(default_factory=dict)

    def canonical(self):
        # Probe timestamps and raw logs do not invalidate identical environments.
        value = asdict(self)
        value.pop('evidence')
        return value

    def summary(self):
        value = self.canonical()
        for field in ('packages', 'libraries', 'frameworks'):
            value.pop(field)
        return value

    @property
    def fingerprint(self):
        return digest(self.canonical())


@dataclass
class Issue:
    code: str
    path: str
    detail: str
    severity: str = 'mandatory'


@dataclass
class Report:
    component: str
    version: str
    source_hash: str
    environment: dict
    environment_hash: str
    engine_version: str = ENGINE_VERSION
    ruleset_hash: str = RULESET_HASH
    status: str = 'UNKNOWN'
    compatibility_state: str = 'UNKNOWN'
    pipeline_phase: str = 'DISCOVER'
    preflight: str = 'UNKNOWN'
    root_requirement: str = 'UNKNOWN_ROOT_REQUIREMENT'
    root_reasons: list = field(default_factory=list)
    issues: list = field(default_factory=list)
    adaptations: list = field(default_factory=list)
    dependencies: list = field(default_factory=list)
    assumptions: list = field(default_factory=list)
    suggested_adapters: list = field(default_factory=list)
    components: list = field(default_factory=list)
    runtime_validation: dict = field(default_factory=dict)
    transaction: dict = field(default_factory=dict)
    staged_hash: str = ''
    validation_timestamp: object = None
    adaptation_plan: dict = field(default_factory=dict)
    attempt_history: list = field(default_factory=list)
    evidence: list = field(default_factory=list)

    def add(self, code, path, detail, severity='mandatory'):
        self.issues.append(asdict(Issue(code, path, detail, severity)))

    def record(self, phase, result, detail='', **fields):
        if phase not in PIPELINE:
            raise ValueError('invalid compatibility pipeline phase: ' + str(phase))
        self.pipeline_phase = phase
        event = {'sequence': len(self.evidence) + 1, 'phase': phase,
                 'result': result, 'detail': str(detail)[:2048]}
        event.update(fields)
        self.evidence.append(event)
        return event

    def set_compatibility(self, state, phase=None, detail=''):
        if state not in STATES:
            raise ValueError('invalid compatibility state: ' + str(state))
        self.compatibility_state = state
        if phase:
            self.record(phase, state, detail)
        return state

    def to_dict(self):
        return asdict(self)

    @property
    def key(self):
        return digest([self.component, self.version, self.source_hash,
                       self.environment_hash, self.engine_version, self.ruleset_hash])
