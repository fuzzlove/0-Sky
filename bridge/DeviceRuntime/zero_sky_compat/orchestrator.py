"""Analyze, adapt, test and repair packages through one compatibility path."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
import threading

from . import analysis, adapters
from .classification import static_state
from .engine import Engine
from .environment import detect
from .failures import fingerprint
from .planner import plan
from .registry import Registry


class PackageAnalyzer:
    def analyze(self, root, environment, report):
        return analysis.inspect(root, environment, report)


class BinaryAnalyzer:
    def results(self, report):
        return [item for item in report.components if item.get('kind') == 'macho']


class DependencyResolver:
    def results(self, report):
        return list(report.dependencies)


class EnvironmentProfiler:
    def profile(self):
        return detect()


class FilesystemMapper:
    def available(self, report):
        return any(item.get('code') == 'BOOTSTRAP_PATH_FAILURE'
                   for item in report.issues)


class EntitlementAnalyzer:
    def results(self, report):
        return [item for item in report.issues if 'ENTITLEMENT' in item['code']]


class HookAnalyzer:
    MARKERS = ('MobileSubstrate', 'Substitute', 'ElleKit', 'libhooker')

    def results(self, report):
        return [item for item in report.components
                if any(marker in item.get('path', '') for marker in self.MARKERS)]


class DaemonAnalyzer:
    def results(self, report):
        return [item for item in report.components if item.get('kind') == 'service']


class APICompatibilityAnalyzer:
    def results(self, report):
        return [item for item in report.issues
                if item['code'] in {'UNSUPPORTED_API', 'UNSUPPORTED_PLATFORM'}]


class AdaptationPlanner:
    def create(self, report):
        return plan(report)


class PackageTransformer:
    REVIEWED = frozenset({'rootless-v1'})

    def strategies(self, report):
        requested = [item['adapter'] for item in plan(report)['adaptations']]
        return [name for name in requested if name in self.REVIEWED]


class BuildManager:
    """Runs only a caller supplied reviewed build function.

    Build instructions from package metadata are never executed.
    """
    def build(self, source, builder=None):
        if builder is None:
            return None
        artifact = Path(builder(Path(source))).resolve(strict=True)
        if artifact.is_symlink():
            raise ValueError('reviewed builder returned a symbolic artifact')
        return artifact


class Installer:
    def install(self, engine, source, backend, adapters=()):
        return engine.install(source, backend, adapters)


class RuntimeTester:
    def summarize(self, report):
        return dict(report.runtime_validation)


class CrashAnalyzer:
    def diagnose(self, detail, phase='runtime'):
        return fingerprint(detail, phase)


class RepairEngine:
    def __init__(self, maximum_attempts=3):
        if not 1 <= maximum_attempts <= 5:
            raise ValueError('repair attempt limit must be between one and five')
        self.maximum_attempts = maximum_attempts

    def may_retry(self, history, strategy):
        frozen = tuple(strategy)
        return (len(history) < self.maximum_attempts and
                all(tuple(item.get('strategy', ())) != frozen for item in history))


class CompatibilityDatabase:
    def __init__(self, path):
        self.registry = Registry(path)


class EvidenceRecorder:
    def events(self, report):
        return list(report.evidence)


@dataclass
class PipelineResult:
    report: object
    work: Path


class CompatibilityEngine:
    """Permanent compatibility engineering layer for current and future inputs."""
    def __init__(self, state, environment, maximum_attempts=3):
        self.engine = Engine(state, environment)
        self.environment = environment
        self.package_analyzer = PackageAnalyzer()
        self.binary_analyzer = BinaryAnalyzer()
        self.dependency_resolver = DependencyResolver()
        self.environment_profiler = EnvironmentProfiler()
        self.filesystem_mapper = FilesystemMapper()
        self.entitlement_analyzer = EntitlementAnalyzer()
        self.hook_analyzer = HookAnalyzer()
        self.daemon_analyzer = DaemonAnalyzer()
        self.api_analyzer = APICompatibilityAnalyzer()
        self.adaptation_planner = AdaptationPlanner()
        self.transformer = PackageTransformer()
        self.build_manager = BuildManager()
        self.installer = Installer()
        self.runtime_tester = RuntimeTester()
        self.crash_analyzer = CrashAnalyzer()
        self.repair_engine = RepairEngine(maximum_attempts)
        self.database = CompatibilityDatabase(self.engine.state / 'registry.sqlite3')
        self.evidence_recorder = EvidenceRecorder()
        self._device_lock = threading.Lock()

    def analyze(self, source):
        report, _, work = self.engine.evaluate(source)
        return PipelineResult(report, work)

    def process(self, source, backend=None, builder=None, repair_strategies=()):
        """Run a bounded pipeline; absent methods stay UNKNOWN."""
        first = self.analyze(source)
        report = first.report
        artifact = Path(source)
        if report.compatibility_state == 'BUILD_REQUIRED':
            built = self.build_manager.build(artifact, builder)
            if built is None:
                report.record('BUILD', 'BUILD_REQUIRED',
                              'reviewed build recipe is unavailable')
                self.engine.save(report, first.work)
                return first
            artifact = built
            report.record('BUILD', 'PASS', 'reviewed builder produced an artifact')
        strategies = self.transformer.strategies(report)
        if report.compatibility_state == 'ADAPTATION_REQUIRED' and not strategies:
            report.record('PLAN', 'ADAPTATION_REQUIRED',
                          'no reviewed adapter implements the generated plan')
            self.engine.save(report, first.work)
            return first
        if backend is None:
            report.add('INSTALL_METHOD_UNKNOWN', '',
                       'no installation backend was discovered for this environment', 'unknown')
            if report.compatibility_state in ('NATIVE_COMPATIBLE', 'TESTING'):
                report.set_compatibility('UNKNOWN', 'INSTALL',
                                         'installation method is not yet known')
            else:
                report.record('INSTALL', report.compatibility_state,
                              'installation deferred until a backend is discovered')
            self.engine.save(report, first.work)
            return first
        with self._device_lock:
            installed = self.installer.install(self.engine, artifact, backend, strategies)
        result = PipelineResult(installed, first.work)
        if (installed.compatibility_state == 'ADAPTATION_REQUIRED' and
                repair_strategies):
            return self.repair(artifact, backend, repair_strategies,
                               prior=installed)
        return result

    def repair(self, source, backend, strategies, prior=None):
        """Try distinct reviewed strategies, stopping at the bounded limit."""
        history = list(getattr(prior, 'attempt_history', []))
        last = prior
        last_work = self.engine.state
        for strategy in strategies:
            names = list(strategy)
            if not self.repair_engine.may_retry(history, names):
                continue
            with self._device_lock:
                current = self.installer.install(self.engine, source, backend, names)
            history.append({'attempt': len(history) + 1, 'strategy': names,
                            'result': current.compatibility_state})
            current.attempt_history = list(history)
            current.record('RETEST', current.compatibility_state,
                           'distinct reviewed repair strategy tested')
            self.engine.registry.save(current)
            last = current
            if current.compatibility_state in {
                    'COMPATIBLE', 'COMPATIBLE_WITH_ADAPTER',
                    'PARTIALLY_COMPATIBLE'} or current.compatibility_state.startswith('BLOCKED_BY_'):
                break
        if last is None:
            result = self.analyze(source)
            last, last_work = result.report, result.work
        return PipelineResult(last, last_work)

    def analyze_batch(self, sources, workers=4):
        """Parallelize read-only analysis; callers serialize later mutations."""
        sources = [Path(item) for item in sources]
        if not 1 <= workers <= 16:
            raise ValueError('batch worker count must be between one and sixteen')
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(self.analyze, sources))
        return sorted(results, key=lambda item: (item.report.component,
                                                  item.report.source_hash))
