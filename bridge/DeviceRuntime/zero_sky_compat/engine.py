"""The authoritative compatibility path: intake → analyze → adapt → install → validate."""
from pathlib import Path
import shutil
import uuid
import tarfile
import zipfile
from . import adapters, analysis, intake, transaction
from .classification import legacy_status, static_state
from .discovery import file_hash, tree_hash
from .model import Report
from .planner import plan
from .registry import Registry


class Engine:
    def __init__(self, state, environment):
        self.state = Path(state)
        self.environment = environment
        self.registry = Registry(self.state / 'registry.sqlite3')
        self.registry.save_environment(environment)

    def save(self, report, work):
        from .rules import suggestions
        report.suggested_adapters = suggestions(report.issues)
        report.adaptation_plan = plan(report)
        transaction.atomic_json(Path(work) / 'adaptation-plan.json', report.adaptation_plan)
        transaction.atomic_json(Path(work) / 'compatibility.json', report.to_dict())
        self.registry.save(report)

    def evaluate(self, source, adapter_names=(), dpkg_deb=None):
        work = self.state / 'artifacts' / uuid.uuid4().hex
        try:
            root, source_hash = intake.stage(source, work, dpkg_deb=dpkg_deb)
        except (OSError, ValueError, tarfile.TarError, zipfile.BadZipFile) as error:
            work.mkdir(parents=True, exist_ok=True)
            root = work / 'staged'
            root.mkdir(exist_ok=True)
            original = work / 'original'
            try:
                source_hash = tree_hash(original) if original.is_dir() else file_hash(original)
            except (OSError, ValueError):
                source_hash = 'unavailable'
            report = Report(Path(source).name, 'unknown', source_hash,
                            self.environment.summary(), self.environment.fingerprint)
            report.status = report.preflight = 'BLOCKED'
            report.add('INTAKE_FAILED', '', 'invalid or unsupported artifact: ' + type(error).__name__)
            report.set_compatibility('BROKEN_UPSTREAM', 'ANALYZE',
                                     'artifact intake failed with concrete parser evidence')
            self.save(report, work)
            return report, root, work
        try:
            name, version, meta = analysis.metadata(root)
            if not meta:
                name = Path(source).name
        except (ValueError, OSError):
            name, version = Path(source).name, 'unknown'
        report = Report(name, version, source_hash, self.environment.summary(), self.environment.fingerprint)
        report.set_compatibility('ANALYZING', 'ANALYZE', 'static package analysis started')
        analysis.inspect(root, self.environment, report, dpkg=shutil.which('dpkg'))
        report.set_compatibility(static_state(report), 'CLASSIFY',
                                 'static evidence classified without runtime inference')
        report.status = legacy_status(report.compatibility_state)
        if adapter_names:
            before_state = report.compatibility_state
            report.set_compatibility('ADAPTING', 'ADAPT',
                                     'reviewed adapters: ' + ', '.join(adapter_names))
            try:
                changes = adapters.apply(root, work, self.environment, report, adapter_names)
                # Re-run all analysis, rather than hiding original mandatory issues.
                revised = Report(name, version, source_hash, report.environment, report.environment_hash)
                revised.adaptations = changes
                revised.evidence = list(report.evidence)
                revised.attempt_history = list(report.attempt_history) + [{
                    'attempt': len(report.attempt_history) + 1,
                    'strategy': list(adapter_names), 'before': before_state,
                    'result': 'TRANSFORMED', 'changes': len(changes)}]
                analysis.inspect(root, self.environment, revised, dpkg=shutil.which('dpkg'))
                report = revised
                classified = static_state(report)
                if changes and classified == 'NATIVE_COMPATIBLE':
                    classified = 'TESTING'
                report.set_compatibility(classified, 'CLASSIFY',
                                         'adapted artifact requires functional validation')
                report.status = legacy_status(report.compatibility_state)
            except (OSError, ValueError, RuntimeError) as error:
                report.add('ADAPTATION_FAILED', '', str(error))
                report.attempt_history.append({
                    'attempt': len(report.attempt_history) + 1,
                    'strategy': list(adapter_names), 'before': before_state,
                    'result': 'FAILED', 'error_class': type(error).__name__})
                # A failed strategy is evidence against that strategy, not
                # proof that the package itself is incompatible.
                report.set_compatibility('ADAPTATION_REQUIRED', 'DIAGNOSE',
                                         'reviewed adaptation failed; another plan may be possible')
                report.status = 'UNKNOWN'
        report.staged_hash = tree_hash(root)
        self.save(report, work)
        return report, root, work

    def install(self, source, backend, adapter_names=(), acknowledge_degraded=False):
        report, root, work = self.evaluate(source, adapter_names)
        return transaction.install(self, report, root, work, backend, acknowledge_degraded)

    def audit_tree(self, source, identity=None, version='unknown'):
        # Audit never changes installed files and never launches arbitrary code.
        source = Path(source)
        report = Report(identity or source.name, version, tree_hash(source),
                        self.environment.summary(), self.environment.fingerprint)
        analysis.inspect(source, self.environment, report)
        report.staged_hash = report.source_hash
        report.add('FUNCTIONAL_AUDIT_PENDING', '', 'read-only static audit cannot establish functionality', 'unknown')
        report.set_compatibility('UNKNOWN', 'CLASSIFY',
                                 'installed read-only audit lacks functional evidence')
        self.registry.save(report)
        return report
