"""Durable, serialized transactions. Pending recovery blocks further mutations."""
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import stat
import tempfile
import time
from .discovery import tree_hash
from .classification import legacy_status, runtime_state
from .validation import outcome


def atomic_json(path, value):
    path = Path(path)
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError('transaction journal path cannot be symbolic')
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8',
                                         prefix='.' + path.name + '.pending-',
                                         dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(value, stream, sort_keys=True, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        if path.is_symlink():
            raise ValueError('transaction journal changed to a symbolic link')
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    descriptor = os.open(str(path.parent), os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@contextmanager
def mutation_lock(state):
    state = Path(state)
    if not hasattr(os, 'O_NOFOLLOW') or not hasattr(os, 'O_DIRECTORY'):
        raise RuntimeError('safe transaction locking is unavailable on this platform')
    if state.is_symlink():
        raise ValueError('transaction state directory cannot be symbolic')
    state.mkdir(parents=True, exist_ok=True)
    directory = os.open(str(state), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    descriptor = -1
    try:
        descriptor = os.open('mutation.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW,
                             0o600, dir_fd=directory)
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError('transaction lock must be a regular file')
        with os.fdopen(descriptor, 'r+') as lock:
            descriptor = -1
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(directory)


def install(engine, report, root, work, backend, acknowledge_degraded=False):
    with mutation_lock(engine.state):
        journal = engine.state / 'transaction.json'
        if journal.is_symlink():
            raise ValueError('transaction journal cannot be symbolic')
        if journal.exists():
            existing = json.loads(journal.read_text())
            if existing.get('phase') not in ('COMMITTED', 'ROLLED_BACK'):
                report.add('RECOVERY_REQUIRED', '', 'unfinished transaction blocks installation')
                report.status = 'BLOCKED'
                report.set_compatibility('UNSAFE_TO_ADAPT', 'CLASSIFY',
                                         'unfinished mutation requires verified recovery')
                engine.save(report, work)
                return report
        if report.preflight != 'ELIGIBLE' or not backend.eligible(report):
            report.add('INSTALL_METHOD_UNKNOWN', '',
                       'no verified transactional backend for this artifact', 'unknown')
            if report.compatibility_state in ('NATIVE_COMPATIBLE', 'TESTING'):
                report.set_compatibility('UNKNOWN', 'CLASSIFY',
                                         'installation method requires discovery')
            else:
                report.record('CLASSIFY', report.compatibility_state,
                              'installation method remains unresolved')
            report.status = legacy_status(report.compatibility_state)
            engine.save(report, work)
            return report
        if engine.registry.quarantined(report.key):
            report.add('REPEATED_FAILURE_QUARANTINE', '',
                       'three matching failures for this artifact and environment; no retry')
            report.status = 'QUARANTINED'
            report.set_compatibility('UNSAFE_TO_ADAPT', 'CLASSIFY',
                                     'bounded repair limit reached for identical failure')
            report.transaction = {'phase': 'ADMISSION_BLOCKED', 'backend': backend.name}
            engine.save(report, work)
            return report
        prior = engine.registry.known_failure(report.key, report.staged_hash, backend.name)
        if prior:
            report.status = report.preflight = 'BLOCKED'
            report.add('KNOWN_FAILURE_REUSED', '', 'same artifact, environment, ruleset and backend already failed; no retry')
            report.issues.extend(i for i in prior['issues'] if i not in report.issues)
            report.runtime_validation = prior.get('runtime_validation', {})
            report.set_compatibility(prior.get('compatibility_state',
                                               runtime_state(report, report.runtime_validation)),
                                     'CLASSIFY', 'identical evidence-backed failure reused')
            report.transaction = {'phase': 'ADMISSION_BLOCKED', 'backend': backend.name}
            engine.save(report, work)
            return report
        if tree_hash(root) != report.staged_hash:
            raise ValueError('staged artifact changed after analysis')
        record = {'phase': 'PREPARING', 'report_key': report.key, 'backend': backend.name,
                  'work': str(work.relative_to(engine.state)), 'staged_hash': report.staged_hash}
        atomic_json(journal, record)
        try:
            snapshot = backend.snapshot(work)
            record.update(phase='PREPARED', snapshot=snapshot)
            atomic_json(journal, record)
        except Exception as error:
            # Snapshot is read-only. No device mutation has started.
            record.update(phase='ROLLED_BACK', error=type(error).__name__)
            atomic_json(journal, record)
            raise
        try:
            record['phase'] = 'INSTALLING'
            atomic_json(journal, record)
            report.set_compatibility('TESTING', 'INSTALL',
                                     'transactional backend began installation')
            backend.install(root)
            if tree_hash(root) != report.staged_hash:
                raise ValueError('backend changed staged input')
            record['phase'] = 'VALIDATING'
            atomic_json(journal, record)
            evidence = backend.validate(root, report)
            report.status = outcome(report, evidence)
            report.set_compatibility(runtime_state(report, evidence), 'TEST',
                                     'mandatory runtime evidence evaluated')
            for phase, value in evidence.items():
                if value.get('passed') is False:
                    engine.registry.learn(str(value.get('detail', '')) + '\n' + str(value.get('stderr', '')), phase)
            if report.compatibility_state not in ('COMPATIBLE', 'COMPATIBLE_WITH_ADAPTER') and not (
                report.compatibility_state == 'PARTIALLY_COMPATIBLE' and acknowledge_degraded):
                raise ValueError('functional validation did not authorize commit')
            report.validation_timestamp = time.time()
            report.status = legacy_status(report.compatibility_state)
            record.update(phase='COMMITTED', status=report.status,
                          compatibility_state=report.compatibility_state)
        except Exception as error:
            failure = engine.registry.record_component_failure(report.key, str(error))
            record.update(phase='ROLLING_BACK', failure=failure)
            atomic_json(journal, record)
            try:
                backend.rollback(snapshot, work)
                if not backend.verify_rollback(snapshot, work):
                    raise RuntimeError('rollback state comparison failed')
                record['phase'] = 'ROLLED_BACK'
            except Exception as rollback_error:
                record.update(phase='ROLLBACK_FAILED', error=type(rollback_error).__name__)
            report.status = 'QUARANTINED' if failure['quarantined'] else 'BLOCKED'
            report.add('TRANSACTION_FAILED', '', str(error))
            if failure['quarantined']:
                report.add('REPEATED_FAILURE_QUARANTINE', '',
                           'three matching failures for this artifact and environment; no retry')
                report.set_compatibility('UNSAFE_TO_ADAPT', 'CLASSIFY',
                                         'bounded retry limit reached')
            else:
                report.set_compatibility(runtime_state(report, report.runtime_validation),
                                         'DIAGNOSE', 'runtime failure diagnosed for repair planning')
            if record['phase'] == 'ROLLBACK_FAILED':
                report.add('ROLLBACK_FAILED', '', 'manual recovery required; further installation disabled')
        atomic_json(journal, record)
        report.transaction = {key: value for key, value in record.items() if key != 'work'}
        engine.save(report, work)
        return report


def recover(engine, backend):
    """Roll back an interrupted mutation using the same trusted backend."""
    with mutation_lock(engine.state):
        journal = engine.state / 'transaction.json'
        if journal.is_symlink():
            raise ValueError('transaction journal cannot be symbolic')
        record = json.loads(journal.read_text())
        if record['phase'] in ('COMMITTED', 'ROLLED_BACK'):
            return record
        if record['backend'] != backend.name or 'snapshot' not in record:
            raise RuntimeError('matching backend snapshot required for recovery')
        work = (engine.state / record['work']).resolve()
        if not work.is_relative_to(engine.state.resolve()):
            raise ValueError('invalid recovery workspace')
        backend.rollback(record['snapshot'], work)
        if not backend.verify_rollback(record['snapshot'], work):
            raise RuntimeError('recovery verification failed')
        record['phase'] = 'ROLLED_BACK'
        atomic_json(journal, record)
        return record
