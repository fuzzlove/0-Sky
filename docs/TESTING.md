# Compatibility testing

Run the scanner and its unit tests:

```sh
python3 tools/ios27_compat_pipeline.py
python3 -m unittest tools.tests.test_ios27_build \
  tools.tests.test_ios27_compat_pipeline \
  tools.tests.test_compatibility tools.tests.test_compatibility_integration
```

The tests cover deterministic IDs and reports, PII redaction, malformed daemon
plists, dependency ordering/cycles, and fail-closed repository admission.
Archive fixtures cover DEB traversal, symlink entries, malformed metadata,
control-archive scripts and their exact-hash review gate, IPA archive faults,
and catalog symlinks that escape the selected checkout. The scanner records
maintainer-script path and command references without executing scripts.
Existing compatibility tests cover intake, unknown methods, state transitions,
shared rootless adaptation, evidence-specific architecture and entitlement
blocks, bounded repair, parallel batch analysis, rollback, and registry
behavior. A regression asserts that unknown evidence cannot produce an
incompatible or blocked state. These tests do not substitute for on-device
smoke and UAT.
The admission tests also cover exact-hash evidence receipts, missing stage
artifacts, and refusal after an evidence file or review pin changes.
The toolkit tests also reject duplicate package identities and require the
overall result to include failures from both smoke and UAT suites.

Run the installed toolkit suite on each USB-connected, paired SRD with its
exact worker instance. The host runner verifies USB identity, uses the pinned
paired SSH profile, stores the full response in a private JSON file, and
prints only counts and the strict combined result:

```sh
./.venv/bin/python addons/PoC/run_toolkit_device_uat.py \
  --udid "$AUTHORIZED_SRD_UDID" \
  --instance-name "$PAIRED_WORKER_INSTANCE" \
  --output artifacts/compatibility/uat/device.json
```

The command returns status 2 if the result is not PASS. Skipped UAT cases stay
skipped. The host independently recomputes the overall result because older
device runtimes reported only the UAT result even when smoke failed.
The runner also retrieves the current 0-Sky Control toolkit inventory after
the suite, so each receipt includes the component badges and separate
installation, compatibility, runtime, smoke, and UAT facets.
If LaunchServices inventory is unavailable, app installation state remains
UNKNOWN and GUI smoke is BLOCKED. The rest of the toolkit inventory remains
available so a single app-discovery failure cannot erase package or CLI state.

For a focused, non-destructive launch check of an explicitly reviewed app,
use `addons/PoC/verify_gui_launch.py` with the exact USB UDID, paired instance,
one allowlisted bundle ID, and an output JSON path. The probe checks
registration, bundle identity, executable hash, process appearance, and ten
seconds of survival. It does not test app features or package transactions.
`addons/PoC/verify_sileo_preflight.py` separately checks source file
persistence, folder ownership, and one simulated authenticated APT plan.
`PLAN_READY` proves the delegated planning path, not the in-app confirmation
flow or package installation.

Export a reviewer bundle from the device receipts with
`python3 tools/export_toolkit_uat.py --receipt DEVICE1.json --receipt DEVICE2.json
--output NEW_DIRECTORY`. The exporter checks exact-device references, recomputes
the combined result, separates every component and test case into JSON files,
and rejects PII before publishing. An exit status of 2 means the bundle was
created but its automated result is not PASS. The bundle never marks release
acceptance; a researcher must review it.

For each installed package, record the exact device model, iOS build, source
hash, package hash, dependencies, registration, runtime probe, smoke case, UAT
case, crash observations, and rollback result. Mark skipped stages explicitly
and keep admission blocked. Device tests must target only the authorized SRD or
the controlled 0-Sky test application.
