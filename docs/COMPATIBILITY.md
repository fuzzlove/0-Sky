# 0-Sky compatibility engine

The authoritative implementation is `bridge/DeviceRuntime/zero_sky_compat`.
Host and device integrations call this package. Release preparation copies
byte-identical engine modules into both transports and hashes every copy.
There are no package-name exceptions and no compatibility bypass flag.

## Restored SRD installation paths

The researcher selected restoration of the earlier DEB and IPA installers.
The authenticated device bridge again uses Procursus apt/dpkg for DEBs and
the paired Mac worker for IPAs. These routes run outside the compatibility
engine's transactional admission. Successful installation does not create a
compatibility PASS record or establish that arbitrary packages work.

DEBs retain archive, metadata, architecture and dependency checks. IPAs retain
bounded archive validation, signing, exact-device identity, live Apple research
authorization, registration and a foreground launch check. Native installers
use SDK-prepared raw APFS Cryptex assets with verified manifest digests.
Release preparation overlays these restored builders and workers; other
retired entry points keep their admission stops.

Live verification on the repaired SRD installed a data-only DEB and a small
UIKit IPA. The IPA registered in its application container and stayed running
for eight seconds. Reboot persistence and arbitrary tweak/app functionality
were not tested by these fixtures.

## Current support and limitations

This implementation is a conservative compatibility foundation, not a claim
that arbitrary legacy applications or tweaks now work on iOS 27.

| Operation | Current implementation |
| --- | --- |
| Intake | Preserved original, SHA-256, bounded DEB/tar/ZIP/bundle staging; scripts never executed |
| Discovery | Packages, applications, Mach-O, frameworks, services, plugins, bundles, scripts and helpers |
| Environment | Device OS/build/model, architecture, UID/GID, bootstrap, package state, available tools, libraries and frameworks |
| Static checks | Metadata, architecture/platform/minimum OS, load commands, dylibs/RPATHs, signatures/entitlements where tools exist, service plists, script assumptions |
| Rootful adaptation | Payload relocation and plist executable paths that reference owned payload files; reversible, collision checked |
| Dependency resolution | Declared package alternatives/versions and binary dependency edges; unresolved mandatory dependencies block |
| Transactions | Serialized snapshot/install/validate/commit with verified rollback and interrupted-transaction recovery |
| Functional installation | Reviewed data/configuration tree backend only; exact installed content is its functional contract |
| Applications/tweaks/daemons/bootstrap | UNKNOWN, ADAPTATION_REQUIRED, or a specific BLOCKED_BY state until a supported backend supplies snapshot, rollback and functional checks |
| XPC | Requires a protocol-specific adapter; a PID, process lifetime or open socket cannot establish success |
| Unknown APIs/security capabilities | Reported explicitly; no entitlement grants, sandbox modification or Apple-service replacement |
| Control UI | Source integration includes summary and advanced per-artifact diagnostics; new application build/deployment still required |
| Installed audit | Read-only package and unmanaged-component inventory; cannot establish functional PASS |

Developer Mode, SRD policy, RemoteXPC service availability, sandbox policy,
shared-cache contents, authorized entitlements and restart persistence remain
unknown unless an adapter obtains direct evidence. Filesystem presence is not
proof of service or API availability. The local SDK is not an iOS 27 runtime
compatibility oracle.

## Pipeline and evidence

`DISCOVER` → `ANALYZE` → `PLAN` → `ADAPT` → `BUILD` → `INSTALL` →
`TEST` → `DIAGNOSE` → `REPAIR` → `RETEST` → `CLASSIFY`.

`Engine.evaluate()` records `NATIVE_COMPATIBLE`, `ADAPTATION_REQUIRED`,
`BUILD_REQUIRED`, a specific evidence-backed blocker, or `UNKNOWN`. Static
native compatibility still requires installation and runtime testing. The
transaction coordinator admits eligible artifacts only to a trusted backend.
Post-install obligations include dependencies and intended functionality,
plus registration, launch, communication, persistence, XPC exchange, loader
acceptance, sandbox/entitlement acceptance, ownership and privilege contracts
where the component types require them. Failed or unavailable mandatory
checks trigger rollback and preserve diagnostics.

COMPATIBLE and COMPATIBLE_WITH_ADAPTER are issued only after every mandatory
runtime obligation passes. PARTIALLY_COMPATIBLE requires mandatory
functionality to pass and explicit
researcher acknowledgement before commit. Backend code is a reviewed part of
0-Sky; package metadata cannot provide probes, commands, approval tokens or
installation adapters. Native command exit status is not runtime evidence.

The data backend rejects code, bundles, services and Debian package metadata.
It does not run package scripts, register applications or claim tweak support.
New platform backends must be implemented through the same coordinator,
not by adding another installer with its own compatibility decision logic.

## Adapter contract

A reviewed backend implements:

- `eligible(report)` — explicit supported artifact classes;
- `snapshot(work)` — complete, durable, serializable state before mutation;
- `install(staged)` — bounded installation from the analyzed hash;
- `validate(staged, report)` — actual evidence for all derived obligations;
- `rollback(snapshot, work)` — restore exact previous state;
- `verify_rollback(snapshot, work)` — independently compare restored state.

Stateful applications, daemon registries, package-manager databases and
maintainer-script side effects require complete snapshots. Removing a package
is not equivalent to restoring a previous version. Old installation paths are
not called when the required adapter is unavailable.

Generic HTTP and Unix-socket probes perform bounded local protocol exchanges.
HTTP redirects and external endpoints are prohibited. Arbitrary shell probes
are not accepted. An XPC adapter must perform the actual application protocol
exchange and check the expected response.

After a process interruption, a pending journal blocks new mutations. A
reviewed caller invokes `transaction.recover(engine, same_backend)` to restore
and verify the saved snapshot. Failed rollback remains a blocking recovery
condition. No automatic retry repeatedly invokes a known incompatible launch
mechanism.

## Registry and repeatability

Each registry key binds identifier, version, original artifact hash, canonical
environment hash, engine version and complete ruleset source hash. Changing an
artifact, device build, dependencies or ruleset cannot inherit old approval.
Canonical environment models are stored once; component reports refer to their
hash and a concise summary. SQLite retains validation history and deterministic
failure fingerprints. A reused failure signature suggests a generic rule; it
never silently authorizes a new security capability.

Artifacts preserve the original input, staged tree, pre-adaptation backup,
transformation hashes, compatibility manifest and transaction diagnostics.
Installed-source audits never rewrite their inputs. Symlink descriptions from
Procursus dpkg are recognized only when the actual link matches the printed
target. Embedded/mounted service paths with unresolved launch context remain
UNKNOWN instead of being incorrectly reported as missing executables.

## Source installation gates

Control's IPA/DEB requests, host IPA worker, runtime refresh, registration repair,
component activation paths and PoC installation commands are gated. Existing
non-transactional shell installers are retired with a diagnostic failure.
New release kits replace legacy bootstrap, native installation, keeper,
package bridge and runtime-manager entry points with canonical engine guards.
`--force` and request-supplied metadata cannot authorize a legacy path.

Read-only doctor, analysis, registry inspection and registrar inspection remain
available. Disable/removal and recovery operations that do not enable a new
component remain available where their existing safety contract permits them.
Exports with legacy mutation side effects are blocked pending a pure export
adapter.

This is an application-level gate. It does not prevent a researcher with
administrator access from invoking system dpkg, SSH or Apple utilities outside
0-Sky. Historical deployed workers, original vendor kits and already-built IPAs
are not automatically changed by source edits. Rebuild and redeploy them before
claiming a mandatory gate across the installed product. The route auditor
reports that coverage boundary explicitly.

## CLI and tests

From the repository root:

```sh
PYTHONPATH=bridge/DeviceRuntime python3 -m zero_sky_compat \
  --state /path/to/research-state --environment /path/to/device-environment.json \
  analyze /path/to/component --adapter rootless-v1
PYTHONPATH=bridge/DeviceRuntime python3 -m zero_sky_compat \
  --state /path/to/research-state registry
python3 tools/tests/test_compatibility.py
python3 tools/audit_compatibility_routes.py
```

On an already paired SRD, environment detection and installed audits run with
its existing Python interpreter. Audit output and registry data remain local.
No device identifiers, keys, bridge tokens, developer home paths or signing
identities are embedded in release code.

The automated behavior suite covers native data components, legacy rootful and
rootless layouts, missing dependencies, daemon and XPC failures, missing dylibs,
incorrect RPATH, architecture and entitlement mismatches, obsolete paths,
invalid metadata, successful/reversed adaptation, failed install rollback,
reruns, upgraded artifacts, environment changes, interrupted recovery, failed
rollback admission blocking, and Procursus inventory edge cases. These fixtures
do not constitute real-device functional validation of arbitrary packages.

## Existing manual repairs

Observed repairs map to generic failure classes: bootstrap link restoration
(`BOOTSTRAP_PATH_FAILURE`), daemon ABI problems
(`LAUNCHCTL_ABI_INCOMPATIBLE`), runtime library execution trust
(`SIGNATURE_INVALID`), application signing/registration and transport failure.
The existing repair scripts are historical diagnostics/backends, not alternative
compatibility engines. The explicitly restored SRD install paths are documented above; other
retired paths remain blocked until a reviewed adapter can snapshot, validate
and reverse them. No package-specific repair is
promoted to unconditional compatibility approval.
