# AFC2 validation record

Checkpoint date: 2026-10-03

Target: authorized Apple SRD, `iPhone13,2`, iOS 27.0 build `24A5390f`,
arm64e. Device-unique identifiers are intentionally omitted.

Additional compatibility targets: authorized `iPhone12,8` (iPhone SE 2020)
and `iPad13,8` (iPad Pro), both on OS 27.0 build `24A437`, arm64e. Their exact
artifacts are represented by separate profiles even where system-binary bytes
match. Structural analysis uniquely derived `0xf454`, `0x1b268`, and `0x68`.

The SE inventory also recorded primary dyld shared-cache UUID
`9744B29F-A357-3E7C-892E-BCDA7A909EED` (mapped size `6377472000`). The
`iPhone13,2` profile records UUID `01C9902F-36E8-3CEC-AB61-33FAFE547A30`
(mapped size `6393724928`). Cache UUID mismatch is now a fail-closed preflight
condition.

## What is verified

- Host-side package construction and static checks have passed for generated
  candidates when the exact device-derived inputs are supplied.
- Host tests cover both known exact builds, binary-byte changes, changed binary
  sizes, missing symbols, ambiguous instruction matches, unreviewed/failed
  profiles, stale shared-cache identities, and recomputation under two distinct
  process mappings. All 21 automated tests passed at this checkpoint.
- Generated runtime guards verify the process UUID, shared-cache UUID,
  `__TEXT,__text` containment, and the recorded run-loop, add-entry, and main
  frame-sequence instructions before resolving any current-process address.
- A fresh read-only discovery against the connected SE reproduced the reviewed
  artifact identities and all three offset records byte-for-byte (apart from
  review/package state). The installation preflight selected only the
  `iPhone12,8-24A437` profile and returned `EXACT_BUILD_MATCH`.
- The paired `iPad13,8` on iPadOS 27.0 build `24A437` was subsequently enrolled
  through an exact-UDID USB route and a dedicated Apple-authorized recovery SSH
  Cryptex. Fresh read-only acquisition found `lockdownd` and `afcd` bytes that
  are identical to the reviewed `iPhone12,8-24A437` artifacts. Independent
  semantic discovery reproduced `0xf454`, `0x1b268`, and `0x68`, while recording
  the iPad-specific primary shared-cache UUID
  `6129963B-B820-3B78-9645-F68A002C8B53` and mapped size `6399148032`.
- Exact iPad preflight returned `EXACT_BUILD_MATCH`. The installed 0-Sky runtime
  manager is `2.4.20`; its package and installed manager, appctl, and bridge
  hashes were verified. The manager now inventories every runtime tweak rather
  than collapsing multiple dylibs into one UI row, and package transactions
  pause injection until the replacement runtime Cryptex is ready.
- Two independent causes from the first iPad trials were fixed: runtime sync
  raced package writes, and the generated injected dylibs omitted `LC_UUID`.
  The build no longer uses `-Wl,-no_uuid`, static validation requires an
  `LC_UUID` in every Mach-O slice, and the device installer classifies only
  MobileSubstrate/TweakInject dylibs as injectable (not AFC2's support shim).
- Profile-bound AppSync package SHA-256
  `9bad9561fe86ccbae6de85f59c1017e9f4fe3e8ac0e8d40e51baebddc3c0b250`
  was installed on the iPad. Exact-hash live-load proof passed for both the
  FrontBoard and `installd` dylibs.
- Profile-bound AFC2D package SHA-256
  `a0c0f3daf737130fc716547df4fe9263a7c9f3c023df8c2a8379f3cb08161594`
  was installed on the iPad. Exact-hash live-load proof passed in `lockdownd`,
  and a read-only `com.apple.afc2` probe listed the device root and successfully
  statted `/System/Library/CoreServices/SystemVersion.plist`.
- The combined exact-identity, package-hash, file-hash, apt, registry, live-PID,
  quarantine, and paired-worker verifier returned `INSTALLED_AND_LOADED` for
  both packages. The iPad profile is reviewed, has exact package bindings,
  records device validation `PASS`, and enables dependent functionality.
- Separately, the iPad's supported 0-Sky stack was updated and verified: runtime
  manager `2.4.20`, the current bridge/core modules, 0-Sky Control `3.5.36`
  (`3.5.36.0`), and 0-Sky Link `1.9.0` build `48`. Both apps were registered,
  executable, running, and the authenticated Core status/database checks passed.
- A read-only host smoke test connected to the profile-bound AFC2D service and
  listed root markers including `/Applications`, `/System`, `/private`, `/usr`,
  and `/var`; the matching runtime registry row and dylib hash identify the
  installed variant.

## What is not verified

- The `__DATA_CONST` import-pointer variants in `variants/` are **untested as
  successful fixes**. Earlier test sessions associated with this line of work
  terminated `lockdownd` before service logic with `CODESIGNING: Invalid
  Page`; later trials also showed PAC and memory exceptions.
- No restore/check-in rehearsal, firmware replacement, direct modification of
  Apple system binaries, or fuzzing was performed. Package application remained
  separate from read-only discovery and used the transactional 0-Sky workflow.
- The current checkpoint does not claim a complete AppSync unsigned-app install
  transaction. A controlled 0-Sky Link reinstall reached the live AppSync
  `installd` hook but failed later in the separate custom `appregistrard` nonce
  path. Both AppSync hooks themselves have exact-hash live-load proof.

See `docs/reproducibility/STATE.md` and the sanitized evidence index for the
complete failure/status matrix.
