# Environment audit

This inventory was made before the portability refactor. The repository has 323
tracked files and a much larger, locally staged release kit (4,689 paths; 361
manifest-listed files). The staged kit is not in Git. Binary archives were
inspected through their manifests and release staging, not treated as source.

| Finding | Classification | Disposition |
| --- | --- | --- |
| Named developer-machine hostname used as the worker/supervisor fallback | REMOVE | Require an exact configured endpoint; no implicit workstation/device name. |
| `/Users/<user>/...`, personal email, physical UDID, or embedded password in tracked source | RELEASE_SANITIZE | Existing tracked-source audit found none; keep an automated release gate. Test fixtures use synthetic identities. |
| Fixed `/Applications/Xcode.app` and beta paths in CoreDevice/debug probes | DISCOVER_AT_RUNTIME | Resolve the active developer directory with `xcode-select`/`xcrun`. |
| Fixed `/opt/homebrew` and `/usr/local` choices in host tools | DISCOVER_AT_RUNTIME | Resolve from PATH or the selected Homebrew prefix; require version checks. The two paths remain documented search candidates only. |
| `/var/jb`, Apple service paths, SRD Cryptex mount root, bundle IDs, authenticated loopback protocol port 48654 | REQUIRED_CONSTANT | These are protocol/platform locations, not Mac workstation paths. Change only through a versioned protocol migration. |
| Default host SSH port 2222 and VNC probe ports | USER_CONFIGURATION | Port 2222 is a collision-prone proposal, not an immutable device identity. Per-device state must record the selected port. VNC ports are probe targets, never proof of service availability. |
| Per-device UDID, forwarded port, SSH key/pin and host alias | DEVICE_CONFIGURATION / SECRET | Select exact device; keep private key and known-host pin outside source and release artifacts. |
| Signing team, identity, provisioning and Apple SRD assets | BUILD_CONFIGURATION / SECRET | Caller-owned release inputs; no automatic signing downgrade. |
| Home-relative Application Support, cache, log and state paths | DISCOVER_AT_RUNTIME | Resolve from the current account and validated configuration, never a named account. |
| Temporary build workspaces | GENERATED_VALUE | Use system temporary APIs and clean up only owned paths. |
| Duplicate `zero_sky_user_config.py` in source and app resources | BUILD_CONFIGURATION | Treat `bridge/zero_sky_user_config.py` as authoritative; verify/copy it during packaging. |
| Untracked 220 MB Link IPA and other proprietary/vendor kit assets | RELEASE_SANITIZE / BUILD_CONFIGURATION | Manifest-verify caller-supplied kit; versioned portability overrides in `bridge/KitScripts` are applied during release preparation. A clean public checkout cannot produce a complete device release without the separately supplied assets. |
| Arbitrary working-directory assumptions in configuration path resolution | USER_CONFIGURATION | Resolve explicit relative config paths against a documented anchor; discovery itself must use module/bundle roots. |
| Python wheelhouse and Xcode/SDK support | BUILD_CONFIGURATION | Pin and validate versions; report unavailable required versus optional capabilities. |

The first high-confidence release blocker is the absent kit in a clean checkout.
The first source-level machine leak is the named hostname fallback. Fixed paths
in probes also make alternate Xcode/Homebrew installations appear unavailable.

## Findings after the deeper binary scan

An app-wide scan found former builders' `/Users/<redacted>/...` source paths in
12 externally supplied, signed Frida/PreferenceLoader device binaries. The
locally built Mac executable also had DWARF source paths, which can be stripped
from the **unsigned** local build. The external binaries cannot be altered in
place without invalidating their signatures. Release preparation and the Xcode
embed phase now fail on these paths. The external kit must be replaced with
sanitized, correctly signed payloads before a distributable build can pass.
