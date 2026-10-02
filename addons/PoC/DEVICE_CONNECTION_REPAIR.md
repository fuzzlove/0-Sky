# Repeatable device connection and Core repair

Run from this directory using the project's pinned Python:

```sh
../../.venv/bin/python repair_device_connection.py --all --repair
```

For one device:

```sh
../../.venv/bin/python repair_device_connection.py --udid DEVICE_UDID --repair
```

Each device runs in a separate process. The command verifies its Apple-paired USB identity, exact-device tunnel, pinned SSH host key, root login, signed pairing registry, fresh worker heartbeat, and authenticated Core status and control-center summary. Disconnected devices are reported as `OFFLINE`; a failure does not prevent checking the other devices. Results are saved in `connection-repair/devices.json` and per-device `connection.json` files. Exit status is zero only when all selected devices pass.

The repair aligns the worker interpreter, key fingerprint, SSH settings, and instance configuration. It preserves compatible interpreters and keeps the local forwarding port separate from the device's remote SSH port. Existing profiles default to remote port 22; corrected recovery services use 22022. Repeated repairs preserve aligned configuration and do not restart its worker. Configuration changes have private backups and rollback on restart failure.

## SSH recovery on research devices

The old SRD Dropbear implementation checked only its sealed image key whenever that file existed. Adding a different Mac key to `authorized_keys` therefore did not restore access. The corrected implementation tries the sealed root key first, then permission-validated home authorized keys.

For an Apple-authorized research device with this failure:

```sh
../../.venv/bin/python repair_device_connection.py --udid DEVICE_UDID --repair --recover-ssh
```

The command installs or reuses an isolated corrected SSH service on port 22022. It uses exact-device USB identity, a fresh research nonce, and Apple TSS authorization. Before changing the persistent route, it proves root login using the existing host-key pin and this Mac's private key. The original SSH runtime remains installed. Only the public key is placed in the device image. Recovery does not request a device reboot.

A bridge whose source differs from the current version is updated with a root backup, import validation, and health rollback. If required, the repair installs the verified SRD launch helper through the same Apple research authorization. It loads the bridge's KeepAlive service, creates that root job for older Mac-managed deployments when absent, and replaces only an exact matching stale bridge process. Existing trusted Macs are preserved. The same command aligns each configured worker's native installers with source, backing up changed files and leaving identical files alone.

Password-based enrollment remains available for SSH servers that support normal authorized keys:

```sh
../../.venv/bin/python repair_device_connection.py --udid DEVICE_UDID --repair --authorize-password
```

The hidden dialog asks for the device's root SSH password. It does not save the password or include it in reports. The older temporary key-enrollment job cannot fix the sealed-key lookup bug and is no longer the `--recover-ssh` implementation.

## Validation and current result

```sh
../../.venv/bin/python -m unittest test_srdssh_key_sources test_device_connection_repair test_ssh_tunnel_ports
../../.venv/bin/python -m unittest discover -s ../../bridge/Tests/HostToolsTests -p test_pairing_binding.py
```

The tests cover key-source selection and permissions, exact device and remote-port isolation, worker environment isolation, configuration rollback and idempotence, and key-enrollment transactions.

Both configured devices passed strict root SSH, authenticated fresh worker heartbeats, and HTTP 200 responses for `getStatus` and `getControlCenterSummary`:

- `<SRD_UDID>`: local port 2227 forwards to corrected remote SSH port 22022; bridge updated to support the current pairing registry.
- `<SECOND_SRD_UDID>`: existing remote port 22 retained.

Both Core databases report integrity `ok`. Core's crash and tweak-conflict notices are separate from connection availability. Refresh or reopen 0-Sky Control to retrieve the repaired summary. The recovery services are installed persistently, but a device reboot after the final changes has not been tested.

## Install error 125 after a bridge update

Bridge and worker deployment must include the adjacent `zero_sky_compat` package. A bridge-only update left that package missing, causing DEB and IPA admission to raise `ModuleNotFoundError` and return status 125. `--repair` now validates and synchronizes the dependency package on the device and beside the per-device Mac worker. Package imports are validated before replacement; a repeated deployment does not change matching files.

The researcher selected restoration of the earlier SRD DEB and IPA installers. The bridge's blanket admission stops and the worker's IPA/runtime-sync stops were removed. Other compatibility diagnostics and retired entry-point guards remain. Installation success does not issue a compatibility PASS record for arbitrary apps or tweaks.

The old image builder also sent a compressed UDZO image that current cryptexd rejected while mounting. Native builders now use the SDK's raw sealed APFS Cryptex assets, verify their manifest digests, and obtain fresh Apple research authorization for the exact device. A process-local HTTP/2 flow-control correction handles the larger image transfer without changing installed dependencies.

Live tests on `<SRD_UDID>` returned HTTP 200 and status 0 for both formats: a data-only DEB installed its expected marker, and a UIKit IPA registered in its MCM application container and remained running for eight seconds. The temporary package, app and its dedicated Cryptex were subsequently removed. Reports are in `installer-verification/deb-result.json`, `ipa-result.json` and `cleanup-result.json`. Failed UI attempts may delete temporary inputs; select the original DEB/IPA files again before retrying.

### LZMA/BZIP2 IPA and TIPA archives

Another status 125 on `TRApp_4.7-3658.tipa` occurred before signing: macOS `ditto` rejected its ZIP LZMA compression. The worker now normalizes LZMA and BZIP2 ZIP members to Deflate before extraction, preserving payload bytes, Unix modes (including symlinks), names, timestamps and comments. Existing Stored/Deflate archives remain unchanged. Conversion is streamed, bounded, checked for sufficient host space and replaced atomically; failures preserve the original archive and clean temporary files. The original 401-entry archive passed byte-for-byte inventory comparison and `ditto` extraction. Reports are in `installer-verification/tipa-compression/report.json`; regression checks are in `test_ipa_compression.py`.

`--all --repair` also applies the archive fix to older configured workers. Release preparation already overlays the updated canonical worker for future devices.

Retrying the original `TRApp_4.7-3658.tipa` on `<SECOND_SRD_UDID>` returned HTTP 200/status 0 in 91 seconds. `wiki.qaq.trapp` registered in its MCM bundle, remained running for eight seconds, and published both PluginKit extensions. Three embedded frameworks were preserved. This was the requested app, so it remains installed. The authenticated installer result is saved in `installer-verification/latest-retry.json`.

### TrollRecorder signature and daemon setup

The first successful install still showed TrollRecorder's “Invalid code signature” screen. The package's main and helper entitlements were intact, but the worker had not created TrollStore's `_TrollStore` ownership marker in the MCM **container root**. The worker now preserves each helper's original CodeDirectory identifier when signing and creates the empty marker only after checking both MCM bundle identifiers and matching the installed executable to the mounted Cryptex. It never writes inside the signed app to add the marker. Removing the one-off marker and reinstalling `TRApp_4.7-3658.tipa` proved that the updated worker created it automatically in a new container; the signature screen did not return.

TrollRecorder's own log then identified the daemon failure: from its foreground app process it repeatedly attempted to spawn `TRCallMonitor` and received `Operation not permitted`. The SRD's Procursus `launchctl` also crashed on an unavailable `_launch_active_user_switch` symbol. On the connected SRD, the broken binary was backed up and replaced byte for byte with the already mounted, signed SRD `launchctl-srd` helper. The installer now uses that verified helper directly to install or refresh `wiki.qaq.trservices` as a root launchd job for `wiki.qaq.trapp`. It verifies the MCM container, ownership marker and helper bytes against the mounted Cryptex before creating the job, and replaces the job's executable path when a reinstall changes the MCM UUID.

On `<SECOND_SRD_UDID>`, two replacement installs returned HTTP 200/status 0. The second replacement changed the MCM path (redacted); the managed job changed to that exact path and launched `TRCallMonitor` with a new PID. The app showed its normal Recordings screen after both installs, with neither the signature nor daemon setup error. The latest screen is `installer-verification/trollrecorder-verified-screen.png`. The local 0-Sky pairing heartbeat was refreshed after worker restarts; both authenticated Core operations again returned HTTP 200 and database integrity `ok`. The same worker changes are installed in both configured Mac device profiles and in the canonical release worker.

The second SRD, `<SRD_UDID>`, was subsequently connected over its pinned SSH route. Its Mac worker had logged transport resets; a device-specific `--repair` refreshed the worker heartbeat and both authenticated Core operations returned HTTP 200. Retrying the same `TRApp_4.7-3658.tipa` then returned HTTP 200/status 0 in 84.8 seconds. Its managed `wiki.qaq.trservices` job is loaded and runs `TRCallMonitor` from the newly registered MCM container, and the app shows the normal Recordings screen in `installer-verification/trollrecorder-second-srd-screen.png`. The original on-screen installer error text was not captured before this successful retry. Reboot persistence and actual call recording have not been tested on either device.
