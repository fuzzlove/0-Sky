# 0-Sky Wi-Fi pairing recovery

The Link pairing request is handled by each enrolled Mac worker. The worker
loads `host-mac/pair.py` from its instance directory. An older bundled helper
did not accept the worker's `remote_port` argument, so the pair job returned
status 125 even though Apple USB trust was valid. The release preparer now
overlays both pairing backends from their canonical HostTools sources, and
`sync_pair_backends.py` updates all existing enrolled Mac workers atomically.

From this `addons/PoC` directory, use the project's pinned Python:

```sh
../../.venv/bin/python sync_pair_backends.py
../../.venv/bin/python sync_pair_backends.py --apply
```

If a specific SRD has verified USB trust but Wi-Fi is not configured, keep
that exact device connected and unlocked. Then run:

```sh
PYTHONPATH=../../bridge/HostTools ../../.venv/bin/python repair_wifi_pairing.py --udid <EXACT-UDID>
```

For a pending `USB_DISCONNECT_REQUIRED` result, disconnect that device's USB
cable and verify over the network:

```sh
PYTHONPATH=../../bridge/HostTools ../../.venv/bin/python repair_wifi_pairing.py --udid <EXACT-UDID> --verify
../../.venv/bin/python verify_wifi_worker.py --udid <EXACT-UDID>
../../.venv/bin/python diagnose_wifi_pairing.py --udid <EXACT-UDID> --allow-wireless
```

The setup step rechecks Apple USB trust and the Mac identity. The verify step
requires an authenticated network transport for the same UDID and host; it
does not treat an enabled setting or connected USB cable as Wi-Fi proof.
`--allow-usb-present` on the verify step still requires a real network
transport and is useful when CoreDevice exposes that path while USB remains
attached. Existing Apple pairing records and SSH authentication policy are
preserved. Repeat runs converge without replacing already aligned workers.
