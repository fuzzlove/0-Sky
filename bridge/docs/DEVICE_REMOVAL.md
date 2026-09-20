# Exact-device removal

0-Sky Bridge service protocol 1.1.2 exposes a typed exact-device removal
operation. The Devices detail panel, device-list context menu, and sidebar
context menu invoke it only after explicit confirmation.

The removal manager validates both the selected UDID and instance name,
serializes the operation against other device work, stops only the selected
instance's four 0-Sky LaunchAgents, and removes its local instance,
public-profile, runtime-state, trust-receipt, and transport-capability files.
It does not run SSH and cannot change the Apple device. It preserves shared SSH
keys, all research sessions and exports, diagnostics, logs, other device
profiles, and unrelated processes. Removal is rejected while the selected
device has an active research session.

The event bus publishes `DEVICE_REMOVAL_STARTED`, `DEVICE_REMOVED`, or
`DEVICE_REMOVAL_FAILED`. A physically attached device is hidden from the
current UI until detached; reconnecting it permits intentional enrollment
again.
