# 0-Sky Early Research Splash

The first 0-Sky Link scene is a Start screen. When the researcher taps
**Start Research Security Console**, Link shows this splash and then its
normal research console. The Start screen is shown after iOS/SpringBoard has
made UIKit available; it does not hold up the system UI. The existing
root device bridge serves an authenticated, read-only `/v1/bootsplash/status`
snapshot. A thin loading bar shows how many of the six actual checks have
completed; failures are shown as failures rather than simulated success. The
screen retries the local status request up to three times while
the bridge, pairing worker, and SSH service settle. It always yields to the
normal Link UI within five seconds, including on errors. It does not start,
configure, or grant access to any service.

If a check still needs attention after the retries, Link asks the user to
retry the connection, use the established Mac-side component setup/repair
workflow, or continue for now. The full installer is deliberately presented
as a Mac-side choice because it may replace Cryptexes and restart the research
UI; the splash never starts that installation silently.

The default minimum display is 3000 ms and the hard maximum is 5000 ms. To
override the defaults on a device, create the **nonsecret**, root-owned,
world-readable `/var/jb/etc/0sky-bootsplash.json` (mode `0644`):

```json
{
  "bootsplash": {
    "enabled": true,
    "minimum_display_ms": 3000,
    "maximum_display_ms": 5000,
    "show_uid": true,
    "show_bootstrap": true,
    "show_trusted_host": true,
    "show_ssh": true,
    "show_runtime": true,
    "show_control": true
  }
}
```

Set `enabled` to `false` to have the Start button open the normal Link console
without a splash. The path is
separate from Core's root-only `/var/jb/etc/0sky` directory so the mobile UI
can read this nonsecret display preference. The authenticated bridge token
remains in its existing protected file; do not put it in this configuration.

`ROOT` is the device bridge's effective UID, and `UID` is its real UID. The
mobile app itself does not gain root. `BOOTSTRAP` checks the rootless prefix,
Python, dpkg and its database, Core database, bridge, manager process, bridge
launchd job, and a nonempty token file. `TRUSTED MAC` uses the existing live pairing
decision; an enrolled but offline Mac is `PAIRED`, never `VERIFIED`. `SSH` is
`READY` only after the device-local socket returns an SSH protocol banner on
port 22 or a signed enrollment's configured remote port. No external network
connection is made. The SRD footer is used only if a live paired host supplies
an explicit verified research class; current hosts report `UNKNOWN`, so the
generic 0-Sky footer is expected.

`RUNTIME` and `CONTROL` reuse the bridge's existing runtime health summary:
the manager/ElleKit state and verified 0-Sky Control registration plus mounted
Cryptex. A registered icon alone never counts as active.

The existing persistent 0-Sky bridge starts an isolated launcher after
its authenticated status socket binds. The launcher waits up to 30 seconds
for SpringBoard, asks the existing `uiopen` tool to foreground Link, and
tries at most three times. A kernel boot-time marker limits it to one launch
per boot, even if the bridge restarts. It never blocks the bridge or iOS UI
and honors `enabled: false`. When the launcher opens Link, it stops at the
Start screen until the researcher taps Start. The UIKit screen begins only
after SpringBoard makes rendering available;
Apple boot components and logo resources are never touched.
