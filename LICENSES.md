# Licensing and attribution

Installation, access, and use of 0-Sky are governed by the
[`0-Sky End User License Agreement and Authorized Security Research Terms`](bridge/0SkyBridge/Resources/Legal/EULA.md).
Separate open-source components remain governed by their respective licenses
as stated below.

`control/` is derived from TrollStore and is distributed under the license in
`control/LICENSE`; upstream authorship notices are retained in the source.
The vendored `control/ChOma/src` source retains its own upstream notices and
license in `control/ChOma/LICENSE`.

The compiled Bridge runtime uses pinned CPython archives produced by
`astral-sh/python-build-standalone`. CPython is distributed under the Python
Software Foundation License; the build system is under MPL-2.0. The runtime
builder retains CPython, pip/vendor, and build-system license material inside
the packaged runtime. Source provenance and archive hashes are locked in
`manifests/host-runtime-sources.json`; the MPL-2.0 text used by the builder is
retained in `bridge/HostRuntime/LICENSE.python-build-standalone.txt`.

Third-party framework names, SDK interfaces, and dependencies remain the
property of their respective owners and are not relicensed by this repository.
No Apple SDK, Apple SRD binary, provisioning profile, certificate, pairing
record, or third-party binary package is included.

No repository-wide license has been asserted for the independently developed
0-Sky Bridge and 0-Sky Link source in this publication. Their copyright and
reuse terms remain with their respective rights holder unless a component file
states otherwise.
