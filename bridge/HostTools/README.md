# 0-Sky Bridge host pairing sources

These are the auditable pairing/trust components used by the complete binary
release. `multi_host_pairing.py` creates and approves signed public-only
requests for an additional Mac. `pair.py` atomically migrates and merges the
device-side trusted-Mac registry. They require the complete release's pinned
Python environment and device Kit; this source tree intentionally excludes
keys, pairing records, credentials, personalized assets, and binary payloads.
