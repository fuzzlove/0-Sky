# 0-Sky sandboxed process injector

This directory vendors the minimal source needed from
[`opa334/opainject`](https://github.com/opa334/opainject), commit
`6308f6006ee1bf548d5b58bd8ab7fb4e5a687eaf` (MIT license).

0-Sky changes are limited to build portability, truthful error propagation,
and failing closed when a sandbox extension cannot be issued or consumed.
The resulting tool is sealed into the authorized SRD runtime Cryptex and is
only selected for a reviewed runtime adapter with an exact process identity.
