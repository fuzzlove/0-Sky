# Preserved AFC2 variants

These sources are forensic research inputs, not release candidates.

| Variant | SHA-256 | Status |
| --- | --- | --- |
| `import-pointer-v1/afc2dService.xm` | `18cfdf1a6357283d0f0a13d88eae12a0f9ddcb2c0cbc235de73204a5f72bcc0e` | Failed in associated trial: `CODESIGNING: Invalid Page`; service logic not reached |
| `import-pointer-v2/afc2dService.xm` | `1e772db601b48fbf14e53a54ab6a18755f8b5f65579cf2cde5f02880eb0774ee` | Failed in associated trial: `CODESIGNING: Invalid Page`; service logic not reached |

Both variants gate on the exact `lockdownd` UUID and attempt to replace an
import pointer in `__DATA_CONST`. Variant v1 additionally checks that the
existing pointer matches `dlsym` resolution. Neither is verified working on
the supported build.
