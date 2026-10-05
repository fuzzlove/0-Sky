# 0-Sky 1.0.0 pre-release 23

This experimental replacement fixes the next distinct failure observed during
fresh-SRD enrollment on Intel. Pre.22 successfully completed Xcode compilation,
signing, and deterministic Debian package creation, but failed while extracting
the first locked Procursus package.

## Self-contained Zstandard package extraction

- The bundled `dpkg-deb` compatibility helper now stream-decompresses
  `data.tar.zst` and `control.tar.zst` without invoking Homebrew or another
  external `zstd` executable.
- First-runtime sync explicitly executes that signed helper with 0-Sky's
  per-user managed Python environment, whose `zstandard==0.25.0` wheel is
  installed from the signed app's offline wheelhouse.
- Expanded payloads have a 4 GiB safety ceiling and continue through the
  existing path-traversal and escaping-symlink checks.
- Missing Zstandard support now tells the user to choose **Repair → Repair Host
  Dependencies**, then **Resume**, and explicitly says Homebrew is unnecessary.
- Suppressed subprocess failures now retain a bounded output tail so the actual
  dependency, compiler, or archive error appears in private setup logs.
- Release validation now extracts a real locked Procursus `.deb` containing a
  Zstandard tar member under the managed interpreter. A gzip-only synthetic
  probe can no longer mask this failure.

## User action

Install pre.23 over pre.22, keep the same unlocked SRD connected directly by
USB, and press **Resume**. Do not delete the existing device profile, pairing
record, SSH identity, SRDssh Cryptex, Procursus installation, or completed Xcode
outputs. The resumable workflow will verify preserved state and continue from
the first incomplete trusted-runtime stage.

## Evidence boundary

The corrected helper extracted the actual locked
`libgdbm6_1.23_iphoneos-arm64.deb` Zstandard payload without an external decoder.
Automated validation passed 317 tool tests (3 private-fixture skips), 128 host
tool tests (1 external-kit skip), and 33/33 BridgeCore checks. Live Intel Resume,
remaining component deployment, and final health verification are still
required before end-to-end readiness can be claimed.
