#!/bin/bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: backup.sh [--repo PATH] [--ref REF] [--output DIR] [--dry-run]

Create a source-only checkpoint archive and SHA-256 sidecar. The archive is
made from Git, so ignored device data, secrets, generated builds, and local
pairing state cannot enter it. The selected ref must resolve to a commit.
EOF
}

repo="$(git rev-parse --show-toplevel 2>/dev/null || true)"
ref="HEAD"
output=""
dry_run=0
while (($#)); do
  case "$1" in
    --repo) repo=${2:?missing path}; shift 2 ;;
    --ref) ref=${2:?missing ref}; shift 2 ;;
    --output) output=${2:?missing directory}; shift 2 ;;
    --dry-run) dry_run=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "error: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done
[[ -n "$repo" && -d "$repo/.git" ]] || { echo "error: --repo is not a Git checkout" >&2; exit 1; }
repo=$(cd "$repo" && pwd -P)
commit=$(git -C "$repo" rev-parse --verify "${ref}^{commit}")
output=${output:-"$repo/checkpoints"}
name="0-sky-${commit:0:12}-source.tar.gz"
archive="$output/$name"

echo "repo=$repo"
echo "ref=$ref"
echo "commit=$commit"
echo "archive=$archive"
if ((dry_run)); then
  echo "DRY_RUN=PASS"
  exit 0
fi

mkdir -p "$output"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/0sky-backup.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
git -C "$repo" archive --format=tar --prefix="0-Sky/" "$commit" > "$tmp/source.tar"
gzip -n -9 < "$tmp/source.tar" > "$tmp/$name"
(
  cd "$tmp"
  shasum -a 256 "$name" > "$name.sha256"
)
mv "$tmp/$name" "$archive"
mv "$tmp/$name.sha256" "$archive.sha256"
(
  cd "$output"
  shasum -a 256 -c "$name.sha256"
)
echo "BACKUP=PASS"
