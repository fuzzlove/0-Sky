#!/bin/bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: restore.sh --source PATH_OR_URL --dest PATH [options]

Options:
  --ref REF                 Checkout this tag/commit (default: HEAD).
  --dry-run                 Print and validate the plan without writing.
  --prepare-external        Clone and patch pinned appregistrard and srdzsh.
  --create-venv             Create .venv and install pinned requirements.
  --python PATH             Python 3.12 interpreter for --create-venv.
  --afcd-input PATH         Exact iPhone13,2/24A5390f afcd input.
  --lockdownd-input PATH    Exact iPhone13,2/24A5390f lockdownd input.
  --build-afc2              Run the host-only AFC2 make check.

This script never pairs, installs, reboots, restores, or changes an SRD.
Device-changing work is intentionally a separate, explicit operator step.
EOF
}

source_path=""; dest=""; ref="HEAD"; dry_run=0; prepare_external=0
build_afc2=0; afcd_input=""; lockdownd_input=""
create_venv=0; python_bin="python3.12"
while (($#)); do
  case "$1" in
    --source) source_path=${2:?missing source}; shift 2 ;;
    --dest) dest=${2:?missing destination}; shift 2 ;;
    --ref) ref=${2:?missing ref}; shift 2 ;;
    --dry-run) dry_run=1; shift ;;
    --prepare-external) prepare_external=1; shift ;;
    --create-venv) create_venv=1; shift ;;
    --python) python_bin=${2:?missing interpreter}; shift 2 ;;
    --afcd-input) afcd_input=${2:?missing path}; shift 2 ;;
    --lockdownd-input) lockdownd_input=${2:?missing path}; shift 2 ;;
    --build-afc2) build_afc2=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "error: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done
[[ -n "$source_path" && -n "$dest" ]] || { usage >&2; exit 2; }

need() { command -v "$1" >/dev/null || { echo "error: missing dependency: $1" >&2; exit 1; }; }
for tool in git python3 shasum xcodebuild xcrun; do need "$tool"; done
sdk=$(xcrun --sdk iphoneos --show-sdk-version)
[[ "$sdk" == 26.5* ]] || { echo "error: expected iPhoneOS SDK 26.5, found $sdk" >&2; exit 1; }
if [[ -e "$dest" && ! -d "$dest/.git" ]]; then
  echo "error: existing destination is not a Git checkout: $dest" >&2
  exit 1
fi

echo "source=$source_path"
echo "destination=$dest"
echo "ref=$ref"
echo "iphoneos_sdk=$sdk"
echo "prepare_external=$prepare_external"
echo "build_afc2=$build_afc2"
echo "create_venv=$create_venv"
if ((dry_run)); then
  [[ -z "$afcd_input" || -f "$afcd_input" ]] || { echo "error: afcd input missing" >&2; exit 1; }
  [[ -z "$lockdownd_input" || -f "$lockdownd_input" ]] || { echo "error: lockdownd input missing" >&2; exit 1; }
  echo "DRY_RUN=PASS"
  exit 0
fi

if [[ ! -d "$dest/.git" ]]; then
  git clone --no-checkout "$source_path" "$dest"
fi
git -C "$dest" checkout --detach "$ref"
python3 "$dest/scripts/reproducibility/verify_manifest.py" --repo "$dest"

if ((create_venv)); then
  need "$python_bin"
  if [[ ! -x "$dest/.venv/bin/python" ]]; then
    "$python_bin" -m venv "$dest/.venv"
  fi
  "$dest/.venv/bin/python" -m pip install --requirement "$dest/requirements.txt"
fi

if ((prepare_external)); then
  mkdir -p "$dest/addons/PoC"
  prepare_patch_repo() {
    local path=$1 origin=$2 base=$3 patch=$4
    if [[ ! -d "$path/.git" ]]; then git clone "$origin" "$path"; fi
    if git -C "$path" apply --reverse --check "$patch" >/dev/null 2>&1; then
      echo "already patched: $path"
      return
    fi
    git -C "$path" checkout --detach "$base"
    git -C "$path" am "$patch"
  }
  prepare_patch_repo "$dest/addons/PoC/appregistrard" \
    https://github.com/insidegui/appregistrard.git \
    691d10b59c441782b20a200a6aea94c1b7848084 \
    "$dest/docs/reproducibility/patches/appregistrard-691d10b-to-5e3c55e.patch"
  prepare_patch_repo "$dest/addons/PoC/srdzsh" \
    https://github.com/fuzzlove/srdzsh \
    dfb0f1e7d484e5f9783777797c8c969dba1b8656 \
    "$dest/docs/reproducibility/patches/srdzsh-dfb0f1e-to-082ee91.patch"
  theos="$dest/artifacts/compatibility/toolchains/theos"
  if [[ ! -d "$theos/.git" ]]; then
    git clone --recursive https://github.com/theos/theos.git "$theos"
  fi
  git -C "$theos" checkout --detach dd5c14bb9d91311e221d51b5bfb8c9e5948156db
  git -C "$theos" submodule update --init --recursive
fi

if ((build_afc2)); then
  [[ -f "$afcd_input" && -f "$lockdownd_input" ]] || {
    echo "error: --build-afc2 requires both exact-build Apple inputs" >&2; exit 1;
  }
  port="$dest/addons/PoC/appsync-afc2d-srd-port"
  mkdir -p "$port/inputs"
  cp "$afcd_input" "$port/inputs/afcd-iPhone13,2-24A5390f"
  cp "$lockdownd_input" "$port/inputs/lockdownd-iPhone13,2-24A5390f"
  (cd "$port" && make check)
fi
echo "RESTORE=PASS"
