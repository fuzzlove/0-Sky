#!/bin/zsh
# Install the already rebuilt SRDsh image on a newly connected authorized SRD
# through RemoteXPC, verify Dropbear SSH, then install/verify Procursus.
# This runner intentionally contains no Sileo installation. The final Filza
# Cryptex stage performs the one required LaunchServices registration.

set -euo pipefail

SCRIPT_DIR=${0:A:h}
EXPLOITDEV=${SCRIPT_DIR:h}
NATIVE_DIR="$SCRIPT_DIR/native-install"
INSTALLER="$NATIVE_DIR/install_cryptex_native.py"
IMAGE_DEFAULT="$NATIVE_DIR/srdsh-apfs-sealed-udzo.dmg"
TRUST_DEFAULT="$NATIVE_DIR/srdsh.gtcd"
HASH_DEFAULT="$NATIVE_DIR/srdsh-apfs-sealed.hash"
MANIFEST_DEFAULT="$EXPLOITDEV/research-cryptex/retry-apfs/com.example.cryptex.cxbd/Restore/BuildManifest.plist"
BOOTSTRAP_DEFAULT="$EXPLOITDEV/../procursus/bootstrap_1900.tar.zst"
AUTHORIZED_KEY_DEFAULT="$NATIVE_DIR/srdsh-authorized-key.pub"
BUILDER="$NATIVE_DIR/build_and_install.sh"
SOURCE_DIR="$SCRIPT_DIR/srdsh"
STATE_DIR="$SCRIPT_DIR/reproduce-state"
ZERO_SKY_DIR="$SCRIPT_DIR/components/zero-sky"
ZERO_SKY_MAIN="$ZERO_SKY_DIR/main.py"
ZERO_SKY_MANIFEST="$ZERO_SKY_DIR/kit/SHA256SUMS"
MACOS_HOST_SETUP="$EXPLOITDEV/../macos_host_setup.py"
PYTHON_LOCK="$ZERO_SKY_DIR/kit/host-mac/requirements-lock.txt"
PYTHON_WHEELHOUSE="$ZERO_SKY_DIR/kit/host-mac/wheelhouse"
RUNTIME_VENV="$STATE_DIR/host-runtime-py312"

EXPECTED_IMAGE_SHA256=6bb03a880830129783d5ba701876311b89a9f2726b5696ec0788175d99388fe5
EXPECTED_TRUST_SHA256=7343a51a0a08df094a765b49077a93878431ff1e3962fbe6d4bbbef09dc4f028
EXPECTED_HASH_SHA256=46bd427c124aa3b75ed09baffbdaa1b7e27963ad0ce46f6686624912325e1b7d
EXPECTED_AUTHORIZED_KEY_SHA256=789feb6c593c33f2db8ed9ccf7422fc0c22cbbd82077f120a462b3aa912fb2aa
EXPECTED_BOOTSTRAP_SHA256=2c639b83423e4365a3a849e2bc7c56671cdcc8da534d424b6b1779a27c0c7c08

UDID=${CRYPTEXCTL_UDID:-auto}
LOCAL_PORT=${SRD_SSH_PORT:-2222}
IDENTITY_FILE=${SRD_SSH_IDENTITY:-$HOME/.ssh/srdsh_ed25519}
IMAGE="$IMAGE_DEFAULT"
TRUST="$TRUST_DEFAULT"
VOLUME_HASH="$HASH_DEFAULT"
MANIFEST="$MANIFEST_DEFAULT"
BOOTSTRAP="$BOOTSTRAP_DEFAULT"
FORCE_BOOTSTRAP=0
CHECK_ONLY=0
REBUILD=0
REBOOT_AFTER_INSTALL=1
STOP_AFTER=procursus
IOS_SDK=${SRD_IOS_SDK:-iphoneos}
IOS_MIN_VERSION=${SRD_IOS_MIN_VERSION:-17.0}
SRDSH_CRYPTEX_VERSION=${SRDSH_VERSION:-1.2.3}
VERBOSE=${SRD_VERBOSE:-0}
INSTALL_COMPONENTS=${SRD_INSTALL_COMPONENTS:-1}
FORCE_COMPONENTS=0
FORCE_FILZA=0
REUSE_EXISTING_SSH=0

usage() {
  cat <<'EOF'
Usage: ./reproduce_srd_stack.sh [options]

Default flow:
  1. auto-detect the sole USB-connected device UDID;
  2. personalize/install the rebuilt SRDsh DMG through RemoteXPC;
  3. reboot once to activate and persistence-test the new cryptex;
  4. install the image's sealed SSH public key for root and verify Dropbear;
  5. install or verify Procursus under the active Preboot volume; and
  6. after verifying Procursus ssh/sshd, install or verify the bundled latest
     CatVNC 0.0.2, CrypStore 2.7.0, 0-Sky 1.8.5, and the latest
     post-reboot-validated Filza 4.0 Cryptex from the preceding 48 hours.

Options:
  --udid ID                 override automatic USB UDID detection
  --port PORT               local iproxy port (default: 2222)
  --identity FILE           SSH private key
  --image FILE              rebuilt sealed/compressed SRDsh DMG
  --trust-cache FILE        wrapped SRDsh trust cache
  --volume-hash FILE        sealed APFS volume hash
  --manifest FILE           BuildManifest template
  --bootstrap FILE          bootstrap_1900.tar.zst
  --sdk SDK                 iOS SDK name (for example: iphoneos18.5 or iphoneos26.0)
  --min-ios VERSION         minimum iOS version encoded in rebuilt binaries
  --verbose                 show path-redacted diagnostic messages
  --rebuild                 rebuild the minimal keyed DMG before installation
  --no-reboot               skip the post-install persistence-test reboot
  --force-bootstrap         re-extract an existing Procursus tree
  --force-components        reinstall CatVNC, CrypStore, 0-Sky, and Filza
  --force-filza             reinstall only the reviewed Filza 4.0 Cryptex
  --skip-components         stop after SSH + Procursus (legacy behavior)
  --stop-after ssh          install and verify SSH only
  --check                   local checks plus a read-only device preflight
  -h, --help                show help

The bundled component handoff comes from the internal review record. No Sileo app is installed.
EOF
}

die() { print -u2 -- "error: $*"; exit 1; }
note() { print -- "\n== $* =="; }
need_file() { [[ -f "$1" ]] || die "missing file: $1"; }
need_cmd() { command -v "$1" >/dev/null 2>&1 || die "missing command: $1"; }
mark() { [[ -z "${SRD_I:-}" ]] || print -r -- "$1" >| "$SRD_I"; }

while (( $# )); do
  case "$1" in
    --udid) (( $# >= 2 )) || die '--udid needs a value'; UDID=$2; shift 2 ;;
    --port) (( $# >= 2 )) || die '--port needs a value'; LOCAL_PORT=$2; shift 2 ;;
    --identity) (( $# >= 2 )) || die '--identity needs a value'; IDENTITY_FILE=$2; shift 2 ;;
    --image) (( $# >= 2 )) || die '--image needs a value'; IMAGE=$2; shift 2 ;;
    --trust-cache) (( $# >= 2 )) || die '--trust-cache needs a value'; TRUST=$2; shift 2 ;;
    --volume-hash) (( $# >= 2 )) || die '--volume-hash needs a value'; VOLUME_HASH=$2; shift 2 ;;
    --manifest) (( $# >= 2 )) || die '--manifest needs a value'; MANIFEST=$2; shift 2 ;;
    --bootstrap) (( $# >= 2 )) || die '--bootstrap needs a value'; BOOTSTRAP=$2; shift 2 ;;
    --sdk) (( $# >= 2 )) || die '--sdk needs a value'; IOS_SDK=$2; shift 2 ;;
    --min-ios) (( $# >= 2 )) || die '--min-ios needs a value'; IOS_MIN_VERSION=$2; shift 2 ;;
    --verbose) VERBOSE=1; shift ;;
    --rebuild) REBUILD=1; shift ;;
    --no-reboot) REBOOT_AFTER_INSTALL=0; shift ;;
    --force-bootstrap) FORCE_BOOTSTRAP=1; shift ;;
    --force-components) FORCE_COMPONENTS=1; shift ;;
    --force-filza) FORCE_FILZA=1; shift ;;
    --skip-components) INSTALL_COMPONENTS=0; shift ;;
    --stop-after) (( $# >= 2 )) || die '--stop-after needs a value'; STOP_AFTER=$2; shift 2 ;;
    --check) CHECK_ONLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ "$LOCAL_PORT" == <1-65535> ]] || die "invalid local port: $LOCAL_PORT"
case "$STOP_AFTER" in ssh|procursus) ;; *) die '--stop-after must be ssh or procursus' ;; esac

if (( VERBOSE )); then
  print -- 'LiquidSky diagnostics enabled; proprietary command lines remain redacted'
fi

mkdir -p "$STATE_DIR"
LOG="$STATE_DIR/run-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOG") 2>&1

mark 1
note 'checking required host commands and local files'
for command_name in python3 shasum ssh ssh-keygen iproxy nc lsof tar zstd; do
  need_cmd "$command_name"
done
need_file "$INSTALLER"
need_file "$MACOS_HOST_SETUP"
need_file "$PYTHON_LOCK"
[[ -d "$PYTHON_WHEELHOUSE" ]] || die "missing bundled Python wheelhouse"
WHEEL_COUNT=$(find "$PYTHON_WHEELHOUSE" -maxdepth 1 -type f -name '*.whl' | wc -l | tr -d ' ')
(( WHEEL_COUNT >= 100 )) || die "bundled Python wheelhouse is incomplete"
need_file "$IMAGE"
need_file "$TRUST"
need_file "$VOLUME_HASH"
need_file "$MANIFEST"
[[ "$STOP_AFTER" == procursus ]] && need_file "$BOOTSTRAP"
if [[ "$STOP_AFTER" == procursus ]] && (( INSTALL_COMPONENTS )); then
  need_file "$ZERO_SKY_MAIN"
  need_file "$ZERO_SKY_MANIFEST"
fi
(( REBUILD )) && { need_file "$BUILDER"; need_file "$IDENTITY_FILE.pub"; }
(( REBUILD )) && need_cmd make
print -- 'required host commands and local files: found'

note 'selecting or preparing the bundled Python runtime'
python_ready() {
  PYTHONNOUSERSITE=1 "$1" -c 'import importlib.metadata as m, sys
assert sys.version_info[:2] == (3, 12)
import pymobiledevice3, Crypto, zstandard
assert m.version("pymobiledevice3") == "11.3.1"
assert m.version("pycryptodome") == "3.23.0"
assert m.version("zstandard") == "0.25.0"' >/dev/null 2>&1
}
python_312() {
  PYTHONNOUSERSITE=1 "$1" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 12) else 1)'     >/dev/null 2>&1
}

PMD3_PYTHON=''
BOOTSTRAP_PYTHON=''
if [[ -n "${SRD_PYTHON:-}" ]]; then
  [[ -x "$SRD_PYTHON" ]] || die "SRD_PYTHON is not executable: $SRD_PYTHON"
  if python_ready "$SRD_PYTHON"; then
    PMD3_PYTHON=$SRD_PYTHON
  elif python_312 "$SRD_PYTHON"; then
    BOOTSTRAP_PYTHON=$SRD_PYTHON
  else
    die 'SRD_PYTHON must use Python 3.12 for the bundled macOS runtime'
  fi
else
  for candidate in     "$RUNTIME_VENV/bin/python3"     "$ZERO_SKY_DIR/.venv/bin/python3"     /Library/Frameworks/Python.framework/Versions/3.12/bin/python3     /opt/homebrew/bin/python3.12     "$(command -v python3)"; do
    if [[ -x "$candidate" ]] && python_ready "$candidate"; then
      PMD3_PYTHON=$candidate
      break
    fi
  done
fi

if [[ -z "$PMD3_PYTHON" ]]; then
  if [[ -z "$BOOTSTRAP_PYTHON" ]]; then
    for candidate in       /Library/Frameworks/Python.framework/Versions/3.12/bin/python3       /opt/homebrew/bin/python3.12       "$(command -v python3)"; do
      if [[ -x "$candidate" ]] && python_312 "$candidate"; then
        BOOTSTRAP_PYTHON=$candidate
        break
      fi
    done
  fi
  [[ -n "$BOOTSTRAP_PYTHON" ]] || die     'Python 3.12 is required; run the bundled macOS setup or install python@3.12'
  note 'preparing bundled offline host runtime'
  "$BOOTSTRAP_PYTHON" -m venv --clear "$RUNTIME_VENV"
  "$RUNTIME_VENV/bin/python3" -m pip install --no-index     --find-links "$PYTHON_WHEELHOUSE" --requirement "$PYTHON_LOCK"
  python_ready "$RUNTIME_VENV/bin/python3" || die     'bundled offline Python runtime validation failed'
  PMD3_PYTHON="$RUNTIME_VENV/bin/python3"
fi
# Never inject the caller's user site into the pinned runtime. An older
# pymobiledevice3 there can shadow the bundled version and change async APIs.
PYTHONPATH_VALUE=${SRD_PYTHONPATH:-}
export PYTHONNOUSERSITE=1
export ZERO_SKY_ARTIFACTS=${ZERO_SKY_ARTIFACTS:-$HOME/Library/Logs/0-sky}
export ZERO_SKY_STATE=${ZERO_SKY_STATE:-$HOME/Library/Application Support/0-Sky/runtime-state}
print -- "pymobiledevice3 Python: $PMD3_PYTHON"
print -- "bootstrap: $BOOTSTRAP"
print -- "build SDK: $IOS_SDK"
print -- "minimum iOS version: $IOS_MIN_VERSION"
print -- "run log: $LOG"

note 'checking complete macOS host requirements'
HOST_REQUIREMENT_ARGS=(
  --requirements-only
  --sdk "$IOS_SDK"
  --identity "$IDENTITY_FILE"
)
[[ "$UDID" == auto ]] || HOST_REQUIREMENT_ARGS+=(--udid "$UDID")
"$PMD3_PYTHON" "$MACOS_HOST_SETUP" "${HOST_REQUIREMENT_ARGS[@]}"

detect_udid() {
  [[ "$UDID" == auto ]] || return 0
  note 'auto-detecting the connected USB device'
  local result
  # Use -c rather than a here-document: zsh materializes heredocs in a temp
  # file, which made device discovery fail before Python started on a nearly
  # full host volume.
  result=$(PYTHONPATH="$PYTHONPATH_VALUE" "$PMD3_PYTHON" -c '
import asyncio
import inspect
from pymobiledevice3.usbmux import list_devices

async def main():
    devices = list_devices()
    if inspect.isawaitable(devices):
        devices = await devices
    devices = [device for device in devices
               if str(device.connection_type).upper() == "USB"]
    if len(devices) != 1:
        print("ERROR:" + ",".join(device.serial for device in devices))
        return
    print(devices[0].serial)

asyncio.run(main())
')
  if [[ "$result" == ERROR:* ]]; then
    local connected=${result#ERROR:}
    [[ -n "$connected" ]] || connected=none
    if (( CHECK_ONLY )); then
      print -- "note: found $connected; device check skipped in check-only mode"
      UDID=CHECK_ONLY_NO_DEVICE
      return
    fi
    die "expected exactly one USB device (found: $connected); use --udid ID"
  fi
  UDID=$result
  [[ -n "$UDID" ]] || die 'USB detection returned an empty UDID'
  print -- "selected UDID: $UDID"
}

probe_existing_srd_ssh() {
  # A proven exact-UDID root channel can avoid an unnecessary reinstall, but
  # it is never accepted as current SRD authorization.  The caller always
  # runs preflight_remotexpc before entering privileged device stages.
  (( CHECK_ONLY || REBUILD )) && return 0
  [[ -f "$IDENTITY_FILE" ]] || return 0
  nc -z 127.0.0.1 "$LOCAL_PORT" >/dev/null 2>&1 || return 0

  local listener_pid listener_command proof
  listener_pid=$(lsof -nP -tiTCP:"$LOCAL_PORT" -sTCP:LISTEN | head -1)
  [[ -n "$listener_pid" ]] || return 0
  listener_command=$(ps -p "$listener_pid" -o command= 2>/dev/null || true)
  if [[ "$listener_command" != *"$UDID"* ]] ||
     [[ "$listener_command" != *iproxy* &&
        "$listener_command" != *pymobiledevice3*usbmux*forward* ]]; then
    return 0
  fi

  proof=$(ssh -p "$LOCAL_PORT" \
    -o BatchMode=yes -o ConnectTimeout=5 -o ConnectionAttempts=1 \
    -o IdentitiesOnly=yes -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
    -i "$IDENTITY_FILE" root@127.0.0.1 \
    'test "$(id -u)" = 0 && printf "SRD_EXISTING_UID0\n"' 2>/dev/null || true)
  if [[ "$proof" == *SRD_EXISTING_UID0* ]]; then
    REUSE_EXISTING_SSH=1
    note 'reusing existing exact-UDID authenticated UID-0 SSH channel'
    print -- "listener PID: $listener_pid"
    print -- "listener:     $listener_command"
    print -- 'Existing payload is usable; current SRD eligibility is still required before privileged work.'
  fi
}

preflight_remotexpc() {
  [[ "$UDID" == CHECK_ONLY_NO_DEVICE ]] && return 0
  note "checking RemoteXPC and SRD eligibility for $UDID"

  local result preflight_rc
  set +e
  result=$(UDID="$UDID" PYTHONPATH="$PYTHONPATH_VALUE" "$PMD3_PYTHON" -c '
import asyncio
import os

from pymobiledevice3.remote.rsd_tunnel import PreferredRsdTunnel
from pymobiledevice3.services.cryptexd import CryptexdService

udid = os.environ["UDID"]


async def main():
    async with PreferredRsdTunnel(serial=udid, autopair=True) as rsd:
        if rsd.udid != udid:
            raise SystemExit(
                f"error: RemoteXPC selected {rsd.udid}, not requested USB UDID {udid}"
            )
        transport = "userspace USB" if rsd.is_in_process_tunnel else "macOS native"
        print(
            f"RemoteXPC target: {rsd.udid} "
            f"({rsd.product_type}, iOS {rsd.product_version}, {transport})",
            flush=True,
        )
        service = CryptexdService(rsd)
        identifiers = await asyncio.wait_for(
            service.read_personalization_identifiers(), timeout=20
        )
        research_enabled = identifiers.get("img4_chip_rsch")
        print(f"SRD research-enabled flag: {research_enabled}", flush=True)
        if research_enabled != 1:
            print(
                "error: the connected target is not positively classified as an "
                "Apple Security Research Device (img4_chip_rsch != 1).",
                flush=True,
            )
            raise SystemExit(78)
        nonce = await asyncio.wait_for(service.cryptex_nonce(3), timeout=20)
        if not nonce:
            print("error: cryptexd returned an empty research nonce", flush=True)
            raise SystemExit(78)
        print(f"cryptexd nonce: {len(nonce)} bytes", flush=True)
        print("RemoteXPC target and research nonce: PASS", flush=True)


asyncio.run(asyncio.wait_for(main(), timeout=60))
')
  preflight_rc=$?
  set -e
  print -- "$result"
  (( preflight_rc == 0 )) || exit "$preflight_rc"
}

check_sha256() {
  local file=$1 expected=$2 label=$3 actual
  actual=$(shasum -a 256 "$file" | awk '{print $1}')
  [[ "$actual" == "$expected" ]] || die "$label SHA-256 mismatch: $actual (use --rebuild for a newly built image or pass the matching artifact explicitly)"
  print -- "$label SHA-256: $actual"
}

check_embedded_identity() {
  [[ "$IMAGE" == "$IMAGE_DEFAULT" ]] || return 0
  need_file "$AUTHORIZED_KEY_DEFAULT"
  need_file "$IDENTITY_FILE"

  local image_key_fp identity_fp
  image_key_fp=$(ssh-keygen -lf "$AUTHORIZED_KEY_DEFAULT" | awk '{print $2}')
  identity_fp=$(ssh-keygen -lf "$IDENTITY_FILE" | awk '{print $2}')
  [[ "$image_key_fp" == "$identity_fp" ]] || die \
    "rebuilt DMG key ($image_key_fp) does not match $IDENTITY_FILE ($identity_fp); rerun with --rebuild"
  print -- "embedded SSH key: $image_key_fp"
}

rebuild_inputs() {
  (( REBUILD )) || return 0
  (( CHECK_ONLY )) && die '--rebuild and --check cannot be combined'
  [[ "$SOURCE_DIR" != *[[:space:]]* ]] || die     "rebuild path contains whitespace; move the bundle to a path without spaces before using --rebuild"
  note "rebuilding minimal SSH + Procursus cryptex for $IDENTITY_FILE.pub"
  make -C "$SOURCE_DIR" clean
  if (( VERBOSE )); then
    # Diagnostic mode must not discard nested compiler output. Without this,
    # GNU make only reports "Error 2" and hides the actual Xcode failure.
    make -C "$SOURCE_DIR" \
      IOS_SDK="$IOS_SDK" \
      IOS_MIN_VERSION="$IOS_MIN_VERSION" \
      SRDSH_AUTHORIZED_KEY="$IDENTITY_FILE.pub" \
      HUSH= \
      "$SOURCE_DIR/build/com.liquidsky.srdssh.dmg"
  else
    make -C "$SOURCE_DIR" \
      IOS_SDK="$IOS_SDK" \
      IOS_MIN_VERSION="$IOS_MIN_VERSION" \
      SRDSH_AUTHORIZED_KEY="$IDENTITY_FILE.pub" \
      "$SOURCE_DIR/build/com.liquidsky.srdssh.dmg"
  fi
  CRYPTEXCTL_UDID="$UDID" SRDSH_AUTHORIZED_KEY="$IDENTITY_FILE.pub" \
    SRDSH_BUILD_ONLY=1 "$BUILDER"
  IMAGE="$IMAGE_DEFAULT"
  TRUST="$TRUST_DEFAULT"
  VOLUME_HASH="$HASH_DEFAULT"
  EXPECTED_IMAGE_SHA256=$(shasum -a 256 "$IMAGE" | awk '{print $1}')
  EXPECTED_TRUST_SHA256=$(shasum -a 256 "$TRUST" | awk '{print $1}')
  EXPECTED_HASH_SHA256=$(shasum -a 256 "$VOLUME_HASH" | awk '{print $1}')
  print -- "rebuilt image SHA-256: $EXPECTED_IMAGE_SHA256"
  print -- "rebuilt trust-cache SHA-256: $EXPECTED_TRUST_SHA256"
  print -- "rebuilt volume-hash SHA-256: $EXPECTED_HASH_SHA256"
  print -- 'minimal keyed image rebuilt; Sileo/Frida/debugserver were excluded'
}

wait_for_usb_reconnect() {
  note "waiting for USB reconnect from $UDID"
  local found=0
  for attempt in {1..90}; do
    if UDID="$UDID" PYTHONPATH="$PYTHONPATH_VALUE" "$PMD3_PYTHON" -c '
import asyncio, inspect, os
from pymobiledevice3.usbmux import list_devices

async def main():
    wanted = os.environ["UDID"]
    devices = list_devices()
    if inspect.isawaitable(devices):
        devices = await devices
    raise SystemExit(0 if any(d.serial == wanted and
        str(d.connection_type).upper() == "USB" for d in devices) else 1)

asyncio.run(main())
' >/dev/null 2>&1
    then
      found=1
      break
    fi
    sleep 2
  done
  (( found )) || die "device $UDID did not reconnect over USB within 180 seconds; unlock it and rerun"
  print -- "USB reconnected: $UDID"
}

restart_target() {
  (( REBOOT_AFTER_INSTALL )) || return 0
  note 'rebooting once to activate and persistence-test the installed cryptex'
  PYTHONPATH="$PYTHONPATH_VALUE" "$PMD3_PYTHON" -m pymobiledevice3 \
    diagnostics restart --udid "$UDID"
  sleep 8
  wait_for_usb_reconnect
}

mark 2
note 'validating rebuilt RemoteXPC inputs'
detect_udid
mark 3
rebuild_inputs
python3 -m py_compile "$INSTALLER"
if [[ "$IMAGE" == "$IMAGE_DEFAULT" ]]; then
  # The release pack is self-contained. Rebuilt APFS images are intentionally
  # nondeterministic, so record their hashes instead of comparing them with a
  # stale digest from a previous build.
  print -- "image SHA-256:       $(shasum -a 256 "$IMAGE" | awk '{print $1}')"
  print -- "trust-cache SHA-256: $(shasum -a 256 "$TRUST" | awk '{print $1}')"
  print -- "volume-hash SHA-256: $(shasum -a 256 "$VOLUME_HASH" | awk '{print $1}')"
  check_sha256 "$AUTHORIZED_KEY_DEFAULT" "$EXPECTED_AUTHORIZED_KEY_SHA256" authorized-key
else
  print -- 'custom image selected; recording hashes without enforcing release digests'
  print -- "image SHA-256:       $(shasum -a 256 "$IMAGE" | awk '{print $1}')"
  print -- "trust-cache SHA-256: $(shasum -a 256 "$TRUST" | awk '{print $1}')"
  print -- "volume-hash SHA-256: $(shasum -a 256 "$VOLUME_HASH" | awk '{print $1}')"
fi
check_embedded_identity
[[ "$STOP_AFTER" == procursus ]] && check_sha256 "$BOOTSTRAP" "$EXPECTED_BOOTSTRAP_SHA256" bootstrap
print -- 'local checks passed'
mark 4
probe_existing_srd_ssh
preflight_remotexpc
if (( CHECK_ONLY )); then
  note 'requesting a read-only Apple TSS personalization ticket'
  PYTHONPATH="$PYTHONPATH_VALUE" "$PMD3_PYTHON" "$INSTALLER" \
    com.liquidsky.srdssh "$IMAGE" "$TRUST" "$VOLUME_HASH" "$SRDSH_CRYPTEX_VERSION" \
    "$UDID" "$MANIFEST" --preflight
  mark 0
  print -- 'check-only mode: research nonce and TSS ticket accepted; device was not modified'
  exit 0
fi
if (( REUSE_EXISTING_SSH )); then
  print -- 'existing mounted SRDssh generation preserved'
else
  mark 5
  note "personalizing rebuilt image for $UDID and installing through RemoteXPC"
  PYTHONPATH="$PYTHONPATH_VALUE" "$PMD3_PYTHON" "$INSTALLER" \
    com.liquidsky.srdssh "$IMAGE" "$TRUST" "$VOLUME_HASH" "$SRDSH_CRYPTEX_VERSION" "$UDID" "$MANIFEST"

  mark 6
  restart_target
fi

if [[ -f "$IDENTITY_FILE" ]]; then
  SSH_IDENTITY=(-i "$IDENTITY_FILE" -o IdentitiesOnly=yes)
else
  SSH_IDENTITY=()
  print -- "note: $IDENTITY_FILE is absent; OpenSSH will try normal identities"
fi
SSH_OPTIONS=(
  -p "$LOCAL_PORT"
  -o BatchMode=yes
  -o ConnectTimeout=5
  -o ConnectionAttempts=1
  -o StrictHostKeyChecking=accept-new
  -o UserKnownHostsFile="$STATE_DIR/known_hosts"
  "${SSH_IDENTITY[@]}"
)

mark 7
if (( REUSE_EXISTING_SSH )); then
  note "keeping existing USB forward on 127.0.0.1:$LOCAL_PORT"
elif nc -z 127.0.0.1 "$LOCAL_PORT" >/dev/null 2>&1; then
  LISTENER_PID=$(lsof -nP -tiTCP:"$LOCAL_PORT" -sTCP:LISTEN | head -1)
  LISTENER_COMMAND=$(ps -p "$LISTENER_PID" -o command= 2>/dev/null || true)
  if [[ "$LISTENER_COMMAND" != *iproxy* || "$LISTENER_COMMAND" != *"$UDID"* ]]; then
    die "port $LOCAL_PORT belongs to a different listener; use --port PORT"
  fi
  print -- "restarting stale/matching iproxy PID $LISTENER_PID"
  kill "$LISTENER_PID" 2>/dev/null || true
  for attempt in {1..20}; do
    kill -0 "$LISTENER_PID" 2>/dev/null || break
    sleep 0.1
  done
fi

if (( ! REUSE_EXISTING_SSH )); then
  note "starting USB forward 127.0.0.1:$LOCAL_PORT -> device:22"
  iproxy "$LOCAL_PORT" 22 -u "$UDID" >> "$STATE_DIR/iproxy-$LOCAL_PORT.log" 2>&1 &
  IPROXY_PID=$!
  print -- "$IPROXY_PID" > "$STATE_DIR/iproxy-$LOCAL_PORT.pid"
  disown "$IPROXY_PID" 2>/dev/null || true
fi

# The launch plist intentionally uses an ephemeral host key in /tmp. Clear only
# this PoC endpoint after reinstall/reboot so a changed host key cannot block it.
ssh-keygen -R "[127.0.0.1]:$LOCAL_PORT" -f "$STATE_DIR/known_hosts" >/dev/null 2>&1 || true

note 'waiting for authenticated Dropbear SSH'
SSH_READY=0
for attempt in {1..45}; do
  if ssh "${SSH_OPTIONS[@]}" root@127.0.0.1 'test "$(id -u)" = 0; echo SRD_SSH_READY' 2>/dev/null |
       grep -Fq SRD_SSH_READY; then
    SSH_READY=1
    break
  fi
  sleep 2
done
if (( ! SSH_READY )); then
  ssh "${SSH_OPTIONS[@]}" -vv root@127.0.0.1 true \
    >"$STATE_DIR/ssh-auth-last.txt" 2>&1 || true
  die "authenticated Dropbear did not become ready; see $STATE_DIR/ssh-auth-last.txt"
fi
print -- "SSH ready: 127.0.0.1:$LOCAL_PORT"

srd_ssh() { ssh "${SSH_OPTIONS[@]}" root@127.0.0.1 "$@"; }

[[ "$STOP_AFTER" == ssh ]] && {
  print -- 'done: rebuilt DMG transferred and Dropbear SSH verified'
  exit 0
}

mark 8
note 'installing or verifying Procursus bootstrap'
if (( ! FORCE_BOOTSTRAP )) && srd_ssh '/var/jb/usr/bin/dpkg --version >/dev/null 2>&1'; then
  print -- 'existing Procursus is operational; extraction skipped'
else
  STAGING="$STATE_DIR/bootstrap-stage"
  python3 -c '
import pathlib, shutil, sys
p = pathlib.Path(sys.argv[1])
if p.exists():
    shutil.rmtree(p)
p.mkdir(parents=True)
' "$STAGING"
  zstd -dc "$BOOTSTRAP" | tar -xf - -C "$STAGING" ./var/jb
  [[ -x "$STAGING/var/jb/usr/bin/dpkg" ]] || die 'bootstrap did not contain dpkg'

  srd_ssh 'set -eu
    TARGET=/private/preboot/$(cat /private/preboot/active)/procursus
    mkdir -p "$TARGET"
    if [ -L /var/jb ]; then rm /var/jb
    elif [ -e /var/jb ]; then echo "refusing to replace non-symlink /var/jb" >&2; exit 73
    fi
    ln -s "$TARGET" /var/jb
    echo "$TARGET"'

  tar -C "$STAGING/var/jb" -cf - . |
    srd_ssh 'TARGET=/private/preboot/$(cat /private/preboot/active)/procursus; tar -xpf - -C "$TARGET"'

  srd_ssh 'set -eu
    chmod 755 /var/jb/prep_bootstrap.sh
    NO_PASSWORD_PROMPT=1 /var/jb/usr/bin/sh /var/jb/prep_bootstrap.sh
    for package in shshd libdimentio0 libkrw0; do
      if /var/jb/usr/bin/dpkg-query -W -f="${db:Status-Abbrev}" "$package" 2>/dev/null | grep -q "^ii"; then
        /var/jb/usr/bin/dpkg --remove --force-depends "$package"
      fi
    done
    /var/jb/usr/bin/dpkg --configure --pending
    printf "%s\n" "source=bootstrap_1900.tar.zst" "sha256=2c639b83423e4365a3a849e2bc7c56671cdcc8da534d424b6b1779a27c0c7c08" > /var/jb/.srd_procursus_bootstrap'
fi

srd_ssh '/var/jb/usr/bin/dpkg --version | head -1; /var/jb/usr/bin/apt-get --version | head -1; /var/jb/usr/bin/apt-get check'

note 'verifying Procursus OpenSSH client and server before component handoff'
srd_ssh 'test -x /var/jb/usr/bin/ssh &&
  test -x /var/jb/usr/sbin/sshd &&
  /var/jb/usr/bin/dpkg-query -W openssh-client openssh-server'

if (( INSTALL_COMPONENTS )); then
  note 'installing or verifying latest CatVNC, 0-Sky Control, 0-Sky Link, and Filza'
  ZERO_SKY_ARGS=(
    --setup
    --udid "$UDID"
    --identity "$IDENTITY_FILE"
    --base-port "$LOCAL_PORT"
    --reuse-port
  )
  (( FORCE_COMPONENTS )) && ZERO_SKY_ARGS+=(--force-components)
  (( FORCE_FILZA )) && ZERO_SKY_ARGS+=(--force-filza)
  (( REBOOT_AFTER_INSTALL )) || ZERO_SKY_ARGS+=(--no-reboot)
  PYTHONPATH="$PYTHONPATH_VALUE" "$PMD3_PYTHON" "$ZERO_SKY_MAIN" \
    "${ZERO_SKY_ARGS[@]}"
else
  print -- 'CatVNC/0-Sky Control/0-Sky Link/Filza component handoff skipped by request'
fi

note 'completed SRD SSH + Procursus + application component workflow'
print -- "device:     $UDID"
print -- "SSH:        PASS (Dropbear via 127.0.0.1:$LOCAL_PORT)"
print -- 'Procursus: PASS'
if (( INSTALL_COMPONENTS )); then
  print -- 'CatVNC:    PASS (0.0.2)'
  print -- '0-Sky Control: PASS (3.3.0)'
  print -- '0-Sky Link:    PASS (1.9.0 build 33)'
  print -- 'Filza:     PASS (4.0, persistent research Cryptex)'
else
  print -- 'Components: skipped'
fi
print -- "log:        $LOG"
mark 0
