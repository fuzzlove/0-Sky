#!/bin/zsh
set -u

SCRIPT_DIR=${0:A:h}
ONLINE=0
case ${1:-} in
  '') ;;
  --online) ONLINE=1 ;;
  *) print -u2 "Usage: ${0:t} [--online]"; exit 64 ;;
esac
SETUP=""
KIT=""
NATIVE=""

# Installed 0-Sky Bridge layout.
if [[ -f "$SCRIPT_DIR/macos_host_setup.py" && -d "$SCRIPT_DIR/../Kit" ]]; then
  SETUP="$SCRIPT_DIR/macos_host_setup.py"
  KIT="$SCRIPT_DIR/../Kit"
# Source checkout / public 0-sky layout.
elif [[ -f "$SCRIPT_DIR/macos_host_setup.py" && -d "$SCRIPT_DIR/kit" ]]; then
  SETUP="$SCRIPT_DIR/macos_host_setup.py"
  KIT="$SCRIPT_DIR/kit"
elif [[ -f "$SCRIPT_DIR/macos_host_setup.py" && \
        -d "$SCRIPT_DIR/exploitdev/srdsh-work/components/zero-sky/kit" ]]; then
  SETUP="$SCRIPT_DIR/macos_host_setup.py"
  KIT="$SCRIPT_DIR/exploitdev/srdsh-work/components/zero-sky/kit"
elif [[ -f "$SCRIPT_DIR/../../../macos_host_setup.py" && -d "$SCRIPT_DIR/kit" ]]; then
  SETUP="$SCRIPT_DIR/../../../macos_host_setup.py"
  KIT="$SCRIPT_DIR/kit"
elif [[ -x "$SCRIPT_DIR/0sky" ]]; then
  # Compact native releases carry the same setup program and kit internally.
  NATIVE="$SCRIPT_DIR/0sky"
fi

print "0-Sky Dependency Installer"
print "=========================="
case $(/usr/bin/uname -m) in
  arm64|x86_64) print "Mac architecture: $(/usr/bin/uname -m)" ;;
  *) print -u2 "This installer supports Intel x86_64 and Apple silicon arm64 Macs."; exit 2 ;;
esac
print "This guided installer verifies the self-contained 0-Sky host runtime,"
print "then creates a private, pinned Python environment for this Mac account."
print "The signed application supplies Python 3.12, dpkg-deb, USB discovery,"
print "USB forwarding, and the offline Python dependency wheelhouse."
if [[ $ONLINE -eq 1 ]]; then
  print "Note: --online is retained only for compatibility. This release does not"
  print "install Homebrew, execute a moving bootstrap script, or substitute network"
  print "downloads for a damaged bundle."
else
  print "Offline mode: no package indexes, Homebrew, curl, or downloads will be used."
fi
print

if [[ -f "$SCRIPT_DIR/../.0sky-incomplete-build" ]]; then
  print -u2 "This app bundle was left incomplete by a failed build."
  print -u2 "Install a complete 0-Sky release before setting up dependencies."
  print "Press Return to close."
  read -r
  exit 2
fi

if [[ -z "$NATIVE" && ( -z "$SETUP" || -z "$KIT" ) ]]; then
  print -u2 "This 0-Sky app has no bundled dependency kit. The app build or installer is incomplete."
  print -u2 "Install a complete release containing Contents/Resources/Kit, then run this installer again."
  print "Press Return to close."
  read -r
  exit 2
fi

if [[ -z "$NATIVE" ]]; then
  for required in SHA256SUMS PORTABILITY.json RELEASE_KIT_APPROVAL.json \
    RELEASE_KIT_MANIFEST.json WHEEL_INVENTORY.json \
    host-mac/HOST_RUNTIME_MANIFEST.json \
    host-mac/install.py host-mac/pair.py \
    host-mac/requirements-lock.txt payloads/0-Sky-Link-1.9.0-universal.ipa; do
    if [[ ! -r "$KIT/$required" ]]; then
      print -u2 "The bundled dependency kit is incomplete (missing $required)."
      print -u2 "Install a complete 0-Sky release; this installer cannot repair an incomplete app bundle."
      print "Press Return to close."
      read -r
      exit 2
    fi
  done
  if [[ ! -d "$KIT/host-mac/wheelhouse" ]]; then
    print -u2 "The bundled offline Python dependencies are missing."
    print -u2 "Install a complete 0-Sky release and run this installer again."
    print "Press Return to close."
    read -r
    exit 2
  fi
fi

PYTHON=""
if [[ -z "$NATIVE" ]]; then
  for candidate in "$KIT/host-mac/runtime/bin/python3"; do
    if [[ -x "$candidate" ]]; then PYTHON="$candidate"; break; fi
  done

  if [[ -z "$PYTHON" ]]; then
    print -u2 "Required component missing: bundled Python 3.12 runtime."
    print -u2 "Expected path: $KIT/host-mac/runtime/bin/python3"
    print -u2 "How to repair a downloaded app: delete this copy of 0SkyBridge.app,"
    print -u2 "re-download the complete verified four-file release, verify SHA256SUMS,"
    print -u2 "and reinstall its .pkg. Do not install Homebrew as a substitute."
    print -u2 "How to repair a source kit: from the 0-Sky repository run:"
    print -u2 "  python3 tools/build_host_runtime.py '/absolute/path/to/a-writable-kit-copy'"
    print -u2 "Then rebuild the application; do not copy files into a signed app."
    print "Press Return to close."
    read -r
    exit 3
  fi
fi

if [[ -n "$NATIVE" ]]; then
  "$NATIVE" --setup-python --requirements-only
else
  ZERO_SKY_KIT="$KIT" PYTHONDONTWRITEBYTECODE=1 \
    "$PYTHON" "$SETUP" --setup-python --requirements-only
fi
result_status=$?

print
if [[ $result_status -eq 0 ]]; then
  print "0-Sky requirements are ready, including the private Python environment."
  print "You can return to 0-Sky Bridge."
else
  print "Setup stopped with status $result_status. The message above identifies the remaining item."
fi
print "Press Return to close."
read -r
exit $result_status
