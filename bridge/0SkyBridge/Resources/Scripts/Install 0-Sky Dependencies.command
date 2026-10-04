#!/bin/zsh
set -u

SCRIPT_DIR=${0:A:h}
ONLINE=0
KIT_OVERRIDE=""
while (( $# )); do
  case "$1" in
    --online) ONLINE=1; shift ;;
    --kit)
      if (( $# < 2 )) || [[ -z "$2" ]]; then
        print -u2 "--kit requires the absolute path to the verified kit directory."
        print -u2 "That directory must contain SHA256SUMS, host-mac, payloads, and the offline wheelhouse."
        exit 64
      fi
      KIT_OVERRIDE="$2"
      shift 2
      ;;
    --help|-h)
      print "Usage: ${0:t} [--online] [--kit '/absolute/path/to/verified kit']"
      print ""
      print "--kit is for source-checkout installation when the authorized kit is stored elsewhere."
      print "Downloaded signed applications must use their embedded Contents/Resources/Kit."
      exit 0
      ;;
    *) print -u2 "Unknown option: $1"; print -u2 "Run ${0:t} --help for exact usage."; exit 64 ;;
  esac
done
SETUP=""
KIT=""
NATIVE=""
SIGNED_APP_LAYOUT=0
[[ "$SCRIPT_DIR" == *.app/Contents/Resources/* ]] && SIGNED_APP_LAYOUT=1

# Installed 0-Sky Bridge layout.
if [[ -f "$SCRIPT_DIR/macos_host_setup.py" ]]; then
  SETUP="$SCRIPT_DIR/macos_host_setup.py"
fi
if [[ -n "$SETUP" && -d "$SCRIPT_DIR/../Kit" ]]; then
  KIT="$SCRIPT_DIR/../Kit"
# Source checkout / public 0-sky layout.
elif [[ -n "$SETUP" && -d "$SCRIPT_DIR/kit" ]]; then
  KIT="$SCRIPT_DIR/kit"
elif [[ -n "$SETUP" && \
        -d "$SCRIPT_DIR/exploitdev/srdsh-work/components/zero-sky/kit" ]]; then
  KIT="$SCRIPT_DIR/exploitdev/srdsh-work/components/zero-sky/kit"
elif [[ -f "$SCRIPT_DIR/../../../macos_host_setup.py" && -d "$SCRIPT_DIR/kit" ]]; then
  SETUP="$SCRIPT_DIR/../../../macos_host_setup.py"
  KIT="$SCRIPT_DIR/kit"
elif [[ -x "$SCRIPT_DIR/0sky" ]]; then
  # Compact native releases carry the same setup program and kit internally.
  NATIVE="$SCRIPT_DIR/0sky"
fi

if [[ -n "$KIT_OVERRIDE" ]]; then
  if (( SIGNED_APP_LAYOUT )); then
    print -u2 "An external --kit path cannot repair a downloaded signed application."
    print -u2 "Reason: changing or bypassing Contents/Resources/Kit would invalidate the verified release boundary."
    print -u2 "Reinstall the complete signed package instead. Expected embedded location:"
    print -u2 "  $SCRIPT_DIR/../Kit"
    exit 64
  fi
  KIT=${KIT_OVERRIDE:A}
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
print "Installer location: $SCRIPT_DIR"
[[ -n "$SETUP" ]] && print "Setup controller: $SETUP"
[[ -n "$KIT" ]] && print "Dependency kit selected: $KIT"
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

if [[ -z "$NATIVE" && -n "$SETUP" && -z "$KIT" && $SIGNED_APP_LAYOUT -eq 0 ]]; then
  print -u2 "The source checkout does not contain the authorized dependency kit at a standard location."
  print -u2 "Select the kit directory itself — not its parent directory. It must contain:"
  print -u2 "  SHA256SUMS"
  print -u2 "  host-mac/HOST_RUNTIME_MANIFEST.json"
  print -u2 "  host-mac/runtime/bin/python3"
  print -u2 "  host-mac/wheelhouse/"
  print -u2 "  payloads/0-Sky-Link-1.9.0-universal.ipa"
  print -u2 "For a non-interactive run, use:"
  print -u2 "  '${0:A}' --kit '/absolute/path/to/verified kit'"
  if [[ -x /usr/bin/osascript ]]; then
    print "Opening a folder chooser for the verified kit…"
    selected=$(/usr/bin/osascript <<'APPLESCRIPT'
try
  set chosenFolder to choose folder with prompt "Select the verified 0-Sky kit directory. It must directly contain SHA256SUMS, host-mac, payloads, and the offline wheelhouse."
  return POSIX path of chosenFolder
on error number -128
  return ""
end try
APPLESCRIPT
)
    if [[ -n "$selected" ]]; then
      KIT=${selected%/}
      print "User-selected dependency kit: $KIT"
    fi
  fi
fi

if [[ -z "$NATIVE" && ( -z "$SETUP" || -z "$KIT" ) ]]; then
  print -u2 "This 0-Sky app has no bundled dependency kit. The app build or installer is incomplete."
  if (( SIGNED_APP_LAYOUT )); then
    print -u2 "Expected embedded path: $SCRIPT_DIR/../Kit"
    print -u2 "Install a complete release containing Contents/Resources/Kit, then run this installer again."
  else
    print -u2 "No kit was selected. Rerun with --kit '/absolute/path/to/verified kit'."
  fi
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
      print -u2 "The selected dependency kit is incomplete."
      print -u2 "Missing required item: $required"
      print -u2 "Expected full path: $KIT/$required"
      if (( SIGNED_APP_LAYOUT )); then
        print -u2 "Install a complete 0-Sky release; this installer cannot repair an incomplete signed app bundle."
      else
        print -u2 "Select the directory that directly contains SHA256SUMS, or restore the complete authorized kit."
        print -u2 "Rerun with: '${0:A}' --kit '/absolute/path/to/verified kit'"
      fi
      print "Press Return to close."
      read -r
      exit 2
    fi
  done
  if [[ ! -d "$KIT/host-mac/wheelhouse" ]]; then
    print -u2 "The bundled offline Python dependencies are missing."
    print -u2 "Expected directory: $KIT/host-mac/wheelhouse"
    print -u2 "Choose a complete verified kit with --kit, or reinstall the complete signed release."
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
