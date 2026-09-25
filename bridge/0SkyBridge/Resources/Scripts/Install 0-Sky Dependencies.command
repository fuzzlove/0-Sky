#!/bin/zsh
set -u

SCRIPT_DIR=${0:A:h}
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
print "This guided installer adds every required macOS component for 0-Sky."
print "Required host packages include Python 3.12, dpkg/dpkg-deb, USB tools,"
print "and the pinned offline 0-Sky Python environment."
print "Homebrew's official installer remains interactive and shows its changes first."
print

if [[ -z "$NATIVE" && ( -z "$SETUP" || -z "$KIT" ) ]]; then
  print -u2 "The 0-Sky setup program or bundled kit could not be found."
  print "Press Return to close."
  read -r
  exit 2
fi

PYTHON=""
if [[ -z "$NATIVE" ]]; then
  for candidate in \
    "/Library/Frameworks/Python.framework/Versions/3.12/bin/python3" \
    "/opt/homebrew/bin/python3.12" "/usr/local/bin/python3.12" \
    "/opt/homebrew/bin/python3" "/usr/local/bin/python3" "/usr/bin/python3"; do
    if [[ -x "$candidate" ]]; then PYTHON="$candidate"; break; fi
  done

  if [[ -z "$PYTHON" ]]; then
    print "Python 3.12 is not installed. Bootstrapping the required runtime now."
    if ! /usr/bin/xcrun --find clang >/dev/null 2>&1; then
      print "Apple Command Line Tools must finish installing first."
      /usr/bin/xcode-select --install 2>/dev/null || true
      print "Finish Apple's installer, then double-click this file again."
      print "Press Return to close."
      read -r
      exit 3
    fi

    BREW=""
    for candidate in "/opt/homebrew/bin/brew" "/usr/local/bin/brew"; do
      if [[ -x "$candidate" ]]; then BREW="$candidate"; break; fi
    done
    if [[ -z "$BREW" ]]; then
      print "Homebrew is not installed. Opening its official interactive installer…"
      TEMP_ROOT=$(/usr/bin/mktemp -d "/tmp/0sky-homebrew.XXXXXX") || exit 4
      cleanup_bootstrap() { /bin/rm -rf "$TEMP_ROOT"; }
      trap cleanup_bootstrap EXIT INT TERM
      if ! /usr/bin/curl --fail --location --show-error --silent \
        --proto '=https' --tlsv1.2 \
        'https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh' \
        --output "$TEMP_ROOT/install.sh"; then
        print -u2 "Could not download Homebrew's official installer."
        exit 4
      fi
      /bin/chmod 0700 "$TEMP_ROOT/install.sh"
      if ! /bin/bash "$TEMP_ROOT/install.sh"; then
        print -u2 "Homebrew installation did not complete."
        exit 4
      fi
      for candidate in "/opt/homebrew/bin/brew" "/usr/local/bin/brew"; do
        if [[ -x "$candidate" ]]; then BREW="$candidate"; break; fi
      done
    fi
    if [[ -z "$BREW" ]]; then
      print -u2 "Homebrew did not provide a usable brew executable."
      exit 4
    fi

    print
    print "Installing the complete 0-Sky host requirement set…"
    if ! "$BREW" install python@3.12 dpkg libusbmuxd zstd ldid autoconf automake pkgconf; then
      print -u2 "One or more required Homebrew packages could not be installed."
      exit 5
    fi
    for candidate in \
      "/opt/homebrew/bin/python3.12" "/usr/local/bin/python3.12" \
      "/Library/Frameworks/Python.framework/Versions/3.12/bin/python3"; do
      if [[ -x "$candidate" ]]; then PYTHON="$candidate"; break; fi
    done
    if [[ -z "$PYTHON" ]]; then
      print -u2 "Python 3.12 is still unavailable after installation."
      exit 5
    fi
  fi
fi

if [[ -n "$NATIVE" ]]; then
  "$NATIVE" --fix-missing --install-homebrew --requirements-only
else
  ZERO_SKY_KIT="$KIT" PYTHONDONTWRITEBYTECODE=1 \
    "$PYTHON" "$SETUP" --fix-missing --install-homebrew --requirements-only
fi
result_status=$?

print
if [[ $result_status -eq 0 ]]; then
  print "0-Sky requirements are ready, including Python 3.12 and dpkg."
  print "You can return to 0-Sky Bridge."
else
  print "Setup stopped with status $result_status. The message above identifies the remaining item."
fi
print "Press Return to close."
read -r
exit $result_status
