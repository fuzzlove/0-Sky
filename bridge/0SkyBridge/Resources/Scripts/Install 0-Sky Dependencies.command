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
elif [[ -x "$SCRIPT_DIR/0sky" ]]; then
  # Compact native releases carry the same setup program and kit internally.
  NATIVE="$SCRIPT_DIR/0sky"
fi

print "0-Sky Dependency Installer"
print "=========================="
print "This installs only missing host tools and the pinned offline Python environment."
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
    print "Apple Command Line Tools are needed before dependency setup can continue."
    /usr/bin/xcode-select --install 2>/dev/null || true
    print "Finish Apple's installer, then double-click this file again."
    print "Press Return to close."
    read -r
    exit 3
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
  print "0-Sky dependencies are ready. You can return to 0-Sky Bridge."
else
  print "Setup stopped with status $result_status. The message above identifies the remaining item."
fi
print "Press Return to close."
read -r
exit $result_status
