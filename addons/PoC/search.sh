#!/bin/bash
set -u

TOOL="cryptexctl.research"
FOUND=""

echo "[*] Searching for $TOOL..."

# 1. Check PATH first
if command -v "$TOOL" >/dev/null 2>&1; then
    FOUND="$(command -v "$TOOL")"
fi

# 2. Search common SRD / Apple developer locations
if [ -z "$FOUND" ]; then
    SEARCH_PATHS=(
        "/Applications"
        "/Library/Developer"
        "$HOME/Library/Developer"
        "/usr/local"
        "/opt/homebrew"
        "$HOME/Downloads"
        "$HOME/Developer"
        "$HOME/Projects"
    )

    for base in "${SEARCH_PATHS[@]}"; do
        [ -e "$base" ] || continue

        RESULT="$(find "$base" -type f -name "$TOOL" 2>/dev/null | head -n 1)"

        if [ -n "$RESULT" ]; then
            FOUND="$RESULT"
            break
        fi
    done
fi

# 3. Report
if [ -z "$FOUND" ]; then
    echo "[FAIL] $TOOL was not found."
    echo
    echo "If you are an approved Apple SRD researcher:"
    echo "  1. Download/install the current SRD host tooling."
    echo "  2. Re-run this script."
    exit 1
fi

echo "[PASS] Found:"
echo "       $FOUND"
echo

REAL="$(python3 - "$FOUND" <<'PY'
import os, sys
print(os.path.realpath(sys.argv[1]))
PY
)"

echo "[*] Resolved path:"
echo "    $REAL"
echo

echo "[*] File information:"
file "$REAL"
echo

echo "[*] Permissions:"
ls -la "$REAL"
echo

echo "[*] Version:"
"$REAL" --version 2>&1 || \
"$REAL" version 2>&1 || \
echo "[WARN] No conventional version flag available."
echo

echo "[*] Code-signing information:"
/usr/bin/codesign -dv --verbose=4 "$REAL" 2>&1 || \
echo "[WARN] codesign inspection failed."
echo

echo "[*] Entitlements:"
/usr/bin/codesign -d --entitlements :- "$REAL" 2>/dev/null || \
echo "[INFO] No readable entitlements."
echo

TOOL_DIR="$(dirname "$REAL")"

echo "[*] Tool directory:"
echo "    $TOOL_DIR"
echo

# Check whether directory already exists in PATH
case ":$PATH:" in
    *":$TOOL_DIR:"*)
        echo "[PASS] Tool directory is already in PATH."
        ;;
    *)
        echo "[WARN] Tool directory is not currently in PATH."
        echo

        read -r -p "Add it permanently to ~/.zprofile? [y/N] " ANSWER

        case "$ANSWER" in
            y|Y|yes|YES)
                LINE="export PATH=\"$TOOL_DIR:\$PATH\""

                if grep -F "$TOOL_DIR" "$HOME/.zprofile" >/dev/null 2>&1; then
                    echo "[INFO] ~/.zprofile already contains this directory."
                else
                    printf '\n# Apple SRD research tools\n%s\n' "$LINE" >> "$HOME/.zprofile"
                    echo "[PASS] Added to ~/.zprofile."
                fi

                echo
                echo "Activate it now with:"
                echo
                echo "    source ~/.zprofile"
                echo
                echo "Then verify:"
                echo
                echo "    command -v cryptexctl.research"
                echo "    cryptexctl.research --version"
                ;;
            *)
                echo "[INFO] PATH unchanged."
                ;;
        esac
        ;;
esac
