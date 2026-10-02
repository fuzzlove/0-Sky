#!/bin/sh
# Install the build-time public key before starting Dropbear.  The cryptex is
# read-only, while Dropbear looks up root's keys under /var/root/.ssh.
set -eu

: "${CRYPTEX_MOUNT_PATH:?missing CRYPTEX_MOUNT_PATH}"
SOURCE_KEY="$CRYPTEX_MOUNT_PATH/etc/srdsh_authorized_key"
KEY_DIR=/var/root/.ssh
AUTHORIZED_KEYS="$KEY_DIR/authorized_keys"
HOST_KEY_DIR=/private/var/db/com.liquidsky.srdssh
HOST_KEY="$HOST_KEY_DIR/dropbear-ed25519-host-key"
LEGACY_HOST_KEY=/private/var/tmp/com.liquidsky.srdssh/dropbear-ed25519-host-key

umask 077
mkdir -p "$KEY_DIR"
touch "$AUTHORIZED_KEYS"

KEY=$(awk 'NF { print; exit }' "$SOURCE_KEY")
if ! grep -qxF "$KEY" "$AUTHORIZED_KEYS"; then
    printf '%s\n' "$KEY" >> "$AUTHORIZED_KEYS"
fi

chown 0:0 "$KEY_DIR" "$AUTHORIZED_KEYS"
chmod 700 "$KEY_DIR"
chmod 600 "$AUTHORIZED_KEYS"

# iOS clears /private/var/tmp during restart. Store the device identity on the
# persistent Data volume so the Mac's strict host-key pin remains valid.
# /var/jb is intentionally not used because this service starts before the
# rootless bootstrap is guaranteed to be mounted.
if [ -L "$HOST_KEY_DIR" ] || [ -L "$HOST_KEY" ]; then
    echo "srdsh: refusing symbolic-link host-key state" >&2
    exit 78
fi
mkdir -p "$HOST_KEY_DIR"
chown 0:0 "$HOST_KEY_DIR"
chmod 700 "$HOST_KEY_DIR"
if [ ! -e "$HOST_KEY" ]; then
    TEMP_KEY="$HOST_KEY_DIR/.dropbear-ed25519-host-key.$$"
    trap 'rm -f "$TEMP_KEY"' EXIT HUP INT TERM
    if [ -f "$LEGACY_HOST_KEY" ] && [ ! -L "$LEGACY_HOST_KEY" ] && \
            "$CRYPTEX_MOUNT_PATH/usr/bin/dropbearkey" -y \
            -f "$LEGACY_HOST_KEY" >/dev/null 2>&1; then
        cp "$LEGACY_HOST_KEY" "$TEMP_KEY"
    else
        "$CRYPTEX_MOUNT_PATH/usr/bin/dropbearkey" -t ed25519 \
            -f "$TEMP_KEY" >/dev/null
    fi
    chown 0:0 "$TEMP_KEY"
    chmod 600 "$TEMP_KEY"
    mv "$TEMP_KEY" "$HOST_KEY"
    trap - EXIT HUP INT TERM
fi
if [ ! -f "$HOST_KEY" ] || ! "$CRYPTEX_MOUNT_PATH/usr/bin/dropbearkey" \
        -y -f "$HOST_KEY" >/dev/null 2>&1; then
    echo "srdsh: persistent Dropbear host key is invalid" >&2
    exit 78
fi
chown 0:0 "$HOST_KEY"
chmod 600 "$HOST_KEY"

# Full SRDssh images include the bounded registration companion; the minimal
# pairing image does not. Keep the startup script reusable without weakening
# Dropbear identity persistence or requiring a second LaunchDaemon.
if [ -x "$CRYPTEX_MOUNT_PATH/usr/bin/srdsh-register-apps-start" ]; then
    (exec sh "$CRYPTEX_MOUNT_PATH/usr/bin/srdsh-register-apps-start" \
        >>/private/var/tmp/srdsh-app-registration.log 2>&1) &
fi

exec "$CRYPTEX_MOUNT_PATH/usr/bin/dropbear" \
    -r "$HOST_KEY" -F
