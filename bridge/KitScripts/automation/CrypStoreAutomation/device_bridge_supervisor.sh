#!/bin/zsh
set -euo pipefail

# Keep 0-Sky Control's authenticated device-local HTTP bridge alive while the Mac
# companion is connected. The iOS UI talks to 127.0.0.1:48654; this SSH
# session either owns that server or monitors an already-running instance and
# takes over after it exits.

DEVICE_HOST=${CRYPSTORE_DEVICE_HOST:?exact device host is required}
DEVICE_USER=${CRYPSTORE_DEVICE_USER:-root}
DEVICE_KEY=${CRYPSTORE_DEVICE_KEY:?device SSH identity is required}
DEVICE_PORT=${CRYPSTORE_DEVICE_PORT:?device SSH port is required}
DEVICE_KNOWN_HOSTS=${CRYPSTORE_DEVICE_KNOWN_HOSTS:?device host-key pin is required}
DEVICE_HOST_ALIAS=${CRYPSTORE_DEVICE_HOST_ALIAS:?device host-key alias is required}

# A CoreDevice per-UDID hostname is only a route. The SSH host key pinned
# through exact-UDID USB enrollment remains the identity check. Prefer that
# route when reachable and retain the configured iproxy endpoint as fallback.
if [[ ${CRYPSTORE_WIRELESS_SSH:-0} == 1 && -n ${CRYPSTORE_DEVICE_UDID:-} &&
      ${CRYPSTORE_DEVICE_UDID} =~ '^[A-Za-z0-9-]+$' ]]; then
  WIRELESS_HOST="${CRYPSTORE_DEVICE_UDID}.coredevice.local"
  if /usr/bin/nc -z -w 2 "$WIRELESS_HOST" 22 >/dev/null 2>&1; then
    DEVICE_HOST="$WIRELESS_HOST"
    DEVICE_PORT=22
  fi
fi

if [[ -L "$DEVICE_KNOWN_HOSTS" || ! -f "$DEVICE_KNOWN_HOSTS" ]]; then
  print -u2 '0-sky bridge: device host-key pin is missing or unsafe'
  exit 78
fi

exec /usr/bin/ssh \
  -o BatchMode=yes \
  -o ConnectTimeout=10 \
  -o ServerAliveInterval=15 \
  -o ServerAliveCountMax=4 \
  -o StrictHostKeyChecking=yes \
  -o "UserKnownHostsFile=\"$DEVICE_KNOWN_HOSTS\"" \
  -o GlobalKnownHostsFile=/dev/null \
  -o "HostKeyAlias=$DEVICE_HOST_ALIAS" \
  -o IdentitiesOnly=yes \
  -o PasswordAuthentication=no \
  -o KbdInteractiveAuthentication=no \
  -i "$DEVICE_KEY" \
  -p "$DEVICE_PORT" \
  "$DEVICE_USER@$DEVICE_HOST" \
  'if [ -f /var/jb/etc/trollstorelite-srd-bridge.token ]; then
       /var/jb/usr/bin/chown root:mobile /var/jb/etc/trollstorelite-srd-bridge.token
       /var/jb/usr/bin/chmod 0640 /var/jb/etc/trollstorelite-srd-bridge.token
     fi
     if /var/jb/usr/bin/wget -qO- http://127.0.0.1:48654/v1/status >/dev/null 2>&1; then
       while /var/jb/usr/bin/wget -qO- http://127.0.0.1:48654/v1/status >/dev/null 2>&1; do
         /var/jb/usr/bin/sleep 5
       done
     fi
     cd /var/jb/var/tmp
     exec /var/jb/usr/bin/python3 /var/jb/usr/local/libexec/trollstorelite-srd-bridge.py'
