#!/bin/sh
# Procursus and the research app Cryptexes are mounted independently at boot.
# Wait for uicache/Python, then let the bounded registrar repair Home Screen
# registrations that LaunchServices may have discarded across the reboot.
set -u

: "${CRYPTEX_MOUNT_PATH:?missing CRYPTEX_MOUNT_PATH}"

i=0
while [ "$i" -lt 360 ]; do
    if [ -x /var/jb/usr/bin/python3 ] && [ -x /var/jb/usr/bin/uicache ]; then
        exec /var/jb/usr/bin/python3 \
            "$CRYPTEX_MOUNT_PATH/usr/bin/srdsh-register-apps.py"
    fi
    i=$((i + 1))
    sleep 2
done

# KeepAlive will retry this bounded dependency wait without creating a tight
# restart loop when Procursus is repaired or mounted late.
echo "srdsh: timed out waiting for Procursus app-registration tools" >&2
exit 0
