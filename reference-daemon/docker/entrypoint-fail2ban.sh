#!/bin/sh
# Runs fail2ban-server and `apti-fail2ban run` side by side. If either one
# exits, the container stops so the restart policy takes over.
set -eu

CONFIG=${APTI_FAIL2BAN_CONFIG:-/etc/apti-fail2ban/config.toml}

apti-fail2ban -c "$CONFIG" check

rm -f /run/fail2ban/fail2ban.sock /run/fail2ban/fail2ban.pid
touch /var/log/fail2ban.log
fail2ban-server -f -x &
f2b=$!

# The jail follows files that `pull` writes; make sure they exist.
touch /var/log/apti-fail2ban/ssh.log

apti-fail2ban -c "$CONFIG" run &
apti=$!

trap 'kill $f2b $apti 2>/dev/null || true' TERM INT

# Exit as soon as one of the two stops (POSIX sh: poll).
while kill -0 "$f2b" 2>/dev/null && kill -0 "$apti" 2>/dev/null; do
  sleep 2
done
kill "$f2b" "$apti" 2>/dev/null || true
wait "$f2b" "$apti" 2>/dev/null || true
exit 1
