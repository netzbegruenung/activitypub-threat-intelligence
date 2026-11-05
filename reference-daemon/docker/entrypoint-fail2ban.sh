#!/bin/sh
# Runs fail2ban-server in the foreground.
set -eu

rm -f /run/fail2ban/fail2ban.sock /run/fail2ban/fail2ban.pid
exec fail2ban-server -f -x
