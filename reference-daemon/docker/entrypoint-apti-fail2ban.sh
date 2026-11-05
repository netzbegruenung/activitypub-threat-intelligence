#!/bin/sh
# Runs `apti-fail2ban run`: push follows the fail2ban log, pull writes the
# ban files the fail2ban container's jails follow.
set -eu

CONFIG=${APTI_FAIL2BAN_CONFIG:-/etc/apti-fail2ban/config.toml}

apti-fail2ban -c "$CONFIG" check

# The jail follows files that `pull` writes; make sure they exist.
touch /var/log/apti-fail2ban/ssh.log

exec apti-fail2ban -c "$CONFIG" run
