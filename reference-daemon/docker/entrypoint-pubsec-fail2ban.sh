#!/bin/sh
# Runs `pubsec-fail2ban run`: push follows the fail2ban log, pull writes the
# ban files the fail2ban container's jails follow.
set -eu

CONFIG=${PUBSEC_FAIL2BAN_CONFIG:-/etc/pubsec-fail2ban/config.toml}

pubsec-fail2ban -c "$CONFIG" check

# The jail follows files that `pull` writes; make sure they exist.
touch /var/log/pubsec-fail2ban/ssh.log

exec pubsec-fail2ban -c "$CONFIG" run
