# Rendered into the postrm of pubsec-fail2ban, inside the "purge" branch.

for jail in $PUBSEC_OWN_JAILS pubsecd-ban; do
    rm -f "/etc/fail2ban/jail.d/$jail.local"
done

if command -v ucf >/dev/null 2>&1; then
    ucf --purge /etc/pubsec-fail2ban/config.toml
fi
if command -v ucfr >/dev/null 2>&1; then
    ucfr --purge pubsec-fail2ban /etc/pubsec-fail2ban/config.toml
fi
rm -f /etc/pubsec-fail2ban/config.toml
rmdir --ignore-fail-on-non-empty /etc/pubsec-fail2ban 2>/dev/null || true

if command -v db_purge >/dev/null 2>&1; then
    db_purge
fi
