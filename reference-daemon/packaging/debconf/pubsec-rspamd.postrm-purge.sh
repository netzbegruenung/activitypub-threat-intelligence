# Rendered into the postrm of pubsec-rspamd, inside the "purge" branch.
# build-deb.sh prepends the shared definitions.

if command -v ucf >/dev/null 2>&1; then
    ucf --purge "$PUBSEC_CONFIG"
fi
if command -v ucfr >/dev/null 2>&1; then
    ucfr --purge pubsec-rspamd "$PUBSEC_CONFIG"
fi
rm -f "$PUBSEC_CONFIG" "$PUBSEC_CONFIG.ucf-old" "$PUBSEC_CONFIG.ucf-new" \
    "$PUBSEC_CONFIG.ucf-dist" "$PUBSEC_CONFIG.dpkg-bak" "$PUBSEC_RSPAMD_SECRET"
rmdir --ignore-fail-on-non-empty /etc/pubsec-rspamd 2>/dev/null || true

# Only if the admin has not added anything to it.
if pubsec_multimap_is_stub "$PUBSEC_MULTIMAP"; then
    rm -f "$PUBSEC_MULTIMAP"
fi

if command -v db_purge >/dev/null 2>&1; then
    db_purge
fi
