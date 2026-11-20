# Body of the debconf config script. build-deb.sh prepends the shebang, the
# confmodule and the shared definitions.

# Start from the installed configuration, so that dpkg-reconfigure shows the
# current settings and the upgrade from versions that shipped config.toml as a
# conffile keeps them (with a noninteractive frontend the defaults are used as
# answers). The tokens are carried over by the postinst.
src=$(pubsec_config_source)
if [ -n "$src" ]; then
    url=$(pubsec_toml_get "$src" pubsecd url)
    if [ -n "$url" ]; then
        db_set pubsec-rspamd/api-url "$url"
    fi
    if pubsec_toml_has "$src" ingest; then
        db_set pubsec-rspamd/report true
        db_set pubsec-rspamd/ignore-networks \
            "$(pubsec_toml_array "$src" ingest ignore_networks)"
    else
        db_set pubsec-rspamd/report false
    fi
    if pubsec_toml_has "$src" ingest.envelope_from; then
        db_set pubsec-rspamd/report-domains true
        own=
        set -f
        for domain in $(pubsec_toml_array "$src" ingest.envelope_from ignore_domains | tr ',' ' '); do
            case " $PUBSEC_PROVIDER_DOMAINS " in
                *" $domain "*) continue ;;
            esac
            own="${own:+$own, }$domain"
        done
        set +f
        db_set pubsec-rspamd/own-domains "$own"
    else
        db_set pubsec-rspamd/report-domains false
    fi
    if pubsec_toml_has "$src" maps; then
        db_set pubsec-rspamd/use-maps true
    else
        db_set pubsec-rspamd/use-maps false
    fi
fi

db_input high pubsec-rspamd/api-url || true
db_go || true
db_input high pubsec-rspamd/push-token || true
db_go || true
db_input high pubsec-rspamd/read-token || true
db_go || true

db_input high pubsec-rspamd/report || true
db_go || true
db_get pubsec-rspamd/report
if [ "$RET" = true ]; then
    db_input medium pubsec-rspamd/ignore-networks || true
    db_go || true
    db_input high pubsec-rspamd/report-domains || true
    db_go || true
    db_get pubsec-rspamd/report-domains
    if [ "$RET" = true ]; then
        db_input medium pubsec-rspamd/own-domains || true
        db_go || true
    fi
fi

db_input high pubsec-rspamd/use-maps || true
db_go || true
db_get pubsec-rspamd/use-maps
# The postinst creates multimap.conf with the include if it is missing and
# removes that stub again when the maps are turned off, but never edits a
# multimap.conf of the admin.
if [ -f "$PUBSEC_MULTIMAP" ] && ! pubsec_multimap_is_stub "$PUBSEC_MULTIMAP"; then
    if [ "$RET" = true ] && ! pubsec_multimap_included "$PUBSEC_MULTIMAP"; then
        db_input high pubsec-rspamd/multimap-note || true
        db_go || true
    elif [ "$RET" != true ] && pubsec_multimap_included "$PUBSEC_MULTIMAP"; then
        db_input high pubsec-rspamd/multimap-remove-note || true
        db_go || true
    fi
fi

exit 0
