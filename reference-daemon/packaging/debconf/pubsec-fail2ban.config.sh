# Body of the debconf config script. build-deb.sh prepends the shebang, the
# confmodule and the shared jail map.

# Jail names that are enabled somewhere in the fail2ban configuration. Reading
# the files directly rather than asking fail2ban-client, because the daemon is
# not necessarily running while the package is configured.
discover_enabled_jails() {
    files=
    for f in /etc/fail2ban/jail.conf /etc/fail2ban/jail.local \
        /etc/fail2ban/jail.d/*.conf /etc/fail2ban/jail.d/*.local; do
        # Unmatched globs stay literal, and a failing test as the last command
        # of the loop would abort this script under `set -e`.
        [ -f "$f" ] || continue
        files="$files $f"
    done
    [ -n "$files" ] || return 0
    # shellcheck disable=SC2086
    awk '
        /^[[:space:]]*\[/ {
            s = $0
            sub(/^[[:space:]]*\[/, "", s)
            sub(/\].*$/, "", s)
            sec = s
            next
        }
        /^[[:space:]]*enabled[[:space:]]*=[[:space:]]*(true|yes|1)[[:space:]]*(#.*)?$/ {
            if (sec != "" && sec != "DEFAULT" && sec != "INCLUDES") print sec
        }
    ' $files 2>/dev/null | sort -u
}

db_input high pubsec-fail2ban/api-url || true
db_go || true
db_input high pubsec-fail2ban/push-token || true
db_go || true
db_input high pubsec-fail2ban/read-token || true
db_go || true
db_input high pubsec-fail2ban/ban-active || true
db_go || true

# Offer the jails that are already active on this host plus the ones this
# package ships. The pull jail is never reportable: importing peers' bans and
# republishing them as own sightings would be a feedback loop.
enabled=$(discover_enabled_jails)
choices=
defaults=
for j in $enabled; do
    case "$j" in
        pubsecd-ban | pubsec-*) continue ;;
    esac
    choices="${choices:+$choices, }$j"
    defaults="${defaults:+$defaults, }$j"
done
for j in $PUBSEC_OWN_JAILS; do
    case ", $choices," in
        *", $j,"*) continue ;;
    esac
    choices="${choices:+$choices, }$j"
done

db_subst pubsec-fail2ban/integrations choices "$choices"
# The Default field of a template is not substituted, so preselect the already
# enabled jails here. Only while the question has no answer: dpkg-reconfigure
# clears the `seen` flag, so that flag cannot distinguish a first install from
# a reconfigure and would discard the admin's previous selection.
db_get pubsec-fail2ban/integrations || true
if [ -z "$RET" ]; then
    db_set pubsec-fail2ban/integrations "$defaults"
fi
db_input high pubsec-fail2ban/integrations || true
db_go || true

db_get pubsec-fail2ban/integrations
case "$RET" in
    *pubsec-haproxy-*)
        db_input medium pubsec-fail2ban/haproxy-note || true
        db_go || true
        ;;
esac

exit 0
