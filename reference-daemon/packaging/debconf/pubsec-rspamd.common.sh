# Shared by the config, postinst and postrm scripts of pubsec-rspamd.
# build-deb.sh copies this file into each of them.

PUBSEC_CONFIG=/etc/pubsec-rspamd/config.toml
# Generated from ingest.report_secret on every configure: the report secret of
# the Lua plugin. modules.local.d/pubsec.conf includes it, so the shipped
# conffiles stay free of secrets and local.d/pubsec.conf stays the admin's.
PUBSEC_RSPAMD_SECRET=/etc/rspamd/local.d/pubsec_secret.inc
# Belongs to the admin. Created with pubsec_multimap_stub only if missing.
PUBSEC_MULTIMAP=/etc/rspamd/local.d/multimap.conf
# Bounce domains of mail service providers whose SPF passes for all their
# customers. Always part of ingest.envelope_from.ignore_domains.
PUBSEC_PROVIDER_DOMAINS="amazonses.com sendgrid.net mcsv.net mailgun.org sparkpostmail.com mandrillapp.com bounces.google.com outlook.com"

pubsec_multimap_stub() {
    cat <<'EOF'
# Created by the pubsec-rspamd package because the file did not exist. Add
# your own multimap rules below; the package does not change this file again.
.include(try=true) "$LOCAL_CONFDIR/local.d/pubsec_multimap.inc"
EOF
}

# Succeeds if FILE is exactly the stub created by the package.
pubsec_multimap_is_stub() {
    [ -f "$1" ] && pubsec_multimap_stub | cmp -s - "$1"
}

# Succeeds if FILE includes the pubsec multimap rules.
pubsec_multimap_included() {
    [ -f "$1" ] && grep -Eq '^[[:space:]]*\.include.*pubsec_multimap\.inc' "$1"
}

pubsec_unescape() {
    sed -e 's/\\"/"/g' -e 's/\\\\/\\/g'
}

# Prints the configuration to read the current settings from: the installed
# one, or the .dpkg-bak copy that dpkg-maintscript-helper rm_conffile leaves
# when upgrading from 2026.11.9 or older, which shipped it as a conffile.
pubsec_config_source() {
    for f in "$PUBSEC_CONFIG" "$PUBSEC_CONFIG.dpkg-bak"; do
        if [ -f "$f" ]; then
            printf '%s' "$f"
            return 0
        fi
    done
}

# The parsers below cover the subset of TOML the package writes and the
# example configuration uses: [table] headers, basic strings and arrays of
# basic strings, also spread over several lines.

# pubsec_toml_lines FILE TABLE: prints the lines of [TABLE] ("" = root).
pubsec_toml_lines() {
    awk -v want="$2" '
        /^[[:space:]]*\[/ {
            s = $0
            sub(/^[[:space:]]*\[+[[:space:]]*/, "", s)
            sub(/[[:space:]]*\].*$/, "", s)
            cur = s
            next
        }
        cur == want
    ' "$1"
}

# pubsec_toml_has FILE TABLE: succeeds if FILE contains [TABLE].
pubsec_toml_has() {
    awk -v want="$2" '
        /^[[:space:]]*\[[^[]/ {
            s = $0
            sub(/^[[:space:]]*\[[[:space:]]*/, "", s)
            sub(/[[:space:]]*\].*$/, "", s)
            if (s == want) { found = 1; exit }
        }
        END { exit !found }
    ' "$1"
}

# pubsec_toml_get FILE TABLE KEY: prints the string value of KEY in [TABLE].
pubsec_toml_get() {
    pubsec_toml_lines "$1" "$2" |
        sed -n "s/^[[:space:]]*$3[[:space:]]*=[[:space:]]*\"\(.*\)\"[[:space:]]*\(#.*\)\{0,1\}\$/\1/p" |
        head -n 1 | pubsec_unescape
}

# pubsec_toml_array FILE TABLE KEY: prints the strings of the array KEY in
# [TABLE], separated by ", ".
pubsec_toml_array() {
    pubsec_toml_lines "$1" "$2" | awk -v key="$3" '
        !on && $0 ~ ("^[[:space:]]*" key "[[:space:]]*=[[:space:]]*\\[") {
            on = 1
            sub(/^[^[]*\[/, "")
        }
        on {
            line = $0
            while (match(line, /"([^"\\]|\\.)*"/)) {
                v = substr(line, RSTART + 1, RLENGTH - 2)
                out = out (out == "" ? "" : ", ") v
                line = substr(line, RSTART + RLENGTH)
            }
            sub(/#.*/, "", line)
            if (line ~ /\]/) exit
        }
        END { print out }
    ' | pubsec_unescape
}
