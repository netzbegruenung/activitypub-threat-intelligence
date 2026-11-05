#!/bin/sh
# Builds the amd64 Debian packages from binaries that were already compiled
# with `cargo build --workspace --release`.
#
#   packaging/build-deb.sh VERSION [BINDIR] [OUTDIR]
#
# VERSION may be given with or without a leading "v" (e.g. v2026.10.10).
set -eu

if [ $# -lt 1 ]; then
    echo "usage: $0 VERSION [BINDIR] [OUTDIR]" >&2
    exit 2
fi

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
version=${1#v}
bindir=$(CDPATH= cd -- "${2:-$root/target/release}" && pwd)
outdir=${3:-$root/../dist}
mkdir -p "$outdir"
outdir=$(CDPATH= cd -- "$outdir" && pwd)

maintainer="AP-TI maintainers <noreply@netzbegruenung.de>"
homepage="https://github.com/netzbegruenung/activitypub-threat-intelligence"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

begin_pkg() {
    pkg=$1
    d=$work/$pkg
    install -d "$d/DEBIAN" "$d/usr/bin" "$d/lib/systemd/system" \
        "$d/usr/share/doc/$pkg"
    : >"$d/DEBIAN/conffiles"
    install -m 0644 "$root/../LICENSE" "$d/usr/share/doc/$pkg/copyright"
    units=
    enable_units=
}

add_bin() {
    install -m 0755 "$bindir/$1" "$d/usr/bin/$1"
}

# add_conf SOURCE ABSOLUTE_TARGET  (registers the target as a conffile)
add_conf() {
    install -D -m 0644 "$1" "$d$2"
    echo "$2" >>"$d/DEBIAN/conffiles"
}

add_example() {
    install -D -m 0644 "$1" "$d/usr/share/doc/$pkg/examples/$(basename "$1")"
}

# add_unit NAME [enable]
add_unit() {
    install -m 0644 "$root/packaging/systemd/$1" "$d/lib/systemd/system/$1"
    units="$units $1"
    [ "${2:-}" = enable ] && enable_units="$enable_units $1"
    return 0
}

write_control() {
    depends="init-system-helpers (>= 1.51), adduser, ca-certificates, libc6 (>= 2.34)${PKG_DEPENDS:+, $PKG_DEPENDS}"
    size=$(du -ks "$d" | cut -f1)
    {
        echo "Package: $pkg"
        echo "Version: $version"
        echo "Architecture: amd64"
        echo "Maintainer: $maintainer"
        echo "Installed-Size: $size"
        echo "Depends: $depends"
        if [ -n "${PKG_RECOMMENDS:-}" ]; then
            echo "Recommends: $PKG_RECOMMENDS"
        fi
        echo "Section: net"
        echo "Priority: optional"
        echo "Homepage: $homepage"
        echo "Description: $PKG_DESC"
        printf '%s\n' "$PKG_LONG" | sed 's/^$/./; s/^/ /'
    } >"$d/DEBIAN/control"
    unset PKG_DEPENDS PKG_RECOMMENDS PKG_DESC PKG_LONG
}

write_maintscripts() {
    user=$1
    home=$2
    cat >"$d/DEBIAN/postinst" <<EOF
#!/bin/sh
set -e

if [ "\$1" = configure ]; then
    if ! getent passwd $user >/dev/null; then
        adduser --system --group --home $home --no-create-home \\
            --gecos "AP-TI $pkg" --quiet $user
    fi
fi
EOF
    if [ "$pkg" = apti-dashboard ]; then
        cat >>"$d/DEBIAN/postinst" <<'EOF'
if [ "$1" = configure ]; then
    install -d -o apti-dashboard -g apti-dashboard -m 0755 /var/www/apti-dashboard
fi
EOF
    fi
    cat >>"$d/DEBIAN/postinst" <<EOF

if [ "\$1" = configure ] && [ -x /usr/bin/deb-systemd-helper ]; then
    for unit in$units; do
        deb-systemd-helper unmask "\$unit" >/dev/null || true
    done
    for unit in$enable_units; do
        if deb-systemd-helper --quiet was-enabled "\$unit"; then
            deb-systemd-helper enable "\$unit" >/dev/null || true
        else
            deb-systemd-helper update-state "\$unit" >/dev/null || true
        fi
    done
    if [ -d /run/systemd/system ]; then
        systemctl --system daemon-reload >/dev/null || true
        if [ -n "\$2" ]; then
            deb-systemd-invoke try-restart$units >/dev/null || true
        fi
    fi
fi

# The shipped configuration contains placeholders, so the service is enabled
# but not started on a fresh install.
exit 0
EOF

    cat >"$d/DEBIAN/prerm" <<EOF
#!/bin/sh
set -e

if [ "\$1" = remove ] && [ -d /run/systemd/system ]; then
    deb-systemd-invoke stop$units >/dev/null || true
fi
exit 0
EOF

    cat >"$d/DEBIAN/postrm" <<EOF
#!/bin/sh
set -e

if [ -d /run/systemd/system ]; then
    systemctl --system daemon-reload >/dev/null || true
fi
if [ -x /usr/bin/deb-systemd-helper ]; then
    if [ "\$1" = remove ]; then
        deb-systemd-helper mask$units >/dev/null || true
    fi
    if [ "\$1" = purge ]; then
        deb-systemd-helper purge$units >/dev/null || true
        deb-systemd-helper unmask$units >/dev/null || true
    fi
fi
exit 0
EOF
    chmod 0755 "$d/DEBIAN/postinst" "$d/DEBIAN/prerm" "$d/DEBIAN/postrm"
}

pack() {
    (cd "$d" && find . -type f ! -path './DEBIAN/*' -printf '%P\0' |
        LC_ALL=C sort -z | xargs -0 -r md5sum >DEBIAN/md5sums)
    dpkg-deb --root-owner-group --build "$d" \
        "$outdir/${pkg}_${version}_amd64.deb" >/dev/null
    echo "built ${pkg}_${version}_amd64.deb"
}

# ------------------------------------------------------------------ aptid
begin_pkg aptid
add_bin aptid
add_bin apti-tui
add_conf "$root/config.example.toml" /etc/aptid/config.toml
add_unit aptid.service enable
PKG_DESC="ActivityPub threat intelligence daemon"
PKG_LONG="aptid federates threat intelligence over ActivityPub: it collects
observations from connectors, applies policy and publishes and consumes
signed activities.

This package also contains apti-tui, the terminal UI used to administer a
running aptid over its control socket."
write_control
write_maintscripts aptid /var/lib/aptid
pack

# ---------------------------------------------------------- apti-fail2ban
begin_pkg apti-fail2ban
add_bin apti-fail2ban
add_conf "$root/crates/apti-fail2ban/apti-fail2ban.example.toml" \
    /etc/apti-fail2ban/config.toml
add_conf "$root/crates/apti-fail2ban/fail2ban/filter.d/apti.conf" \
    /etc/fail2ban/filter.d/apti.conf
add_example "$root/crates/apti-fail2ban/fail2ban/jail.d/aptid-ssh.conf.example"
add_unit apti-fail2ban.service enable
PKG_RECOMMENDS="fail2ban"
PKG_DESC="fail2ban connector for aptid"
PKG_LONG="Follows the fail2ban log and reports bans to aptid, and writes the
active list back into files that fail2ban reads through the shipped apti
filter."
write_control
write_maintscripts apti-fail2ban /var/lib/apti-fail2ban
pack

# ------------------------------------------------------------ apti-rspamd
begin_pkg apti-rspamd
add_bin apti-rspamd
add_conf "$root/crates/apti-rspamd/apti-rspamd.example.toml" \
    /etc/apti-rspamd/config.toml
add_conf "$root/crates/apti-rspamd/rspamd/lua.local.d/apti.lua" \
    /etc/rspamd/lua.local.d/apti.lua
add_conf "$root/crates/apti-rspamd/rspamd/modules.local.d/apti.conf" \
    /etc/rspamd/modules.local.d/apti.conf
add_example "$root/crates/apti-rspamd/rspamd/local.d/multimap.conf.example"
add_unit apti-rspamd.service enable
PKG_RECOMMENDS="rspamd"
PKG_DESC="Rspamd connector for aptid"
PKG_LONG="Turns Rspamd scan results into observations for aptid and serves the
active list back to Rspamd as multimaps."
write_control
write_maintscripts apti-rspamd /var/lib/apti-rspamd
pack

# ------------------------------------------------------------ apti-statsd
begin_pkg apti-statsd
add_bin apti-statsd
add_conf "$root/crates/apti-statsd/apti-statsd.example.toml" \
    /etc/apti-statsd/config.toml
add_unit apti-statsd.service enable
PKG_DESC="public statistics page for an AP-TI hub"
PKG_LONG="Polls a hub's internal REST API and publishes aggregates over its
TLP:CLEAR dataset as a self-contained statistics page and a JSON directory of
connected nodes."
write_control
write_maintscripts apti-statsd /var/lib/apti-statsd
pack

# --------------------------------------------------------- apti-allowlist
begin_pkg apti-allowlist
add_bin apti-allowlist
add_conf "$root/crates/apti-allowlist/apti-allowlist.example.toml" \
    /etc/apti-allowlist/config.toml
add_unit apti-allowlist.service enable
PKG_DESC="allowlist sync for aptid"
PKG_LONG="Keeps the aptid allowlist in sync with a text file, so networks and
domains that must never be reported or banned stay exempt."
write_control
write_maintscripts apti-allowlist /var/lib/apti-allowlist
pack

# --------------------------------------------------------- apti-dashboard
begin_pkg apti-dashboard
add_bin apti-dashboard
add_conf "$root/crates/apti-dashboard/apti-dashboard.example.toml" \
    /etc/apti-dashboard/config.toml
add_unit apti-dashboard.service
add_unit apti-dashboard.timer enable
PKG_DESC="static HTML threat map for aptid"
PKG_LONG="Renders the aptid active list into a self-contained HTML page. The
shipped timer re-renders the page every 15 minutes."
write_control
write_maintscripts apti-dashboard /var/lib/apti-dashboard
pack
