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
    if [ "$pkg" = pubsec-dashboard ]; then
        cat >>"$d/DEBIAN/postinst" <<'EOF'
if [ "$1" = configure ]; then
    install -d -o pubsec-dashboard -g pubsec-dashboard -m 0755 /var/www/pubsec-dashboard
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

# ------------------------------------------------------------------ pubsecd
begin_pkg pubsecd
add_bin pubsecd
add_bin pubsec-tui
add_conf "$root/config.example.toml" /etc/pubsecd/config.toml
add_unit pubsecd.service enable
PKG_DESC="ActivityPub threat intelligence daemon"
PKG_LONG="pubsecd federates threat intelligence over ActivityPub: it collects
observations from connectors, applies policy and publishes and consumes
signed activities.

This package also contains pubsec-tui, the terminal UI used to administer a
running pubsecd over its control socket."
write_control
write_maintscripts pubsecd /var/lib/pubsecd
pack

# ---------------------------------------------------------- pubsec-fail2ban
begin_pkg pubsec-fail2ban
add_bin pubsec-fail2ban
add_conf "$root/crates/pubsec-fail2ban/pubsec-fail2ban.example.toml" \
    /etc/pubsec-fail2ban/config.toml
add_conf "$root/crates/pubsec-fail2ban/fail2ban/filter.d/pubsec.conf" \
    /etc/fail2ban/filter.d/pubsec.conf
add_example "$root/crates/pubsec-fail2ban/fail2ban/jail.d/pubsecd-ssh.conf.example"
add_unit pubsec-fail2ban.service enable
PKG_RECOMMENDS="fail2ban"
PKG_DESC="fail2ban connector for pubsecd"
PKG_LONG="Follows the fail2ban log and reports bans to pubsecd, and writes the
active list back into files that fail2ban reads through the shipped pubsec
filter."
write_control
write_maintscripts pubsec-fail2ban /var/lib/pubsec-fail2ban
pack

# ------------------------------------------------------------ pubsec-rspamd
begin_pkg pubsec-rspamd
add_bin pubsec-rspamd
add_conf "$root/crates/pubsec-rspamd/pubsec-rspamd.example.toml" \
    /etc/pubsec-rspamd/config.toml
add_conf "$root/crates/pubsec-rspamd/rspamd/lua.local.d/pubsec.lua" \
    /etc/rspamd/lua.local.d/pubsec.lua
add_conf "$root/crates/pubsec-rspamd/rspamd/modules.local.d/pubsec.conf" \
    /etc/rspamd/modules.local.d/pubsec.conf
add_example "$root/crates/pubsec-rspamd/rspamd/local.d/multimap.conf.example"
add_unit pubsec-rspamd.service enable
PKG_RECOMMENDS="rspamd"
PKG_DESC="Rspamd connector for pubsecd"
PKG_LONG="Turns Rspamd scan results into observations for pubsecd and serves the
active list back to Rspamd as multimaps."
write_control
write_maintscripts pubsec-rspamd /var/lib/pubsec-rspamd
pack

# ------------------------------------------------------------ pubsec-statsd
begin_pkg pubsec-statsd
add_bin pubsec-statsd
add_conf "$root/crates/pubsec-statsd/pubsec-statsd.example.toml" \
    /etc/pubsec-statsd/config.toml
add_unit pubsec-statsd.service enable
PKG_DESC="public statistics page for an AP-TI hub"
PKG_LONG="Polls a hub's internal REST API and publishes aggregates over its
TLP:CLEAR dataset as a self-contained statistics page and a JSON directory of
connected nodes."
write_control
write_maintscripts pubsec-statsd /var/lib/pubsec-statsd
pack

# --------------------------------------------------------- pubsec-allowlist
begin_pkg pubsec-allowlist
add_bin pubsec-allowlist
add_conf "$root/crates/pubsec-allowlist/pubsec-allowlist.example.toml" \
    /etc/pubsec-allowlist/config.toml
add_unit pubsec-allowlist.service enable
PKG_DESC="allowlist sync for pubsecd"
PKG_LONG="Keeps the pubsecd allowlist in sync with a text file, so networks and
domains that must never be reported or banned stay exempt."
write_control
write_maintscripts pubsec-allowlist /var/lib/pubsec-allowlist
pack

# --------------------------------------------------------- pubsec-dashboard
begin_pkg pubsec-dashboard
add_bin pubsec-dashboard
add_conf "$root/crates/pubsec-dashboard/pubsec-dashboard.example.toml" \
    /etc/pubsec-dashboard/config.toml
add_unit pubsec-dashboard.service
add_unit pubsec-dashboard.timer enable
PKG_DESC="static HTML threat map for pubsecd"
PKG_LONG="Renders the pubsecd active list into a self-contained HTML page. The
shipped timer re-renders the page every 15 minutes."
write_control
write_maintscripts pubsec-dashboard /var/lib/pubsec-dashboard
pack
