# Docker

Compose setup for `pubsecd`, `pubsec-fail2ban` and `fail2ban`. The images are
built locally on Debian trixie and nothing is pushed to a registry. Each
Dockerfile downloads the released binary for `PUBSEC_VERSION` from the GitHub
release and checks it against the release's `SHA256SUMS`. There is no Rust
toolchain in the build.

Only `linux/x86_64` is supported, because that is what the releases contain.

## pubsecd

```sh
cd docker
cp .env.example .env                                  # release tag
cp config/pubsecd.example.toml config/pubsecd.toml        # set [instance]
cp config/pubsec-fail2ban.example.toml config/pubsec-fail2ban.toml
docker compose build
docker compose up -d pubsecd
```

The compose file publishes the ActivityPub listener on `127.0.0.1:8080`
(put a TLS reverse proxy in front, passing `Host` through) and the internal
REST API on `127.0.0.1:8081`. Inside the container both bind `0.0.0.0`.
Do not publish the API on a public address.

Create the API tokens in the TUI and copy the secrets into
`config/pubsec-fail2ban.toml` (`push_token`, `read_token`):

```sh
docker compose exec pubsecd pubsec-tui --socket /run/pubsecd/control.sock
```

## fail2ban and pubsec-fail2ban

```sh
docker compose up -d fail2ban pubsec-fail2ban
```

These are two containers. `fail2ban` runs stock `fail2ban-server` and does
the banning; `pubsec-fail2ban` runs the connector. They exchange files over
two volumes: `f2b-log` holds fail2ban's log, which `push` follows, and
`f2b-pull` holds the ban files written by `pull`, which the `pubsecd-*` jails
follow. The connector uses the Debian base, because the released binary is
linked against glibc.

- **Host network and capabilities:** only the `fail2ban` container runs with
  `network_mode: host` and `NET_ADMIN`/`NET_RAW`, so the nftables action
  bans on the host. This is the only privileged part. To only report bans,
  drop both and set `banaction = dummy` in
  `fail2ban/jail.d/00-defaults.local`.
- **The connector is unprivileged** and reaches pubsecd over the compose
  network (`http://pubsecd:8081`).
- **Config:** `fail2ban/fail2ban.local` sets the log target to a file, which
  `push` needs. `fail2ban/jail.d/` holds the jails, including `pubsecd-ssh`
  fed by `pull`. That jail is in `push.ignore_jails`; keep it there.
- **Host with legacy iptables:** set `banaction = iptables-multiport` in
  `00-defaults.local`.

## Public hub (pubsec-statsd)

`compose.hub.example.yaml` runs a public hub: `pubsecd` in hub mode (follows
back every node that connects, ingests only TLP:CLEAR, and trusts connected
nodes) and `pubsec-statsd`, which publishes an aggregate statistics page over
the hub's TLP:CLEAR dataset and a JSON directory of connected nodes, behind
Caddy for TLS.

```sh
cd docker
cp .env.example .env
cp config/pubsecd-hub.example.toml config/pubsecd-hub.toml      # set [instance]
cp config/pubsec-statsd.example.toml config/pubsec-statsd.toml
cp Caddyfile.hub.example Caddyfile.hub                       # set hosts
docker compose -f compose.hub.example.yaml build
docker compose -f compose.hub.example.yaml up -d
```

Then create a `read` token with `max_tlp = "clear"` for pubsec-statsd and put
its secret in `config/pubsec-statsd.toml`:

```sh
docker compose -f compose.hub.example.yaml exec pubsecd pubsec-tui --socket /run/pubsecd/control.sock
```

- `ti.example.net` serves the hub's ActivityPub endpoints; other AP-TI nodes
  connect by following `feed@ti.example.net`.
- `stats.example.net` serves the public statistics page (`/`) and the
  connected-node directory (`/nodes.json`). Individual observables are not
  published.
- pubsec-statsd renders both into the `statsd-public` volume after every poll
  and Caddy serves that volume read-only; pubsec-statsd itself publishes no
  port and is not reachable from the network.
- The internal API (`8081`) is reached by pubsec-statsd over the compose
  network; keep it off the public internet.

## Parsing other containers' logs

`compose.landscape.example.yaml` shows how to mount the log volumes of other
services read-only into the `fail2ban` container:

```sh
cp fail2ban/jail.d/landscape.local.example fail2ban/jail.d/landscape.local
docker compose -f compose.yaml -f compose.landscape.example.yaml up -d
```

Rules for this setup:

1. The application must write its log to a **file** on a volume, not to
   stdout.
2. Mount the same volume read-only into `fail2ban` and point a jail's
   `logpath` at the file.
3. Use `backend = polling` (the default here), because inotify is unreliable
   on shared volumes.
4. Map each new jail to a behaviour in `[push.jails.<jail>]` of
   `config/pubsec-fail2ban.toml`. Unmapped jails are not reported.
5. The `fail2ban` image contains fail2ban's stock filters (`sshd`, `apache-auth`,
   `postfix`, ...). Mount custom ones into `/etc/fail2ban/filter.d/`.

The service names, volumes and log paths in the example are placeholders.
Check each application's real log location.

## Notes

- State lives in the named volumes `pubsecd-data` (database and actor key),
  `pubsecd-run` (control socket), `f2b-state`, `f2b-pull` and `f2b-log`.
- `SHA256SUMS` comes from the same release as the binary. It protects
  against corrupt downloads, not against a compromised release.
