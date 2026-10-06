# Docker

Compose setup for `aptid` and `apti-fail2ban`. The images are built locally
and nothing is pushed to a registry. Each Dockerfile downloads the released
binary for `APTI_VERSION` from the GitHub release and checks it against the
release's `SHA256SUMS`. There is no Rust toolchain in the build.

Only `linux/x86_64` is supported, because that is what the releases contain.

## aptid

```sh
cd docker
cp .env.example .env                                  # release tag
cp config/aptid.example.toml config/aptid.toml        # set [instance]
cp config/apti-fail2ban.example.toml config/apti-fail2ban.toml
docker compose build
docker compose up -d aptid
```

The compose file publishes the ActivityPub listener on `127.0.0.1:8080`
(put a TLS reverse proxy in front, passing `Host` through) and the internal
REST API on `127.0.0.1:8081`. Inside the container both bind `0.0.0.0`.
Do not publish the API on a public address.

Create the API tokens in the TUI and copy the secrets into
`config/apti-fail2ban.toml` (`push_token`, `read_token`):

```sh
docker compose exec aptid apti-tui --socket /run/aptid/control.sock
```

## apti-fail2ban

```sh
docker compose up -d apti-fail2ban
```

The container runs `fail2ban-server` and `apti-fail2ban run` together and
stops if either one exits. It uses the Debian base, because the released
binary is linked against glibc.

- **Host network and capabilities:** `network_mode: host` with `NET_ADMIN`
  and `NET_RAW` so the nftables action bans on the host. This is the only
  privileged part. To only report bans, drop both and set `banaction = dummy`
  in `fail2ban/jail.d/00-defaults.local`.
- **Config:** `fail2ban/fail2ban.local` sets the log target to a file, which
  `push` needs. `fail2ban/jail.d/` holds the jails, including `aptid-ssh`
  fed by `pull`. That jail is in `push.ignore_jails`; keep it there.
- **Host with legacy iptables:** set `banaction = iptables-multiport` in
  `00-defaults.local`.

## Parsing other containers' logs

`compose.landscape.example.yaml` shows how to mount the log volumes of other
services read-only into the `apti-fail2ban` container:

```sh
cp fail2ban/jail.d/landscape.local.example fail2ban/jail.d/landscape.local
docker compose -f compose.yaml -f compose.landscape.example.yaml up -d
```

Rules for this setup:

1. The application must write its log to a **file** on a volume, not to
   stdout.
2. Mount the same volume read-only into `apti-fail2ban` and point a jail's
   `logpath` at the file.
3. Use `backend = polling` (the default here), because inotify is unreliable
   on shared volumes.
4. Map each new jail to a behaviour in `[push.jails.<jail>]` of
   `config/apti-fail2ban.toml`. Unmapped jails are not reported.
5. The image contains fail2ban's stock filters (`sshd`, `apache-auth`,
   `postfix`, ...). Mount custom ones into `/etc/fail2ban/filter.d/`.

The service names, volumes and log paths in the example are placeholders.
Check each application's real log location.

## Notes

- State lives in the named volumes `aptid-data` (database and actor key),
  `aptid-run` (control socket), `f2b-state` and `f2b-pull`.
- `SHA256SUMS` comes from the same release as the binary. It protects
  against corrupt downloads, not against a compromised release.
