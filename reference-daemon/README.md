# AP-TI reference daemon

Reference implementation of the *ActivityPub Threat Intelligence Profile*
([`../proposal.md`](../proposal.md), draft-activitypub-threatintel-00).

It follows the deployment model of Appendix D. The workspace contains these crates:

| Crate | Kind | Contents |
|---|---|---|
| `apti-core` | library | Data model (Sec. 4), normalisation (4.1, 10), policy and effective-expiry engine (Sec. 7), control-socket protocol. No I/O. |
| `aptid` | daemon | ActivityPub federation, SQLite storage, internal REST API, control socket. |
| `apti-tui` | TUI | Management client that talks to the daemon over the control socket. |
| `apti-fail2ban` | connector | Pushes fail2ban bans to aptid and writes aptid's active list to files that fail2ban bans from. |
| `apti-allowlist` | connector | Keeps aptid's local allowlist in sync with a text file (bulk import). |
| `apti-rspamd` | connector | Reports IPs and SPF-authenticated envelope-from domains that keep sending spam according to Rspamd to aptid, and serves aptid's active list to Rspamd as multimap files. |

## Build and run

Requires Rust ≥ 1.85. SQLite is built in (`rusqlite` with the `bundled` feature).

```sh
cargo build --release
cp config.example.toml /etc/aptid/config.toml   # then edit it
./target/release/aptid --config /etc/aptid/config.toml --check
./target/release/aptid --config /etc/aptid/config.toml
./target/release/apti-tui --socket /run/aptid/control.sock
```

Logging uses `RUST_LOG`, e.g. `RUST_LOG=aptid=debug`.

### Audit log

With `[audit] enabled = true` the daemon logs every change to an observable
to stdout, next to the other log messages, so the systemd journal captures
it. Audit lines have the target `audit` and are logged at INFO regardless
of `RUST_LOG`:

```sh
journalctl -u aptid -g ' audit: '
```

```
INFO audit: observation received by="api:fail2ban" obs_type="ipv4-addr" value="45.13.7.9" behavior="ssh-bruteforce" count=12 seen="…" tlp="green"
INFO audit: evidence stored by="daemon" obs_type="ipv4-addr" value="45.13.7.9" behavior="ssh-bruteforce" evidence="Sighting" id="https://ti.example.net/objects/…" tlp="green"
INFO audit: active changed by="daemon" obs_type="ipv4-addr" value="45.13.7.9" behavior="ssh-bruteforce" changes="added,activated" active=true flagged=false suspended=false allowlisted=false expiry="…" tlp="green" support=2.0 dispute=0.0
INFO audit: allowlist added by="control:uid=1000" obs_type="ipv4-addr" value="45.13.7.9" behavior="all" id=3 scope="local" summary="our scanner"
```

| Event | When |
|---|---|
| `observation received` | A sensor pushed an observation (`POST /api/v1/observations`). |
| `evidence stored`, `evidence updated` | A Sighting, ThreatIndicator or Opinion was stored or replaced by a newer copy: from a peer (inbox or pull sync) or an own Sighting from a publish batch. |
| `evidence withdrawn` | A peer withdrew evidence with `Delete` or a Tombstone. |
| `evidence purged` | Retention removed evidence that can no longer contribute (Section 11). |
| `allowlist added`, `allowlist extended`, `allowlist removed` | An allowlist entry was changed in the TUI, over the REST API or by resolving a review item. Published entries name their Opinion (`object`). |
| `review resolved` | A review item was dismissed, suspended or allowlisted. |
| `active changed` | A recompute changed an entry of the active list. `changes` lists `added`, `activated`/`deactivated`, `suspended`/`unsuspended`, `flagged`/`unflagged`, `expiry`, `tlp` (while listed) or `removed`; the other fields show the new state. New entries that are neither listed, suspended nor flagged are left out. |

`by` names who caused the change: `api:<token name>`, `control:uid=<uid>`,
`peer:<actor id>` or `daemon`. Strings are quoted and escaped, so remote
values cannot break or forge lines. Pushed observations are logged one per
line, so busy sensors produce many lines.

The daemon opens three endpoints:

- **Public listener** (`[public].bind`): the ActivityPub endpoints. Run it
  behind a TLS-terminating reverse proxy that passes the `Host` header through
  unchanged, because HTTP signatures cover it.
- **Internal REST API** (`[api].bind`): bearer tokens managed in `apti-tui`
  (see [API tokens](#api-tokens)).
  Bind it to an internal address only.
- **Control socket** (`[control].socket`): a unix socket for `apti-tui`,
  created with the configured mode. Each peer is checked with `SO_PEERCRED`:
  the daemon's own uid and root are always allowed, plus `allowed_uids` /
  `allowed_gids`.

The SQLite database and the actor key are created with mode 0600.

## Configuration

See [`config.example.toml`](config.example.toml). The TOML file holds:

- bootstrap settings: URLs, listeners, intervals;
- policy defaults: `k`, local weight, T/M/TLP per behaviour, bootstrap trust
  per operator, and a static allowlist of high-impact infrastructure.

Settings the spec bounds are checked at startup: `publish.tombstone_days`
must be at least 180, `federation.full_resync_interval_secs` at most a week,
`policy.recompute_interval_secs` at most an hour, and
`policy.reject_special_purpose` must stay `true`.

Anything you change in the TUI is stored in the database and **overrides**
the file.

The daemon's own organisation is always trusted, with weight
`policy.local_weight` (default 2, which equals the default `k = 2`). With the
defaults, your own sensors can activate an observable on their own. Set
`local_weight` below `k` if you want to require confirmation from peers.

## REST API

### API tokens

Create tokens in the TUI's **Tokens** tab (`a`). The daemon generates a
random 256-bit secret (`apti_…`), shows it **once** and stores only its
SHA-512 hash in the database. Each token has:

- a unique name (shown in logs);
- one or more scopes: `push`, `read`, `allowlist`, `publish` (see below);
- `max_tlp`, the most restrictive TLP the client may read from the active
  list.

Scope and TLP changes (`e`) take effect immediately. `n` replaces the secret
(the old one stops working at once) and `d` deletes the token. The Tokens tab
also shows when each token was last used.

Tokens are no longer read from the config file: a config that still contains
`[[api.tokens]]` is rejected at startup. Recreate those tokens in the TUI and
give the new secrets to the clients.

### Push observations (scope `push`)

```sh
curl -X POST https://ti-internal:8081/api/v1/observations \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '[{"value": "45.13.7.9", "behavior": "ssh-bruteforce", "port": 22, "service": "ssh", "count": 12},
       {"value": "Evil-Domain.example.", "behavior": "phishing"}]'
# {"accepted":2,"rejected":[]}
```

Fields: `value` (required), `behavior` (required), `observableType`, `port`,
`service`, `seenAt` (RFC 3339, defaults to now), `count` (defaults to 1) and
`tlp`. The request body can be a single object or an array of up to 1000.

`tlp` sets the TLP of the Sighting and replaces the behaviour's publish TLP
(`red` is rejected). It lets a sensor share different kinds of values with
different audiences, e.g. sending IPs as `green` and spam domains as
`clear`:

- Within one batch, the most restrictive requested TLP of an observable wins.
- A published Sighting keeps its TLP. A request for a less restrictive TLP
  updates it without changing the TLP. A request for a more restrictive TLP
  starts a new Sighting with that TLP, so the observation never reaches a
  wider audience than requested; the old Sighting ages out.
- Any `push` token can set any shareable TLP, so give push tokens only to
  sensors you trust with the publish policy.

The daemon normalises each value (IDNA A-labels, RFC 5952, CIDR). It rejects:

- special-purpose addresses and names (RFC 6890);
- prefixes shorter than /24 (IPv4) or /48 (IPv6);
- allowlisted values.

Each rejection is reported per item. Accepted observations are merged per
observable and behaviour, then published every `publish.batch_interval_secs`
as one `Create` or `Update` of a Sighting (Sec. 4.4, 5.3).

### Read the active list (scope `read`)

```sh
curl -H "Authorization: Bearer $TOKEN" \
  'https://ti-internal:8081/api/v1/active?type=ipv4-addr&behavior=ssh-bruteforce&port=22'
```

```json
{"generated": "...", "lastRecompute": "...", "entries": [
  {"observableType": "ipv4-addr", "observableValue": "45.13.7.9", "behavior": "ssh-bruteforce",
   "includeSubdomains": false, "effectiveExpiry": "2026-10-04T13:38:59.324Z", "ttl": 86395,
   "tlp": "green", "flagged": false, "ports": [22], "services": ["ssh"]}]}
```

`ttl` is the number of seconds left until the effective expiry. You can use it
directly as an nftables or ipset element timeout. Filters: `type`, `behavior`,
`port`, `service`.

Each entry carries the most restrictive TLP of the evidence that supports it
(indicators in effect, Sightings within T and `agree` Opinions).
Entries above the token's `max_tlp` are left out, which keeps the TLP intact
(Sec. 9).

### Manage the allowlist

Token scopes:

| Scope | Allows |
|---|---|
| `read` | Listing entries |
| `allowlist` | Adding and removing local entries |
| `allowlist` + `publish` | Also published entries, which are federated as `strongly-disagree` Opinions |

```sh
# Add (scope defaults to "local"; behaviors empty = all)
curl -X POST https://ti-internal:8081/api/v1/allowlist \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"value": "45.13.7.0/24", "behaviors": ["scan"], "validUntil": "2026-12-31T00:00:00Z",
       "summary": "our vulnerability scanner"}'
# 201 {"id": 3, "scope": "local", "observableType": "ipv4-addr", "observableValue": "45.13.7.0/24", ...}

curl -H "Authorization: Bearer $TOKEN" 'https://ti-internal:8081/api/v1/allowlist?scope=local'
curl -H "Authorization: Bearer $TOKEN" https://ti-internal:8081/api/v1/allowlist/3
curl -X DELETE -H "Authorization: Bearer $TOKEN" https://ti-internal:8081/api/v1/allowlist/3
```

POST fields:
- `value` (required);
- `scope`: `local` or `published`;
- `behaviors`;
- `tlp` (published only);
- `validUntil`;
- `summary`: the rationale, published with the Opinion of a published entry;
- `source`: who manages the entry (for example a sync tool). It is stored
  and returned, but never published.

Behaviour:
- **Idempotent POST:** if an unexpired entry with the same scope, value and
  behaviours (and, for published entries, the same TLP) exists, POST returns
  it with `200` instead of `201`. If both have a `validUntil` and the new one
  is later, the entry is extended; a published entry's Opinion is sent again
  as an `Update` to the audience it was first published to.
- **Batching:** the `Create`, `Update` and `Delete` activities of published
  entries are sent with the next publish batch (`publish.batch_interval_secs`),
  grouped by type and audience with up to 1000 objects per activity
  (Sec. 5.3). Several changes to one entry within an interval become one
  activity: a `Create` carries the latest version, and a `Delete` replaces
  everything else. The Opinion is in `activeObjects` immediately.
- **Normalisation:** local entries accept any prefix length. Published
  entries must pass the same checks as published evidence.
- **Deleting a published entry** sends a `Delete` to followers (with the
  next batch).
- **Effect:** changes trigger a recompute. Allowlisted values are also
  rejected by `POST /api/v1/observations`.

`GET /api/v1/health` returns `{"status":"ok"}` and needs no token.

## fail2ban connector (`apti-fail2ban`)

`apti-fail2ban` connects fail2ban to aptid in both directions:

| Subcommand | Direction |
|---|---|
| `push` | Follows the fail2ban log and sends every `Ban` / `Increase Ban` to aptid as an observation (needs a `push` token). |
| `pull` | Polls `GET /api/v1/active` and appends ban lines to files that fail2ban jails follow (needs a `read` token). `pull --once` updates the files once, e.g. from cron. |
| `run` | Both. |
| `check` | Validates the config. |

```sh
apti-fail2ban -c /etc/apti-fail2ban/config.toml check
apti-fail2ban -c /etc/apti-fail2ban/config.toml run
```

See [`crates/apti-fail2ban/apti-fail2ban.example.toml`](crates/apti-fail2ban/apti-fail2ban.example.toml).

### Push

- **Jail mapping:** each jail is mapped to a behaviour, an optional port and
  an optional service in `[push.jails.<jail>]`. Unmapped jails are skipped
  unless `default_behavior` is set.
- **Ignored lines:** `Restore Ban` (re-applied after a fail2ban restart) is
  ignored unless `report_restored = true`. `Unban` is always ignored.
- **Batching:** bans are sent every `batch_interval_secs`, at most 1000 per
  request.
- **Resuming:** the read position (inode and offset) is saved only after
  aptid has accepted the batch. If aptid is unreachable, bans stay queued
  (bounded by `max_queue`) and are retried with backoff. On first start the
  client begins at the end of the log.
- **Log handling:** both log rotation and copy-truncate are handled.
- **Log target:** fail2ban must log to a file (`logtarget = /var/log/fail2ban.log`),
  not to syslog or the journal.

> **Feedback loop:** put the jails fed by `pull` (e.g. `aptid-ssh`) into
> `push.ignore_jails`. Otherwise bans imported from peers would be published
> again as your own Sightings.

### Pull

1. Install the filter and the example jail:

   ```sh
   cp crates/apti-fail2ban/fail2ban/filter.d/apti.conf /etc/fail2ban/filter.d/
   cp crates/apti-fail2ban/fail2ban/jail.d/aptid-ssh.conf.example /etc/fail2ban/jail.d/aptid-ssh.conf
   ```

2. Each `[[pull.output]]` selects entries by behaviour, IP type and
   (optionally) port, and appends lines such as:

   ```
   2026-10-03 16:05:59 apti-ban 45.13.7.9 behavior=ssh-bruteforce expires=2026-10-04T14:05:55Z
   ```

   CIDR prefixes are written as-is; the filter uses `<SUBNET>`, which needs
   fail2ban ≥ 0.10. Domains are never written.

3. Check that the filter matches the file:
   `fail2ban-regex /var/log/apti-fail2ban/ssh.log /etc/fail2ban/filter.d/apti.conf`

**How bans follow the effective expiry.** fail2ban bans for a fixed
`bantime`, so the connector approximates each entry's effective expiry:

- An IP is written when it becomes active.
- It is written again every `refresh_secs` while it stays active.
- Once it expires or is suspended (for example by an allowlist entry), it is
  no longer written, and fail2ban unbans it after at most one `bantime`.

Use `maxretry = 1` and `bantime > refresh_secs + interval_secs`. The
defaults are 1800 + 300 s, with `bantime = 3600`.

If aptid is unreachable, nothing is written, so existing bans simply run out.
Files are rotated to `.1` when they exceed `max_size_bytes`.

## Allowlist file (`apti-allowlist`)

`apti-allowlist` keeps the local or published allowlist in sync with a
hand-edited text file through the REST API (needs an `allowlist` token). The file holds one IP
address, CIDR prefix or domain per line; `#` starts a comment and blank lines
are ignored. Entries apply to all behaviours. Local entries never expire;
published entries are valid for `valid_for_days` and renewed while the tool
runs.

| Flag | Effect |
|---|---|
| `--append` | Values in the file are added; nothing is removed. |
| `--source-of-truth` | Values are added, and entries this tool created are removed once their value is no longer in the file. |
| `--once` | Reconcile once and exit, e.g. from cron. |
| `--check` | Validates the config. |

```sh
apti-allowlist -c /etc/apti-allowlist/config.toml --check
apti-allowlist -c /etc/apti-allowlist/config.toml --source-of-truth
```

See [`crates/apti-allowlist/apti-allowlist.example.toml`](crates/apti-allowlist/apti-allowlist.example.toml).

- **Reconcile:** the whole file is read every `poll_interval_secs`. A change
  is applied once the content is the same at two consecutive reads, so a
  half-written file is not used. Every `resync_interval_secs` the file is
  reconciled anyway, which restores entries removed in the TUI. Additions
  are sent before removals.
- **Present values:** a value counts as present only if an unexpired entry
  of the configured scope exists that applies to all behaviours (and, for
  published entries, has the configured TLP). A TUI entry restricted to some
  behaviours does not count, and the tool adds its own entry.
- **Ownership:** entries the tool creates carry the internal source
  `apti-allowlist:<path>` (`file.source`), which is never published.
  Source-of-truth mode removes only these, unless `prune_all = true`, which
  removes every entry of the scope that is not in the file. Use a distinct
  source per file if you run several instances. `file.summary` is an
  optional rationale; published entries carry it as the Opinion's
  `summary`.
- **Guards:** a missing or unreadable file changes nothing. A file without
  values removes nothing unless `allow_empty = true`, and a reconcile that
  would remove more than `max_removals` entries (default 100) removes none.
  Invalid lines are logged and skipped.
- **Domains** cover only themselves, not their subdomains (unlike
  `policy.allowlist` in the aptid config).
- **Published entries:** with `file.scope = "published"` the entries are
  federated as `strongly-disagree` Opinions with `file.tlp` (required; not
  RED). The token needs `allowlist` and `publish`; removals send `Delete` to
  followers. Activities go out with aptid's next publish batch, so a bulk
  import or a TLP change becomes a few activities, not one per line. Values must pass the checks for published evidence (no private
  addresses, prefixes of at least /24 or /48); aptid rejects the others.
  Entries are valid for `valid_for_days` (default 90) and are extended with
  an `Update` once they expire within `renew_before_days` (default a tenth).
  An entry with another TLP does not count: changing `file.tlp` publishes
  new entries, and in source-of-truth mode withdraws the old ones. An
  instance manages one scope; run two instances for local and published
  entries. Published entries suspend values in the own active list, but
  only local entries make `POST /api/v1/observations` reject a value.
- **Rejected values** are logged when the file changes and retried at the
  next resync.
- **Outages:** if aptid is unreachable, the reconcile is retried with
  backoff.

## Rspamd connector (`apti-rspamd`)

`apti-rspamd` connects Rspamd to aptid in both directions. It runs one local
HTTP endpoint (`[server].bind`, default `127.0.0.1:11380`):

| Path | Direction |
|---|---|
| `POST /v1/report` | A Lua plugin in Rspamd posts the result of each scanned message. IPs and, optionally, SPF-authenticated envelope-from domains that keep sending bad messages are reported to aptid as observations (`[ingest]`, needs a `push` token). |
| `GET /maps/<name>` | aptid's active list as multimap files, refreshed every `maps.interval_secs` (`[maps]`, needs a `read` token). |

| Subcommand | Effect |
|---|---|
| `run` | Serves the endpoint and runs the configured sections. |
| `maps` | Fetches the active list once and prints all maps. |
| `check` | Validates the config. |

```sh
apti-rspamd -c /etc/apti-rspamd/config.toml check
apti-rspamd -c /etc/apti-rspamd/config.toml run
```

See [`crates/apti-rspamd/apti-rspamd.example.toml`](crates/apti-rspamd/apti-rspamd.example.toml).
Keep the endpoint on loopback: the maps contain TLP-restricted data, limited
by the read token's `max_tlp`.

### Ingest

1. Install the plugin and its settings (Debian paths; `CONFDIR` and
   `LOCAL_CONFDIR` are both `/etc/rspamd`):

   ```sh
   cp crates/apti-rspamd/rspamd/lua.local.d/apti.lua /etc/rspamd/lua.local.d/
   cp crates/apti-rspamd/rspamd/modules.local.d/apti.conf /etc/rspamd/modules.local.d/
   ```

   Set `secret` in `apti.conf` to `ingest.report_secret`. The plugin
   registers the idempotent symbol `APTI_REPORT`, which runs after scoring.
   For each message with a score of at least its `min_score` it sends the
   sending IP, the envelope-from domain, the score, the action, the names
   and scores of all symbols that fired (also those with score 0) and
   whether the sender authenticated. Local senders are skipped, and
   failures never affect mail processing.

2. A message is **bad** if its score, minus the score of the symbols in
   `ignore_symbols`, is at least `min_score`. An IP that sends `min_messages`
   bad messages within `window_secs` is reported as an observation with
   `behavior` (default `smtp-spam`), `service`, `port`, `tlp` and the number
   of bad messages as `count`. While it keeps sending, it is reported again
   at most once per `report_interval_secs`.

- **Skipped senders:** authenticated users (`ignore_authenticated`),
  special-purpose addresses and `ignore_networks` (own relays, backup MX).
  aptid also rejects allowlisted values.
- **IPv6** senders are tracked and reported as their `ipv6_prefix` (default
  /64; aptid accepts /48 and longer).
- **Batching and outages:** reports are sent every `batch_interval_secs`, at
  most 1000 per request. If aptid is unreachable they stay queued (bounded by
  `max_queue`) and are retried with backoff. The counters are in memory only;
  `max_tracked` bounds how many IPs and domains are tracked.
- **TLP:** `ingest.tlp` and `ingest.envelope_from.tlp` set the TLP of the
  reported IPs and domains separately (see the `tlp` field of
  [push observations](#push-observations-scope-push)). Unset, aptid uses the
  behaviour's publish TLP.

#### Envelope-from domains

With `[ingest.envelope_from]` the domain of the SMTP envelope sender
(`MAIL FROM`) of bad messages is reported too, as `domain-name` with its own
`behavior` (default `smtp-spam`) and `tlp`. The exact domain is reported,
never its parent. A message counts for its domain only if:

- it is bad (same rule as for IPs) and has a non-empty envelope sender
  (bounces are skipped);
- every symbol in `require_symbols` fired, by default `R_SPF_ALLOW`.
  The envelope sender can be forged freely; an SPF pass means the domain
  authorised the sending IP, so the domain owner is responsible;
- no symbol in `skip_symbols` fired, by default `FREEMAIL_ENVFROM` and
  `DISPOSABLE_ENVFROM`, which Rspamd sets for shared mail providers;
- the domain passes aptid's normalisation and is not in `ignore_domains`
  (which also matches subdomains).

A domain with `min_messages` such messages from at least `min_senders`
distinct senders within `window_secs` is reported, at most once per
`report_interval_secs` (both default to a day).

- **`ignore_domains`:** add your own domains and the bounce domains of mail
  service providers. Their SPF records authorise the provider's servers for
  all customers; the example config lists common ones. Rspamd's freemail
  list is incomplete (e.g. `mailbox.org` was missing in the 4.2.1 maps), so
  add the providers your users see.
- **Shared SPF:** SPF records that include large platforms let other
  customers of the platform pass SPF for the domain. Raise `min_messages`
  or `min_senders` if that is a concern, and set `local_weight` below `k`
  in aptid to require confirmation from peers.

> **Feedback loop:** the symbols of the multimaps fed by `[maps]` must match
> `ignore_symbols` (default `APTI_*`). Otherwise a message that is bad only
> because a peer listed its sender would be published again as your own
> Sighting.

### Maps

Add the rules of
[`rspamd/local.d/multimap.conf.example`](crates/apti-rspamd/rspamd/local.d/multimap.conf.example)
to `/etc/rspamd/local.d/multimap.conf`:

| Symbol | Matches | Map (example config) |
|---|---|---|
| `APTI_BAD_IP` | sending IP | `ip`: all behaviours |
| `APTI_BAD_URL` | hosts of URLs in the message | `url-domains`: phishing, malware-hosting, command-and-control |
| `APTI_BAD_FROM` | envelope sender domain | `sender-domains`: smtp-spam |
| `APTI_BAD_HEADER_FROM` | `From` header domain | `sender-domains` |

Each `[[maps.map]]` selects entries by `kind` (`ip` or `domain`) and
behaviour. Entries flagged for review are left out unless
`include_flagged = true`.

```
# apti-rspamd map url-domains
# phishing
/(^|\.)phish\.example\.com$/i
```

- **IP maps** list addresses and CIDR prefixes (radix map). **Domain maps**
  are regexp maps (`regexp = true` in multimap). A domain whose entry has
  `includeSubdomains` also matches its subdomains.
- **Behaviours** are written as a comment above each entry, because
  multimap reads a value after the key as a symbol name.
- **Caching:** responses carry `ETag`, `Last-Modified` and `Expires`.
  Unchanged maps are answered with `304`. Rspamd checks HTTP maps at most
  every `map_watch_interval` (5 minutes by default), so a change can take
  that long to reach Rspamd.
- **Outages:** if aptid is unreachable, the maps are rendered from the last
  fetched list, so entries still drop out at their effective expiry.

## ActivityPub endpoints

| Path | Description |
|---|---|
| `/.well-known/webfinger` | `acct:<username>@<host>` |
| `/actor` | `Service` actor with `operator`, `activeObjects`, `publicKey`, `endpoints.sharedInbox` |
| `/org` | `Organization` with `operatedActors` (bidirectional operator link, Sec. 3.2) |
| `/actor/inbox`, `/inbox` | Inbox and shared inbox (HTTP signature required) |
| `/actor/active` | `activeObjects`, paged with 1000 items per page, newest first, Tombstones kept. Signed fetch required; filtered by TLP. |
| `/actor/outbox` | Recent activities visible to the requester |
| `/actor/followers`, `/actor/following` | Counts only |
| `/objects/{id}`, `/activities/{id}` | Single objects. Signed fetch required unless TLP:CLEAR. |
| `/ns/ti` | JSON-LD context of Appendix B |

TLP visibility on fetch:

| TLP | Who can see it |
|---|---|
| CLEAR | anyone |
| GREEN | accepted followers |
| AMBER, AMBER+STRICT | the named recipients that were configured when the object was first published. Later `Update`s and `Delete`s of the object go to the same recipients. |

## TUI

Switch tabs with `←`/`→` or the number keys. Global keys: `r` refresh,
`R` recompute now, `q` quit. On every table, `f` opens a filter with one
field per column (case-insensitive substring, all fields must match) and `F`
clears it. Filters are kept per tab. The scroll bar and the bottom border
show the position of the selected row; with a filter active it reads
`selected/matching (total)`.

| Tab | Actions |
|---|---|
| Status | Counters, queues, last recompute; TLP addressing overview. `e` set the default TLP and the AMBER recipient list |
| Following | `a` follow (`user@host` or URL), `d` unfollow, `s` full resync |
| Followers | `a` approve, `x` reject or remove (needed for TLP:GREEN) |
| Operators | `e` set trusted/weight (operator default or per behaviour), `t` toggle trust, `c` clear a policy, `m` override actor→operator mapping |
| Behaviours | `e` set `k` (number or `off`), T, M and the publish TLP per behaviour |
| Tokens | REST API tokens: `a` create (secret shown once), `e` edit scopes and max TLP, `n` new secret, `d` delete |
| Review | `d` dismiss, `s` suspend `(O, b)`, `w` allowlist `O`, `h` show resolved, `⏎` lookup |
| Allowlist | `a` add (local, or published as a `strongly-disagree` Opinion), `d` remove (published entries send `Delete`) |
| Active | `d` dismiss: suspend the selected `(O, b)` with a local allowlist entry (undo by removing it in the Allowlist tab), `i` include inactive or suspended entries, `⏎` lookup |
| Lookup | `/` look up a value: shows assessments with S/D weights, all evidence (including withdrawn) and covering allowlist entries. Filters apply to the evidence table |

## How the spec maps to the code

| Spec | Where |
|---|---|
| 4.1 Normalisation, 10 special-purpose rejection | `apti-core/src/normalize.rs` |
| 4.3–4.5 Evidence objects and validation | `apti-core/src/model.rs` |
| 7 Effective expiry, quorum, suspension, allowlist | `apti-core/src/expiry.rs`, `policy.rs` (Table 1 defaults) |
| 3.2 Operator resolution (verified link, else PSL) | `aptid/src/client.rs` |
| 5.1 Activities, 8 origin, replay and newer-`updated` rules | `aptid/src/inbox.rs`, `db.rs` (`upsert_evidence`) |
| 5.2 Addressing, 5.3 batching | `aptid/src/publish.rs` |
| 5.3 `activeObjects` and pull sync | `aptid/src/ap.rs`, `aptid/src/sync.rs` |
| 8 HTTP signatures | `aptid/src/httpsig.rs` |
| 9 Aggregation, 11 retention | `aptid/src/engine.rs`, `aptid/src/api.rs` |
| Appendix D control socket | `aptid/src/control.rs`, `apti-tui` |
| Appendix D internal API: sensors and enforcement | `aptid/src/api.rs`, `aptid/src/allowlist.rs`, `apti-fail2ban`, `apti-rspamd` |

## Tests

```sh
cargo test --workspace
```

- **Unit tests:** normalisation edge cases and the expiry scenarios (quorum
  with weights, `w = k`, `k = off`, the M cap, revoked or future-dated
  evidence, D ≥ S suspension, prefix allowlist, opinions via
  `indicatorRefs`). Also HTTP signature round trip and tampering, the database
  upsert rules (withdrawn objects cannot be revived, foreign publishers are
  ignored), and `activeObjects` paging.
- **`crates/aptid/tests/integration.rs`:**
  - **Local pipeline:** the full path through the REST API, the batcher, the
    engine and the control socket.
  - **Observation TLP:** requested TLPs replace the behaviour default, RED
    is rejected, the most restrictive request in a batch wins, and a
    stricter request starts a new Sighting.
  - **Two daemons:** they federate over localhost: WebFinger follow, manual
    approval, Accept, a pull sync that reveals GREEN content after acceptance,
    inbox `Create` and `Update`, verified operator mapping, the untrusted
    review queue, trust activation, a published allowlist that suspends
    remotely, `Delete` re-activating the entry, and `Undo`.
  - **REST allowlist:** scopes, validation, idempotent POST, extension of
    published entries with `Update`, TLP as part of a published entry,
    the unpublished `source`, batching of Opinion activities (grouping,
    collapsing a `Create` and `Delete` within one interval),
    suspension, and withdrawal of published entries.
  - **API tokens:** creation, scope changes, rotation and deletion over the
    control socket; only the SHA-512 hash is stored.
- **`crates/aptid/tests/audit.rs`:** the audit log: nothing is logged when
  disabled; a push, the published Sighting, activation, an allowlist entry
  from the control socket, suspension, removal over the REST API and
  re-activation are logged with their origin; a newline in a summary is
  escaped; a recompute without changes logs nothing. Unit tests in
  `aptid/src/audit.rs` cover the active-list diff.
- **`crates/apti-fail2ban`:**
  - **Unit tests:** fail2ban log parsing and jail mapping, the log tailer
    (rotation, truncation, resume), and the pull re-emit logic.
  - **End-to-end test** against an in-process aptid: fail2ban log → push →
    Sighting → pull → ban file, including a dynamic allowlist and an outage
    followed by a restart.
  - **Manual check:** the shipped filter was verified with
    `fail2ban-regex` (fail2ban 1.1.0).
- **`crates/apti-allowlist`:**
  - **Unit tests:** config validation, file parsing and the reconcile plan
    (restricted and expired entries, ownership, `prune_all`, TLP and
    renewal of published entries).
  - **End-to-end tests** against an in-process aptid: import, edits,
    restoring removed entries, the removal guards, append mode, waiting
    for a stable file, an outage, and published entries (TLP, summary
    published but source not, one batched `Create`, rejected values,
    renewal, TLP change, missing `publish` scope).
- **`crates/apti-rspamd`:**
  - **Unit tests:** config validation, report parsing, the reputation
    window (ignored symbols, cooldown, IPv6 prefixes, skipped senders,
    bounded state), the envelope-from rule (SPF required, zero-score skip
    symbols, ignored and invalid domains, distinct senders, TLP per rule),
    map rendering and conditional requests.
  - **End-to-end test** against an in-process aptid: reports → push →
    Sighting → map file, including the shared secret, the feedback-loop
    guard, a forged and an authenticated envelope sender, separate TLPs for
    IPs and domains, an allowlist that removes the IP from the map, `304`
    responses and an outage.
  - **Manual check:** the Lua plugin and the multimap rules were verified
    with Rspamd 4.2.1: all four symbols match, a message that is bad only
    because of `APTI_*` symbols is not reported, and repeated spam is. With
    real SPF records: an SPF-authenticated envelope-from domain is reported
    with its own TLP, a forged one is skipped, and `gmail.com` is skipped
    via the zero-score `FREEMAIL_ENVFROM`.

## Limitations

These are deliberate scope cuts for a reference implementation:

- **HTTP signatures:** only draft-cavage-12 (`rsa-sha256` / `hs2019` with RSA)
  is implemented. The spec allows it as an alternative to RFC 9421.
- **Integrity proofs:** FEP-8b32 proofs are not verified. Content from
  `Announce` is fetched again from its origin with a signed fetch.
- **Publishing:** the daemon publishes Sightings (from sensors) and allowlist
  Opinions. It does not publish `ThreatIndicator`s or `agree`/`disagree`
  Opinions, but it consumes all three evidence types.
- **RDAP:** holder verification for `disagree` Opinions is not implemented.
  Opinions count only if their operator is trusted.
- **Exports:** JSON only. There are no TAXII, RPZ, DNSBL or nftables exports;
  `ttl` makes a client-side nftables export simple.
- **SSRF:** remote URLs must be https (or http with `allow_http`) and resolve
  to public addresses (unless `allow_private_addresses` is set). An actor's
  inbox, shared inbox and `activeObjects` must be on the actor's own host.
  An HTTP(S) proxy taken from the environment must also have a public
  address.
- **Scale:** the engine reloads all live evidence on every recompute. This is
  fine for tens of thousands of objects, but not for a large aggregator.
- **Shutdown:** in-flight HTTP requests are not drained on shutdown.
- **AMBER visibility:** AMBER objects are visible to the recipient list that
  was configured when they were first published, and refreshed Sightings are
  delivered only to that list. Changing the list later affects new objects
  only.
- **Withdrawing Sightings:** own Sightings cannot be withdrawn with `Delete`
  (for example after a false positive); they age out after T. Publish an
  allowlist entry to counter them.
- **Rate limits:** inbox requests are limited per signing actor, not per
  operator, and signed `GET`s are not rate-limited (Section 10 asks for both).
- **Federation peers:** the hosts of followed actors and followers are not
  allowlisted automatically (Section 10). Add them to `policy.allowlist`.
- **Documentation ranges:** `allow_documentation_ranges` accepts RFC 5737 /
  RFC 3849 / RFC 2606 values, which Section 10 requires consumers to reject.
  Use it for demos only.
