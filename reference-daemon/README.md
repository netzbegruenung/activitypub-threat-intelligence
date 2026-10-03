# AP-TI reference daemon

Reference implementation of the *ActivityPub Threat Intelligence Profile*
([`../proposal.md`](../proposal.md), draft-seeberg-activitypub-threatintel-00).

It follows the deployment model of Appendix D. The workspace contains three crates:

| Crate | Kind | Contents |
|---|---|---|
| `apti-core` | library | Data model (Sec. 4), normalisation (4.1, 10), policy and effective-expiry engine (Sec. 7), control-socket protocol. No I/O. |
| `aptid` | daemon | ActivityPub federation, SQLite storage, internal REST API, control socket. |
| `apti-tui` | TUI | Management client that talks to the daemon over the control socket. |
| `apti-fail2ban` | connector | Pushes fail2ban bans to aptid and writes aptid's active list to files that fail2ban bans from. |

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

The daemon opens three endpoints:

- **Public listener** (`[public].bind`): the ActivityPub endpoints. Run it
  behind a TLS-terminating reverse proxy that passes the `Host` header through
  unchanged, because HTTP signatures cover it.
- **Internal REST API** (`[api].bind`): bearer tokens from the config file.
  Bind it to an internal address only.
- **Control socket** (`[control].socket`): a unix socket for `apti-tui`,
  created with the configured mode. Each peer is checked with `SO_PEERCRED`:
  the daemon's own uid and root are always allowed, plus `allowed_uids` /
  `allowed_gids`.

The SQLite database and the actor key are created with mode 0600.

## Configuration

See [`config.example.toml`](config.example.toml). The TOML file holds:

- bootstrap settings: URLs, listeners, tokens, intervals;
- policy defaults: `k`, local weight, T/M/TLP per behaviour, bootstrap trust
  per operator, and a static allowlist of high-impact infrastructure.

Anything you change in the TUI is stored in the database and **overrides**
the file.

The daemon's own organisation is always trusted, with weight
`policy.local_weight` (default 2, which equals the default `k = 2`). With the
defaults, your own sensors can activate an observable on their own. Set
`local_weight` below `k` if you want to require confirmation from peers.

## REST API

### Push observations (scope `push`)

```sh
curl -X POST https://ti-internal:8081/api/v1/observations \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '[{"value": "45.13.7.9", "behavior": "ssh-bruteforce", "port": 22, "service": "ssh", "count": 12},
       {"value": "Evil-Domain.example.", "behavior": "phishing"}]'
# {"accepted":2,"rejected":[]}
```

Fields: `value` (required), `behavior` (required), `observableType`, `port`,
`service`, `seenAt` (RFC 3339, defaults to now) and `count` (defaults to 1).
The request body can be a single object or an array of up to 1000.

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

Each entry carries the most restrictive TLP of the evidence that supports it.
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
- `summary`.

Behaviour:
- **Idempotent POST:** if an unexpired entry with the same scope, value and
  behaviours exists, POST returns it with `200` instead of `201`.
- **Normalisation:** local entries accept any prefix length. Published
  entries must pass the same checks as published evidence.
- **Deleting a published entry** sends a `Delete` to followers.
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
| AMBER, AMBER+STRICT | the named recipients that were configured when the object was published |

## TUI

Switch tabs with `←`/`→` or the number keys. Global keys: `r` refresh,
`R` recompute now, `q` quit.

| Tab | Actions |
|---|---|
| Status | Counters, queues, last recompute |
| Following | `a` follow (`user@host` or URL), `d` unfollow, `s` full resync |
| Followers | `a` approve, `x` reject or remove (needed for TLP:GREEN) |
| Operators | `e` set trusted/weight (operator default or per behaviour), `t` toggle trust, `c` clear a policy, `m` override actor→operator mapping |
| Behaviours | `e` set `k` (number or `off`), T, M and the publish TLP per behaviour |
| TLP | `e` set the default TLP and the AMBER recipient list |
| Review | `d` dismiss, `s` suspend `(O, b)`, `w` allowlist `O`, `h` show resolved, `⏎` lookup |
| Allowlist | `a` add (local, or published as a `strongly-disagree` Opinion), `d` remove (published entries send `Delete`) |
| Active | `i` include inactive or suspended entries, `⏎` lookup |
| Lookup | `/` look up a value: shows assessments with S/D weights, all evidence (including withdrawn) and covering allowlist entries |

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
| Appendix D internal API: sensors and enforcement | `aptid/src/api.rs`, `aptid/src/allowlist.rs`, `apti-fail2ban` |

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
  - **Two daemons:** they federate over localhost: WebFinger follow, manual
    approval, Accept, a pull sync that reveals GREEN content after acceptance,
    inbox `Create` and `Update`, verified operator mapping, the untrusted
    review queue, trust activation, a published allowlist that suspends
    remotely, `Delete` re-activating the entry, and `Undo`.
  - **REST allowlist:** scopes, validation, idempotent POST, suspension,
    and withdrawal of published entries.
- **`crates/apti-fail2ban`:**
  - **Unit tests:** fail2ban log parsing and jail mapping, the log tailer
    (rotation, truncation, resume), and the pull re-emit logic.
  - **End-to-end test** against an in-process aptid: fail2ban log → push →
    Sighting → pull → ban file, including a dynamic allowlist and an outage
    followed by a restart.
  - **Manual check:** the shipped filter was verified with
    `fail2ban-regex` (fail2ban 1.1.0).

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
  was configured when they were published. Changing the list later does not
  change who can see existing objects.
