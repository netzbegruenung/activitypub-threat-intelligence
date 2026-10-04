# ActivityPub Threat Intelligence (AP-TI)

AP-TI lets organisations share network threat intelligence over ActivityPub.
The shared observables are IP addresses, prefixes and domains linked to abuse
such as SSH brute force, spam, scanning or command-and-control.

STIX/TAXII and MISP work well inside a fixed sharing community, but they have
no open discovery. ActivityPub adds discovery (WebFinger), a follow graph and
domain-bound identity, so participants can find each other across
organisational boundaries.

## Core ideas

- **Evidence types.** Publishers share *Sightings* (first-hand observations),
  *ThreatIndicators* (curated claims with a validity period) and *Opinions*
  (agreement, disagreement or allowlisting). The terms follow STIX 2.1, so
  aggregators can map them directly to STIX/TAXII.
- **Nothing is listed forever.** All evidence ages out. Peers cannot set
  expiry for others: each consumer computes an *effective expiry* from fresh
  evidence under its own trust policy.
- **Local trust policy.** Following an actor does not mean trusting it.
  Consumers set trust and weights per operator and behaviour. Sightings
  activate an observable only when a weighted quorum of trusted operators
  reports it. Trusted disagreement or allowlist entries can suspend it.
- **TLP-aware sharing.** Every object has a Traffic Light Protocol level
  (CLEAR, GREEN, AMBER, AMBER+STRICT). The level decides how the object is
  addressed and who may fetch it.
- **Hardened against abuse.** The spec covers poisoning, Sybil attacks,
  replay, origin checks and special-purpose addresses, and adds privacy
  guidance for personal data such as IP addresses.

Enforcement points (firewalls, fail2ban, DNS RPZ and so on) never use
ActivityPub themselves. They read an aggregator's exported active list.

## Sharing observables between organisations

Every receiving organisation decides on its own how much weight the evidence
of each peer carries. The rules are in Sections 5.2, 7 and 8 of the
[spec](proposal.md). The [`config.example.toml`](reference-daemon/config.example.toml)
names used by the reference daemon are given in brackets.

### Trust and weights

Trust and weight are set per **operator** (the organisation behind one or more
actors), not per actor. They can also be set per behaviour, for example to
trust a partner for `ssh-bruteforce` but not for `smtp-spam`.

- **Trust** (`trusted`, default `false`). Evidence from untrusted operators
  never affects the active list. The reference daemon puts it in a review
  queue instead. Following a peer only means receiving its evidence. It does
  not mean trusting it.
- **Weight** (`weight`, default 1, must be ≥ 0). This is how much a trusted
  operator counts towards the quorum and in disputes. An operator counts
  once, however many Sightings or actors it has. Weight 0 means the operator
  is trusted but counts for nothing in the quorum or in disputes. Its
  Indicators and allowlist entries still apply.
- **Own organisation.** The daemon always trusts its own sensors, with weight
  `local_weight` (default 2).

### Quorum

*Sightings* (raw observations) list an observable only when enough trusted
operators report it. *ThreatIndicators* from a trusted operator do not need a
quorum. They stay listed until their own `validUntil`, but never longer than
the maximum evidence age M.

- **Threshold `k`** (`default_k`, or `k` per behaviour, default 2). The summed
  weight of operators with recent Sightings must reach at least `k`. With
  `k = "off"`, Sightings never list an observable alone and only Indicators
  do. The example config uses this for `command-and-control`.
- **Expiry.** Sort the operators by their latest `lastSeen`, newest first, and
  add up their weights. The `lastSeen` of the operator at which the sum
  reaches `k` is the quorum time L. The entry expires at L + min(T, M), where
  T is the Sighting TTL and M the maximum evidence age of the behaviour.
  Nobody else can extend an expiry. Once trusted operators stop reporting an
  observable, it drops off the list.
- **Disputes.** Trusted `disagree` or `strongly-disagree` Opinions add up to a
  dispute weight D. Supporting operators (valid indicator, Sighting within T,
  `agree` Opinion) add up to a support weight S. If D > 0 the entry is
  flagged for review. If D ≥ S it is suspended. A trusted allowlist entry
  always suspends it.

Example with `k = 2`, `local_weight = 2` and two partners at weight 1:

| Who reports `45.13.7.9` for `ssh-bruteforce` | Summed weight | Listed? |
|---|---|---|
| Partner A only | 1 | No |
| Partners A and B | 2 | Yes, until the older of their two `lastSeen` + T |
| Own sensors only | 2 | Yes. Set `local_weight` below `k` to require peer confirmation. |
| Partner A with weight 2 | 2 | Yes. A weight equal to `k` lets one operator list observables alone. |

High weights and `k = 1` make a single compromised operator enough to list
observables. Keep weights below `k` unless you trust that operator to act
alone.

### TLP

Every evidence object carries a [TLP 2.0](https://www.first.org/tlp/) level.
The publisher sets it (`default_tlp`, or `tlp` per behaviour; default
`green`). The level decides how the object is delivered and who can fetch it:

| TLP | Delivered to / readable by |
|---|---|
| `clear` | Anyone. May be addressed to the public collection. |
| `green` | Followers only. The daemon approves follow requests manually by default. |
| `amber`, `amber+strict` | Only the named recipient actors configured when the object was first published. Its later `Update`s and `Delete` go to the same recipients. |
| `red` | Never shared over AP-TI. |

- Objects above `clear` need a signed fetch. The publisher returns only
  objects the requesting actor is allowed to see.
- Receivers must not `Announce` or re-share evidence beyond its TLP. The
  reference daemon publishes only its own observations and never peer
  evidence.
- A Sighting that confirms an indicator (`indicatorRefs`) must not have a
  less restrictive TLP than that indicator. The daemon drops Sightings that
  break this rule.
- On the active list, each entry carries the most restrictive TLP of the
  evidence that supports it (indicators, Sightings and `agree` Opinions).
  API tokens have a `max_tlp`, and entries above it are left out. For example, an enforcement tool whose token allows only
  `green` never gets an entry that rests on `amber` evidence.
- The spec recommends `green` or stricter for scan, brute-force, spam and
  DDoS sources, so that attackers are not warned that they were detected.

## Repository layout

| Path | Contents |
|---|---|
| [`proposal.md`](proposal.md) | The protocol specification (Internet-Draft style, *draft-activitypub-threatintel-00*): data model, publication, lifecycle, effective-expiry algorithm, trust, security and privacy. |
| [`reference-daemon/`](reference-daemon/) | Rust reference implementation following the deployment model in Appendix D of the spec. |
| `.github/workflows/`, `.woodpecker/` | CI: formatting and tests on every change; release binaries for tags of the form `vYYYY.MM.N`. |

## Reference implementation

The [`reference-daemon`](reference-daemon/) Cargo workspace contains:

| Component | Role |
|---|---|
| `apti-core` | Library: data model, normalisation, trust policy and effective-expiry engine. No I/O. |
| `aptid` | Daemon: ActivityPub federation, SQLite storage, internal REST API for sensors and enforcement, management control socket. |
| `apti-tui` | Terminal UI for following peers, setting trust, working through the review queue and managing allowlists. |
| `apti-fail2ban` | Connector: reports fail2ban bans to `aptid` and writes the active list back to files that fail2ban bans from. |
| `apti-allowlist` | Connector: keeps the local allowlist in sync with a hand-edited text file (append or source-of-truth mode). |

A typical deployment works like this:

1. Local sensors (for example fail2ban) push observations to `aptid`.
2. `aptid` batches them into Sightings and federates them to followers.
3. `aptid` combines its own evidence with trusted peer evidence into an active
   list.
4. Enforcement tools pull that list.

To get started:

```sh
cd reference-daemon
cargo build --release
cargo test --workspace
```

See [`reference-daemon/README.md`](reference-daemon/README.md) for
configuration, the REST API, the fail2ban connector, ActivityPub endpoints,
the TUI, and known limitations.

## Status

Experimental, work in progress. The specification is a draft and may change.
The JSON-LD context URI is still a placeholder.

## License

Apache License 2.0, see [`LICENSE`](LICENSE).
