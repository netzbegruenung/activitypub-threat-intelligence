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
