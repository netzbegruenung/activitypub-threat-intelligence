# ActivityPub Threat Intelligence Profile (AP-TI)

**draft-activitypub-threatintel-00**
Intended status: Experimental · October 2026

## Abstract

A profile of ActivityPub for continuous, federated sharing of network observables (IP addresses, prefixes, domains) associated with abusive behaviour such as SSH brute force, spam or C2. Organisations publish batched Sightings, curated Indicators and Opinions. Nothing is listed forever: every piece of evidence ages out, and each consumer computes an effective expiry under its own trust policy. Terms are aligned with STIX 2.1 so aggregators can map them to STIX/TAXII directly.

## Status of This Memo

Work in progress. Do not cite except as such.

## 1. Introduction

STIX/TAXII and MISP sync work well inside a known, fixed sharing community. They lack open discovery: finding, following and identifying new participants across organisational boundaries. ActivityPub provides that via WebFinger, a follow graph and domain-bound identity. This profile uses ActivityPub for discovery, exchange and consensus only. Enforcement points consume aggregator output (Section 9), never ActivityPub directly.

Network observables are fragile and go stale quickly [RFC9424]. Therefore:

- every piece of evidence has a bounded lifetime;
- peers report facts (Sightings) and judgements (Opinions); they cannot set expiry for others;
- each consumer decides, per operator and behaviour, which input it accepts and how it is weighted (Section 7).

Out of scope: URLs, file hashes, other observable types, and direct enforcement.

### 1.1. Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all capitals, as shown here.

## 2. Terminology

- **Observable:** a normalised `(observableType, observableValue)` pair.
- **Behaviour:** an `observedBehavior` value (Section 4.2).
- **Evidence:** a `ThreatIndicator`, `Sighting` or `Opinion` object.
- **Publisher:** the actor in `attributedTo` of an evidence object.
- **Consumer:** an entity that processes AP-TI objects.
- **Aggregator:** a consumer that exports active observables in operational formats.
- **Operator:** the organisation controlling one or more actors (Section 3.2). Trust and independence are evaluated per operator.
- **Effective expiry:** the consumer-computed end of an observable's active period for one behaviour (Section 7).

## 3. Actors

### 3.1. Publishing Actors

Publishers SHOULD use dedicated `Service` actors and MUST be discoverable via WebFinger [RFC7033]. Each publishing actor MUST expose `activeObjects` (Section 5.3).

Publishers MUST require signed fetches (HTTP signatures on `GET`) for `activeObjects` and for every object whose `tlp` is not `clear`, and MUST return only content the requesting actor is authorised to see under its TLP.

Community feeds MAY be run as `Group` actors [FEP-1b12].

### 3.2. Operators

An actor SHOULD carry an `operator` property referencing an `Organization` actor. That `Organization` MUST list the actor in its `operatedActors` property. The link is valid only if both directions match. Otherwise, and in the absence of `operator`, the consumer MUST assume actors under the same registrable domain [PSL] belong to the same operator, and MAY override this mapping locally.

## 4. Data Model

Terms are defined by the context in Appendix B. AS2 terms (`id`, `attributedTo`, `published`, `updated`, `summary`, `tag`) keep their AS2 meaning. Common to all evidence objects:

| Property | Req. | Value |
|---|---|---|
| `id`, `attributedTo`, `published` | MUST | AS2 |
| `updated` | MAY | AS2; MUST be present after any `Update` |
| `tlp` | MUST | `clear`, `green`, `amber`, `amber+strict` [TLP2] |
| `summary` | MAY | Short text. MUST NOT identify victims. |

### 4.1. Observables and Normalisation

`observableType` is one of `ipv4-addr`, `ipv6-addr`, `domain-name` (STIX SCO names). Consumers MUST ignore objects with unknown types. `observableValue` MUST be in normal form; consumers MUST reject other values.

- `ipv4-addr`: dotted decimal without leading zeros, optionally `/len` with host bits zero [RFC4632].
- `ipv6-addr`: [RFC5952] form, optionally `/len` with host bits zero.
- A full-length prefix (`/32` for IPv4, `/128` for IPv6) is written as the bare address.
- `domain-name`: lowercase, IDNA A-labels [RFC5890] [RFC5891], no trailing dot.

Consumers SHOULD reject IPv4 prefixes shorter than /24 and IPv6 prefixes shorter than /48.

### 4.2. Behaviour

`observedBehavior` is one or more values from this open vocabulary. Consumers MUST treat unknown values as `other`.

`scan`, `ssh-bruteforce`, `auth-bruteforce`, `smtp-spam`, `exploit-attempt`, `ddos-source`, `phishing`, `malware-hosting`, `command-and-control`, `other`.

Optional qualifiers: `port` (integer, destination port observed) and `service` (IANA service name [RFC6335], e.g. `ssh`, `smtp`).

### 4.3. `ThreatIndicator`

A curated claim with an explicit validity period, set by the publisher.

| Property | Req. | Value |
|---|---|---|
| `observableType`, `observableValue` | MUST | 4.1 |
| `observedBehavior` | MUST | 4.2 |
| `port`, `service` | MAY | 4.2 |
| `includeSubdomains` | MAY | Boolean, `domain-name` only. Default `false`. |
| `validFrom`, `validUntil` | MUST | [RFC3339] UTC; `validFrom` < `validUntil` |
| `confidence` | SHOULD | Integer 0–100 (STIX) |
| `infrastructureTypes` | MAY | STIX `infrastructure-type-ov` |
| `revoked` | MAY | Boolean. Default `false`. |
| `tag` | MAY | AS2 `Hashtag` objects (e.g. malware family) |

### 4.4. `Sighting`

A statement of fact: the publisher observed the observable exhibiting the behaviour. Maps to STIX `sighting`. This is the normal form for continuous, first-hand observations.

| Property | Req. | Value |
|---|---|---|
| `observableType`, `observableValue` | MUST | 4.1. This is the matching key. |
| `observedBehavior` | MUST | 4.2 |
| `port`, `service` | MAY | 4.2 |
| `firstSeen`, `lastSeen` | MUST | [RFC3339]; `firstSeen` ≤ `lastSeen` |
| `count` | SHOULD | Integer ≥ 1, cumulative over `[firstSeen, lastSeen]` |
| `indicatorRefs` | MAY | `ThreatIndicator` id(s) this confirms. `tlp` MUST NOT be less restrictive than theirs. |

A publisher SHOULD keep at most one Sighting per observable and behaviour, and refresh it with `Update` (new `lastSeen`, `count`, `updated`).

### 4.5. `Opinion`

A judgement on an observable or indicator. Maps to STIX `opinion`.

| Property | Req. | Value |
|---|---|---|
| `observableType` + `observableValue`, and/or `indicatorRefs` | MUST | Target |
| `observedBehavior` | MAY | Restricts the Opinion to these behaviours. Default: all. |
| `opinion` | MUST | `strongly-disagree`, `disagree`, `neutral`, `agree`, `strongly-agree` |
| `validUntil` | MAY | [RFC3339]. Default `published` + 90 d. |
| `summary` | SHOULD | Rationale |

An Opinion on a prefix also covers the addresses and longer prefixes inside it. An Opinion on a domain covers only that domain. An Opinion with `indicatorRefs` applies to the observable of each referenced indicator.

An Opinion of `strongly-disagree` on an observable with no `indicatorRefs` is an **allowlist entry**. The holder of an address or domain (verifiable via RDAP [RFC9083]) MAY publish `disagree` Opinions.

## 5. Publication

### 5.1. Activities

| Activity | `object` | Meaning |
|---|---|---|
| `Create` | one or more evidence objects | New evidence |
| `Update` | one or more full evidence objects | Replace; applied only if `updated` is newer than the stored copy |
| `Delete` | one or more evidence ids | Withdraw. For a `ThreatIndicator` this equals revocation. |

All objects in one activity MUST share the same `tlp` and MUST have `attributedTo` equal to the activity's `actor`. Receivers MUST validate each object independently and drop only the invalid ones.

### 5.2. Addressing and TLP

| `tlp` | Addressing |
|---|---|
| `clear` | MAY include `as:Public` |
| `green` | Followers collection only; actor SHOULD set `manuallyApprovesFollowers` |
| `amber`, `amber+strict` | Named recipients only |
| `red` | MUST NOT be shared via this profile |

`Update` and `Delete` of an `amber` or `amber+strict` object SHOULD be addressed to the recipients of its `Create`, so that changing the recipient list does not widen or narrow the audience of existing objects.

Consumers MUST NOT `Announce` or re-share content beyond its TLP.

### 5.3. Batching and Sync

- An activity MUST NOT carry more than 1000 objects. Publishers SHOULD batch on an interval (e.g. 5–15 min) and SHOULD emit at most one Sighting update per observable and behaviour per interval.
- `activeObjects` is an `OrderedCollection` of the actor's current evidence, newest `updated` (or `published`) first, paged with at most 1000 items per page. It contains non-revoked indicators until `validUntil`, Sightings until `lastSeen` + the publisher's T (Table 1), and Opinions until `validUntil`.
- Deleted or revoked objects MUST remain in `activeObjects` as `Tombstone` (with `deleted`) or with `revoked: true` for at least 180 days.
- Consumers MUST read `activeObjects` on first follow. For incremental sync they read pages until they reach an item not newer than their last sync point. They SHOULD resync fully at least weekly. Pull-only consumption (no inbox delivery) is permitted.
- Generic fediverse software ignores unknown types. Publishers MAY additionally post a human-readable `Note`, which consumers MUST NOT interpret as evidence.

## 6. Lifecycle

- **Expiry:** no activity is sent; evidence ages out (Section 7).
- **Change / refresh:** `Update` with the full object. The publisher MAY move `validUntil` in either direction.
- **Early expiry:** `Update` with `validUntil` set to the current time.
- **Revocation** (false positive): `Update` with `revoked: true`, or `Delete`. A revoked indicator MUST NOT be un-revoked; publish a new one instead.
- **Withdrawal** of a Sighting or Opinion: `Delete`.

## 7. Effective Expiry

All parameters below are **local consumer policy**. Each organisation decides whom it trusts, for which behaviours, with what weight, and whether Sightings alone may activate an observable.

Policy per operator `p` and behaviour `b`:

- `trusted(p, b)`: boolean. Default `false`.
- `w(p, b)`: weight ≥ 0. Default 1.
- `k(b)`: activation threshold, or `off` (Sightings never activate on their own). Default 2.
- `T(b)`, `M(b)`: Sighting TTL and maximum evidence age (Table 1).

For observable `O` and behaviour `b`, using only trusted, authenticated (Section 8), non-withdrawn evidence matching `b`:

```
base(x)  = x.updated if present, else x.published

# Indicators: the publisher's validity, capped by evidence age
E_ind = max over non-revoked indicators i with i.validFrom <= now of
          min(i.validUntil, base(i) + M(b))

# Sightings: weighted per-operator quorum on recency
last(p)  = max lastSeen over Sightings from operator p
L        = latest t such that  sum of w(p, b) over p with last(p) >= t  >= k(b)
E_sig    = L + min(T(b), M(b))        (undefined if k(b) = off or quorum not met)

effectiveExpiry(O, b) = max(E_ind, E_sig)
```

`(O, b)` is active iff `now < effectiveExpiry(O, b)` and it is not suspended.

- Each piece of evidence ages out on its own. An attacker that keeps misbehaving stays listed for as long as trusted operators keep reporting it. Nothing stays listed without fresh trusted evidence.
- Setting `w(p, b) = k(b)` lets a single operator activate observables alone. `k(b) = off` restricts activation to Indicators.
- Evidence with a `published` or `updated`, or a Sighting with a `lastSeen`, more than 5 minutes in the future MUST be discarded.

**Suspension.** Let D be the summed weight of operators with a current `disagree` or `strongly-disagree` Opinion on `(O, b)`, and S the summed weight of operators supporting it (an indicator that is in effect, i.e. `validFrom <= now < min(validUntil, base + M(b))`, a Sighting within `T(b)`, or `agree`/`strongly-agree`). An operator with both kinds of evidence counts towards D and S. When D > 0 the consumer MUST flag `(O, b)` for review. It SHOULD suspend `(O, b)` when D ≥ S. A trusted allowlist entry (Section 4.5) suspends `O` for all covered behaviours.

**Table 1: Default T / M (non-normative; informed by [RFC9424] and [MISP-DECAY])**

| `observedBehavior` | T | M |
|---|---|---|
| `scan`, `ddos-source` | 1 d | 7 d |
| `ssh-bruteforce`, `auth-bruteforce` | 1 d | 14 d |
| `smtp-spam` | 2 d | 30 d |
| `exploit-attempt` | 3 d | 30 d |
| `phishing`, `malware-hosting` | 7 d | 30 d |
| `command-and-control` (IP) | 7 d | 90 d |
| `command-and-control` (domain) | 30 d | 180 d |
| `other` | 1 d | 14 d |

For IP observables, M SHOULD NOT exceed 90 days. The refresh-before-lifetime pattern follows DOTS mitigation lifetimes [RFC9132].

## 8. Trust and Authenticity

- Following an actor does not imply trusting it. Consumers MUST keep an explicit trust policy per operator (Section 7). Untrusted input MUST NOT affect effective expiry; consumers MAY queue it for review.
- **Authenticity:** inbox deliveries MUST carry a valid HTTP signature ([RFC9421] or [CAVAGE]). Objects received any other way (`Announce`, relays) MUST be fetched again from their `id` (signed fetch) or verified with an integrity proof [FEP-8b32].
- **Origin:** the host of each object's `id` MUST equal the host of its `attributedTo`, and `attributedTo` MUST equal the activity's `actor`. Otherwise the object is discarded.
- **Replay:** consumers MUST process each activity `id` at most once and MUST ignore `Update`s that are not newer than the stored object.

## 9. Aggregation

Aggregators apply Sections 7 and 8 and export active `(O, b)` pairs, optionally filtered by behaviour, `port` or `service`. Exports MUST preserve TLP: an exported pair carries the most restrictive TLP of the evidence supporting it (indicators, Sightings and `agree`/`strongly-agree` Opinions counted in S), and is only given to recipients allowed to see that TLP. Exports SHOULD be recomputed at least hourly. Typical targets (informative):

- TAXII 2.1 collections [TAXII2.1], `valid_until` = effective expiry (Appendix A);
- DNS RPZ [RPZ] for domains;
- DNSBL [RFC5782] for `smtp-spam`;
- nftables/ipset sets with per-element timeout = effective expiry − now, e.g. scoped to port 22 for `ssh-bruteforce`;
- fail2ban or plain lists.

## 10. Security Considerations

- **Poisoning / self-DoS:** attackers publish addresses of CDNs, clouds, public resolvers, large mail providers or fediverse peers to get them blocked. Consumers MUST reject special-purpose addresses [RFC6890] and SHOULD apply allowlists of high-impact benign infrastructure, including their own federation peers and upstream resolvers. For shared hosting, use `domain-name` rather than IP. Shared and CGNAT addresses need extra caution.
- **Sybil:** quorum is counted per operator. It is only as strong as the operator mapping (Section 3.2) and the trust list. High weights or `k = 1` make a single compromised operator sufficient.
- **Allowlist abuse:** an attacker's Opinions only matter if their operator is trusted. Consumers SHOULD review new allowlist entries for broad prefixes.
- **Perpetual listing:** bounded by per-evidence age (Section 7). Peers cannot set expiry.
- **Tipping off:** public evidence reveals detection to adversaries, who may also probe whether their infrastructure is listed. Use `green` or stricter when this matters.
- **Integrity:** HTTP signatures cover transport only, hence the re-fetch/proof and origin rules (Section 8).
- **Resource exhaustion:** enforce the batch limit; rate-limit per actor and per operator; bound page sizes and sync frequency.

## 11. Privacy Considerations

Following [RFC6973]:

- IP addresses can be personal data (CJEU C-582/14 *Breyer*). Sources of `scan`, `*-bruteforce`, `smtp-spam` and `ddos-source` are mostly compromised residential hosts.
- Processing for network and information security can be a legitimate interest under GDPR Art. 6(1)(f) and Recital 49. Participants remain responsible for their own legal basis.
- For the behaviours above, publishers SHOULD default to `green` or stricter.
- `summary` fields MUST NOT contain victim identifiers. Publishers SHOULD publish a contact for removal requests.
- Consumers SHOULD delete records of inactive observables after a bounded retention period.

## 12. IANA Considerations

None. The vocabulary is published as a JSON-LD context at a stable URI (TBD; `https://example.org/ns/ti` is a placeholder) and is intended for submission as a Fediverse Enhancement Proposal.

## 13. References

### 13.1. Normative

- [ActivityPub] Lemmer-Webber, C., et al., "ActivityPub", W3C Recommendation, 23 January 2018.
- [AS2] Snell, J., Prodromou, E., "Activity Streams 2.0", W3C Recommendation, 23 May 2017; and "Activity Vocabulary", W3C Recommendation, 23 May 2017.
- [JSON-LD] "JSON-LD 1.1", W3C Recommendation, 16 July 2020.
- [STIX2.1] OASIS, "STIX Version 2.1", OASIS Standard, 10 June 2021.
- [TLP2] FIRST, "Traffic Light Protocol (TLP) Version 2.0", August 2022.
- [RFC2119], [RFC8174] BCP 14.
- [RFC3339] Date and Time on the Internet: Timestamps.
- [RFC4632] Classless Inter-domain Routing (CIDR).
- [RFC5890], [RFC5891] IDNA2008.
- [RFC5952] A Recommendation for IPv6 Address Text Representation.
- [RFC6335] IANA Procedures for the Service Name and Transport Protocol Port Number Registry.
- [RFC6890] Special-Purpose IP Address Registries.
- [RFC7033] WebFinger.
- [RFC9421] HTTP Message Signatures.

### 13.2. Informative

- [CAVAGE] draft-cavage-http-signatures-12.
- [FEP-8b32] Object Integrity Proofs.
- [FEP-1b12] Group federation.
- [PSL] Mozilla, Public Suffix List.
- [TAXII2.1] OASIS, "TAXII Version 2.1", OASIS Standard, 10 June 2021.
- [RFC9424] Indicators of Compromise (IoCs) and Their Role in Attack Defence.
- [RFC9132] DOTS Signal Channel Specification.
- [RFC5782] DNS Blacklists and Whitelists.
- [RFC7970] IODEF v2; [RFC8727] JSON Binding of IODEF.
- [RFC6973] Privacy Considerations for Internet Protocols.
- [RFC9083] JSON Responses for RDAP.
- [RPZ] draft-vixie-dnsop-dns-rpz, DNS Response Policy Zones.
- [MISP-DECAY] MISP Project, "Decaying of Indicators".
- [GDPR] Regulation (EU) 2016/679.
- [RFC2606], [RFC5737], [RFC3849], [RFC5398] Reserved names, addresses and ASNs used in examples.

## Appendix A. STIX 2.1 Mapping

| AP-TI | STIX 2.1 |
|---|---|
| `ThreatIndicator` | `indicator`, `indicator_types: [malicious-activity]`, `pattern_type: stix`, `pattern: [<observableType>:value = '<observableValue>']` |
| `includeSubdomains: true` | pattern adds `OR domain-name:value LIKE '%.<value>'` |
| `id` | `external_references[].url`; STIX id = type + `--` + UUIDv5 of `id` |
| `attributedTo` / `operator` | `created_by_ref` → `identity` (`identity_class: organization`) |
| `published` / `updated` | `created` / `modified` |
| `validFrom` / `validUntil` | `valid_from` / `valid_until` (aggregator: effective expiry) |
| `confidence`, `revoked` | same |
| `observedBehavior`, `port`, `service` | custom properties `x_apti_observed_behavior`, `x_apti_port`, `x_apti_service` |
| `infrastructureTypes` | `infrastructure` SDO + `relationship` (`indicates`) |
| `tlp` | `object_marking_refs` (TLP 2.0 marking definitions) |
| `tag` / `summary` | `labels` / `description` |
| `Sighting` | `sighting`: `sighting_of_ref` = `indicatorRefs`, or an aggregator-created indicator for the observable; `first_seen`, `last_seen`, `count`; `where_sighted_refs` → observer `identity` |
| `Opinion` | `opinion`: `opinion`, `explanation` ← `summary`, `object_refs` = `indicatorRefs` or the observable SCO |
| `Delete` / `Tombstone` | `revoked: true` |

## Appendix B. JSON-LD Context

```json
{
  "@context": {
    "ti": "https://example.org/ns/ti#",
    "xsd": "http://www.w3.org/2001/XMLSchema#",
    "ThreatIndicator": "ti:ThreatIndicator",
    "Sighting": "ti:Sighting",
    "Opinion": "ti:Opinion",
    "observableType": "ti:observableType",
    "observableValue": "ti:observableValue",
    "observedBehavior": {"@id": "ti:observedBehavior", "@container": "@set"},
    "port": {"@id": "ti:port", "@type": "xsd:nonNegativeInteger"},
    "service": "ti:service",
    "includeSubdomains": {"@id": "ti:includeSubdomains", "@type": "xsd:boolean"},
    "infrastructureTypes": {"@id": "ti:infrastructureTypes", "@container": "@set"},
    "validFrom": {"@id": "ti:validFrom", "@type": "xsd:dateTime"},
    "validUntil": {"@id": "ti:validUntil", "@type": "xsd:dateTime"},
    "confidence": {"@id": "ti:confidence", "@type": "xsd:nonNegativeInteger"},
    "tlp": "ti:tlp",
    "revoked": {"@id": "ti:revoked", "@type": "xsd:boolean"},
    "firstSeen": {"@id": "ti:firstSeen", "@type": "xsd:dateTime"},
    "lastSeen": {"@id": "ti:lastSeen", "@type": "xsd:dateTime"},
    "count": {"@id": "ti:count", "@type": "xsd:nonNegativeInteger"},
    "indicatorRefs": {"@id": "ti:indicatorRefs", "@type": "@id", "@container": "@set"},
    "opinion": "ti:opinion",
    "operator": {"@id": "ti:operator", "@type": "@id"},
    "operatedActors": {"@id": "ti:operatedActors", "@type": "@id", "@container": "@set"},
    "activeObjects": {"@id": "ti:activeObjects", "@type": "@id"}
  }
}
```

## Appendix C. Examples

Publishing actor:

```json
{
  "@context": ["https://www.w3.org/ns/activitystreams", "https://example.org/ns/ti"],
  "type": "Service",
  "id": "https://ti.example.net/actor",
  "preferredUsername": "feed",
  "inbox": "https://ti.example.net/actor/inbox",
  "outbox": "https://ti.example.net/actor/outbox",
  "followers": "https://ti.example.net/actor/followers",
  "manuallyApprovesFollowers": true,
  "operator": "https://example.net/org",
  "activeObjects": "https://ti.example.net/actor/active"
}
```

Batched Sightings from a daemon (TLP:GREEN, followers only):

```json
{
  "@context": ["https://www.w3.org/ns/activitystreams", "https://example.org/ns/ti"],
  "type": "Create",
  "id": "https://ti.example.net/act/42",
  "actor": "https://ti.example.net/actor",
  "to": ["https://ti.example.net/actor/followers"],
  "object": [
    {
      "type": "Sighting",
      "id": "https://ti.example.net/s/101",
      "attributedTo": "https://ti.example.net/actor",
      "published": "2026-10-03T10:15:00Z",
      "observableType": "ipv4-addr",
      "observableValue": "198.51.100.23",
      "observedBehavior": ["ssh-bruteforce"],
      "service": "ssh",
      "port": 22,
      "firstSeen": "2026-10-03T10:01:12Z",
      "lastSeen": "2026-10-03T10:14:40Z",
      "count": 412,
      "tlp": "green"
    },
    {
      "type": "Sighting",
      "id": "https://ti.example.net/s/102",
      "attributedTo": "https://ti.example.net/actor",
      "published": "2026-10-03T10:15:00Z",
      "observableType": "ipv6-addr",
      "observableValue": "2001:db8:4::17",
      "observedBehavior": ["smtp-spam"],
      "service": "smtp",
      "port": 25,
      "firstSeen": "2026-10-03T09:58:03Z",
      "lastSeen": "2026-10-03T10:12:51Z",
      "count": 37,
      "tlp": "green"
    }
  ]
}
```

Curated indicator (TLP:CLEAR, public):

```json
{
  "@context": ["https://www.w3.org/ns/activitystreams", "https://example.org/ns/ti"],
  "type": "Create",
  "id": "https://ti.example.org/act/1",
  "actor": "https://ti.example.org/actor",
  "to": ["https://www.w3.org/ns/activitystreams#Public"],
  "object": {
    "type": "ThreatIndicator",
    "id": "https://ti.example.org/ind/1",
    "attributedTo": "https://ti.example.org/actor",
    "published": "2026-10-01T10:00:00Z",
    "observableType": "ipv4-addr",
    "observableValue": "192.0.2.10",
    "observedBehavior": ["command-and-control"],
    "validFrom": "2026-10-01T10:00:00Z",
    "validUntil": "2026-10-08T10:00:00Z",
    "confidence": 85,
    "tlp": "clear",
    "tag": [{"type": "Hashtag", "name": "#cobaltstrike"}],
    "summary": "Cobalt Strike team server."
  }
}
```

Allowlist entry:

```json
{
  "@context": ["https://www.w3.org/ns/activitystreams", "https://example.org/ns/ti"],
  "type": "Create",
  "id": "https://ti.example.com/act/3",
  "actor": "https://ti.example.com/actor",
  "to": ["https://ti.example.com/actor/followers"],
  "object": {
    "type": "Opinion",
    "id": "https://ti.example.com/op/3",
    "attributedTo": "https://ti.example.com/actor",
    "published": "2026-10-02T08:00:00Z",
    "observableType": "ipv4-addr",
    "observableValue": "203.0.113.0/24",
    "opinion": "strongly-disagree",
    "validUntil": "2026-12-31T00:00:00Z",
    "tlp": "green",
    "summary": "Outbound relays of a large mail provider (AS64500)."
  }
}
```

## Appendix D. Deployment Model (Informative)

A typical participating organisation runs:

- **Daemon(s):** one or more AP-TI `Service` actors under one `Organization`. They publish local observations as batched Sightings, follow foreign actors, sync `activeObjects`, and compute effective expiry (Section 7).
- **Internal API:** authenticated, organisation-internal only. Local sensors (sshd/fail2ban, MTA, WAF, IDS) submit observations; the daemon batches them into Sightings. A read endpoint exports the active list (Section 9), filterable by behaviour, type and port.
- **Control socket:** a unix socket for management, mode 0600/0660, peer verified via `SO_PEERCRED`, never exposed over TCP.
- **TUI** (via the socket):
  - follow and unfollow foreign actors (WebFinger lookup);
  - set trust, weight and behaviour scope per operator (separate from following);
  - set `k` and T/M overrides per behaviour;
  - approve incoming follow requests (TLP:GREEN);
  - work through the review queue (disputes, untrusted input);
  - manage local and published allowlist entries.
