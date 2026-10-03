//! Observable normalisation (Section 4.1) and poisoning protection (Section 10).

use std::net::IpAddr;

use ipnet::IpNet;

use crate::model::ObservableType;

/// Local acceptance policy for observable values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormPolicy {
    /// Shortest IPv4 prefix accepted (Section 4.1: SHOULD reject < /24).
    pub min_v4_prefix: u8,
    /// Shortest IPv6 prefix accepted (Section 4.1: SHOULD reject < /48).
    pub min_v6_prefix: u8,
    /// Reject RFC 6890 special-purpose addresses and special-use names (MUST).
    pub reject_special_purpose: bool,
    /// Accept documentation ranges and names (RFC 5737, RFC 3849, RFC 2606)
    /// even though they are special-purpose. For demos and tests only.
    pub allow_documentation: bool,
}

impl Default for NormPolicy {
    fn default() -> Self {
        Self {
            min_v4_prefix: 24,
            min_v6_prefix: 48,
            reject_special_purpose: true,
            allow_documentation: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NormError {
    #[error("empty value")]
    Empty,
    #[error("not a valid {0}")]
    Invalid(&'static str),
    #[error("value is not in normal form (expected `{0}`)")]
    NotNormal(String),
    #[error("value does not match observableType {0}")]
    TypeMismatch(ObservableType),
    #[error("prefix has host bits set")]
    HostBits,
    #[error("prefix /{len} is shorter than the accepted minimum /{min}")]
    PrefixTooShort { len: u8, min: u8 },
    #[error("special-purpose address or name ({0})")]
    SpecialPurpose(&'static str),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Special {
    Reserved(&'static str),
    Documentation(&'static str),
}

const V4_SPECIAL: &[(&str, Special)] = &[
    ("0.0.0.0/8", Special::Reserved("this network")),
    ("10.0.0.0/8", Special::Reserved("private-use")),
    (
        "100.64.0.0/10",
        Special::Reserved("shared address space / CGNAT"),
    ),
    ("127.0.0.0/8", Special::Reserved("loopback")),
    ("169.254.0.0/16", Special::Reserved("link local")),
    ("172.16.0.0/12", Special::Reserved("private-use")),
    (
        "192.0.0.0/24",
        Special::Reserved("IETF protocol assignments"),
    ),
    ("192.0.2.0/24", Special::Documentation("TEST-NET-1")),
    ("192.88.99.0/24", Special::Reserved("6to4 relay anycast")),
    ("192.168.0.0/16", Special::Reserved("private-use")),
    ("198.18.0.0/15", Special::Reserved("benchmarking")),
    ("198.51.100.0/24", Special::Documentation("TEST-NET-2")),
    ("203.0.113.0/24", Special::Documentation("TEST-NET-3")),
    ("224.0.0.0/4", Special::Reserved("multicast")),
    ("240.0.0.0/4", Special::Reserved("reserved")),
];

const V6_SPECIAL: &[(&str, Special)] = &[
    ("::/128", Special::Reserved("unspecified")),
    ("::1/128", Special::Reserved("loopback")),
    ("::ffff:0:0/96", Special::Reserved("IPv4-mapped")),
    ("64:ff9b::/96", Special::Reserved("IPv4-IPv6 translation")),
    ("64:ff9b:1::/48", Special::Reserved("local-use translation")),
    ("100::/64", Special::Reserved("discard-only")),
    ("2001::/23", Special::Reserved("IETF protocol assignments")),
    ("2001:db8::/32", Special::Documentation("documentation")),
    ("2002::/16", Special::Reserved("6to4")),
    ("3fff::/20", Special::Documentation("documentation")),
    ("fc00::/7", Special::Reserved("unique local")),
    ("fe80::/10", Special::Reserved("link local")),
    ("ff00::/8", Special::Reserved("multicast")),
];

const NAME_SPECIAL: &[(&str, Special)] = &[
    ("localhost", Special::Reserved("localhost")),
    ("invalid", Special::Reserved("invalid")),
    ("local", Special::Reserved("mDNS")),
    ("home.arpa", Special::Reserved("home network")),
    ("onion", Special::Reserved("onion")),
    ("test", Special::Documentation("test")),
    ("example", Special::Documentation("example")),
    ("example.com", Special::Documentation("example")),
    ("example.net", Special::Documentation("example")),
    ("example.org", Special::Documentation("example")),
];

fn overlaps(a: &IpNet, b: &IpNet) -> bool {
    a.contains(b) || b.contains(a)
}

fn special_ip(net: &IpNet) -> Option<Special> {
    let table = match net {
        IpNet::V4(_) => V4_SPECIAL,
        IpNet::V6(_) => V6_SPECIAL,
    };
    if let IpNet::V4(n) = net {
        if n.addr().is_broadcast() {
            return Some(Special::Reserved("broadcast"));
        }
    }
    // Prefer the documentation classification if both match.
    let mut found = None;
    for (range, kind) in table {
        let r: IpNet = range.parse().expect("static table");
        if overlaps(&r, net) {
            if matches!(kind, Special::Documentation(_)) && r.contains(net) {
                return Some(*kind);
            }
            found = Some(*kind);
        }
    }
    found
}

fn special_name(name: &str) -> Option<Special> {
    NAME_SPECIAL.iter().find_map(|(suffix, kind)| {
        (name == *suffix || name.ends_with(&format!(".{suffix}"))).then_some(*kind)
    })
}

fn apply_special(s: Option<Special>, policy: &NormPolicy) -> Result<(), NormError> {
    if !policy.reject_special_purpose {
        return Ok(());
    }
    match s {
        None => Ok(()),
        Some(Special::Documentation(_)) if policy.allow_documentation => Ok(()),
        Some(Special::Documentation(what)) | Some(Special::Reserved(what)) => {
            Err(NormError::SpecialPurpose(what))
        }
    }
}

fn normalise_ip(input: &str, policy: &NormPolicy) -> Result<(ObservableType, String), NormError> {
    let net: IpNet = if input.contains('/') {
        let net: IpNet = input.parse().map_err(|_| NormError::Invalid("IP prefix"))?;
        if net.trunc() != net {
            return Err(NormError::HostBits);
        }
        net
    } else {
        let addr: IpAddr = input
            .parse()
            .map_err(|_| NormError::Invalid("IP address"))?;
        IpNet::from(addr)
    };
    let (ty, min) = match net {
        IpNet::V4(_) => (ObservableType::Ipv4Addr, policy.min_v4_prefix),
        IpNet::V6(_) => (ObservableType::Ipv6Addr, policy.min_v6_prefix),
    };
    if net.prefix_len() < min {
        return Err(NormError::PrefixTooShort {
            len: net.prefix_len(),
            min,
        });
    }
    apply_special(special_ip(&net), policy)?;
    // Host routes are written without a prefix length; std's Display for
    // Ipv6Addr follows RFC 5952.
    let value = if net.prefix_len() == net.max_prefix_len() {
        net.addr().to_string()
    } else {
        net.to_string()
    };
    Ok((ty, value))
}

fn normalise_domain(input: &str, policy: &NormPolicy) -> Result<String, NormError> {
    let trimmed = input.strip_suffix('.').unwrap_or(input);
    let ascii =
        idna::domain_to_ascii_strict(trimmed).map_err(|_| NormError::Invalid("domain name"))?;
    if ascii.is_empty() || ascii.len() > 253 || !ascii.contains('.') {
        return Err(NormError::Invalid("domain name"));
    }
    for label in ascii.split('.') {
        let ok = !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-');
        if !ok {
            return Err(NormError::Invalid("domain name"));
        }
    }
    if ascii.parse::<IpAddr>().is_ok()
        || ascii
            .rsplit('.')
            .next()
            .is_some_and(|tld| tld.bytes().all(|c| c.is_ascii_digit()))
    {
        return Err(NormError::Invalid("domain name"));
    }
    apply_special(special_name(&ascii), policy)?;
    Ok(ascii)
}

/// Normalise raw input (e.g. from a local sensor). If `ty` is `None` the type
/// is inferred. Returns the observable type and its normal form.
pub fn normalise(
    input: &str,
    ty: Option<ObservableType>,
    policy: &NormPolicy,
) -> Result<(ObservableType, String), NormError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(NormError::Empty);
    }
    let looks_ip = input.contains(':')
        || input
            .split('/')
            .next()
            .is_some_and(|h| h.bytes().all(|c| c.is_ascii_digit() || c == b'.'));
    let wants_ip = match ty {
        Some(t) if t.is_ip() => true,
        Some(ObservableType::DomainName) => false,
        Some(ObservableType::Unknown) => return Err(NormError::Invalid("observable type")),
        Some(_) | None => looks_ip,
    };
    let (found, value) = if wants_ip {
        normalise_ip(input, policy)?
    } else {
        (ObservableType::DomainName, normalise_domain(input, policy)?)
    };
    if let Some(t) = ty {
        if t != found {
            return Err(NormError::TypeMismatch(t));
        }
    }
    Ok((found, value))
}

/// Check that `value` is already in normal form for `ty` (consumer rule).
pub fn check_normal(ty: ObservableType, value: &str, policy: &NormPolicy) -> Result<(), NormError> {
    let (_, normal) = normalise(value, Some(ty), policy)?;
    if normal != value {
        return Err(NormError::NotNormal(normal));
    }
    Ok(())
}

/// Parse a normalised IP observable into a network.
pub fn ip_net(value: &str) -> Option<IpNet> {
    if value.contains('/') {
        value.parse().ok()
    } else {
        value.parse::<IpAddr>().ok().map(IpNet::from)
    }
}

/// Whether the observable `container` covers `target` (same type assumed):
/// IP prefixes cover contained addresses and prefixes; a domain covers
/// itself, and its subdomains if `include_subdomains` is set.
pub fn covers(ty: ObservableType, container: &str, target: &str, include_subdomains: bool) -> bool {
    if container == target {
        return true;
    }
    match ty {
        ObservableType::Ipv4Addr | ObservableType::Ipv6Addr => {
            match (ip_net(container), ip_net(target)) {
                (Some(c), Some(t)) => c.contains(&t),
                _ => false,
            }
        }
        ObservableType::DomainName => {
            include_subdomains && target.ends_with(&format!(".{container}"))
        }
        ObservableType::Unknown => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p() -> NormPolicy {
        NormPolicy::default()
    }

    #[test]
    fn ipv4() {
        assert_eq!(
            normalise("8.8.4.4", None, &p()).unwrap(),
            (ObservableType::Ipv4Addr, "8.8.4.4".into())
        );
        assert_eq!(
            normalise(" 8.8.4.0/24 ", None, &p()).unwrap().1,
            "8.8.4.0/24"
        );
        assert_eq!(normalise("8.8.4.4/32", None, &p()).unwrap().1, "8.8.4.4");
        assert!(normalise("08.8.4.4", None, &p()).is_err());
        assert_eq!(
            normalise("8.8.4.1/24", None, &p()),
            Err(NormError::HostBits)
        );
        assert_eq!(
            normalise("8.8.0.0/16", None, &p()),
            Err(NormError::PrefixTooShort { len: 16, min: 24 })
        );
        assert!(check_normal(ObservableType::Ipv4Addr, "8.8.4.4/32", &p()).is_err());
        assert!(check_normal(ObservableType::Ipv4Addr, "8.8.4.4", &p()).is_ok());
    }

    #[test]
    fn ipv6() {
        assert_eq!(
            normalise("2A00:1450:4001:0000:0000:0000:0000:0001", None, &p())
                .unwrap()
                .1,
            "2a00:1450:4001::1"
        );
        assert_eq!(
            normalise("2a00:1450:4001::/48", None, &p()).unwrap().1,
            "2a00:1450:4001::/48"
        );
        assert!(normalise("2a00:1450::/32", None, &p()).is_err());
        assert!(check_normal(ObservableType::Ipv6Addr, "2a00:1450:4001:0::1", &p()).is_err());
    }

    #[test]
    fn special_purpose() {
        for v in [
            "10.1.2.3",
            "127.0.0.1",
            "100.64.1.1",
            "192.168.1.0/24",
            "::1",
            "fe80::1",
            "fd00::1",
            "255.255.255.255",
            "224.0.0.1",
        ] {
            assert!(
                matches!(normalise(v, None, &p()), Err(NormError::SpecialPurpose(_))),
                "{v}"
            );
        }
        assert!(normalise("192.0.2.10", None, &p()).is_err());
        let docs = NormPolicy {
            allow_documentation: true,
            ..p()
        };
        assert!(normalise("192.0.2.10", None, &docs).is_ok());
        assert!(normalise("2001:db8:4::17", None, &docs).is_ok());
        assert!(normalise("evil.example", None, &docs).is_ok());
        assert!(normalise("10.0.0.1", None, &docs).is_err());
        let off = NormPolicy {
            reject_special_purpose: false,
            ..p()
        };
        assert!(normalise("10.0.0.1", None, &off).is_ok());
    }

    #[test]
    fn domains() {
        assert_eq!(
            normalise("Bücher.DE.", None, &p()).unwrap(),
            (ObservableType::DomainName, "xn--bcher-kva.de".into())
        );
        assert!(check_normal(ObservableType::DomainName, "Evil.com", &p()).is_err());
        assert!(check_normal(ObservableType::DomainName, "evil.com.", &p()).is_err());
        assert!(check_normal(ObservableType::DomainName, "evil.com", &p()).is_ok());
        assert!(normalise("localhost", None, &p()).is_err());
        assert!(normalise("foo.localhost", None, &p()).is_err());
        assert!(normalise("under_score.com", None, &p()).is_err());
        assert!(normalise("-bad.com", None, &p()).is_err());
        assert!(normalise("evil.example", None, &p()).is_err());
    }

    #[test]
    fn type_mismatch() {
        assert_eq!(
            normalise("8.8.8.8", Some(ObservableType::Ipv6Addr), &p()),
            Err(NormError::TypeMismatch(ObservableType::Ipv6Addr))
        );
        assert!(normalise("8.8.8.8", Some(ObservableType::DomainName), &p()).is_err());
    }

    #[test]
    fn coverage() {
        assert!(covers(
            ObservableType::Ipv4Addr,
            "8.8.4.0/24",
            "8.8.4.4",
            false
        ));
        assert!(!covers(
            ObservableType::Ipv4Addr,
            "8.8.4.0/24",
            "8.8.5.4",
            false
        ));
        assert!(covers(
            ObservableType::Ipv6Addr,
            "2a00:1450:4001::/48",
            "2a00:1450:4001::1",
            false
        ));
        assert!(covers(
            ObservableType::DomainName,
            "evil.com",
            "a.evil.com",
            true
        ));
        assert!(!covers(
            ObservableType::DomainName,
            "evil.com",
            "a.evil.com",
            false
        ));
        assert!(!covers(
            ObservableType::DomainName,
            "evil.com",
            "notevil.com",
            true
        ));
    }
}
