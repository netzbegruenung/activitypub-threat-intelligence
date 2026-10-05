//! Country lookup for findings: MaxMind DB for IPs, optional DNS for domains.

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use apti_core::ObservableType;
use ipnet::IpNet;
use maxminddb::{path, Reader};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

/// Bucket for findings without a known country (user-assigned ISO code).
pub const UNKNOWN: &str = "ZZ";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Country {
    /// ISO 3166-1 alpha-2 code.
    pub code: String,
    /// English name, if the database has one.
    pub name: Option<String>,
}

pub trait CountryLookup {
    fn lookup(&self, ip: IpAddr) -> Option<Country>;
}

/// Any MaxMind DB with a GeoIP2 `country` record (DB-IP Country Lite,
/// GeoLite2-Country, GeoIP2-City, ...).
pub struct MmdbLookup {
    reader: Reader<Vec<u8>>,
}

impl MmdbLookup {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let reader = Reader::open_readfile(path)
            .with_context(|| format!("opening GeoIP database {}", path.display()))?;
        Ok(Self { reader })
    }
}

impl CountryLookup for MmdbLookup {
    fn lookup(&self, ip: IpAddr) -> Option<Country> {
        // IPv6 lookups fail in IPv4-only databases; that just means unknown.
        let r = self.reader.lookup(ip).ok()?;
        let code = |p: &[maxminddb::PathElement]| r.decode_path::<&str>(p).ok().flatten();
        let code = code(&path!["country", "iso_code"])
            .or_else(|| code(&path!["registered_country", "iso_code"]))
            .filter(|c| valid_code(c))?;
        let name = r
            .decode_path::<&str>(&path!["country", "names", "en"])
            .ok()
            .flatten()
            .filter(|n| n.len() <= 100 && !n.chars().any(char::is_control))
            .map(str::to_string);
        Some(Country {
            code: code.to_ascii_uppercase(),
            name,
        })
    }
}

fn valid_code(c: &str) -> bool {
    c.len() == 2 && c.bytes().all(|b| b.is_ascii_alphabetic())
}

/// Address to look up for an IP or prefix observable: the network address
/// of a prefix.
pub fn ip_of(ty: ObservableType, value: &str) -> Option<IpAddr> {
    if !ty.is_ip() {
        return None;
    }
    value
        .parse::<IpNet>()
        .map(|n| n.network())
        .or_else(|_| value.parse::<IpAddr>())
        .ok()
}

/// Countries of a finding. IPs have at most one; a domain has one per
/// country its addresses are in. Empty means unknown.
pub fn countries_of(
    geo: &dyn CountryLookup,
    ty: ObservableType,
    value: &str,
    resolved: &HashMap<String, Vec<IpAddr>>,
    names: &mut HashMap<String, String>,
) -> BTreeSet<String> {
    let ips = match ty {
        ObservableType::DomainName => resolved.get(value).cloned().unwrap_or_default(),
        _ => ip_of(ty, value).into_iter().collect(),
    };
    let mut out = BTreeSet::new();
    for ip in ips {
        if let Some(c) = geo.lookup(ip) {
            if let Some(n) = c.name {
                names.entry(c.code.clone()).or_insert(n);
            }
            out.insert(c.code);
        }
    }
    out
}

/// Resolve `domains` with the system resolver, `concurrency` at a time.
/// Domains that fail or time out map to no addresses.
pub async fn resolve(
    domains: BTreeSet<String>,
    timeout: Duration,
    concurrency: usize,
) -> HashMap<String, Vec<IpAddr>> {
    let limit = Arc::new(Semaphore::new(concurrency));
    let mut tasks = JoinSet::new();
    for d in domains {
        let limit = limit.clone();
        tasks.spawn(async move {
            let _permit = limit.acquire_owned().await;
            let addrs = match tokio::time::timeout(timeout, tokio::net::lookup_host((&*d, 0))).await
            {
                Ok(Ok(a)) => a.map(|s| s.ip()).collect::<BTreeSet<_>>(),
                Ok(Err(e)) => {
                    tracing::debug!(domain = %d, "resolution failed: {e}");
                    BTreeSet::new()
                }
                Err(_) => {
                    tracing::debug!(domain = %d, "resolution timed out");
                    BTreeSet::new()
                }
            };
            (d, addrs.into_iter().collect())
        });
    }
    let mut out = HashMap::new();
    while let Some(r) = tasks.join_next().await {
        if let Ok((d, a)) = r {
            out.insert(d, a);
        }
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Maps the first octet / first hextet to a country.
    pub struct Fake;

    impl CountryLookup for Fake {
        fn lookup(&self, ip: IpAddr) -> Option<Country> {
            let code = match ip {
                IpAddr::V4(v4) => match v4.octets()[0] {
                    45 => "DE",
                    46 => "US",
                    _ => return None,
                },
                IpAddr::V6(v6) => match v6.segments()[0] {
                    0x2a01 => "FR",
                    _ => return None,
                },
            };
            Some(Country {
                code: code.into(),
                name: Some(format!("Name of {code}")),
            })
        }
    }

    #[test]
    fn prefixes_use_network_address() {
        assert_eq!(
            ip_of(ObservableType::Ipv4Addr, "45.13.7.0/24"),
            Some("45.13.7.0".parse().unwrap())
        );
        assert_eq!(
            ip_of(ObservableType::Ipv6Addr, "2a01:4f8:1::/48"),
            Some("2a01:4f8:1::".parse().unwrap())
        );
        assert_eq!(
            ip_of(ObservableType::Ipv4Addr, "45.13.7.9"),
            Some("45.13.7.9".parse().unwrap())
        );
        assert_eq!(ip_of(ObservableType::DomainName, "45.13.7.9"), None);
        assert_eq!(ip_of(ObservableType::Ipv4Addr, "nonsense"), None);
    }

    #[test]
    fn domains_count_each_country_once() {
        let mut names = HashMap::new();
        let resolved = HashMap::from([(
            "evil.test".to_string(),
            vec![
                "45.1.1.1".parse().unwrap(),
                "45.2.2.2".parse().unwrap(),
                "46.1.1.1".parse().unwrap(),
                "10.0.0.1".parse().unwrap(),
            ],
        )]);
        let c = countries_of(
            &Fake,
            ObservableType::DomainName,
            "evil.test",
            &resolved,
            &mut names,
        );
        assert_eq!(c, ["DE".to_string(), "US".to_string()].into());
        assert_eq!(names["DE"], "Name of DE");
        let c = countries_of(
            &Fake,
            ObservableType::DomainName,
            "other.test",
            &resolved,
            &mut names,
        );
        assert!(c.is_empty());
    }
}
