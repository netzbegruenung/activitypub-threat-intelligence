//! HTTP signatures, draft-cavage-http-signatures-12 profile as used on the
//! fediverse (`rsa-sha256` / `hs2019` with RSASSA-PKCS1-v1_5 SHA-256).

use axum::http::HeaderMap;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::{DateTime, TimeDelta, Utc};
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::pkcs8::DecodePublicKey;
use rsa::sha2::{Digest, Sha256};
use rsa::signature::{SignatureEncoding, Signer, Verifier};
use rsa::RsaPublicKey;
use url::Url;

use crate::keys::Keys;

#[derive(Debug, thiserror::Error)]
pub enum SigError {
    #[error("missing Signature header")]
    Missing,
    #[error("malformed Signature header: {0}")]
    Malformed(&'static str),
    #[error("unsupported algorithm `{0}`")]
    Algorithm(String),
    #[error("signed header `{0}` is missing from the request")]
    MissingHeader(String),
    #[error("signature must cover {0}")]
    Coverage(&'static str),
    #[error("signature is expired or dated in the future")]
    Stale,
    #[error("digest mismatch")]
    Digest,
    #[error("invalid public key")]
    Key,
    #[error("signature verification failed")]
    Invalid,
}

pub fn digest_header(body: &[u8]) -> String {
    format!("SHA-256={}", B64.encode(Sha256::digest(body)))
}

fn authority(url: &Url) -> String {
    match url.port() {
        Some(p) => format!("{}:{}", url.host_str().unwrap_or_default(), p),
        None => url.host_str().unwrap_or_default().to_string(),
    }
}

fn request_target(url: &Url) -> String {
    match url.query() {
        Some(q) => format!("{}?{}", url.path(), q),
        None => url.path().to_string(),
    }
}

/// Headers to add to an outgoing request: `Date`, optionally `Digest`, and
/// `Signature`. `Host` is set by the HTTP client from the URL.
pub fn sign_request(
    keys: &Keys,
    key_id: &str,
    method: &str,
    url: &Url,
    body: Option<&[u8]>,
) -> Vec<(&'static str, String)> {
    let date = httpdate::fmt_http_date(std::time::SystemTime::now());
    let mut names = vec!["(request-target)", "host", "date"];
    let mut lines = vec![
        format!(
            "(request-target): {} {}",
            method.to_lowercase(),
            request_target(url)
        ),
        format!("host: {}", authority(url)),
        format!("date: {date}"),
    ];
    let mut out = vec![("date", date)];
    if let Some(body) = body {
        let digest = digest_header(body);
        names.push("digest");
        lines.push(format!("digest: {digest}"));
        out.push(("digest", digest));
    }
    let sig = keys.signing.sign(lines.join("\n").as_bytes());
    out.push((
        "signature",
        format!(
            "keyId=\"{key_id}\",algorithm=\"rsa-sha256\",headers=\"{}\",signature=\"{}\"",
            names.join(" "),
            B64.encode(sig.to_bytes())
        ),
    ));
    out
}

#[derive(Debug, Clone, PartialEq)]
pub struct ParsedSignature {
    pub key_id: String,
    pub algorithm: Option<String>,
    pub headers: Vec<String>,
    pub signature: Vec<u8>,
    pub created: Option<i64>,
    pub expires: Option<i64>,
}

pub fn parse_signature(value: &str) -> Result<ParsedSignature, SigError> {
    let mut key_id = None;
    let mut algorithm = None;
    let mut headers = None;
    let mut signature = None;
    let mut created = None;
    let mut expires = None;
    let mut rest = value.trim();
    while !rest.is_empty() {
        let eq = rest
            .find('=')
            .ok_or(SigError::Malformed("expected key=value"))?;
        let key = rest[..eq].trim().to_ascii_lowercase();
        rest = &rest[eq + 1..];
        let val;
        if let Some(r) = rest.strip_prefix('"') {
            let end = r
                .find('"')
                .ok_or(SigError::Malformed("unterminated string"))?;
            val = r[..end].to_string();
            rest = &r[end + 1..];
        } else {
            let end = rest.find(',').unwrap_or(rest.len());
            val = rest[..end].trim().to_string();
            rest = &rest[end..];
        }
        rest = rest
            .trim_start()
            .strip_prefix(',')
            .unwrap_or(rest)
            .trim_start();
        match key.as_str() {
            "keyid" => key_id = Some(val),
            "algorithm" => algorithm = Some(val),
            "headers" => headers = Some(val),
            "signature" => signature = Some(val),
            "created" => created = val.parse().ok(),
            "expires" => expires = val.parse().ok(),
            _ => {}
        }
    }
    Ok(ParsedSignature {
        key_id: key_id.ok_or(SigError::Malformed("keyId"))?,
        algorithm,
        headers: headers
            .unwrap_or_else(|| "date".into())
            .split_whitespace()
            .map(|h| h.to_ascii_lowercase())
            .collect(),
        signature: B64
            .decode(signature.ok_or(SigError::Malformed("signature"))?)
            .map_err(|_| SigError::Malformed("signature encoding"))?,
        created,
        expires,
    })
}

/// Extract the signature from `Signature` (or `Authorization: Signature ...`).
pub fn signature_from_headers(headers: &HeaderMap) -> Result<ParsedSignature, SigError> {
    if let Some(v) = headers.get("signature").and_then(|v| v.to_str().ok()) {
        return parse_signature(v);
    }
    if let Some(v) = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Signature "))
    {
        return parse_signature(v);
    }
    Err(SigError::Missing)
}

/// Verify a parsed signature against the request.
/// `body` must be provided for requests with a body; its digest is checked.
#[allow(clippy::too_many_arguments)]
pub fn verify(
    sig: &ParsedSignature,
    method: &str,
    path_and_query: &str,
    headers: &HeaderMap,
    body: Option<&[u8]>,
    public_key_pem: &str,
    now: DateTime<Utc>,
    max_age: TimeDelta,
) -> Result<(), SigError> {
    match sig.algorithm.as_deref() {
        None | Some("hs2019") | Some("rsa-sha256") => {}
        Some(other) => return Err(SigError::Algorithm(other.to_string())),
    }
    if !sig.headers.iter().any(|h| h == "(request-target)") {
        return Err(SigError::Coverage("(request-target)"));
    }
    if !sig.headers.iter().any(|h| h == "host") {
        return Err(SigError::Coverage("host"));
    }
    let skew = TimeDelta::minutes(5);
    // Freshness: Date header or (created).
    if sig.headers.iter().any(|h| h == "date") {
        let date = headers
            .get("date")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| SigError::MissingHeader("date".into()))?;
        let t: DateTime<Utc> = httpdate::parse_http_date(date)
            .map_err(|_| SigError::Malformed("date"))?
            .into();
        if t > now + skew || now - t > max_age {
            return Err(SigError::Stale);
        }
    } else if let Some(created) = sig
        .created
        .filter(|_| sig.headers.iter().any(|h| h == "(created)"))
    {
        let t = DateTime::from_timestamp(created, 0).ok_or(SigError::Stale)?;
        if t > now + skew || now - t > max_age {
            return Err(SigError::Stale);
        }
    } else {
        return Err(SigError::Coverage("date or (created)"));
    }
    if let Some(exp) = sig.expires {
        if now.timestamp() > exp {
            return Err(SigError::Stale);
        }
    }
    if let Some(body) = body {
        if !sig.headers.iter().any(|h| h == "digest") {
            return Err(SigError::Coverage("digest"));
        }
        let digest = headers
            .get("digest")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| SigError::MissingHeader("digest".into()))?;
        let want = B64.encode(Sha256::digest(body));
        let ok = digest.split(',').any(|d| {
            d.trim()
                .split_once('=')
                .is_some_and(|(alg, v)| alg.eq_ignore_ascii_case("sha-256") && v == want)
        });
        if !ok {
            return Err(SigError::Digest);
        }
    }

    let mut lines = Vec::with_capacity(sig.headers.len());
    for h in &sig.headers {
        let line = match h.as_str() {
            "(request-target)" => format!(
                "(request-target): {} {}",
                method.to_lowercase(),
                path_and_query
            ),
            "(created)" => format!(
                "(created): {}",
                sig.created.ok_or(SigError::Malformed("created"))?
            ),
            "(expires)" => format!(
                "(expires): {}",
                sig.expires.ok_or(SigError::Malformed("expires"))?
            ),
            name => {
                let values: Vec<&str> = headers
                    .get_all(name)
                    .iter()
                    .filter_map(|v| v.to_str().ok())
                    .map(str::trim)
                    .collect();
                if values.is_empty() {
                    return Err(SigError::MissingHeader(name.to_string()));
                }
                format!("{name}: {}", values.join(", "))
            }
        };
        lines.push(line);
    }
    let key =
        RsaPublicKey::from_public_key_pem(public_key_pem.trim()).map_err(|_| SigError::Key)?;
    let signature = Signature::try_from(sig.signature.as_slice()).map_err(|_| SigError::Invalid)?;
    VerifyingKey::<Sha256>::new(key)
        .verify(lines.join("\n").as_bytes(), &signature)
        .map_err(|_| SigError::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers_for(url: &Url, signed: &[(&'static str, String)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("host", HeaderValue::from_str(&authority(url)).unwrap());
        for (k, v) in signed {
            h.insert(*k, HeaderValue::from_str(v).unwrap());
        }
        h
    }

    #[test]
    fn roundtrip_and_tamper() {
        let (keys, _) = Keys::generate().unwrap();
        let url = Url::parse("https://ti.example.net:8443/actor/inbox?x=1").unwrap();
        let body = br#"{"type":"Create"}"#;
        let signed = sign_request(
            &keys,
            "https://a.example/actor#main-key",
            "POST",
            &url,
            Some(body),
        );
        let headers = headers_for(&url, &signed);
        let sig = signature_from_headers(&headers).unwrap();
        assert_eq!(sig.key_id, "https://a.example/actor#main-key");
        let now = Utc::now();
        let max = TimeDelta::hours(12);
        verify(
            &sig,
            "POST",
            "/actor/inbox?x=1",
            &headers,
            Some(body),
            &keys.public_pem,
            now,
            max,
        )
        .unwrap();

        // Tampered body.
        assert!(matches!(
            verify(
                &sig,
                "POST",
                "/actor/inbox?x=1",
                &headers,
                Some(b"{}"),
                &keys.public_pem,
                now,
                max
            ),
            Err(SigError::Digest)
        ));
        // Different path.
        assert!(matches!(
            verify(
                &sig,
                "POST",
                "/other",
                &headers,
                Some(body),
                &keys.public_pem,
                now,
                max
            ),
            Err(SigError::Invalid)
        ));
        // Stale.
        assert!(matches!(
            verify(
                &sig,
                "POST",
                "/actor/inbox?x=1",
                &headers,
                Some(body),
                &keys.public_pem,
                now + TimeDelta::days(1),
                max
            ),
            Err(SigError::Stale)
        ));
        // Wrong key.
        let (other, _) = Keys::generate().unwrap();
        assert!(matches!(
            verify(
                &sig,
                "POST",
                "/actor/inbox?x=1",
                &headers,
                Some(body),
                &other.public_pem,
                now,
                max
            ),
            Err(SigError::Invalid)
        ));
    }

    #[test]
    fn get_without_digest() {
        let (keys, _) = Keys::generate().unwrap();
        let url = Url::parse("https://ti.example.net/actor/active?page=1").unwrap();
        let signed = sign_request(&keys, "k", "GET", &url, None);
        let headers = headers_for(&url, &signed);
        let sig = signature_from_headers(&headers).unwrap();
        verify(
            &sig,
            "GET",
            "/actor/active?page=1",
            &headers,
            None,
            &keys.public_pem,
            Utc::now(),
            TimeDelta::hours(1),
        )
        .unwrap();
    }

    #[test]
    fn parses_header() {
        let p = parse_signature(r#"keyId="https://x/a#k",algorithm="hs2019",headers="(request-target) host date",signature="AAAA""#).unwrap();
        assert_eq!(p.headers, vec!["(request-target)", "host", "date"]);
        assert_eq!(p.algorithm.as_deref(), Some("hs2019"));
        assert!(parse_signature("garbage").is_err());
    }
}
