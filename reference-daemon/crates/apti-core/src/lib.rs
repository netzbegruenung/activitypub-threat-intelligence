//! Core types and algorithms for the ActivityPub Threat Intelligence profile
//! (AP-TI, draft-seeberg-activitypub-threatintel-00).
//!
//! This crate is free of I/O. It contains the data model (Section 4),
//! observable normalisation (Section 4.1), consumer policy and the
//! effective-expiry engine (Section 7), and the control-socket protocol
//! shared between `aptid` and `apti-tui`.

pub mod expiry;
pub mod model;
pub mod normalize;
pub mod policy;
pub mod protocol;

pub use model::{Behavior, EvidenceKind, EvidenceObject, ObservableType, OpinionValue, Tlp};

/// JSON-LD context URI of the AP-TI vocabulary (placeholder, Section 12).
pub const TI_CONTEXT: &str = "https://example.org/ns/ti";
/// ActivityStreams context URI.
pub const AS_CONTEXT: &str = "https://www.w3.org/ns/activitystreams";
/// The ActivityStreams public collection.
pub const AS_PUBLIC: &str = "https://www.w3.org/ns/activitystreams#Public";
/// Maximum number of objects per activity and per collection page (Section 5.3).
pub const MAX_BATCH: usize = 1000;
/// Clock skew tolerance for future-dated evidence (Section 7).
pub const FUTURE_TOLERANCE_SECS: i64 = 300;

/// The `@context` value used on all AP-TI documents.
pub fn context() -> serde_json::Value {
    serde_json::json!([AS_CONTEXT, TI_CONTEXT])
}

/// The JSON-LD context document of Appendix B.
pub fn context_document() -> serde_json::Value {
    serde_json::json!({
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
    })
}
