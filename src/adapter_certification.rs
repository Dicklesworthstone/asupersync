//! Source-owned adapter certification declarations.
//!
//! The JSON matrix in `artifacts/adapter_certification_matrix_v1.json` is the
//! reviewed operator artifact. This module is the source-owned declaration
//! surface that keeps adapter identities and fail-closed status from drifting
//! into hand-maintained prose.

/// Adapter category rendered by the certification matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AdapterCategory {
    /// HTTP protocol adapters.
    Http,
    /// Database protocol adapters.
    Database,
    /// Messaging and broker adapters.
    Messaging,
    /// TLS adapters.
    Tls,
    /// Transport adapters.
    Transport,
}

impl AdapterCategory {
    /// Stable JSON identifier for this category.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Database => "database",
            Self::Messaging => "messaging",
            Self::Tls => "tls",
            Self::Transport => "transport",
        }
    }
}

/// Certification state used by the fail-closed adapter matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AdapterCertificationStatus {
    /// Live implementation and reference coverage are wired.
    CertifiedLive,
    /// Live proof is valid only behind explicit opt-in features.
    CertifiedOptIn,
    /// Local implementation exists, but reference or deployment proof is partial.
    PartialFailClosed,
    /// Required implementation or reference proof is unavailable.
    UnavailableFailClosed,
}

impl AdapterCertificationStatus {
    /// Stable JSON identifier for this status.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CertifiedLive => "certified_live",
            Self::CertifiedOptIn => "certified_opt_in",
            Self::PartialFailClosed => "partial_fail_closed",
            Self::UnavailableFailClosed => "unavailable_fail_closed",
        }
    }
}

/// Rendered operator status for adapter rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AdapterRenderedStatus {
    /// Proof-backed passing status.
    Pass,
    /// Expected fail-closed status.
    Xfail,
    /// Blocked status with an explicit external or missing-proof reason.
    Blocked,
}

impl AdapterRenderedStatus {
    /// Stable rendered identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Xfail => "XFAIL",
            Self::Blocked => "BLOCKED",
        }
    }
}

/// Source-owned adapter declaration projected into the certification matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdapterCertificationDeclaration {
    /// Stable adapter row identifier.
    pub adapter_id: &'static str,
    /// Adapter category.
    pub category: AdapterCategory,
    /// Certification status.
    pub certification_status: AdapterCertificationStatus,
    /// Rendered operator status.
    pub rendered_status: AdapterRenderedStatus,
    /// Whether this row must fail closed without full reference coverage.
    pub fail_closed_without_full_reference: bool,
}

/// Canonical adapter declarations for the fail-closed certification matrix.
pub const ADAPTER_CERTIFICATIONS: &[AdapterCertificationDeclaration] = &[
    AdapterCertificationDeclaration {
        adapter_id: "http-h1-h2",
        category: AdapterCategory::Http,
        certification_status: AdapterCertificationStatus::CertifiedLive,
        rendered_status: AdapterRenderedStatus::Pass,
        fail_closed_without_full_reference: false,
    },
    AdapterCertificationDeclaration {
        adapter_id: "database-postgres-mysql-sqlite",
        category: AdapterCategory::Database,
        certification_status: AdapterCertificationStatus::PartialFailClosed,
        rendered_status: AdapterRenderedStatus::Xfail,
        fail_closed_without_full_reference: true,
    },
    AdapterCertificationDeclaration {
        adapter_id: "messaging-nats-jetstream-kafka-redis",
        category: AdapterCategory::Messaging,
        certification_status: AdapterCertificationStatus::PartialFailClosed,
        rendered_status: AdapterRenderedStatus::Xfail,
        fail_closed_without_full_reference: true,
    },
    AdapterCertificationDeclaration {
        adapter_id: "tls-rustls",
        category: AdapterCategory::Tls,
        certification_status: AdapterCertificationStatus::CertifiedOptIn,
        rendered_status: AdapterRenderedStatus::Pass,
        fail_closed_without_full_reference: false,
    },
    AdapterCertificationDeclaration {
        adapter_id: "transport-quic-websocket-router",
        category: AdapterCategory::Transport,
        certification_status: AdapterCertificationStatus::PartialFailClosed,
        rendered_status: AdapterRenderedStatus::Xfail,
        fail_closed_without_full_reference: true,
    },
];

/// Find a declaration by adapter id.
#[must_use]
pub fn adapter_certification(adapter_id: &str) -> Option<&'static AdapterCertificationDeclaration> {
    ADAPTER_CERTIFICATIONS
        .iter()
        .find(|declaration| declaration.adapter_id == adapter_id)
}

#[cfg(test)]
mod tests {
    use super::{
        ADAPTER_CERTIFICATIONS, AdapterCategory, AdapterCertificationStatus, AdapterRenderedStatus,
        adapter_certification,
    };

    #[test]
    fn adapter_certifications_have_stable_ids_and_statuses() {
        assert_eq!(ADAPTER_CERTIFICATIONS.len(), 5);
        let http = adapter_certification("http-h1-h2").expect("http adapter");
        assert_eq!(http.category, AdapterCategory::Http);
        assert_eq!(
            http.certification_status,
            AdapterCertificationStatus::CertifiedLive
        );
        assert_eq!(http.rendered_status, AdapterRenderedStatus::Pass);
        assert!(!http.fail_closed_without_full_reference);

        let database =
            adapter_certification("database-postgres-mysql-sqlite").expect("database adapter");
        assert_eq!(
            database.certification_status,
            AdapterCertificationStatus::PartialFailClosed
        );
        assert_eq!(database.rendered_status, AdapterRenderedStatus::Xfail);
        assert!(database.fail_closed_without_full_reference);
    }
}
