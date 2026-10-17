//! Channel bonding Phase A4 — protocol version and capability negotiation.
//!
//! Bonded donors may run different ATP builds. This control-plane surface keeps
//! mixed-version fleets fail-closed: peers agree on one protocol version, one
//! transport intersection, one assignment mode, and whether auth/resume are
//! required before any donor starts spraying symbols.

use core::fmt;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
};

use serde::{Deserialize, Serialize};

use super::assignment::{
    BONDING_ASSIGNMENT_VERSION, BondAuthKeyRef, DonorAssignment, DonorAssignmentError,
    MAX_BONDING_DONORS,
};

/// Current bonded-handshake protocol version.
pub const BONDING_HANDSHAKE_VERSION: u16 = BONDING_ASSIGNMENT_VERSION;

/// Structured event schema for receiver-side donor admission traces.
pub const BONDING_DONOR_ADMISSION_TRACE_SCHEMA: &str = "atp-bonding-donor-admission-v1";

/// Transport family advertised during bonded-transfer negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum BondTransport {
    /// Direct IP path.
    DirectIp,
    /// SSH-carried control or data path.
    Ssh,
    /// Tailscale or another WireGuard-backed path.
    Tailscale,
}

/// Assignment mode selected by a compatible handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BondingAssignmentMode {
    /// Static donor residue classes: donor `i` owns `esi % N == i`.
    StaticResidue,
    /// Receiver-allocated explicit ESI windows.
    DynamicWindows,
}

/// Negotiation offer from a receiver or donor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondingHandshake {
    /// Lowest compatible bonding protocol version.
    pub min_protocol_version: u16,
    /// Highest compatible bonding protocol version.
    pub max_protocol_version: u16,
    /// Supported path transports.
    pub supported_transports: BTreeSet<BondTransport>,
    /// Whether explicit receiver-allocated ESI windows are supported.
    pub supports_dynamic_windows: bool,
    /// Whether partial-transfer resume metadata is supported.
    pub supports_resume: bool,
    /// Whether symbols must carry auth tags on this endpoint.
    pub auth_required: bool,
    /// Maximum donor count accepted by this endpoint.
    pub max_donor_count: u32,
    /// Forward-compatible extension tokens. Unknown tokens are ignored.
    pub extension_capabilities: BTreeSet<String>,
}

impl BondingHandshake {
    /// Build a version-1 static-residue offer.
    #[must_use]
    pub fn v1_static(
        transports: impl IntoIterator<Item = BondTransport>,
        max_donor_count: u32,
        auth_required: bool,
    ) -> Self {
        Self {
            min_protocol_version: BONDING_HANDSHAKE_VERSION,
            max_protocol_version: BONDING_HANDSHAKE_VERSION,
            supported_transports: transports.into_iter().collect(),
            supports_dynamic_windows: false,
            supports_resume: false,
            auth_required,
            max_donor_count,
            extension_capabilities: BTreeSet::new(),
        }
    }

    /// Set an inclusive protocol version range.
    #[must_use]
    pub const fn with_protocol_range(
        mut self,
        min_protocol_version: u16,
        max_protocol_version: u16,
    ) -> Self {
        self.min_protocol_version = min_protocol_version;
        self.max_protocol_version = max_protocol_version;
        self
    }

    /// Advertise receiver-allocated dynamic ESI windows.
    #[must_use]
    pub const fn with_dynamic_windows(mut self, supported: bool) -> Self {
        self.supports_dynamic_windows = supported;
        self
    }

    /// Advertise partial-transfer resume metadata.
    #[must_use]
    pub const fn with_resume(mut self, supported: bool) -> Self {
        self.supports_resume = supported;
        self
    }

    /// Advertise a forward-compatible extension token.
    #[must_use]
    pub fn with_extension_capability(mut self, capability: impl Into<String>) -> Self {
        self.extension_capabilities.insert(capability.into());
        self
    }

    /// Negotiate a compatible agreement with `peer`.
    ///
    /// Unknown extension tokens are intentionally ignored. Core behavior is
    /// selected only from fields both peers understand in this version.
    pub fn negotiate(&self, peer: &Self) -> Result<BondingAgreement, BondingHandshakeError> {
        self.validate_offer()?;
        peer.validate_offer()?;

        let protocol_version = self.max_protocol_version.min(peer.max_protocol_version);
        let required_min = self.min_protocol_version.max(peer.min_protocol_version);
        if protocol_version < required_min {
            return Err(BondingHandshakeError::IncompatibleProtocolVersion {
                local_min: self.min_protocol_version,
                local_max: self.max_protocol_version,
                peer_min: peer.min_protocol_version,
                peer_max: peer.max_protocol_version,
            });
        }

        let supported_transports = self
            .supported_transports
            .intersection(&peer.supported_transports)
            .copied()
            .collect::<BTreeSet<_>>();
        if supported_transports.is_empty() {
            return Err(BondingHandshakeError::NoCommonTransport);
        }

        let max_donor_count = self.max_donor_count.min(peer.max_donor_count);
        if max_donor_count == 0 {
            return Err(BondingHandshakeError::InvalidDonorCount { donor_count: 0 });
        }

        Ok(BondingAgreement {
            protocol_version,
            supported_transports,
            assignment_mode: if self.supports_dynamic_windows && peer.supports_dynamic_windows {
                BondingAssignmentMode::DynamicWindows
            } else {
                BondingAssignmentMode::StaticResidue
            },
            resume_supported: self.supports_resume && peer.supports_resume,
            auth_required: self.auth_required || peer.auth_required,
            max_donor_count,
        })
    }

    fn validate_offer(&self) -> Result<(), BondingHandshakeError> {
        if self.min_protocol_version == 0 || self.min_protocol_version > self.max_protocol_version {
            return Err(BondingHandshakeError::InvalidProtocolRange {
                min: self.min_protocol_version,
                max: self.max_protocol_version,
            });
        }
        if self.supported_transports.is_empty() {
            return Err(BondingHandshakeError::NoCommonTransport);
        }
        if self.max_donor_count == 0 {
            return Err(BondingHandshakeError::InvalidDonorCount { donor_count: 0 });
        }
        if self.max_donor_count > MAX_BONDING_DONORS {
            return Err(BondingHandshakeError::TooManyDonors {
                donor_count: self.max_donor_count,
                max: MAX_BONDING_DONORS,
            });
        }
        Ok(())
    }
}

/// Result of a compatible bonding handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondingAgreement {
    /// Selected bonding protocol version.
    pub protocol_version: u16,
    /// Common supported transports.
    pub supported_transports: BTreeSet<BondTransport>,
    /// Assignment mode for this donor/receiver pair.
    pub assignment_mode: BondingAssignmentMode,
    /// Whether resume may be used.
    pub resume_supported: bool,
    /// Whether symbols must carry auth tags.
    pub auth_required: bool,
    /// Negotiated donor-count ceiling.
    pub max_donor_count: u32,
}

impl BondingAgreement {
    /// Whether this agreement permits a transport family.
    #[must_use]
    pub fn supports_transport(&self, transport: BondTransport) -> bool {
        self.supported_transports.contains(&transport)
    }
}

/// Receiver-side result of accepting one bonded donor control connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BondingDonorEnrollment {
    /// Receiver-assigned donor index.
    pub donor_index: u32,
    /// Negotiated control-plane agreement with this donor.
    pub agreement: BondingAgreement,
    /// Assignment sent back to the donor before it starts spraying symbols.
    pub assignment: DonorAssignment,
}

impl BondingDonorEnrollment {
    /// Build the structured C1 admission trace for this enrollment.
    #[must_use]
    pub fn admission_trace(&self) -> BondingDonorAdmissionTrace {
        BondingDonorAdmissionTrace {
            schema_version: BONDING_DONOR_ADMISSION_TRACE_SCHEMA,
            event: "bonding_donor_admitted",
            donor_index: self.donor_index,
            donor_count: self.assignment.donor_count,
            protocol_version: self.agreement.protocol_version,
            assignment_mode: self.agreement.assignment_mode,
            supported_transports: self.agreement.supported_transports.clone(),
            auth_required: self.agreement.auth_required,
            resume_supported: self.agreement.resume_supported,
            receiver_udp_endpoints: self.assignment.receiver_udp_endpoints.clone(),
        }
    }
}

/// Redaction-safe receiver-side event emitted after accepting one donor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BondingDonorAdmissionTrace {
    /// Stable schema marker for downstream log parsers.
    pub schema_version: &'static str,
    /// Stable event name.
    pub event: &'static str,
    /// Receiver-assigned donor index.
    pub donor_index: u32,
    /// Total donors expected for this bonded transfer.
    pub donor_count: u32,
    /// Negotiated bonding protocol version.
    pub protocol_version: u16,
    /// Negotiated donor assignment mode.
    pub assignment_mode: BondingAssignmentMode,
    /// Common transport families negotiated with this donor.
    pub supported_transports: BTreeSet<BondTransport>,
    /// Whether symbol authentication is required.
    pub auth_required: bool,
    /// Whether resume metadata is supported.
    pub resume_supported: bool,
    /// Shared receiver UDP endpoints sent in the donor assignment.
    pub receiver_udp_endpoints: Vec<SocketAddr>,
}

/// Receiver-side control-plane allocator for Phase C1 donor admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BondingReceiverControlPlane {
    receiver_offer: BondingHandshake,
    registry: BondingControlRegistry,
    receiver_udp_endpoints: Vec<SocketAddr>,
    auth_key_ref: Option<BondAuthKeyRef>,
}

impl BondingReceiverControlPlane {
    /// Create a receiver control plane for one bonded transfer.
    pub fn new(
        receiver_offer: BondingHandshake,
        expected_donor_count: u32,
        receiver_udp_endpoints: Vec<SocketAddr>,
        auth_key_ref: Option<BondAuthKeyRef>,
    ) -> Result<Self, BondingHandshakeError> {
        receiver_offer.validate_offer()?;
        if receiver_udp_endpoints.is_empty() {
            return Err(BondingHandshakeError::NoReceiverUdpEndpoint);
        }
        if receiver_offer.auth_required && auth_key_ref.is_none() {
            return Err(BondingHandshakeError::MissingRequiredAuthKeyRef);
        }
        if expected_donor_count > receiver_offer.max_donor_count {
            return Err(BondingHandshakeError::ReceiverDonorCountTooSmall {
                expected_donor_count,
                receiver_max_donor_count: receiver_offer.max_donor_count,
            });
        }

        Ok(Self {
            receiver_offer,
            registry: BondingControlRegistry::new(expected_donor_count)?,
            receiver_udp_endpoints,
            auth_key_ref,
        })
    }

    /// Enroll the next donor that completed the control handshake.
    ///
    /// Donor indexes are allocated in arrival order. Every donor receives the
    /// same receiver UDP endpoint set so all residue classes feed one data-plane
    /// listener.
    pub fn enroll_next_donor(
        &mut self,
        donor_offer: &BondingHandshake,
    ) -> Result<BondingDonorEnrollment, BondingHandshakeError> {
        if self.registry.is_complete() {
            return Err(BondingHandshakeError::TooManyDonorControls {
                expected_donor_count: self.registry.expected_donor_count(),
            });
        }

        let donor_index = self.registry.enrolled_count() as u32;
        let agreement = self.receiver_offer.negotiate(donor_offer)?;
        self.registry.enroll_donor(donor_index, agreement.clone())?;

        let assignment = DonorAssignment::new_static(
            donor_index,
            self.registry.expected_donor_count(),
            self.receiver_udp_endpoints.clone(),
            self.auth_key_ref.clone(),
        );
        assignment
            .validate()
            .map_err(|error| BondingHandshakeError::InvalidDonorAssignment {
                donor_index,
                error,
            })?;

        Ok(BondingDonorEnrollment {
            donor_index,
            agreement,
            assignment,
        })
    }

    /// Borrow the receiver's donor-control registry.
    #[must_use]
    pub const fn registry(&self) -> &BondingControlRegistry {
        &self.registry
    }

    /// True when every expected donor control connection has been enrolled.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.registry.is_complete()
    }
}

/// Receiver-side registry of negotiated donor control connections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BondingControlRegistry {
    expected_donor_count: u32,
    donors: BTreeMap<u32, BondingAgreement>,
}

impl BondingControlRegistry {
    /// Create an empty registry for one bonded transfer.
    pub fn new(expected_donor_count: u32) -> Result<Self, BondingHandshakeError> {
        if expected_donor_count == 0 {
            return Err(BondingHandshakeError::InvalidDonorCount { donor_count: 0 });
        }
        if expected_donor_count > MAX_BONDING_DONORS {
            return Err(BondingHandshakeError::TooManyDonors {
                donor_count: expected_donor_count,
                max: MAX_BONDING_DONORS,
            });
        }
        Ok(Self {
            expected_donor_count,
            donors: BTreeMap::new(),
        })
    }

    /// Enroll one donor's negotiated control agreement.
    pub fn enroll_donor(
        &mut self,
        donor_index: u32,
        agreement: BondingAgreement,
    ) -> Result<(), BondingHandshakeError> {
        if donor_index >= self.expected_donor_count {
            return Err(BondingHandshakeError::DonorIndexOutOfRange {
                donor_index,
                donor_count: self.expected_donor_count,
            });
        }
        if agreement.max_donor_count < self.expected_donor_count {
            return Err(BondingHandshakeError::AgreementDonorCountTooSmall {
                donor_index,
                expected_donor_count: self.expected_donor_count,
                agreement_max_donor_count: agreement.max_donor_count,
            });
        }
        if self.donors.insert(donor_index, agreement).is_some() {
            return Err(BondingHandshakeError::DuplicateDonorControl { donor_index });
        }
        Ok(())
    }

    /// Number of unique donor control connections enrolled.
    #[must_use]
    pub fn enrolled_count(&self) -> usize {
        self.donors.len()
    }

    /// Expected donor count for this bonded transfer.
    #[must_use]
    pub const fn expected_donor_count(&self) -> u32 {
        self.expected_donor_count
    }

    /// True when every donor index in `0..expected_donor_count` is enrolled.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.enrolled_count() == self.expected_donor_count as usize
    }

    /// Return one donor's negotiated agreement.
    #[must_use]
    pub fn agreement_for(&self, donor_index: u32) -> Option<&BondingAgreement> {
        self.donors.get(&donor_index)
    }

    /// Donor indexes that have completed control negotiation, sorted ascending.
    #[must_use]
    pub fn enrolled_donor_indices(&self) -> Vec<u32> {
        self.donors.keys().copied().collect()
    }

    /// Donor indexes still missing from the expected control set.
    #[must_use]
    pub fn missing_donor_indices(&self) -> Vec<u32> {
        (0..self.expected_donor_count)
            .filter(|donor_index| !self.donors.contains_key(donor_index))
            .collect()
    }
}

/// Bonded-handshake validation or negotiation failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BondingHandshakeError {
    /// Donor count was zero.
    InvalidDonorCount { donor_count: u32 },
    /// Donor count exceeds the conservative Phase-A ceiling.
    TooManyDonors { donor_count: u32, max: u32 },
    /// Protocol range was internally invalid.
    InvalidProtocolRange { min: u16, max: u16 },
    /// Local and peer protocol ranges do not overlap.
    IncompatibleProtocolVersion {
        local_min: u16,
        local_max: u16,
        peer_min: u16,
        peer_max: u16,
    },
    /// No transport family is common to both peers.
    NoCommonTransport,
    /// Donor index is outside the expected donor set.
    DonorIndexOutOfRange { donor_index: u32, donor_count: u32 },
    /// The same donor control connection was enrolled twice.
    DuplicateDonorControl { donor_index: u32 },
    /// A negotiated donor agreement cannot support this transfer's donor count.
    AgreementDonorCountTooSmall {
        donor_index: u32,
        expected_donor_count: u32,
        agreement_max_donor_count: u32,
    },
    /// Receiver offer cannot support the expected donor count.
    ReceiverDonorCountTooSmall {
        expected_donor_count: u32,
        receiver_max_donor_count: u32,
    },
    /// Receiver did not publish a UDP spray endpoint for the donors.
    NoReceiverUdpEndpoint,
    /// Receiver requires bonded symbol auth but has no assignable key reference.
    MissingRequiredAuthKeyRef,
    /// More donor control connections arrived than this transfer accepts.
    TooManyDonorControls { expected_donor_count: u32 },
    /// The generated assignment failed the Phase-A assignment validator.
    InvalidDonorAssignment {
        donor_index: u32,
        error: DonorAssignmentError,
    },
}

impl fmt::Display for BondingHandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDonorCount { donor_count } => write!(
                f,
                "invalid channel-bonding donor count {donor_count}; must be nonzero"
            ),
            Self::TooManyDonors { donor_count, max } => write!(
                f,
                "channel-bonding donor count {donor_count} exceeds max {max}"
            ),
            Self::InvalidProtocolRange { min, max } => {
                write!(f, "invalid channel-bonding protocol range {min}..={max}")
            }
            Self::IncompatibleProtocolVersion {
                local_min,
                local_max,
                peer_min,
                peer_max,
            } => write!(
                f,
                "incompatible channel-bonding protocol versions: local {local_min}..={local_max}, peer {peer_min}..={peer_max}"
            ),
            Self::NoCommonTransport => f.write_str("no common channel-bonding transport"),
            Self::DonorIndexOutOfRange {
                donor_index,
                donor_count,
            } => write!(
                f,
                "channel-bonding donor index {donor_index} is outside 0..{donor_count}"
            ),
            Self::DuplicateDonorControl { donor_index } => write!(
                f,
                "channel-bonding donor {donor_index} control connection enrolled twice"
            ),
            Self::AgreementDonorCountTooSmall {
                donor_index,
                expected_donor_count,
                agreement_max_donor_count,
            } => write!(
                f,
                "channel-bonding donor {donor_index} agreement supports {agreement_max_donor_count} donors, below expected {expected_donor_count}"
            ),
            Self::ReceiverDonorCountTooSmall {
                expected_donor_count,
                receiver_max_donor_count,
            } => write!(
                f,
                "channel-bonding receiver offer supports {receiver_max_donor_count} donors, below expected {expected_donor_count}"
            ),
            Self::NoReceiverUdpEndpoint => {
                f.write_str("channel-bonding receiver has no UDP spray endpoint")
            }
            Self::MissingRequiredAuthKeyRef => f.write_str(
                "channel-bonding receiver requires symbol auth but has no assignable key reference",
            ),
            Self::TooManyDonorControls {
                expected_donor_count,
            } => write!(
                f,
                "channel-bonding receiver already enrolled all {expected_donor_count} donors"
            ),
            Self::InvalidDonorAssignment { donor_index, error } => write!(
                f,
                "channel-bonding donor {donor_index} assignment is invalid: {error}"
            ),
        }
    }
}

impl std::error::Error for BondingHandshakeError {}

#[cfg(test)]
#[path = "handshake_inline_tests.rs"]
mod tests;
