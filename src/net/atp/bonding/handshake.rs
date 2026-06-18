//! Channel bonding Phase A4 — protocol version and capability negotiation.
//!
//! Bonded donors may run different ATP builds. This control-plane surface keeps
//! mixed-version fleets fail-closed: peers agree on one protocol version, one
//! transport intersection, one assignment mode, and whether auth/resume are
//! required before any donor starts spraying symbols.

use core::fmt;
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::assignment::{BONDING_ASSIGNMENT_VERSION, MAX_BONDING_DONORS};

/// Current bonded-handshake protocol version.
pub const BONDING_HANDSHAKE_VERSION: u16 = BONDING_ASSIGNMENT_VERSION;

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
        if self.min_protocol_version == 0 || self.min_protocol_version > self.max_protocol_version
        {
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
        }
    }
}

impl std::error::Error for BondingHandshakeError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_degrades_to_static_residue_when_dynamic_windows_are_not_common() {
        let receiver = BondingHandshake::v1_static(
            [BondTransport::DirectIp, BondTransport::Tailscale],
            16,
            true,
        )
        .with_dynamic_windows(true)
        .with_resume(true)
        .with_extension_capability("phase-e.dynamic-window-v1");
        let donor = BondingHandshake::v1_static([BondTransport::Tailscale], 8, false)
            .with_extension_capability("donor-private-future");

        let agreement = receiver.negotiate(&donor).expect("compatible");

        assert_eq!(agreement.protocol_version, BONDING_HANDSHAKE_VERSION);
        assert_eq!(
            agreement.assignment_mode,
            BondingAssignmentMode::StaticResidue
        );
        assert!(!agreement.resume_supported);
        assert!(agreement.auth_required);
        assert_eq!(agreement.max_donor_count, 8);
        assert_eq!(
            agreement.supported_transports,
            BTreeSet::from([BondTransport::Tailscale])
        );
        assert!(agreement.supports_transport(BondTransport::Tailscale));
        assert!(!agreement.supports_transport(BondTransport::DirectIp));
    }

    #[test]
    fn handshake_selects_dynamic_windows_and_resume_when_both_peers_support_them() {
        let receiver = BondingHandshake::v1_static([BondTransport::DirectIp], 16, true)
            .with_dynamic_windows(true)
            .with_resume(true);
        let donor = BondingHandshake::v1_static([BondTransport::DirectIp], 12, true)
            .with_dynamic_windows(true)
            .with_resume(true);

        let agreement = receiver.negotiate(&donor).expect("compatible");

        assert_eq!(
            agreement.assignment_mode,
            BondingAssignmentMode::DynamicWindows
        );
        assert!(agreement.resume_supported);
        assert!(agreement.auth_required);
        assert_eq!(agreement.max_donor_count, 12);
        assert!(agreement.supports_transport(BondTransport::DirectIp));
    }

    #[test]
    fn handshake_ignores_unknown_extensions_but_refuses_no_common_transport() {
        let receiver = BondingHandshake::v1_static([BondTransport::DirectIp], 16, true)
            .with_extension_capability("unknown.receiver.future");
        let donor = BondingHandshake::v1_static([BondTransport::Ssh], 16, true)
            .with_extension_capability("unknown.donor.future");

        let err = receiver.negotiate(&donor).expect_err("no common transport");
        assert_eq!(err, BondingHandshakeError::NoCommonTransport);
    }

    #[test]
    fn handshake_refuses_incompatible_versions_with_typed_error() {
        let receiver = BondingHandshake::v1_static([BondTransport::DirectIp], 16, true)
            .with_protocol_range(2, 2);
        let donor = BondingHandshake::v1_static([BondTransport::DirectIp], 16, true);

        let err = receiver.negotiate(&donor).expect_err("version mismatch");

        assert_eq!(
            err,
            BondingHandshakeError::IncompatibleProtocolVersion {
                local_min: 2,
                local_max: 2,
                peer_min: BONDING_HANDSHAKE_VERSION,
                peer_max: BONDING_HANDSHAKE_VERSION,
            }
        );
        assert!(err.to_string().contains("incompatible"));
    }

    #[test]
    fn handshake_refuses_invalid_offer_shapes() {
        let donor = BondingHandshake::v1_static([BondTransport::DirectIp], 16, true);
        let version_zero = BondingHandshake::v1_static([BondTransport::DirectIp], 16, true)
            .with_protocol_range(0, BONDING_HANDSHAKE_VERSION);
        assert_eq!(
            version_zero.negotiate(&donor),
            Err(BondingHandshakeError::InvalidProtocolRange {
                min: 0,
                max: BONDING_HANDSHAKE_VERSION,
            })
        );

        let zero_donors = BondingHandshake::v1_static([BondTransport::DirectIp], 0, true);
        assert_eq!(
            zero_donors.negotiate(&donor),
            Err(BondingHandshakeError::InvalidDonorCount { donor_count: 0 })
        );

        let too_many_donors = BondingHandshake::v1_static(
            [BondTransport::DirectIp],
            MAX_BONDING_DONORS + 1,
            true,
        );
        assert_eq!(
            too_many_donors.negotiate(&donor),
            Err(BondingHandshakeError::TooManyDonors {
                donor_count: MAX_BONDING_DONORS + 1,
                max: MAX_BONDING_DONORS,
            })
        );
    }
}
