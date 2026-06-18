//! Channel bonding Phase A3 — donor assignment and symbol-auth posture.
//!
//! This module is deliberately control-plane data only. It does not move bytes or
//! open sockets; it gives later RQ/QUIC data paths a validated donor assignment
//! plus one fail-closed helper for verifying bonded symbols before they can enter
//! a decoder or source-first persistence path.
//!
//! Security model:
//!
//! * A donor may spray only after A1 proves byte-identical content and A2/A3
//!   assign the donor a disjoint ESI set for the transfer.
//! * `BondAuthKeyRef` is an out-of-band handle to the shared symbol-auth key.
//!   Raw key material is intentionally not representable here.
//! * A symbol is accepted only if its existing `AuthenticationTag` verifies under
//!   the shared `SecurityContext`; missing, zero, or wrong-key tags are rejected
//!   before data-path consumers persist or decode the symbol.

use core::fmt;
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use crate::security::{AuthenticatedSymbol, AuthenticationTag, SecurityContext};
use crate::types::Symbol;

use super::esi::{EsiPartition, EsiPartitionError};

/// Version of the Phase-A donor-assignment record.
pub const BONDING_ASSIGNMENT_VERSION: u16 = 1;

/// Conservative ceiling for Phase-A donor fanout.
pub const MAX_BONDING_DONORS: u32 = 1024;

/// Out-of-band reference to the shared symbol-auth key for a bonded transfer.
///
/// The enum intentionally carries only handles. A raw `--rq-auth-key-hex` value
/// belongs in the existing encrypted/control-plane setup, never in donor
/// assignment structs that may be serialized for coordination or diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BondAuthKeyRef {
    /// Environment variable name containing the key on the local host.
    EnvVar(String),
    /// Local key file path or deployment-managed secret mount.
    KeyFile(String),
    /// Control-plane key identifier, receipt id, or KMS alias.
    ControlPlane(String),
}

impl BondAuthKeyRef {
    /// Return the non-secret handle string.
    #[must_use]
    pub fn value(&self) -> &str {
        match self {
            Self::EnvVar(value) | Self::KeyFile(value) | Self::ControlPlane(value) => value,
        }
    }

    /// True when the key reference has a non-empty handle.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.value().trim().is_empty()
    }
}

/// Validated assignment for one bonded donor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DonorAssignment {
    /// Assignment record version.
    pub protocol_version: u16,
    /// Zero-based donor index.
    pub donor_index: u32,
    /// Total donors participating in the bonded transfer.
    pub donor_count: u32,
    /// Optional receiver-assigned half-open ESI windows.
    ///
    /// Empty means Phase-A static residue ownership from A2. Non-empty windows
    /// are an explicit assignment and therefore override the static residue map.
    pub esi_windows: Vec<EsiWindow>,
    /// Receiver UDP endpoints reachable by this donor.
    pub receiver_udp_endpoints: Vec<SocketAddr>,
    /// Out-of-band reference to the shared symbol-auth key.
    pub auth_key_ref: Option<BondAuthKeyRef>,
}

impl DonorAssignment {
    /// Build a static-residue assignment (`esi % donor_count == donor_index`).
    #[must_use]
    pub fn new_static(
        donor_index: u32,
        donor_count: u32,
        receiver_udp_endpoints: Vec<SocketAddr>,
        auth_key_ref: Option<BondAuthKeyRef>,
    ) -> Self {
        Self {
            protocol_version: BONDING_ASSIGNMENT_VERSION,
            donor_index,
            donor_count,
            esi_windows: Vec::new(),
            receiver_udp_endpoints,
            auth_key_ref,
        }
    }

    /// Build an explicit-window assignment for dynamic receiver allocation.
    #[must_use]
    pub fn new_windowed(
        donor_index: u32,
        donor_count: u32,
        esi_windows: Vec<EsiWindow>,
        receiver_udp_endpoints: Vec<SocketAddr>,
        auth_key_ref: Option<BondAuthKeyRef>,
    ) -> Self {
        Self {
            protocol_version: BONDING_ASSIGNMENT_VERSION,
            donor_index,
            donor_count,
            esi_windows,
            receiver_udp_endpoints,
            auth_key_ref,
        }
    }

    /// Validate assignment shape before a donor can be enrolled.
    pub fn validate(&self) -> Result<(), DonorAssignmentError> {
        if self.protocol_version != BONDING_ASSIGNMENT_VERSION {
            return Err(DonorAssignmentError::UnsupportedVersion {
                version: self.protocol_version,
            });
        }
        if self.donor_count > MAX_BONDING_DONORS {
            return Err(DonorAssignmentError::TooManyDonors {
                donor_count: self.donor_count,
                max: MAX_BONDING_DONORS,
            });
        }
        EsiPartition::new(self.donor_index, self.donor_count)
            .map_err(DonorAssignmentError::InvalidPartition)?;
        if self.receiver_udp_endpoints.is_empty() {
            return Err(DonorAssignmentError::NoReceiverEndpoints);
        }
        if self
            .auth_key_ref
            .as_ref()
            .is_some_and(|auth_ref| !auth_ref.is_valid())
        {
            return Err(DonorAssignmentError::EmptyAuthKeyRef);
        }
        validate_esi_windows(&self.esi_windows)?;
        Ok(())
    }

    /// Return true when this donor owns `esi` under the validated assignment.
    #[must_use]
    pub fn owns_esi(&self, esi: u32) -> bool {
        if !self.esi_windows.is_empty() {
            return self.esi_windows.iter().any(|window| window.contains(esi));
        }

        EsiPartition::new(self.donor_index, self.donor_count)
            .map(|partition| partition.owns_esi(esi))
            .unwrap_or(false)
    }

    /// Whether the assignment expects authenticated symbols.
    #[must_use]
    pub fn requires_symbol_auth(&self) -> bool {
        self.auth_key_ref.is_some()
    }
}

/// Half-open ESI assignment window `[start, end)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EsiWindow {
    /// First included ESI.
    pub start_inclusive: u32,
    /// First excluded ESI.
    pub end_exclusive: u32,
}

impl EsiWindow {
    /// Construct a half-open ESI window.
    #[must_use]
    pub const fn new(start_inclusive: u32, end_exclusive: u32) -> Self {
        Self {
            start_inclusive,
            end_exclusive,
        }
    }

    /// True when the window contains at least one ESI.
    #[must_use]
    pub const fn is_non_empty(self) -> bool {
        self.start_inclusive < self.end_exclusive
    }

    /// True when `esi` is inside `[start, end)`.
    #[must_use]
    pub const fn contains(self, esi: u32) -> bool {
        self.start_inclusive <= esi && esi < self.end_exclusive
    }
}

/// Symbol-auth decision for a bonded symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BondedSymbolAuthVerdict {
    /// The tag verified and the returned symbol is safe to feed downstream.
    Accepted(AuthenticatedSymbol),
    /// The symbol must be dropped before persistence/decode.
    Rejected(BondedSymbolRejectReason),
}

/// Why a bonded symbol was rejected before the data path consumed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BondedSymbolRejectReason {
    /// Auth is required but the datagram carried no tag.
    MissingTag,
    /// The all-zero unauthenticated sentinel is never valid on a bonded path.
    ZeroTag,
    /// The tag did not verify under the assignment's shared auth context.
    InvalidTag,
}

/// Verify an already-framed bonded symbol before persistence or decode.
#[must_use]
pub fn verify_bonded_symbol_tag(
    context: &SecurityContext,
    symbol: &Symbol,
    tag: Option<AuthenticationTag>,
) -> BondedSymbolAuthVerdict {
    let Some(tag) = tag else {
        return BondedSymbolAuthVerdict::Rejected(BondedSymbolRejectReason::MissingTag);
    };
    if tag.is_zero() {
        return BondedSymbolAuthVerdict::Rejected(BondedSymbolRejectReason::ZeroTag);
    }

    let mut authenticated = AuthenticatedSymbol::from_parts(symbol.clone(), tag);
    match context.verify_authenticated_symbol(&mut authenticated) {
        Ok(()) if authenticated.is_verified() => BondedSymbolAuthVerdict::Accepted(authenticated),
        _ => BondedSymbolAuthVerdict::Rejected(BondedSymbolRejectReason::InvalidTag),
    }
}

/// Assignment validation errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DonorAssignmentError {
    /// The assignment record version is not supported by this code.
    UnsupportedVersion { version: u16 },
    /// Donor index/count did not form a valid A2 ESI partition.
    InvalidPartition(EsiPartitionError),
    /// Donor count exceeds the Phase-A conservative ceiling.
    TooManyDonors { donor_count: u32, max: u32 },
    /// Donors need at least one receiver endpoint to send symbols.
    NoReceiverEndpoints,
    /// A key-ref handle was present but blank.
    EmptyAuthKeyRef,
    /// A window was empty or inverted.
    InvalidEsiWindow {
        start_inclusive: u32,
        end_exclusive: u32,
    },
    /// Explicit receiver windows overlap.
    OverlappingEsiWindows {
        previous_end_exclusive: u32,
        next_start_inclusive: u32,
    },
}

impl fmt::Display for DonorAssignmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion { version } => {
                write!(f, "unsupported channel-bonding assignment version {version}")
            }
            Self::InvalidPartition(err) => write!(f, "{err}"),
            Self::TooManyDonors { donor_count, max } => write!(
                f,
                "channel-bonding donor count {donor_count} exceeds max {max}"
            ),
            Self::NoReceiverEndpoints => {
                f.write_str("channel-bonding donor assignment has no receiver endpoints")
            }
            Self::EmptyAuthKeyRef => {
                f.write_str("channel-bonding donor assignment has an empty auth key reference")
            }
            Self::InvalidEsiWindow {
                start_inclusive,
                end_exclusive,
            } => write!(
                f,
                "invalid channel-bonding ESI window [{start_inclusive}, {end_exclusive})"
            ),
            Self::OverlappingEsiWindows {
                previous_end_exclusive,
                next_start_inclusive,
            } => write!(
                f,
                "overlapping channel-bonding ESI windows: previous ends at {previous_end_exclusive}, next starts at {next_start_inclusive}"
            ),
        }
    }
}

impl std::error::Error for DonorAssignmentError {}

fn validate_esi_windows(windows: &[EsiWindow]) -> Result<(), DonorAssignmentError> {
    for window in windows {
        if !window.is_non_empty() {
            return Err(DonorAssignmentError::InvalidEsiWindow {
                start_inclusive: window.start_inclusive,
                end_exclusive: window.end_exclusive,
            });
        }
    }

    let mut sorted = windows.to_vec();
    sorted.sort_unstable();
    for pair in sorted.windows(2) {
        let previous = pair[0];
        let next = pair[1];
        if previous.end_exclusive > next.start_inclusive {
            return Err(DonorAssignmentError::OverlappingEsiWindows {
                previous_end_exclusive: previous.end_exclusive,
                next_start_inclusive: next.start_inclusive,
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::SecurityContext;
    use crate::types::{SymbolId, SymbolKind};

    fn endpoint() -> SocketAddr {
        "127.0.0.1:8472".parse().expect("test endpoint")
    }

    fn symbol() -> Symbol {
        Symbol::new(
            SymbolId::new_for_test(7, 0, 4),
            b"bonded-symbol".to_vec(),
            SymbolKind::Repair,
        )
    }

    #[test]
    fn static_assignment_uses_a2_residue_partition() {
        let assignment = DonorAssignment::new_static(
            1,
            3,
            vec![endpoint()],
            Some(BondAuthKeyRef::ControlPlane("bond-key-1".to_string())),
        );
        assignment.validate().expect("valid assignment");

        assert!(assignment.owns_esi(1));
        assert!(assignment.owns_esi(4));
        assert!(!assignment.owns_esi(2));
        assert!(assignment.requires_symbol_auth());
    }

    #[test]
    fn explicit_windows_override_static_residue() {
        let assignment = DonorAssignment::new_windowed(
            1,
            3,
            vec![EsiWindow::new(10, 12)],
            vec![endpoint()],
            None,
        );
        assignment.validate().expect("valid windowed assignment");

        assert!(!assignment.owns_esi(1), "windowed assignments override residue");
        assert!(assignment.owns_esi(10));
        assert!(assignment.owns_esi(11));
        assert!(!assignment.owns_esi(12));
    }

    #[test]
    fn invalid_assignment_shapes_fail_closed() {
        let no_endpoint = DonorAssignment::new_static(0, 1, Vec::new(), None);
        assert!(matches!(
            no_endpoint.validate(),
            Err(DonorAssignmentError::NoReceiverEndpoints)
        ));

        let bad_index = DonorAssignment::new_static(3, 3, vec![endpoint()], None);
        assert!(matches!(
            bad_index.validate(),
            Err(DonorAssignmentError::InvalidPartition(
                EsiPartitionError::DonorIndexOutOfRange { .. }
            ))
        ));

        let overlapping = DonorAssignment::new_windowed(
            0,
            1,
            vec![EsiWindow::new(4, 9), EsiWindow::new(8, 10)],
            vec![endpoint()],
            None,
        );
        assert!(matches!(
            overlapping.validate(),
            Err(DonorAssignmentError::OverlappingEsiWindows { .. })
        ));

        let empty_key = DonorAssignment::new_static(
            0,
            1,
            vec![endpoint()],
            Some(BondAuthKeyRef::EnvVar(" ".to_string())),
        );
        assert!(matches!(
            empty_key.validate(),
            Err(DonorAssignmentError::EmptyAuthKeyRef)
        ));
    }

    #[test]
    fn bonded_symbol_auth_accepts_only_verified_tags() {
        let ctx = SecurityContext::for_testing(9);
        let other = SecurityContext::for_testing(10);
        let symbol = symbol();
        let good_tag = *ctx.sign_symbol(&symbol).tag();
        let bad_tag = *other.sign_symbol(&symbol).tag();

        assert!(matches!(
            verify_bonded_symbol_tag(&ctx, &symbol, Some(good_tag)),
            BondedSymbolAuthVerdict::Accepted(_)
        ));
        assert_eq!(
            verify_bonded_symbol_tag(&ctx, &symbol, Some(bad_tag)),
            BondedSymbolAuthVerdict::Rejected(BondedSymbolRejectReason::InvalidTag)
        );
        assert_eq!(
            verify_bonded_symbol_tag(&ctx, &symbol, Some(AuthenticationTag::zero())),
            BondedSymbolAuthVerdict::Rejected(BondedSymbolRejectReason::ZeroTag)
        );
        assert_eq!(
            verify_bonded_symbol_tag(&ctx, &symbol, None),
            BondedSymbolAuthVerdict::Rejected(BondedSymbolRejectReason::MissingTag)
        );
    }
}
