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

use super::descriptor::{BondEntryBlockGeometry, BondProofError, BondTransferDescriptor};
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
            .is_ok_and(|partition| partition.owns_esi(esi))
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

/// Donor-local spray plan for one bonded transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BondedDonorSpraySchedule {
    /// Zero-based donor index.
    pub donor_index: u32,
    /// Total donors in the schedule.
    pub donor_count: u32,
    /// Per-entry/source-block ESI assignments for this donor.
    pub blocks: Vec<BondedBlockSpraySchedule>,
}

impl BondedDonorSpraySchedule {
    /// Count all source symbols this donor should spray.
    #[must_use]
    pub fn source_symbol_count(&self) -> usize {
        self.blocks
            .iter()
            .map(|block| block.source_esis.len())
            .sum()
    }

    /// Count all repair symbols this donor should spray for the configured budget.
    #[must_use]
    pub fn repair_symbol_count(&self) -> usize {
        self.blocks
            .iter()
            .map(|block| block.repair_esis.len())
            .sum()
    }

    /// Count source + repair symbols this donor should spray.
    #[must_use]
    pub fn total_symbol_count(&self) -> usize {
        self.source_symbol_count() + self.repair_symbol_count()
    }

    /// Return true when every non-empty descriptor block gave this donor at least
    /// one source or repair symbol under the configured assignment.
    #[must_use]
    pub fn covers_every_block(&self) -> bool {
        self.blocks.iter().all(|block| !block.is_empty())
    }
}

/// Per-source-block ESI assignment for one donor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BondedBlockSpraySchedule {
    /// Descriptor-agreed RaptorQ identity and source-block geometry.
    pub geometry: BondEntryBlockGeometry,
    /// Systematic/source ESIs owned by this donor (`esi < K`).
    pub source_esis: Vec<u32>,
    /// Repair/FEC ESIs owned by this donor for the configured repair budget.
    pub repair_esis: Vec<u32>,
    /// Donor-local timing stagger slots. This does not change ESI ownership; it
    /// lets B3 smooth the first burst by delaying donor `i` by `i` slots.
    pub stagger_delay_slots: u32,
}

impl BondedBlockSpraySchedule {
    /// Return true when this donor has no work for this source block.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.source_esis.is_empty() && self.repair_esis.is_empty()
    }

    /// Return all ESIs in emission order: source first, then repair.
    #[must_use]
    pub fn ordered_esis(&self) -> Vec<u32> {
        let mut esis = Vec::with_capacity(self.source_esis.len() + self.repair_esis.len());
        esis.extend_from_slice(&self.source_esis);
        esis.extend_from_slice(&self.repair_esis);
        esis
    }
}

/// Scheduler construction errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BondScheduleError {
    /// The donor assignment is invalid.
    InvalidAssignment(DonorAssignmentError),
    /// The shared transfer descriptor is invalid.
    InvalidDescriptor(BondProofError),
    /// Repair ESI budget overflowed the `u32` ESI space.
    RepairBudgetOverflow {
        /// Descriptor entry index.
        entry_index: u32,
        /// Source block number within the entry.
        source_block_number: u8,
        /// First repair ESI (`K`).
        source_symbols: u16,
        /// Requested repair symbols for this block.
        repair_symbols: u32,
    },
}

impl fmt::Display for BondScheduleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAssignment(err) => write!(f, "{err}"),
            Self::InvalidDescriptor(err) => write!(f, "{err}"),
            Self::RepairBudgetOverflow {
                entry_index,
                source_block_number,
                source_symbols,
                repair_symbols,
            } => write!(
                f,
                "channel-bonding repair schedule overflow for entry {entry_index} block {source_block_number}: K={source_symbols}, repair={repair_symbols}"
            ),
        }
    }
}

impl std::error::Error for BondScheduleError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidAssignment(err) => Some(err),
            Self::InvalidDescriptor(err) => Some(err),
            Self::RepairBudgetOverflow { .. } => None,
        }
    }
}

/// Build the deterministic donor-side symbol schedule for a descriptor.
///
/// This is the pure scheduler B1 needs before it calls into the existing RQ
/// encoder: every returned ESI is owned by `assignment`, source ESIs remain
/// source-first for the receiver's memcpy path, and repair ESIs start at `K`.
/// The function is control-plane only; it does not encode or transmit symbols.
pub fn schedule_bonded_donor_spray(
    descriptor: &BondTransferDescriptor,
    assignment: &DonorAssignment,
    repair_symbols_per_block: u32,
) -> Result<BondedDonorSpraySchedule, BondScheduleError> {
    assignment
        .validate()
        .map_err(BondScheduleError::InvalidAssignment)?;
    descriptor
        .validate()
        .map_err(BondScheduleError::InvalidDescriptor)?;

    let mut blocks = Vec::new();
    for entry in &descriptor.entries {
        let Some(source_block_count) = descriptor.entry_source_block_count(entry.index) else {
            continue;
        };
        for source_block_number in 0..source_block_count {
            let Ok(source_block_number) = u8::try_from(source_block_number) else {
                continue;
            };
            let Some(geometry) = descriptor.entry_block_geometry(entry.index, source_block_number)
            else {
                continue;
            };
            blocks.push(schedule_block(
                assignment,
                geometry,
                repair_symbols_per_block,
            )?);
        }
    }

    Ok(BondedDonorSpraySchedule {
        donor_index: assignment.donor_index,
        donor_count: assignment.donor_count,
        blocks,
    })
}

fn schedule_block(
    assignment: &DonorAssignment,
    geometry: BondEntryBlockGeometry,
    repair_symbols_per_block: u32,
) -> Result<BondedBlockSpraySchedule, BondScheduleError> {
    let source_symbols = u32::from(geometry.source_symbols);
    let repair_start = source_symbols;
    let repair_end = repair_start
        .checked_add(repair_symbols_per_block)
        .ok_or_else(|| BondScheduleError::RepairBudgetOverflow {
            entry_index: geometry.entry_index,
            source_block_number: geometry.source_block_number,
            source_symbols: geometry.source_symbols,
            repair_symbols: repair_symbols_per_block,
        })?;

    let source_esis = (0..source_symbols)
        .filter(|esi| assignment.owns_esi(*esi))
        .collect();
    let repair_esis = (repair_start..repair_end)
        .filter(|esi| assignment.owns_esi(*esi))
        .collect();

    Ok(BondedBlockSpraySchedule {
        geometry,
        source_esis,
        repair_esis,
        stagger_delay_slots: assignment.donor_index,
    })
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
                write!(
                    f,
                    "unsupported channel-bonding assignment version {version}"
                )
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
    use super::super::descriptor::{BondEntry, BondTransferDescriptor};
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

    fn descriptor() -> BondTransferDescriptor {
        BondTransferDescriptor {
            transfer_id: "bond-schedule-transfer".to_string(),
            root_name: "root".to_string(),
            is_directory: false,
            total_bytes: 13,
            merkle_root_hex: "schedule-root".to_string(),
            entries: vec![BondEntry {
                index: 0,
                rel_path: "payload.bin".to_string(),
                size: 13,
                sha256_hex: "00".repeat(32),
            }],
            symbol_size: 4,
            max_block_size: 8,
            auth_key_id: Some("key-1".to_string()),
        }
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

        assert!(
            !assignment.owns_esi(1),
            "windowed assignments override residue"
        );
        assert!(assignment.owns_esi(10));
        assert!(assignment.owns_esi(11));
        assert!(!assignment.owns_esi(12));
    }

    #[test]
    fn donor_spray_schedule_partitions_source_and_repair_esis() {
        let descriptor = descriptor();
        let donor0 = DonorAssignment::new_static(0, 2, vec![endpoint()], None);
        let donor1 = DonorAssignment::new_static(1, 2, vec![endpoint()], None);

        let schedule0 =
            schedule_bonded_donor_spray(&descriptor, &donor0, 4).expect("donor 0 schedule");
        let schedule1 =
            schedule_bonded_donor_spray(&descriptor, &donor1, 4).expect("donor 1 schedule");

        assert_eq!(schedule0.blocks.len(), 2);
        assert_eq!(schedule1.blocks.len(), 2);
        assert!(schedule0.covers_every_block());
        assert!(schedule1.covers_every_block());
        assert_eq!(
            schedule0.total_symbol_count() + schedule1.total_symbol_count(),
            12
        );

        for (left, right) in schedule0.blocks.iter().zip(&schedule1.blocks) {
            assert_eq!(left.geometry, right.geometry);
            let left_esis = left.ordered_esis();
            let right_esis = right.ordered_esis();
            let mut combined = left_esis.clone();
            combined.extend_from_slice(&right_esis);
            combined.sort_unstable();
            combined.dedup();
            assert_eq!(
                combined,
                vec![0, 1, 2, 3, 4, 5],
                "two donors cover source ESIs 0..K and four repair ESIs"
            );

            for esi in left_esis {
                assert!(!right_esis.contains(&esi));
                assert_eq!(esi % 2, 0);
            }
            for esi in right_esis {
                assert_eq!(esi % 2, 1);
            }
        }
    }

    #[test]
    fn donor_count_one_schedule_is_single_source_isomorphic() {
        let descriptor = descriptor();
        let assignment = DonorAssignment::new_static(0, 1, vec![endpoint()], None);

        let schedule = schedule_bonded_donor_spray(&descriptor, &assignment, 3).expect("schedule");

        assert_eq!(schedule.blocks.len(), 2);
        assert_eq!(schedule.blocks[0].source_esis, vec![0, 1]);
        assert_eq!(schedule.blocks[0].repair_esis, vec![2, 3, 4]);
        assert_eq!(schedule.blocks[1].source_esis, vec![0, 1]);
        assert_eq!(schedule.blocks[1].repair_esis, vec![2, 3, 4]);
        assert_eq!(schedule.total_symbol_count(), 10);
    }

    #[test]
    fn windowed_schedule_overrides_residue_and_keeps_source_first() {
        let descriptor = descriptor();
        let assignment = DonorAssignment::new_windowed(
            1,
            3,
            vec![EsiWindow::new(0, 2), EsiWindow::new(4, 5)],
            vec![endpoint()],
            None,
        );

        let schedule = schedule_bonded_donor_spray(&descriptor, &assignment, 4).expect("schedule");

        assert_eq!(schedule.blocks[0].source_esis, vec![0, 1]);
        assert_eq!(schedule.blocks[0].repair_esis, vec![4]);
        assert_eq!(schedule.blocks[0].ordered_esis(), vec![0, 1, 4]);
        assert_eq!(schedule.blocks[0].stagger_delay_slots, 1);
    }

    #[test]
    fn spray_schedule_fails_closed_for_invalid_inputs() {
        let descriptor = descriptor();
        let invalid_assignment = DonorAssignment::new_static(2, 2, vec![endpoint()], None);
        assert!(matches!(
            schedule_bonded_donor_spray(&descriptor, &invalid_assignment, 1),
            Err(BondScheduleError::InvalidAssignment(
                DonorAssignmentError::InvalidPartition(
                    EsiPartitionError::DonorIndexOutOfRange { .. }
                )
            ))
        ));

        let mut bad_descriptor = descriptor();
        bad_descriptor.total_bytes += 1;
        let assignment = DonorAssignment::new_static(0, 1, vec![endpoint()], None);
        assert!(matches!(
            schedule_bonded_donor_spray(&bad_descriptor, &assignment, 1),
            Err(BondScheduleError::InvalidDescriptor(
                BondProofError::TotalBytesMismatch { .. }
            ))
        ));
    }

    #[test]
    fn spray_schedule_rejects_repair_budget_overflow() {
        let descriptor = descriptor();
        let assignment = DonorAssignment::new_static(0, 1, vec![endpoint()], None);

        let err = schedule_bonded_donor_spray(&descriptor, &assignment, u32::MAX)
            .expect_err("overflowing repair ESI budget must fail closed");

        assert_eq!(
            err,
            BondScheduleError::RepairBudgetOverflow {
                entry_index: 0,
                source_block_number: 0,
                source_symbols: 2,
                repair_symbols: u32::MAX,
            }
        );
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
