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
use std::{collections::BTreeSet, net::SocketAddr};

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
    /// Materialize the donor's exact symbol-emission stream in transport order.
    ///
    /// This is the B1 handoff to the data path: callers can iterate one flat
    /// stream and encode `(entry, source block, esi)` without re-running residue
    /// ownership decisions. Source ESIs are always listed before repair ESIs for
    /// each block so the receiver's source-first fast path stays available.
    #[must_use]
    pub fn symbol_emissions(&self) -> Vec<BondedDonorSymbolEmission> {
        self.blocks
            .iter()
            .flat_map(|block| block.symbol_emissions(self.donor_index))
            .collect()
    }

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

/// One `(entry, source block, esi)` that a bonded donor should encode and emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BondedDonorSymbolEmission {
    /// Donor that owns this symbol under the active assignment.
    pub donor_index: u32,
    /// Descriptor-agreed RaptorQ identity and source-block geometry.
    pub geometry: BondEntryBlockGeometry,
    /// Encoding symbol id to emit.
    pub esi: u32,
    /// Whether this ESI is a systematic source or repair symbol.
    pub kind: BondedDonorSymbolKind,
    /// Donor-local stagger slot to preserve B1/B3 pacing order.
    pub stagger_delay_slots: u32,
}

/// Scheduled bonded symbol kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BondedDonorSymbolKind {
    /// Systematic source symbol (`esi < K`).
    Source,
    /// Repair/FEC symbol (`esi >= K`).
    Repair,
}

/// Collective source-range coverage for a bonded transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BondedSourceFirstCoverage {
    /// Number of donor assignments included in the report.
    pub assignment_count: usize,
    /// Per-entry/source-block source ESI coverage.
    pub blocks: Vec<BondedBlockSourceFirstCoverage>,
}

impl BondedSourceFirstCoverage {
    /// True when every block has every source ESI covered exactly once.
    #[must_use]
    pub fn is_source_complete_exactly_once(&self) -> bool {
        self.blocks
            .iter()
            .all(BondedBlockSourceFirstCoverage::is_source_complete_exactly_once)
    }
}

/// Per-block aggregate source ESI coverage across all donors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BondedBlockSourceFirstCoverage {
    /// Descriptor-agreed RaptorQ identity and source-block geometry.
    pub geometry: BondEntryBlockGeometry,
    /// Per-donor source range ownership for this block.
    pub donors: Vec<BondedDonorSourceFirstCoverage>,
    /// Source ESIs not covered by any donor assignment.
    pub missing_source_esis: Vec<u32>,
    /// Source ESIs covered by more than one donor assignment.
    pub duplicate_source_esis: Vec<u32>,
}

impl BondedBlockSourceFirstCoverage {
    /// True when this block can complete from source symbols without decode.
    #[must_use]
    pub fn is_source_complete_exactly_once(&self) -> bool {
        self.missing_source_esis.is_empty() && self.duplicate_source_esis.is_empty()
    }

    /// Count all donor-owned source ESIs for this block.
    #[must_use]
    pub fn scheduled_source_symbol_count(&self) -> usize {
        self.donors
            .iter()
            .map(|donor| donor.source_esis.len())
            .sum()
    }
}

/// One donor's source-first work for a single source block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BondedDonorSourceFirstCoverage {
    /// Zero-based donor index.
    pub donor_index: u32,
    /// Systematic/source ESIs owned by this donor (`esi < K`).
    pub source_esis: Vec<u32>,
    /// First repair ESI this donor owns after the source range, if known.
    pub first_repair_esi: Option<u32>,
    /// Same donor-local timing stagger as the spray schedule.
    pub stagger_delay_slots: u32,
}

/// Receiver-observed donor weight for dynamic repair-window allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BondedDonorWindowWeight {
    /// Zero-based donor index.
    pub donor_index: u32,
    /// Relative allocation weight, normally derived from observed goodput.
    pub weight: u32,
}

/// One donor's dynamic receiver-allocated repair window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BondedDonorRepairWindow {
    /// Zero-based donor index.
    pub donor_index: u32,
    /// Half-open repair ESI window assigned to this donor.
    pub esi_window: EsiWindow,
    /// Number of repair symbols in `esi_window`.
    pub symbol_count: u32,
    /// Compact timing stagger slot for this allocation round.
    pub stagger_delay_slots: u32,
}

/// Disjoint dynamic repair windows for one source block and feedback round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BondedRepairWindowPlan {
    /// Descriptor-agreed RaptorQ identity and source-block geometry.
    pub geometry: BondEntryBlockGeometry,
    /// First repair ESI considered for this allocation round.
    pub first_repair_esi: u32,
    /// First unallocated repair ESI after all windows.
    pub next_repair_esi: u32,
    /// Per-donor disjoint windows, sorted by donor index.
    pub windows: Vec<BondedDonorRepairWindow>,
}

impl BondedRepairWindowPlan {
    /// True when every allocated window is non-empty and strictly disjoint.
    #[must_use]
    pub fn windows_are_disjoint(&self) -> bool {
        self.windows.iter().all(|window| {
            window.esi_window.is_non_empty()
                && window
                    .esi_window
                    .end_exclusive
                    .checked_sub(window.esi_window.start_inclusive)
                    == Some(window.symbol_count)
        }) && self
            .windows
            .windows(2)
            .all(|pair| pair[0].esi_window.end_exclusive <= pair[1].esi_window.start_inclusive)
    }

    /// Total repair symbols allocated across all donors.
    #[must_use]
    pub fn allocated_symbol_count(&self) -> u32 {
        self.windows.iter().map(|window| window.symbol_count).sum()
    }
}

/// A receiver-allocated repair window materialized as a donor assignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BondedDonorRepairWindowAssignment {
    /// Zero-based donor index.
    pub donor_index: u32,
    /// Explicit-window assignment to send to this donor for the repair round.
    pub assignment: DonorAssignment,
    /// Repair window that produced `assignment.esi_windows`.
    pub repair_window: BondedDonorRepairWindow,
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
    /// First repair ESI candidate after this initial spray window.
    ///
    /// B3 donor-control loops use this cursor when a receiver sends `NeedMore`:
    /// continue from here, filter through the same donor assignment, and never
    /// re-emit a repair ESI already present in `repair_esis`.
    pub next_repair_esi: u32,
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

    /// Materialize this block's donor-owned symbols in source-first order.
    #[must_use]
    pub fn symbol_emissions(&self, donor_index: u32) -> Vec<BondedDonorSymbolEmission> {
        let mut emissions = Vec::with_capacity(self.source_esis.len() + self.repair_esis.len());
        emissions.extend(
            self.source_esis
                .iter()
                .copied()
                .map(|esi| BondedDonorSymbolEmission {
                    donor_index,
                    geometry: self.geometry,
                    esi,
                    kind: BondedDonorSymbolKind::Source,
                    stagger_delay_slots: self.stagger_delay_slots,
                }),
        );
        emissions.extend(
            self.repair_esis
                .iter()
                .copied()
                .map(|esi| BondedDonorSymbolEmission {
                    donor_index,
                    geometry: self.geometry,
                    esi,
                    kind: BondedDonorSymbolKind::Repair,
                    stagger_delay_slots: self.stagger_delay_slots,
                }),
        );
        emissions
    }

    /// Build a B3 continuation batch for this block after the initial spray.
    pub fn repair_continuation(
        &self,
        assignment: &DonorAssignment,
        requested_symbols: usize,
    ) -> Result<BondedBlockRepairSchedule, BondScheduleError> {
        schedule_bonded_repair_continuation(
            assignment,
            self.geometry,
            self.next_repair_esi,
            requested_symbols,
        )
    }
}

/// Donor-local continuation plan for one block after receiver `NeedMore`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BondedBlockRepairSchedule {
    /// Descriptor-agreed RaptorQ identity and source-block geometry.
    pub geometry: BondEntryBlockGeometry,
    /// Repair ESIs owned by this donor for the requested continuation batch.
    pub repair_esis: Vec<u32>,
    /// First repair ESI candidate after this continuation batch.
    pub next_repair_esi: u32,
    /// Same donor-local timing stagger as the initial block schedule.
    pub stagger_delay_slots: u32,
}

/// Scheduler construction errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BondScheduleError {
    /// The donor assignment is invalid.
    InvalidAssignment(DonorAssignmentError),
    /// The shared transfer descriptor is invalid.
    InvalidDescriptor(BondProofError),
    /// A collective schedule needs at least one donor assignment.
    NoDonorAssignments,
    /// All donors must agree on the same donor-count geometry.
    InconsistentDonorCount {
        /// Donor count from the first assignment.
        expected: u32,
        /// Donor count from a later assignment.
        actual: u32,
    },
    /// The same donor index appeared more than once in one collective schedule.
    DuplicateDonorAssignment {
        /// Reused donor index.
        donor_index: u32,
    },
    /// Dynamic window allocation needs at least one positive donor weight.
    ZeroWindowWeightSum,
    /// A dynamic repair window allocation exceeded the `u32` ESI space.
    RepairWindowAllocationOverflow {
        /// Descriptor entry index.
        entry_index: u32,
        /// Source block number within the entry.
        source_block_number: u8,
        /// First repair ESI candidate for this allocation.
        first_repair_esi: u32,
        /// Requested aggregate repair symbols.
        requested_symbols: u32,
    },
    /// Failed-donor reallocation exceeded the `u32` repair-symbol budget.
    FailedDonorRepairBudgetOverflow {
        /// Failed donor whose window would overflow the aggregate budget.
        donor_index: u32,
        /// Repair symbols already accumulated from earlier failed donors.
        accumulated_symbols: u32,
        /// Repair symbols from this failed donor's outstanding window.
        added_symbols: u32,
    },
    /// A failed donor was named for reallocation but had no outstanding window.
    MissingFailedDonorWindow {
        /// Failed donor index with no matching outstanding window.
        donor_index: u32,
    },
    /// A repair window names a donor that is not in the enrolled assignment set.
    MissingDonorAssignment {
        /// Donor index named by the repair window.
        donor_index: u32,
    },
    /// A repair window is empty or its symbol count does not match its ESI range.
    InvalidRepairWindow {
        /// Donor index named by the repair window.
        donor_index: u32,
        /// First included ESI.
        start_inclusive: u32,
        /// First excluded ESI.
        end_exclusive: u32,
        /// Advertised number of repair symbols.
        symbol_count: u32,
    },
    /// A repair window starts before the plan's declared repair cursor.
    RepairWindowBeforeFirstRepair {
        /// Donor index named by the repair window.
        donor_index: u32,
        /// First included ESI.
        start_inclusive: u32,
        /// First repair ESI allowed by the plan.
        first_repair_esi: u32,
    },
    /// Two receiver-allocated repair windows overlap.
    OverlappingRepairWindows {
        /// Donor index for the earlier window.
        previous_donor_index: u32,
        /// Donor index for the later overlapping window.
        next_donor_index: u32,
        /// End of the earlier window.
        previous_end_exclusive: u32,
        /// Start of the later overlapping window.
        next_start_inclusive: u32,
    },
    /// The plan's continuation cursor would re-enter an allocated window.
    RepairWindowCursorBeforeWindowEnd {
        /// Advertised next repair ESI after this plan.
        next_repair_esi: u32,
        /// Highest exclusive end across allocated windows.
        window_end_exclusive: u32,
    },
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
    /// A repair continuation must start at or beyond `K`.
    RepairStartBeforeSource {
        /// Descriptor entry index.
        entry_index: u32,
        /// Source block number within the entry.
        source_block_number: u8,
        /// First repair ESI (`K`).
        source_symbols: u16,
        /// Requested first continuation candidate.
        first_repair_esi: u32,
    },
    /// The continuation cursor exceeded the `u32` ESI space.
    RepairContinuationOverflow {
        /// Descriptor entry index.
        entry_index: u32,
        /// Source block number within the entry.
        source_block_number: u8,
        /// First repair ESI candidate for this continuation.
        first_repair_esi: u32,
        /// Donor-owned repair symbols requested.
        requested_symbols: usize,
    },
    /// A finite explicit window assignment cannot satisfy the requested deficit.
    InsufficientRepairWindow {
        /// Descriptor entry index.
        entry_index: u32,
        /// Source block number within the entry.
        source_block_number: u8,
        /// Donor-owned repair symbols requested.
        requested_symbols: usize,
        /// Symbols covered by the explicit windows.
        scheduled_symbols: usize,
    },
}

impl fmt::Display for BondScheduleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAssignment(err) => write!(f, "{err}"),
            Self::InvalidDescriptor(err) => write!(f, "{err}"),
            Self::NoDonorAssignments => {
                f.write_str("channel-bonding source coverage needs at least one donor assignment")
            }
            Self::InconsistentDonorCount { expected, actual } => write!(
                f,
                "channel-bonding donor count mismatch in collective schedule: expected {expected}, got {actual}"
            ),
            Self::DuplicateDonorAssignment { donor_index } => write!(
                f,
                "channel-bonding collective schedule has duplicate donor assignment {donor_index}"
            ),
            Self::ZeroWindowWeightSum => f.write_str(
                "channel-bonding dynamic repair window allocation has zero total donor weight",
            ),
            Self::RepairWindowAllocationOverflow {
                entry_index,
                source_block_number,
                first_repair_esi,
                requested_symbols,
            } => write!(
                f,
                "channel-bonding dynamic repair window allocation overflow for entry {entry_index} block {source_block_number}: first_repair_esi={first_repair_esi}, requested={requested_symbols}"
            ),
            Self::FailedDonorRepairBudgetOverflow {
                donor_index,
                accumulated_symbols,
                added_symbols,
            } => write!(
                f,
                "channel-bonding failed-donor repair budget overflow at donor {donor_index}: accumulated={accumulated_symbols}, added={added_symbols}"
            ),
            Self::MissingFailedDonorWindow { donor_index } => write!(
                f,
                "channel-bonding failed donor {donor_index} had no outstanding repair window to reallocate"
            ),
            Self::MissingDonorAssignment { donor_index } => write!(
                f,
                "channel-bonding repair window names unenrolled donor {donor_index}"
            ),
            Self::InvalidRepairWindow {
                donor_index,
                start_inclusive,
                end_exclusive,
                symbol_count,
            } => write!(
                f,
                "channel-bonding repair window for donor {donor_index} is invalid: range=[{start_inclusive},{end_exclusive}), symbols={symbol_count}"
            ),
            Self::RepairWindowBeforeFirstRepair {
                donor_index,
                start_inclusive,
                first_repair_esi,
            } => write!(
                f,
                "channel-bonding repair window for donor {donor_index} starts at {start_inclusive}, before plan first repair ESI {first_repair_esi}"
            ),
            Self::OverlappingRepairWindows {
                previous_donor_index,
                next_donor_index,
                previous_end_exclusive,
                next_start_inclusive,
            } => write!(
                f,
                "channel-bonding repair windows overlap: donor {previous_donor_index} ends at {previous_end_exclusive}, donor {next_donor_index} starts at {next_start_inclusive}"
            ),
            Self::RepairWindowCursorBeforeWindowEnd {
                next_repair_esi,
                window_end_exclusive,
            } => write!(
                f,
                "channel-bonding repair window cursor {next_repair_esi} is before allocated window end {window_end_exclusive}"
            ),
            Self::RepairBudgetOverflow {
                entry_index,
                source_block_number,
                source_symbols,
                repair_symbols,
            } => write!(
                f,
                "channel-bonding repair schedule overflow for entry {entry_index} block {source_block_number}: K={source_symbols}, repair={repair_symbols}"
            ),
            Self::RepairStartBeforeSource {
                entry_index,
                source_block_number,
                source_symbols,
                first_repair_esi,
            } => write!(
                f,
                "channel-bonding repair continuation for entry {entry_index} block {source_block_number} starts at ESI {first_repair_esi}, before K={source_symbols}"
            ),
            Self::RepairContinuationOverflow {
                entry_index,
                source_block_number,
                first_repair_esi,
                requested_symbols,
            } => write!(
                f,
                "channel-bonding repair continuation overflow for entry {entry_index} block {source_block_number}: first_repair_esi={first_repair_esi}, requested={requested_symbols}"
            ),
            Self::InsufficientRepairWindow {
                entry_index,
                source_block_number,
                requested_symbols,
                scheduled_symbols,
            } => write!(
                f,
                "channel-bonding explicit repair windows for entry {entry_index} block {source_block_number} scheduled {scheduled_symbols}/{requested_symbols} requested symbols"
            ),
        }
    }
}

impl std::error::Error for BondScheduleError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidAssignment(err) => Some(err),
            Self::InvalidDescriptor(err) => Some(err),
            Self::NoDonorAssignments
            | Self::InconsistentDonorCount { .. }
            | Self::DuplicateDonorAssignment { .. }
            | Self::ZeroWindowWeightSum
            | Self::RepairWindowAllocationOverflow { .. }
            | Self::FailedDonorRepairBudgetOverflow { .. }
            | Self::MissingFailedDonorWindow { .. }
            | Self::MissingDonorAssignment { .. }
            | Self::InvalidRepairWindow { .. }
            | Self::RepairWindowBeforeFirstRepair { .. }
            | Self::OverlappingRepairWindows { .. }
            | Self::RepairWindowCursorBeforeWindowEnd { .. }
            | Self::RepairBudgetOverflow { .. }
            | Self::RepairStartBeforeSource { .. }
            | Self::RepairContinuationOverflow { .. }
            | Self::InsufficientRepairWindow { .. } => None,
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

/// Report collective source-range coverage across a bonded donor set.
///
/// B4 uses this pure scheduler check to keep bonded transfers on the systematic
/// fast path: donors should collectively cover every source ESI (`0..K`) exactly
/// once before spending bandwidth on repair ESIs. The report is intentionally
/// non-transport; later RQ/QUIC paths can consume it to decide whether source
/// retransmit or repair feedback should be preferred.
pub fn schedule_bonded_source_first_coverage(
    descriptor: &BondTransferDescriptor,
    assignments: &[DonorAssignment],
) -> Result<BondedSourceFirstCoverage, BondScheduleError> {
    descriptor
        .validate()
        .map_err(BondScheduleError::InvalidDescriptor)?;
    validate_collective_assignments(assignments)?;

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
            blocks.push(schedule_block_source_first_coverage(assignments, geometry));
        }
    }

    Ok(BondedSourceFirstCoverage {
        assignment_count: assignments.len(),
        blocks,
    })
}

/// Allocate fresh disjoint dynamic repair windows for one feedback round.
///
/// The receiver is the sole allocator, so windows are contiguous above the
/// current high-water mark and cannot overlap. Donor sizes are proportional to
/// `weight`; leftover symbols from integer division go to the largest fractional
/// remainders, then lower donor indexes for deterministic ties.
pub fn allocate_bonded_repair_windows(
    geometry: BondEntryBlockGeometry,
    first_repair_esi: u32,
    requested_symbols: u32,
    donor_weights: &[BondedDonorWindowWeight],
) -> Result<BondedRepairWindowPlan, BondScheduleError> {
    let source_symbols = u32::from(geometry.source_symbols);
    if first_repair_esi < source_symbols {
        return Err(BondScheduleError::RepairStartBeforeSource {
            entry_index: geometry.entry_index,
            source_block_number: geometry.source_block_number,
            source_symbols: geometry.source_symbols,
            first_repair_esi,
        });
    }
    validate_window_weights(donor_weights)?;

    if requested_symbols == 0 {
        return Ok(BondedRepairWindowPlan {
            geometry,
            first_repair_esi,
            next_repair_esi: first_repair_esi,
            windows: Vec::new(),
        });
    }

    let mut donor_weights = donor_weights.to_vec();
    donor_weights.sort_unstable_by_key(|weight| weight.donor_index);
    let symbol_counts = proportional_window_symbol_counts(requested_symbols, &donor_weights)?;

    let mut cursor = first_repair_esi;
    let mut windows = Vec::new();
    let mut stagger_slot = 0u32;
    for (weight, symbol_count) in donor_weights.iter().zip(symbol_counts) {
        if symbol_count == 0 {
            continue;
        }
        let end_exclusive = cursor.checked_add(symbol_count).ok_or(
            BondScheduleError::RepairWindowAllocationOverflow {
                entry_index: geometry.entry_index,
                source_block_number: geometry.source_block_number,
                first_repair_esi,
                requested_symbols,
            },
        )?;
        windows.push(BondedDonorRepairWindow {
            donor_index: weight.donor_index,
            esi_window: EsiWindow::new(cursor, end_exclusive),
            symbol_count,
            stagger_delay_slots: stagger_slot,
        });
        stagger_slot = stagger_slot.saturating_add(1);
        cursor = end_exclusive;
    }

    Ok(BondedRepairWindowPlan {
        geometry,
        first_repair_esi,
        next_repair_esi: cursor,
        windows,
    })
}

/// Reallocate failed donors' outstanding windows to live survivors.
///
/// The replacement windows start at `current_high_water_esi` instead of reusing
/// the failed donors' old ESIs. RaptorQ repair symbols are fungible, so fresh
/// disjoint ESIs avoid duplicates while preserving the failed donors' aggregate
/// repair-symbol budget.
pub fn reallocate_failed_bonded_repair_windows(
    geometry: BondEntryBlockGeometry,
    current_high_water_esi: u32,
    outstanding_windows: &[BondedDonorRepairWindow],
    failed_donor_indices: &[u32],
    survivor_weights: &[BondedDonorWindowWeight],
) -> Result<BondedRepairWindowPlan, BondScheduleError> {
    let mut failed = BTreeSet::new();
    for donor_index in failed_donor_indices {
        failed.insert(*donor_index);
    }

    let mut requested_symbols = 0u32;
    for donor_index in failed {
        let Some(window) = outstanding_windows
            .iter()
            .find(|window| window.donor_index == donor_index)
        else {
            return Err(BondScheduleError::MissingFailedDonorWindow { donor_index });
        };
        validate_repair_window_shape(*window)?;
        requested_symbols = requested_symbols.checked_add(window.symbol_count).ok_or(
            BondScheduleError::FailedDonorRepairBudgetOverflow {
                donor_index,
                accumulated_symbols: requested_symbols,
                added_symbols: window.symbol_count,
            },
        )?;
    }

    allocate_bonded_repair_windows(
        geometry,
        current_high_water_esi,
        requested_symbols,
        survivor_weights,
    )
}

/// Convert receiver-allocated repair windows into explicit donor assignments.
///
/// Dynamic-window repair is receiver-owned: the receiver allocates disjoint ESI
/// windows, then sends each donor an explicit assignment for only its window.
/// Donors with no window are omitted instead of receiving an empty window list,
/// because empty `esi_windows` means static-residue ownership.
pub fn schedule_bonded_repair_window_assignments(
    assignments: &[DonorAssignment],
    plan: &BondedRepairWindowPlan,
) -> Result<Vec<BondedDonorRepairWindowAssignment>, BondScheduleError> {
    validate_collective_assignments(assignments)?;
    validate_repair_window_plan(plan)?;

    let mut assigned_donors = BTreeSet::new();
    let mut windowed = Vec::with_capacity(plan.windows.len());
    for window in &plan.windows {
        if !assigned_donors.insert(window.donor_index) {
            return Err(BondScheduleError::DuplicateDonorAssignment {
                donor_index: window.donor_index,
            });
        }

        let Some(base_assignment) = assignments
            .iter()
            .find(|assignment| assignment.donor_index == window.donor_index)
        else {
            return Err(BondScheduleError::MissingDonorAssignment {
                donor_index: window.donor_index,
            });
        };

        let mut assignment = base_assignment.clone();
        assignment.esi_windows = vec![window.esi_window];
        assignment
            .validate()
            .map_err(BondScheduleError::InvalidAssignment)?;
        windowed.push(BondedDonorRepairWindowAssignment {
            donor_index: window.donor_index,
            assignment,
            repair_window: *window,
        });
    }

    Ok(windowed)
}

/// Continue one block's repair stream for a receiver `NeedMore` deficit.
///
/// `first_repair_esi` is the first global repair ESI candidate to consider.
/// Static-residue assignments jump to this donor's next owned ESI at or after
/// that cursor and then keep advancing by donor count. Explicit windows are
/// finite receiver allocations and must cover the full requested deficit.
pub fn schedule_bonded_repair_continuation(
    assignment: &DonorAssignment,
    geometry: BondEntryBlockGeometry,
    first_repair_esi: u32,
    requested_symbols: usize,
) -> Result<BondedBlockRepairSchedule, BondScheduleError> {
    assignment
        .validate()
        .map_err(BondScheduleError::InvalidAssignment)?;
    let source_symbols = u32::from(geometry.source_symbols);
    if first_repair_esi < source_symbols {
        return Err(BondScheduleError::RepairStartBeforeSource {
            entry_index: geometry.entry_index,
            source_block_number: geometry.source_block_number,
            source_symbols: geometry.source_symbols,
            first_repair_esi,
        });
    }
    if requested_symbols == 0 {
        return Ok(BondedBlockRepairSchedule {
            geometry,
            repair_esis: Vec::new(),
            next_repair_esi: first_repair_esi,
            stagger_delay_slots: assignment.donor_index,
        });
    }

    let (repair_esis, next_repair_esi) = if assignment.esi_windows.is_empty() {
        schedule_static_repair_continuation(
            assignment,
            geometry,
            first_repair_esi,
            requested_symbols,
        )?
    } else {
        schedule_windowed_repair_continuation(
            assignment,
            geometry,
            first_repair_esi,
            requested_symbols,
        )?
    };

    Ok(BondedBlockRepairSchedule {
        geometry,
        repair_esis,
        next_repair_esi,
        stagger_delay_slots: assignment.donor_index,
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
        next_repair_esi: repair_end,
        stagger_delay_slots: assignment.donor_index,
    })
}

fn validate_collective_assignments(
    assignments: &[DonorAssignment],
) -> Result<(), BondScheduleError> {
    let Some(first) = assignments.first() else {
        return Err(BondScheduleError::NoDonorAssignments);
    };
    let expected_donor_count = first.donor_count;
    let mut donor_indices = BTreeSet::new();

    for assignment in assignments {
        assignment
            .validate()
            .map_err(BondScheduleError::InvalidAssignment)?;
        if assignment.donor_count != expected_donor_count {
            return Err(BondScheduleError::InconsistentDonorCount {
                expected: expected_donor_count,
                actual: assignment.donor_count,
            });
        }
        if !donor_indices.insert(assignment.donor_index) {
            return Err(BondScheduleError::DuplicateDonorAssignment {
                donor_index: assignment.donor_index,
            });
        }
    }

    Ok(())
}

fn validate_window_weights(
    donor_weights: &[BondedDonorWindowWeight],
) -> Result<(), BondScheduleError> {
    if donor_weights.is_empty() {
        return Err(BondScheduleError::NoDonorAssignments);
    }
    let mut donor_indices = BTreeSet::new();
    for weight in donor_weights {
        if !donor_indices.insert(weight.donor_index) {
            return Err(BondScheduleError::DuplicateDonorAssignment {
                donor_index: weight.donor_index,
            });
        }
    }
    Ok(())
}

fn validate_repair_window_shape(window: BondedDonorRepairWindow) -> Result<(), BondScheduleError> {
    let window_symbol_count = window
        .esi_window
        .end_exclusive
        .checked_sub(window.esi_window.start_inclusive);
    if !window.esi_window.is_non_empty() || window_symbol_count != Some(window.symbol_count) {
        return Err(BondScheduleError::InvalidRepairWindow {
            donor_index: window.donor_index,
            start_inclusive: window.esi_window.start_inclusive,
            end_exclusive: window.esi_window.end_exclusive,
            symbol_count: window.symbol_count,
        });
    }
    Ok(())
}

fn validate_repair_window_plan(plan: &BondedRepairWindowPlan) -> Result<(), BondScheduleError> {
    if plan.next_repair_esi < plan.first_repair_esi {
        return Err(BondScheduleError::RepairWindowCursorBeforeWindowEnd {
            next_repair_esi: plan.next_repair_esi,
            window_end_exclusive: plan.first_repair_esi,
        });
    }

    let mut windows = plan.windows.clone();
    windows.sort_unstable_by_key(|window| {
        (
            window.esi_window.start_inclusive,
            window.esi_window.end_exclusive,
            window.donor_index,
        )
    });

    let mut previous: Option<BondedDonorRepairWindow> = None;
    let mut highest_end = plan.first_repair_esi;
    for window in windows {
        validate_repair_window_shape(window)?;
        if window.esi_window.start_inclusive < plan.first_repair_esi {
            return Err(BondScheduleError::RepairWindowBeforeFirstRepair {
                donor_index: window.donor_index,
                start_inclusive: window.esi_window.start_inclusive,
                first_repair_esi: plan.first_repair_esi,
            });
        }
        if let Some(previous_window) = previous {
            if previous_window.esi_window.end_exclusive > window.esi_window.start_inclusive {
                return Err(BondScheduleError::OverlappingRepairWindows {
                    previous_donor_index: previous_window.donor_index,
                    next_donor_index: window.donor_index,
                    previous_end_exclusive: previous_window.esi_window.end_exclusive,
                    next_start_inclusive: window.esi_window.start_inclusive,
                });
            }
        }
        highest_end = highest_end.max(window.esi_window.end_exclusive);
        previous = Some(window);
    }

    if plan.next_repair_esi < highest_end {
        return Err(BondScheduleError::RepairWindowCursorBeforeWindowEnd {
            next_repair_esi: plan.next_repair_esi,
            window_end_exclusive: highest_end,
        });
    }

    Ok(())
}

fn proportional_window_symbol_counts(
    requested_symbols: u32,
    donor_weights: &[BondedDonorWindowWeight],
) -> Result<Vec<u32>, BondScheduleError> {
    let total_weight = donor_weights
        .iter()
        .map(|weight| u64::from(weight.weight))
        .sum::<u64>();
    if total_weight == 0 {
        return Err(BondScheduleError::ZeroWindowWeightSum);
    }

    let requested = u64::from(requested_symbols);
    let mut counts = Vec::with_capacity(donor_weights.len());
    let mut remainders = Vec::with_capacity(donor_weights.len());
    let mut allocated = 0u32;

    for (position, weight) in donor_weights.iter().enumerate() {
        let numerator = requested.saturating_mul(u64::from(weight.weight));
        let base = numerator / total_weight;
        let count = u32::try_from(base).unwrap_or(u32::MAX);
        allocated = allocated.saturating_add(count);
        counts.push(count);
        remainders.push((numerator % total_weight, weight.donor_index, position));
    }

    let mut remaining = requested_symbols.saturating_sub(allocated);
    remainders.sort_unstable_by(|left, right| {
        right
            .0
            .cmp(&left.0)
            .then_with(|| left.1.cmp(&right.1))
            .then_with(|| left.2.cmp(&right.2))
    });
    for (_, _, position) in remainders {
        if remaining == 0 {
            break;
        }
        counts[position] = counts[position].saturating_add(1);
        remaining -= 1;
    }

    Ok(counts)
}

fn schedule_block_source_first_coverage(
    assignments: &[DonorAssignment],
    geometry: BondEntryBlockGeometry,
) -> BondedBlockSourceFirstCoverage {
    let source_symbol_count = usize::from(geometry.source_symbols);
    let mut coverage_counts = vec![0u16; source_symbol_count];
    let mut donors = Vec::with_capacity(assignments.len());

    for assignment in assignments {
        let source_esis: Vec<u32> = (0..u32::from(geometry.source_symbols))
            .filter(|esi| assignment.owns_esi(*esi))
            .collect();
        for esi in &source_esis {
            let slot = &mut coverage_counts[*esi as usize];
            *slot = slot.saturating_add(1);
        }
        donors.push(BondedDonorSourceFirstCoverage {
            donor_index: assignment.donor_index,
            source_esis,
            first_repair_esi: first_assigned_repair_esi_at_or_after(
                assignment,
                u32::from(geometry.source_symbols),
            ),
            stagger_delay_slots: assignment.donor_index,
        });
    }

    let mut missing_source_esis = Vec::new();
    let mut duplicate_source_esis = Vec::new();
    for (esi, count) in coverage_counts.into_iter().enumerate() {
        if count == 0 {
            missing_source_esis.push(esi as u32);
        } else if count > 1 {
            duplicate_source_esis.push(esi as u32);
        }
    }

    BondedBlockSourceFirstCoverage {
        geometry,
        donors,
        missing_source_esis,
        duplicate_source_esis,
    }
}

fn first_assigned_repair_esi_at_or_after(
    assignment: &DonorAssignment,
    first_repair_esi: u32,
) -> Option<u32> {
    if assignment.esi_windows.is_empty() {
        return first_static_owned_esi_at_or_after(assignment, first_repair_esi);
    }

    assignment
        .esi_windows
        .iter()
        .filter(|window| window.end_exclusive > first_repair_esi)
        .map(|window| window.start_inclusive.max(first_repair_esi))
        .min()
}

fn schedule_static_repair_continuation(
    assignment: &DonorAssignment,
    geometry: BondEntryBlockGeometry,
    first_repair_esi: u32,
    requested_symbols: usize,
) -> Result<(Vec<u32>, u32), BondScheduleError> {
    let mut repair_esis = Vec::with_capacity(requested_symbols);
    let Some(mut next_repair_esi) =
        first_static_owned_esi_at_or_after(assignment, first_repair_esi)
    else {
        return Err(BondScheduleError::RepairContinuationOverflow {
            entry_index: geometry.entry_index,
            source_block_number: geometry.source_block_number,
            first_repair_esi,
            requested_symbols,
        });
    };

    for _ in 0..requested_symbols {
        repair_esis.push(next_repair_esi);
        next_repair_esi = next_repair_esi.checked_add(assignment.donor_count).ok_or(
            BondScheduleError::RepairContinuationOverflow {
                entry_index: geometry.entry_index,
                source_block_number: geometry.source_block_number,
                first_repair_esi,
                requested_symbols,
            },
        )?;
    }

    Ok((repair_esis, next_repair_esi))
}

fn first_static_owned_esi_at_or_after(assignment: &DonorAssignment, start: u32) -> Option<u32> {
    let residue = start % assignment.donor_count;
    let delta = if residue <= assignment.donor_index {
        assignment.donor_index - residue
    } else {
        assignment
            .donor_count
            .checked_sub(residue - assignment.donor_index)?
    };
    start.checked_add(delta)
}

fn schedule_windowed_repair_continuation(
    assignment: &DonorAssignment,
    geometry: BondEntryBlockGeometry,
    first_repair_esi: u32,
    requested_symbols: usize,
) -> Result<(Vec<u32>, u32), BondScheduleError> {
    let mut repair_esis = Vec::with_capacity(requested_symbols);
    let mut windows = assignment.esi_windows.clone();
    windows.sort_unstable();

    for window in windows {
        if repair_esis.len() == requested_symbols {
            break;
        }
        if window.end_exclusive <= first_repair_esi {
            continue;
        }
        let mut esi = window.start_inclusive.max(first_repair_esi);
        while esi < window.end_exclusive && repair_esis.len() < requested_symbols {
            repair_esis.push(esi);
            esi = esi
                .checked_add(1)
                .ok_or(BondScheduleError::RepairContinuationOverflow {
                    entry_index: geometry.entry_index,
                    source_block_number: geometry.source_block_number,
                    first_repair_esi,
                    requested_symbols,
                })?;
        }
    }

    if repair_esis.len() != requested_symbols {
        return Err(BondScheduleError::InsufficientRepairWindow {
            entry_index: geometry.entry_index,
            source_block_number: geometry.source_block_number,
            requested_symbols,
            scheduled_symbols: repair_esis.len(),
        });
    }

    let next_repair_esi = repair_esis
        .last()
        .and_then(|esi| esi.checked_add(1))
        .ok_or(BondScheduleError::RepairContinuationOverflow {
            entry_index: geometry.entry_index,
            source_block_number: geometry.source_block_number,
            first_repair_esi,
            requested_symbols,
        })?;
    Ok((repair_esis, next_repair_esi))
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
    fn source_first_coverage_proves_static_donors_cover_k_exactly_once() {
        let descriptor = descriptor();
        let assignments = vec![
            DonorAssignment::new_static(0, 2, vec![endpoint()], None),
            DonorAssignment::new_static(1, 2, vec![endpoint()], None),
        ];

        let coverage =
            schedule_bonded_source_first_coverage(&descriptor, &assignments).expect("coverage");

        assert_eq!(coverage.assignment_count, 2);
        assert_eq!(coverage.blocks.len(), 2);
        assert!(coverage.is_source_complete_exactly_once());

        for block in &coverage.blocks {
            assert!(block.is_source_complete_exactly_once());
            assert_eq!(
                block.scheduled_source_symbol_count(),
                usize::from(block.geometry.source_symbols)
            );
            assert_eq!(block.missing_source_esis, Vec::<u32>::new());
            assert_eq!(block.duplicate_source_esis, Vec::<u32>::new());
            assert_eq!(block.donors[0].donor_index, 0);
            assert_eq!(block.donors[0].source_esis, vec![0]);
            assert_eq!(block.donors[0].first_repair_esi, Some(2));
            assert_eq!(block.donors[0].stagger_delay_slots, 0);
            assert_eq!(block.donors[1].donor_index, 1);
            assert_eq!(block.donors[1].source_esis, vec![1]);
            assert_eq!(block.donors[1].first_repair_esi, Some(3));
            assert_eq!(block.donors[1].stagger_delay_slots, 1);
        }
    }

    #[test]
    fn source_first_coverage_reports_windowed_missing_and_duplicate_source_esis() {
        let descriptor = descriptor();
        let assignments = vec![
            DonorAssignment::new_windowed(0, 2, vec![EsiWindow::new(0, 1)], vec![endpoint()], None),
            DonorAssignment::new_windowed(1, 2, vec![EsiWindow::new(0, 1)], vec![endpoint()], None),
        ];

        let coverage =
            schedule_bonded_source_first_coverage(&descriptor, &assignments).expect("coverage");

        assert!(!coverage.is_source_complete_exactly_once());
        for block in &coverage.blocks {
            assert_eq!(block.missing_source_esis, vec![1]);
            assert_eq!(block.duplicate_source_esis, vec![0]);
            assert_eq!(block.scheduled_source_symbol_count(), 2);
            assert_eq!(block.donors[0].source_esis, vec![0]);
            assert_eq!(block.donors[0].first_repair_esi, None);
            assert_eq!(block.donors[1].source_esis, vec![0]);
            assert_eq!(block.donors[1].first_repair_esi, None);
        }
    }

    #[test]
    fn source_first_coverage_fails_closed_for_invalid_collective_assignments() {
        let descriptor = descriptor();

        assert_eq!(
            schedule_bonded_source_first_coverage(&descriptor, &[]),
            Err(BondScheduleError::NoDonorAssignments)
        );

        let duplicate = vec![
            DonorAssignment::new_static(0, 2, vec![endpoint()], None),
            DonorAssignment::new_static(0, 2, vec![endpoint()], None),
        ];
        assert_eq!(
            schedule_bonded_source_first_coverage(&descriptor, &duplicate),
            Err(BondScheduleError::DuplicateDonorAssignment { donor_index: 0 })
        );

        let mismatched_count = vec![
            DonorAssignment::new_static(0, 2, vec![endpoint()], None),
            DonorAssignment::new_static(1, 3, vec![endpoint()], None),
        ];
        assert_eq!(
            schedule_bonded_source_first_coverage(&descriptor, &mismatched_count),
            Err(BondScheduleError::InconsistentDonorCount {
                expected: 2,
                actual: 3,
            })
        );
    }

    #[test]
    fn dynamic_repair_windows_are_disjoint_and_weighted_by_goodput() {
        let descriptor = descriptor();
        let geometry = descriptor
            .entry_block_geometry(0, 0)
            .expect("descriptor block geometry");
        let weights = vec![
            BondedDonorWindowWeight {
                donor_index: 0,
                weight: 1,
            },
            BondedDonorWindowWeight {
                donor_index: 1,
                weight: 3,
            },
        ];

        let plan =
            allocate_bonded_repair_windows(geometry, 2, 8, &weights).expect("window allocation");

        assert_eq!(plan.first_repair_esi, 2);
        assert_eq!(plan.next_repair_esi, 10);
        assert_eq!(plan.allocated_symbol_count(), 8);
        assert!(plan.windows_are_disjoint());
        assert_eq!(
            plan.windows,
            vec![
                BondedDonorRepairWindow {
                    donor_index: 0,
                    esi_window: EsiWindow::new(2, 4),
                    symbol_count: 2,
                    stagger_delay_slots: 0,
                },
                BondedDonorRepairWindow {
                    donor_index: 1,
                    esi_window: EsiWindow::new(4, 10),
                    symbol_count: 6,
                    stagger_delay_slots: 1,
                },
            ]
        );
    }

    #[test]
    fn repair_window_plan_disjointness_rejects_malformed_windows() {
        let descriptor = descriptor();
        let geometry = descriptor
            .entry_block_geometry(0, 0)
            .expect("descriptor block geometry");

        let valid = BondedRepairWindowPlan {
            geometry,
            first_repair_esi: 2,
            next_repair_esi: 6,
            windows: vec![BondedDonorRepairWindow {
                donor_index: 0,
                esi_window: EsiWindow::new(2, 6),
                symbol_count: 4,
                stagger_delay_slots: 0,
            }],
        };
        assert!(valid.windows_are_disjoint());

        let empty = BondedRepairWindowPlan {
            windows: vec![BondedDonorRepairWindow {
                donor_index: 0,
                esi_window: EsiWindow::new(6, 6),
                symbol_count: 0,
                stagger_delay_slots: 0,
            }],
            ..valid.clone()
        };
        assert!(
            !empty.windows_are_disjoint(),
            "empty windows do not allocate repair symbols"
        );

        let misreported_count = BondedRepairWindowPlan {
            windows: vec![BondedDonorRepairWindow {
                donor_index: 0,
                esi_window: EsiWindow::new(2, 6),
                symbol_count: 3,
                stagger_delay_slots: 0,
            }],
            ..valid.clone()
        };
        assert!(
            !misreported_count.windows_are_disjoint(),
            "symbol_count must match the half-open ESI range"
        );

        let overlapping = BondedRepairWindowPlan {
            windows: vec![
                BondedDonorRepairWindow {
                    donor_index: 0,
                    esi_window: EsiWindow::new(2, 5),
                    symbol_count: 3,
                    stagger_delay_slots: 0,
                },
                BondedDonorRepairWindow {
                    donor_index: 1,
                    esi_window: EsiWindow::new(4, 6),
                    symbol_count: 2,
                    stagger_delay_slots: 1,
                },
            ],
            ..valid
        };
        assert!(!overlapping.windows_are_disjoint());
    }

    #[test]
    fn dynamic_repair_windows_distribute_remainders_deterministically() {
        let descriptor = descriptor();
        let geometry = descriptor
            .entry_block_geometry(0, 0)
            .expect("descriptor block geometry");
        let weights = vec![
            BondedDonorWindowWeight {
                donor_index: 2,
                weight: 1,
            },
            BondedDonorWindowWeight {
                donor_index: 0,
                weight: 1,
            },
            BondedDonorWindowWeight {
                donor_index: 1,
                weight: 1,
            },
        ];

        let plan =
            allocate_bonded_repair_windows(geometry, 2, 5, &weights).expect("window allocation");

        assert!(plan.windows_are_disjoint());
        assert_eq!(plan.allocated_symbol_count(), 5);
        assert_eq!(
            plan.windows,
            vec![
                BondedDonorRepairWindow {
                    donor_index: 0,
                    esi_window: EsiWindow::new(2, 4),
                    symbol_count: 2,
                    stagger_delay_slots: 0,
                },
                BondedDonorRepairWindow {
                    donor_index: 1,
                    esi_window: EsiWindow::new(4, 6),
                    symbol_count: 2,
                    stagger_delay_slots: 1,
                },
                BondedDonorRepairWindow {
                    donor_index: 2,
                    esi_window: EsiWindow::new(6, 7),
                    symbol_count: 1,
                    stagger_delay_slots: 2,
                },
            ]
        );
    }

    #[test]
    fn dynamic_repair_window_stagger_slots_are_compact() {
        let descriptor = descriptor();
        let geometry = descriptor
            .entry_block_geometry(0, 0)
            .expect("descriptor block geometry");
        let weights = vec![
            BondedDonorWindowWeight {
                donor_index: 2,
                weight: 0,
            },
            BondedDonorWindowWeight {
                donor_index: 7,
                weight: 1,
            },
            BondedDonorWindowWeight {
                donor_index: 42,
                weight: 1,
            },
        ];

        let plan =
            allocate_bonded_repair_windows(geometry, 2, 2, &weights).expect("window allocation");

        assert_eq!(plan.allocated_symbol_count(), 2);
        assert_eq!(
            plan.windows
                .iter()
                .map(|window| (window.donor_index, window.stagger_delay_slots))
                .collect::<Vec<_>>(),
            vec![(7, 0), (42, 1)]
        );
    }

    #[test]
    fn dynamic_repair_windows_fail_closed_for_invalid_allocation_inputs() {
        let descriptor = descriptor();
        let geometry = descriptor
            .entry_block_geometry(0, 0)
            .expect("descriptor block geometry");

        assert_eq!(
            allocate_bonded_repair_windows(geometry, 2, 1, &[]),
            Err(BondScheduleError::NoDonorAssignments)
        );
        assert_eq!(
            allocate_bonded_repair_windows(
                geometry,
                2,
                1,
                &[
                    BondedDonorWindowWeight {
                        donor_index: 0,
                        weight: 1,
                    },
                    BondedDonorWindowWeight {
                        donor_index: 0,
                        weight: 1,
                    },
                ],
            ),
            Err(BondScheduleError::DuplicateDonorAssignment { donor_index: 0 })
        );
        assert_eq!(
            allocate_bonded_repair_windows(
                geometry,
                2,
                1,
                &[
                    BondedDonorWindowWeight {
                        donor_index: 0,
                        weight: 0,
                    },
                    BondedDonorWindowWeight {
                        donor_index: 1,
                        weight: 0,
                    },
                ],
            ),
            Err(BondScheduleError::ZeroWindowWeightSum)
        );
        assert_eq!(
            allocate_bonded_repair_windows(
                geometry,
                1,
                1,
                &[BondedDonorWindowWeight {
                    donor_index: 0,
                    weight: 1,
                }],
            ),
            Err(BondScheduleError::RepairStartBeforeSource {
                entry_index: 0,
                source_block_number: 0,
                source_symbols: 2,
                first_repair_esi: 1,
            })
        );
        assert_eq!(
            allocate_bonded_repair_windows(
                geometry,
                u32::MAX,
                1,
                &[BondedDonorWindowWeight {
                    donor_index: 0,
                    weight: 1,
                }],
            ),
            Err(BondScheduleError::RepairWindowAllocationOverflow {
                entry_index: 0,
                source_block_number: 0,
                first_repair_esi: u32::MAX,
                requested_symbols: 1,
            })
        );
    }

    #[test]
    fn failed_donor_window_reallocation_moves_budget_to_survivors() {
        let descriptor = descriptor();
        let geometry = descriptor
            .entry_block_geometry(0, 0)
            .expect("descriptor block geometry");
        let initial = allocate_bonded_repair_windows(
            geometry,
            2,
            8,
            &[
                BondedDonorWindowWeight {
                    donor_index: 0,
                    weight: 1,
                },
                BondedDonorWindowWeight {
                    donor_index: 1,
                    weight: 3,
                },
            ],
        )
        .expect("initial allocation");

        let replacement = reallocate_failed_bonded_repair_windows(
            geometry,
            initial.next_repair_esi,
            &initial.windows,
            &[1],
            &[BondedDonorWindowWeight {
                donor_index: 0,
                weight: 1,
            }],
        )
        .expect("reallocation");

        assert_eq!(replacement.first_repair_esi, 10);
        assert_eq!(replacement.next_repair_esi, 16);
        assert_eq!(replacement.allocated_symbol_count(), 6);
        assert!(replacement.windows_are_disjoint());
        assert_eq!(
            replacement.windows,
            vec![BondedDonorRepairWindow {
                donor_index: 0,
                esi_window: EsiWindow::new(10, 16),
                symbol_count: 6,
                stagger_delay_slots: 0,
            }]
        );
    }

    #[test]
    fn failed_donor_window_reallocation_rejects_unknown_failed_donor() {
        let descriptor = descriptor();
        let geometry = descriptor
            .entry_block_geometry(0, 0)
            .expect("descriptor block geometry");
        let initial = allocate_bonded_repair_windows(
            geometry,
            2,
            4,
            &[BondedDonorWindowWeight {
                donor_index: 0,
                weight: 1,
            }],
        )
        .expect("initial allocation");

        assert_eq!(
            reallocate_failed_bonded_repair_windows(
                geometry,
                initial.next_repair_esi,
                &initial.windows,
                &[1],
                &[BondedDonorWindowWeight {
                    donor_index: 0,
                    weight: 1,
                }],
            ),
            Err(BondScheduleError::MissingFailedDonorWindow { donor_index: 1 })
        );
    }

    #[test]
    fn failed_donor_window_reallocation_rejects_overflowing_budget() {
        let descriptor = descriptor();
        let geometry = descriptor
            .entry_block_geometry(0, 0)
            .expect("descriptor block geometry");
        let outstanding_windows = vec![
            BondedDonorRepairWindow {
                donor_index: 0,
                esi_window: EsiWindow::new(0, u32::MAX),
                symbol_count: u32::MAX,
                stagger_delay_slots: 0,
            },
            BondedDonorRepairWindow {
                donor_index: 1,
                esi_window: EsiWindow::new(u32::MAX - 1, u32::MAX),
                symbol_count: 1,
                stagger_delay_slots: 1,
            },
        ];

        assert_eq!(
            reallocate_failed_bonded_repair_windows(
                geometry,
                u32::from(geometry.source_symbols),
                &outstanding_windows,
                &[0, 1],
                &[BondedDonorWindowWeight {
                    donor_index: 2,
                    weight: 1,
                }],
            ),
            Err(BondScheduleError::FailedDonorRepairBudgetOverflow {
                donor_index: 1,
                accumulated_symbols: u32::MAX,
                added_symbols: 1,
            })
        );
    }

    #[test]
    fn failed_donor_window_reallocation_rejects_malformed_failed_window() {
        let descriptor = descriptor();
        let geometry = descriptor
            .entry_block_geometry(0, 0)
            .expect("descriptor block geometry");
        let outstanding_windows = vec![BondedDonorRepairWindow {
            donor_index: 0,
            esi_window: EsiWindow::new(4, 6),
            symbol_count: 3,
            stagger_delay_slots: 0,
        }];

        assert_eq!(
            reallocate_failed_bonded_repair_windows(
                geometry,
                6,
                &outstanding_windows,
                &[0],
                &[BondedDonorWindowWeight {
                    donor_index: 1,
                    weight: 1,
                }],
            ),
            Err(BondScheduleError::InvalidRepairWindow {
                donor_index: 0,
                start_inclusive: 4,
                end_exclusive: 6,
                symbol_count: 3,
            })
        );
    }

    #[test]
    fn repair_window_assignments_preserve_control_metadata_and_override_residue() {
        let descriptor = descriptor();
        let geometry = descriptor
            .entry_block_geometry(0, 0)
            .expect("descriptor block geometry");
        let auth = BondAuthKeyRef::ControlPlane("bond-key-1".to_string());
        let assignments = vec![
            DonorAssignment::new_static(0, 2, vec![endpoint()], Some(auth.clone())),
            DonorAssignment::new_static(1, 2, vec![endpoint()], Some(auth.clone())),
        ];
        let plan = allocate_bonded_repair_windows(
            geometry,
            2,
            8,
            &[
                BondedDonorWindowWeight {
                    donor_index: 0,
                    weight: 1,
                },
                BondedDonorWindowWeight {
                    donor_index: 1,
                    weight: 3,
                },
            ],
        )
        .expect("window allocation");

        let windowed = schedule_bonded_repair_window_assignments(&assignments, &plan)
            .expect("window assignments");

        assert_eq!(windowed.len(), 2);
        assert_eq!(windowed[0].donor_index, 0);
        assert_eq!(windowed[0].repair_window, plan.windows[0]);
        assert_eq!(
            windowed[0].assignment.esi_windows,
            vec![EsiWindow::new(2, 4)]
        );
        assert_eq!(
            windowed[0].assignment.receiver_udp_endpoints,
            vec![endpoint()]
        );
        assert_eq!(windowed[0].assignment.auth_key_ref, Some(auth.clone()));
        assert!(windowed[0].assignment.owns_esi(2));
        assert!(windowed[0].assignment.owns_esi(3));
        assert!(!windowed[0].assignment.owns_esi(4));

        assert_eq!(windowed[1].donor_index, 1);
        assert_eq!(windowed[1].repair_window, plan.windows[1]);
        assert_eq!(
            windowed[1].assignment.esi_windows,
            vec![EsiWindow::new(4, 10)]
        );
        assert_eq!(windowed[1].assignment.auth_key_ref, Some(auth));
        assert!(windowed[1].assignment.owns_esi(9));
        assert!(!windowed[1].assignment.owns_esi(3));
    }

    #[test]
    fn repair_window_assignments_fail_closed_for_unknown_or_malformed_windows() {
        let descriptor = descriptor();
        let geometry = descriptor
            .entry_block_geometry(0, 0)
            .expect("descriptor block geometry");
        let assignments = vec![DonorAssignment::new_static(0, 2, vec![endpoint()], None)];
        let missing_donor_plan = BondedRepairWindowPlan {
            geometry,
            first_repair_esi: 2,
            next_repair_esi: 4,
            windows: vec![BondedDonorRepairWindow {
                donor_index: 1,
                esi_window: EsiWindow::new(2, 4),
                symbol_count: 2,
                stagger_delay_slots: 0,
            }],
        };

        assert_eq!(
            schedule_bonded_repair_window_assignments(&assignments, &missing_donor_plan),
            Err(BondScheduleError::MissingDonorAssignment { donor_index: 1 })
        );

        let malformed_plan = BondedRepairWindowPlan {
            geometry,
            first_repair_esi: 2,
            next_repair_esi: 4,
            windows: vec![BondedDonorRepairWindow {
                donor_index: 0,
                esi_window: EsiWindow::new(2, 4),
                symbol_count: 3,
                stagger_delay_slots: 0,
            }],
        };

        assert_eq!(
            schedule_bonded_repair_window_assignments(&assignments, &malformed_plan),
            Err(BondScheduleError::InvalidRepairWindow {
                donor_index: 0,
                start_inclusive: 2,
                end_exclusive: 4,
                symbol_count: 3,
            })
        );
    }

    #[test]
    fn repair_window_assignments_reject_overlapping_windows() {
        let descriptor = descriptor();
        let geometry = descriptor
            .entry_block_geometry(0, 0)
            .expect("descriptor block geometry");
        let assignments = vec![
            DonorAssignment::new_static(0, 2, vec![endpoint()], None),
            DonorAssignment::new_static(1, 2, vec![endpoint()], None),
        ];
        let overlapping_plan = BondedRepairWindowPlan {
            geometry,
            first_repair_esi: 2,
            next_repair_esi: 8,
            windows: vec![
                BondedDonorRepairWindow {
                    donor_index: 0,
                    esi_window: EsiWindow::new(2, 6),
                    symbol_count: 4,
                    stagger_delay_slots: 0,
                },
                BondedDonorRepairWindow {
                    donor_index: 1,
                    esi_window: EsiWindow::new(5, 8),
                    symbol_count: 3,
                    stagger_delay_slots: 1,
                },
            ],
        };

        assert_eq!(
            schedule_bonded_repair_window_assignments(&assignments, &overlapping_plan),
            Err(BondScheduleError::OverlappingRepairWindows {
                previous_donor_index: 0,
                next_donor_index: 1,
                previous_end_exclusive: 6,
                next_start_inclusive: 5,
            })
        );
    }

    #[test]
    fn repair_window_assignments_reject_stale_window_cursor() {
        let descriptor = descriptor();
        let geometry = descriptor
            .entry_block_geometry(0, 0)
            .expect("descriptor block geometry");
        let assignments = vec![DonorAssignment::new_static(0, 1, vec![endpoint()], None)];
        let stale_cursor_plan = BondedRepairWindowPlan {
            geometry,
            first_repair_esi: 2,
            next_repair_esi: 3,
            windows: vec![BondedDonorRepairWindow {
                donor_index: 0,
                esi_window: EsiWindow::new(2, 5),
                symbol_count: 3,
                stagger_delay_slots: 0,
            }],
        };

        assert_eq!(
            schedule_bonded_repair_window_assignments(&assignments, &stale_cursor_plan),
            Err(BondScheduleError::RepairWindowCursorBeforeWindowEnd {
                next_repair_esi: 3,
                window_end_exclusive: 5,
            })
        );
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
    fn donor_count_one_emission_stream_matches_single_source_order() {
        let descriptor = descriptor();
        let assignment = DonorAssignment::new_static(0, 1, vec![endpoint()], None);

        let schedule = schedule_bonded_donor_spray(&descriptor, &assignment, 3).expect("schedule");
        let emissions = schedule
            .symbol_emissions()
            .into_iter()
            .map(|emission| {
                (
                    emission.geometry.entry_index,
                    emission.geometry.source_block_number,
                    emission.esi,
                    emission.kind,
                    emission.donor_index,
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(
            emissions,
            vec![
                (0, 0, 0, BondedDonorSymbolKind::Source, 0),
                (0, 0, 1, BondedDonorSymbolKind::Source, 0),
                (0, 0, 2, BondedDonorSymbolKind::Repair, 0),
                (0, 0, 3, BondedDonorSymbolKind::Repair, 0),
                (0, 0, 4, BondedDonorSymbolKind::Repair, 0),
                (0, 1, 0, BondedDonorSymbolKind::Source, 0),
                (0, 1, 1, BondedDonorSymbolKind::Source, 0),
                (0, 1, 2, BondedDonorSymbolKind::Repair, 0),
                (0, 1, 3, BondedDonorSymbolKind::Repair, 0),
                (0, 1, 4, BondedDonorSymbolKind::Repair, 0),
            ],
            "donor_count=1 must preserve the single-source source-then-repair ESI stream"
        );
    }

    #[test]
    fn donor_symbol_emissions_are_residue_filtered_and_source_first() {
        let descriptor = descriptor();
        let donor = DonorAssignment::new_static(1, 3, vec![endpoint()], None);

        let schedule = schedule_bonded_donor_spray(&descriptor, &donor, 8).expect("schedule");
        let emissions = schedule.symbol_emissions();

        assert!(!emissions.is_empty());
        for emission in &emissions {
            assert_eq!(emission.donor_index, 1);
            assert!(donor.owns_esi(emission.esi));
            assert_eq!(emission.esi % 3, 1);
            assert_eq!(emission.stagger_delay_slots, 1);
            match emission.kind {
                BondedDonorSymbolKind::Source => {
                    assert!(emission.esi < u32::from(emission.geometry.source_symbols));
                }
                BondedDonorSymbolKind::Repair => {
                    assert!(emission.esi >= u32::from(emission.geometry.source_symbols));
                }
            }
        }

        for block in &schedule.blocks {
            let kinds = block
                .symbol_emissions(schedule.donor_index)
                .into_iter()
                .map(|emission| emission.kind)
                .collect::<Vec<_>>();
            let first_repair = kinds
                .iter()
                .position(|kind| *kind == BondedDonorSymbolKind::Repair);
            let last_source = kinds
                .iter()
                .rposition(|kind| *kind == BondedDonorSymbolKind::Source);
            if let (Some(first_repair), Some(last_source)) = (first_repair, last_source) {
                assert!(
                    last_source < first_repair,
                    "source symbols must precede repair symbols within each block"
                );
            }
        }
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
    fn repair_continuation_resumes_after_initial_window_without_duplicates() {
        let descriptor = descriptor();
        let donor0 = DonorAssignment::new_static(0, 2, vec![endpoint()], None);
        let donor1 = DonorAssignment::new_static(1, 2, vec![endpoint()], None);
        let schedule0 =
            schedule_bonded_donor_spray(&descriptor, &donor0, 4).expect("donor 0 schedule");
        let schedule1 =
            schedule_bonded_donor_spray(&descriptor, &donor1, 4).expect("donor 1 schedule");

        assert_eq!(schedule0.blocks[0].repair_esis, vec![2, 4]);
        assert_eq!(schedule0.blocks[0].next_repair_esi, 6);
        assert_eq!(schedule1.blocks[0].repair_esis, vec![3, 5]);
        assert_eq!(schedule1.blocks[0].next_repair_esi, 6);

        let repair0 = schedule0.blocks[0]
            .repair_continuation(&donor0, 3)
            .expect("donor 0 continuation");
        let repair1 = schedule1.blocks[0]
            .repair_continuation(&donor1, 3)
            .expect("donor 1 continuation");

        assert_eq!(repair0.repair_esis, vec![6, 8, 10]);
        assert_eq!(repair0.next_repair_esi, 12);
        assert_eq!(repair1.repair_esis, vec![7, 9, 11]);
        assert_eq!(repair1.next_repair_esi, 13);

        for esi in &repair0.repair_esis {
            assert!(!schedule0.blocks[0].repair_esis.contains(esi));
            assert_eq!(esi % 2, 0);
        }
        for esi in &repair1.repair_esis {
            assert!(!schedule1.blocks[0].repair_esis.contains(esi));
            assert_eq!(esi % 2, 1);
        }
    }

    #[test]
    fn windowed_repair_continuation_requires_enough_receiver_window() {
        let descriptor = descriptor();
        let geometry = descriptor
            .entry_block_geometry(0, 0)
            .expect("descriptor block geometry");
        let assignment =
            DonorAssignment::new_windowed(0, 3, vec![EsiWindow::new(6, 8)], vec![endpoint()], None);

        let repair =
            schedule_bonded_repair_continuation(&assignment, geometry, 6, 2).expect("windowed");
        assert_eq!(repair.repair_esis, vec![6, 7]);
        assert_eq!(repair.next_repair_esi, 8);

        assert_eq!(
            schedule_bonded_repair_continuation(&assignment, geometry, 6, 3),
            Err(BondScheduleError::InsufficientRepairWindow {
                entry_index: 0,
                source_block_number: 0,
                requested_symbols: 3,
                scheduled_symbols: 2,
            })
        );
    }

    #[test]
    fn repair_continuation_rejects_source_esi_start() {
        let descriptor = descriptor();
        let geometry = descriptor
            .entry_block_geometry(0, 0)
            .expect("descriptor block geometry");
        let assignment = DonorAssignment::new_static(0, 1, vec![endpoint()], None);

        assert_eq!(
            schedule_bonded_repair_continuation(&assignment, geometry, 1, 1),
            Err(BondScheduleError::RepairStartBeforeSource {
                entry_index: 0,
                source_block_number: 0,
                source_symbols: 2,
                first_repair_esi: 1,
            })
        );
    }

    #[test]
    fn spray_schedule_fails_closed_for_invalid_inputs() {
        let valid_descriptor = descriptor();
        let invalid_assignment = DonorAssignment::new_static(2, 2, vec![endpoint()], None);
        assert!(matches!(
            schedule_bonded_donor_spray(&valid_descriptor, &invalid_assignment, 1),
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
