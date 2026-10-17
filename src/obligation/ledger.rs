//! Runtime obligation ledger — central registry for linear token tracking.
//!
//! The ledger is the runtime's single source of truth for obligation lifecycle.
//! Every acquire/commit/abort flows through here, making leaks structurally
//! impossible when the ledger is used correctly.
//!
//! # Invariants
//!
//! 1. Every obligation ID is unique and issued exactly once.
//! 2. Every obligation transitions through exactly one path:
//!    `Reserved → Committed` or `Reserved → Aborted` or `Reserved → Leaked`.
//! 3. Region close requires zero pending obligations for that region.
//! 4. Double-resolve panics (enforced by `ObligationRecord`).
//!
//! # Integration
//!
//! The ledger is designed to be held by the runtime state and queried by:
//! - The scheduler (to check quiescence conditions)
//! - The leak oracle (to verify invariants in lab mode)
//! - The cancellation protocol (to abort obligations during drain)

use crate::record::{
    ObligationAbortReason, ObligationKind, ObligationRecord, ObligationResolution, ObligationState,
    SourceLocation,
};
use crate::types::{ObligationId, RegionId, TaskId, Time};
use crate::util::ArenaIndex;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Error returned when a fallible ledger transition arrives after region finalization.
///
/// br-asupersync-qyf37e: this powers the fallible
/// [`ObligationLedger::try_commit`] / [`ObligationLedger::try_abort`]
/// public surface when a token arrives AFTER the owning region has
/// been marked finalized via
/// [`ObligationLedger::mark_region_finalized`]. The infallible
/// `commit` / `abort` methods retain their existing
/// invariant-violation panic shape; the fallible variants exist for
/// callsites (Drop impls, late-arrival handlers) that legitimately
/// race with region finalization and prefer a `Result` return.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerError {
    /// The owning region was finalized before this commit/abort
    /// arrived. The structured-concurrency contract forbids
    /// obligation transitions after region close — auditors
    /// observing an event with timestamp > region.closed_at
    /// interpret it as a phantom transition. Operators should
    /// route the late-arrival through Drop-time aborts before the
    /// region closes.
    RegionFinalized {
        /// The owning region that was already finalized when the call arrived.
        region: RegionId,
        /// The obligation whose token was presented after finalize.
        obligation: ObligationId,
    },
    /// The obligation has already been resolved (committed, aborted,
    /// or leaked). Returned by the fallible `try_abort_by_id` path
    /// when a drain caller races with the obligation's natural
    /// completion. The infallible `abort_by_id` keeps its existing
    /// double-resolve panic shape; this variant exists for callsites
    /// (drain loops, recovery handlers) that legitimately race with
    /// the obligation's normal commit/abort and prefer a `Result`
    /// return.
    AlreadyResolved {
        /// The obligation whose ID was looked up after it had already
        /// transitioned out of the Reserved state.
        obligation: ObligationId,
        /// The terminal state observed at the time of the racy call.
        state: ObligationState,
    },
    /// The obligation ID is not known to the ledger. Returned by the
    /// fallible `try_abort_by_id` path. The infallible `abort_by_id`
    /// keeps its existing not-found panic shape.
    NotFound {
        /// The obligation ID that was not present in the ledger.
        obligation: ObligationId,
    },
    /// The obligation is not in the expected pending state. Returned when
    /// trying to resolve an obligation that has already been committed,
    /// aborted, or leaked.
    NotPending {
        /// The obligation ID that was not in pending state.
        obligation: ObligationId,
        /// The actual state observed.
        state: ObligationState,
    },
    /// Obligation token validation failed - the token's fields do not
    /// match the ledger record. This indicates token corruption or
    /// use-after-resolve.
    TokenMismatch {
        /// The obligation ID from the token.
        obligation: ObligationId,
        /// Description of which field mismatched.
        field: &'static str,
    },
    /// Ledger stats underflow - attempting to decrement a counter below zero.
    /// This indicates a double-resolution or other accounting error.
    StatsUnderflow {
        /// The counter that would underflow.
        counter: &'static str,
    },
    /// Cannot acquire obligation against finalized region. The region was
    /// closed before this obligation could be created.
    AcquireAfterFinalize {
        /// The region that was already finalized.
        region: RegionId,
        /// The obligation kind that was attempted.
        kind: ObligationKind,
        /// The holder that attempted the acquire.
        holder: TaskId,
    },
    /// Obligation ledger index space exhausted within current generation.
    /// This is a resource limit error - too many obligations created.
    IndexOverflow {
        /// The current generation that ran out of index space.
        generation: u32,
    },
    /// Obligation ledger generation counter exhausted. This is extremely
    /// unlikely in practice but must be handled for correctness.
    GenerationOverflow,
}

impl std::fmt::Display for LedgerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RegionFinalized { region, obligation } => write!(
                f,
                "obligation {obligation:?} cannot transition: owning region {region:?} \
                 was already finalized (br-asupersync-qyf37e)"
            ),
            Self::AlreadyResolved { obligation, state } => write!(
                f,
                "obligation {obligation:?} cannot abort_by_id: already resolved \
                 (state={state:?})"
            ),
            Self::NotFound { obligation } => {
                write!(f, "obligation {obligation:?} not found in ledger")
            }
            Self::NotPending { obligation, state } => write!(
                f,
                "obligation {obligation:?} is not pending (state={state:?})"
            ),
            Self::TokenMismatch { obligation, field } => write!(
                f,
                "obligation token {obligation:?} {field} does not match ledger record"
            ),
            Self::StatsUnderflow { counter } => {
                write!(f, "obligation ledger {counter} stats underflow")
            }
            Self::AcquireAfterFinalize {
                region,
                kind,
                holder,
            } => write!(
                f,
                "cannot acquire obligation against finalized region {region:?} \
                 (kind={kind:?}, holder={holder:?})"
            ),
            Self::IndexOverflow { generation } => write!(
                f,
                "obligation ledger index overflow within generation {generation}; reset required"
            ),
            Self::GenerationOverflow => {
                write!(f, "obligation ledger generation overflow")
            }
        }
    }
}

impl std::error::Error for LedgerError {}
use std::sync::Arc;

/// A linear token representing a live obligation.
///
/// This token must be consumed by calling [`ObligationLedger::commit`] or
/// [`ObligationLedger::abort`]. Dropping it without resolution is a logic
/// error caught by the ledger's leak check.
///
/// The token is intentionally `!Clone` and `!Copy` to approximate linearity.
#[must_use = "obligation tokens must be committed or aborted; dropping leaks the obligation"]
#[derive(Debug)]
pub struct ObligationToken {
    id: ObligationId,
    kind: ObligationKind,
    holder: TaskId,
    region: RegionId,
}

impl ObligationToken {
    /// Returns the obligation ID.
    #[must_use]
    pub fn id(&self) -> ObligationId {
        self.id
    }

    /// Returns the obligation kind.
    #[must_use]
    pub fn kind(&self) -> ObligationKind {
        self.kind
    }

    /// Returns the holder task ID.
    #[must_use]
    pub fn holder(&self) -> TaskId {
        self.holder
    }

    /// Returns the owning region ID.
    #[must_use]
    pub fn region(&self) -> RegionId {
        self.region
    }
}

/// Statistics about the ledger's obligation tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LedgerStats {
    /// Total obligations ever acquired.
    pub total_acquired: u64,
    /// Total obligations committed.
    pub total_committed: u64,
    /// Total obligations aborted.
    pub total_aborted: u64,
    /// Total obligations leaked.
    pub total_leaked: u64,
    /// Currently pending (reserved, not yet resolved).
    pub pending: u64,
}

impl LedgerStats {
    /// Returns true if all obligations have been resolved.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.pending == 0 && self.total_leaked == 0
    }
}

/// Count summary for a filtered obligation snapshot.
///
/// # Examples
///
/// ```
/// use asupersync::obligation::ledger::ObligationLedger;
/// use asupersync::record::ObligationKind;
/// use asupersync::types::{RegionId, TaskId, Time};
///
/// let mut ledger = ObligationLedger::new();
/// let task = TaskId::testing_default();
/// let region = RegionId::testing_default();
///
/// let _pending = ledger.acquire(ObligationKind::Lease, task, region, Time::from_nanos(10));
/// let committed = ledger.acquire(ObligationKind::Ack, task, region, Time::from_nanos(20));
/// ledger.commit(committed, Time::from_nanos(30));
///
/// let region_counts = ledger.counts_for_region(region);
/// assert_eq!(region_counts.pending, 1);
/// assert_eq!(region_counts.resolved(), 1);
/// assert_eq!(region_counts.total(), 2);
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ObligationCounts {
    /// Obligations still pending and blocking quiescence.
    pub pending: usize,
    /// Obligations committed successfully.
    pub committed: usize,
    /// Obligations aborted cleanly.
    pub aborted: usize,
    /// Obligations marked leaked.
    pub leaked: usize,
}

impl ObligationCounts {
    /// Builds counts from a deterministic or filtered obligation record stream.
    #[must_use]
    pub fn from_records<'a>(records: impl IntoIterator<Item = &'a ObligationRecord>) -> Self {
        let mut counts = Self::default();
        for record in records {
            counts.record_state(record.state);
        }
        counts
    }

    /// Total obligations represented by this snapshot.
    #[must_use]
    pub const fn total(self) -> usize {
        self.pending + self.committed + self.aborted + self.leaked
    }

    /// Total terminal obligations represented by this snapshot.
    #[must_use]
    pub const fn resolved(self) -> usize {
        self.committed + self.aborted + self.leaked
    }

    fn record_state(&mut self, state: ObligationState) {
        match state {
            ObligationState::Reserved => self.pending += 1,
            ObligationState::Committed => self.committed += 1,
            ObligationState::Aborted => self.aborted += 1,
            ObligationState::Leaked => self.leaked += 1,
        }
    }
}

/// Owned diagnostic snapshot for one obligation record.
///
/// This is the public read-only audit shape. It intentionally copies the fields
/// operators and tests need without cloning the record's optional backtrace.
///
/// # Examples
///
/// ```
/// use asupersync::obligation::ledger::ObligationLedger;
/// use asupersync::record::{ObligationKind, ObligationState};
/// use asupersync::types::{RegionId, TaskId, Time};
///
/// let mut ledger = ObligationLedger::new();
/// let task = TaskId::testing_default();
/// let region = RegionId::testing_default();
/// let token = ledger.acquire(ObligationKind::Lease, task, region, Time::from_nanos(10));
/// let id = token.id();
///
/// let audit = ledger.audit_region(region, Time::from_nanos(25));
/// assert_eq!(audit[0].id, id);
/// assert_eq!(audit[0].state, ObligationState::Reserved);
/// assert_eq!(audit[0].age_ns, 15);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObligationAuditRecord {
    /// Unique obligation ID.
    pub id: ObligationId,
    /// Obligation kind.
    pub kind: ObligationKind,
    /// Task holding or formerly holding the obligation.
    pub holder: TaskId,
    /// Owning region.
    pub region: RegionId,
    /// Current lifecycle state.
    pub state: ObligationState,
    /// Time when the obligation was reserved.
    pub reserved_at: Time,
    /// Time when the obligation entered a terminal state, if any.
    pub resolved_at: Option<Time>,
    /// Saturating age at the snapshot time, in nanoseconds.
    pub age_ns: u64,
    /// Optional caller-provided diagnostic description.
    pub description: Option<String>,
    /// Source location where the obligation was acquired.
    pub acquired_at: SourceLocation,
    /// Reason for abort, if applicable.
    pub abort_reason: Option<ObligationAbortReason>,
    /// Whether the live record carried a captured backtrace.
    pub has_acquire_backtrace: bool,
}

impl ObligationAuditRecord {
    /// Copies diagnostic fields from a live obligation record.
    #[must_use]
    pub fn from_record(record: &ObligationRecord, now: Time) -> Self {
        Self {
            id: record.id,
            kind: record.kind,
            holder: record.holder,
            region: record.region,
            state: record.state,
            reserved_at: record.reserved_at,
            resolved_at: record.resolved_at,
            age_ns: now.duration_since(record.reserved_at),
            description: record.description.clone(),
            acquired_at: record.acquired_at,
            abort_reason: record.abort_reason,
            has_acquire_backtrace: record.acquire_backtrace.is_some(),
        }
    }
}

/// A leaked obligation diagnostic for the leak oracle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeakedObligation {
    /// The obligation ID.
    pub id: ObligationId,
    /// The obligation kind.
    pub kind: ObligationKind,
    /// The task that held it.
    pub holder: TaskId,
    /// The region it belonged to.
    pub region: RegionId,
    /// When it was reserved.
    pub reserved_at: Time,
    /// Description, if any.
    pub description: Option<String>,
    /// Source location of acquisition.
    pub acquired_at: SourceLocation,
}

/// Result of a ledger leak check.
#[derive(Debug, Clone)]
pub struct LeakCheckResult {
    /// Leaked obligations found.
    pub leaked: Vec<LeakedObligation>,
}

impl LeakCheckResult {
    /// Returns true if no leaks were found.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.leaked.is_empty()
    }
}

/// Deterministic summary from draining all currently pending obligations in a region.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RegionObligationDrain {
    /// Pending obligations observed at the start of the drain.
    pub pending_observed: usize,
    /// Obligations successfully aborted by the drain.
    pub aborted: usize,
    /// Obligations skipped because the owning region is already finalized.
    pub finalized: usize,
    /// Obligations that raced with another resolver before the drain reached them.
    pub already_resolved: usize,
    /// IDs that disappeared before the drain reached them.
    pub missing: usize,
}

impl RegionObligationDrain {
    /// Returns true if every observed obligation reached a deterministic outcome.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.pending_observed
            == self.aborted + self.finalized + self.already_resolved + self.missing
    }
}

/// The obligation ledger: central registry for obligation lifecycle.
///
/// All obligation acquire/commit/abort operations flow through the ledger.
/// It maintains a `BTreeMap` for deterministic iteration order (required for
/// lab-mode reproducibility).
#[derive(Debug)]
pub struct ObligationLedger {
    /// All obligations, keyed by ID. BTreeMap for deterministic iteration.
    obligations: BTreeMap<ObligationId, ObligationRecord>,
    /// Next slot index for ID allocation within the current ledger generation.
    next_index: u32,
    /// Current generation for obligation IDs issued by this ledger epoch.
    generation: u32,
    /// Running statistics.
    stats: LedgerStats,
    /// br-asupersync-qyf37e: regions that have been marked
    /// finalized via [`Self::mark_region_finalized`]. Tokens whose
    /// owning region is in this set are rejected by the fallible
    /// [`Self::try_commit`] / [`Self::try_abort`] surface — late
    /// arrival from a Drop impl or detached handler.
    /// `BTreeSet<RegionId>` keeps iteration deterministic for the
    /// audit/snapshot paths.
    finalized_regions: BTreeSet<RegionId>,
    /// How many committed or aborted records stay queryable; `None` keeps
    /// every record (see [`Self::with_resolved_retention`]).
    resolved_retention: Option<usize>,
    /// Committed and aborted ids in resolution order, oldest first. Only a
    /// ledger with a bounded retention records them.
    resolved_order: VecDeque<ObligationId>,
}

impl Default for ObligationLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl ObligationLedger {
    fn pending_record_for_id_mut(
        &mut self,
        id: ObligationId,
        _operation: &'static str,
    ) -> Result<&mut ObligationRecord, LedgerError> {
        let record = self
            .obligations
            .get_mut(&id)
            .ok_or(LedgerError::NotFound { obligation: id })?;
        if !record.is_pending() {
            return Err(LedgerError::NotPending {
                obligation: id,
                state: record.state,
            });
        }
        Ok(record)
    }

    fn resolve_one_pending(&mut self, _operation: &'static str) -> Result<(), LedgerError> {
        self.stats.pending = self
            .stats
            .pending
            .checked_sub(1)
            .ok_or(LedgerError::StatsUnderflow { counter: "pending" })?;
        Ok(())
    }

    fn record_for_token_mut(
        &mut self,
        token: &ObligationToken,
    ) -> Result<&mut ObligationRecord, LedgerError> {
        let record = self.pending_record_for_id_mut(token.id, "token resolve")?;
        if record.kind != token.kind {
            return Err(LedgerError::TokenMismatch {
                obligation: token.id,
                field: "kind",
            });
        }
        if record.holder != token.holder {
            return Err(LedgerError::TokenMismatch {
                obligation: token.id,
                field: "holder",
            });
        }
        if record.region != token.region {
            return Err(LedgerError::TokenMismatch {
                obligation: token.id,
                field: "region",
            });
        }
        Ok(record)
    }

    fn finish_resolution(
        &mut self,
        operation: &'static str,
        resolution: ObligationResolution,
    ) -> Result<(), LedgerError> {
        match resolution {
            ObligationResolution::Commit => {
                self.stats.total_committed += 1;
            }
            ObligationResolution::Abort(_) => {
                self.stats.total_aborted += 1;
            }
            ObligationResolution::Leak => {
                self.stats.total_leaked += 1;
            }
        }
        self.resolve_one_pending(operation)
    }

    fn resolve_token(
        &mut self,
        token: &ObligationToken,
        operation: &'static str,
        resolution: ObligationResolution,
        now: Time,
    ) -> Result<u64, LedgerError> {
        let duration = {
            let record = self.record_for_token_mut(token)?;
            record.resolve_with(now, resolution)
        };
        self.finish_resolution(operation, resolution)?;
        self.retain_resolved(token.id, resolution);
        Ok(duration)
    }

    fn resolve_id(
        &mut self,
        id: ObligationId,
        operation: &'static str,
        resolution: ObligationResolution,
        now: Time,
    ) -> Result<u64, LedgerError> {
        let duration = {
            let record = self.pending_record_for_id_mut(id, operation)?;
            record.resolve_with(now, resolution)
        };
        self.finish_resolution(operation, resolution)?;
        self.retain_resolved(id, resolution);
        Ok(duration)
    }

    /// Under a bounded retention, records a commit or abort and drops the
    /// oldest committed or aborted records past the bound. Leaked records are
    /// never dropped: leak diagnostics read them.
    fn retain_resolved(&mut self, id: ObligationId, resolution: ObligationResolution) {
        let Some(limit) = self.resolved_retention else {
            return;
        };
        if matches!(resolution, ObligationResolution::Leak) {
            return;
        }
        self.resolved_order.push_back(id);
        while self.resolved_order.len() > limit {
            if let Some(oldest) = self.resolved_order.pop_front() {
                self.obligations.remove(&oldest);
            }
        }
    }

    /// Creates an empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self {
            obligations: BTreeMap::new(),
            next_index: 0,
            generation: 0,
            stats: LedgerStats::default(),
            finalized_regions: BTreeSet::new(),
            resolved_retention: None,
            resolved_order: VecDeque::new(),
        }
    }

    /// Creates an empty ledger that keeps at most `limit` committed or aborted
    /// records (br-asupersync-rrtgoy).
    ///
    /// A ledger from [`Self::new`] keeps every record it ever created, so a
    /// long-lived owner that acquires one obligation per operation (a
    /// messaging consumer, one per delivery) grows without bound, and every
    /// full scan grows with it. This ledger instead drops the oldest committed
    /// or aborted record once more than `limit` of them exist:
    ///
    /// - Pending and leaked records are always kept. Region drains and leak
    ///   diagnostics read them.
    /// - [`Self::stats`] counts every obligation ever acquired, committed,
    ///   aborted or leaked, as before. Record queries ([`Self::get`],
    ///   [`Self::obligation_state`], [`Self::counts`], [`Self::audit`],
    ///   [`Self::iter`]) see only the retained records, and a dropped id reads
    ///   as absent.
    /// - When a generation's index space is exhausted, the ledger moves to the
    ///   next generation instead of failing with
    ///   [`LedgerError::IndexOverflow`]. Ids stay unique because they carry
    ///   the generation.
    #[must_use]
    pub fn with_resolved_retention(limit: usize) -> Self {
        Self {
            resolved_retention: Some(limit),
            ..Self::new()
        }
    }

    /// br-asupersync-qyf37e: marks `region` as finalized so that
    /// subsequent calls to [`Self::try_commit`] / [`Self::try_abort`]
    /// for tokens whose owning region matches return
    /// [`LedgerError::RegionFinalized`] instead of mutating ledger
    /// state. Idempotent.
    ///
    /// **Status (verified 2026-05-29): the fence machinery is complete and
    /// unit-tested here — [`Self::commit`] (`finalized_regions` check before
    /// mutate), [`Self::abort`], [`Self::abort_by_id`], and
    /// [`Self::acquire_with_context`] (via `acquire_internal`) all fail-closed
    /// on a finalized region, and the `try_*` variants surface it as an error.
    /// The FABRIC consumer production call site now drains pending ack
    /// obligations and invokes this method from
    /// `FabricConsumer::finalize_region`, which `ConsumerActor::on_stop` calls
    /// after its mailbox drain.**
    ///
    /// IMPORTANT — do NOT confuse this type with the runtime's
    /// `crate::runtime::obligation_table::ObligationTable` (Σ shard C). That
    /// SEPARATE type is ALREADY fenced in production: `RuntimeState`'s region
    /// driver `advance_region_state` calls
    /// `self.obligations.mark_region_finalized(region_id)` right after
    /// `complete_close()` returns true (`src/runtime/state.rs`, near the
    /// `RegionCloseComplete` trace event). The runtime core is covered.
    ///
    /// THIS `ObligationLedger` is used by the messaging / FABRIC + session
    /// lane (e.g. `FabricConsumer` in `src/messaging/consumer.rs`, plus
    /// `src/messaging/{fabric,service}.rs` and `src/messaging/session/obligation.rs`).
    /// `FabricConsumer` owns a ledger and resolves obligations via
    /// `commit`/`abort`/`acquire_with_context`; its finalize hook is the
    /// MESSAGING region/consumer finalize path, NOT `RuntimeState`. That hook
    /// is intentionally responsible for aborting live ack obligations before
    /// marking the owner region finalized, so Drop-late commit/abort paths cannot
    /// mutate an already-closed region's audit trail. Tracked as
    /// br-asupersync-qyf37e / -u1gcfp / -12cqs2 and gauntlet finding CONF-001.
    ///
    /// Tokens captured across the region boundary (e.g. in a Drop impl
    /// outside the scope) that arrive after `mark_region_finalized` are
    /// fenced off: [`Self::try_commit`] / [`Self::try_abort`] return
    /// [`LedgerError::RegionFinalized`], and the infallible
    /// [`Self::commit`] / [`Self::abort`] / [`Self::abort_by_id`] fail
    /// closed (no mutation, return `0`) instead of silently mutating an
    /// already-finalized region's audit trail.
    pub fn mark_region_finalized(&mut self, region: RegionId) {
        self.finalized_regions.insert(region);
    }

    /// Returns `true` if `region` has been marked finalized via
    /// [`Self::mark_region_finalized`].
    #[must_use]
    pub fn is_region_finalized(&self, region: RegionId) -> bool {
        self.finalized_regions.contains(&region)
    }

    /// br-asupersync-qyf37e: fallible variant of [`Self::commit`]
    /// that returns [`LedgerError::RegionFinalized`] if the token's
    /// owning region was already marked finalized via
    /// [`Self::mark_region_finalized`]. Use this from Drop impls or
    /// detached handlers that may race with region close.
    ///
    /// Where [`Self::commit`] panics, this returns the error instead,
    /// leaving the ledger unchanged: [`LedgerError::NotFound`],
    /// [`LedgerError::NotPending`] (already committed, aborted or leaked,
    /// e.g. by a region drain that won the race) or
    /// [`LedgerError::TokenMismatch`] (br-asupersync-rrtgoy L1).
    #[allow(clippy::needless_pass_by_value)] // Token consumed intentionally to prevent reuse
    pub fn try_commit(&mut self, token: ObligationToken, now: Time) -> Result<u64, LedgerError> {
        if self.finalized_regions.contains(&token.region) {
            return Err(LedgerError::RegionFinalized {
                region: token.region,
                obligation: token.id,
            });
        }
        self.resolve_token(&token, "try_commit", ObligationResolution::Commit, now)
    }

    /// br-asupersync-qyf37e: fallible variant of [`Self::abort`].
    /// See [`Self::try_commit`] for the contract and the errors it
    /// returns where [`Self::abort`] panics.
    #[allow(clippy::needless_pass_by_value)] // Token consumed intentionally to prevent reuse
    pub fn try_abort(
        &mut self,
        token: ObligationToken,
        now: Time,
        reason: ObligationAbortReason,
    ) -> Result<u64, LedgerError> {
        if self.finalized_regions.contains(&token.region) {
            return Err(LedgerError::RegionFinalized {
                region: token.region,
                obligation: token.id,
            });
        }
        self.resolve_token(
            &token,
            "try_abort",
            ObligationResolution::Abort(reason),
            now,
        )
    }

    /// Acquires a new obligation, returning a linear token.
    ///
    /// The token must be passed to [`commit`](Self::commit) or
    /// [`abort`](Self::abort) to resolve the obligation.
    ///
    /// br-asupersync-12cqs2: PANICS if the owning region was already
    /// marked finalized via [`Self::mark_region_finalized`]. Minting
    /// a fresh obligation against a finalized region is a
    /// programming error (the structured-concurrency contract
    /// forbids post-close mutation). Callers that legitimately race
    /// with region finalize (Drop impls, late-arrival handlers) MUST
    /// use [`Self::try_acquire`] / [`Self::try_acquire_with_context`]
    /// which return [`LedgerError::RegionFinalized`] on the late path.
    pub fn acquire(
        &mut self,
        kind: ObligationKind,
        holder: TaskId,
        region: RegionId,
        now: Time,
    ) -> ObligationToken {
        self.acquire_with_context(
            kind,
            holder,
            region,
            now,
            SourceLocation::unknown(),
            None,
            None,
        )
    }

    /// Internal acquire implementation that returns Result for all error cases.
    #[allow(clippy::too_many_arguments)]
    fn acquire_internal(
        &mut self,
        kind: ObligationKind,
        holder: TaskId,
        region: RegionId,
        now: Time,
        location: SourceLocation,
        backtrace: Option<Arc<std::backtrace::Backtrace>>,
        description: Option<String>,
    ) -> Result<ObligationToken, LedgerError> {
        // Check if region is finalized
        if self.finalized_regions.contains(&region) {
            return Err(LedgerError::AcquireAfterFinalize {
                region,
                kind,
                holder,
            });
        }

        // A bounded ledger moves to the next generation when this one's index
        // space runs out; it no longer holds every id it issued, so it must not
        // stop working after u32::MAX acquisitions (br-asupersync-rrtgoy).
        if self.next_index == u32::MAX && self.resolved_retention.is_some() {
            self.generation = self
                .generation
                .checked_add(1)
                .ok_or(LedgerError::GenerationOverflow)?;
            self.next_index = 0;
        }

        // Check for index overflow
        let next_index = self
            .next_index
            .checked_add(1)
            .ok_or(LedgerError::IndexOverflow {
                generation: self.generation,
            })?;

        let idx = ArenaIndex::new(self.next_index, self.generation);
        self.next_index = next_index;
        let id = ObligationId::from_arena(idx);

        let record = if let Some(desc) = description {
            ObligationRecord::with_description_and_context(
                id, kind, holder, region, now, desc, location, backtrace,
            )
        } else {
            ObligationRecord::new_with_context(id, kind, holder, region, now, location, backtrace)
        };

        self.obligations.insert(id, record);
        self.stats.total_acquired += 1;
        self.stats.pending += 1;

        Ok(ObligationToken {
            id,
            kind,
            holder,
            region,
        })
    }

    /// Acquires a new obligation with full context.
    ///
    /// br-asupersync-12cqs2: PANICS if the owning region was already
    /// marked finalized. See [`Self::acquire`] for the rationale.
    /// Use [`Self::try_acquire_with_context`] for the fallible
    /// variant that returns [`LedgerError::RegionFinalized`] when the
    /// late-arrival path is intentional.
    #[allow(clippy::too_many_arguments)]
    pub fn acquire_with_context(
        &mut self,
        kind: ObligationKind,
        holder: TaskId,
        region: RegionId,
        now: Time,
        location: SourceLocation,
        backtrace: Option<Arc<std::backtrace::Backtrace>>,
        description: Option<String>,
    ) -> ObligationToken {
        self.acquire_internal(kind, holder, region, now, location, backtrace, description)
            .unwrap_or_else(|err| match err {
                LedgerError::AcquireAfterFinalize { region, kind, holder } => {
                    panic!(
                        "br-asupersync-12cqs2: cannot acquire obligation against finalized region {region:?} \
                         (kind={kind:?}, holder={holder:?}); use try_acquire_with_context for late-arrival paths"
                    )
                }
                LedgerError::IndexOverflow { generation } => {
                    panic!(
                        "obligation ledger index overflow within generation {generation}; reset required"
                    )
                }
                _ => panic!("unexpected error in acquire_with_context: {err}"),
            })
    }

    /// br-asupersync-12cqs2: fallible variant of [`Self::acquire`].
    /// Returns [`LedgerError::RegionFinalized`] (with a sentinel
    /// `obligation` ID since no token is minted) when the owning
    /// region was already finalized. Use this from Drop impls,
    /// detached cleanup tasks, or anywhere a late-arrival race with
    /// region finalize is part of the contract.
    pub fn try_acquire(
        &mut self,
        kind: ObligationKind,
        holder: TaskId,
        region: RegionId,
        now: Time,
    ) -> Result<ObligationToken, LedgerError> {
        self.try_acquire_with_context(
            kind,
            holder,
            region,
            now,
            SourceLocation::unknown(),
            None,
            None,
        )
    }

    /// br-asupersync-12cqs2: fallible variant of
    /// [`Self::acquire_with_context`]. See [`Self::try_acquire`] for
    /// the contract.
    #[allow(clippy::too_many_arguments)]
    pub fn try_acquire_with_context(
        &mut self,
        kind: ObligationKind,
        holder: TaskId,
        region: RegionId,
        now: Time,
        location: SourceLocation,
        backtrace: Option<Arc<std::backtrace::Backtrace>>,
        description: Option<String>,
    ) -> Result<ObligationToken, LedgerError> {
        self.acquire_internal(kind, holder, region, now, location, backtrace, description)
            .map_err(|err| match err {
                LedgerError::AcquireAfterFinalize { region, .. } => {
                    // Convert to the existing RegionFinalized error variant for API consistency
                    LedgerError::RegionFinalized {
                        region,
                        // No token minted yet; sentinel ID for pattern-match.
                        obligation: ObligationId::from_arena(ArenaIndex::new(0, u32::MAX)),
                    }
                }
                other => other,
            })
    }

    /// Commits an obligation, consuming the token.
    ///
    /// Returns the duration the obligation was held (in nanoseconds).
    ///
    /// br-asupersync-u1gcfp: if the token's owning region was already
    /// marked finalized, the call BAILS — no mutation, returns 0.
    /// This makes Drop impls and other infallible late-arrival paths
    /// fail-closed rather than mutating ledger state past the
    /// region's lifetime. Callers that need to OBSERVE the late
    /// arrival should use [`Self::try_commit`] instead.
    ///
    /// # Panics
    ///
    /// Panics if the obligation was already resolved or does not
    /// exist (and the region is NOT finalized — finalized regions
    /// silently bail per the fence check above).
    #[allow(clippy::needless_pass_by_value)] // Token consumed intentionally to prevent reuse
    pub fn commit(&mut self, token: ObligationToken, now: Time) -> u64 {
        // br-asupersync-u1gcfp: fence check FIRST. Drop impls in
        // messaging/fabric.rs and elsewhere call ledger.commit/abort
        // unconditionally; without this fence they would mutate the
        // ledger after the region has finalized, producing phantom
        // transitions that violate temporal ordering.
        if self.finalized_regions.contains(&token.region) {
            return 0;
        }
        self.resolve_token(&token, "commit", ObligationResolution::Commit, now)
            .unwrap_or_else(|err| panic!("commit: {err}"))
    }

    /// Aborts an obligation, consuming the token.
    ///
    /// Returns the duration the obligation was held (in nanoseconds).
    ///
    /// br-asupersync-u1gcfp: same fail-closed-on-finalized contract
    /// as [`Self::commit`]. If the token's owning region was already
    /// marked finalized, the call BAILS — no mutation, returns 0.
    ///
    /// # Panics
    ///
    /// Panics if the obligation was already resolved or does not
    /// exist (and the region is NOT finalized).
    #[allow(clippy::needless_pass_by_value)] // Token consumed intentionally to prevent reuse
    pub fn abort(
        &mut self,
        token: ObligationToken,
        now: Time,
        reason: ObligationAbortReason,
    ) -> u64 {
        // br-asupersync-u1gcfp: fence check FIRST.
        if self.finalized_regions.contains(&token.region) {
            return 0;
        }
        self.resolve_token(&token, "abort", ObligationResolution::Abort(reason), now)
            .unwrap_or_else(|err| panic!("abort: {err}"))
    }

    /// Aborts an obligation by ID.
    ///
    /// This is intended for external drain and recovery paths that enumerate
    /// pending obligations by ID after the original linear token is no longer
    /// available to the caller.
    ///
    /// br-asupersync-u1gcfp: same fail-closed contract as
    /// [`Self::abort`]. If the obligation's owning region was already
    /// marked finalized, the call BAILS — no mutation, returns 0.
    /// This protects external drain paths from being a back-door
    /// around the finalized fence.
    ///
    /// # Panics
    ///
    /// Panics if the obligation was already resolved or does not
    /// exist (and the region is NOT finalized).
    pub fn abort_by_id(
        &mut self,
        id: ObligationId,
        now: Time,
        reason: ObligationAbortReason,
    ) -> u64 {
        // br-asupersync-u1gcfp: fence check FIRST. We have to look up
        // the record's region before we can check the fence (the
        // caller passed only an ID), but the lookup is lightweight
        // and the alternative — letting a drain path mutate
        // post-finalize — is precisely what this fix exists to
        // prevent. If the obligation doesn't exist, fall through to
        // the existing pending_record_for_id_mut path which will
        // panic with the established diagnostic.
        if let Some(region) = self.obligations.get(&id).map(|r| r.region) {
            if self.finalized_regions.contains(&region) {
                return 0;
            }
        }
        self.resolve_id(id, "abort_by_id", ObligationResolution::Abort(reason), now)
            .unwrap_or_else(|err| panic!("abort_by_id: {err}"))
    }

    /// Race-tolerant variant of [`Self::abort_by_id`] for drain loops
    /// and recovery handlers that legitimately race with an
    /// obligation's natural completion.
    ///
    /// Token-double-fulfillment scenario this exists to handle:
    /// thread T1 holds the ledger lock and commits a token
    /// (state → Committed), then thread T2 acquires the ledger lock
    /// inside a region drain and calls `abort_by_id(id)` for the same
    /// obligation. The infallible `abort_by_id` panics in that
    /// situation (`pending_record_for_id_mut` asserts `is_pending()`).
    /// `try_abort_by_id` instead returns `Err(LedgerError::AlreadyResolved)`
    /// so the drain loop can continue without unwinding the worker.
    ///
    /// Contract:
    ///   * Returns `Err(LedgerError::RegionFinalized)` if the owning region
    ///     is finalized (matching `try_abort`).
    ///   * Returns `Err(LedgerError::NotFound)` if the obligation was
    ///     never in the ledger.
    ///   * Returns `Err(LedgerError::AlreadyResolved)` if the obligation
    ///     exists but has already transitioned out of `Reserved` (i.e.
    ///     committed, aborted, or leaked) — the new variant from
    ///     br-asupersync-qrt5gw.
    ///   * Otherwise transitions to `Aborted` and returns `Ok(duration)`.
    ///
    /// Stats accounting matches `abort_by_id` exactly:
    /// `total_aborted += 1` and `pending -= 1` only on the successful
    /// transition path. The three error paths touch neither counter, so the
    /// ledger's `LedgerStats::is_clean()` invariant is preserved across racy
    /// callers.
    pub fn try_abort_by_id(
        &mut self,
        id: ObligationId,
        now: Time,
        reason: ObligationAbortReason,
    ) -> Result<u64, LedgerError> {
        let Some(record_state_and_region) = self.obligations.get(&id).map(|r| (r.state, r.region))
        else {
            return Err(LedgerError::NotFound { obligation: id });
        };
        let (state, region) = record_state_and_region;
        if self.finalized_regions.contains(&region) {
            return Err(LedgerError::RegionFinalized {
                region,
                obligation: id,
            });
        }
        if state != ObligationState::Reserved {
            return Err(LedgerError::AlreadyResolved {
                obligation: id,
                state,
            });
        }
        self.resolve_id(
            id,
            "try_abort_by_id",
            ObligationResolution::Abort(reason),
            now,
        )
    }

    /// Marks an obligation as leaked (runtime detected the holder completed
    /// without resolving).
    ///
    /// # Panics
    ///
    /// Panics if the obligation was already resolved or does not exist.
    pub fn mark_leaked(&mut self, id: ObligationId, now: Time) -> u64 {
        self.resolve_id(id, "mark_leaked", ObligationResolution::Leak, now)
            .unwrap_or_else(|err| panic!("mark_leaked: {err}"))
    }

    /// Returns the current ledger statistics.
    #[must_use]
    pub fn stats(&self) -> LedgerStats {
        self.stats
    }

    /// Returns the number of currently pending obligations.
    #[must_use]
    pub fn pending_count(&self) -> u64 {
        self.stats.pending
    }

    /// Returns counts across all obligations in deterministic ledger order.
    ///
    /// # Examples
    ///
    /// ```
    /// use asupersync::obligation::ledger::ObligationLedger;
    /// use asupersync::record::ObligationKind;
    /// use asupersync::types::{RegionId, TaskId, Time};
    ///
    /// let mut ledger = ObligationLedger::new();
    /// let task = TaskId::testing_default();
    /// let region = RegionId::testing_default();
    ///
    /// let _lease = ledger.acquire(ObligationKind::Lease, task, region, Time::from_nanos(10));
    /// let ack = ledger.acquire(ObligationKind::Ack, task, region, Time::from_nanos(20));
    /// ledger.commit(ack, Time::from_nanos(30));
    ///
    /// assert_eq!(ledger.counts().total(), 2);
    /// assert_eq!(ledger.counts_for_region(region).pending, 1);
    /// assert_eq!(ledger.counts_for_task(task).total(), 2);
    /// assert_eq!(ledger.counts_for_kind(ObligationKind::Ack).committed, 1);
    /// assert_eq!(
    ///     ledger
    ///         .counts_for_region_and_kind(region, ObligationKind::Lease)
    ///         .pending,
    ///     1
    /// );
    /// ```
    #[must_use]
    pub fn counts(&self) -> ObligationCounts {
        ObligationCounts::from_records(self.obligations.values())
    }

    /// Returns counts for obligations belonging to `region`.
    #[must_use]
    pub fn counts_for_region(&self, region: RegionId) -> ObligationCounts {
        ObligationCounts::from_records(
            self.obligations
                .values()
                .filter(|record| record.region == region),
        )
    }

    /// Returns counts for obligations held by `task`.
    #[must_use]
    pub fn counts_for_task(&self, task: TaskId) -> ObligationCounts {
        ObligationCounts::from_records(
            self.obligations
                .values()
                .filter(|record| record.holder == task),
        )
    }

    /// Returns counts for obligations of `kind`.
    #[must_use]
    pub fn counts_for_kind(&self, kind: ObligationKind) -> ObligationCounts {
        ObligationCounts::from_records(
            self.obligations
                .values()
                .filter(|record| record.kind == kind),
        )
    }

    /// Returns counts for obligations matching both `region` and `kind`.
    #[must_use]
    pub fn counts_for_region_and_kind(
        &self,
        region: RegionId,
        kind: ObligationKind,
    ) -> ObligationCounts {
        ObligationCounts::from_records(
            self.obligations
                .values()
                .filter(|record| record.region == region && record.kind == kind),
        )
    }

    /// Returns the lifecycle state for `id`, if it is known to this ledger.
    ///
    /// # Examples
    ///
    /// ```
    /// use asupersync::obligation::ledger::ObligationLedger;
    /// use asupersync::record::{ObligationKind, ObligationState};
    /// use asupersync::types::{RegionId, TaskId, Time};
    ///
    /// let mut ledger = ObligationLedger::new();
    /// let task = TaskId::testing_default();
    /// let region = RegionId::testing_default();
    /// let token = ledger.acquire(ObligationKind::Lease, task, region, Time::from_nanos(10));
    /// let id = token.id();
    ///
    /// assert_eq!(ledger.obligation_state(id), Some(ObligationState::Reserved));
    /// ```
    #[must_use]
    pub fn obligation_state(&self, id: ObligationId) -> Option<ObligationState> {
        self.obligations.get(&id).map(|record| record.state)
    }

    /// Returns owned audit snapshots for every obligation.
    ///
    /// Results are ordered by [`ObligationId`] for deterministic diagnostics.
    ///
    /// # Examples
    ///
    /// ```
    /// use asupersync::obligation::ledger::ObligationLedger;
    /// use asupersync::record::ObligationKind;
    /// use asupersync::types::{RegionId, TaskId, Time};
    ///
    /// let mut ledger = ObligationLedger::new();
    /// let task = TaskId::testing_default();
    /// let region = RegionId::testing_default();
    /// let _lease = ledger.acquire(ObligationKind::Lease, task, region, Time::from_nanos(10));
    /// let _ack = ledger.acquire(ObligationKind::Ack, task, region, Time::from_nanos(20));
    ///
    /// assert_eq!(ledger.audit(Time::from_nanos(30)).len(), 2);
    /// assert_eq!(ledger.audit_region(region, Time::from_nanos(30)).len(), 2);
    /// assert_eq!(ledger.audit_task(task, Time::from_nanos(30)).len(), 2);
    /// assert_eq!(ledger.audit_kind(ObligationKind::Lease, Time::from_nanos(30)).len(), 1);
    /// ```
    #[must_use]
    pub fn audit(&self, now: Time) -> Vec<ObligationAuditRecord> {
        self.obligations
            .values()
            .map(|record| ObligationAuditRecord::from_record(record, now))
            .collect()
    }

    /// Returns owned audit snapshots for obligations belonging to `region`.
    ///
    /// Results are ordered by [`ObligationId`] for deterministic diagnostics.
    #[must_use]
    pub fn audit_region(&self, region: RegionId, now: Time) -> Vec<ObligationAuditRecord> {
        self.obligations
            .values()
            .filter(|record| record.region == region)
            .map(|record| ObligationAuditRecord::from_record(record, now))
            .collect()
    }

    /// Returns owned audit snapshots for obligations held by `task`.
    ///
    /// Results are ordered by [`ObligationId`] for deterministic diagnostics.
    #[must_use]
    pub fn audit_task(&self, task: TaskId, now: Time) -> Vec<ObligationAuditRecord> {
        self.obligations
            .values()
            .filter(|record| record.holder == task)
            .map(|record| ObligationAuditRecord::from_record(record, now))
            .collect()
    }

    /// Returns owned audit snapshots for obligations of `kind`.
    ///
    /// Results are ordered by [`ObligationId`] for deterministic diagnostics.
    #[must_use]
    pub fn audit_kind(&self, kind: ObligationKind, now: Time) -> Vec<ObligationAuditRecord> {
        self.obligations
            .values()
            .filter(|record| record.kind == kind)
            .map(|record| ObligationAuditRecord::from_record(record, now))
            .collect()
    }

    /// Returns the number of pending obligations for a specific region.
    #[must_use]
    pub fn pending_for_region(&self, region: RegionId) -> usize {
        self.obligations
            .values()
            .filter(|o| o.region == region && o.state == ObligationState::Reserved) // ubs:ignore - enum equality, not a secret
            .count()
    }

    /// Returns the number of pending obligations for a specific task.
    #[must_use]
    pub fn pending_for_task(&self, task: TaskId) -> usize {
        self.obligations
            .values()
            .filter(|o| o.holder == task && o.state == ObligationState::Reserved)
            .count()
    }

    /// Returns IDs of all pending obligations for a region.
    ///
    /// Callers performing cancellation drain can feed the returned IDs into
    /// [`abort_by_id`](Self::abort_by_id) to resolve them deterministically
    /// without needing to recover the original linear tokens.
    #[must_use]
    pub fn pending_ids_for_region(&self, region: RegionId) -> Vec<ObligationId> {
        self.obligations
            .iter()
            .filter(|(_, o)| o.region == region && o.state == ObligationState::Reserved)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Aborts every obligation pending in `region` at the start of the drain.
    ///
    /// This is the cross-module synchronization point for cancellation and
    /// cleanup paths: callers do not need to recover each original linear token
    /// or open-code the `pending_ids_for_region` + `try_abort_by_id` sequence.
    /// The initial ID snapshot is deterministic, so lab/runtime traces are
    /// stable across equivalent schedules.
    #[must_use]
    pub fn abort_pending_for_region(
        &mut self,
        region: RegionId,
        now: Time,
        reason: ObligationAbortReason,
    ) -> RegionObligationDrain {
        let pending = self.pending_ids_for_region(region);
        let mut summary = RegionObligationDrain {
            pending_observed: pending.len(),
            ..RegionObligationDrain::default()
        };

        if self.finalized_regions.contains(&region) {
            summary.finalized = pending.len();
            return summary;
        }

        for id in pending {
            match self.try_abort_by_id(id, now, reason) {
                Ok(_) => summary.aborted += 1,
                Err(LedgerError::AlreadyResolved { .. }) => summary.already_resolved += 1,
                Err(LedgerError::NotFound { .. }) => summary.missing += 1,
                Err(LedgerError::RegionFinalized { .. }) => summary.finalized += 1,
                Err(LedgerError::NotPending { .. }) => summary.already_resolved += 1,
                Err(LedgerError::TokenMismatch { .. }) => summary.missing += 1,
                Err(LedgerError::StatsUnderflow { .. }) => summary.missing += 1,
                Err(LedgerError::AcquireAfterFinalize { .. }) => summary.finalized += 1,
                Err(LedgerError::IndexOverflow { .. }) => summary.missing += 1,
                Err(LedgerError::GenerationOverflow) => summary.missing += 1,
            }
        }

        debug_assert!(
            summary.is_complete(),
            "region obligation drain summary must account for every observed obligation"
        );
        summary
    }

    /// Returns true if the region has no pending obligations (quiescence check).
    #[must_use]
    pub fn is_region_clean(&self, region: RegionId) -> bool {
        self.pending_for_region(region) == 0
    }

    /// Checks all obligations for leaks.
    ///
    /// Returns a deterministic leak report. In lab mode, the test should fail
    /// if leaks are found.
    #[must_use]
    pub fn check_leaks(&self) -> LeakCheckResult {
        let leaked: Vec<LeakedObligation> = self
            .obligations
            .iter()
            .filter(|(_, o)| o.is_pending() || o.is_leaked())
            .map(|(_, o)| LeakedObligation {
                id: o.id,
                kind: o.kind,
                holder: o.holder,
                region: o.region,
                reserved_at: o.reserved_at,
                description: o.description.clone(),
                acquired_at: o.acquired_at,
            })
            .collect();

        LeakCheckResult { leaked }
    }

    /// Checks for leaks in a specific region.
    #[must_use]
    pub fn check_region_leaks(&self, region: RegionId) -> LeakCheckResult {
        let leaked: Vec<LeakedObligation> = self
            .obligations
            .iter()
            .filter(|(_, o)| o.region == region && (o.is_pending() || o.is_leaked()))
            .map(|(_, o)| LeakedObligation {
                id: o.id,
                kind: o.kind,
                holder: o.holder,
                region: o.region,
                reserved_at: o.reserved_at,
                description: o.description.clone(),
                acquired_at: o.acquired_at,
            })
            .collect();

        LeakCheckResult { leaked }
    }

    /// Returns a reference to an obligation record by ID.
    #[must_use]
    pub fn get(&self, id: ObligationId) -> Option<&ObligationRecord> {
        self.obligations.get(&id)
    }

    /// Returns the total number of obligations (all states).
    #[must_use]
    pub fn len(&self) -> usize {
        self.obligations.len()
    }

    /// Returns true if the ledger has no obligations at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.obligations.is_empty()
    }

    /// Resets the ledger to empty state.
    ///
    /// # Panics
    ///
    /// Panics if any obligations are still pending or leaked. Reset is only
    /// valid once every obligation has been resolved cleanly (committed or
    /// aborted); otherwise it would silently hide active obligations or erase
    /// leak diagnostics.
    ///
    /// Reset clears the live set, rewinds slot allocation back to index `0`,
    /// and bumps the ledger generation. Post-reset obligations can therefore
    /// reuse compact index space without allowing stale pre-reset IDs or
    /// tokens to resolve newly allocated records.
    pub fn reset(&mut self) {
        assert!(
            !self.obligations.values().any(ObligationRecord::is_pending),
            "cannot reset obligation ledger with pending obligations"
        );
        assert!(
            !self.obligations.values().any(ObligationRecord::is_leaked),
            "cannot reset obligation ledger with leaked obligations"
        );
        self.obligations.clear();
        self.resolved_order.clear();
        self.finalized_regions.clear();
        self.stats = LedgerStats::default();
        self.next_index = 0;
        self.generation = self
            .generation
            .checked_add(1)
            .expect("obligation ledger generation overflow");
    }

    /// Iterates over all obligations in deterministic order.
    pub fn iter(&self) -> impl Iterator<Item = (&ObligationId, &ObligationRecord)> {
        self.obligations.iter()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[path = "ledger_inline_tests.rs"]
mod tests;
