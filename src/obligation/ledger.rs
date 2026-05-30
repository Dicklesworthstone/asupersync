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
use std::collections::{BTreeMap, BTreeSet};

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
        Ok(duration)
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
    pub fn try_commit(&mut self, token: ObligationToken, now: Time) -> Result<u64, LedgerError> {
        if self.finalized_regions.contains(&token.region) {
            return Err(LedgerError::RegionFinalized {
                region: token.region,
                obligation: token.id,
            });
        }
        Ok(self.commit(token, now))
    }

    /// br-asupersync-qyf37e: fallible variant of [`Self::abort`].
    /// See [`Self::try_commit`] for the contract.
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
        Ok(self.abort(token, now, reason))
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
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::record::ObligationKind;
    use crate::util::ArenaIndex;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn make_task() -> TaskId {
        TaskId::from_arena(ArenaIndex::new(1, 0))
    }

    fn make_region() -> RegionId {
        RegionId::from_arena(ArenaIndex::new(0, 0))
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct LedgerObservation {
        stats: LedgerStats,
        len: usize,
        pending_count: u64,
        pending_for_region: usize,
        pending_for_task: usize,
        pending_ids_for_region: usize,
        region_clean: bool,
        leak_count: usize,
        region_leak_count: usize,
    }

    fn observe_ledger(
        ledger: &ObligationLedger,
        task: TaskId,
        region: RegionId,
    ) -> LedgerObservation {
        LedgerObservation {
            stats: ledger.stats(),
            len: ledger.len(),
            pending_count: ledger.pending_count(),
            pending_for_region: ledger.pending_for_region(region),
            pending_for_task: ledger.pending_for_task(task),
            pending_ids_for_region: ledger.pending_ids_for_region(region).len(),
            region_clean: ledger.is_region_clean(region),
            leak_count: ledger.check_leaks().leaked.len(),
            region_leak_count: ledger.check_region_leaks(region).leaked.len(),
        }
    }

    // ---- Basic lifecycle ---------------------------------------------------

    #[test]
    fn acquire_commit_clean() {
        init_test("acquire_commit_clean");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let token = ledger.acquire(
            ObligationKind::SendPermit,
            task,
            region,
            Time::from_nanos(10),
        );
        let pending = ledger.pending_count();
        crate::assert_with_log!(pending == 1, "pending", 1, pending);

        let duration = ledger.commit(token, Time::from_nanos(25));
        crate::assert_with_log!(duration == 15, "duration", 15, duration);

        let pending = ledger.pending_count();
        crate::assert_with_log!(pending == 0, "pending after commit", 0, pending);

        let stats = ledger.stats();
        crate::assert_with_log!(stats.is_clean(), "clean", true, stats.is_clean());
        crate::assert_with_log!(
            stats.total_acquired == 1,
            "acquired",
            1,
            stats.total_acquired
        );
        crate::assert_with_log!(
            stats.total_committed == 1,
            "committed",
            1,
            stats.total_committed
        );
        crate::test_complete!("acquire_commit_clean");
    }

    #[test]
    fn acquire_abort_clean() {
        init_test("acquire_abort_clean");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let token = ledger.acquire(ObligationKind::Ack, task, region, Time::from_nanos(5));
        let duration = ledger.abort(token, Time::from_nanos(10), ObligationAbortReason::Cancel);
        crate::assert_with_log!(duration == 5, "duration", 5, duration);

        let stats = ledger.stats();
        crate::assert_with_log!(stats.is_clean(), "clean", true, stats.is_clean());
        crate::assert_with_log!(stats.total_aborted == 1, "aborted", 1, stats.total_aborted);
        crate::test_complete!("acquire_abort_clean");
    }

    // ---- Leak detection ---------------------------------------------------

    #[test]
    fn leak_check_detects_pending() {
        init_test("leak_check_detects_pending");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let _token = ledger.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        // Intentionally not resolving — simulate a lost token.

        let result = ledger.check_leaks();
        let is_clean = result.is_clean();
        crate::assert_with_log!(!is_clean, "not clean", false, is_clean);
        let len = result.leaked.len();
        crate::assert_with_log!(len == 1, "leaked count", 1, len);
        let kind = result.leaked[0].kind;
        crate::assert_with_log!(
            kind == ObligationKind::Lease,
            "leaked kind",
            ObligationKind::Lease,
            kind
        );
        crate::test_complete!("leak_check_detects_pending");
    }

    #[test]
    fn leak_check_clean_after_resolve() {
        init_test("leak_check_clean_after_resolve");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let t1 = ledger.acquire(ObligationKind::SendPermit, task, region, Time::ZERO);
        let t2 = ledger.acquire(ObligationKind::Ack, task, region, Time::ZERO);

        ledger.commit(t1, Time::from_nanos(1));
        ledger.abort(t2, Time::from_nanos(1), ObligationAbortReason::Explicit);

        let result = ledger.check_leaks();
        crate::assert_with_log!(result.is_clean(), "clean", true, result.is_clean());
        crate::test_complete!("leak_check_clean_after_resolve");
    }

    // ---- Region queries ---------------------------------------------------

    #[test]
    fn pending_for_region() {
        init_test("pending_for_region");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let r1 = RegionId::from_arena(ArenaIndex::new(0, 0));
        let r2 = RegionId::from_arena(ArenaIndex::new(1, 0));

        let _t1 = ledger.acquire(ObligationKind::SendPermit, task, r1, Time::ZERO);
        let _t2 = ledger.acquire(ObligationKind::Ack, task, r1, Time::ZERO);
        let _t3 = ledger.acquire(ObligationKind::Lease, task, r2, Time::ZERO);

        let r1_pending = ledger.pending_for_region(r1);
        crate::assert_with_log!(r1_pending == 2, "r1 pending", 2, r1_pending);

        let r2_pending = ledger.pending_for_region(r2);
        crate::assert_with_log!(r2_pending == 1, "r2 pending", 1, r2_pending);

        let r1_clean = ledger.is_region_clean(r1);
        crate::assert_with_log!(!r1_clean, "r1 not clean", false, r1_clean);
        crate::test_complete!("pending_for_region");
    }

    #[test]
    fn pending_ids_for_region_returns_sorted() {
        init_test("pending_ids_for_region_returns_sorted");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let t1 = ledger.acquire(ObligationKind::SendPermit, task, region, Time::ZERO);
        let t2 = ledger.acquire(ObligationKind::Ack, task, region, Time::ZERO);

        let ids = ledger.pending_ids_for_region(region);
        crate::assert_with_log!(ids.len() == 2, "ids len", 2, ids.len());
        // BTreeMap ensures deterministic order.
        crate::assert_with_log!(ids[0] == t1.id(), "first id", t1.id(), ids[0]);
        crate::assert_with_log!(ids[1] == t2.id(), "second id", t2.id(), ids[1]);

        crate::test_complete!("pending_ids_for_region_returns_sorted");
    }

    // ---- Mark leaked -----------------------------------------------------

    #[test]
    fn mark_leaked_updates_stats() {
        init_test("mark_leaked_updates_stats");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let token = ledger.acquire(ObligationKind::IoOp, task, region, Time::from_nanos(0));
        let id = token.id();
        // Intentionally not resolving token; mark as leaked below.

        ledger.mark_leaked(id, Time::from_nanos(100));

        let stats = ledger.stats();
        crate::assert_with_log!(!stats.is_clean(), "not clean", false, stats.is_clean());
        crate::assert_with_log!(stats.total_leaked == 1, "leaked", 1, stats.total_leaked);
        crate::assert_with_log!(stats.pending == 0, "pending", 0, stats.pending);
        crate::test_complete!("mark_leaked_updates_stats");
    }

    #[test]
    fn check_leaks_includes_marked_leaked_obligations() {
        init_test("check_leaks_includes_marked_leaked_obligations");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let token = ledger.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        let leaked_id = token.id();
        ledger.mark_leaked(leaked_id, Time::from_nanos(10));

        let result = ledger.check_leaks();
        crate::assert_with_log!(!result.is_clean(), "not clean", false, result.is_clean());
        crate::assert_with_log!(
            result.leaked.len() == 1,
            "leak count",
            1,
            result.leaked.len()
        );
        crate::assert_with_log!(
            result.leaked[0].id == leaked_id,
            "leaked id",
            leaked_id,
            result.leaked[0].id
        );
        crate::test_complete!("check_leaks_includes_marked_leaked_obligations");
    }

    // ---- Task queries ----------------------------------------------------

    #[test]
    fn pending_for_task() {
        init_test("pending_for_task");
        let mut ledger = ObligationLedger::new();
        let t1 = TaskId::from_arena(ArenaIndex::new(0, 0));
        let t2 = TaskId::from_arena(ArenaIndex::new(1, 0));
        let region = make_region();

        let _tok1 = ledger.acquire(ObligationKind::SendPermit, t1, region, Time::ZERO);
        let _tok2 = ledger.acquire(ObligationKind::Ack, t1, region, Time::ZERO);
        let _tok3 = ledger.acquire(ObligationKind::Lease, t2, region, Time::ZERO);

        let t1_pending = ledger.pending_for_task(t1);
        crate::assert_with_log!(t1_pending == 2, "t1 pending", 2, t1_pending);

        let t2_pending = ledger.pending_for_task(t2);
        crate::assert_with_log!(t2_pending == 1, "t2 pending", 1, t2_pending);

        crate::test_complete!("pending_for_task");
    }

    // ---- Region leak check -----------------------------------------------

    #[test]
    fn check_region_leaks_scoped() {
        init_test("check_region_leaks_scoped");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let r1 = RegionId::from_arena(ArenaIndex::new(0, 0));
        let r2 = RegionId::from_arena(ArenaIndex::new(1, 0));

        let _t1 = ledger.acquire(ObligationKind::SendPermit, task, r1, Time::ZERO);
        let t2 = ledger.acquire(ObligationKind::Ack, task, r2, Time::ZERO);
        ledger.commit(t2, Time::from_nanos(1));

        let r1_result = ledger.check_region_leaks(r1);
        crate::assert_with_log!(
            !r1_result.is_clean(),
            "r1 leaks",
            false,
            r1_result.is_clean()
        );

        let r2_result = ledger.check_region_leaks(r2);
        crate::assert_with_log!(r2_result.is_clean(), "r2 clean", true, r2_result.is_clean());

        crate::test_complete!("check_region_leaks_scoped");
    }

    // ---- Empty ledger is clean -------------------------------------------

    #[test]
    fn empty_ledger_is_clean() {
        init_test("empty_ledger_is_clean");
        let ledger = ObligationLedger::new();
        let result = ledger.check_leaks();
        crate::assert_with_log!(result.is_clean(), "clean", true, result.is_clean());
        crate::assert_with_log!(ledger.is_empty(), "empty", true, ledger.is_empty());
        let len = ledger.len();
        crate::assert_with_log!(len == 0, "len", 0, len);
        crate::test_complete!("empty_ledger_is_clean");
    }

    // ---- Reset -----------------------------------------------------------

    #[test]
    fn reset_clears_everything() {
        init_test("reset_clears_everything");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let token = ledger.acquire(ObligationKind::SendPermit, task, region, Time::ZERO);
        ledger.commit(token, Time::from_nanos(1));

        crate::assert_with_log!(ledger.len() == 1, "len before reset", 1, ledger.len());
        ledger.reset();
        crate::assert_with_log!(
            ledger.is_empty(),
            "empty after reset",
            true,
            ledger.is_empty()
        );
        let stats = ledger.stats();
        crate::assert_with_log!(
            stats.total_acquired == 0,
            "acquired",
            0,
            stats.total_acquired
        );
        crate::test_complete!("reset_clears_everything");
    }

    #[test]
    fn reset_panics_if_pending_obligation_exists() {
        init_test("reset_panics_if_pending_obligation_exists");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let stale = ledger.acquire(ObligationKind::SendPermit, task, region, Time::ZERO);
        let stale_id = stale.id();

        let reset = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| ledger.reset()));
        crate::assert_with_log!(reset.is_err(), "reset rejected", true, reset.is_err());

        let pending = ledger.pending_count();
        crate::assert_with_log!(pending == 1, "pending preserved", 1, pending);

        let leaks = ledger.check_leaks();
        crate::assert_with_log!(
            !leaks.is_clean(),
            "leak report still non-clean",
            false,
            leaks.is_clean()
        );
        crate::assert_with_log!(leaks.leaked.len() == 1, "leak count", 1, leaks.leaked.len());
        crate::assert_with_log!(
            leaks.leaked[0].id == stale_id,
            "stale id tracked",
            stale_id,
            leaks.leaked[0].id
        );

        let region_leaks = ledger.check_region_leaks(region);
        crate::assert_with_log!(
            !region_leaks.is_clean(),
            "region leak report still non-clean",
            false,
            region_leaks.is_clean()
        );

        ledger.commit(stale, Time::from_nanos(2));
        crate::test_complete!("reset_panics_if_pending_obligation_exists");
    }

    #[test]
    fn reset_panics_if_leaked_obligation_exists() {
        init_test("reset_panics_if_leaked_obligation_exists");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let leaked = ledger.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        let leaked_id = leaked.id();
        ledger.mark_leaked(leaked_id, Time::from_nanos(5));

        let reset = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| ledger.reset()));
        crate::assert_with_log!(reset.is_err(), "reset rejected", true, reset.is_err());

        let stats = ledger.stats();
        crate::assert_with_log!(stats.pending == 0, "pending preserved", 0, stats.pending);
        crate::assert_with_log!(
            stats.total_leaked == 1,
            "leaked preserved",
            1,
            stats.total_leaked
        );
        crate::assert_with_log!(
            !stats.is_clean(),
            "still not clean",
            false,
            stats.is_clean()
        );

        let leaks = ledger.check_leaks();
        crate::assert_with_log!(
            !leaks.is_clean(),
            "leak report still non-clean",
            false,
            leaks.is_clean()
        );
        crate::assert_with_log!(leaks.leaked.len() == 1, "leak count", 1, leaks.leaked.len());
        crate::assert_with_log!(
            leaks.leaked[0].id == leaked_id,
            "leaked id tracked",
            leaked_id,
            leaks.leaked[0].id
        );
        crate::test_complete!("reset_panics_if_leaked_obligation_exists");
    }

    #[test]
    fn reset_reuses_index_with_bumped_generation() {
        init_test("reset_reuses_index_with_bumped_generation");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let old = ledger.acquire(ObligationKind::SendPermit, task, region, Time::ZERO);
        let old_id = old.id();
        let old_idx = old_id.arena_index();
        ledger.commit(old, Time::from_nanos(1));

        ledger.reset();

        let fresh = ledger.acquire(ObligationKind::Ack, task, region, Time::from_nanos(2));
        let fresh_idx = fresh.id().arena_index();
        crate::assert_with_log!(
            fresh.id() != old_id,
            "fresh id differs",
            true,
            fresh.id() != old_id
        );
        crate::assert_with_log!(
            fresh_idx.index() == old_idx.index(),
            "index reused after clean reset",
            old_idx.index(),
            fresh_idx.index()
        );
        crate::assert_with_log!(
            fresh_idx.generation() == old_idx.generation().saturating_add(1),
            "generation bumped after clean reset",
            old_idx.generation().saturating_add(1),
            fresh_idx.generation()
        );

        ledger.commit(fresh, Time::from_nanos(3));
        crate::test_complete!("reset_reuses_index_with_bumped_generation");
    }

    #[test]
    fn reset_clears_finalized_region_fence() {
        init_test("reset_clears_finalized_region_fence");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let token = ledger.acquire(ObligationKind::SendPermit, task, region, Time::ZERO);
        ledger.commit(token, Time::from_nanos(1));
        ledger.mark_region_finalized(region);
        crate::assert_with_log!(
            ledger.is_region_finalized(region),
            "region finalized before reset",
            true,
            ledger.is_region_finalized(region)
        );

        ledger.reset();

        crate::assert_with_log!(
            !ledger.is_region_finalized(region),
            "reset clears finalized region fence",
            false,
            ledger.is_region_finalized(region)
        );

        let fresh = ledger
            .try_acquire(ObligationKind::Ack, task, region, Time::from_nanos(2))
            .expect("reset must allow fresh acquire for the same region id");
        crate::assert_with_log!(
            ledger.pending_count() == 1,
            "fresh acquire allowed after reset",
            1,
            ledger.pending_count()
        );
        ledger.commit(fresh, Time::from_nanos(3));

        crate::test_complete!("reset_clears_finalized_region_fence");
    }

    #[test]
    fn stale_id_from_previous_generation_cannot_touch_post_reset_obligation() {
        init_test("stale_id_from_previous_generation_cannot_touch_post_reset_obligation");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let stale = ledger.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        let stale_id = stale.id();
        ledger.abort_by_id(
            stale_id,
            Time::from_nanos(10),
            ObligationAbortReason::Cancel,
        );

        ledger.reset();

        let fresh = ledger.acquire(ObligationKind::Lease, task, region, Time::from_nanos(20));
        let fresh_id = fresh.id();
        let fresh_idx = fresh_id.arena_index();
        let stale_idx = stale_id.arena_index();
        crate::assert_with_log!(
            fresh_idx.index() == stale_idx.index(),
            "slot index reused",
            stale_idx.index(),
            fresh_idx.index()
        );
        crate::assert_with_log!(
            fresh_idx.generation() != stale_idx.generation(),
            "generation differs",
            true,
            fresh_idx.generation() != stale_idx.generation()
        );

        let stale_abort = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ledger.abort_by_id(
                stale_id,
                Time::from_nanos(30),
                ObligationAbortReason::Cancel,
            )
        }));
        crate::assert_with_log!(
            stale_abort.is_err(),
            "stale id rejected",
            true,
            stale_abort.is_err()
        );

        let fresh_record = ledger.get(fresh_id).expect("fresh obligation exists");
        crate::assert_with_log!(
            fresh_record.is_pending(),
            "fresh obligation remains pending",
            true,
            fresh_record.is_pending()
        );

        ledger.commit(fresh, Time::from_nanos(40));
        crate::test_complete!(
            "stale_id_from_previous_generation_cannot_touch_post_reset_obligation"
        );
    }

    #[test]
    fn metamorphic_reset_advances_generation_monotonically() {
        init_test("metamorphic_reset_advances_generation_monotonically");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let first = ledger.acquire(
            ObligationKind::SendPermit,
            task,
            region,
            Time::from_nanos(1),
        );
        let first_idx = first.id().arena_index();
        ledger.commit(first, Time::from_nanos(2));
        ledger.reset();

        let second = ledger.acquire(
            ObligationKind::SendPermit,
            task,
            region,
            Time::from_nanos(3),
        );
        let second_idx = second.id().arena_index();
        ledger.commit(second, Time::from_nanos(4));
        ledger.reset();

        let third = ledger.acquire(
            ObligationKind::SendPermit,
            task,
            region,
            Time::from_nanos(5),
        );
        let third_idx = third.id().arena_index();
        ledger.commit(third, Time::from_nanos(6));

        crate::assert_with_log!(
            first_idx.index() == second_idx.index(),
            "reset reuses slot after first epoch",
            first_idx.index(),
            second_idx.index()
        );
        crate::assert_with_log!(
            second_idx.index() == third_idx.index(),
            "reset reuses slot after second epoch",
            second_idx.index(),
            third_idx.index()
        );
        crate::assert_with_log!(
            second_idx.generation() == first_idx.generation().saturating_add(1),
            "first reset bumps generation by one",
            first_idx.generation().saturating_add(1),
            second_idx.generation()
        );
        crate::assert_with_log!(
            third_idx.generation() == second_idx.generation().saturating_add(1),
            "second reset bumps generation by one",
            second_idx.generation().saturating_add(1),
            third_idx.generation()
        );

        crate::test_complete!("metamorphic_reset_advances_generation_monotonically");
    }

    #[test]
    fn metamorphic_post_reset_commit_matches_fresh_epoch_observables() {
        init_test("metamorphic_post_reset_commit_matches_fresh_epoch_observables");
        let task = make_task();
        let region = make_region();

        let mut fresh = ObligationLedger::new();
        let fresh_token = fresh.acquire(ObligationKind::Ack, task, region, Time::from_nanos(10));
        let fresh_idx = fresh_token.id().arena_index();
        fresh.commit(fresh_token, Time::from_nanos(20));
        let fresh_observation = observe_ledger(&fresh, task, region);

        let mut recycled = ObligationLedger::new();
        let old = recycled.acquire(ObligationKind::Lease, task, region, Time::from_nanos(1));
        recycled.abort(old, Time::from_nanos(2), ObligationAbortReason::Cancel);
        recycled.reset();

        let recycled_token =
            recycled.acquire(ObligationKind::Ack, task, region, Time::from_nanos(10));
        let recycled_idx = recycled_token.id().arena_index();
        recycled.commit(recycled_token, Time::from_nanos(20));
        let recycled_observation = observe_ledger(&recycled, task, region);

        crate::assert_with_log!(
            fresh_observation == recycled_observation,
            "post-reset epoch observables match fresh epoch",
            fresh_observation,
            recycled_observation
        );
        crate::assert_with_log!(
            recycled_idx.index() == fresh_idx.index(),
            "post-reset epoch rewinds slot allocation",
            fresh_idx.index(),
            recycled_idx.index()
        );
        crate::assert_with_log!(
            recycled_idx.generation() == fresh_idx.generation().saturating_add(1),
            "post-reset epoch bumps generation",
            fresh_idx.generation().saturating_add(1),
            recycled_idx.generation()
        );

        crate::test_complete!("metamorphic_post_reset_commit_matches_fresh_epoch_observables");
    }

    #[test]
    fn metamorphic_stale_token_after_reset_matches_drop_before_reset_round_trip() {
        init_test("metamorphic_stale_token_after_reset_matches_drop_before_reset_round_trip");
        let task = make_task();
        let region = make_region();

        let mut baseline = ObligationLedger::new();
        let baseline_stale =
            baseline.acquire(ObligationKind::Lease, task, region, Time::from_nanos(1));
        let baseline_stale_id = baseline_stale.id();
        baseline.abort_by_id(
            baseline_stale_id,
            Time::from_nanos(2),
            ObligationAbortReason::Cancel,
        );
        drop(baseline_stale);
        baseline.reset();

        let baseline_fresh =
            baseline.acquire(ObligationKind::Ack, task, region, Time::from_nanos(10));
        let baseline_fresh_id = baseline_fresh.id();
        baseline.commit(baseline_fresh, Time::from_nanos(20));
        let baseline_observation = observe_ledger(&baseline, task, region);
        let baseline_resolution = observable_resolution_state(&baseline, baseline_fresh_id);

        let mut commit_replay = ObligationLedger::new();
        let stale_commit =
            commit_replay.acquire(ObligationKind::Lease, task, region, Time::from_nanos(1));
        let stale_commit_id = stale_commit.id();
        commit_replay.abort_by_id(
            stale_commit_id,
            Time::from_nanos(2),
            ObligationAbortReason::Cancel,
        );
        commit_replay.reset();

        let commit_fresh =
            commit_replay.acquire(ObligationKind::Ack, task, region, Time::from_nanos(10));
        let commit_fresh_id = commit_fresh.id();
        commit_replay.commit(commit_fresh, Time::from_nanos(20));
        let stale_commit_replay = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            commit_replay.commit(stale_commit, Time::from_nanos(21))
        }));
        crate::assert_with_log!(
            stale_commit_replay.is_err(),
            "stale commit replay rejected after reset",
            true,
            stale_commit_replay.is_err()
        );
        crate::assert_with_log!(
            observable_resolution_state(&commit_replay, commit_fresh_id) == baseline_resolution,
            "stale commit replay preserves fresh terminal observables",
            baseline_resolution,
            observable_resolution_state(&commit_replay, commit_fresh_id)
        );
        crate::assert_with_log!(
            observe_ledger(&commit_replay, task, region) == baseline_observation,
            "stale commit replay preserves ledger observation",
            baseline_observation,
            observe_ledger(&commit_replay, task, region)
        );

        let mut abort_replay = ObligationLedger::new();
        let stale_abort =
            abort_replay.acquire(ObligationKind::Lease, task, region, Time::from_nanos(1));
        let stale_abort_id = stale_abort.id();
        abort_replay.abort_by_id(
            stale_abort_id,
            Time::from_nanos(2),
            ObligationAbortReason::Cancel,
        );
        abort_replay.reset();

        let abort_fresh =
            abort_replay.acquire(ObligationKind::Ack, task, region, Time::from_nanos(10));
        let abort_fresh_id = abort_fresh.id();
        abort_replay.commit(abort_fresh, Time::from_nanos(20));
        let stale_abort_replay = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            abort_replay.abort(
                stale_abort,
                Time::from_nanos(21),
                ObligationAbortReason::Explicit,
            )
        }));
        crate::assert_with_log!(
            stale_abort_replay.is_err(),
            "stale abort replay rejected after reset",
            true,
            stale_abort_replay.is_err()
        );
        crate::assert_with_log!(
            observable_resolution_state(&abort_replay, abort_fresh_id) == baseline_resolution,
            "stale abort replay preserves fresh terminal observables",
            baseline_resolution,
            observable_resolution_state(&abort_replay, abort_fresh_id)
        );
        crate::assert_with_log!(
            observe_ledger(&abort_replay, task, region) == baseline_observation,
            "stale abort replay preserves ledger observation",
            baseline_observation,
            observe_ledger(&abort_replay, task, region)
        );

        crate::test_complete!(
            "metamorphic_stale_token_after_reset_matches_drop_before_reset_round_trip"
        );
    }

    #[test]
    fn metamorphic_failed_reset_then_commit_matches_commit_then_reset() {
        init_test("metamorphic_failed_reset_then_commit_matches_commit_then_reset");
        let task = make_task();
        let region = make_region();

        let mut raced = ObligationLedger::new();
        let raced_token = raced.acquire(
            ObligationKind::SendPermit,
            task,
            region,
            Time::from_nanos(100),
        );

        let early_reset = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| raced.reset()));
        crate::assert_with_log!(
            early_reset.is_err(),
            "early reset rejected",
            true,
            early_reset.is_err()
        );

        raced.commit(raced_token, Time::from_nanos(110));
        raced.reset();
        let raced_post_reset =
            raced.acquire(ObligationKind::Ack, task, region, Time::from_nanos(120));
        let raced_idx = raced_post_reset.id().arena_index();
        raced.commit(raced_post_reset, Time::from_nanos(130));
        let raced_observation = observe_ledger(&raced, task, region);

        let mut canonical = ObligationLedger::new();
        let canonical_token = canonical.acquire(
            ObligationKind::SendPermit,
            task,
            region,
            Time::from_nanos(100),
        );
        canonical.commit(canonical_token, Time::from_nanos(110));
        canonical.reset();
        let canonical_post_reset =
            canonical.acquire(ObligationKind::Ack, task, region, Time::from_nanos(120));
        let canonical_idx = canonical_post_reset.id().arena_index();
        canonical.commit(canonical_post_reset, Time::from_nanos(130));
        let canonical_observation = observe_ledger(&canonical, task, region);

        crate::assert_with_log!(
            raced_observation == canonical_observation,
            "failed reset leaves eventual epoch observables unchanged",
            canonical_observation,
            raced_observation
        );
        crate::assert_with_log!(
            raced_idx == canonical_idx,
            "failed reset does not advance generation or slot allocation",
            canonical_idx,
            raced_idx
        );

        crate::test_complete!("metamorphic_failed_reset_then_commit_matches_commit_then_reset");
    }

    // ---- Deterministic iteration -----------------------------------------

    #[test]
    fn iteration_is_deterministic() {
        init_test("iteration_is_deterministic");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        // Acquire multiple obligations.
        let t1 = ledger.acquire(ObligationKind::SendPermit, task, region, Time::ZERO);
        let t2 = ledger.acquire(ObligationKind::Ack, task, region, Time::ZERO);
        let t3 = ledger.acquire(ObligationKind::Lease, task, region, Time::ZERO);

        // Iteration order should be by ID (BTreeMap).
        let ids: Vec<ObligationId> = ledger.iter().map(|(id, _)| *id).collect();
        crate::assert_with_log!(ids.len() == 3, "len", 3, ids.len());
        // IDs are monotonically increasing since we allocate sequentially.
        crate::assert_with_log!(ids[0] == t1.id(), "first", t1.id(), ids[0]);
        crate::assert_with_log!(ids[1] == t2.id(), "second", t2.id(), ids[1]);
        crate::assert_with_log!(ids[2] == t3.id(), "third", t3.id(), ids[2]);
        crate::test_complete!("iteration_is_deterministic");
    }

    // ---- Get by ID -------------------------------------------------------

    #[test]
    fn get_by_id() {
        init_test("get_by_id");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let token = ledger.acquire(ObligationKind::IoOp, task, region, Time::from_nanos(42));
        let id = token.id();

        let record = ledger.get(id).expect("should exist");
        crate::assert_with_log!(
            record.kind == ObligationKind::IoOp,
            "kind",
            ObligationKind::IoOp,
            record.kind
        );
        crate::assert_with_log!(record.is_pending(), "pending", true, record.is_pending());

        ledger.commit(token, Time::from_nanos(50));
        let record = ledger.get(id).expect("still exists");
        crate::assert_with_log!(!record.is_pending(), "resolved", false, record.is_pending());
        crate::test_complete!("get_by_id");
    }

    // ---- Acquire with description ----------------------------------------

    #[test]
    fn acquire_with_context_captures_description() {
        init_test("acquire_with_context_captures_description");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let token = ledger.acquire_with_context(
            ObligationKind::Lease,
            task,
            region,
            Time::ZERO,
            SourceLocation::unknown(),
            None,
            Some("my lease description".to_string()),
        );
        let id = token.id();

        let record = ledger.get(id).expect("exists");
        crate::assert_with_log!(
            record.description == Some("my lease description".to_string()),
            "description",
            Some("my lease description".to_string()),
            record.description
        );

        ledger.commit(token, Time::from_nanos(1));
        crate::test_complete!("acquire_with_context_captures_description");
    }

    // ---- Multiple kinds in one ledger ------------------------------------

    #[test]
    fn multiple_obligation_kinds() {
        init_test("multiple_obligation_kinds");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let t_send = ledger.acquire(ObligationKind::SendPermit, task, region, Time::ZERO);
        let t_ack = ledger.acquire(ObligationKind::Ack, task, region, Time::ZERO);
        let t_lease = ledger.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        let t_io = ledger.acquire(ObligationKind::IoOp, task, region, Time::ZERO);

        let pending = ledger.pending_count();
        crate::assert_with_log!(pending == 4, "pending", 4, pending);

        ledger.commit(t_send, Time::from_nanos(1));
        ledger.abort(t_ack, Time::from_nanos(1), ObligationAbortReason::Cancel);
        ledger.commit(t_lease, Time::from_nanos(1));
        ledger.abort(t_io, Time::from_nanos(1), ObligationAbortReason::Error);

        let stats = ledger.stats();
        crate::assert_with_log!(
            stats.total_committed == 2,
            "committed",
            2,
            stats.total_committed
        );
        crate::assert_with_log!(stats.total_aborted == 2, "aborted", 2, stats.total_aborted);
        crate::assert_with_log!(stats.is_clean(), "clean", true, stats.is_clean());
        crate::test_complete!("multiple_obligation_kinds");
    }

    // ---- Cancel drain: abort all pending obligations for a region --------

    #[test]
    fn cancel_drain_aborts_all_region_obligations() {
        init_test("cancel_drain_aborts_all_region_obligations");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        // Simulate: task holds three obligations when cancel is requested.
        let _t1 = ledger.acquire(ObligationKind::SendPermit, task, region, Time::ZERO);
        let _t2 = ledger.acquire(ObligationKind::Ack, task, region, Time::ZERO);
        let _t3 = ledger.acquire(ObligationKind::Lease, task, region, Time::ZERO);

        let pending = ledger.pending_for_region(region);
        crate::assert_with_log!(pending == 3, "pre-drain pending", 3, pending);

        // Drain: enumerate pending IDs and abort each one.
        let drain_time = Time::from_nanos(100);
        let pending_ids = ledger.pending_ids_for_region(region);
        crate::assert_with_log!(pending_ids.len() == 3, "drain ids", 3, pending_ids.len());

        for id in &pending_ids {
            ledger.abort_by_id(*id, drain_time, ObligationAbortReason::Cancel);
        }

        // Region should now be clean.
        let is_clean = ledger.is_region_clean(region);
        crate::assert_with_log!(is_clean, "region clean after drain", true, is_clean);

        let stats = ledger.stats();
        crate::assert_with_log!(stats.pending == 0, "global pending", 0, stats.pending);
        crate::assert_with_log!(
            stats.total_aborted == 3,
            "aborted count",
            3,
            stats.total_aborted
        );
        crate::assert_with_log!(
            stats.total_leaked == 0,
            "leaked count",
            0,
            stats.total_leaked
        );
        crate::assert_with_log!(stats.is_clean(), "ledger clean", true, stats.is_clean());
        crate::test_complete!("cancel_drain_aborts_all_region_obligations");
    }

    // ---- Cancel drain: multi-task region --------------------------------

    #[test]
    fn cancel_drain_multi_task_region() {
        init_test("cancel_drain_multi_task_region");
        let mut ledger = ObligationLedger::new();
        let t1 = TaskId::from_arena(ArenaIndex::new(0, 0));
        let t2 = TaskId::from_arena(ArenaIndex::new(1, 0));
        let t3 = TaskId::from_arena(ArenaIndex::new(2, 0));
        let region = make_region();

        // Three tasks in the same region, each with an obligation.
        let tok1 = ledger.acquire(ObligationKind::SendPermit, t1, region, Time::ZERO);
        let tok2 = ledger.acquire(ObligationKind::Ack, t2, region, Time::ZERO);
        let tok3 = ledger.acquire(ObligationKind::Lease, t3, region, Time::ZERO);

        // During drain, abort all obligations in the region.
        let drain_time = Time::from_nanos(50);
        ledger.abort(tok1, drain_time, ObligationAbortReason::Cancel);
        ledger.abort(tok2, drain_time, ObligationAbortReason::Cancel);
        ledger.abort(tok3, drain_time, ObligationAbortReason::Cancel);

        let is_clean = ledger.is_region_clean(region);
        crate::assert_with_log!(is_clean, "region clean", true, is_clean);

        let stats = ledger.stats();
        crate::assert_with_log!(stats.total_aborted == 3, "aborted", 3, stats.total_aborted);
        crate::assert_with_log!(stats.is_clean(), "ledger clean", true, stats.is_clean());
        crate::test_complete!("cancel_drain_multi_task_region");
    }

    // ---- Region isolation: drain one region, other unaffected -----------

    #[test]
    fn region_isolation_during_drain() {
        init_test("region_isolation_during_drain");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let r_cancel = RegionId::from_arena(ArenaIndex::new(0, 0));
        let r_alive = RegionId::from_arena(ArenaIndex::new(1, 0));

        // Obligations in region being cancelled.
        let tok_cancel = ledger.acquire(ObligationKind::SendPermit, task, r_cancel, Time::ZERO);
        // Obligations in region that is still alive.
        let _tok_alive = ledger.acquire(ObligationKind::Ack, task, r_alive, Time::ZERO);

        // Drain only the cancelled region.
        ledger.abort(
            tok_cancel,
            Time::from_nanos(10),
            ObligationAbortReason::Cancel,
        );

        // Cancelled region is clean.
        let cancel_clean = ledger.is_region_clean(r_cancel);
        crate::assert_with_log!(cancel_clean, "cancelled region clean", true, cancel_clean);

        // Alive region still has its obligation.
        let alive_pending = ledger.pending_for_region(r_alive);
        crate::assert_with_log!(alive_pending == 1, "alive region pending", 1, alive_pending);

        // Global ledger still has a pending obligation.
        let global_pending = ledger.pending_count();
        crate::assert_with_log!(global_pending == 1, "global pending", 1, global_pending);
        crate::test_complete!("region_isolation_during_drain");
    }

    // ---- Deterministic drain ordering -----------------------------------

    #[test]
    fn drain_ordering_is_deterministic() {
        init_test("drain_ordering_is_deterministic");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        // Acquire obligations in a known order.
        let _t1 = ledger.acquire(ObligationKind::SendPermit, task, region, Time::ZERO);
        let _t2 = ledger.acquire(ObligationKind::Ack, task, region, Time::from_nanos(1));
        let _t3 = ledger.acquire(ObligationKind::Lease, task, region, Time::from_nanos(2));

        // IDs should be monotonically increasing (BTreeMap).
        let ids = ledger.pending_ids_for_region(region);
        for window in ids.windows(2) {
            crate::assert_with_log!(window[0] < window[1], "monotonic ids", true, true);
        }

        // Drain in the deterministic order returned by pending_ids_for_region.
        let drain_time = Time::from_nanos(100);
        for id in &ids {
            ledger.abort_by_id(*id, drain_time, ObligationAbortReason::Cancel);
        }

        let is_clean = ledger.is_region_clean(region);
        crate::assert_with_log!(is_clean, "clean after ordered drain", true, is_clean);
        let stats = ledger.stats();
        crate::assert_with_log!(stats.total_aborted == 3, "aborted", 3, stats.total_aborted);
        crate::assert_with_log!(stats.total_leaked == 0, "leaked", 0, stats.total_leaked);
        crate::test_complete!("drain_ordering_is_deterministic");
    }

    // ---- Quiescence: region clean implies zero pending obligations ------

    #[test]
    fn region_quiescence_after_mixed_resolution() {
        init_test("region_quiescence_after_mixed_resolution");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        // Acquire four obligations of different kinds.
        let t1 = ledger.acquire(ObligationKind::SendPermit, task, region, Time::ZERO);
        let t2 = ledger.acquire(ObligationKind::Ack, task, region, Time::ZERO);
        let t3 = ledger.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        let t4 = ledger.acquire(ObligationKind::IoOp, task, region, Time::ZERO);

        // Resolve them via different paths (commit, abort, cancel-abort).
        ledger.commit(t1, Time::from_nanos(10));
        ledger.abort(t2, Time::from_nanos(20), ObligationAbortReason::Explicit);
        ledger.abort(t3, Time::from_nanos(30), ObligationAbortReason::Cancel);
        ledger.commit(t4, Time::from_nanos(40));

        // Region should be clean regardless of resolution path.
        let is_clean = ledger.is_region_clean(region);
        crate::assert_with_log!(is_clean, "quiescent", true, is_clean);

        let leaks = ledger.check_region_leaks(region);
        crate::assert_with_log!(leaks.is_clean(), "no leaks", true, leaks.is_clean());

        let stats = ledger.stats();
        crate::assert_with_log!(stats.pending == 0, "pending zero", 0, stats.pending);
        crate::assert_with_log!(stats.is_clean(), "stats clean", true, stats.is_clean());
        crate::test_complete!("region_quiescence_after_mixed_resolution");
    }

    // ---- Abort reason preserved -----------------------------------------

    #[test]
    fn abort_reason_preserved_in_record() {
        init_test("abort_reason_preserved_in_record");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let token = ledger.acquire(ObligationKind::SendPermit, task, region, Time::ZERO);
        let id = token.id();

        ledger.abort(token, Time::from_nanos(10), ObligationAbortReason::Cancel);

        let record = ledger.get(id).expect("record exists");
        crate::assert_with_log!(
            record.state == ObligationState::Aborted,
            "state aborted",
            ObligationState::Aborted,
            record.state
        );
        crate::assert_with_log!(
            record.abort_reason == Some(ObligationAbortReason::Cancel),
            "abort reason",
            Some(ObligationAbortReason::Cancel),
            record.abort_reason
        );
        crate::test_complete!("abort_reason_preserved_in_record");
    }

    #[test]
    fn forged_token_metadata_panics_without_mutating_ledger() {
        init_test("forged_token_metadata_panics_without_mutating_ledger");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let token = ledger.acquire(ObligationKind::SendPermit, task, region, Time::ZERO);
        let id = token.id();
        let forged = ObligationToken {
            id,
            kind: ObligationKind::Ack,
            holder: task,
            region,
        };

        let commit = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ledger.commit(forged, Time::from_nanos(10));
        }));
        crate::assert_with_log!(
            commit.is_err(),
            "forged token rejected",
            true,
            commit.is_err()
        );

        let record = ledger.get(id).expect("record exists");
        crate::assert_with_log!(
            record.state == ObligationState::Reserved,
            "state unchanged",
            ObligationState::Reserved,
            record.state
        );

        let stats = ledger.stats();
        crate::assert_with_log!(
            stats.total_committed == 0,
            "committed",
            0,
            stats.total_committed
        );
        crate::assert_with_log!(stats.total_aborted == 0, "aborted", 0, stats.total_aborted);
        crate::assert_with_log!(stats.pending == 1, "pending", 1, stats.pending);
        crate::test_complete!("forged_token_metadata_panics_without_mutating_ledger");
    }

    #[test]
    fn abort_by_id_double_resolve_panics_without_pending_underflow() {
        init_test("abort_by_id_double_resolve_panics_without_pending_underflow");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let token = ledger.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        let id = token.id();

        let duration = ledger.abort_by_id(id, Time::from_nanos(25), ObligationAbortReason::Cancel);
        crate::assert_with_log!(duration == 25, "duration", 25, duration);

        let second_abort = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ledger.abort_by_id(id, Time::from_nanos(30), ObligationAbortReason::Cancel);
        }));
        crate::assert_with_log!(
            second_abort.is_err(),
            "double resolve rejected",
            true,
            second_abort.is_err()
        );

        let record = ledger.get(id).expect("record exists");
        crate::assert_with_log!(
            record.state == ObligationState::Aborted,
            "state remains aborted",
            ObligationState::Aborted,
            record.state
        );

        let stats = ledger.stats();
        crate::assert_with_log!(stats.total_aborted == 1, "aborted", 1, stats.total_aborted);
        crate::assert_with_log!(stats.total_leaked == 0, "leaked", 0, stats.total_leaked);
        crate::assert_with_log!(stats.pending == 0, "pending", 0, stats.pending);
        crate::test_complete!("abort_by_id_double_resolve_panics_without_pending_underflow");
    }

    /// Race-tolerance contract for `try_abort_by_id` covering all four
    /// branches: NotFound, AlreadyResolved (committed and aborted), the
    /// happy reserved-then-aborted path, and the no-op fast-return for
    /// already-finalized regions. Pinned together so a future refactor
    /// that drops one branch can't pass the rest in isolation.
    #[test]
    fn try_abort_by_id_race_branches() {
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        // (a) NotFound: no acquire happened for this ID. Use a fabricated
        // ID by acquiring + dropping (marking the slot used), then synthesise
        // a never-acquired ID via new_for_test in a fresh generation that
        // the ledger never minted.
        let phantom_id = ObligationId::new_for_test(99_999, 7);
        match ledger.try_abort_by_id(
            phantom_id,
            Time::from_nanos(1),
            ObligationAbortReason::Cancel,
        ) {
            Err(LedgerError::NotFound { obligation }) => {
                assert_eq!(obligation, phantom_id);
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
        assert_eq!(ledger.stats().pending, 0);
        assert_eq!(ledger.stats().total_aborted, 0);

        // (b) Happy path: reserve then race-tolerant abort succeeds.
        let token_b = ledger.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        let id_b = token_b.id();
        match ledger.try_abort_by_id(id_b, Time::from_nanos(10), ObligationAbortReason::Cancel) {
            Ok(duration) => assert_eq!(duration, 10),
            other => panic!("expected Ok(10), got {other:?}"),
        }
        assert_eq!(ledger.stats().total_aborted, 1);
        assert_eq!(ledger.stats().pending, 0);

        // (c) AlreadyResolved (Aborted): hitting the just-aborted record
        // again must not panic and must not double-decrement pending.
        let pending_before = ledger.stats().pending;
        let aborted_before = ledger.stats().total_aborted;
        match ledger.try_abort_by_id(id_b, Time::from_nanos(20), ObligationAbortReason::Cancel) {
            Err(LedgerError::AlreadyResolved { obligation, state }) => {
                assert_eq!(obligation, id_b);
                assert_eq!(state, ObligationState::Aborted);
            }
            other => panic!("expected AlreadyResolved(Aborted), got {other:?}"),
        }
        assert_eq!(ledger.stats().pending, pending_before);
        assert_eq!(ledger.stats().total_aborted, aborted_before);

        // (d) AlreadyResolved (Committed): the canonical token-double-
        // fulfillment race — commit happens first, drain calls
        // try_abort_by_id second. Must observe Committed without panicking.
        let token_d = ledger.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        let id_d = token_d.id();
        let _ = ledger.commit(token_d, Time::from_nanos(40));
        match ledger.try_abort_by_id(id_d, Time::from_nanos(50), ObligationAbortReason::Cancel) {
            Err(LedgerError::AlreadyResolved { obligation, state }) => {
                assert_eq!(obligation, id_d);
                assert_eq!(state, ObligationState::Committed);
            }
            other => panic!("expected AlreadyResolved(Committed), got {other:?}"),
        }
        // Stats unchanged from the commit alone (one committed, no abort).
        let stats_d = ledger.stats();
        assert_eq!(stats_d.total_committed, 1);
        assert_eq!(stats_d.total_aborted, 1, "from branch (b), unchanged here");
        assert_eq!(stats_d.pending, 0);

        // (e) Region finalized: fallible drain callers observe the fence
        // explicitly instead of silently mutating a closed region.
        // mark_region_finalized is intentionally idempotent so this can run
        // after branch (d).
        let token_e = ledger.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        let id_e = token_e.id();
        ledger.mark_region_finalized(region);
        match ledger.try_abort_by_id(id_e, Time::from_nanos(60), ObligationAbortReason::Cancel) {
            Err(LedgerError::RegionFinalized {
                region: err_region,
                obligation,
            }) => {
                assert_eq!(err_region, region);
                assert_eq!(obligation, id_e);
            }
            other => panic!("expected RegionFinalized after finalize, got {other:?}"),
        }
        // The pending count for id_e MUST stay >0 — the fence prevented
        // the abort path from running, so the obligation is still
        // outstanding (and the leak detector will flag it on close, which
        // is the documented contract).
        // We discard the token to satisfy the Drop linearity check; any
        // late-arrival drain would now route through the same fence.
        std::mem::drop(token_e);
        assert!(
            ledger.stats().pending >= 1,
            "fence must NOT decrement pending; got {:?}",
            ledger.stats(),
        );
    }

    #[test]
    fn try_abort_by_id_race_matrix_logs_evidence() {
        init_test("try_abort_by_id_race_matrix_logs_evidence");

        const SCENARIO_ID: &str = "TRY-ABORT-BY-ID-RACE-MATRIX-N3GXII";
        const RCH_COMMAND: &str = "rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_asupersync_n3gxii_ledger_final cargo test -p asupersync --lib try_abort_by_id_race_matrix_logs_evidence --features test-internals -- --nocapture";

        fn record_state(ledger: &ObligationLedger, id: ObligationId) -> &'static str {
            ledger
                .get(id)
                .map_or("Missing", |record| match record.state {
                    ObligationState::Reserved => "Reserved",
                    ObligationState::Committed => "Committed",
                    ObligationState::Aborted => "Aborted",
                    ObligationState::Leaked => "Leaked",
                })
        }

        fn abort_result(result: &Result<u64, LedgerError>) -> String {
            match result {
                Ok(duration) => format!("Ok({duration})"),
                Err(LedgerError::NotFound { .. }) => "Err(NotFound)".to_string(),
                Err(LedgerError::AlreadyResolved { state, .. }) => {
                    format!("Err(AlreadyResolved::{state:?})")
                }
                Err(LedgerError::RegionFinalized { .. }) => "Err(RegionFinalized)".to_string(),
                Err(other) => format!("Err({other:?})"),
            }
        }

        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();
        let mut rows = Vec::new();
        let mut double_fulfillment_count = 0usize;

        let missing_id = ObligationId::new_for_test(99_999, 9);
        let missing_result = ledger.try_abort_by_id(
            missing_id,
            Time::from_nanos(1),
            ObligationAbortReason::Cancel,
        );
        assert!(matches!(
            missing_result,
            Err(LedgerError::NotFound { obligation }) if obligation == missing_id
        ));
        rows.push(serde_json::json!({
            "case": "missing_id",
            "task_id": format!("{task:?}"),
            "obligation_id": format!("{missing_id:?}"),
            "generation": missing_id.arena_index().generation(),
            "race_participant": "drain_abort_without_record",
            "fulfillment_state_before": "Missing",
            "abort_result": abort_result(&missing_result),
            "fulfillment_state_after": record_state(&ledger, missing_id),
        }));

        let token_success = ledger.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        let id_success = token_success.id();
        let before_success = record_state(&ledger, id_success);
        let success_result = ledger.try_abort_by_id(
            id_success,
            Time::from_nanos(10),
            ObligationAbortReason::Cancel,
        );
        assert_eq!(success_result, Ok(10));
        rows.push(serde_json::json!({
            "case": "reserved_abort_success",
            "task_id": format!("{task:?}"),
            "obligation_id": format!("{id_success:?}"),
            "generation": id_success.arena_index().generation(),
            "race_participant": "drain_abort_wins",
            "fulfillment_state_before": before_success,
            "abort_result": abort_result(&success_result),
            "fulfillment_state_after": record_state(&ledger, id_success),
        }));

        let token_commit = ledger.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        let id_commit = token_commit.id();
        let _duration = ledger.commit(token_commit, Time::from_nanos(20));
        let before_commit_race = record_state(&ledger, id_commit);
        let committed_result = ledger.try_abort_by_id(
            id_commit,
            Time::from_nanos(30),
            ObligationAbortReason::Cancel,
        );
        assert!(matches!(
            committed_result,
            Err(LedgerError::AlreadyResolved {
                obligation,
                state: ObligationState::Committed,
            }) if obligation == id_commit
        ));
        double_fulfillment_count += 1;
        rows.push(serde_json::json!({
            "case": "concurrent_fulfillment_commit_wins",
            "task_id": format!("{task:?}"),
            "obligation_id": format!("{id_commit:?}"),
            "generation": id_commit.arena_index().generation(),
            "race_participant": "token_commit_then_drain_abort",
            "fulfillment_state_before": before_commit_race,
            "abort_result": abort_result(&committed_result),
            "fulfillment_state_after": record_state(&ledger, id_commit),
        }));

        let token_abort = ledger.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        let id_abort = token_abort.id();
        let first_abort = ledger.try_abort_by_id(
            id_abort,
            Time::from_nanos(40),
            ObligationAbortReason::Cancel,
        );
        assert_eq!(first_abort, Ok(40));
        let before_double_abort = record_state(&ledger, id_abort);
        let double_abort_result = ledger.try_abort_by_id(
            id_abort,
            Time::from_nanos(50),
            ObligationAbortReason::Cancel,
        );
        assert!(matches!(
            double_abort_result,
            Err(LedgerError::AlreadyResolved {
                obligation,
                state: ObligationState::Aborted,
            }) if obligation == id_abort
        ));
        double_fulfillment_count += 1;
        rows.push(serde_json::json!({
            "case": "concurrent_abort_double_abort_idempotence",
            "task_id": format!("{task:?}"),
            "obligation_id": format!("{id_abort:?}"),
            "generation": id_abort.arena_index().generation(),
            "race_participant": "two_drain_aborts_same_id",
            "fulfillment_state_before": before_double_abort,
            "abort_result": abort_result(&double_abort_result),
            "fulfillment_state_after": record_state(&ledger, id_abort),
        }));

        let token_stale = ledger.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        let id_live = token_stale.id();
        let live_index = id_live.arena_index();
        let stale_id = ObligationId::new_for_test(
            live_index.index(),
            live_index.generation().saturating_add(1),
        );
        let stale_result = ledger.try_abort_by_id(
            stale_id,
            Time::from_nanos(60),
            ObligationAbortReason::Cancel,
        );
        assert!(matches!(
            stale_result,
            Err(LedgerError::NotFound { obligation }) if obligation == stale_id
        ));
        rows.push(serde_json::json!({
            "case": "stale_generation_aba_rejected",
            "task_id": format!("{task:?}"),
            "obligation_id": format!("{stale_id:?}"),
            "generation": stale_id.arena_index().generation(),
            "race_participant": "stale_generation_drain_abort",
            "fulfillment_state_before": "Missing",
            "abort_result": abort_result(&stale_result),
            "fulfillment_state_after": record_state(&ledger, stale_id),
            "live_obligation_state_after": record_state(&ledger, id_live),
        }));
        let live_cleanup = ledger.try_abort_by_id(
            id_live,
            Time::from_nanos(70),
            ObligationAbortReason::Explicit,
        );
        assert_eq!(live_cleanup, Ok(70));

        let stats = ledger.stats();
        let leak_count = ledger.check_leaks().leaked.len();
        assert_eq!(
            stats.pending, 0,
            "race matrix must not leak pending obligations"
        );
        assert_eq!(leak_count, 0, "race matrix leak report must be clean");

        let report = serde_json::json!({
            "scenario_id": SCENARIO_ID,
            "task_id": format!("{task:?}"),
            "region_id": format!("{region:?}"),
            "race_matrix": rows,
            "double_fulfillment_count": double_fulfillment_count,
            "stats": {
                "pending": stats.pending,
                "total_committed": stats.total_committed,
                "total_aborted": stats.total_aborted,
                "total_leaked": stats.total_leaked,
            },
            "leak_count": leak_count,
            "exact_rch_command": RCH_COMMAND,
            "artifact_paths": [],
            "final_race_tolerant_verdict": "pass"
        });

        println!("ASUPERSYNC_TRY_ABORT_BY_ID_RACE_MATRIX_BEGIN");
        println!(
            "{}",
            serde_json::to_string_pretty(&report).expect("serialize try_abort_by_id report")
        );
        println!("ASUPERSYNC_TRY_ABORT_BY_ID_RACE_MATRIX_END");

        crate::test_complete!("try_abort_by_id_race_matrix_logs_evidence");
    }

    #[test]
    fn abort_by_id_supports_cancel_drain_without_leak_accounting() {
        init_test("abort_by_id_supports_cancel_drain_without_leak_accounting");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let token = ledger.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        let id = token.id();

        let duration = ledger.abort_by_id(id, Time::from_nanos(25), ObligationAbortReason::Cancel);
        crate::assert_with_log!(duration == 25, "duration", 25, duration);

        let record = ledger.get(id).expect("record exists");
        crate::assert_with_log!(
            record.state == ObligationState::Aborted,
            "state aborted",
            ObligationState::Aborted,
            record.state
        );
        crate::assert_with_log!(
            record.abort_reason == Some(ObligationAbortReason::Cancel),
            "abort reason",
            Some(ObligationAbortReason::Cancel),
            record.abort_reason
        );

        let stats = ledger.stats();
        crate::assert_with_log!(stats.total_aborted == 1, "aborted", 1, stats.total_aborted);
        crate::assert_with_log!(stats.total_leaked == 0, "leaked", 0, stats.total_leaked);
        crate::assert_with_log!(stats.pending == 0, "pending", 0, stats.pending);
        crate::assert_with_log!(stats.is_clean(), "clean", true, stats.is_clean());
        crate::test_complete!("abort_by_id_supports_cancel_drain_without_leak_accounting");
    }

    fn observable_resolution_state(
        ledger: &ObligationLedger,
        id: ObligationId,
    ) -> (
        ObligationId,
        ObligationKind,
        TaskId,
        RegionId,
        Time,
        ObligationState,
        Option<Time>,
        Option<ObligationAbortReason>,
        LedgerStats,
    ) {
        let record = ledger.get(id).expect("record exists");
        (
            record.id,
            record.kind,
            record.holder,
            record.region,
            record.reserved_at,
            record.state,
            record.resolved_at,
            record.abort_reason,
            ledger.stats(),
        )
    }

    #[test]
    fn metamorphic_commit_then_abort_matches_commit_only_terminal_observables() {
        init_test("metamorphic_commit_then_abort_matches_commit_only_terminal_observables");
        let task = make_task();
        let region = make_region();

        let mut baseline = ObligationLedger::new();
        let baseline_token = baseline.acquire(ObligationKind::SendPermit, task, region, Time::ZERO);
        let baseline_id = baseline_token.id();
        baseline.commit(baseline_token, Time::from_nanos(25));
        let expected = observable_resolution_state(&baseline, baseline_id);
        let expected_observation = observe_ledger(&baseline, task, region);

        let mut transformed = ObligationLedger::new();
        let transformed_token =
            transformed.acquire(ObligationKind::SendPermit, task, region, Time::ZERO);
        let transformed_id = transformed_token.id();
        transformed.commit(transformed_token, Time::from_nanos(25));

        for (idx, rejected) in [
            replay_abort_attempt(
                &mut transformed,
                transformed_id,
                Time::from_nanos(26),
                ObligationAbortReason::Cancel,
            ),
            replay_abort_attempt(
                &mut transformed,
                transformed_id,
                Time::from_nanos(30),
                ObligationAbortReason::Explicit,
            ),
            replay_abort_attempt(
                &mut transformed,
                transformed_id,
                Time::from_nanos(40),
                ObligationAbortReason::Error,
            ),
        ]
        .into_iter()
        .enumerate()
        {
            crate::assert_with_log!(rejected, "commit-then-abort rejected", idx, rejected);
        }

        crate::assert_with_log!(
            observable_resolution_state(&transformed, transformed_id) == expected,
            "commit terminal observables preserved",
            expected,
            observable_resolution_state(&transformed, transformed_id)
        );
        crate::assert_with_log!(
            observe_ledger(&transformed, task, region) == expected_observation,
            "commit ledger observation preserved",
            expected_observation,
            observe_ledger(&transformed, task, region)
        );

        crate::test_complete!(
            "metamorphic_commit_then_abort_matches_commit_only_terminal_observables"
        );
    }

    #[test]
    fn metamorphic_double_commit_matches_single_commit_terminal_observables() {
        init_test("metamorphic_double_commit_matches_single_commit_terminal_observables");
        let task = make_task();
        let region = make_region();

        let mut baseline = ObligationLedger::new();
        let baseline_token = baseline.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        let baseline_id = baseline_token.id();
        baseline.commit(baseline_token, Time::from_nanos(15));
        let expected = observable_resolution_state(&baseline, baseline_id);
        let expected_observation = observe_ledger(&baseline, task, region);

        let mut transformed = ObligationLedger::new();
        let transformed_token =
            transformed.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        let transformed_id = transformed_token.id();
        transformed.commit(transformed_token, Time::from_nanos(15));

        for (idx, rejected) in [
            replay_commit_attempt(
                &mut transformed,
                transformed_id,
                ObligationKind::Lease,
                task,
                region,
                Time::from_nanos(16),
            ),
            replay_commit_attempt(
                &mut transformed,
                transformed_id,
                ObligationKind::Lease,
                task,
                region,
                Time::from_nanos(25),
            ),
        ]
        .into_iter()
        .enumerate()
        {
            crate::assert_with_log!(rejected, "double-commit rejected", idx, rejected);
        }

        crate::assert_with_log!(
            observable_resolution_state(&transformed, transformed_id) == expected,
            "double-commit terminal observables preserved",
            expected,
            observable_resolution_state(&transformed, transformed_id)
        );
        crate::assert_with_log!(
            observe_ledger(&transformed, task, region) == expected_observation,
            "double-commit ledger observation preserved",
            expected_observation,
            observe_ledger(&transformed, task, region)
        );

        crate::test_complete!(
            "metamorphic_double_commit_matches_single_commit_terminal_observables"
        );
    }

    #[test]
    fn metamorphic_abort_then_commit_matches_abort_only_terminal_observables() {
        init_test("metamorphic_abort_then_commit_matches_abort_only_terminal_observables");
        let task = make_task();
        let region = make_region();

        let mut baseline = ObligationLedger::new();
        let baseline_token = baseline.acquire(ObligationKind::Ack, task, region, Time::ZERO);
        let baseline_id = baseline_token.id();
        baseline.abort(
            baseline_token,
            Time::from_nanos(35),
            ObligationAbortReason::Explicit,
        );
        let expected = observable_resolution_state(&baseline, baseline_id);
        let expected_observation = observe_ledger(&baseline, task, region);

        let mut transformed = ObligationLedger::new();
        let transformed_token = transformed.acquire(ObligationKind::Ack, task, region, Time::ZERO);
        let transformed_id = transformed_token.id();
        transformed.abort(
            transformed_token,
            Time::from_nanos(35),
            ObligationAbortReason::Explicit,
        );

        let rejected = replay_commit_attempt(
            &mut transformed,
            transformed_id,
            ObligationKind::Ack,
            task,
            region,
            Time::from_nanos(36),
        );
        crate::assert_with_log!(rejected, "abort-then-commit rejected", true, rejected);
        crate::assert_with_log!(
            observable_resolution_state(&transformed, transformed_id) == expected,
            "abort terminal observables preserved",
            expected,
            observable_resolution_state(&transformed, transformed_id)
        );
        crate::assert_with_log!(
            observe_ledger(&transformed, task, region) == expected_observation,
            "abort ledger observation preserved",
            expected_observation,
            observe_ledger(&transformed, task, region)
        );

        crate::test_complete!(
            "metamorphic_abort_then_commit_matches_abort_only_terminal_observables"
        );
    }

    #[test]
    fn metamorphic_independent_commit_reordering_preserves_terminal_observables() {
        init_test("metamorphic_independent_commit_reordering_preserves_terminal_observables");
        let task_a = TaskId::from_arena(ArenaIndex::new(10, 0));
        let task_b = TaskId::from_arena(ArenaIndex::new(11, 0));
        let region_a = RegionId::from_arena(ArenaIndex::new(20, 0));
        let region_b = RegionId::from_arena(ArenaIndex::new(21, 0));

        let mut forward = ObligationLedger::new();
        let forward_first = forward.acquire(
            ObligationKind::SendPermit,
            task_a,
            region_a,
            Time::from_nanos(1),
        );
        let forward_second =
            forward.acquire(ObligationKind::Lease, task_b, region_b, Time::from_nanos(2));
        let first_id = forward_first.id();
        let second_id = forward_second.id();
        forward.commit(forward_first, Time::from_nanos(10));
        forward.commit(forward_second, Time::from_nanos(20));
        let forward_first_state = observable_resolution_state(&forward, first_id);
        let forward_second_state = observable_resolution_state(&forward, second_id);
        let forward_region_a = observe_ledger(&forward, task_a, region_a);
        let forward_region_b = observe_ledger(&forward, task_b, region_b);

        let mut reversed = ObligationLedger::new();
        let reversed_first = reversed.acquire(
            ObligationKind::SendPermit,
            task_a,
            region_a,
            Time::from_nanos(1),
        );
        let reversed_second =
            reversed.acquire(ObligationKind::Lease, task_b, region_b, Time::from_nanos(2));
        let reversed_first_id = reversed_first.id();
        let reversed_second_id = reversed_second.id();
        reversed.commit(reversed_second, Time::from_nanos(20));
        reversed.commit(reversed_first, Time::from_nanos(10));

        crate::assert_with_log!(
            reversed_first_id == first_id,
            "first obligation id stable across reorder",
            first_id,
            reversed_first_id
        );
        crate::assert_with_log!(
            reversed_second_id == second_id,
            "second obligation id stable across reorder",
            second_id,
            reversed_second_id
        );
        crate::assert_with_log!(
            observable_resolution_state(&reversed, reversed_first_id) == forward_first_state,
            "first independent obligation preserved",
            forward_first_state,
            observable_resolution_state(&reversed, reversed_first_id)
        );
        crate::assert_with_log!(
            observable_resolution_state(&reversed, reversed_second_id) == forward_second_state,
            "second independent obligation preserved",
            forward_second_state,
            observable_resolution_state(&reversed, reversed_second_id)
        );
        crate::assert_with_log!(
            observe_ledger(&reversed, task_a, region_a) == forward_region_a,
            "region A observables preserved",
            forward_region_a,
            observe_ledger(&reversed, task_a, region_a)
        );
        crate::assert_with_log!(
            observe_ledger(&reversed, task_b, region_b) == forward_region_b,
            "region B observables preserved",
            forward_region_b,
            observe_ledger(&reversed, task_b, region_b)
        );

        crate::test_complete!(
            "metamorphic_independent_commit_reordering_preserves_terminal_observables"
        );
    }

    #[test]
    fn commit_once_and_replayed_commit_attempts_preserve_observable_state() {
        init_test("commit_once_and_replayed_commit_attempts_preserve_observable_state");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let token = ledger.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        let id = token.id();

        let duration = ledger.commit(token, Time::from_nanos(25));
        crate::assert_with_log!(duration == 25, "duration", 25, duration);

        let expected = observable_resolution_state(&ledger, id);
        for now in [
            Time::from_nanos(26),
            Time::from_nanos(40),
            Time::from_nanos(100),
        ] {
            let replay = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                ledger.commit(
                    ObligationToken {
                        id,
                        kind: ObligationKind::Lease,
                        holder: task,
                        region,
                    },
                    now,
                );
            }));
            crate::assert_with_log!(
                replay.is_err(),
                "replayed commit rejected",
                true,
                replay.is_err()
            );
            crate::assert_with_log!(
                observable_resolution_state(&ledger, id) == expected,
                "observable state preserved",
                expected,
                observable_resolution_state(&ledger, id)
            );
        }

        crate::test_complete!("commit_once_and_replayed_commit_attempts_preserve_observable_state");
    }

    #[test]
    fn abort_once_and_replayed_abort_attempts_preserve_observable_state() {
        init_test("abort_once_and_replayed_abort_attempts_preserve_observable_state");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let token = ledger.acquire(ObligationKind::Ack, task, region, Time::ZERO);
        let id = token.id();

        let duration = ledger.abort(token, Time::from_nanos(25), ObligationAbortReason::Explicit);
        crate::assert_with_log!(duration == 25, "duration", 25, duration);

        let expected = observable_resolution_state(&ledger, id);
        for now in [
            Time::from_nanos(26),
            Time::from_nanos(40),
            Time::from_nanos(100),
        ] {
            let replay = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                ledger.abort_by_id(id, now, ObligationAbortReason::Cancel);
            }));
            crate::assert_with_log!(
                replay.is_err(),
                "replayed abort rejected",
                true,
                replay.is_err()
            );
            crate::assert_with_log!(
                observable_resolution_state(&ledger, id) == expected,
                "observable state preserved",
                expected,
                observable_resolution_state(&ledger, id)
            );
        }

        crate::test_complete!("abort_once_and_replayed_abort_attempts_preserve_observable_state");
    }

    #[test]
    fn abort_after_commit_replay_preserves_committed_observable_state() {
        init_test("abort_after_commit_replay_preserves_committed_observable_state");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let token = ledger.acquire(ObligationKind::SendPermit, task, region, Time::ZERO);
        let id = token.id();

        let duration = ledger.commit(token, Time::from_nanos(50));
        crate::assert_with_log!(duration == 50, "duration", 50, duration);

        let expected = observable_resolution_state(&ledger, id);
        for now in [
            Time::from_nanos(51),
            Time::from_nanos(60),
            Time::from_nanos(75),
        ] {
            let replay = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                ledger.abort_by_id(id, now, ObligationAbortReason::Cancel);
            }));
            crate::assert_with_log!(
                replay.is_err(),
                "abort after commit rejected",
                true,
                replay.is_err()
            );
            crate::assert_with_log!(
                observable_resolution_state(&ledger, id) == expected,
                "committed state preserved",
                expected,
                observable_resolution_state(&ledger, id)
            );
        }

        crate::test_complete!("abort_after_commit_replay_preserves_committed_observable_state");
    }

    fn replay_commit_attempt(
        ledger: &mut ObligationLedger,
        id: ObligationId,
        kind: ObligationKind,
        holder: TaskId,
        region: RegionId,
        now: Time,
    ) -> bool {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ledger.commit(
                ObligationToken {
                    id,
                    kind,
                    holder,
                    region,
                },
                now,
            );
        }))
        .is_err()
    }

    fn replay_abort_attempt(
        ledger: &mut ObligationLedger,
        id: ObligationId,
        now: Time,
        reason: ObligationAbortReason,
    ) -> bool {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ledger.abort_by_id(id, now, reason);
        }))
        .is_err()
    }

    #[test]
    fn metamorphic_commit_and_abort_replay_schedules_converge_on_same_terminal_observables() {
        init_test(
            "metamorphic_commit_and_abort_replay_schedules_converge_on_same_terminal_observables",
        );
        let task = make_task();
        let region = make_region();

        let mut commit_then_abort = ObligationLedger::new();
        let token = commit_then_abort.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        let id = token.id();
        commit_then_abort.commit(token, Time::from_nanos(10));
        let committed_expected = observable_resolution_state(&commit_then_abort, id);
        for (idx, rejected) in [
            replay_commit_attempt(
                &mut commit_then_abort,
                id,
                ObligationKind::Lease,
                task,
                region,
                Time::from_nanos(11),
            ),
            replay_abort_attempt(
                &mut commit_then_abort,
                id,
                Time::from_nanos(12),
                ObligationAbortReason::Cancel,
            ),
            replay_commit_attempt(
                &mut commit_then_abort,
                id,
                ObligationKind::Lease,
                task,
                region,
                Time::from_nanos(13),
            ),
        ]
        .into_iter()
        .enumerate()
        {
            crate::assert_with_log!(rejected, "commit-first replay rejected", idx, rejected);
            crate::assert_with_log!(
                observable_resolution_state(&commit_then_abort, id) == committed_expected,
                "commit-first observable state preserved",
                committed_expected,
                observable_resolution_state(&commit_then_abort, id)
            );
        }

        let mut abort_then_commit = ObligationLedger::new();
        let token = abort_then_commit.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        let id = token.id();
        abort_then_commit.commit(token, Time::from_nanos(10));
        for (idx, rejected) in [
            replay_abort_attempt(
                &mut abort_then_commit,
                id,
                Time::from_nanos(11),
                ObligationAbortReason::Cancel,
            ),
            replay_commit_attempt(
                &mut abort_then_commit,
                id,
                ObligationKind::Lease,
                task,
                region,
                Time::from_nanos(12),
            ),
            replay_abort_attempt(
                &mut abort_then_commit,
                id,
                Time::from_nanos(13),
                ObligationAbortReason::Explicit,
            ),
        ]
        .into_iter()
        .enumerate()
        {
            crate::assert_with_log!(rejected, "abort-first replay rejected", idx, rejected);
            crate::assert_with_log!(
                observable_resolution_state(&abort_then_commit, id) == committed_expected,
                "abort-first observable state preserved",
                committed_expected,
                observable_resolution_state(&abort_then_commit, id)
            );
        }

        crate::assert_with_log!(
            observable_resolution_state(&commit_then_abort, id)
                == observable_resolution_state(&abort_then_commit, id),
            "committed replay schedules converge",
            observable_resolution_state(&commit_then_abort, id),
            observable_resolution_state(&abort_then_commit, id)
        );

        let mut abort_only_then_commit = ObligationLedger::new();
        let token = abort_only_then_commit.acquire(ObligationKind::Ack, task, region, Time::ZERO);
        let id = token.id();
        abort_only_then_commit.abort(token, Time::from_nanos(20), ObligationAbortReason::Explicit);
        let aborted_expected = observable_resolution_state(&abort_only_then_commit, id);
        for (idx, rejected) in [
            replay_abort_attempt(
                &mut abort_only_then_commit,
                id,
                Time::from_nanos(21),
                ObligationAbortReason::Cancel,
            ),
            replay_commit_attempt(
                &mut abort_only_then_commit,
                id,
                ObligationKind::Ack,
                task,
                region,
                Time::from_nanos(22),
            ),
        ]
        .into_iter()
        .enumerate()
        {
            crate::assert_with_log!(rejected, "abort terminal replay rejected", idx, rejected);
            crate::assert_with_log!(
                observable_resolution_state(&abort_only_then_commit, id) == aborted_expected,
                "abort terminal state preserved",
                aborted_expected,
                observable_resolution_state(&abort_only_then_commit, id)
            );
        }

        let mut commit_only_then_abort = ObligationLedger::new();
        let token = commit_only_then_abort.acquire(ObligationKind::Ack, task, region, Time::ZERO);
        let id = token.id();
        commit_only_then_abort.abort(token, Time::from_nanos(20), ObligationAbortReason::Explicit);
        for (idx, rejected) in [
            replay_commit_attempt(
                &mut commit_only_then_abort,
                id,
                ObligationKind::Ack,
                task,
                region,
                Time::from_nanos(21),
            ),
            replay_abort_attempt(
                &mut commit_only_then_abort,
                id,
                Time::from_nanos(22),
                ObligationAbortReason::Error,
            ),
        ]
        .into_iter()
        .enumerate()
        {
            crate::assert_with_log!(rejected, "commit terminal replay rejected", idx, rejected);
            crate::assert_with_log!(
                observable_resolution_state(&commit_only_then_abort, id) == aborted_expected,
                "commit terminal state preserved",
                aborted_expected,
                observable_resolution_state(&commit_only_then_abort, id)
            );
        }

        crate::assert_with_log!(
            observable_resolution_state(&abort_only_then_commit, id)
                == observable_resolution_state(&commit_only_then_abort, id),
            "aborted replay schedules converge",
            observable_resolution_state(&abort_only_then_commit, id),
            observable_resolution_state(&commit_only_then_abort, id)
        );

        crate::test_complete!(
            "metamorphic_commit_and_abort_replay_schedules_converge_on_same_terminal_observables"
        );
    }

    // =========================================================================
    // Wave 55 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn ledger_stats_debug_clone_copy_eq_default() {
        let stats = LedgerStats::default();
        let dbg = format!("{stats:?}");
        assert!(dbg.contains("LedgerStats"), "{dbg}");
        let copied = stats;
        let cloned = stats;
        assert_eq!(copied, cloned);
        assert_eq!(stats.total_acquired, 0);
        assert!(stats.is_clean());
    }

    #[test]
    fn leak_check_result_debug_clone() {
        let result = LeakCheckResult { leaked: vec![] };
        let dbg = format!("{result:?}");
        assert!(dbg.contains("LeakCheckResult"), "{dbg}");
        let cloned = result;
        assert!(cloned.is_clean());
    }

    // =========================================================================
    // Conservation-of-acquired metamorphic relation
    //
    // For any sequence of ledger operations, the invariant
    //
    //     total_acquired == total_committed + total_aborted + total_leaked + pending
    //
    // must hold. This catches off-by-one and miscategorization bugs across
    // acquire / commit / abort / abort_by_id / mark_leaked / reset paths
    // without needing an oracle for the expected pending count after a
    // mixed-operation sequence.
    // =========================================================================

    #[track_caller]
    fn assert_conservation(ledger: &ObligationLedger, step: &str) {
        let s = ledger.stats();
        let rhs = s.total_committed + s.total_aborted + s.total_leaked + s.pending;
        assert_eq!(
            s.total_acquired, rhs,
            "conservation violated after {step}: \
             acquired={} vs committed({})+aborted({})+leaked({})+pending({}) = {}",
            s.total_acquired, s.total_committed, s.total_aborted, s.total_leaked, s.pending, rhs,
        );
    }

    #[test]
    fn metamorphic_conservation_of_acquired_across_mixed_operations() {
        init_test("metamorphic_conservation_of_acquired_across_mixed_operations");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        assert_conservation(&ledger, "initial");

        // ---- Pre-reset phase: exercise all token-consuming + by-id paths ----

        let t1 = ledger.acquire(
            ObligationKind::SendPermit,
            task,
            region,
            Time::from_nanos(1),
        );
        assert_conservation(&ledger, "acquire t1");

        let t2 = ledger.acquire_with_context(
            ObligationKind::Ack,
            task,
            region,
            Time::from_nanos(2),
            SourceLocation::unknown(),
            None,
            Some("ctx".to_string()),
        );
        assert_conservation(&ledger, "acquire_with_context t2");

        let t3 = ledger.acquire(ObligationKind::Lease, task, region, Time::from_nanos(3));
        assert_conservation(&ledger, "acquire t3");

        let t3_id = t3.id();
        let pre_reset_acquired = ledger.stats().total_acquired;
        assert_eq!(pre_reset_acquired, 3);

        ledger.commit(t1, Time::from_nanos(10));
        assert_conservation(&ledger, "commit t1");

        ledger.abort(t2, Time::from_nanos(11), ObligationAbortReason::Cancel);
        assert_conservation(&ledger, "abort t2");

        // By-id resolution after original token has been dropped.
        drop(t3);
        ledger.abort_by_id(t3_id, Time::from_nanos(12), ObligationAbortReason::Explicit);
        assert_conservation(&ledger, "abort_by_id t3");

        let pre_reset = ledger.stats();
        assert_eq!(pre_reset.pending, 0);
        assert!(pre_reset.is_clean());
        assert_eq!(
            pre_reset.total_acquired,
            pre_reset.total_committed + pre_reset.total_aborted + pre_reset.total_leaked,
            "fully-resolved ledger satisfies conservation trivially with pending=0",
        );

        // ---- Reset midstream: counters zero, conservation holds trivially ----

        ledger.reset();
        assert_conservation(&ledger, "reset");
        let post_reset = ledger.stats();
        assert_eq!(post_reset, LedgerStats::default());

        // ---- Post-reset phase: re-acquire, include mark_leaked path ----

        let t4 = ledger.acquire(ObligationKind::SendPermit, task, region, Time::ZERO);
        assert_conservation(&ledger, "post-reset acquire t4");

        let t5 = ledger.acquire(ObligationKind::Ack, task, region, Time::from_nanos(1));
        assert_conservation(&ledger, "post-reset acquire t5");

        ledger.commit(t4, Time::from_nanos(5));
        assert_conservation(&ledger, "post-reset commit t4");

        let t5_id = t5.id();
        drop(t5);
        ledger.mark_leaked(t5_id, Time::from_nanos(6));
        assert_conservation(&ledger, "mark_leaked t5");

        let final_stats = ledger.stats();
        assert_eq!(final_stats.total_acquired, 2);
        assert_eq!(final_stats.total_committed, 1);
        assert_eq!(final_stats.total_aborted, 0);
        assert_eq!(final_stats.total_leaked, 1);
        assert_eq!(final_stats.pending, 0);
        assert!(
            !final_stats.is_clean(),
            "leaked obligation keeps ledger dirty"
        );
        assert_eq!(ledger.check_leaks().leaked.len(), 1);

        crate::test_complete!("metamorphic_conservation_of_acquired_across_mixed_operations");
    }

    // --- Metamorphic: conservation-of-acquired ------------------------------
    //
    // MR (conservation / flow invariant):
    //   stats.total_acquired
    //     == stats.total_committed
    //      + stats.total_aborted
    //      + stats.total_leaked
    //      + stats.pending
    //
    // Every acquired obligation is in exactly one of four terminal buckets —
    // committed, aborted, leaked, or still pending — so the sum of those
    // four counters must equal the running total of acquisitions at every
    // observable point. reset() zeros all five fields simultaneously, so
    // the equation stays 0 == 0 across the epoch boundary and can be driven
    // to hold again in the new epoch.
    //
    // Bug classes caught:
    //   * miscounted acquire/commit/abort/abort_by_id/mark_leaked paths
    //     (off-by-one, skipped increment, double increment)
    //   * mis-routing between terminal buckets (e.g. mark_leaked bumping
    //     total_aborted instead of total_leaked)
    //   * pending not decremented on a resolution path
    //   * reset() leaving one of the five fields non-zero
    //
    // Independence: orthogonal to region-partition, permutation-invariance,
    // and reset-generation MRs already in this module — those check
    // geometric or temporal relations, this one checks flow conservation.
    #[test]
    fn metamorphic_conservation_acquired_equals_resolved_plus_pending() {
        init_test("metamorphic_conservation_acquired_equals_resolved_plus_pending");
        let task = make_task();
        let region = make_region();

        fn check_conservation(ledger: &ObligationLedger, step: &str) {
            let s = ledger.stats();
            let resolved_plus_pending = s
                .total_committed
                .saturating_add(s.total_aborted)
                .saturating_add(s.total_leaked)
                .saturating_add(s.pending);
            assert_eq!(
                s.total_acquired,
                resolved_plus_pending,
                "conservation violated at {step}: \
                 total_acquired={} vs committed+aborted+leaked+pending={} \
                 (committed={}, aborted={}, leaked={}, pending={})",
                s.total_acquired,
                resolved_plus_pending,
                s.total_committed,
                s.total_aborted,
                s.total_leaked,
                s.pending
            );
        }

        let mut ledger = ObligationLedger::new();
        check_conservation(&ledger, "empty");

        // Phase 1: staggered acquisitions — conservation must hold after each.
        let mut live_tokens: Vec<ObligationToken> = Vec::new();
        for i in 0..6 {
            let kind = match i % 3 {
                0 => ObligationKind::SendPermit,
                1 => ObligationKind::Ack,
                _ => ObligationKind::Lease,
            };
            let tok = ledger.acquire(kind, task, region, Time::from_nanos(10 + i));
            live_tokens.push(tok);
            check_conservation(&ledger, "phase1.acquire");
        }
        assert_eq!(ledger.stats().total_acquired, 6);
        assert_eq!(ledger.stats().pending, 6);

        // Phase 2: mixed terminal resolutions across all four paths —
        // commit via token, abort via token, abort_by_id via id,
        // and mark_leaked via id. Conservation must hold after each.
        let tok_commit = live_tokens.remove(0);
        ledger.commit(tok_commit, Time::from_nanos(100));
        check_conservation(&ledger, "phase2.commit");

        let tok_abort = live_tokens.remove(0);
        ledger.abort(
            tok_abort,
            Time::from_nanos(110),
            ObligationAbortReason::Cancel,
        );
        check_conservation(&ledger, "phase2.abort");

        let tok_abort_by_id = live_tokens.remove(0);
        let id_for_abort_by_id = tok_abort_by_id.id();
        // Drop the token so only the ID path resolves the obligation.
        drop(tok_abort_by_id);
        ledger.abort_by_id(
            id_for_abort_by_id,
            Time::from_nanos(120),
            ObligationAbortReason::Error,
        );
        check_conservation(&ledger, "phase2.abort_by_id");

        let tok_leak = live_tokens.remove(0);
        let id_for_leak = tok_leak.id();
        drop(tok_leak);
        ledger.mark_leaked(id_for_leak, Time::from_nanos(130));
        check_conservation(&ledger, "phase2.mark_leaked");

        // Two obligations remain pending — conservation must still balance.
        assert_eq!(ledger.stats().pending, 2);
        assert_eq!(ledger.stats().total_committed, 1);
        assert_eq!(ledger.stats().total_aborted, 2);
        assert_eq!(ledger.stats().total_leaked, 1);

        let tok_pending_commit = live_tokens.remove(0);
        ledger.commit(tok_pending_commit, Time::from_nanos(140));
        check_conservation(&ledger, "phase2.resolve_pending_commit");

        let tok_pending_abort = live_tokens.remove(0);
        ledger.abort(
            tok_pending_abort,
            Time::from_nanos(150),
            ObligationAbortReason::Explicit,
        );
        check_conservation(&ledger, "phase2.resolve_pending_abort");
        assert!(live_tokens.is_empty());
        assert_eq!(ledger.stats().pending, 0);

        // Phase 3: reset requires a clean ledger, then zeros all five counters
        // simultaneously. The ledger above intentionally exercised the leaked
        // bucket, so keep that ledger as leak-conservation evidence and use a
        // clean fully resolved ledger for the reset contract.
        assert!(!ledger.stats().is_clean());

        let mut reset_ledger = ObligationLedger::new();
        let reset_commit = reset_ledger.acquire(
            ObligationKind::SendPermit,
            task,
            region,
            Time::from_nanos(160),
        );
        let reset_abort =
            reset_ledger.acquire(ObligationKind::Ack, task, region, Time::from_nanos(170));
        reset_ledger.commit(reset_commit, Time::from_nanos(180));
        reset_ledger.abort(
            reset_abort,
            Time::from_nanos(190),
            ObligationAbortReason::Explicit,
        );
        check_conservation(&reset_ledger, "phase3.clean_pre_reset");
        assert!(reset_ledger.stats().is_clean());

        reset_ledger.reset();
        check_conservation(&reset_ledger, "phase3.reset");
        assert_eq!(reset_ledger.stats().total_acquired, 0);
        assert!(reset_ledger.stats().is_clean());

        // Phase 4: re-acquire after reset and resolve one to confirm the
        // invariant tracks across the epoch boundary (the token held across
        // reset has been invalidated by the generation bump; any attempt to
        // commit it would panic — see metamorphic_post_reset_* tests).
        let post_reset = reset_ledger.acquire(
            ObligationKind::SendPermit,
            task,
            region,
            Time::from_nanos(200),
        );
        check_conservation(&reset_ledger, "phase4.post_reset_acquire");
        reset_ledger.commit(post_reset, Time::from_nanos(210));
        check_conservation(&reset_ledger, "phase4.post_reset_commit");
        assert_eq!(reset_ledger.stats().total_acquired, 1);
        assert_eq!(reset_ledger.stats().total_committed, 1);
        assert_eq!(reset_ledger.stats().pending, 0);

        crate::test_complete!("metamorphic_conservation_acquired_equals_resolved_plus_pending");
    }

    /// br-asupersync-qyf37e: try_commit on a token whose region has
    /// been marked finalized must return Err(LedgerError::RegionFinalized).
    /// This pins the public surface that Drop impls / detached
    /// handlers should use when racing region close.
    #[test]
    fn qyf37e_try_commit_after_region_finalized_returns_err() {
        let mut ledger = ObligationLedger::new();
        let region = make_region();
        let task = TaskId::from_arena(ArenaIndex::new(1, 0));
        let token = ledger.acquire(
            ObligationKind::SendPermit,
            task,
            region,
            Time::from_nanos(0),
        );

        // Mark the owning region finalized — the structured-concurrency
        // finalize phase has completed and the obligation should not
        // be allowed to transition.
        ledger.mark_region_finalized(region);
        assert!(ledger.is_region_finalized(region));

        let obligation_id = token.id();
        let err = ledger
            .try_commit(token, Time::from_nanos(100))
            .expect_err("late commit must be rejected after region finalize");

        match err {
            LedgerError::RegionFinalized {
                region: r,
                obligation: o,
            } => {
                assert_eq!(r, region);
                assert_eq!(o, obligation_id);
            }
            other => panic!("expected RegionFinalized, got {other:?}"),
        }

        // The obligation record is still pending (we did not mutate it).
        assert_eq!(ledger.stats().pending, 1);
        assert_eq!(ledger.stats().total_committed, 0);
    }

    /// br-asupersync-qyf37e: same shape for try_abort.
    #[test]
    fn qyf37e_try_abort_after_region_finalized_returns_err() {
        let mut ledger = ObligationLedger::new();
        let region = make_region();
        let task = TaskId::from_arena(ArenaIndex::new(1, 0));
        let token = ledger.acquire(
            ObligationKind::SendPermit,
            task,
            region,
            Time::from_nanos(0),
        );
        ledger.mark_region_finalized(region);

        let err = ledger
            .try_abort(token, Time::from_nanos(100), ObligationAbortReason::Cancel)
            .expect_err("late abort must be rejected after region finalize");

        match err {
            LedgerError::RegionFinalized { .. } => {}
            other => panic!("expected RegionFinalized, got {other:?}"),
        }
        assert_eq!(ledger.stats().pending, 1);
        assert_eq!(ledger.stats().total_aborted, 0);
    }

    /// br-asupersync-qyf37e: try_commit on a NOT-finalized region
    /// passes through to commit and returns the duration.
    #[test]
    fn qyf37e_try_commit_before_region_finalized_succeeds() {
        let mut ledger = ObligationLedger::new();
        let region = make_region();
        let task = TaskId::from_arena(ArenaIndex::new(1, 0));
        let token = ledger.acquire(
            ObligationKind::SendPermit,
            task,
            region,
            Time::from_nanos(0),
        );
        let duration = ledger
            .try_commit(token, Time::from_nanos(100))
            .expect("commit before finalize must succeed");
        assert_eq!(duration, 100);
        assert_eq!(ledger.stats().total_committed, 1);
        assert_eq!(ledger.stats().pending, 0);
    }

    // ================================================================
    // br-asupersync-12cqs2 — acquire_with_context fence
    // ================================================================

    /// br-asupersync-12cqs2: try_acquire on a finalized region must
    /// return Err(LedgerError::RegionFinalized) WITHOUT minting a
    /// token, incrementing stats, or otherwise mutating the ledger.
    #[test]
    fn b12cqs2_try_acquire_after_region_finalized_returns_err() {
        let mut ledger = ObligationLedger::new();
        let region = make_region();
        let task = TaskId::from_arena(ArenaIndex::new(1, 0));

        ledger.mark_region_finalized(region);
        assert!(ledger.is_region_finalized(region));

        let stats_before = ledger.stats();
        let err = ledger
            .try_acquire(
                ObligationKind::SendPermit,
                task,
                region,
                Time::from_nanos(0),
            )
            .expect_err("acquire on finalized region must be rejected");

        match err {
            LedgerError::RegionFinalized { region: r, .. } => assert_eq!(r, region),
            other => panic!("expected RegionFinalized, got {other:?}"),
        }

        // No mutation: stats unchanged.
        let stats_after = ledger.stats();
        assert_eq!(stats_after.total_acquired, stats_before.total_acquired);
        assert_eq!(stats_after.pending, stats_before.pending);
    }

    /// br-asupersync-12cqs2: try_acquire on a NOT-finalized region
    /// behaves like the infallible acquire (mints a token).
    #[test]
    fn b12cqs2_try_acquire_before_finalize_succeeds() {
        let mut ledger = ObligationLedger::new();
        let region = make_region();
        let task = TaskId::from_arena(ArenaIndex::new(1, 0));

        let token = ledger
            .try_acquire(ObligationKind::Lease, task, region, Time::from_nanos(0))
            .expect("acquire before finalize must succeed");
        assert_eq!(token.kind(), ObligationKind::Lease);
        assert_eq!(ledger.stats().pending, 1);
    }

    /// br-asupersync-12cqs2: the infallible `acquire` PANICS when
    /// called on a finalized region. This pins the contract that
    /// late-arrival callers MUST use try_acquire instead.
    #[test]
    #[should_panic(expected = "br-asupersync-12cqs2")]
    fn b12cqs2_infallible_acquire_after_finalize_panics() {
        let mut ledger = ObligationLedger::new();
        let region = make_region();
        let task = TaskId::from_arena(ArenaIndex::new(1, 0));
        ledger.mark_region_finalized(region);
        let _ = ledger.acquire(
            ObligationKind::SendPermit,
            task,
            region,
            Time::from_nanos(0),
        );
    }

    // ================================================================
    // br-asupersync-u1gcfp — commit/abort fence (silent bail)
    // ================================================================

    /// br-asupersync-u1gcfp: infallible `commit` on a token whose
    /// region was finalized after token mint MUST bail silently
    /// (return 0, no mutation). This protects Drop impls that call
    /// `ledger.commit` unconditionally from mutating the ledger past
    /// region finalize.
    #[test]
    fn b_u1gcfp_commit_after_finalize_bails_silently() {
        let mut ledger = ObligationLedger::new();
        let region = make_region();
        let task = TaskId::from_arena(ArenaIndex::new(1, 0));
        let token = ledger.acquire(
            ObligationKind::SendPermit,
            task,
            region,
            Time::from_nanos(0),
        );
        let stats_after_acquire = ledger.stats();
        assert_eq!(stats_after_acquire.pending, 1);

        ledger.mark_region_finalized(region);

        let duration = ledger.commit(token, Time::from_nanos(100));
        assert_eq!(duration, 0, "commit on finalized region must return 0");

        // No mutation: stats are unchanged from the post-acquire snapshot.
        let stats_after_commit = ledger.stats();
        assert_eq!(stats_after_commit.total_committed, 0);
        assert_eq!(stats_after_commit.pending, stats_after_acquire.pending);
    }

    /// br-asupersync-u1gcfp: same fail-closed contract for abort.
    #[test]
    fn b_u1gcfp_abort_after_finalize_bails_silently() {
        let mut ledger = ObligationLedger::new();
        let region = make_region();
        let task = TaskId::from_arena(ArenaIndex::new(1, 0));
        let token = ledger.acquire(ObligationKind::Lease, task, region, Time::from_nanos(0));
        ledger.mark_region_finalized(region);

        let duration = ledger.abort(token, Time::from_nanos(50), ObligationAbortReason::Cancel);
        assert_eq!(duration, 0, "abort on finalized region must return 0");

        let stats = ledger.stats();
        assert_eq!(stats.total_aborted, 0);
        assert_eq!(stats.pending, 1);
    }

    /// br-asupersync-u1gcfp: same fail-closed contract for abort_by_id.
    #[test]
    fn b_u1gcfp_abort_by_id_after_finalize_bails_silently() {
        let mut ledger = ObligationLedger::new();
        let region = make_region();
        let task = TaskId::from_arena(ArenaIndex::new(1, 0));
        let token = ledger.acquire(ObligationKind::IoOp, task, region, Time::from_nanos(0));
        let id = token.id();
        ledger.mark_region_finalized(region);

        let duration = ledger.abort_by_id(id, Time::from_nanos(50), ObligationAbortReason::Cancel);
        assert_eq!(duration, 0, "abort_by_id on finalized region must return 0");

        assert_eq!(ledger.stats().total_aborted, 0);
        assert_eq!(ledger.stats().pending, 1);
    }
}
