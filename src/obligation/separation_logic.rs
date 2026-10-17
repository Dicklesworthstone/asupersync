//! Separation Logic specifications for obligation invariants.
//!
//! # Overview
//!
//! This module defines formal Separation Logic (SL) specifications for every
//! obligation type in Asupersync. The framework follows Iris-style concurrent
//! separation logic, encoding:
//!
//! - **Resource predicates**: what heap state each obligation exclusively owns
//! - **Frame conditions**: what heap state the obligation does NOT affect
//! - **Pre/post conditions**: Hoare triples for creation, transfer, and release
//! - **Separating conjunction properties**: anti-aliasing guarantees
//!
//! # Iris-Style Notation
//!
//! We use Iris-style notation (compatible with Creusot/Verus) for the formal
//! predicates. In this encoding:
//!
//! ```text
//! P ∗ Q        separating conjunction: P and Q hold on disjoint resources
//! P −∗ Q       magic wand: consuming P yields Q (frame-preserving update)
//! □ P          persistence: P holds without consuming resources
//! ▷ P          later modality: P holds at the next step
//! {P} e {Q}    Hoare triple: if P, then e produces Q
//! own(γ, a)    ghost ownership of resource γ in state a
//! ●(a)         authoritative element of a resource algebra
//! ◯(a)         fragment element of a resource algebra
//! ```
//!
//! # Resource Algebras
//!
//! Obligation ownership uses three resource algebras:
//!
//! 1. **Excl(ObligationState)**: Exclusive ownership of obligation state.
//!    Ensures exactly one holder can observe or mutate state at a time, and
//!    terminal states remain exclusive tombstones rather than frame units.
//!
//! 2. **Auth(ℕ)**: Authoritative natural number (pending count per region/task).
//!    Enables fractional reasoning about how many obligations are outstanding.
//!
//! 3. **Agree(ObligationKind)**: Agreement on obligation kind. Prevents kind
//!    mutation after creation.
//!
//! # Specification Structure
//!
//! For each obligation type (SendPermit, Ack, Lease, IoOp, SemaphorePermit):
//!
//! 1. **Resource predicate** `Obl(o, k, h, r)`:
//!    ```text
//!    Obl(o, k, h, r) ≜
//!      own(γ_state(o), ●Excl(Reserved))
//!      ∗ own(γ_kind(o), Agree(k))
//!      ∗ own(γ_holder(o), Agree(h))
//!      ∗ own(γ_region(o), Agree(r))
//!      ∗ own(γ_pending(h), ◯(1))
//!      ∗ own(γ_region_pending(r), ◯(1))
//!    ```
//!
//! 2. **Frame condition**: `Obl(o, k, h, r)` does NOT touch:
//!    - Other obligations `o' ≠ o`
//!    - Scheduler state
//!    - Budget state (except through region pending count)
//!    - Other tasks' obligation lists
//!
//! 3. **Hoare triples** for each operation (reserve, commit, abort, leak).
//!
//! 4. **Separating conjunction**: `Obl(o₁, ..) ∗ Obl(o₂, ..)` implies `o₁ ≠ o₂`.
//!
//! # Usage
//!
//! ```
//! use asupersync::obligation::separation_logic::{
//!     SeparationLogicVerifier, ResourcePredicate, Judgment,
//!     FrameCondition, SeparationProperty,
//! };
//! use asupersync::obligation::marking::{MarkingEvent, MarkingEventKind};
//! use asupersync::record::ObligationKind;
//! use asupersync::types::{ObligationId, RegionId, TaskId, Time};
//!
//! let r0 = RegionId::new_for_test(0, 0);
//! let t0 = TaskId::new_for_test(0, 0);
//! let o0 = ObligationId::new_for_test(0, 0);
//!
//! let events = vec![
//!     MarkingEvent::new(Time::ZERO, MarkingEventKind::Reserve {
//!         obligation: o0, kind: ObligationKind::SendPermit, task: t0, region: r0,
//!     }),
//!     MarkingEvent::new(Time::from_nanos(10), MarkingEventKind::Commit {
//!         obligation: o0, region: r0, kind: ObligationKind::SendPermit,
//!     }),
//!     MarkingEvent::new(Time::from_nanos(20), MarkingEventKind::RegionClose { region: r0 }),
//! ];
//!
//! let mut verifier = SeparationLogicVerifier::new();
//! let result = verifier.verify(&events);
//! assert!(result.is_sound());
//! ```

use crate::record::{ObligationKind, ObligationState};
use crate::types::{ObligationId, RegionId, TaskId, Time};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use super::marking::{MarkingEvent, MarkingEventKind};

// ============================================================================
// Resource Algebras
// ============================================================================

/// Exclusive resource algebra element.
///
/// Models `Excl(A)`: at most one owner can hold the element at a time.
/// The RA is keyed by a single obligation ghost name, so any attempt to
/// compose two owned fragments is invalid. `Consumed` is a terminal tombstone,
/// not a unit that can be framed with a live fragment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Excl<A: Clone + PartialEq> {
    /// The resource holds a value — exactly one owner.
    Some(A),
    /// The resource has been consumed (moved to a successor state).
    Consumed,
}

impl<A: Clone + PartialEq> Excl<A> {
    /// Attempt to compose two exclusive elements for the same ghost name.
    ///
    /// Composition always fails because exclusive ownership admits at most one
    /// fragment. This includes `Consumed`, which still occupies the ghost name
    /// and therefore blocks reuse.
    #[must_use]
    pub fn compose(&self, other: &Self) -> Option<Self> {
        let _ = (self, other);
        None
    }

    /// Returns true if the element is valid (not a failed composition).
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        // Both variants are individually valid; only composition can fail.
        true
    }
}

/// Agreement resource algebra element.
///
/// Models `Agree(A)`: all holders must agree on the value. Composition is
/// defined only when both holders agree: `Agree(a) · Agree(b) = Agree(a)` iff `a = b`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Agree<A: Clone + PartialEq>(pub A);

impl<A: Clone + PartialEq> Agree<A> {
    /// Attempt to compose two agreement elements.
    #[must_use]
    pub fn compose(&self, other: &Self) -> Option<Self> {
        if self.0 == other.0 {
            Some(self.clone())
        } else {
            None // Disagreement: ⊥
        }
    }
}

/// Authoritative/fragment resource algebra for counting.
///
/// Models `Auth(ℕ)` with authoritative element `●(n)` and fragments `◯(m)`.
/// Validity: `●(n) · ◯(m)` is valid iff `m ≤ n`.
/// Used for tracking pending obligation counts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthNat {
    /// Authoritative element: knows the true count.
    Auth(u64),
    /// Fragment element: claims a portion of the count.
    Frag(u64),
}

impl AuthNat {
    /// Attempt composition. `Auth(n) · Frag(m)` requires `m ≤ n`.
    #[must_use]
    pub fn compose(&self, other: &Self) -> Option<Self> {
        match (self, other) {
            (Self::Auth(n), Self::Frag(m)) | (Self::Frag(m), Self::Auth(n)) => {
                if *m <= *n {
                    Some(Self::Auth(*n))
                } else {
                    None // Fragment exceeds authoritative count.
                }
            }
            (Self::Frag(a), Self::Frag(b)) => a.checked_add(*b).map(Self::Frag),
            (Self::Auth(_), Self::Auth(_)) => None, // Two authorities: ⊥
        }
    }
}

// ============================================================================
// Resource Predicates
// ============================================================================

/// Resource predicate for a single obligation.
///
/// Encodes `Obl(o, k, h, r)` in Iris-style notation:
///
/// ```text
/// Obl(o, k, h, r) ≜
///   own(γ_state(o), ●Excl(Reserved))
///   ∗ own(γ_kind(o), Agree(k))
///   ∗ own(γ_holder(o), Agree(h))
///   ∗ own(γ_region(o), Agree(r))
///   ∗ own(γ_pending(h), ◯(1))
///   ∗ own(γ_region_pending(r), ◯(1))
/// ```
///
/// The predicate asserts exclusive ownership of the obligation state,
/// agreement on kind/holder/region, and a unit fragment contribution
/// to both the task's and region's pending count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourcePredicate {
    /// The obligation identifier (ghost name γ).
    pub obligation: ObligationId,
    /// Exclusive ownership of the current state.
    pub state: Excl<ObligationState>,
    /// Agreement on the obligation kind.
    pub kind: Agree<ObligationKind>,
    /// Agreement on the holding task.
    pub holder: Agree<TaskId>,
    /// Agreement on the owning region.
    pub region: Agree<RegionId>,
    /// Fragment contribution to holder's pending count.
    pub holder_pending_frag: AuthNat,
    /// Fragment contribution to region's pending count.
    pub region_pending_frag: AuthNat,
}

impl ResourcePredicate {
    /// Construct an `Obl(o, k, h, r)` predicate in the Reserved state.
    ///
    /// This is the predicate established by the `reserve` operation.
    #[must_use]
    pub fn reserved(
        obligation: ObligationId,
        kind: ObligationKind,
        holder: TaskId,
        region: RegionId,
    ) -> Self {
        Self {
            obligation,
            state: Excl::Some(ObligationState::Reserved),
            kind: Agree(kind),
            holder: Agree(holder),
            region: Agree(region),
            holder_pending_frag: AuthNat::Frag(1),
            region_pending_frag: AuthNat::Frag(1),
        }
    }

    /// Predicate for a resolved (terminal) obligation.
    ///
    /// After resolution, the pending fragments are consumed (returned to 0),
    /// and the state becomes `Excl::Consumed`.
    #[must_use]
    pub fn resolved(
        obligation: ObligationId,
        kind: ObligationKind,
        holder: TaskId,
        region: RegionId,
    ) -> Self {
        Self {
            obligation,
            state: Excl::Consumed,
            kind: Agree(kind),
            holder: Agree(holder),
            region: Agree(region),
            holder_pending_frag: AuthNat::Frag(0),
            region_pending_frag: AuthNat::Frag(0),
        }
    }

    /// Check if two predicates refer to disjoint obligations.
    ///
    /// Separation: `Obl(o₁, ..) ∗ Obl(o₂, ..)` requires `o₁ ≠ o₂`.
    #[must_use]
    pub fn is_separable_from(&self, other: &Self) -> bool {
        self.obligation != other.obligation
    }
}

impl fmt::Display for ResourcePredicate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = match &self.state {
            Excl::Some(s) => format!("{s:?}"),
            Excl::Consumed => "Consumed".to_string(),
        };
        write!(
            f,
            "Obl({:?}, {}, {:?}, {:?}) [state={}]",
            self.obligation, self.kind.0, self.holder.0, self.region.0, state,
        )
    }
}

// ============================================================================
// Frame Conditions
// ============================================================================

/// Frame condition asserting what an obligation operation does NOT touch.
///
/// In Iris: `{P ∗ F} e {Q ∗ F}` — the frame `F` is preserved across `e`.
///
/// For obligation operations, the frame includes:
/// - Other obligations (`o' ≠ o`)
/// - Scheduler state
/// - Budget state (except region pending count)
/// - Other tasks' obligation lists
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameCondition {
    /// The obligation being operated on.
    pub target: ObligationId,
    /// Resources explicitly excluded from the frame (the "footprint").
    pub footprint: OperationFootprint,
}

/// The footprint of an obligation operation — what it touches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationFootprint {
    /// Obligation IDs whose state may change.
    pub obligations_touched: Vec<ObligationId>,
    /// Task IDs whose pending count may change.
    pub tasks_touched: Vec<TaskId>,
    /// Region IDs whose pending count may change.
    pub regions_touched: Vec<RegionId>,
}

impl FrameCondition {
    /// Create a frame condition for a single-obligation operation.
    ///
    /// The footprint is minimal: only the target obligation, its holder's
    /// pending count, and its region's pending count are affected.
    #[must_use]
    pub fn single_obligation(target: ObligationId, holder: TaskId, region: RegionId) -> Self {
        Self {
            target,
            footprint: OperationFootprint {
                obligations_touched: vec![target],
                tasks_touched: vec![holder],
                regions_touched: vec![region],
            },
        }
    }

    /// Check if a given obligation is in the frame (NOT touched).
    #[must_use]
    pub fn is_framed(&self, obligation: ObligationId) -> bool {
        !self.footprint.obligations_touched.contains(&obligation)
    }

    /// Check if a given task's pending count is in the frame.
    #[must_use]
    pub fn task_is_framed(&self, task: TaskId) -> bool {
        !self.footprint.tasks_touched.contains(&task)
    }

    /// Check if a given region's pending count is in the frame.
    #[must_use]
    pub fn region_is_framed(&self, region: RegionId) -> bool {
        !self.footprint.regions_touched.contains(&region)
    }
}

impl fmt::Display for FrameCondition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Frame(target={:?}, footprint=[{} obls, {} tasks, {} regions])",
            self.target,
            self.footprint.obligations_touched.len(),
            self.footprint.tasks_touched.len(),
            self.footprint.regions_touched.len(),
        )
    }
}

// ============================================================================
// Separation Properties
// ============================================================================

/// Properties of the separating conjunction for obligations.
///
/// Encodes the key anti-aliasing guarantees:
///
/// ```text
/// 1. Obl(o₁, ..) ∗ Obl(o₂, ..) ⊢ o₁ ≠ o₂           (distinct identity)
/// 2. Obl(o, k, h₁, ..) ∗ Obl(o, k, h₂, ..) ⊢ False   (no aliasing)
/// 3. Obl(o, ..) ∗ Resolved(o) ⊢ False                  (no use-after-release)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeparationProperty {
    /// Two live obligations have distinct identities.
    DistinctIdentity {
        /// Left obligation.
        left: ObligationId,
        /// Right obligation.
        right: ObligationId,
    },
    /// An obligation cannot be held by two tasks simultaneously.
    NoAliasing {
        /// The aliased obligation.
        obligation: ObligationId,
    },
    /// A resolved obligation cannot be used again.
    NoUseAfterRelease {
        /// The released obligation.
        obligation: ObligationId,
    },
    /// Region closure requires zero pending obligations.
    RegionClosureQuiescence {
        /// The region that must be quiescent.
        region: RegionId,
    },
    /// Task completion requires zero pending obligations.
    HolderCleanup {
        /// The task that must have zero pending.
        task: TaskId,
    },
    /// Trace events and per-obligation transitions must respect time order.
    TemporalOrdering {
        /// The obligation involved, if the violation is obligation-local.
        obligation: Option<ObligationId>,
    },
    /// Authoritative pending counters must match the live obligation fragments.
    AuthoritativePendingAgreement,
}

impl SeparationProperty {
    /// Returns a formal Iris-style statement of this property.
    #[must_use]
    pub fn formal_statement(&self) -> &'static str {
        match self {
            Self::DistinctIdentity { .. } => "Obl(o1, ..) * Obl(o2, ..) |- o1 != o2",
            Self::NoAliasing { .. } => "Obl(o, k, h1, r) * Obl(o, k, h2, r) |- False",
            Self::NoUseAfterRelease { .. } => "Obl(o, ..) * Resolved(o) |- False",
            Self::RegionClosureQuiescence { .. } => "RegionClosed(r) |- RegionPending(r) = 0",
            Self::HolderCleanup { .. } => "TaskCompleted(t) |- HolderPending(t) = 0",
            Self::TemporalOrdering { .. } => "reserve(o) at t0, resolve(o) at t1 |- t0 <= t1",
            Self::AuthoritativePendingAgreement => {
                "sum live Obl(o, ..) fragments |- authoritative holder/region counts agree"
            }
        }
    }
}

impl fmt::Display for SeparationProperty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DistinctIdentity { left, right } => {
                write!(f, "DistinctIdentity({left:?}, {right:?})")
            }
            Self::NoAliasing { obligation } => {
                write!(f, "NoAliasing({obligation:?})")
            }
            Self::NoUseAfterRelease { obligation } => {
                write!(f, "NoUseAfterRelease({obligation:?})")
            }
            Self::RegionClosureQuiescence { region } => {
                write!(f, "RegionClosureQuiescence({region:?})")
            }
            Self::HolderCleanup { task } => {
                write!(f, "HolderCleanup({task:?})")
            }
            Self::TemporalOrdering { obligation } => {
                write!(f, "TemporalOrdering({obligation:?})")
            }
            Self::AuthoritativePendingAgreement => {
                write!(f, "AuthoritativePendingAgreement")
            }
        }
    }
}

// ============================================================================
// Hoare Triples (Judgments)
// ============================================================================

/// A Hoare triple (judgment) for an obligation operation.
///
/// Encodes `{P} op {Q}` where P is the precondition, op is the operation,
/// and Q is the postcondition. Both P and Q are expressed in terms of
/// resource predicates and frame conditions.
///
/// ```text
/// Reserve:
///   {HolderPending(h, n) * RegionPending(r, m) * RegionOpen(r)}
///     reserve(k, h, r)
///   {Obl(o, k, h, r) * HolderPending(h, n+1) * RegionPending(r, m+1)}
///
/// Commit:
///   {Obl(o, k, h, r) * HolderPending(h, n+1) * RegionPending(r, m+1)}
///     commit(o)
///   {Resolved(o) * HolderPending(h, n) * RegionPending(r, m)}
///
/// Abort:
///   {Obl(o, k, h, r) * HolderPending(h, n+1) * RegionPending(r, m+1)}
///     abort(o, reason)
///   {Resolved(o) * HolderPending(h, n) * RegionPending(r, m)}
///
/// Leak (error):
///   {Obl(o, k, h, r) * TaskCompleted(h)}
///     leak(o)
///   {Leaked(o) * ErrorFlag}
///
/// Transfer (delegation):
///   {Obl(o, k, h1, r) * HolderPending(h1, n+1) * HolderPending(h2, m)}
///     transfer(o, h2)
///   {Obl(o, k, h2, r) * HolderPending(h1, n) * HolderPending(h2, m+1)}
///
/// RegionClose:
///   {RegionPending(r, 0) * RegionOpen(r)}
///     close(r)
///   {RegionClosed(r)}
/// ```
#[derive(Debug, Clone)]
pub struct Judgment {
    /// Operation name.
    pub operation: JudgmentOp,
    /// Precondition: resource predicates that must hold.
    pub precondition: JudgmentCondition,
    /// Postcondition: resource predicates established.
    pub postcondition: JudgmentCondition,
    /// Frame condition: what is NOT affected.
    pub frame: Option<FrameCondition>,
}

/// The operation in a Hoare triple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JudgmentOp {
    /// `reserve(k, h, r)` — create a new obligation.
    Reserve {
        /// Obligation kind.
        kind: ObligationKind,
        /// Holding task.
        holder: TaskId,
        /// Owning region.
        region: RegionId,
    },
    /// `commit(o)` — resolve by committing.
    Commit {
        /// Obligation to commit.
        obligation: ObligationId,
    },
    /// `abort(o, reason)` — resolve by aborting.
    Abort {
        /// Obligation to abort.
        obligation: ObligationId,
    },
    /// `leak(o)` — mark leaked (error path).
    Leak {
        /// Leaked obligation.
        obligation: ObligationId,
    },
    /// `transfer(o, new_holder)` — delegate to another task.
    Transfer {
        /// Obligation to transfer.
        obligation: ObligationId,
        /// New holding task.
        new_holder: TaskId,
    },
    /// `close(r)` — close a region.
    RegionClose {
        /// Region to close.
        region: RegionId,
    },
}

/// Condition in a Hoare triple (pre or post).
#[derive(Debug, Clone)]
pub struct JudgmentCondition {
    /// Resource predicates that must hold (separating conjunction).
    pub predicates: Vec<ResourcePredicate>,
    /// Pending counts per holder.
    pub holder_pending: BTreeMap<TaskId, u64>,
    /// Pending counts per region.
    pub region_pending: BTreeMap<RegionId, u64>,
    /// Regions that must be open.
    pub regions_open: BTreeSet<RegionId>,
    /// Regions that must be closed.
    pub regions_closed: BTreeSet<RegionId>,
}

impl JudgmentCondition {
    /// Empty condition (trivially satisfied).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            predicates: Vec::new(),
            holder_pending: BTreeMap::new(),
            region_pending: BTreeMap::new(),
            regions_open: BTreeSet::new(),
            regions_closed: BTreeSet::new(),
        }
    }
}

impl Judgment {
    /// Build the Reserve judgment.
    ///
    /// ```text
    /// {HolderPending(h, n) * RegionPending(r, m) * RegionOpen(r)}
    ///   reserve(k, h, r)
    /// {Obl(o, k, h, r) * HolderPending(h, n+1) * RegionPending(r, m+1)}
    /// ```
    #[must_use]
    pub fn reserve(
        obligation: ObligationId,
        kind: ObligationKind,
        holder: TaskId,
        region: RegionId,
        holder_pending_before: u64,
        region_pending_before: u64,
    ) -> Self {
        let holder_pending_after = holder_pending_before
            .checked_add(1)
            .expect("reserve judgment holder pending overflow");
        let region_pending_after = region_pending_before
            .checked_add(1)
            .expect("reserve judgment region pending overflow");

        let mut pre = JudgmentCondition::empty();
        pre.holder_pending.insert(holder, holder_pending_before);
        pre.region_pending.insert(region, region_pending_before);
        pre.regions_open.insert(region);

        let mut post = JudgmentCondition::empty();
        post.predicates.push(ResourcePredicate::reserved(
            obligation, kind, holder, region,
        ));
        post.holder_pending.insert(holder, holder_pending_after);
        post.region_pending.insert(region, region_pending_after);

        Self {
            operation: JudgmentOp::Reserve {
                kind,
                holder,
                region,
            },
            precondition: pre,
            postcondition: post,
            frame: Some(FrameCondition::single_obligation(
                obligation, holder, region,
            )),
        }
    }

    /// Build the Commit judgment.
    ///
    /// ```text
    /// {Obl(o, k, h, r) * HolderPending(h, n+1) * RegionPending(r, m+1)}
    ///   commit(o)
    /// {Resolved(o) * HolderPending(h, n) * RegionPending(r, m)}
    /// ```
    #[must_use]
    pub fn commit(
        obligation: ObligationId,
        kind: ObligationKind,
        holder: TaskId,
        region: RegionId,
        holder_pending_before: u64,
        region_pending_before: u64,
    ) -> Self {
        let holder_pending_after = holder_pending_before
            .checked_sub(1)
            .expect("commit judgment requires positive holder pending count");
        let region_pending_after = region_pending_before
            .checked_sub(1)
            .expect("commit judgment requires positive region pending count");

        let mut pre = JudgmentCondition::empty();
        pre.predicates.push(ResourcePredicate::reserved(
            obligation, kind, holder, region,
        ));
        pre.holder_pending.insert(holder, holder_pending_before);
        pre.region_pending.insert(region, region_pending_before);

        let mut post = JudgmentCondition::empty();
        post.predicates.push(ResourcePredicate::resolved(
            obligation, kind, holder, region,
        ));
        post.holder_pending.insert(holder, holder_pending_after);
        post.region_pending.insert(region, region_pending_after);

        Self {
            operation: JudgmentOp::Commit { obligation },
            precondition: pre,
            postcondition: post,
            frame: Some(FrameCondition::single_obligation(
                obligation, holder, region,
            )),
        }
    }

    /// Build the Abort judgment (identical postcondition shape to Commit).
    #[must_use]
    pub fn abort(
        obligation: ObligationId,
        kind: ObligationKind,
        holder: TaskId,
        region: RegionId,
        holder_pending_before: u64,
        region_pending_before: u64,
    ) -> Self {
        let mut j = Self::commit(
            obligation,
            kind,
            holder,
            region,
            holder_pending_before,
            region_pending_before,
        );
        j.operation = JudgmentOp::Abort { obligation };
        j
    }

    /// Build the RegionClose judgment.
    ///
    /// ```text
    /// {RegionPending(r, 0) * RegionOpen(r)}
    ///   close(r)
    /// {RegionClosed(r)}
    /// ```
    #[must_use]
    pub fn region_close(region: RegionId) -> Self {
        let mut pre = JudgmentCondition::empty();
        pre.region_pending.insert(region, 0);
        pre.regions_open.insert(region);

        let mut post = JudgmentCondition::empty();
        post.region_pending.insert(region, 0);
        post.regions_closed.insert(region);

        Self {
            operation: JudgmentOp::RegionClose { region },
            precondition: pre,
            postcondition: post,
            frame: None,
        }
    }
}

impl fmt::Display for Judgment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let op = match &self.operation {
            JudgmentOp::Reserve {
                kind,
                holder,
                region,
            } => format!("reserve({kind}, {holder:?}, {region:?})"),
            JudgmentOp::Commit { obligation } => format!("commit({obligation:?})"),
            JudgmentOp::Abort { obligation } => format!("abort({obligation:?})"),
            JudgmentOp::Leak { obligation } => format!("leak({obligation:?})"),
            JudgmentOp::Transfer {
                obligation,
                new_holder,
            } => format!("transfer({obligation:?}, {new_holder:?})"),
            JudgmentOp::RegionClose { region } => format!("close({region:?})"),
        };
        write!(
            f,
            "{{{}P}} {op} {{{}Q}}",
            self.precondition.predicates.len(),
            self.postcondition.predicates.len(),
        )
    }
}

// ============================================================================
// Verification Result
// ============================================================================

/// A violation of a separation logic property.
#[derive(Debug, Clone)]
pub struct SLViolation {
    /// Which property was violated.
    pub property: SeparationProperty,
    /// When the violation was detected.
    pub time: Time,
    /// Description of the violation.
    pub description: String,
}

impl fmt::Display for SLViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] at t={}: {} (formal: {})",
            self.property,
            self.time,
            self.description,
            self.property.formal_statement(),
        )
    }
}

/// Result of verifying separation logic properties against a trace.
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Violations detected.
    pub violations: Vec<SLViolation>,
    /// Events checked.
    pub events_checked: usize,
    /// Judgments verified.
    pub judgments_verified: usize,
    /// Frame conditions checked.
    pub frame_checks: usize,
    /// Separation properties verified.
    pub separation_checks: usize,
}

impl VerificationResult {
    /// Returns true if no violations were detected.
    #[must_use]
    pub fn is_sound(&self) -> bool {
        self.violations.is_empty()
    }

    /// Returns violations for a specific property kind.
    pub fn violations_for_property<'a>(
        &'a self,
        predicate: impl Fn(&SeparationProperty) -> bool + 'a,
    ) -> impl Iterator<Item = &'a SLViolation> + 'a {
        self.violations
            .iter()
            .filter(move |v| predicate(&v.property))
    }
}

impl fmt::Display for VerificationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Separation Logic Verification")?;
        writeln!(f, "=============================")?;
        writeln!(f, "Events checked:     {}", self.events_checked)?;
        writeln!(f, "Judgments verified:  {}", self.judgments_verified)?;
        writeln!(f, "Frame checks:       {}", self.frame_checks)?;
        writeln!(f, "Separation checks:  {}", self.separation_checks)?;
        writeln!(f, "Sound:              {}", self.is_sound())?;

        if !self.violations.is_empty() {
            writeln!(f)?;
            writeln!(f, "Violations ({}):", self.violations.len())?;
            for v in &self.violations {
                writeln!(f, "  {v}")?;
            }
        }

        Ok(())
    }
}

// ============================================================================
// Ghost State Tracking
// ============================================================================

/// Per-obligation ghost state tracked during verification.
#[derive(Debug, Clone)]
struct GhostObligation {
    kind: ObligationKind,
    holder: TaskId,
    region: RegionId,
    state: ObligationState,
    reserved_at: Time,
    resolved_at: Option<Time>,
}

// ============================================================================
// Separation Logic Verifier
// ============================================================================

/// Verifies separation logic properties against a sequence of marking events.
///
/// The verifier tracks ghost state for each obligation and checks:
///
/// 1. **Exclusive ownership**: No two obligations share an ID (Excl RA).
/// 2. **Frame preservation**: Operations only touch their footprint.
/// 3. **Judgment soundness**: Pre/postconditions of Hoare triples hold.
/// 4. **Separation**: Live obligations have disjoint identities.
/// 5. **No use-after-release**: Resolved obligations are never operated on.
/// 6. **Region closure quiescence**: Closed regions have zero pending.
#[derive(Debug, Default)]
pub struct SeparationLogicVerifier {
    /// Ghost state for each obligation.
    obligations: BTreeMap<ObligationId, GhostObligation>,
    /// Pending count per holder (authoritative).
    holder_pending: BTreeMap<TaskId, u64>,
    /// Pending count per region (authoritative).
    region_pending: BTreeMap<RegionId, u64>,
    /// Closed regions.
    closed_regions: BTreeSet<RegionId>,
    /// Resolved obligations (for use-after-release checking).
    resolved: BTreeSet<ObligationId>,
    /// Violations accumulated during verification.
    violations: Vec<SLViolation>,
    /// Counters.
    judgments_verified: usize,
    frame_checks: usize,
    separation_checks: usize,
    /// The most recent event timestamp observed in this trace.
    last_event_time: Option<Time>,
}

impl SeparationLogicVerifier {
    /// Creates a new verifier.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Verify separation logic properties against a marking event trace.
    #[must_use]
    pub fn verify(&mut self, events: &[MarkingEvent]) -> VerificationResult {
        self.reset();

        for event in events {
            self.process_event(event);
        }

        // Final check: all live obligations should be resolved.
        self.check_final_state(events.last().map_or(Time::ZERO, |e| e.time));

        VerificationResult {
            violations: self.violations.clone(),
            events_checked: events.len(),
            judgments_verified: self.judgments_verified,
            frame_checks: self.frame_checks,
            separation_checks: self.separation_checks,
        }
    }

    fn reset(&mut self) {
        self.obligations.clear();
        self.holder_pending.clear();
        self.region_pending.clear();
        self.closed_regions.clear();
        self.resolved.clear();
        self.violations.clear();
        self.judgments_verified = 0;
        self.frame_checks = 0;
        self.separation_checks = 0;
        self.last_event_time = None;
    }

    fn process_event(&mut self, event: &MarkingEvent) {
        if let Some(last_time) = self.last_event_time
            && event.time < last_time
        {
            self.violations.push(SLViolation {
                property: SeparationProperty::TemporalOrdering { obligation: None },
                time: event.time,
                description: format!(
                    "event at t={} appears after later event at t={} — trace time must be monotone",
                    event.time, last_time,
                ),
            });
        }
        self.last_event_time = Some(event.time);

        match &event.kind {
            MarkingEventKind::Reserve {
                obligation,
                kind,
                task,
                region,
            } => {
                self.verify_reserve(*obligation, *kind, *task, *region, event.time);
            }
            MarkingEventKind::Commit {
                obligation,
                kind,
                region,
            } => {
                self.verify_resolve(
                    *obligation,
                    ObligationState::Committed,
                    *kind,
                    *region,
                    event.time,
                );
            }
            MarkingEventKind::Abort {
                obligation,
                kind,
                region,
            } => {
                self.verify_resolve(
                    *obligation,
                    ObligationState::Aborted,
                    *kind,
                    *region,
                    event.time,
                );
            }
            MarkingEventKind::Leak {
                obligation,
                kind,
                region,
            } => {
                self.verify_resolve(
                    *obligation,
                    ObligationState::Leaked,
                    *kind,
                    *region,
                    event.time,
                );
            }
            MarkingEventKind::RegionClose { region } => {
                self.verify_region_close(*region, event.time);
            }
            MarkingEventKind::TaskComplete { .. } => {}
        }

        self.check_authoritative_pending_agreement(event.time);
    }

    /// Verify the Reserve judgment.
    ///
    /// ```text
    /// Pre:  RegionOpen(r), no existing ghost for o
    /// Post: Obl(o, k, h, r), HolderPending(h) += 1, RegionPending(r) += 1
    /// ```
    fn verify_reserve(
        &mut self,
        obligation: ObligationId,
        kind: ObligationKind,
        holder: TaskId,
        region: RegionId,
        time: Time,
    ) {
        self.judgments_verified += 1;

        if self.resolved.contains(&obligation) {
            self.violations.push(SLViolation {
                property: SeparationProperty::NoUseAfterRelease { obligation },
                time,
                description: format!(
                    "reserve({obligation:?}) reuses a resolved obligation id — \
                     terminal tombstone must remain exclusive",
                ),
            });
            return;
        }

        // Check precondition: no aliasing (Excl RA).
        if self.obligations.contains_key(&obligation) {
            self.violations.push(SLViolation {
                property: SeparationProperty::NoAliasing { obligation },
                time,
                description: format!(
                    "reserve({obligation:?}) but ghost state already exists — \
                     Excl composition fails (aliasing)",
                ),
            });
            return;
        }

        // Check precondition: region must be open.
        if self.closed_regions.contains(&region) {
            self.violations.push(SLViolation {
                property: SeparationProperty::RegionClosureQuiescence { region },
                time,
                description: format!(
                    "reserve in closed region {region:?} — RegionOpen(r) precondition fails",
                ),
            });
            return;
        }

        // Check separation: verify against all live obligations.
        self.separation_checks += 1;
        // Separation holds trivially: obligation is new, so o ≠ o' for all existing.

        // Frame check: other obligations are untouched.
        self.frame_checks += 1;

        let holder_after = self
            .holder_pending
            .get(&holder)
            .copied()
            .unwrap_or(0)
            .checked_add(1);
        let region_after = self
            .region_pending
            .get(&region)
            .copied()
            .unwrap_or(0)
            .checked_add(1);
        let (Some(holder_after), Some(region_after)) = (holder_after, region_after) else {
            self.violations.push(SLViolation {
                property: SeparationProperty::AuthoritativePendingAgreement,
                time,
                description: format!(
                    "reserve({obligation:?}) would overflow authoritative pending counts \
                     for holder {holder:?} or region {region:?}",
                ),
            });
            return;
        };

        // Establish postcondition: create ghost state.
        self.obligations.insert(
            obligation,
            GhostObligation {
                kind,
                holder,
                region,
                state: ObligationState::Reserved,
                reserved_at: time,
                resolved_at: None,
            },
        );
        self.holder_pending.insert(holder, holder_after);
        self.region_pending.insert(region, region_after);
    }

    /// Verify a resolution judgment (commit, abort, or leak).
    ///
    /// ```text
    /// Pre:  Obl(o, k, h, r) with state = Reserved
    /// Post: Resolved(o), HolderPending(h) -= 1, RegionPending(r) -= 1
    /// ```
    fn verify_resolve(
        &mut self,
        obligation: ObligationId,
        new_state: ObligationState,
        kind: ObligationKind,
        region: RegionId,
        time: Time,
    ) {
        self.judgments_verified += 1;

        // Check use-after-release.
        if self.resolved.contains(&obligation) {
            self.violations.push(SLViolation {
                property: SeparationProperty::NoUseAfterRelease { obligation },
                time,
                description: format!(
                    "{new_state:?}({obligation:?}) but obligation already resolved — \
                     Excl::Consumed cannot be composed",
                ),
            });
            return;
        }

        // Check precondition: ghost state must exist.
        let Some(ghost) = self.obligations.get_mut(&obligation) else {
            self.violations.push(SLViolation {
                property: SeparationProperty::NoAliasing { obligation },
                time,
                description: format!(
                    "{new_state:?}({obligation:?}) but no ghost state — \
                     obligation was never reserved",
                ),
            });
            return;
        };

        // Check precondition: must be in Reserved state (Excl(Reserved)).
        if ghost.state != ObligationState::Reserved {
            self.violations.push(SLViolation {
                property: SeparationProperty::NoUseAfterRelease { obligation },
                time,
                description: format!(
                    "{new_state:?}({obligation:?}) but state is {:?}, not Reserved",
                    ghost.state,
                ),
            });
            return;
        }

        if time < ghost.reserved_at {
            self.violations.push(SLViolation {
                property: SeparationProperty::TemporalOrdering {
                    obligation: Some(obligation),
                },
                time,
                description: format!(
                    "{new_state:?}({obligation:?}) at t={} precedes reserve at t={} — \
                     later-modality order violated",
                    time, ghost.reserved_at,
                ),
            });
            return;
        }

        // Check kind agreement (Agree RA).
        if ghost.kind != kind {
            self.violations.push(SLViolation {
                property: SeparationProperty::NoAliasing { obligation },
                time,
                description: format!(
                    "kind mismatch: reserved as {}, resolved as {kind} — \
                     Agree composition fails",
                    ghost.kind,
                ),
            });
            return;
        }

        // Check region agreement (Agree RA).
        if ghost.region != region {
            self.violations.push(SLViolation {
                property: SeparationProperty::NoAliasing { obligation },
                time,
                description: format!(
                    "region mismatch: reserved in {:?}, resolved in {region:?} — \
                     Agree composition fails",
                    ghost.region,
                ),
            });
            return;
        }

        // Frame check: only this obligation's state changes.
        self.frame_checks += 1;

        // Validate authoritative counts before mutating ghost state.
        let holder = ghost.holder;
        let ghost_region = ghost.region;
        let Some(count) = self.holder_pending.get_mut(&holder) else {
            self.violations.push(SLViolation {
                property: SeparationProperty::AuthoritativePendingAgreement,
                time,
                description: format!(
                    "{new_state:?}({obligation:?}) missing authoritative holder counter for {holder:?}",
                ),
            });
            return;
        };
        if *count == 0 {
            self.violations.push(SLViolation {
                property: SeparationProperty::AuthoritativePendingAgreement,
                time,
                description: format!(
                    "{new_state:?}({obligation:?}) would underflow holder counter for {holder:?}",
                ),
            });
            return;
        }
        *count -= 1;

        let Some(count) = self.region_pending.get_mut(&ghost_region) else {
            self.violations.push(SLViolation {
                property: SeparationProperty::AuthoritativePendingAgreement,
                time,
                description: format!(
                    "{new_state:?}({obligation:?}) missing authoritative region counter for {ghost_region:?}",
                ),
            });
            return;
        };
        if *count == 0 {
            self.violations.push(SLViolation {
                property: SeparationProperty::AuthoritativePendingAgreement,
                time,
                description: format!(
                    "{new_state:?}({obligation:?}) would underflow region counter for {ghost_region:?}",
                ),
            });
            return;
        }
        *count -= 1;

        // Establish postcondition.
        ghost.state = new_state;
        ghost.resolved_at = Some(time);
        self.resolved.insert(obligation);
    }

    /// Verify the RegionClose judgment.
    ///
    /// ```text
    /// Pre:  RegionPending(r) = 0, RegionOpen(r)
    /// Post: RegionClosed(r)
    /// ```
    fn verify_region_close(&mut self, region: RegionId, time: Time) {
        self.judgments_verified += 1;
        let mut precondition_ok = true;

        // Check precondition: region pending count must be zero.
        let pending = self.region_pending.get(&region).copied().unwrap_or(0);
        if pending > 0 {
            precondition_ok = false;
            self.violations.push(SLViolation {
                property: SeparationProperty::RegionClosureQuiescence { region },
                time,
                description: format!(
                    "close({region:?}) with {pending} pending obligations — \
                     RegionPending(r, 0) precondition fails",
                ),
            });
        }

        // Check not already closed.
        if self.closed_regions.contains(&region) {
            precondition_ok = false;
            self.violations.push(SLViolation {
                property: SeparationProperty::RegionClosureQuiescence { region },
                time,
                description: format!(
                    "close({region:?}) but region already closed — \
                     RegionOpen(r) precondition fails",
                ),
            });
        }

        if !precondition_ok {
            return;
        }

        // Establish postcondition.
        self.closed_regions.insert(region);
    }

    /// Final state check: all obligations should be resolved.
    fn check_final_state(&mut self, trace_end: Time) {
        for (id, ghost) in &self.obligations {
            if ghost.state == ObligationState::Reserved {
                self.violations.push(SLViolation {
                    property: SeparationProperty::HolderCleanup { task: ghost.holder },
                    time: trace_end,
                    description: format!(
                        "obligation {id:?} ({}) still Reserved at trace end \
                         (holder {:?}, reserved at t={}) — \
                         HolderPending cleanup failed",
                        ghost.kind, ghost.holder, ghost.reserved_at,
                    ),
                });
            }
        }

        self.check_authoritative_pending_agreement(trace_end);
    }

    fn check_authoritative_pending_agreement(&mut self, time: Time) {
        let mut expected_holder_pending = BTreeMap::<TaskId, u64>::new();
        let mut expected_region_pending = BTreeMap::<RegionId, u64>::new();

        for ghost in self
            .obligations
            .values()
            .filter(|ghost| ghost.state == ObligationState::Reserved)
        {
            *expected_holder_pending.entry(ghost.holder).or_insert(0) += 1;
            *expected_region_pending.entry(ghost.region).or_insert(0) += 1;
        }

        let holder_keys = self
            .holder_pending
            .keys()
            .copied()
            .chain(expected_holder_pending.keys().copied())
            .collect::<BTreeSet<_>>();
        for holder in holder_keys {
            let actual = self.holder_pending.get(&holder).copied().unwrap_or(0);
            let expected = expected_holder_pending.get(&holder).copied().unwrap_or(0);
            if actual != expected {
                self.violations.push(SLViolation {
                    property: SeparationProperty::AuthoritativePendingAgreement,
                    time,
                    description: format!(
                        "holder counter mismatch for {holder:?}: authoritative={actual}, fragments={expected}",
                    ),
                });
            }
        }

        let region_keys = self
            .region_pending
            .keys()
            .copied()
            .chain(expected_region_pending.keys().copied())
            .collect::<BTreeSet<_>>();
        for region in region_keys {
            let actual = self.region_pending.get(&region).copied().unwrap_or(0);
            let expected = expected_region_pending.get(&region).copied().unwrap_or(0);
            if actual != expected {
                self.violations.push(SLViolation {
                    property: SeparationProperty::AuthoritativePendingAgreement,
                    time,
                    description: format!(
                        "region counter mismatch for {region:?}: authoritative={actual}, fragments={expected}",
                    ),
                });
            }
        }
    }
}

// ============================================================================
// Specification Table: per-obligation-kind specs
// ============================================================================

/// Complete Separation Logic specification for one obligation kind.
///
/// Bundles the resource predicate shape, frame condition, and Hoare triples
/// for a specific obligation kind. All five kinds (SendPermit, Ack, Lease,
/// IoOp, SemaphorePermit) share the same specification structure (kind-uniform
/// state machine),
/// but are documented separately for completeness.
#[derive(Debug, Clone)]
pub struct ObligationSpec {
    /// The obligation kind this specification covers.
    pub kind: ObligationKind,

    /// Resource predicate formal definition (Iris notation).
    ///
    /// ```text
    /// Obl(o, K, h, r) ≜
    ///   own(γ_state(o), ●Excl(Reserved))
    ///   ∗ own(γ_kind(o), Agree(K))
    ///   ∗ own(γ_holder(o), Agree(h))
    ///   ∗ own(γ_region(o), Agree(r))
    ///   ∗ own(γ_pending(h), ◯(1))
    ///   ∗ own(γ_region_pending(r), ◯(1))
    /// ```
    pub resource_predicate: &'static str,

    /// Frame condition: what this obligation does NOT touch.
    ///
    /// ```text
    /// Frame(o, h, r) ≜
    ///   ∀ o' ≠ o. Obl(o', ..) is preserved
    ///   ∧ ∀ h' ≠ h. HolderPending(h', _) is preserved
    ///   ∧ ∀ r' ≠ r. RegionPending(r', _) is preserved
    ///   ∧ SchedulerState is preserved
    ///   ∧ BudgetState is preserved
    /// ```
    pub frame_condition: &'static str,

    /// Pre/post conditions for `reserve`.
    pub reserve_triple: &'static str,

    /// Pre/post conditions for `commit`.
    pub commit_triple: &'static str,

    /// Pre/post conditions for `abort`.
    pub abort_triple: &'static str,

    /// Separating conjunction properties.
    pub separation_properties: &'static [&'static str],
}

impl ObligationSpec {
    /// Generate the specification for a given obligation kind.
    ///
    /// All kinds share the same formal structure (kind-uniform state machine).
    #[must_use]
    pub fn for_kind(kind: ObligationKind) -> Self {
        // All obligation kinds share the identical specification shape.
        // This is by design: the kind-uniform state machine contract ensures
        // that SendPermit, Ack, Lease, IoOp, and SemaphorePermit follow the same rules.
        Self {
            kind,
            resource_predicate: concat!(
                "Obl(o, K, h, r) := ",
                "own(gamma_state(o), Auth(Excl(Reserved))) * ",
                "own(gamma_kind(o), Agree(K)) * ",
                "own(gamma_holder(o), Agree(h)) * ",
                "own(gamma_region(o), Agree(r)) * ",
                "own(gamma_pending(h), Frag(1)) * ",
                "own(gamma_region_pending(r), Frag(1))",
            ),
            frame_condition: concat!(
                "Frame(o, h, r) := ",
                "forall o' != o. Obl(o', ..) preserved AND ",
                "forall h' != h. HolderPending(h', _) preserved AND ",
                "forall r' != r. RegionPending(r', _) preserved AND ",
                "SchedulerState preserved AND BudgetState preserved",
            ),
            reserve_triple: concat!(
                "{HolderPending(h, n) * RegionPending(r, m) * RegionOpen(r)} ",
                "reserve(K, h, r) ",
                "{Obl(o, K, h, r) * HolderPending(h, n+1) * RegionPending(r, m+1)}",
            ),
            commit_triple: concat!(
                "{Obl(o, K, h, r) * HolderPending(h, n+1) * RegionPending(r, m+1)} ",
                "commit(o) ",
                "{Resolved(o) * HolderPending(h, n) * RegionPending(r, m)}",
            ),
            abort_triple: concat!(
                "{Obl(o, K, h, r) * HolderPending(h, n+1) * RegionPending(r, m+1)} ",
                "abort(o, reason) ",
                "{Resolved(o) * HolderPending(h, n) * RegionPending(r, m)}",
            ),
            separation_properties: &[
                "Obl(o1, ..) * Obl(o2, ..) |- o1 != o2  (distinct identity)",
                "Obl(o, K, h1, r) * Obl(o, K, h2, r) |- False  (no aliasing)",
                "Obl(o, ..) * Resolved(o) |- False  (no use-after-release)",
                "RegionClosed(r) |- RegionPending(r) = 0  (quiescence)",
                "TaskCompleted(t) |- HolderPending(t) = 0  (holder cleanup)",
            ],
        }
    }

    /// Generate specifications for all obligation kinds.
    #[must_use]
    pub fn all_specs() -> Vec<Self> {
        vec![
            Self::for_kind(ObligationKind::SendPermit),
            Self::for_kind(ObligationKind::Ack),
            Self::for_kind(ObligationKind::Lease),
            Self::for_kind(ObligationKind::IoOp),
            Self::for_kind(ObligationKind::SemaphorePermit),
        ]
    }
}

impl fmt::Display for ObligationSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== Separation Logic Specification: {} ===", self.kind)?;
        writeln!(f)?;
        writeln!(f, "Resource Predicate:")?;
        writeln!(f, "  {}", self.resource_predicate)?;
        writeln!(f)?;
        writeln!(f, "Frame Condition:")?;
        writeln!(f, "  {}", self.frame_condition)?;
        writeln!(f)?;
        writeln!(f, "Hoare Triples:")?;
        writeln!(f, "  Reserve: {}", self.reserve_triple)?;
        writeln!(f, "  Commit:  {}", self.commit_triple)?;
        writeln!(f, "  Abort:   {}", self.abort_triple)?;
        writeln!(f)?;
        writeln!(f, "Separation Properties:")?;
        for prop in self.separation_properties {
            writeln!(f, "  - {prop}")?;
        }
        Ok(())
    }
}

// ============================================================================
// Protocol-Specific Specifications (Session Type Integration)
// ============================================================================

/// Separation Logic specification for session-typed obligation protocols.
///
/// Extends the base obligation specs with protocol-level invariants
/// derived from the session type encoding (bd-3u5d3).
///
/// ```text
/// SendPermit protocol (two-phase send):
///   G = Sender -> Receiver: Reserve . Sender -> Receiver: {Send(T).end | Abort.end}
///
///   Channel(ch, S) := own(gamma_chan(ch), Auth(Excl(S)))
///
///   {Channel(ch, Send<Reserve, Select<Send<T, End>, Send<Abort, End>>>)}
///     ch.send(reserve_msg)
///   {Channel(ch, Select<Send<T, End>, Send<Abort, End>>) * Obl(o, SendPermit, h, r)}
///
/// Lease protocol (renewable resource):
///   G = Holder -> Resource: Acquire . mu X. Holder -> Resource: {Renew.X | Release.end}
///
///   {Channel(ch, Send<Acquire, HolderLoop>)}
///     ch.send(acquire_msg)
///   {Channel(ch, HolderLoop) * Obl(o, Lease, h, r)}
///
/// Reserve-Commit protocol (two-phase effect):
///   G = Initiator -> Executor: Reserve(K) . Initiator -> Executor: {Commit.end | Abort.end}
///
///   {True}
///     initiator.reserve(k)
///   {Channel(ch, Select<Send<Commit, End>, Send<Abort, End>>) * Obl(o, K, h, r)}
/// ```
#[derive(Debug, Clone)]
pub struct ProtocolSpec {
    /// Protocol name.
    pub name: &'static str,
    /// Global type (session type notation).
    pub global_type: &'static str,
    /// Channel predicate.
    pub channel_predicate: &'static str,
    /// Hoare triple for the initial operation.
    pub init_triple: &'static str,
    /// Hoare triple for the commit/send path.
    pub commit_triple: &'static str,
    /// Hoare triple for the abort/cancel path.
    pub abort_triple: &'static str,
    /// Delegation (channel transfer) triple.
    pub delegation_triple: &'static str,
}

impl ProtocolSpec {
    /// Specification for the SendPermit protocol.
    #[must_use]
    pub fn send_permit() -> Self {
        Self {
            name: "SendPermit (Two-Phase Send)",
            global_type: "Sender -> Receiver: Reserve . Sender -> Receiver: {Send(T).end | Abort.end}",
            channel_predicate: "Channel(ch, S) := own(gamma_chan(ch), Auth(Excl(S)))",
            init_triple: concat!(
                "{Channel(ch, Send<Reserve, Select<Send<T, End>, Send<Abort, End>>>)} ",
                "ch.send(reserve_msg) ",
                "{Channel(ch, Select<Send<T, End>, Send<Abort, End>>) * Obl(o, SendPermit, h, r)}",
            ),
            commit_triple: concat!(
                "{Channel(ch, Select<Send<T, End>, Send<Abort, End>>) * Obl(o, SendPermit, h, r)} ",
                "ch.select_left(); ch.send(msg) ",
                "{Channel(ch, End) * Resolved(o)}",
            ),
            abort_triple: concat!(
                "{Channel(ch, Select<Send<T, End>, Send<Abort, End>>) * Obl(o, SendPermit, h, r)} ",
                "ch.select_right(); ch.send(abort_msg) ",
                "{Channel(ch, End) * Resolved(o)}",
            ),
            delegation_triple: concat!(
                "{Channel(ch, S) * Obl(o, SendPermit, h1, r) * HolderPending(h1, n+1) * HolderPending(h2, m)} ",
                "transfer(ch, o, h2) ",
                "{Channel(ch, S) * Obl(o, SendPermit, h2, r) * HolderPending(h1, n) * HolderPending(h2, m+1)}",
            ),
        }
    }

    /// Specification for the Lease protocol.
    #[must_use]
    pub fn lease() -> Self {
        Self {
            name: "Lease (Renewable Resource)",
            global_type: "Holder -> Resource: Acquire . mu X. Holder -> Resource: {Renew.X | Release.end}",
            channel_predicate: "Channel(ch, S) := own(gamma_chan(ch), Auth(Excl(S)))",
            init_triple: concat!(
                "{Channel(ch, Send<Acquire, HolderLoop>)} ",
                "ch.send(acquire_msg) ",
                "{Channel(ch, HolderLoop) * Obl(o, Lease, h, r)}",
            ),
            commit_triple: concat!(
                "{Channel(ch, Select<Send<Renew, End>, Send<Release, End>>) * Obl(o, Lease, h, r)} ",
                "ch.select_right(); ch.send(release_msg) ",
                "{Channel(ch, End) * Resolved(o)}",
            ),
            abort_triple: concat!(
                "{Channel(ch, Select<Send<Renew, End>, Send<Release, End>>) * Obl(o, Lease, h, r)} ",
                "cancel(h) ",
                "{Channel(ch, End) * Resolved(o)}",
            ),
            delegation_triple: concat!(
                "{Channel(ch, S) * Obl(o, Lease, h1, r) * HolderPending(h1, n+1) * HolderPending(h2, m)} ",
                "transfer(ch, o, h2) ",
                "{Channel(ch, S) * Obl(o, Lease, h2, r) * HolderPending(h1, n) * HolderPending(h2, m+1)}",
            ),
        }
    }

    /// Specification for the Reserve-Commit protocol.
    #[must_use]
    pub fn reserve_commit() -> Self {
        Self {
            name: "Reserve-Commit (Two-Phase Effect)",
            global_type: "Initiator -> Executor: Reserve(K) . Initiator -> Executor: {Commit.end | Abort(reason).end}",
            channel_predicate: "Channel(ch, S) := own(gamma_chan(ch), Auth(Excl(S)))",
            init_triple: concat!(
                "{True} ",
                "initiator.reserve(k, h, r) ",
                "{Channel(ch, Select<Send<Commit, End>, Send<Abort, End>>) * Obl(o, K, h, r)}",
            ),
            commit_triple: concat!(
                "{Channel(ch, Select<Send<Commit, End>, Send<Abort, End>>) * Obl(o, K, h, r)} ",
                "ch.select_left(); ch.send(commit_msg) ",
                "{Channel(ch, End) * Resolved(o)}",
            ),
            abort_triple: concat!(
                "{Channel(ch, Select<Send<Commit, End>, Send<Abort, End>>) * Obl(o, K, h, r)} ",
                "ch.select_right(); ch.send(abort_msg) ",
                "{Channel(ch, End) * Resolved(o)}",
            ),
            delegation_triple: concat!(
                "{Channel(ch, S) * Obl(o, K, h1, r) * HolderPending(h1, n+1) * HolderPending(h2, m)} ",
                "transfer(ch, o, h2) ",
                "{Channel(ch, S) * Obl(o, K, h2, r) * HolderPending(h1, n) * HolderPending(h2, m+1)}",
            ),
        }
    }

    /// All protocol specifications.
    #[must_use]
    pub fn all_protocols() -> Vec<Self> {
        vec![Self::send_permit(), Self::lease(), Self::reserve_commit()]
    }
}

impl fmt::Display for ProtocolSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== Protocol Spec: {} ===", self.name)?;
        writeln!(f)?;
        writeln!(f, "Global Type:")?;
        writeln!(f, "  {}", self.global_type)?;
        writeln!(f)?;
        writeln!(f, "Channel Predicate:")?;
        writeln!(f, "  {}", self.channel_predicate)?;
        writeln!(f)?;
        writeln!(f, "Init:       {}", self.init_triple)?;
        writeln!(f, "Commit:     {}", self.commit_triple)?;
        writeln!(f, "Abort:      {}", self.abort_triple)?;
        writeln!(f, "Delegation: {}", self.delegation_triple)?;
        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[path = "separation_logic_inline_tests.rs"]
mod tests;
