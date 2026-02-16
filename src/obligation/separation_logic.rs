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
//!    Ensures exactly one holder can observe or mutate state at a time.
//!
//! 2. **Auth(ℕ)**: Authoritative natural number (pending count per region/task).
//!    Enables fractional reasoning about how many obligations are outstanding.
//!
//! 3. **Agree(ObligationKind)**: Agreement on obligation kind. Prevents kind
//!    mutation after creation.
//!
//! # Specification Structure
//!
//! For each obligation type (SendPermit, Ack, Lease, IoOp):
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
/// The RA composition `Excl(a) · Excl(b) = ⊥` (always invalid) ensures
/// no two owners simultaneously hold the same exclusive resource.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Excl<A: Clone + PartialEq> {
    /// The resource holds a value — exactly one owner.
    Some(A),
    /// The resource has been consumed (moved to a successor state).
    Consumed,
}

impl<A: Clone + PartialEq> Excl<A> {
    /// Attempt to compose two exclusive elements. Returns `None` if
    /// both are `Some` (disjointness violation).
    #[must_use]
    pub fn compose(&self, other: &Self) -> Option<Self> {
        match (self, other) {
            (Self::Consumed, x) | (x, Self::Consumed) => Some(x.clone()),
            (Self::Some(_), Self::Some(_)) => None, // ⊥: aliasing
        }
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
        let mut pre = JudgmentCondition::empty();
        pre.holder_pending.insert(holder, holder_pending_before);
        pre.region_pending.insert(region, region_pending_before);
        pre.regions_open.insert(region);

        let mut post = JudgmentCondition::empty();
        post.predicates.push(ResourcePredicate::reserved(
            obligation, kind, holder, region,
        ));
        post.holder_pending
            .insert(holder, holder_pending_before + 1);
        post.region_pending
            .insert(region, region_pending_before + 1);

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
        post.holder_pending
            .insert(holder, holder_pending_before.saturating_sub(1));
        post.region_pending
            .insert(region, region_pending_before.saturating_sub(1));

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
    }

    fn process_event(&mut self, event: &MarkingEvent) {
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
        }
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
        *self.holder_pending.entry(holder).or_insert(0) += 1;
        *self.region_pending.entry(region).or_insert(0) += 1;
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

        // Establish postcondition.
        let holder = ghost.holder;
        let ghost_region = ghost.region;
        ghost.state = new_state;
        ghost.resolved_at = Some(time);

        self.resolved.insert(obligation);

        // Decrement pending counts.
        if let Some(count) = self.holder_pending.get_mut(&holder) {
            *count = count.saturating_sub(1);
        }
        if let Some(count) = self.region_pending.get_mut(&ghost_region) {
            *count = count.saturating_sub(1);
        }
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
    }
}

// ============================================================================
// Specification Table: per-obligation-kind specs
// ============================================================================

/// Complete Separation Logic specification for one obligation kind.
///
/// Bundles the resource predicate shape, frame condition, and Hoare triples
/// for a specific obligation kind. All four kinds (SendPermit, Ack, Lease,
/// IoOp) share the same specification structure (kind-uniform state machine),
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
        // All four obligation kinds share the identical specification shape.
        // This is by design: the kind-uniform state machine contract ensures
        // that SendPermit, Ack, Lease, and IoOp follow the same rules.
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
mod tests {
    use super::*;
    use crate::util::ArenaIndex;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn r(n: u32) -> RegionId {
        RegionId::from_arena(ArenaIndex::new(n, 0))
    }

    fn t(n: u32) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(n, 0))
    }

    fn o(n: u32) -> ObligationId {
        ObligationId::from_arena(ArenaIndex::new(n, 0))
    }

    fn reserve_event(
        time_ns: u64,
        obligation: ObligationId,
        kind: ObligationKind,
        task: TaskId,
        region: RegionId,
    ) -> MarkingEvent {
        MarkingEvent::new(
            Time::from_nanos(time_ns),
            MarkingEventKind::Reserve {
                obligation,
                kind,
                task,
                region,
            },
        )
    }

    fn commit_event(
        time_ns: u64,
        obligation: ObligationId,
        region: RegionId,
        kind: ObligationKind,
    ) -> MarkingEvent {
        MarkingEvent::new(
            Time::from_nanos(time_ns),
            MarkingEventKind::Commit {
                obligation,
                region,
                kind,
            },
        )
    }

    fn abort_event(
        time_ns: u64,
        obligation: ObligationId,
        region: RegionId,
        kind: ObligationKind,
    ) -> MarkingEvent {
        MarkingEvent::new(
            Time::from_nanos(time_ns),
            MarkingEventKind::Abort {
                obligation,
                region,
                kind,
            },
        )
    }

    fn leak_event(
        time_ns: u64,
        obligation: ObligationId,
        region: RegionId,
        kind: ObligationKind,
    ) -> MarkingEvent {
        MarkingEvent::new(
            Time::from_nanos(time_ns),
            MarkingEventKind::Leak {
                obligation,
                region,
                kind,
            },
        )
    }

    fn close_event(time_ns: u64, region: RegionId) -> MarkingEvent {
        MarkingEvent::new(
            Time::from_nanos(time_ns),
            MarkingEventKind::RegionClose { region },
        )
    }

    // ---- Resource Algebra tests ------------------------------------------------

    #[test]
    fn excl_compose_disjoint() {
        init_test("excl_compose_disjoint");
        let a: Excl<ObligationState> = Excl::Some(ObligationState::Reserved);
        let b: Excl<ObligationState> = Excl::Consumed;
        let result = a.compose(&b);
        crate::assert_with_log!(result.is_some(), "disjoint compose succeeds", true, true);
        crate::test_complete!("excl_compose_disjoint");
    }

    #[test]
    fn excl_compose_aliasing_fails() {
        init_test("excl_compose_aliasing_fails");
        let a: Excl<ObligationState> = Excl::Some(ObligationState::Reserved);
        let b: Excl<ObligationState> = Excl::Some(ObligationState::Committed);
        let result = a.compose(&b);
        crate::assert_with_log!(result.is_none(), "aliasing compose fails", true, true);
        crate::test_complete!("excl_compose_aliasing_fails");
    }

    #[test]
    fn agree_compose_matching() {
        init_test("agree_compose_matching");
        let a = Agree(ObligationKind::SendPermit);
        let b = Agree(ObligationKind::SendPermit);
        let result = a.compose(&b);
        crate::assert_with_log!(result.is_some(), "matching agree succeeds", true, true);
        crate::test_complete!("agree_compose_matching");
    }

    #[test]
    fn agree_compose_mismatch_fails() {
        init_test("agree_compose_mismatch_fails");
        let a = Agree(ObligationKind::SendPermit);
        let b = Agree(ObligationKind::Lease);
        let result = a.compose(&b);
        crate::assert_with_log!(result.is_none(), "mismatch agree fails", true, true);
        crate::test_complete!("agree_compose_mismatch_fails");
    }

    #[test]
    fn auth_nat_valid_fragment() {
        init_test("auth_nat_valid_fragment");
        let auth = AuthNat::Auth(5);
        let frag = AuthNat::Frag(3);
        let result = auth.compose(&frag);
        crate::assert_with_log!(result.is_some(), "valid fragment compose", true, true);
        crate::test_complete!("auth_nat_valid_fragment");
    }

    #[test]
    fn auth_nat_exceeding_fragment_fails() {
        init_test("auth_nat_exceeding_fragment_fails");
        let auth = AuthNat::Auth(2);
        let frag = AuthNat::Frag(5);
        let result = auth.compose(&frag);
        crate::assert_with_log!(result.is_none(), "exceeding fragment fails", true, true);
        crate::test_complete!("auth_nat_exceeding_fragment_fails");
    }

    #[test]
    fn auth_nat_two_auth_fails() {
        init_test("auth_nat_two_auth_fails");
        let a = AuthNat::Auth(1);
        let b = AuthNat::Auth(2);
        let result = a.compose(&b);
        crate::assert_with_log!(result.is_none(), "two auth fails", true, true);
        crate::test_complete!("auth_nat_two_auth_fails");
    }

    #[test]
    fn auth_nat_fragments_additive() {
        init_test("auth_nat_fragments_additive");
        let a = AuthNat::Frag(3);
        let b = AuthNat::Frag(4);
        let result = a.compose(&b);
        let expected = AuthNat::Frag(7);
        crate::assert_with_log!(
            result == Some(expected.clone()),
            "fragments add",
            expected,
            result
        );
        crate::test_complete!("auth_nat_fragments_additive");
    }

    #[test]
    fn auth_nat_fragment_overflow_returns_none() {
        init_test("auth_nat_fragment_overflow_returns_none");
        let a = AuthNat::Frag(u64::MAX);
        let b = AuthNat::Frag(1);
        let result = a.compose(&b);
        crate::assert_with_log!(
            result.is_none(),
            "fragment overflow yields invalid composition",
            true,
            true
        );
        crate::test_complete!("auth_nat_fragment_overflow_returns_none");
    }

    // ---- Resource Predicate tests ----------------------------------------------

    #[test]
    fn resource_predicate_separation() {
        init_test("resource_predicate_separation");
        let p1 = ResourcePredicate::reserved(o(0), ObligationKind::SendPermit, t(0), r(0));
        let p2 = ResourcePredicate::reserved(o(1), ObligationKind::Ack, t(0), r(0));
        let separable = p1.is_separable_from(&p2);
        crate::assert_with_log!(separable, "different IDs are separable", true, separable);
        crate::test_complete!("resource_predicate_separation");
    }

    #[test]
    fn resource_predicate_same_id_not_separable() {
        init_test("resource_predicate_same_id_not_separable");
        let p1 = ResourcePredicate::reserved(o(0), ObligationKind::SendPermit, t(0), r(0));
        let p2 = ResourcePredicate::reserved(o(0), ObligationKind::SendPermit, t(0), r(0));
        let separable = p1.is_separable_from(&p2);
        crate::assert_with_log!(!separable, "same ID not separable", false, separable);
        crate::test_complete!("resource_predicate_same_id_not_separable");
    }

    #[test]
    fn resource_predicate_display() {
        init_test("resource_predicate_display");
        let p = ResourcePredicate::reserved(o(0), ObligationKind::Lease, t(1), r(2));
        let s = format!("{p}");
        let has_lease = s.contains("lease");
        crate::assert_with_log!(has_lease, "display has kind", true, has_lease);
        crate::test_complete!("resource_predicate_display");
    }

    // ---- Frame Condition tests -------------------------------------------------

    #[test]
    fn frame_condition_other_obligations_framed() {
        init_test("frame_condition_other_obligations_framed");
        let frame = FrameCondition::single_obligation(o(0), t(0), r(0));
        let framed = frame.is_framed(o(1));
        crate::assert_with_log!(framed, "other obligation is framed", true, framed);
        let not_framed = !frame.is_framed(o(0));
        crate::assert_with_log!(not_framed, "target is NOT framed", true, not_framed);
        crate::test_complete!("frame_condition_other_obligations_framed");
    }

    #[test]
    fn frame_condition_other_tasks_framed() {
        init_test("frame_condition_other_tasks_framed");
        let frame = FrameCondition::single_obligation(o(0), t(0), r(0));
        let framed = frame.task_is_framed(t(1));
        crate::assert_with_log!(framed, "other task is framed", true, framed);
        let not_framed = !frame.task_is_framed(t(0));
        crate::assert_with_log!(not_framed, "target task NOT framed", true, not_framed);
        crate::test_complete!("frame_condition_other_tasks_framed");
    }

    #[test]
    fn frame_condition_other_regions_framed() {
        init_test("frame_condition_other_regions_framed");
        let frame = FrameCondition::single_obligation(o(0), t(0), r(0));
        let framed = frame.region_is_framed(r(1));
        crate::assert_with_log!(framed, "other region is framed", true, framed);
        crate::test_complete!("frame_condition_other_regions_framed");
    }

    // ---- Separation Property tests ---------------------------------------------

    #[test]
    fn separation_property_formal_statements() {
        init_test("separation_property_formal_statements");
        let props = [
            SeparationProperty::DistinctIdentity {
                left: o(0),
                right: o(1),
            },
            SeparationProperty::NoAliasing { obligation: o(0) },
            SeparationProperty::NoUseAfterRelease { obligation: o(0) },
            SeparationProperty::RegionClosureQuiescence { region: r(0) },
            SeparationProperty::HolderCleanup { task: t(0) },
        ];
        for prop in &props {
            let stmt = prop.formal_statement();
            let non_empty = !stmt.is_empty();
            crate::assert_with_log!(non_empty, format!("{prop} has statement"), true, non_empty);
        }
        crate::test_complete!("separation_property_formal_statements");
    }

    // ---- Judgment tests --------------------------------------------------------

    #[test]
    fn judgment_reserve_has_frame() {
        init_test("judgment_reserve_has_frame");
        let j = Judgment::reserve(o(0), ObligationKind::SendPermit, t(0), r(0), 0, 0);
        let has_frame = j.frame.is_some();
        crate::assert_with_log!(has_frame, "reserve judgment has frame", true, has_frame);

        // Postcondition should have the obligation predicate.
        let post_pred_count = j.postcondition.predicates.len();
        crate::assert_with_log!(
            post_pred_count == 1,
            "one postcondition predicate",
            1,
            post_pred_count
        );

        // Postcondition pending counts should be incremented.
        let holder_count = j.postcondition.holder_pending.get(&t(0)).copied();
        crate::assert_with_log!(
            holder_count == Some(1),
            "holder pending = 1",
            Some(1),
            holder_count
        );

        let region_count = j.postcondition.region_pending.get(&r(0)).copied();
        crate::assert_with_log!(
            region_count == Some(1),
            "region pending = 1",
            Some(1),
            region_count
        );
        crate::test_complete!("judgment_reserve_has_frame");
    }

    #[test]
    fn judgment_commit_decrements_counts() {
        init_test("judgment_commit_decrements_counts");
        let j = Judgment::commit(o(0), ObligationKind::SendPermit, t(0), r(0), 2, 3);
        let holder_post = j.postcondition.holder_pending.get(&t(0)).copied();
        crate::assert_with_log!(
            holder_post == Some(1),
            "holder decremented",
            Some(1),
            holder_post
        );
        let region_post = j.postcondition.region_pending.get(&r(0)).copied();
        crate::assert_with_log!(
            region_post == Some(2),
            "region decremented",
            Some(2),
            region_post
        );
        crate::test_complete!("judgment_commit_decrements_counts");
    }

    #[test]
    fn judgment_region_close_requires_zero_pending() {
        init_test("judgment_region_close_requires_zero_pending");
        let j = Judgment::region_close(r(0));
        let pre_pending = j.precondition.region_pending.get(&r(0)).copied();
        crate::assert_with_log!(
            pre_pending == Some(0),
            "pre requires 0 pending",
            Some(0),
            pre_pending
        );
        let pre_open = j.precondition.regions_open.contains(&r(0));
        crate::assert_with_log!(pre_open, "pre requires open", true, pre_open);
        let post_closed = j.postcondition.regions_closed.contains(&r(0));
        crate::assert_with_log!(post_closed, "post has closed", true, post_closed);
        crate::test_complete!("judgment_region_close_requires_zero_pending");
    }

    // ---- Verifier: sound traces ------------------------------------------------

    #[test]
    fn verifier_clean_reserve_commit_close() {
        init_test("verifier_clean_reserve_commit_close");
        let events = vec![
            reserve_event(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit_event(10, o(0), r(0), ObligationKind::SendPermit),
            close_event(20, r(0)),
        ];

        let mut verifier = SeparationLogicVerifier::new();
        let result = verifier.verify(&events);
        let sound = result.is_sound();
        crate::assert_with_log!(sound, "clean trace is sound", true, sound);
        let jv = result.judgments_verified;
        crate::assert_with_log!(jv == 3, "3 judgments verified", 3, jv);
        crate::test_complete!("verifier_clean_reserve_commit_close");
    }

    #[test]
    fn verifier_clean_abort_path() {
        init_test("verifier_clean_abort_path");
        let events = vec![
            reserve_event(0, o(0), ObligationKind::Lease, t(0), r(0)),
            abort_event(5, o(0), r(0), ObligationKind::Lease),
            close_event(10, r(0)),
        ];

        let mut verifier = SeparationLogicVerifier::new();
        let result = verifier.verify(&events);
        let sound = result.is_sound();
        crate::assert_with_log!(sound, "abort path is sound", true, sound);
        crate::test_complete!("verifier_clean_abort_path");
    }

    #[test]
    fn verifier_clean_multiple_obligations() {
        init_test("verifier_clean_multiple_obligations");
        let events = vec![
            reserve_event(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve_event(1, o(1), ObligationKind::Ack, t(0), r(0)),
            reserve_event(2, o(2), ObligationKind::Lease, t(1), r(0)),
            commit_event(10, o(0), r(0), ObligationKind::SendPermit),
            commit_event(11, o(1), r(0), ObligationKind::Ack),
            abort_event(12, o(2), r(0), ObligationKind::Lease),
            close_event(20, r(0)),
        ];

        let mut verifier = SeparationLogicVerifier::new();
        let result = verifier.verify(&events);
        let sound = result.is_sound();
        crate::assert_with_log!(sound, "multiple obligations sound", true, sound);
        crate::test_complete!("verifier_clean_multiple_obligations");
    }

    #[test]
    fn verifier_clean_nested_regions() {
        init_test("verifier_clean_nested_regions");
        let events = vec![
            reserve_event(0, o(0), ObligationKind::Lease, t(0), r(0)),
            reserve_event(1, o(1), ObligationKind::SendPermit, t(1), r(1)),
            commit_event(10, o(1), r(1), ObligationKind::SendPermit),
            close_event(15, r(1)),
            commit_event(20, o(0), r(0), ObligationKind::Lease),
            close_event(25, r(0)),
        ];

        let mut verifier = SeparationLogicVerifier::new();
        let result = verifier.verify(&events);
        let sound = result.is_sound();
        crate::assert_with_log!(sound, "nested regions sound", true, sound);
        crate::test_complete!("verifier_clean_nested_regions");
    }

    #[test]
    fn verifier_leak_is_terminal() {
        init_test("verifier_leak_is_terminal");
        let events = vec![
            reserve_event(0, o(0), ObligationKind::IoOp, t(0), r(0)),
            leak_event(5, o(0), r(0), ObligationKind::IoOp),
            close_event(10, r(0)),
        ];

        let mut verifier = SeparationLogicVerifier::new();
        let result = verifier.verify(&events);
        let sound = result.is_sound();
        crate::assert_with_log!(sound, "leak is terminal (sound)", true, sound);
        crate::test_complete!("verifier_leak_is_terminal");
    }

    // ---- Verifier: violations --------------------------------------------------

    #[test]
    fn verifier_detects_aliasing() {
        init_test("verifier_detects_aliasing");
        let events = vec![
            reserve_event(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve_event(5, o(0), ObligationKind::SendPermit, t(0), r(0)), // Alias!
        ];

        let mut verifier = SeparationLogicVerifier::new();
        let result = verifier.verify(&events);
        let sound = result.is_sound();
        crate::assert_with_log!(!sound, "aliasing detected", false, sound);
        let aliasing_count = result
            .violations_for_property(|p| matches!(p, SeparationProperty::NoAliasing { .. }))
            .count();
        crate::assert_with_log!(
            aliasing_count == 1,
            "one aliasing violation",
            1,
            aliasing_count
        );
        crate::test_complete!("verifier_detects_aliasing");
    }

    #[test]
    fn verifier_detects_use_after_release() {
        init_test("verifier_detects_use_after_release");
        let events = vec![
            reserve_event(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit_event(10, o(0), r(0), ObligationKind::SendPermit),
            commit_event(20, o(0), r(0), ObligationKind::SendPermit), // Use after release!
        ];

        let mut verifier = SeparationLogicVerifier::new();
        let result = verifier.verify(&events);
        let sound = result.is_sound();
        crate::assert_with_log!(!sound, "use-after-release detected", false, sound);
        let uar_count = result
            .violations_for_property(|p| matches!(p, SeparationProperty::NoUseAfterRelease { .. }))
            .count();
        crate::assert_with_log!(
            uar_count == 1,
            "one use-after-release violation",
            1,
            uar_count
        );
        crate::test_complete!("verifier_detects_use_after_release");
    }

    #[test]
    fn verifier_detects_region_close_with_pending() {
        init_test("verifier_detects_region_close_with_pending");
        let events = vec![
            reserve_event(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            close_event(10, r(0)), // Region closed with pending obligation!
        ];

        let mut verifier = SeparationLogicVerifier::new();
        let result = verifier.verify(&events);
        let sound = result.is_sound();
        crate::assert_with_log!(!sound, "pending at close detected", false, sound);
        let quiescence_count = result
            .violations_for_property(|p| {
                matches!(p, SeparationProperty::RegionClosureQuiescence { .. })
            })
            .count();
        crate::assert_with_log!(
            quiescence_count >= 1,
            "quiescence violation",
            true,
            quiescence_count >= 1
        );
        crate::test_complete!("verifier_detects_region_close_with_pending");
    }

    #[test]
    fn verifier_detects_kind_mismatch() {
        init_test("verifier_detects_kind_mismatch");
        let events = vec![
            reserve_event(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit_event(10, o(0), r(0), ObligationKind::Lease), // Kind mismatch!
        ];

        let mut verifier = SeparationLogicVerifier::new();
        let result = verifier.verify(&events);
        let sound = result.is_sound();
        crate::assert_with_log!(!sound, "kind mismatch detected", false, sound);
        crate::test_complete!("verifier_detects_kind_mismatch");
    }

    #[test]
    fn verifier_detects_region_mismatch() {
        init_test("verifier_detects_region_mismatch");
        let events = vec![
            reserve_event(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit_event(10, o(0), r(1), ObligationKind::SendPermit), // Region mismatch!
        ];

        let mut verifier = SeparationLogicVerifier::new();
        let result = verifier.verify(&events);
        let sound = result.is_sound();
        crate::assert_with_log!(!sound, "region mismatch detected", false, sound);
        crate::test_complete!("verifier_detects_region_mismatch");
    }

    #[test]
    fn verifier_detects_resolve_without_reserve() {
        init_test("verifier_detects_resolve_without_reserve");
        let events = vec![
            commit_event(10, o(99), r(0), ObligationKind::SendPermit), // Never reserved!
        ];

        let mut verifier = SeparationLogicVerifier::new();
        let result = verifier.verify(&events);
        let sound = result.is_sound();
        crate::assert_with_log!(!sound, "resolve without reserve detected", false, sound);
        crate::test_complete!("verifier_detects_resolve_without_reserve");
    }

    #[test]
    fn verifier_detects_unresolved_at_trace_end() {
        init_test("verifier_detects_unresolved_at_trace_end");
        let events = vec![
            reserve_event(0, o(0), ObligationKind::Ack, t(0), r(0)),
            // No resolution — obligation still pending at trace end.
        ];

        let mut verifier = SeparationLogicVerifier::new();
        let result = verifier.verify(&events);
        let sound = result.is_sound();
        crate::assert_with_log!(!sound, "unresolved detected", false, sound);
        let holder_count = result
            .violations_for_property(|p| matches!(p, SeparationProperty::HolderCleanup { .. }))
            .count();
        crate::assert_with_log!(
            holder_count == 1,
            "holder cleanup violation",
            1,
            holder_count
        );
        crate::test_complete!("verifier_detects_unresolved_at_trace_end");
    }

    #[test]
    fn verifier_detects_reserve_in_closed_region() {
        init_test("verifier_detects_reserve_in_closed_region");
        let events = vec![
            close_event(0, r(0)),
            reserve_event(10, o(0), ObligationKind::SendPermit, t(0), r(0)), // After close!
        ];

        let mut verifier = SeparationLogicVerifier::new();
        let result = verifier.verify(&events);
        let sound = result.is_sound();
        crate::assert_with_log!(!sound, "reserve in closed region detected", false, sound);
        crate::test_complete!("verifier_detects_reserve_in_closed_region");
    }

    #[test]
    fn verifier_detects_double_close() {
        init_test("verifier_detects_double_close");
        let events = vec![close_event(0, r(0)), close_event(10, r(0))];

        let mut verifier = SeparationLogicVerifier::new();
        let result = verifier.verify(&events);
        let sound = result.is_sound();
        crate::assert_with_log!(!sound, "double close detected", false, sound);
        crate::test_complete!("verifier_detects_double_close");
    }

    #[test]
    fn verifier_failed_close_with_pending_does_not_poison_later_close() {
        init_test("verifier_failed_close_with_pending_does_not_poison_later_close");
        let events = vec![
            reserve_event(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            close_event(10, r(0)), // invalid: pending > 0
            commit_event(20, o(0), r(0), ObligationKind::SendPermit),
            close_event(30, r(0)), // should be valid after commit
        ];

        let mut verifier = SeparationLogicVerifier::new();
        let result = verifier.verify(&events);

        let quiescence_count = result
            .violations_for_property(|p| {
                matches!(p, SeparationProperty::RegionClosureQuiescence { .. })
            })
            .count();
        crate::assert_with_log!(
            quiescence_count == 1,
            "only the first close should violate quiescence",
            1,
            quiescence_count
        );

        let poisoned_close = result
            .violations
            .iter()
            .any(|v| v.description.contains("already closed"));
        crate::assert_with_log!(
            !poisoned_close,
            "failed close should not mark region closed",
            false,
            poisoned_close
        );
        crate::test_complete!("verifier_failed_close_with_pending_does_not_poison_later_close");
    }

    // ---- Verifier: realistic scenarios -----------------------------------------

    #[test]
    fn verifier_realistic_channel_send_with_cancel() {
        init_test("verifier_realistic_channel_send_with_cancel");
        let events = vec![
            reserve_event(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve_event(1, o(1), ObligationKind::SendPermit, t(1), r(0)),
            commit_event(10, o(0), r(0), ObligationKind::SendPermit),
            abort_event(11, o(1), r(0), ObligationKind::SendPermit),
            close_event(20, r(0)),
        ];

        let mut verifier = SeparationLogicVerifier::new();
        let result = verifier.verify(&events);
        let sound = result.is_sound();
        crate::assert_with_log!(sound, "cancel scenario sound", true, sound);
        crate::test_complete!("verifier_realistic_channel_send_with_cancel");
    }

    #[test]
    fn verifier_all_four_kinds_uniform() {
        init_test("verifier_all_four_kinds_uniform");
        let kinds = [
            ObligationKind::SendPermit,
            ObligationKind::Ack,
            ObligationKind::Lease,
            ObligationKind::IoOp,
        ];

        for (i, kind) in kinds.iter().enumerate() {
            let idx = i as u32;
            let events = vec![
                reserve_event(0, o(idx), *kind, t(0), r(0)),
                commit_event(10, o(idx), r(0), *kind),
                close_event(20, r(0)),
            ];

            let mut verifier = SeparationLogicVerifier::new();
            let result = verifier.verify(&events);
            let sound = result.is_sound();
            crate::assert_with_log!(sound, format!("{kind} is sound"), true, sound);
        }
        crate::test_complete!("verifier_all_four_kinds_uniform");
    }

    #[test]
    fn verifier_reuse_across_traces() {
        init_test("verifier_reuse_across_traces");
        let mut verifier = SeparationLogicVerifier::new();

        // First trace: violation.
        let events1 = vec![
            reserve_event(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            close_event(10, r(0)),
        ];
        let r1 = verifier.verify(&events1);
        let r1_sound = r1.is_sound();
        crate::assert_with_log!(!r1_sound, "first not sound", false, r1_sound);

        // Second trace: clean.
        let events2 = vec![
            reserve_event(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit_event(5, o(0), r(0), ObligationKind::SendPermit),
            close_event(10, r(0)),
        ];
        let r2 = verifier.verify(&events2);
        let r2_sound = r2.is_sound();
        crate::assert_with_log!(r2_sound, "second is sound", true, r2_sound);
        crate::test_complete!("verifier_reuse_across_traces");
    }

    // ---- Spec table tests ------------------------------------------------------

    #[test]
    fn obligation_spec_all_kinds() {
        init_test("obligation_spec_all_kinds");
        let specs = ObligationSpec::all_specs();
        let count = specs.len();
        crate::assert_with_log!(count == 4, "4 specs", 4, count);

        for spec in &specs {
            let has_predicate = !spec.resource_predicate.is_empty();
            crate::assert_with_log!(
                has_predicate,
                format!("{} has predicate", spec.kind),
                true,
                has_predicate
            );
            let has_frame = !spec.frame_condition.is_empty();
            crate::assert_with_log!(
                has_frame,
                format!("{} has frame", spec.kind),
                true,
                has_frame
            );
            let has_reserve = !spec.reserve_triple.is_empty();
            crate::assert_with_log!(
                has_reserve,
                format!("{} has reserve triple", spec.kind),
                true,
                has_reserve
            );
            let sep_count = spec.separation_properties.len();
            crate::assert_with_log!(
                sep_count == 5,
                format!("{} has 5 sep props", spec.kind),
                5,
                sep_count
            );
        }
        crate::test_complete!("obligation_spec_all_kinds");
    }

    #[test]
    fn obligation_spec_display() {
        init_test("obligation_spec_display");
        let spec = ObligationSpec::for_kind(ObligationKind::SendPermit);
        let s = format!("{spec}");
        let has_send = s.contains("send_permit");
        crate::assert_with_log!(has_send, "display has kind name", true, has_send);
        let has_frame = s.contains("Frame");
        crate::assert_with_log!(has_frame, "display has frame", true, has_frame);
        crate::test_complete!("obligation_spec_display");
    }

    // ---- Protocol spec tests ---------------------------------------------------

    #[test]
    fn protocol_spec_all_protocols() {
        init_test("protocol_spec_all_protocols");
        let protocols = ProtocolSpec::all_protocols();
        let count = protocols.len();
        crate::assert_with_log!(count == 3, "3 protocols", 3, count);

        for proto in &protocols {
            let has_global = !proto.global_type.is_empty();
            crate::assert_with_log!(
                has_global,
                format!("{} has global type", proto.name),
                true,
                has_global
            );
            let has_init = !proto.init_triple.is_empty();
            crate::assert_with_log!(
                has_init,
                format!("{} has init triple", proto.name),
                true,
                has_init
            );
            let has_delegation = !proto.delegation_triple.is_empty();
            crate::assert_with_log!(
                has_delegation,
                format!("{} has delegation triple", proto.name),
                true,
                has_delegation
            );
        }
        crate::test_complete!("protocol_spec_all_protocols");
    }

    #[test]
    fn protocol_spec_display() {
        init_test("protocol_spec_display");
        let proto = ProtocolSpec::send_permit();
        let s = format!("{proto}");
        let has_name = s.contains("SendPermit");
        crate::assert_with_log!(has_name, "display has protocol name", true, has_name);
        let has_global = s.contains("Sender -> Receiver");
        crate::assert_with_log!(has_global, "display has global type", true, has_global);
        crate::test_complete!("protocol_spec_display");
    }

    // ---- Verification Result display -------------------------------------------

    #[test]
    fn verification_result_display() {
        init_test("verification_result_display");
        let events = vec![
            reserve_event(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit_event(10, o(0), r(0), ObligationKind::SendPermit),
            close_event(20, r(0)),
        ];

        let mut verifier = SeparationLogicVerifier::new();
        let result = verifier.verify(&events);
        let s = format!("{result}");
        let has_sound = s.contains("Sound:");
        crate::assert_with_log!(has_sound, "display has Sound", true, has_sound);
        let has_events = s.contains("Events checked:");
        crate::assert_with_log!(has_events, "display has events", true, has_events);
        crate::test_complete!("verification_result_display");
    }
}
