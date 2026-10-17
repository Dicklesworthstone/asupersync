//! Guarded Recursion Lens: Time-Indexed Behavior for Actors and Leases.
//!
//! This module captures the guarded recursion / "later" modality lens as a
//! concrete design note tied to actor and lease APIs in asupersync.
//!
//! # Background: What is Guarded Recursion?
//!
//! In type theory, the **later modality** (written `▸A` or `later(A)`) delays
//! a type by one time step. Guarded recursion allows defining infinite
//! (coinductive) behaviors safely: a self-referencing definition is productive
//! if every recursive occurrence is guarded by `▸`.
//!
//! For example, an infinite stream `Stream A = A × ▸(Stream A)` is well-defined
//! because the recursive reference `Stream A` appears only under `▸`.
//!
//! # How This Maps to Asupersync
//!
//! Asupersync's runtime is inherently step-indexed via its deterministic lab
//! runtime (virtual time advances in discrete steps) and its explicit state
//! machines. The "later" modality is realized concretely:
//!
//! ## Actors as Guarded Fixed Points
//!
//! An actor's behavior unfolds one message at a time:
//!
//! ```text
//! ActorBehavior<S, M> = S × (M → ▸(ActorBehavior<S, M>))
//! ```
//!
//! This reads: an actor has a current state `S` and a handler that, given a
//! message `M`, produces the *next* behavior (guarded by `▸`). The `handle()`
//! method implements this unfolding:
//!
//! ```text
//! step(t):
//!   msg ← mailbox.recv()       // blocks until message or close
//!   self.handle(cx, msg)        // mutate state, may spawn sub-tasks
//!   → ▸(step(t+1))             // next step is "later"
//! ```
//!
//! The guard ensures:
//! - **Productivity**: Each step processes exactly one message.
//! - **Termination**: The loop terminates when the mailbox closes
//!   (mailbox close = coinductive termination signal).
//! - **Cancel safety**: `on_stop` runs after the mailbox drains, providing a
//!   clean finalization phase.
//!
//! ## Leases as Time-Indexed Obligations
//!
//! A lease is a time-indexed obligation that transitions through states:
//!
//! ```text
//! LeaseEvolution(t) =
//!   | Active { expires_at }  if t < expires_at
//!   | Expired                if t ≥ expires_at ∧ ¬renewed
//!   | Released               if holder released before expiry
//! ```
//!
//! The renewal operation extends the "active" window:
//!
//! ```text
//! renew(lease, duration, now):
//!   requires: lease.state(now) = Active
//!   ensures:  lease.expires_at' = now + duration
//!   effect:   shifts the ▸ boundary forward in time
//! ```
//!
//! Key insight: **renewal is a re-guarding operation**. It moves the
//! `▸`-boundary (expiry) into the future, keeping the lease "productive"
//! (active). Without renewal, the lease becomes "non-productive" (expired)
//! after a fixed number of time steps.
//!
//! ## Region Lifecycle as Step-Indexed Protocol
//!
//! ```text
//! RegionProtocol = Open → ▸(Closing → ▸(Draining → ▸(Finalizing → ▸(Closed))))
//! ```
//!
//! Each transition is guarded: a region cannot skip phases. The guard ensures
//! that children complete before the parent finalizes (structured concurrency).
//!
//! ## Budget Consumption as Decreasing Sequence
//!
//! A budget is a monotonically decreasing resource:
//!
//! ```text
//! budget(t+1) ≤ budget(t)     (deadline approaches, polls consumed)
//! ```
//!
//! This is the dual of guarded recursion: instead of producing one step of
//! output, we consume one step of resource. The budget reaching zero is the
//! inductive termination condition.
//!
//! # Practical Payoff
//!
//! The primary payoff of the guarded recursion lens is **time-indexed lease
//! renewal reasoning**:
//!
//! 1. **Liveness proof**: If a lease is renewed every `d` units with duration
//!    `d`, it is always active. This is a coinductive argument: `active(t)`
//!    implies `active(t + d)` via renewal.
//!
//! 2. **Expiry proof**: An unrenewed lease expires at exactly
//!    `created_at + initial_duration`. This is an inductive argument with
//!    base case at creation time.
//!
//! 3. **Nested deadline monotonicity**: If a lease lives inside a region with
//!    deadline `D`, the lease's expiry cannot exceed `D`. This is the
//!    deadline monotonicity invariant: `lease.expires_at ≤ region.deadline`.
//!
//! 4. **Actor restart reasoning**: A supervised actor restarts with fresh
//!    state, but the restart itself is a `▸`-guarded step. This means the
//!    restart protocol is well-founded (no infinite restart loops without
//!    time advancing).
//!
//! # Constraints for Future Phases
//!
//! See [`PreservationConstraint`] for the machine-readable checklist.

use crate::types::Time;
use std::time::Duration;

/// Time-indexed invariants that the runtime must preserve to keep the
/// guarded recursion lens valid.
///
/// Each invariant corresponds to a concrete runtime property that, if
/// violated, would break the time-indexed reasoning described above.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimeIndexedInvariant {
    /// Actor message processing is sequential: at most one message is
    /// handled per step per actor. Concurrent message delivery to the
    /// same actor would break the guarded fixed-point model.
    ActorSequentialProcessing,

    /// Actor mailbox close triggers `on_stop`. The coinductive
    /// termination signal (mailbox close) must produce the finalization
    /// step rather than silently dropping the actor.
    ActorCleanFinalization,

    /// Lease expiry is monotonically determined by time: once
    /// `now ≥ expires_at`, the lease is expired regardless of state.
    /// No operation other than `renew` can move `expires_at` forward.
    LeaseTimeMonotonicity,

    /// Lease renewal extends expiry from `now`, not from `expires_at`.
    /// This prevents "banking" renewals: you must be active to renew.
    LeaseRenewalFromNow,

    /// Lease state transitions are irreversible for terminal states:
    /// `Released` and `Expired` cannot transition back to `Active`.
    LeaseTerminalIrreversibility,

    /// Region phases progress strictly forward:
    /// `Open → Closing → Draining → Finalizing → Closed`.
    /// No backward transitions.
    RegionPhaseMonotonicity,

    /// Budget consumption is monotonically decreasing within a region:
    /// polls and cost only decrease, deadline only approaches.
    BudgetMonotonicConsumption,

    /// Deadline monotonicity across the region tree: child deadline
    /// cannot exceed parent deadline.
    DeadlineTreeMonotonicity,

    /// Supervised actor restart is a guarded step: the restart factory
    /// produces a `▸(Actor)`, meaning time must advance before the new
    /// actor processes messages.
    SupervisedRestartGuarded,
}

/// Constraints that future phases must preserve to keep the guarded
/// recursion / "later" modality lens valid.
///
/// Each constraint is a "don't break this" note for later phases.
#[derive(Debug, Clone)]
pub struct PreservationConstraint {
    /// The invariant this constraint protects.
    pub invariant: TimeIndexedInvariant,
    /// Human-readable description of what must be preserved.
    pub constraint: &'static str,
    /// Why breaking this would invalidate the lens.
    pub rationale: &'static str,
}

/// Returns the full checklist of preservation constraints.
#[must_use]
pub fn preservation_constraints() -> Vec<PreservationConstraint> {
    vec![
        PreservationConstraint {
            invariant: TimeIndexedInvariant::ActorSequentialProcessing,
            constraint: "Actor mailbox must remain single-consumer",
            rationale: "Concurrent message handling would make the actor's state evolution \
                        non-deterministic within a single time step, breaking the guarded \
                        fixed-point model where each step produces exactly one state transition.",
        },
        PreservationConstraint {
            invariant: TimeIndexedInvariant::ActorCleanFinalization,
            constraint: "Actor on_stop must run when mailbox closes",
            rationale: "The coinductive termination signal (mailbox close) must trigger \
                        finalization. Skipping on_stop would leave the actor in a \
                        non-terminal state, breaking the coinductive unwinding.",
        },
        PreservationConstraint {
            invariant: TimeIndexedInvariant::LeaseTimeMonotonicity,
            constraint: "Lease expiry is determined solely by time comparison",
            rationale: "The time-indexed model requires that lease validity is a pure \
                        function of current time: active(t) = (t < expires_at). Any \
                        state that overrides this (e.g., 'force-active despite expired') \
                        would break the time-indexing.",
        },
        PreservationConstraint {
            invariant: TimeIndexedInvariant::LeaseRenewalFromNow,
            constraint: "Lease renewal sets expires_at = now + duration",
            rationale: "Renewal from 'now' ensures the lease cannot accumulate unbounded \
                        future credit. This is the re-guarding operation: it places a \
                        new guard exactly 'duration' steps ahead.",
        },
        PreservationConstraint {
            invariant: TimeIndexedInvariant::LeaseTerminalIrreversibility,
            constraint: "Released and Expired lease states are terminal",
            rationale: "Terminal states in the lease state machine correspond to \
                        coinductive termination. Allowing transitions back to Active \
                        would create an inconsistent state history.",
        },
        PreservationConstraint {
            invariant: TimeIndexedInvariant::RegionPhaseMonotonicity,
            constraint: "Region lifecycle phases are strictly forward",
            rationale: "The step-indexed protocol Open → Closing → ... → Closed \
                        is a finite unfolding. Backward transitions would violate \
                        the well-foundedness of the region shutdown sequence.",
        },
        PreservationConstraint {
            invariant: TimeIndexedInvariant::BudgetMonotonicConsumption,
            constraint: "Budget resources only decrease during execution",
            rationale: "Budget is the dual of guarded recursion: a decreasing measure \
                        that guarantees termination. Adding budget mid-execution would \
                        break the inductive termination argument.",
        },
        PreservationConstraint {
            invariant: TimeIndexedInvariant::DeadlineTreeMonotonicity,
            constraint: "Child deadline <= parent deadline in the region tree",
            rationale: "Nested time bounds must tighten inward. A child with a longer \
                        deadline than its parent would outlive the parent's scope, \
                        violating structured concurrency.",
        },
        PreservationConstraint {
            invariant: TimeIndexedInvariant::SupervisedRestartGuarded,
            constraint: "Actor restart via supervision advances time by at least one step",
            rationale: "The restart factory must be guarded: spawning a replacement actor \
                        consumes at least one scheduling step. Without this guard, a \
                        crash-restart loop could diverge at a single time point.",
        },
    ]
}

/// A lightweight model of lease evolution for testing time-indexed properties.
///
/// This mirrors the real `Lease` struct but is self-contained for unit testing
/// the guarded recursion invariants without depending on `RuntimeState`.
#[derive(Debug, Clone)]
pub struct LeaseModel {
    /// When the lease was created.
    pub created_at: Time,
    /// Current expiry time.
    pub expires_at: Time,
    /// Initial duration for reference.
    pub initial_duration: Duration,
    /// How many times renewed.
    pub renewal_count: u32,
    /// Whether explicitly released.
    pub released: bool,
}

impl LeaseModel {
    /// Create a new active lease model.
    #[must_use]
    pub fn new(created_at: Time, duration: Duration) -> Self {
        Self {
            created_at,
            expires_at: created_at + duration,
            initial_duration: duration,
            renewal_count: 0,
            released: false,
        }
    }

    /// Is the lease active at the given time?
    #[must_use]
    pub fn is_active(&self, now: Time) -> bool {
        !self.released && now < self.expires_at
    }

    /// Is the lease expired at the given time?
    #[must_use]
    pub fn is_expired(&self, now: Time) -> bool {
        !self.released && now >= self.expires_at
    }

    /// Renew the lease from `now`.
    ///
    /// Returns `false` if the lease is already expired or released.
    pub fn renew(&mut self, duration: Duration, now: Time) -> bool {
        if self.released || now >= self.expires_at {
            return false;
        }
        self.expires_at = now + duration;
        self.renewal_count += 1;
        true
    }

    /// Release the lease.
    ///
    /// Returns `false` if already released or expired.
    pub fn release(&mut self, now: Time) -> bool {
        if self.released || now >= self.expires_at {
            return false;
        }
        self.released = true;
        true
    }

    /// Remaining time until expiry, or zero.
    #[must_use]
    pub fn remaining(&self, now: Time) -> Duration {
        if self.released || now >= self.expires_at {
            Duration::ZERO
        } else {
            Duration::from_nanos(self.expires_at.duration_since(now))
        }
    }
}

/// A lightweight model of actor step evolution.
///
/// Models the actor's behavior as a sequence of time-indexed steps where
/// each step processes one message and advances the step counter.
#[derive(Debug, Clone)]
pub struct ActorStepModel {
    /// Current step index (how many messages processed).
    pub step: u64,
    /// Whether the mailbox is closed.
    pub mailbox_closed: bool,
    /// Whether on_stop has been called.
    pub finalized: bool,
}

impl ActorStepModel {
    /// Create a new actor model at step 0.
    #[must_use]
    pub fn new() -> Self {
        Self {
            step: 0,
            mailbox_closed: false,
            finalized: false,
        }
    }

    /// Process one message (advance one step).
    ///
    /// Returns `false` if the mailbox is closed.
    pub fn process_message(&mut self) -> bool {
        if self.mailbox_closed {
            return false;
        }
        self.step += 1;
        true
    }

    /// Close the mailbox (coinductive termination signal).
    pub fn close_mailbox(&mut self) {
        self.mailbox_closed = true;
    }

    /// Run finalization (on_stop).
    ///
    /// Returns `false` if already finalized or mailbox not closed.
    pub fn finalize(&mut self) -> bool {
        if self.finalized || !self.mailbox_closed {
            return false;
        }
        self.finalized = true;
        true
    }

    /// Is the actor in a terminal state?
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        self.mailbox_closed && self.finalized
    }
}

impl Default for ActorStepModel {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[path = "guarded_inline_tests.rs"]
mod tests;
