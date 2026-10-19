//! Owned regions that apply typed child policies at terminal publication.
//!
//! `Scope<P>` remains the legacy marker-only surface. This opt-in owner keeps
//! a real policy and applies it to members spawned through `PolicyRegion::spawn`,
//! after the native spawn wrapper has frozen the member's outcome. A parked
//! owner does not delay fail-fast: the member's completion requests cancellation.
//!
//! Membership is bounded by a total retained-member limit. Both live members
//! and completed results count until `join` consumes the region. Descendants
//! spawned by a member remain region-owned and are drained at close, but do not
//! become typed policy members automatically. No principal spawning context is
//! exposed by this owner.
//!
//! User policies run without runtime or control locks and may run concurrently
//! on different workers. `Escalate` cancels the authoritative parent selected
//! at region admission, including a sealed-region fallback. This can cancel
//! other work in that parent, including the opener. The ordinary `Scope` and
//! `Cx::spawn` behavior is unchanged (br-asupersync-mfqmcs).

use super::{ChildRegion, ChildRegionError, ChildRegionSpec, Cx, cap};
use crate::record::task::TaskOutcome;
use crate::runtime::spawn_mailbox::{RegionCommand, SpawnGateway};
use crate::runtime::task_handle::{ObservedSpawnCompletion, SpawnTerminalObserver};
use crate::runtime::{JoinError, SpawnError, TaskHandle};
use crate::types::policy::{AggregateDecision, PolicyAction};
use crate::types::{CancelReason, Outcome, PanicPayload, Policy, RegionId, TaskId};
use parking_lot::Mutex;
use std::any::Any;
use std::fmt;
use std::future::{Future, poll_fn};
use std::num::NonZeroUsize;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;

/// Refusal before a typed member is handed to runtime admission.
#[derive(Debug)]
#[non_exhaustive]
pub enum PolicyRegionSpawnError {
    /// Live and completed members already occupy the retained-member limit.
    AtCapacity {
        /// The configured total retained-member limit.
        limit: usize,
    },
    /// Cancellation, escalation, or a policy fault stopped further membership.
    Stopped,
    /// Reserving the next member's bookkeeping storage failed.
    Allocation,
    /// The runtime's ordinary spawn path refused the request.
    Spawn(SpawnError),
}

impl fmt::Display for PolicyRegionSpawnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AtCapacity { limit } => write!(f, "policy region member limit {limit} reached"),
            Self::Stopped => write!(f, "policy region no longer accepts members"),
            Self::Allocation => write!(f, "policy region member storage could not be reserved"),
            Self::Spawn(error) => write!(f, "policy region spawn failed: {error}"),
        }
    }
}

impl std::error::Error for PolicyRegionSpawnError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Spawn(error) => Some(error),
            _ => None,
        }
    }
}

/// The runtime's retained close receipt, separate from typed policy aggregation.
///
/// A receipt is available only after actual region quiescence. The runtime's
/// erased task outcome does not substitute for `PolicyRegionReport::decision`.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PolicyRegionClose {
    /// Runtime task/region outcome, including ordinary close cancellation.
    pub outcome: TaskOutcome,
    /// Finalizer/cleanup failure, retained independently of member outcomes.
    pub cleanup_outcome: Option<TaskOutcome>,
    /// This region's panic or the first panic propagated by a descendant.
    pub descendant_panic: Option<PanicPayload>,
}

/// Typed member results after retirement and an attempted quiescent close.
#[derive(Debug)]
#[non_exhaustive]
#[must_use = "inspect both the policy decision and the region close receipt"]
pub struct PolicyRegionReport<T, E> {
    /// Identity of the owned policy region.
    pub region: RegionId,
    /// Every accepted member's exact terminal outcome, in spawn order.
    ///
    /// Admission denials appear as cancellation and were never policy callbacks,
    /// because no child task was minted. Acknowledged typed cancellation cleanup
    /// results retain the ordinary `Cx::spawn` result policy.
    pub outcomes: Vec<Outcome<T, E>>,
    /// Policy aggregation, or the first policy callback/aggregation panic.
    ///
    /// A child panic is an `Outcome::Panicked` in `outcomes`. It is distinct
    /// from a panic in the policy itself, which appears as `Err` here.
    pub decision: Result<AggregateDecision<E>, PanicPayload>,
    /// First non-`Continue` action observed, with the admitted child identity.
    ///
    /// A policy callback panic installs a fail-fast cancellation action here.
    pub first_action: Option<(TaskId, PolicyAction)>,
    /// Whether a member policy requested parent-region escalation.
    pub escalated: bool,
    /// A requested cancellation could not be submitted to the owning runtime.
    ///
    /// Successful submission alone does not certify drain; inspect `close`.
    pub cancellation_dispatch_failed: bool,
    /// Actual close receipt. An error is not evidence of quiescence.
    pub close: Result<PolicyRegionClose, ChildRegionError>,
}

#[derive(Default)]
struct Control {
    first_action: Option<(TaskId, PolicyAction)>,
    policy_panic: Option<PanicPayload>,
    escalated: bool,
    cancellation_dispatch_failed: bool,
}

struct SharedPolicy<P> {
    policy: P,
    region: RegionId,
    parent: RegionId,
    gateway: Arc<SpawnGateway>,
    stopped: AtomicBool,
    control: Mutex<Control>,
}

impl<P> SharedPolicy<P> {
    fn dispatch(&self, region: RegionId, reason: CancelReason) -> Result<(), ChildRegionError> {
        self.stopped.store(true, Ordering::Release);
        if self
            .gateway
            .enqueue_region_command(RegionCommand::Cancel { region_id: region, reason })
            .is_err()
        {
            self.control.lock().cancellation_dispatch_failed = true;
            Err(ChildRegionError::RuntimeUnavailable)
        } else {
            Ok(())
        }
    }

    fn apply(&self, child: TaskId, action: PolicyAction) {
        let (region, reason) = match &action {
            PolicyAction::Continue => return,
            PolicyAction::CancelSiblings(reason) => (self.region, reason.clone()),
            PolicyAction::Escalate => (
                self.parent,
                CancelReason::fail_fast().with_region(self.region).with_task(child),
            ),
        };
        {
            let mut control = self.control.lock();
            control.escalated |= matches!(action, PolicyAction::Escalate);
            if control.first_action.is_none() {
                control.first_action = Some((child, action));
            }
        }
        let _ = self.dispatch(region, reason);
    }
}

struct MemberObserver<P> {
    shared: Arc<SharedPolicy<P>>,
}

impl<T, P> SpawnTerminalObserver<Outcome<T, P::Error>> for MemberObserver<P>
where
    T: Send + 'static,
    P: Policy,
{
    fn classify(
        &self,
        completion: ObservedSpawnCompletion<Outcome<T, P::Error>>,
    ) -> std::thread::Result<Result<Outcome<T, P::Error>, JoinError>> {
        // A value suppressed by task cancellation can itself have a panicking
        // destructor. It is still one typed member panic, observed exactly once.
        catch_unwind(AssertUnwindSafe(|| completion.classify()))
    }

    fn panic_payload(&self, payload: Box<dyn Any + Send>) -> PanicPayload {
        contained_panic_payload(payload)
    }

    fn on_terminal(&self, child: TaskId, result: &Result<Outcome<T, P::Error>, JoinError>) {
        let action = catch_unwind(AssertUnwindSafe(|| match result {
            Ok(outcome) => self.shared.policy.on_child_outcome(child, outcome),
            Err(JoinError::Cancelled(reason)) => self.shared.policy.on_child_outcome(
                child,
                &Outcome::<T, P::Error>::Cancelled(reason.clone()),
            ),
            Err(JoinError::Panicked(payload)) => self.shared.policy.on_child_outcome(
                child,
                &Outcome::<T, P::Error>::Panicked(payload.clone()),
            ),
            Err(JoinError::PolledAfterCompletion) => self.shared.policy.on_child_outcome(
                child,
                &Outcome::<T, P::Error>::Panicked(PanicPayload::new(
                    "policy region member polled after completion",
                )),
            ),
        }));
        match action {
            Ok(action) => self.shared.apply(child, action),
            Err(payload) => {
                // Arm cancellation before retiring any user panic payload.
                // The frozen child result is still published unchanged.
                self.shared.apply(
                    child,
                    PolicyAction::CancelSiblings(
                        CancelReason::fail_fast().with_region(self.shared.region).with_task(child),
                    ),
                );
                let payload = contained_panic_payload(payload);
                let mut control = self.shared.control.lock();
                if control.policy_panic.is_none() {
                    control.policy_panic = Some(payload);
                }
            }
        }
    }
}

// Retiring a caught panic payload is itself user code. Preserve the original
// panic if that destructor panics too; forgetting only that second payload
// avoids a third destructor panic escaping through terminal publication.
fn contained_panic_payload(payload: Box<dyn Any + Send>) -> PanicPayload {
    let message = super::scope::payload_to_string(&payload);
    if let Err(second) = catch_unwind(AssertUnwindSafe(|| drop(payload))) {
        std::mem::forget(second);
    }
    PanicPayload::new(message)
}

/// A bounded typed membership owner with real policy-driven cancellation.
///
/// Use `Cx::open_policy_region` to create one. A member's factory receives the
/// admission-built child context with the opener's capability set and met
/// budgets. Only movable `Send + 'static` members are supported here.
///
/// Dropping the owner or its unpolled `join` future requests region close
/// before retained values or errors are destroyed. Drop cannot wait; the
/// enclosing region remains the eventual drain backstop.
#[must_use = "join the policy region to observe typed outcomes and quiescence"]
pub struct PolicyRegion<T, P: Policy, Caps = cap::All> {
    region: Option<ChildRegion<Caps>>,
    shared: Arc<SharedPolicy<P>>,
    opener: Cx<cap::None>,
    limit: NonZeroUsize,
    members: Vec<TaskHandle<Outcome<T, P::Error>>>,
    // Keep results in this owner so Drop arms child close before user Drop.
    outcomes: Vec<Outcome<T, P::Error>>,
}

impl<T, P: Policy, Caps> fmt::Debug for PolicyRegion<T, P, Caps> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PolicyRegion")
            .field("region", &self.shared.region)
            .field("parent", &self.shared.parent)
            .field("retained_members", &self.members.len())
            .field("limit", &self.limit)
            .finish_non_exhaustive()
    }
}

impl<Caps> Cx<Caps>
where
    Caps: cap::HasSpawn + Send + Sync + 'static,
{
    /// Open an owned region whose typed members consult a real policy.
    ///
    /// `limit` counts both live members and retained results. Storage grows
    /// only when a member is spawned; a large limit is not an eager allocation.
    /// A member error or panic can cancel siblings while the opener is parked
    /// on unrelated work, before it calls `PolicyRegion::join`.
    ///
    /// `Escalate` cancels the admitted parent region, which can include the
    /// opener and unrelated siblings there. A policy panic cancels only this
    /// owned subtree and is retained separately from the originating outcome.
    /// Policy callbacks may run concurrently on native workers and never run
    /// under runtime or owner-control locks.
    ///
    /// The new surface is opt-in. It does not activate the marker policy on
    /// legacy `Scope<P>` or change any ordinary spawn method.
    pub async fn open_policy_region<T, P>(
        &self,
        spec: ChildRegionSpec,
        policy: P,
        limit: NonZeroUsize,
    ) -> Result<PolicyRegion<T, P, Caps>, ChildRegionError>
    where
        T: Send + 'static,
        P: Policy,
    {
        let region = self.open_child_region(spec).await?;
        let gateway = region
            .cx()
            .spawn_gateway_handle()
            .ok_or(ChildRegionError::NoRuntimeGateway)?;
        let shared = Arc::new(SharedPolicy {
            policy,
            region: region.region_id(),
            parent: region.parent_region_id(),
            gateway,
            stopped: AtomicBool::new(false),
            control: Mutex::new(Control::default()),
        });
        Ok(PolicyRegion {
            region: Some(region),
            shared,
            opener: self.retype(),
            limit,
            members: Vec::new(),
            outcomes: Vec::new(),
        })
    }
}

impl<T, P: Policy, Caps> PolicyRegion<T, P, Caps> {
    /// The owned policy region's identity.
    #[must_use]
    pub fn region_id(&self) -> RegionId {
        self.shared.region
    }

    /// The authoritative parent targeted by `PolicyAction::Escalate`.
    #[must_use]
    pub fn parent_region_id(&self) -> RegionId {
        self.shared.parent
    }

    /// Total retained members, including completed members awaiting collection.
    #[must_use]
    pub fn len(&self) -> usize {
        self.members.len()
    }

    /// Whether no member has been accepted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// Request cancellation of this subtree and stop accepting new members.
    ///
    /// Submission is separate from drain. Call `join` to observe all results
    /// and actual region quiescence.
    pub fn cancel(&self, reason: CancelReason) -> Result<(), ChildRegionError> {
        self.shared.dispatch(self.shared.region, reason)
    }
}

impl<T, P, Caps> PolicyRegion<T, P, Caps>
where
    T: Send + 'static,
    P: Policy,
    Caps: cap::HasSpawn + Send + Sync + 'static,
{
    /// Spawn a typed member, returning its stable zero-based input index.
    ///
    /// The factory is called only by an admitted task. Admission-time denial
    /// is collected as cancellation, just as with ordinary `Cx::spawn`.
    /// A cancellation racing this call can deny the queued member after this
    /// method returns successfully. No member is created on a synchronous
    /// refusal, and no factory is called merely to check the member limit.
    pub fn spawn<F, Fut>(&mut self, f: F) -> Result<usize, PolicyRegionSpawnError>
    where
        F: FnOnce(Cx<Caps>) -> Fut + Send + 'static,
        Fut: Future<Output = Outcome<T, P::Error>> + Send + 'static,
    {
        if self.shared.stopped.load(Ordering::Acquire) {
            return Err(PolicyRegionSpawnError::Stopped);
        }
        if self.members.len() == self.limit.get() {
            return Err(PolicyRegionSpawnError::AtCapacity { limit: self.limit.get() });
        }
        self.members
            .try_reserve(1)
            .map_err(|_| PolicyRegionSpawnError::Allocation)?;
        // Reserve result storage before admission as well. There is no
        // allocation or user destructor between collecting a result and
        // installing it in the owning guard.
        self.outcomes
            .try_reserve(self.members.len() + 1)
            .map_err(|_| PolicyRegionSpawnError::Allocation)?;
        let region = self.region.as_ref().expect("an unconsumed policy owner has its region");
        let observer = MemberObserver { shared: Arc::clone(&self.shared) };
        let handle = region
            .cx()
            .spawn_with_terminal_observer(f, observer)
            .map_err(PolicyRegionSpawnError::Spawn)?;
        let index = self.members.len();
        self.members.push(handle);
        Ok(index)
    }

    /// Drain every member, close the subtree, and aggregate exact typed results.
    ///
    /// Member policy decisions already run at terminal publication; a parked
    /// early member cannot hide a later member's failure. Collection retains
    /// input order and yields after 64 ready members per poll. All direct
    /// handles cross their real retirement barriers before region close.
    ///
    /// Cancellation of the opener is observed through both member drain and
    /// region cleanup. It is acknowledged with the normal masking rules and
    /// forwarded to this subtree; it never replaces an individual outcome or
    /// shortens the close wait. The outer task retains its ordinary spawn
    /// policy, including cancellation before its first user poll.
    ///
    /// A successful close includes descendants, finalizers and obligations.
    /// Non-cooperative work may delay it indefinitely. The report keeps typed
    /// aggregation separate from erased runtime and cleanup outcomes.
    pub async fn join(mut self) -> PolicyRegionReport<T, P::Error> {
        let opener = self.opener.clone();
        let mut cancelled = pin!(opener.cancelled());
        let mut forwarded = false;
        let mut next = 0;
        poll_fn(|task| {
            if !forwarded && cancelled.as_mut().poll(task).is_ready() {
                forwarded = true;
                let reason = opener.cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("policy region opener cancelled"));
                let _ = opener.checkpoint();
                let _ = self.cancel(reason);
            }
            for _ in 0..64 {
                let Some(handle) = self.members.get_mut(next) else {
                    return Poll::Ready(());
                };
                match handle.poll_join(task) {
                    Poll::Ready(joined) => {
                        self.outcomes.push(member_outcome(joined));
                        next += 1;
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }
            if next == self.members.len() {
                Poll::Ready(())
            } else {
                task.waker().wake_by_ref();
                Poll::Pending
            }
        }).await;

        let shared = Arc::clone(&self.shared);
        let region = self.region.take().expect("policy region closes exactly once");
        let mut closing = pin!(region.close_with_outcome());
        let close = poll_fn(|task| {
            // Keep acknowledgement live while descendants or finalizers
            // are still draining, not only while direct members are joined.
            if !forwarded && cancelled.as_mut().poll(task).is_ready() {
                forwarded = true;
                let reason = opener.cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("policy region opener cancelled"));
                let _ = opener.checkpoint();
                let _ = shared.dispatch(shared.region, reason);
            }
            closing.as_mut().poll(task)
        }).await.map(|receipt| PolicyRegionClose {
            outcome: receipt.outcome,
            cleanup_outcome: receipt.cleanup_outcome,
            descendant_panic: receipt.descendant_panic,
        });
        // A masked observation may become acknowledgeable after cleanup.
        if opener.is_cancel_requested() {
            let _ = opener.checkpoint();
        }
        let (first_action, escalated, cancellation_dispatch_failed, policy_panic) = {
            let mut control = self.shared.control.lock();
            (
                control.first_action.take(),
                control.escalated,
                control.cancellation_dispatch_failed,
                control.policy_panic.take(),
            )
        };
        let decision = match policy_panic {
            Some(payload) => Err(payload),
            None => catch_unwind(AssertUnwindSafe(|| {
                self.shared.policy.aggregate_outcomes(&self.outcomes)
            })).map_err(contained_panic_payload),
        };
        PolicyRegionReport {
            region: self.shared.region,
            outcomes: std::mem::take(&mut self.outcomes),
            decision,
            first_action,
            escalated,
            cancellation_dispatch_failed,
            close,
        }
    }
}

fn member_outcome<T, E>(joined: Result<Outcome<T, E>, JoinError>) -> Outcome<T, E> {
    match joined {
        Ok(outcome) => outcome,
        Err(JoinError::Cancelled(reason)) => Outcome::Cancelled(reason),
        Err(JoinError::Panicked(payload)) => Outcome::Panicked(payload),
        Err(JoinError::PolledAfterCompletion) => Outcome::Panicked(PanicPayload::new(
            "policy region member polled after completion",
        )),
    }
}

impl<T, P: Policy, Caps> Drop for PolicyRegion<T, P, Caps> {
    fn drop(&mut self) {
        // This body runs before any retained result or policy destructor.
        // If join has taken the region, its owned close future already carries
        // the same backstop and is dropped before this argument.
        drop(self.region.take());
    }
}

#[cfg(test)]
#[path = "policy_region/tests.rs"]
mod tests;
