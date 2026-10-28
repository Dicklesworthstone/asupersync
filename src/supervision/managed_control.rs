//! Bounded activation of configured deferred children in a managed supervisor.
//!
//! Requests join the existing controller and restart domain. This is not
//! arbitrary child insertion: only a configured `start_immediately = false`
//! binding can be activated, at most once. Automatic generation replacement
//! then follows the binding's ordinary restart mode and the supervisor policy.

use super::{ChildName, ManagedGeneration};
use crate::channel::{mpsc, oneshot};
use crate::cx::Cx;
use crate::types::CancelReason;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

const QUEUED: u8 = 0;
const CLAIMED: u8 = 1;
const CANCELLED: u8 = 2;

/// Refusal or interrupted observation of a deferred-child activation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ManagedActivationError {
    /// No command was admitted; retry after the controller makes progress.
    #[error("managed supervisor activation mailbox is full")]
    Full,
    /// The controller stopped or no longer accepts activation requests.
    #[error("managed supervisor activation is closed")]
    Closed,
    /// Cancellation before claim guarantees that this request cannot start a child.
    ///
    /// After claim, the caller can stop waiting but the supervisor retains the
    /// child and drains it at shutdown. `may_have_started` reports that ownership
    /// transfer; it does not assert that factory construction succeeded.
    #[error("managed activation cancelled (may_have_started={may_have_started}): {reason:?}")]
    Cancelled {
        /// The caller's cancellation reason.
        reason: CancelReason,
        /// Whether the controller claimed the request before cancellation.
        may_have_started: bool,
    },
    /// The compiled topology does not contain this name.
    #[error("unknown managed child: {child}")]
    UnknownChild {
        /// The requested child name.
        child: ChildName,
    },
    /// Eager children cannot be started through this deferred activation API.
    #[error("managed child is not deferred: {child}")]
    NotDeferred {
        /// The configured child name.
        child: ChildName,
    },
    /// This deferred binding already entered its one activation attempt.
    #[error("managed child has already been activated: {child}")]
    AlreadyActivated {
        /// The configured child name.
        child: ChildName,
    },
    /// Dependencies must already have a live, nonterminal generation.
    ///
    /// This refusal does not consume the child's activation attempt.
    #[error("managed child {child} requires unavailable dependency {dependency}")]
    DependencyUnavailable {
        /// The configured child name.
        child: ChildName,
        /// The dependency that must be activated or recovered first.
        dependency: ChildName,
    },
    /// Factory entry failed; the supervisor report retains the detailed cause.
    #[error("managed child failed to start: {child}")]
    StartFailed {
        /// The configured child name.
        child: ChildName,
    },
}

/// A cloneable capability to activate configured deferred children.
///
/// Clones share a bounded mailbox. At most the configured number of commands
/// wait in it, plus one start owned by the controller. Calls refuse a full
/// mailbox immediately; they do not create an unbounded capacity-waiter list.
/// Cancelled queued commands retain their slot until the controller dequeues
/// them, and cannot invoke their factory.
///
/// The caller's `Cx` controls request cancellation. Child regions, budgets,
/// names and restart intensity belong to the supervisor's `Cx`. Dropping the
/// last control closes admission; existing children continue under their
/// declared restart policy until they terminate or the supervisor is aborted.
#[derive(Clone)]
pub struct ManagedSupervisorControl {
    sender: mpsc::Sender<ActivationRequest>,
}

impl std::fmt::Debug for ManagedSupervisorControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedSupervisorControl")
            .finish_non_exhaustive()
    }
}

impl ManagedSupervisorControl {
    /// Activate one configured deferred binding under the running supervisor.
    ///
    /// Success observes the actual factory entry and returns its canonical
    /// generation. It is not a readiness, health or successful-completion
    /// guarantee: the child may already have terminated when this returns.
    /// Dependencies are checked before admission; a refusal can be retried.
    ///
    /// Dropping this future or cancelling its `Cx` before controller claim
    /// prevents this request from starting anything. After claim, the child
    /// remains supervisor-owned even if observation is cancelled or dropped.
    /// Use the supervisor handle's `abort` and `join` to stop and drain the tree.
    pub async fn activate(
        &self,
        cx: &Cx,
        child: &str,
    ) -> Result<ManagedGeneration, ManagedActivationError> {
        if cx.checkpoint().is_err() {
            return Err(cancelled(cx, false));
        }
        let (reply, mut response) = oneshot::channel();
        let state = Arc::new(AtomicU8::new(QUEUED));
        let guard = ActivationGuard(Arc::clone(&state));
        let command = ActivationRequest {
            child: child.into(),
            caller: cx.clone(),
            state,
            reply,
        };
        match self.sender.try_send(command) {
            Ok(()) => {}
            Err(mpsc::SendError::Full(_)) => return Err(ManagedActivationError::Full),
            Err(mpsc::SendError::Disconnected(_)) => return Err(ManagedActivationError::Closed),
            Err(mpsc::SendError::Cancelled(_)) => return Err(cancelled(cx, false)),
        }
        match response.recv(cx).await {
            Ok(result) => result,
            Err(oneshot::RecvError::Cancelled) => Err(cancelled(cx, guard.cancel())),
            Err(_) if cx.checkpoint().is_err() => Err(cancelled(cx, guard.cancel())),
            Err(_) => Err(ManagedActivationError::Closed),
        }
    }
}

fn cancelled(cx: &Cx, may_have_started: bool) -> ManagedActivationError {
    ManagedActivationError::Cancelled {
        reason: cx
            .cancel_reason()
            .unwrap_or_else(|| CancelReason::user("managed activation caller cancelled")),
        may_have_started,
    }
}

struct ActivationGuard(Arc<AtomicU8>);

impl ActivationGuard {
    fn cancel(&self) -> bool {
        matches!(
            self.0
                .compare_exchange(QUEUED, CANCELLED, Ordering::AcqRel, Ordering::Acquire),
            Err(CLAIMED)
        )
    }
}

impl Drop for ActivationGuard {
    fn drop(&mut self) {
        self.cancel();
    }
}

pub(crate) struct ActivationRequest {
    pub(crate) child: ChildName,
    caller: Cx,
    state: Arc<AtomicU8>,
    reply: oneshot::Sender<Result<ManagedGeneration, ManagedActivationError>>,
}

impl ActivationRequest {
    /// Linearizes request withdrawal against controller-owned child admission.
    pub(crate) fn claim(&self) -> bool {
        // The caller may be cancelled without polling its activation future
        // again. Check the retained context on the controller too, on both
        // sides of the claim CAS so cancellation in that gap cannot start work.
        if self.caller.checkpoint().is_err() {
            let _ =
                self.state
                    .compare_exchange(QUEUED, CANCELLED, Ordering::AcqRel, Ordering::Acquire);
            return false;
        }
        if self
            .state
            .compare_exchange(QUEUED, CLAIMED, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        if self.caller.checkpoint().is_err() {
            self.state.store(CANCELLED, Ordering::Release);
            return false;
        }
        true
    }

    pub(crate) fn complete(self, result: Result<ManagedGeneration, ManagedActivationError>) {
        // In-memory notification only: cleanup/parent cancellation must not
        // suppress a receipt for an already owned start.
        let _ = self.reply.send_blocking(result);
    }
}

pub(crate) type ActivationReceiver = mpsc::Receiver<ActivationRequest>;

pub(crate) fn channel(
    pending_capacity: NonZeroUsize,
) -> (ManagedSupervisorControl, ActivationReceiver) {
    let (sender, receiver) = mpsc::channel(pending_capacity.get());
    (ManagedSupervisorControl { sender }, receiver)
}
