//! Bounded lifecycle control of configured children in a managed supervisor.
//!
//! Requests join the existing controller and restart domain. This is not
//! arbitrary child insertion: only a configured `start_immediately = false`
//! binding can be activated, at most once. Automatic generation replacement
//! then follows the binding's ordinary restart mode and the supervisor policy.

use super::{BudgetRefusal, ChildName, ManagedGeneration, ManagedRestartMode};
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

/// Refusal or interrupted observation of an individual child lifecycle command.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ManagedChildControlError {
    /// No command was admitted; retry after the controller makes progress.
    #[error("managed supervisor control mailbox is full")]
    Full,
    /// The controller stopped or no longer accepts commands.
    #[error("managed supervisor control is closed")]
    Closed,
    /// A cancelled queued request cannot change a child's lifecycle.
    ///
    /// After claim, the supervisor owns the operation even when its caller
    /// stops waiting. This flag describes ownership, not completed cleanup.
    #[error("managed child control cancelled (may_have_applied={may_have_applied}): {reason:?}")]
    Cancelled {
        /// The caller's cancellation reason.
        reason: CancelReason,
        /// Whether the controller claimed the command before cancellation.
        may_have_applied: bool,
    },
    /// The compiled topology does not contain this name.
    #[error("unknown managed child: {child}")]
    UnknownChild {
        /// The requested child name.
        child: ChildName,
    },
    /// The binding has no owned, started generation.
    #[error("managed child is not running: {child}")]
    NotRunning {
        /// The configured child name.
        child: ChildName,
    },
    /// The generation changed before this command could be claimed.
    #[error("managed child generation changed: {child}")]
    StaleGeneration {
        /// The configured child name.
        child: ChildName,
        /// The generation the caller intended to control.
        expected: ManagedGeneration,
        /// The generation currently owned by the controller.
        actual: ManagedGeneration,
    },
    /// A direct or transitive dependent still owns a generation.
    #[error("managed child {child} is still required by {dependent}")]
    DependencyInUse {
        /// The requested dependency.
        child: ChildName,
        /// The dependent that must be stopped and drained first.
        dependent: ChildName,
    },
    /// Drain or permanent factory retirement failed.
    ///
    /// The supervisor report retains the detailed cause. This is not a
    /// successful quiescence receipt; the supervisor finishes its cleanup.
    #[error("managed child could not be stopped cleanly: {child}")]
    StopFailed {
        /// The configured child name.
        child: ChildName,
    },
    /// Temporary children never enter a replacement generation.
    #[error("managed child restart is disabled: {child}")]
    RestartDisabled {
        /// The configured child name.
        child: ChildName,
    },
    /// A local or shared restart allowance refused the requested batch.
    ///
    /// The failure is published after the policy's required cleanup. Refusal
    /// under Stop retires the selected group; escalation can stop the tree.
    #[error("managed child restart allowance refused {child}: {refusal:?}")]
    RestartRefused {
        /// The configured child name.
        child: ChildName,
        /// The actual restart accounting refusal.
        refusal: BudgetRefusal,
    },
    /// The requested policy batch did not produce a replacement for this child.
    ///
    /// Cancellation, cleanup failure or a failed start can prevent replacement.
    /// The supervisor retains affected work and terminal outcomes; optional
    /// siblings follow their ordinary policy. This error is not a successful
    /// replacement or quiescence receipt.
    #[error("managed child could not be restarted: {child}")]
    RestartFailed {
        /// The configured child name.
        child: ChildName,
    },
}

/// Controller ownership state of one configured binding at a snapshot boundary.
///
/// These states describe ownership, not readiness or health. A child can finish
/// independently immediately before or after the controller publishes a snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ManagedChildState {
    /// A configured deferred binding is still available for its first activation.
    Dormant,
    /// The controller owns this admitted generation.
    ///
    /// Its body may already have completed; the controller has not yet retired
    /// or replaced its ownership. Use this exact identity for stop/restart fences.
    Active {
        /// Current canonical task and generation-region identity.
        generation: ManagedGeneration,
    },
    /// The binding will never invoke its factory again.
    Retired {
        /// Last admitted generation, or None if none was admitted.
        last_generation: Option<ManagedGeneration>,
    },
}

/// A configured binding in a managed supervisor ownership snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ManagedChildInfo {
    /// Name in the compiled supervisor topology.
    pub name: ChildName,
    /// Declared automatic restart mode.
    pub restart_mode: ManagedRestartMode,
    /// Controller-owned lifecycle state at the snapshot boundary.
    pub state: ManagedChildState,
}

/// Refusal or interrupted observation of a managed ownership snapshot.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ManagedSnapshotError {
    /// No query was admitted; all control operations share this bounded mailbox.
    #[error("managed supervisor control mailbox is full")]
    Full,
    /// The controller stopped or no longer accepts requests.
    #[error("managed supervisor snapshot is closed")]
    Closed,
    /// The caller stopped waiting; inspection never changes child ownership.
    #[error("managed supervisor snapshot cancelled: {reason:?}")]
    Cancelled {
        /// The caller's cancellation reason.
        reason: CancelReason,
    },
}

/// A cloneable capability to inspect, activate, stop and restart configured children.
///
/// Clones share a bounded mailbox. At most the configured number of commands
/// wait in it, plus one command owned by the controller. Calls refuse a full
/// mailbox immediately; they do not create an unbounded capacity-waiter list.
/// Cancelled queued commands retain their slot until the controller dequeues
/// them, and cannot change a child's lifecycle.
///
/// The caller's `Cx` controls request cancellation. Child regions, budgets,
/// names and restart intensity belong to the supervisor's `Cx`. Dropping the
/// last control closes admission; existing children continue under their
/// declared restart policy until they terminate or the supervisor is aborted.
#[derive(Clone)]
pub struct ManagedSupervisorControl {
    sender: mpsc::Sender<ControlRequest>,
}

impl std::fmt::Debug for ManagedSupervisorControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedSupervisorControl")
            .finish_non_exhaustive()
    }
}

impl ManagedSupervisorControl {
    /// Snapshot every configured binding in deterministic compiled start order.
    ///
    /// The controller takes this ownership snapshot when it services the query.
    /// It can wait behind boot, a restart, backoff or cleanup; it is not a live
    /// progress feed. Active means the controller owns that generation, not that
    /// its body is healthy or still running. Names include dormant and retired
    /// bindings, and inspection never consumes a child result.
    ///
    /// Queries use the same bounded mailbox as activation, stopping and restart.
    /// A queued query is withdrawn when its future is dropped or its `Cx` is
    /// cancelled. A committed snapshot remains observable if cancellation races
    /// with delivery. Child ownership and restart accounting are unchanged.
    pub async fn which_children(
        &self,
        cx: &Cx,
    ) -> Result<Vec<ManagedChildInfo>, ManagedSnapshotError> {
        if cx.checkpoint().is_err() {
            return Err(snapshot_cancelled(cx));
        }
        let (reply, mut response) = oneshot::channel();
        let state = Arc::new(AtomicU8::new(QUEUED));
        let _guard = ActivationGuard(Arc::clone(&state));
        let request = SnapshotRequest {
            caller: cx.clone(),
            state,
            reply,
        };
        match self.sender.try_send(ControlRequest::WhichChildren(request)) {
            Ok(()) => {}
            Err(mpsc::SendError::Full(_)) => return Err(ManagedSnapshotError::Full),
            Err(mpsc::SendError::Disconnected(_)) => return Err(ManagedSnapshotError::Closed),
            Err(mpsc::SendError::Cancelled(_)) => return Err(snapshot_cancelled(cx)),
        }
        match response.recv(cx).await {
            Ok(result) => result,
            Err(oneshot::RecvError::Cancelled) => Err(snapshot_cancelled(cx)),
            Err(_) if cx.checkpoint().is_err() => Err(snapshot_cancelled(cx)),
            Err(_) => Err(ManagedSnapshotError::Closed),
        }
    }

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
        match self.sender.try_send(ControlRequest::Activate(command)) {
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

    /// Permanently stop one configured binding after draining its generation.
    ///
    /// The expected identity fences delayed or retried commands from stopping a
    /// replacement generation. A direct or transitive dependent with an owned
    /// generation must be stopped first, even if its task has already exited.
    ///
    /// Success returns the stopped identity after its task, descendants and
    /// region finalizers finish and its factory is retired. It never restarts
    /// siblings or consumes restart intensity. The binding cannot subsequently
    /// be activated, and is excluded from automatic sibling restart batches.
    ///
    /// Before controller claim, dropping this future or cancelling its `Cx`
    /// withdraws the command. After claim, cleanup remains supervisor-owned;
    /// caller cancellation can only interrupt observation. A successful receipt
    /// is preserved even if cancellation races with its delivery.
    pub async fn stop_child(
        &self,
        cx: &Cx,
        child: &str,
        expected: ManagedGeneration,
    ) -> Result<ManagedGeneration, ManagedChildControlError> {
        self.control_child(cx, child, expected, ControlRequest::Stop)
            .await
    }

    /// Restart a current generation using the supervisor's configured strategy.
    ///
    /// The expected identity fences delayed commands from restarting a newer
    /// generation. Temporary, dormant and permanently stopped bindings cannot
    /// be restarted. An explicit request restarts a Transient source even when
    /// its orderly shutdown succeeds; collateral children keep their own modes.
    ///
    /// Once claimed, this operation cancels every owned generation selected by
    /// OneForOne, OneForAll or RestForOne before awaiting any child. It then uses
    /// the same local and shared restart allowance, backoff, dependency order,
    /// name ownership and escalation as automatic recovery. Claim is not an
    /// admission preflight: a refused restart can leave children stopped or
    /// stop the supervisor. Under the local Stop escalation policy, refusal
    /// drains and permanently retires the entire selected group.
    ///
    /// Success returns the actual replacement identity after all selected old
    /// generations drain and the controller finishes the replacement batch.
    /// Optional siblings retain their ordinary start/refusal policy. Success
    /// observes factory entry, not application readiness or continued health.
    ///
    /// Dropping or cancelling before claim withdraws this request. After claim,
    /// the supervisor owns the batch even if its caller stops waiting. Parent
    /// cancellation during drain or backoff prevents replacement admission.
    pub async fn restart_child(
        &self,
        cx: &Cx,
        child: &str,
        expected: ManagedGeneration,
    ) -> Result<ManagedGeneration, ManagedChildControlError> {
        self.control_child(cx, child, expected, ControlRequest::Restart)
            .await
    }

    async fn control_child(
        &self,
        cx: &Cx,
        child: &str,
        expected: ManagedGeneration,
        kind: fn(ChildControlRequest) -> ControlRequest,
    ) -> Result<ManagedGeneration, ManagedChildControlError> {
        if cx.checkpoint().is_err() {
            return Err(stop_cancelled(cx, false));
        }
        let (reply, mut response) = oneshot::channel();
        let state = Arc::new(AtomicU8::new(QUEUED));
        let guard = ActivationGuard(Arc::clone(&state));
        let command = kind(ChildControlRequest {
            child: child.into(),
            expected,
            caller: cx.clone(),
            state,
            reply,
        });
        match self.sender.try_send(command) {
            Ok(()) => {}
            Err(mpsc::SendError::Full(_)) => return Err(ManagedChildControlError::Full),
            Err(mpsc::SendError::Disconnected(_)) => return Err(ManagedChildControlError::Closed),
            Err(mpsc::SendError::Cancelled(_)) => return Err(stop_cancelled(cx, false)),
        }
        match response.recv(cx).await {
            Ok(result) => result,
            Err(oneshot::RecvError::Cancelled) => Err(stop_cancelled(cx, guard.cancel())),
            Err(_) if cx.checkpoint().is_err() => Err(stop_cancelled(cx, guard.cancel())),
            Err(_) => Err(ManagedChildControlError::Closed),
        }
    }
}

fn snapshot_cancelled(cx: &Cx) -> ManagedSnapshotError {
    ManagedSnapshotError::Cancelled {
        reason: cx
            .cancel_reason()
            .unwrap_or_else(|| CancelReason::user("managed supervisor query caller cancelled")),
    }
}

fn stop_cancelled(cx: &Cx, may_have_applied: bool) -> ManagedChildControlError {
    ManagedChildControlError::Cancelled {
        reason: cx
            .cancel_reason()
            .unwrap_or_else(|| CancelReason::user("managed child control caller cancelled")),
        may_have_applied,
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
        claim_request(&self.caller, &self.state)
    }

    pub(crate) fn complete(self, result: Result<ManagedGeneration, ManagedActivationError>) {
        // In-memory notification only: cleanup/parent cancellation must not
        // suppress a receipt for an already owned start.
        let _ = self.reply.send_blocking(result);
    }
}

pub(crate) struct ChildControlRequest {
    pub(crate) child: ChildName,
    pub(crate) expected: ManagedGeneration,
    caller: Cx,
    state: Arc<AtomicU8>,
    reply: oneshot::Sender<Result<ManagedGeneration, ManagedChildControlError>>,
}

impl ChildControlRequest {
    pub(crate) fn claim(&self) -> bool {
        claim_request(&self.caller, &self.state)
    }

    pub(crate) fn complete(self, result: Result<ManagedGeneration, ManagedChildControlError>) {
        // Lifecycle receipts do not depend on either Cx remaining live.
        let _ = self.reply.send_blocking(result);
    }
}

pub(crate) struct SnapshotRequest {
    caller: Cx,
    state: Arc<AtomicU8>,
    reply: oneshot::Sender<Result<Vec<ManagedChildInfo>, ManagedSnapshotError>>,
}

impl SnapshotRequest {
    pub(crate) fn claim(&self) -> bool {
        claim_request(&self.caller, &self.state)
    }

    pub(crate) fn complete(self, result: Result<Vec<ManagedChildInfo>, ManagedSnapshotError>) {
        // Publish the owned snapshot without depending on a live caller Cx.
        let _ = self.reply.send_blocking(result);
    }
}

fn claim_request(caller: &Cx, state: &AtomicU8) -> bool {
    // The caller can cancel without repolling its response future. Check the
    // retained context on both sides of claim before performing any effect.
    if caller.checkpoint().is_err() {
        let _ = state.compare_exchange(QUEUED, CANCELLED, Ordering::AcqRel, Ordering::Acquire);
        return false;
    }
    if state
        .compare_exchange(QUEUED, CLAIMED, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return false;
    }
    if caller.checkpoint().is_err() {
        state.store(CANCELLED, Ordering::Release);
        return false;
    }
    true
}

pub(crate) enum ControlRequest {
    Activate(ActivationRequest),
    Stop(ChildControlRequest),
    Restart(ChildControlRequest),
    WhichChildren(SnapshotRequest),
}

pub(crate) type ControlReceiver = mpsc::Receiver<ControlRequest>;

pub(crate) fn channel(
    pending_capacity: NonZeroUsize,
) -> (ManagedSupervisorControl, ControlReceiver) {
    let (sender, receiver) = mpsc::channel(pending_capacity.get());
    (ManagedSupervisorControl { sender }, receiver)
}
