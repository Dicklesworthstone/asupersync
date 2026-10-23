//! Typed observation of the checked, region-owned remote invocation path.

use super::{
    PreparedTypedRemoteCall, Signature, TypedRemoteComputation, TypedRemoteError,
    TypedRemoteLimits, TypedRemoteOutcome, TypedRemoteStage, decode_value,
};
use crate::cx::{ChildRegionError, Cx};
use crate::distributed::remote_owned::{
    RemoteLeaseSettlement, RemoteRunClose, RemoteRunConfig, RemoteRunHandle,
    RemoteRunHandleError, RemoteRunReport, RemoteRunTaskError, RemoteRunTrigger,
    prepare_run, spawn_remote_owned,
};
use crate::remote::{ComputationName, NodeId, RemoteOutcome, RemoteTaskId};
#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
use crate::remote::{NativeRemoteOwnedError, NativeRemoteReservation};
use crate::types::{CancelReason, Outcome, TaskId, Time};
use std::fmt;
use std::future::poll_fn;
use std::marker::PhantomData;
use std::task::{Context, Poll};
#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
use std::time::Duration;

/// Refusal while encoding or submitting a typed owned invocation.
///
/// A response-codec failure is carried by [`TypedRemoteRunReply::outcome`],
/// after retirement, so it cannot discard the invocation's cleanup receipt.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TypedRemoteRunError {
    /// Input schema, encoding, or complete application-envelope limit failed.
    #[error(transparent)]
    Codec(#[from] TypedRemoteError),
    /// The ordinary owned path refused capability, budget, or task admission.
    #[error(transparent)]
    Owned(#[from] RemoteRunHandleError),
    /// The reserved native path refused input, authority, timing or task admission.
    #[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
    #[error(transparent)]
    NativeOwned(#[from] NativeRemoteOwnedError),
}

/// Typed remote result with the original cancellation and checked-lease facts.
///
/// The lease settlement describes protocol delivery and local ownership. It
/// remains `Committed` if a timely remote Success was delivered but its typed
/// application envelope cannot be decoded. Inspect the outcome as well, or
/// use [`TypedRemoteRunReport::is_success`]. Debug omits values and diagnostics.
#[non_exhaustive]
pub struct TypedRemoteRunReply<T> {
    /// Original transport correlation identity.
    pub remote_task_id: RemoteTaskId,
    /// Decoded remote terminal, codec failure, or exact underlying failure.
    pub outcome: Outcome<TypedRemoteOutcome<T>, TypedRemoteError>,
    /// Cancellation observed by the real proxy task.
    pub cancellation: Option<CancelReason>,
    /// Original checked local lease settlement, without reclassification.
    pub settlement: RemoteLeaseSettlement,
}

impl<T> fmt::Debug for TypedRemoteRunReply<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TypedRemoteRunReply")
            .field("remote_task_id", &self.remote_task_id)
            .field(
                "typed_success",
                &matches!(self.outcome, Outcome::Ok(TypedRemoteOutcome::Success(_))),
            )
            .field("cancelled", &self.cancellation.is_some())
            .field("settlement", &self.settlement)
            .finish_non_exhaustive()
    }
}

/// Typed result returned after actual proxy retirement and child-region close.
///
/// All lifecycle fields come from the existing [`RemoteRunReport`]. A valid
/// decoded payload cannot override cancellation, an aborted lease, or failed
/// descendant/finalizer cleanup. `Ok(report)` means reporting was reached.
#[non_exhaustive]
pub struct TypedRemoteRunReport<T> {
    /// Why the owner began closing the invocation subtree.
    pub trigger: RemoteRunTrigger,
    /// Real proxy result, retaining task admission, panic, and cancellation errors.
    pub task: Result<TypedRemoteRunReply<T>, RemoteRunTaskError>,
    /// Actual child-close and finalizer receipt, including close refusal.
    pub close: Result<RemoteRunClose, ChildRegionError>,
    /// Original explicit cancellation-enqueue failure, if any.
    pub cancel_error: Option<ChildRegionError>,
}

impl<T> fmt::Debug for TypedRemoteRunReport<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TypedRemoteRunReport")
            .field("trigger", &self.trigger)
            .field("proxy_returned", &self.task.is_ok())
            .field("child_closed", &self.close.is_ok())
            .field("cancel_enqueue_failed", &self.cancel_error.is_some())
            .finish_non_exhaustive()
    }
}

impl<T> TypedRemoteRunReport<T> {
    /// Requires timely typed success, checked commit, and successful subtree close.
    /// This is not a distributed exactly-once or compensation guarantee.
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self.trigger, RemoteRunTrigger::Finished)
            && self.cancel_error.is_none()
            && self.task.as_ref().is_ok_and(|reply| {
                reply.cancellation.is_none()
                    && reply.settlement == RemoteLeaseSettlement::Committed
                    && matches!(reply.outcome, Outcome::Ok(TypedRemoteOutcome::Success(_)))
            })
            && self.close.as_ref().is_ok_and(|close| {
                matches!(close.outcome, Outcome::Ok(()))
                    && close
                        .cleanup_outcome
                        .as_ref()
                        .is_none_or(|outcome| matches!(outcome, Outcome::Ok(())))
            })
    }
}

/// A typed computation owned independently of polling its result handle.
///
/// The existing [`RemoteRunHandle`] owns task admission, the checked lease,
/// remote cancellation, and child-region close. Dropping this handle requests
/// cancellation through that owner; its runtime retains cleanup work.
/// Dropping only a join future preserves the handle and its eventual report.
///
/// Output decoding occurs during terminal observation, after the invocation
/// has retired. User deserializers execute in the observer's context, as on
/// [`super::TypedRemoteHandle`]. Codec errors consume the terminal once and
/// retain its lifecycle evidence. Arbitrary deserializer allocations and
/// callbacks are outside the application-envelope byte limit.
#[must_use = "dropping the typed owned handle requests cancellation"]
pub struct TypedRemoteRunHandle<C: TypedRemoteComputation> {
    inner: RemoteRunHandle,
    signature: Signature,
    limits: TypedRemoteLimits,
    marker: PhantomData<fn() -> C>,
}

impl<C: TypedRemoteComputation> fmt::Debug for TypedRemoteRunHandle<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TypedRemoteRunHandle")
            .field("computation", &self.signature.name)
            .field("owner", &self.inner)
            .finish_non_exhaustive()
    }
}

impl<C: TypedRemoteComputation> TypedRemoteRunHandle<C> {
    /// Real local owner identity, provisional until its ordinary task admission.
    #[must_use]
    pub fn local_task_id(&self) -> TaskId {
        self.inner.local_task_id()
    }

    /// Invocation cancellation deadline captured at owned task submission.
    #[must_use]
    pub fn deadline(&self) -> Time {
        self.inner.deadline()
    }

    /// Whether the underlying owner has retired and published its terminal.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.inner.is_finished()
    }

    /// Request invocation cancellation; only its join receipt establishes cleanup.
    pub fn abort(&self) {
        self.inner.abort();
    }

    /// Request cancellation with the existing reason-strengthening semantics.
    pub fn abort_with_reason(&self, reason: CancelReason) {
        self.inner.abort_with_reason(reason);
    }

    /// Consume and decode one ready report; pending leaves ownership untouched.
    /// Repeated terminal consumption returns the ordinary owner join error.
    pub fn try_join(
        &mut self,
    ) -> Result<Option<TypedRemoteRunReport<C::Output>>, RemoteRunHandleError> {
        self.inner
            .try_join()
            .map(|report| report.map(|report| decode_report::<C>(self.signature, self.limits, report)))
    }

    /// Poll without surrendering the owner when observation stops.
    /// Decoding only begins after the underlying retirement barrier is open.
    pub fn poll_join(
        &mut self,
        task: &mut Context<'_>,
    ) -> Poll<Result<TypedRemoteRunReport<C::Output>, RemoteRunHandleError>> {
        self.inner.poll_join(task).map(|result| {
            result.map(|report| decode_report::<C>(self.signature, self.limits, report))
        })
    }

    /// Observe the terminal report without interrupting cleanup on observer cancellation.
    ///
    /// Like [`RemoteRunHandle::join`], this observation is uninterruptible.
    /// Dropping its future preserves the handle; use `abort` to stop the work.
    pub async fn join(
        &mut self,
        _cx: &Cx,
    ) -> Result<TypedRemoteRunReport<C::Output>, RemoteRunHandleError> {
        poll_fn(|task| self.poll_join(task)).await
    }

    /// Request cancellation and collect its actual terminal and close receipt.
    pub async fn close(
        &mut self,
        cx: &Cx,
    ) -> Result<TypedRemoteRunReport<C::Output>, RemoteRunHandleError> {
        self.inner
            .close(cx)
            .await
            .map(|report| decode_report::<C>(self.signature, self.limits, report))
    }
}

impl<C: TypedRemoteComputation> PreparedTypedRemoteCall<C> {
    /// Execute a prepared typed call through a reserved native domain and child region.
    ///
    /// Reserve exactly [`Self::encoded_len`] before calling. The reservation
    /// supplies route authority without an attached legacy `RemoteCap`; the
    /// caller's capability mask, native frame bounds and child constraints
    /// still apply. Checked lease admission precedes native publication.
    ///
    /// The native owner retains its charge while the proxy and driver drain,
    /// including cancellation and timeout. The exact protocol outcome and
    /// child-close receipt are collected before typed response decoding. A
    /// codec refusal preserves those receipts and the checked lease settlement.
    /// Decoded report values belong to the caller and are outside native buffer
    /// accounting; user deserializer allocations have the same boundary.
    ///
    /// The first poll submits a region-owned task and releases the prepared
    /// input after copying it under native admission. An unpolled future
    /// performs no dispatch. Dropping a started future drops its owned handle
    /// and requests cancellation; the runtime retains admitted cleanup. The
    /// timeout begins at submission and initiates cancellation without
    /// manufacturing remote quiescence.
    #[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
    pub async fn run_admitted_owned(
        self,
        cx: &Cx,
        reservation: NativeRemoteReservation,
        lease: Duration,
        config: RemoteRunConfig,
    ) -> Result<TypedRemoteRunReport<C::Output>, TypedRemoteRunError> {
        let mut call = self.spawn_admitted_owned(cx, reservation, lease, config)?;
        Ok(call.join(cx).await?)
    }

    /// Start a typed, region-owned invocation inside a reserved native domain.
    ///
    /// The reservation must cover exactly [`Self::encoded_len`]. Work starts
    /// independently of result polling and follows the existing native owned
    /// timeout, checked-lease and cancellation/drain path. Parent close waits
    /// for the invocation without a manual native-handle close.
    ///
    /// The complete prepared input is bounded and copied under the reservation
    /// before this method returns. An unread raw terminal report stays charged;
    /// typed decoding runs only when the returned handle consumes that report.
    /// Consumption transfers report values to the caller, even if decoding
    /// fails. Dropping the handle requests cancellation and retains native
    /// driver/proxy charges until their actual retirement.
    #[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
    pub fn spawn_admitted_owned(
        self,
        cx: &Cx,
        reservation: NativeRemoteReservation,
        lease: Duration,
        config: RemoteRunConfig,
    ) -> Result<TypedRemoteRunHandle<C>, TypedRemoteRunError> {
        let inner = reservation.spawn_owned(
            cx,
            &ComputationName::new(C::NAME),
            self.input.data(),
            lease,
            config,
        )?;
        Ok(TypedRemoteRunHandle {
            inner,
            signature: self.signature,
            limits: self.limits,
            marker: PhantomData,
        })
    }

    /// Publish through the existing checked, region-owned remote path.
    ///
    /// The encoded envelope stays bounded by this prepared call's limits.
    /// Checked lease admission precedes remote registration and send. The
    /// timeout begins here and includes owner/proxy admission and remote work;
    /// it initiates cancellation, not forced remote termination. Native leases
    /// and drain policy bound silent peers; custom runtimes must supply an
    /// eventual terminal result. This does not acquire native per-peer credits.
    pub fn spawn_owned(
        self,
        cx: &Cx,
        node: NodeId,
        config: RemoteRunConfig,
    ) -> Result<TypedRemoteRunHandle<C>, TypedRemoteRunError> {
        let inner = spawn_remote_owned(
            cx,
            node,
            ComputationName::new(C::NAME),
            self.input,
            config,
        )?;
        Ok(TypedRemoteRunHandle {
            inner,
            signature: self.signature,
            limits: self.limits,
            marker: PhantomData,
        })
    }
}

/// Encode and submit a typed computation with checked task/region ownership.
///
/// The existing owned path's cancellation, remote/runtime, timer, and positive
/// timeout requirements are checked before application serialization. They are
/// checked again when publishing the prepared call, so cancellation during
/// serialization cannot admit remote work. The invocation timeout starts at
/// owned task submission, after encoding. No remote authority is acquired
/// implicitly and V1-V3 transport envelopes are unchanged.
pub fn spawn_remote_typed_owned<C: TypedRemoteComputation>(
    cx: &Cx,
    node: NodeId,
    input: &C::Input,
    limits: TypedRemoteLimits,
    config: RemoteRunConfig,
) -> Result<TypedRemoteRunHandle<C>, TypedRemoteRunError> {
    let _ = prepare_run(cx, &config).map_err(RemoteRunHandleError::Run)?;
    PreparedTypedRemoteCall::<C>::encode(input, limits)?.spawn_owned(cx, node, config)
}

fn decode_report<C: TypedRemoteComputation>(
    signature: Signature,
    limits: TypedRemoteLimits,
    report: RemoteRunReport,
) -> TypedRemoteRunReport<C::Output> {
    TypedRemoteRunReport {
        trigger: report.trigger,
        task: report.task.map(|reply| TypedRemoteRunReply {
            remote_task_id: reply.remote_task_id,
            cancellation: reply.cancellation,
            settlement: reply.settlement,
            outcome: match reply.outcome {
                Outcome::Ok(RemoteOutcome::Success(bytes)) => {
                    match decode_value(signature, TypedRemoteStage::Response, &bytes, limits) {
                        Ok(value) => Outcome::Ok(TypedRemoteOutcome::Success(value)),
                        Err(error) => Outcome::Err(error),
                    }
                }
                Outcome::Ok(RemoteOutcome::Failed(message)) => {
                    Outcome::Ok(TypedRemoteOutcome::Failed(message))
                }
                Outcome::Ok(RemoteOutcome::Cancelled(reason)) => {
                    Outcome::Ok(TypedRemoteOutcome::Cancelled(reason))
                }
                Outcome::Ok(RemoteOutcome::Panicked(message)) => {
                    Outcome::Ok(TypedRemoteOutcome::Panicked(message))
                }
                Outcome::Err(error) => Outcome::Err(error.into()),
                Outcome::Cancelled(reason) => Outcome::Cancelled(reason),
                Outcome::Panicked(payload) => Outcome::Panicked(payload),
            },
        }),
        close: report.close,
        cancel_error: report.cancel_error,
    }
}

#[cfg(test)]
mod tests;
