//! Typed application results through the node's existing membership owner.

use super::{
    NativeDistributedClient, NativeDistributedComponentResult, NativeDistributedOutboundError,
    NativeDistributedRemoteError, NativeDistributedRemoteHandle, prepare_run,
};
use crate::distributed::membership::owned::remote::MembershipRemoteReport;
use crate::distributed::membership::owned::work::MembershipWorkReport;
use crate::distributed::remote_owned::{RemoteRunConfig, RemoteRunError};
use crate::remote::typed::TypedRemoteReportDecoder;
use crate::remote::{
    ComputationName, NodeId, PreparedTypedRemoteCall, TypedRemoteComputation, TypedRemoteError,
    TypedRemoteLimits, TypedRemoteRunReport,
};
use crate::types::{TaskId, Time};
use std::fmt;
use std::future::poll_fn;
use std::task::{Context, Poll};

/// Codec or existing node admission refusal before a typed owner was returned.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NativeDistributedTypedRemoteError {
    /// The complete request envelope could not be encoded within its bound.
    #[error(transparent)]
    Codec(#[from] TypedRemoteError),
    /// Existing node authority, route, capacity, timing or task admission refused.
    #[error(transparent)]
    Outbound(#[from] NativeDistributedOutboundError),
}

/// Typed remote result with the original membership and child-close receipts.
///
/// A response-codec refusal remains inside the nested remote reply. It cannot
/// erase a committed transport settlement, turn a revoked membership lease
/// into success, or discard either child-region close result.
#[non_exhaustive]
pub struct NativeDistributedTypedRemoteReport<T> {
    /// Exact membership ownership report, with only its remote payload decoded.
    pub work: MembershipWorkReport<Result<TypedRemoteRunReport<T>, RemoteRunError>>,
}

impl<T> fmt::Debug for NativeDistributedTypedRemoteReport<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeDistributedTypedRemoteReport")
            .field("work", &self.work)
            .finish_non_exhaustive()
    }
}

impl<T> NativeDistributedTypedRemoteReport<T> {
    /// Requires authorized membership success and a successful, drained typed
    /// invocation. This is not a distributed exactly-once guarantee.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.work.is_success()
            && matches!(&self.work.task, Ok(Ok(remote)) if remote.is_success())
    }
}

/// Actual typed operation report and the independent owner-retirement result.
pub type NativeDistributedTypedRemoteResult<T> = NativeDistributedComponentResult<
    Result<NativeDistributedTypedRemoteReport<T>, NativeDistributedRemoteError>,
>;

impl NativeDistributedClient {
    // This is only a refusal preflight, never a reservation. The raw path checks
    // again after arbitrary user serialization, including reentrant changes to
    // node admission, route generation, membership authority and owner capacity.
    fn typed_preflight(
        &self, node: &NodeId, incarnation: u64, config: &RemoteRunConfig,
    ) -> Result<usize, NativeDistributedOutboundError> {
        let frame_limit = self.route_frame_limit(node, incarnation)?;
        let _ = prepare_run(&self.principal, config)?;
        if self.shared.retained_operations() >= self.shared.max_operations {
            return Err(NativeDistributedOutboundError::OperationCapacity);
        }
        self.shared.check_open()?;
        Ok(frame_limit)
    }

    /// Encode and submit typed work through this node's membership-owned path.
    ///
    /// Node admission, the exact Alive route, principal authority, timing and
    /// owner capacity are checked before application serialization. No node
    /// lock is held across serializer callbacks; submission checks again after
    /// them. The codec request bound is the smaller of the requested bound and
    /// the current route's frame limit. Transport framing can impose a further
    /// limit. User serializer/deserializer allocations remain caller-owned.
    ///
    /// The invocation timeout starts at submission, after encoding, and includes
    /// owner-queue delay. Typed decoding waits for actual owner retirement and
    /// preserves membership revocation, cancellation, remote settlement and
    /// both child-close receipts. Dropping the handle cancels through the same
    /// owner; node close still drains it. No remote authority or retry is added.
    pub fn spawn_remote_typed<C: TypedRemoteComputation>(
        &self, node: NodeId, incarnation: u64, input: &C::Input,
        limits: TypedRemoteLimits, config: RemoteRunConfig,
    ) -> Result<NativeDistributedTypedRemoteHandle<C>, NativeDistributedTypedRemoteError> {
        let frame_limit = self.typed_preflight(&node, incarnation, &config)?;
        let limits = TypedRemoteLimits::new(
            limits.max_request_bytes().min(frame_limit), limits.max_response_bytes(),
        );
        let prepared = PreparedTypedRemoteCall::<C>::encode(input, limits)?;
        self.spawn_prepared_remote_typed(node, incarnation, prepared, config)
    }

    /// Submit caller-prepared typed bytes through this node's existing owner.
    ///
    /// Preparation does not reserve a node slot or confer authority. The exact
    /// incarnation, current route bound and principal are checked at submission.
    /// The encoded input allocation is compacted before the raw path's retained
    /// allocation check, so codec spare capacity cannot refuse a fitting value.
    /// Completed unread handles retain the ordinary node operation credit until
    /// observation, or until a dropped handle's owner actually retires.
    pub fn spawn_prepared_remote_typed<C: TypedRemoteComputation>(
        &self, node: NodeId, incarnation: u64, prepared: PreparedTypedRemoteCall<C>,
        config: RemoteRunConfig,
    ) -> Result<NativeDistributedTypedRemoteHandle<C>, NativeDistributedTypedRemoteError> {
        let frame_limit = self.typed_preflight(&node, incarnation, &config)?;
        if prepared.encoded_len() > frame_limit {
            return Err(NativeDistributedOutboundError::RequestTooLarge.into());
        }
        let (input, decoder) = prepared.into_owned_parts();
        let inner = self.spawn_remote(
            node, incarnation, ComputationName::new(C::NAME), input, config,
        )?;
        Ok(NativeDistributedTypedRemoteHandle { inner, decoder })
    }
}

/// Typed observation of the node's real bounded operation and retirement barrier.
///
/// The inner owner retains input/result accounting and drop cancellation. Codec
/// callbacks run only after terminal observation, with no node locks held. A
/// dropped join future leaves the handle usable; a completed observation is
/// consumed once, including when response decoding refuses the payload.
#[must_use = "join or close to collect the typed remote and retirement results"]
pub struct NativeDistributedTypedRemoteHandle<C: TypedRemoteComputation> {
    inner: NativeDistributedRemoteHandle,
    decoder: TypedRemoteReportDecoder<C>,
}

impl<C: TypedRemoteComputation> fmt::Debug for NativeDistributedTypedRemoteHandle<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeDistributedTypedRemoteHandle")
            .field("computation", &C::NAME)
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}

impl<C: TypedRemoteComputation> NativeDistributedTypedRemoteHandle<C> {
    /// Existing submission deadline; encoding precedes this deadline's start.
    #[must_use]
    pub const fn deadline(&self) -> Time { self.inner.deadline() }

    /// The real node-owned task, provisional until spawn admission completes.
    #[must_use]
    pub fn task_id(&self) -> TaskId { self.inner.task_id() }

    /// True only after the runtime has opened the owner retirement barrier.
    #[must_use]
    pub fn is_finished(&self) -> bool { self.inner.is_finished() }

    /// Request the existing operation cancellation without discarding its report.
    pub fn abort(&self) { self.inner.abort(); }

    /// Wait for retirement and decode the retained remote result exactly once.
    pub async fn join(&mut self) -> NativeDistributedTypedRemoteResult<C::Output> {
        poll_fn(|cx| self.poll_join(cx)).await
    }

    /// Cancellation-independent observation of the existing retirement barrier.
    pub fn poll_join(
        &mut self, cx: &mut Context<'_>,
    ) -> Poll<NativeDistributedTypedRemoteResult<C::Output>> {
        self.inner.poll_join(cx).map(|result| NativeDistributedComponentResult {
            outcome: result.outcome.map(|outcome| outcome.map(|report| self.decode(report))),
            retirement: result.retirement,
        })
    }

    /// Request cancellation and collect actual protocol and local drain receipts.
    pub async fn close(&mut self) -> NativeDistributedTypedRemoteResult<C::Output> {
        self.abort();
        self.join().await
    }

    fn decode(&self, report: MembershipRemoteReport) -> NativeDistributedTypedRemoteReport<C::Output> {
        let MembershipWorkReport { trigger, task, close, lease } = report.work;
        NativeDistributedTypedRemoteReport {
            work: MembershipWorkReport {
                trigger,
                task: task.map(|remote| remote.map(|report| self.decoder.decode(report))),
                close,
                lease,
            },
        }
    }
}
