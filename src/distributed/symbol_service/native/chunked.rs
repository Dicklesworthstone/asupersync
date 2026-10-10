//! Native multi-frame adapter sharing the original transport's admission domain.

use super::{RemoteSymbolError, RemoteSymbolTransport};
use crate::cx::Cx;
use crate::distributed::distribution::ReplicaAck;
use crate::distributed::symbol_service::service::chunked::{
    BEGIN, CHUNK, COMMIT, SYMBOL_CHUNKED_SERVICE_COMPUTATION, Upload,
    range_request, read_progress, read_range, request, upload_body,
};
use crate::distributed::symbol_service::service::validate_receipt;
use crate::distributed::symbol_service::{SymbolBatchKey, SymbolBatchLimits, SymbolStoreError, decode_symbol_batch, encode_symbol_batch};
use crate::remote::{
    ComputationName, IdempotencyKey, RemoteComputationClient, RemoteInput, RemotePeerHello,
    RemoteServiceWireOutcome, RemoteServiceWireRequest, RemoteServiceWireResponse, RemoteTaskId,
    SpawnRequest,
};
use crate::security::{AuthKey, AuthenticatedSymbol};
use std::future::{Future, poll_fn};
use std::io::{self, Write};
use std::sync::Arc;
use zeroize::Zeroizing;

impl RemoteSymbolTransport {
    /// Use a separately granted chunked symbol capability with finite shared admission.
    ///
    /// The complete canonical batch may exceed the client's JSON frame limit.
    /// Every request/response payload is bounded by `max_chunk_bytes` plus fixed
    /// metadata; construction counts the actual empty JSON envelopes and admits
    /// worst-case byte-array expansion BEFORE allocating/copying batch payloads.
    /// The receiver has independent staging, chunk, batch, and frame policies.
    /// Its smaller advertised chunk limit is honored without changing identity.
    ///
    /// One credit covers encoding, all frames, final verification and destruction.
    /// Each RPC retains the client's bounded connection/retry/attempt policy.
    /// An owner Cx deadline bounds the whole transfer; without one, the explicit
    /// batch size and per-RPC limits bound its finite sequence of calls. There is
    /// no automatic replay after ambiguous delivery and no implicit resume token.
    /// Dropping/cancelling closes local work but incomplete remote staging remains
    /// charged until the receiver's fixed expiry/reap. A lost commit receipt can
    /// follow successful publication; a subsequent identical send is idempotent.
    #[allow(clippy::too_many_arguments)]
    pub fn new_chunked_bounded(
        cx: Cx, hello: RemotePeerHello,
        routes: impl IntoIterator<Item = (String, RemoteComputationClient)>,
        auth_key: Arc<AuthKey>, limits: SymbolBatchLimits,
        max_in_flight: usize, max_chunk_bytes: usize,
    ) -> Result<Self, RemoteSymbolError> {
        if max_chunk_bytes == 0 || u32::try_from(max_chunk_bytes).is_err() {
            return Err(RemoteSymbolError::Configuration);
        }
        let mut transport = Self::new_bounded(cx, hello, routes, auth_key, limits, max_in_flight)?;
        for (replica, client) in transport.routes.iter() {
            transport.check_chunk_frame_budget(replica, client, max_chunk_bytes)?;
        }
        transport.chunk_bytes = Some(max_chunk_bytes);
        Ok(transport)
    }

    /// Send or reconcile a chunked upload using a caller-owned attempt identity.
    ///
    /// The caller must persist `attempt` before first dispatch and reserve it for
    /// this exact canonical signed batch in the authenticated origin's namespace.
    /// Do not reuse it for an unrelated upload, including work submitted through
    /// a different transport or the compatibility `send_symbols` entry point.
    /// After a publisher restart, supplying the same attempt and exact batch
    /// continues the receiver's retained prefix; an already retained batch yields
    /// a newly verified commit receipt. An attempt with different batch metadata
    /// is refused while its original stage is present.
    ///
    /// This is explicit caller-driven reconciliation, not automatic retry.
    /// Receiver expiry, abort, or restart can remove an incomplete stage, in which
    /// case the exact upload starts again. A lost commit reply can follow a
    /// successful publication. This API does not persist caller intent, add
    /// receiver durability, guarantee remote rollback, or establish exactly-once
    /// execution. Cancellation/drop retains the existing remote staging policy.
    ///
    /// Only transports constructed with `new_chunked_bounded` support this
    /// operation; whole-batch transports return `Configuration` before dispatch.
    /// The clone-shared credit, complete owner deadline, frame bounds and
    /// authenticated receipt checks are the same as ordinary chunked sends.
    pub async fn send_symbols_with_attempt(
        &self, replica: &str, symbols: Vec<AuthenticatedSymbol>, attempt: u64,
    ) -> Result<ReplicaAck, RemoteSymbolError> {
        if self.cx.is_cancel_requested() { return Err(RemoteSymbolError::Cancelled); }
        let maximum = self.chunk_bytes.ok_or(RemoteSymbolError::Configuration)?;
        if !self.routes.contains_key(replica) { return Err(RemoteSymbolError::UnknownReplica); }
        self.admission.run(|| {
            self.with_owner_deadline(self.send_chunked_attempt(replica, symbols, maximum, Some(attempt)))
        }).await
    }

    fn check_chunk_frame_budget(
        &self, replica: &str, client: &RemoteComputationClient, maximum: usize,
    ) -> Result<(), RemoteSymbolError> {
        // Maximal correlation IDs keep this bound valid for every later frame.
        let spawn = SpawnRequest {
            remote_task_id: RemoteTaskId::from_raw(u64::MAX),
            computation: ComputationName::new(SYMBOL_CHUNKED_SERVICE_COMPUTATION),
            input: RemoteInput::new(Vec::new()), lease: client.config().attempt_timeout(),
            idempotency_key: IdempotencyKey::from_raw(u128::MAX), budget: None,
            origin_node: self.hello.peer_node().clone(), origin_region: self.cx.region_id(), origin_task: self.cx.task_id(),
        };
        let wire = RemoteServiceWireRequest::from_spawn_request(self.hello.clone(), &spawn)
            .map_err(|_| RemoteSymbolError::Configuration)?;
        let response = RemoteServiceWireResponse::Outcome {
            remote_task_id: u64::MAX, outcome: RemoteServiceWireOutcome::Success(Vec::new()),
        };
        // Request: 14-byte prefix + replica + 68-byte upload + 8-byte offset + chunk.
        // Response: range header + chunk, progress (92), or attempt + receipt.
        let request_bytes = maximum.checked_add(90 + replica.len()).ok_or(RemoteSymbolError::Configuration)?;
        let response_bytes = maximum.checked_add(80).ok_or(RemoteSymbolError::Configuration)?.max(82 + replica.len()).max(92);
        let ceiling = client.config().wire_limits().max_frame_bytes();
        for (base, bytes) in [(encoded_size(&wire)?, request_bytes), (encoded_size(&response)?, response_bytes)] {
            let total = bytes.checked_mul(4).and_then(|expanded| base.checked_add(expanded))
                .ok_or(RemoteSymbolError::Configuration)?;
            if total > ceiling { return Err(RemoteSymbolError::Configuration); }
        }
        Ok(())
    }

    fn check_chunk_context(&self) -> Result<(), RemoteSymbolError> {
        if self.cx.is_cancel_requested() {
            let _ = self.cx.checkpoint();
            return Err(RemoteSymbolError::Cancelled);
        }
        if self.cx.budget().deadline.is_some_and(|deadline| self.cx.now() >= deadline) {
            return Err(RemoteSymbolError::Deadline);
        }
        Ok(())
    }

    pub(super) async fn with_owner_deadline<T>(
        &self, future: impl Future<Output = Result<T, RemoteSymbolError>>,
    ) -> Result<T, RemoteSymbolError> {
        let operation = async {
            self.check_chunk_context()?;
            let result = if let Some(deadline) = self.cx.budget().deadline {
                if self.cx.timer_driver().is_none() { return Err(RemoteSymbolError::Configuration); }
                crate::time::timeout_at(deadline, future).await.map_err(|_| RemoteSymbolError::Deadline)?
            } else { future.await };
            self.check_chunk_context()?;
            result
        };
        let mut operation = std::pin::pin!(operation);
        poll_fn(|task| {
            // Sleep and the existing client's per-RPC timeout obtain their clock
            // from the ambient context. Bind the complete poll to this transport's
            // owner even when a different task/context polls the borrowed future.
            // The guard is destroyed before Pending crosses an await boundary.
            let _owner = Cx::set_current(Some(self.cx.clone()));
            operation.as_mut().poll(task)
        }).await
    }

    pub(super) async fn send_chunked(
        &self, replica: &str, symbols: Vec<AuthenticatedSymbol>, maximum: usize,
    ) -> Result<ReplicaAck, RemoteSymbolError> {
        self.send_chunked_attempt(replica, symbols, maximum, None).await
    }

    async fn send_chunked_attempt(
        &self, replica: &str, symbols: Vec<AuthenticatedSymbol>, maximum: usize, attempt: Option<u64>,
    ) -> Result<ReplicaAck, RemoteSymbolError> {
        self.check_chunk_context()?;
        let batch = encode_symbol_batch(&symbols, self.limits)?;
        drop(symbols);
        self.check_chunk_context()?;
        let upload = Upload { key: batch.key(), attempt: attempt.unwrap_or_else(|| RemoteTaskId::next().raw()),
            total: batch.as_ref().len(), count: batch.symbol_count() };
        let response = self.call_named(replica, SYMBOL_CHUNKED_SERVICE_COMPUTATION,
            request(BEGIN, replica, &upload_body(upload))?).await?;
        let (mut offset, accepted) = read_progress(&response, upload)?;
        drop(response);
        let chunk = maximum.min(accepted);
        while offset < upload.total {
            self.check_chunk_context()?;
            let end = offset + chunk.min(upload.total - offset);
            let mut body = Zeroizing::new(upload_body(upload));
            body.try_reserve_exact(8 + end - offset).map_err(|_| SymbolStoreError::Allocation)?;
            body.extend_from_slice(&(offset as u64).to_le_bytes());
            body.extend_from_slice(&batch.as_ref()[offset..end]);
            let input = request(CHUNK, replica, &body)?;
            drop(body);
            let response = self.call_named(replica, SYMBOL_CHUNKED_SERVICE_COMPUTATION, input).await?;
            let (received, limit) = read_progress(&response, upload)?;
            if received != end || limit != accepted { return Err(SymbolStoreError::Identity.into()); }
            offset = received;
        }
        self.check_chunk_context()?;
        let response = self.call_named(replica, SYMBOL_CHUNKED_SERVICE_COMPUTATION,
            request(COMMIT, replica, &upload_body(upload))?).await?;
        if response.get(..8) != Some(upload.attempt.to_le_bytes().as_slice()) {
            return Err(SymbolStoreError::Identity.into());
        }
        Ok(validate_receipt(&response[8..], replica, upload.key, upload.count)?)
    }

    pub(super) async fn fetch_chunked(
        &self, replica: &str, key: SymbolBatchKey, maximum: usize,
    ) -> Result<Vec<AuthenticatedSymbol>, RemoteSymbolError> {
        let mut bytes = Zeroizing::new(Vec::new());
        let mut expected = None;
        loop {
            self.check_chunk_context()?;
            let response = self.call_named(replica, SYMBOL_CHUNKED_SERVICE_COMPUTATION,
                range_request(replica, key, bytes.len(), maximum)?).await?;
            let (total, count, chunk) = read_range(&response, key, bytes.len(), maximum)?;
            if total > self.limits.max_encoded_bytes || count as usize > self.limits.max_symbols {
                return Err(SymbolStoreError::Limit("fetched bytes or symbols").into());
            }
            if let Some(metadata) = expected {
                if metadata != (total, count) { return Err(SymbolStoreError::Identity.into()); }
            } else {
                bytes.try_reserve_exact(total).map_err(|_| SymbolStoreError::Allocation)?;
                expected = Some((total, count));
            }
            bytes.extend_from_slice(chunk);
            if bytes.len() == total { break; }
        }
        self.check_chunk_context()?;
        if super::super::batch::key(key.object_id, &bytes) != key { return Err(SymbolStoreError::Identity.into()); }
        let symbols = decode_symbol_batch(&bytes, &self.auth_key, self.limits)?;
        if symbols[0].symbol().id().object_id() != key.object_id
            || expected != Some((bytes.len(), symbols.len() as u32))
        { return Err(SymbolStoreError::Identity.into()); }
        self.check_chunk_context()?;
        Ok(symbols)
    }
}

struct CountWriter(usize);
impl Write for CountWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self.0.checked_add(bytes.len()).ok_or_else(|| io::Error::other("frame size overflow"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

fn encoded_size(value: &impl serde::Serialize) -> Result<usize, RemoteSymbolError> {
    let mut writer = CountWriter(0);
    serde_json::to_writer(&mut writer, value).map_err(|_| RemoteSymbolError::Configuration)?;
    Ok(writer.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::distributed::ComputationSchemaRegistry;
    use crate::remote::{NodeId, RemoteProtocolVersion};
    use crate::time::{TimerDriver, TimerDriverHandle, VirtualClock};
    use crate::types::{Budget, RegionId, TaskId, Time};
    use crate::util::ArenaIndex;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::{Context, Poll, Wake, Waker};

    fn transport(cx: Cx) -> RemoteSymbolTransport {
        RemoteSymbolTransport {
            cx, hello: RemotePeerHello::new(NodeId::new("origin"), RemoteProtocolVersion::V1,
                ComputationSchemaRegistry::new().fingerprint()),
            routes: Arc::new(BTreeMap::new()), auth_key: Arc::new(AuthKey::from_seed(42)),
            limits: SymbolBatchLimits { max_encoded_bytes: 4096, max_symbols: 16, max_payload_bytes: 2048, max_decoded_bytes: 8192 },
            admission: Arc::new(super::super::admission::Admission::new(1)), chunk_bytes: Some(128),
        }
    }

    fn timed_cx(id: u32, budget: Budget, timer: TimerDriverHandle) -> Cx {
        Cx::new_with_drivers(RegionId::from_arena(ArenaIndex::new(id, 0)),
            TaskId::from_arena(ArenaIndex::new(id, 0)), budget, None, None, None, Some(timer), None)
    }

    #[derive(Default)]
    struct WakeCount(AtomicUsize);
    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
    }


    #[test]
    fn explicit_attempt_refuses_whole_batch_transport_before_route_or_admission() {
        let mut transport = transport(Cx::for_testing());
        transport.chunk_bytes = None;
        let mut sending = Box::pin(transport.send_symbols_with_attempt("missing", Vec::new(), 17));
        let result = sending.as_mut().poll(&mut Context::from_waker(Waker::noop()));
        assert!(matches!(result, Poll::Ready(Err(RemoteSymbolError::Configuration))));
        assert_eq!(transport.in_flight(), 0);
    }

    #[test]
    fn whole_transfer_timer_and_inner_polls_use_owner_despite_foreign_ambient_clock() {
        let clock = Arc::new(VirtualClock::new());
        let driver = Arc::new(TimerDriver::with_clock(Arc::clone(&clock)));
        let owner = timed_cx(1, Budget::INFINITE.with_deadline(Time::from_nanos(100)),
            TimerDriverHandle::new(Arc::clone(&driver)));
        let foreign_clock = Arc::new(VirtualClock::new());
        foreign_clock.advance(1000);
        let foreign = timed_cx(2, Budget::INFINITE, TimerDriverHandle::with_virtual_clock(foreign_clock));
        let transport = transport(owner.clone());
        let polls = AtomicUsize::new(0);
        let inner = poll_fn(|_| {
            assert_eq!(Cx::current().unwrap().task_id(), owner.task_id());
            polls.fetch_add(1, Ordering::SeqCst);
            Poll::Pending::<Result<(), RemoteSymbolError>>
        });
        let wake = Arc::new(WakeCount::default());
        let waker = Waker::from(Arc::clone(&wake));
        let mut task = Context::from_waker(&waker);
        let mut operation = Box::pin(transport.with_owner_deadline(inner));
        let _foreign = Cx::set_current(Some(foreign.clone()));
        assert!(operation.as_mut().poll(&mut task).is_pending(), "foreign clock must not expire the owner");
        assert_eq!(Cx::current().unwrap().task_id(), foreign.task_id());
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        clock.advance(100);
        driver.process_timers();
        assert!(wake.0.load(Ordering::SeqCst) > 0, "owner timer must wake the parked operation");
        assert!(matches!(operation.as_mut().poll(&mut task), Poll::Ready(Err(RemoteSymbolError::Deadline))));
        assert_eq!(Cx::current().unwrap().task_id(), foreign.task_id());
    }

    #[test]
    fn declared_owner_deadline_without_owner_timer_refuses_before_inner_dispatch() {
        let owner = Cx::for_testing_with_budget(Budget::INFINITE.with_deadline(Time::from_nanos(u64::MAX)));
        let transport = transport(owner);
        let dispatched = AtomicBool::new(false);
        let mut operation = Box::pin(transport.with_owner_deadline(async {
            dispatched.store(true, Ordering::SeqCst);
            Ok(())
        }));
        assert!(matches!(operation.as_mut().poll(&mut Context::from_waker(Waker::noop())), Poll::Ready(Err(RemoteSymbolError::Configuration))));
        assert!(!dispatched.load(Ordering::SeqCst));
    }
}
