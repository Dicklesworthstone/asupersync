//! Authenticated, single-owner ingress and application execution.

mod reorder;
mod retry;

use super::{
    AuthenticatedPbftTransport, LimitedPayload, PbftAuthError, PbftAuthenticator,
    PbftPacketTransport, protocol_error,
};
use crate::cx::Cx;
use crate::distributed::consensus::pbft::{
    PbftConfig, PbftExecution, PbftMessage, PbftStateMachine, PbftTransport,
};
use crate::distributed::consensus::types::{
    ConsensusBatch, ConsensusRequest, ConsensusResponse, MessageDigest, ReplicaId,
    SequenceNumber, ViewNumber,
};
use crate::error::{Error, ErrorKind, Result};
use crate::types::Time;
use parking_lot::Mutex as InboxMutex;
use reorder::ReorderBuffer;
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

/// Result of one bounded ingress attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PbftIngressOutcome {
    /// An authenticated message was processed or retained in the opt-in inbox.
    /// This does not by itself mean a quorum or application result exists.
    Processed,
    /// The authenticated protocol packet refers to an already applied prefix.
    /// It was retired without mutating state or reapplying an operation.
    AlreadyApplied(SequenceNumber),
    /// A packet was refused before changing consensus/application state.
    Rejected(PbftAuthError),
    /// An opt-in inbox refused a sequence outside its 64-sequence live window.
    OutsideWindow(SequenceNumber),
    /// An authenticated author proposed/voted for two digests in the same slot.
    /// The first retained digest is preserved; the conflicting one is refused.
    Equivocation(SequenceNumber),
    /// Bounded inbox, proposal-window, or forwarding capacity is full.
    /// Retry after progress; no additional request was admitted.
    BufferFull,
}

struct SharedPackets<T>(Arc<T>);

impl<T> Clone for SharedPackets<T> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<T: PbftPacketTransport> PbftPacketTransport for SharedPackets<T> {
    async fn send_packet(&self, recipient: &ReplicaId, packet: Vec<u8>) -> Result<()> {
        self.0.send_packet(recipient, packet).await
    }

    async fn broadcast_packet(&self, packet: Vec<u8>) -> Result<()> {
        self.0.broadcast_packet(packet).await
    }

    async fn receive_packet(&self, max_packet_bytes: usize) -> Result<Vec<u8>> {
        self.0.receive_packet(max_packet_bytes).await
    }
}

// The legacy engine counts a local prepare on every replica, including the
// primary. Publish that primary vote to peers as well. Otherwise three live
// nodes in a four-node group cannot prepare when the fourth backup is silent:
// each backup sees only its own vote and the other live backup's vote.
// This is a normal-case driver step, not a change to legacy transport behavior.
struct PrimaryVotingTransport<T>(
    AuthenticatedPbftTransport<SharedPackets<T>>,
    Option<Arc<InboxMutex<ReorderBuffer>>>,
    Option<Arc<InboxMutex<retry::Outbox>>>,
);

impl<T: PbftPacketTransport> PbftTransport for PrimaryVotingTransport<T> {
    async fn send_to_replica(&self, recipient: &ReplicaId, message: PbftMessage) -> Result<()> {
        if let Some(cache) = &self.2 {
            let frame = retry::Frame::signed(&self.0.auth, Some(recipient), &message)?;
            let frames = cache.lock().remember(vec![frame])?;
            self.0.packets.send_packet(recipient, frames[0].bytes.clone()).await
        } else {
            self.0.send_to_replica(recipient, message).await
        }
    }

    async fn broadcast(&self, message: PbftMessage) -> Result<()> {
        if let Some(inbox) = &self.1 {
            // The engine has installed the entry before emitting a proposal or
            // prepare. Publish that fact before a send can yield or be dropped.
            inbox.lock().observe_outbound(&message).map_err(inbox_error)?;
        }
        let prepare = match &message {
            PbftMessage::PrePrepare { view, sequence, digest, replica_id, .. } => {
                Some(PbftMessage::Prepare {
                    view: *view,
                    sequence: *sequence,
                    digest: digest.clone(),
                    replica_id: replica_id.clone(),
                })
            }
            _ => None,
        };
        if let Some(cache) = &self.2 {
            let mut frames = vec![retry::Frame::signed(&self.0.auth, None, &message)?];
            if let Some(prepare) = &prepare {
                frames.push(retry::Frame::signed(&self.0.auth, None, prepare)?);
            }
            // Reserve the proposal AND its prepare before any send can yield.
            // A retry uses these exact signatures, not a newly assigned slot.
            let frames = cache.lock().remember(frames)?;
            for frame in frames {
                self.0.packets.broadcast_packet(frame.bytes.clone()).await?;
            }
            return Ok(());
        }
        self.0.broadcast(message).await?;
        if let Some(prepare) = prepare {
            self.0.broadcast(prepare).await?;
        }
        Ok(())
    }

    async fn receive(&self) -> Result<PbftMessage> {
        self.0.receive().await
    }
}

fn inbox_error(outcome: PbftIngressOutcome) -> Error {
    Error::new(ErrorKind::InvalidStateTransition)
        .with_message(format!("PBFT bounded inbox refused admission: {outcome:?}"))
}

/// A single-owner PBFT application node with no unsigned remote-ingress API.
///
/// Construction binds the protocol's replica count/id to the pinned keys.
/// Remote packets can enter only through signature verification. Local
/// submissions are a trusted application boundary, not client authentication.
/// All driving methods take `&mut self`, preventing competing receive loops or
/// a response waiter that is stranded by a second consumer of the same stream.
/// No task, socket, timer service, or key is created by construction.
///
/// Cancellation is an explicit request to stop this controller, including
/// while the context is masked; it is observed without acknowledging the task's
/// cancellation protocol. The currently borrowed I/O future is dropped before
/// returning. Partial sends, consumed datagrams, admitted proposals, committed
/// effects, and synchronous application callbacks are NOT rolled back. The
/// packet transport must preserve/retire its own partial framing on drop.
///
/// The normal-case driver publishes the primary's prepare vote. The additive
/// [`Self::new_with_reordering`] constructor retains early votes in a bounded
/// inbox. [`Self::new_with_recovery`] additionally retains signed packets for
/// paced retransmission. [`Self::new`] preserves original direct admission.
/// None adds view changes, stable checkpoints, durable recovery, bounded
/// committed-log retention, or a proof of Byzantine safety/liveness. Packet,
/// inbox, and retry-cache bounds are not total log bounds.
pub struct AuthenticatedPbftNode<T: PbftPacketTransport, S: PbftStateMachine> {
    driver: PbftExecution<PrimaryVotingTransport<T>, S>,
    packets: SharedPackets<T>,
    auth: Arc<PbftAuthenticator>,
    max_batch_size: usize,
    reorder: Option<Arc<InboxMutex<ReorderBuffer>>>,
    outbox: Option<Arc<InboxMutex<retry::Outbox>>>,
}

impl<T: PbftPacketTransport, S: PbftStateMachine> AuthenticatedPbftNode<T, S> {
    /// Bind one application to one authenticated membership and transport.
    ///
    /// The existing execution driver additionally requires exactly `3f + 1`
    /// replicas and a nonzero maximum batch size. Every replica must use
    /// compatible packet and batch limits; differing bounds can harm liveness.
    pub fn new(
        config: PbftConfig,
        packets: T,
        auth: Arc<PbftAuthenticator>,
        machine: S,
    ) -> Result<Self> {
        Self::build(config, packets, auth, machine, None, None)
    }

    /// Enable bounded, cancellation-resilient normal-case vote reordering.
    ///
    /// Retains at most 8192 distinct votes over the next 64 sequences. Each
    /// authenticated replica gets at most one vote per phase and sequence;
    /// duplicates do not consume additional capacity. Only votes matching an
    /// installed proposal reach the engine. Completion retires inbox state.
    /// The new admission bounds are opt-in and do not change `new` callers.
    ///
    /// The current protocol supports view zero only. Out-of-window traffic and
    /// inbox pressure are explicit refusals, not unbounded buffering. A primary
    /// refuses new requests before reserving a 65th outstanding sequence, while
    /// exact retries remain permitted. Committed logs/results remain retained
    /// by the legacy execution driver; this is not durable recovery or pruning.
    pub fn new_with_reordering(
        config: PbftConfig,
        packets: T,
        auth: Arc<PbftAuthenticator>,
        machine: S,
    ) -> Result<Self> {
        Self::build(config, packets, auth, machine, Some(Arc::new(InboxMutex::new(ReorderBuffer::default()))), None)
    }

    fn build(
        config: PbftConfig,
        packets: T,
        auth: Arc<PbftAuthenticator>,
        machine: S,
        reorder: Option<Arc<InboxMutex<ReorderBuffer>>>,
        outbox: Option<Arc<InboxMutex<retry::Outbox>>>,
    ) -> Result<Self> {
        if config.replica_count != auth.membership().replica_count() {
            return Err(protocol_error(PbftAuthError::Configuration));
        }
        let max_batch_size = config.max_batch_size;
        let packets = SharedPackets(Arc::new(packets));
        let transport = PrimaryVotingTransport(
            AuthenticatedPbftTransport::new(packets.clone(), Arc::clone(&auth)),
            reorder.clone(),
            outbox.clone(),
        );
        let driver = PbftExecution::new(
            auth.local_replica().clone(), config, transport, machine,
        )?;
        Ok(Self { driver, packets, auth, max_batch_size, reorder, outbox })
    }

    /// Highest contiguous sequence applied to the application, not just admitted.
    pub fn last_applied(&self) -> Result<SequenceNumber> {
        self.driver.last_applied()
    }

    /// Actual retained response for this exact request; never a fabricated success.
    pub fn committed_response(&self, request: &ConsensusRequest) -> Result<Option<ConsensusResponse>> {
        self.driver.committed_response(request)
    }

    /// Admit/forward a local request without claiming consensus completion.
    ///
    /// Conservatively reserve wire space for worst-width proposal metadata
    /// before admitting a sequence. This avoids permanently reserving a log
    /// slot for a request whose proposal cannot fit the packet bound. A request
    /// very close to the limit may be refused even if today's encoding fits.
    pub async fn submit_request(&mut self, cx: &Cx, request: ConsensusRequest) -> Result<()> {
        until_stopped(cx, async {
            self.prepare_submission(&request)?;
            self.driver.submit_request(cx, request).await?;
            self.drain_reordered(cx).await?;
            Ok(())
        }).await
    }

    /// Verify and process one externally supplied packet, without unsigned bypass.
    ///
    /// Rejections happen before the protocol engine is invoked. Authenticated
    /// packets below the applied watermark are retired without reopening the
    /// log, so delayed duplicate proposals cannot terminate a healthy pump.
    /// Application or protocol errors after admission are returned as `Err`.
    pub async fn process_packet(&mut self, cx: &Cx, packet: &[u8]) -> Result<PbftIngressOutcome> {
        until_stopped(cx, self.admit_packet(cx, packet)).await
    }

    /// Receive, authenticate, and process one packet in the calling task.
    ///
    /// A parked receive is woken by `Cx` cancellation even when no peer sends
    /// another packet. Dropping this future also drops its receive operation
    /// and its owned cancellation registration; it leaves no detached pump.
    /// In reordering mode, a previously interrupted ready delivery is resumed
    /// first and can return `Processed` without requiring a new network packet.
    pub async fn receive_one(&mut self, cx: &Cx) -> Result<PbftIngressOutcome> {
        until_stopped(cx, async {
            if self.drain_reordered(cx).await? {
                return Ok(PbftIngressOutcome::Processed);
            }
            let packet = self.packets.receive_packet(self.auth.max_packet_bytes()).await?;
            self.admit_packet(cx, &packet).await
        }).await
    }

    /// Run the authenticated pump until cancellation or an admitted/I/O error.
    ///
    /// Unauthenticated packets are discarded without stopping the node. For
    /// per-rejection diagnostics, drive `receive_one` explicitly instead. A
    /// scheduler yield after each packet prevents a ready invalid-packet stream
    /// from monopolizing the worker.
    pub async fn run(&mut self, cx: &Cx) -> Result<()> {
        loop {
            self.receive_one(cx).await?;
            crate::runtime::yield_now().await;
        }
    }

    /// Submit a request and drive ingress until its actual application result exists.
    ///
    /// This method owns the pump for the duration of the borrow. Unrelated
    /// requests continue to be processed. It can wait indefinitely without a
    /// quorum; use `submit_with_timeout` for a bounded whole-call wait. Exact
    /// retries recover retained results/proposals without applying twice.
    pub async fn submit_and_wait(&mut self, cx: &Cx, request: ConsensusRequest) -> Result<ConsensusResponse> {
        // Check cancellation and the size budget before retaining a second
        // copy for receipt lookup. Neither an oversized request nor a stopped
        // caller should cause an unbounded clone before admission.
        until_stopped(cx, async {
            self.prepare_submission(&request)?;
            self.driver.submit_request(cx, request.clone()).await?;
            self.drain_reordered(cx).await?;
            Ok(())
        }).await?;
        loop {
            if let Some(response) = self.committed_response(&request)? {
                return Ok(response);
            }
            self.receive_one(cx).await?;
            crate::runtime::yield_now().await;
        }
    }

    /// Bound admission, forwarding, quorum waiting, and result retrieval by one timeout.
    ///
    /// Expiry does not establish nondelivery and does not undo committed effects.
    /// Zero duration refuses before any transport method is invoked.
    pub async fn submit_with_timeout(
        &mut self,
        cx: &Cx,
        request: ConsensusRequest,
        duration: Duration,
    ) -> Result<ConsensusResponse> {
        if duration.is_zero() {
            return Err(Error::new(ErrorKind::DeadlineExceeded));
        }
        crate::time::timeout(cx.now(), duration, self.submit_and_wait(cx, request))
            .await
            .map_err(|_| Error::new(ErrorKind::DeadlineExceeded))?
    }

    async fn admit_packet(&self, cx: &Cx, packet: &[u8]) -> Result<PbftIngressOutcome> {
        let message = match self.auth.open(packet) {
            Ok(message) => message,
            Err(error) => return Ok(PbftIngressOutcome::Rejected(error)),
        };
        match &message {
            PbftMessage::Request(request) => {
                if let Err(error) = self.preflight_request(request) {
                    return Ok(PbftIngressOutcome::Rejected(error));
                }
            }
            PbftMessage::PrePrepare { batch, .. }
                if batch.is_empty() || batch.len() > self.max_batch_size =>
            {
                return Ok(PbftIngressOutcome::Rejected(PbftAuthError::Configuration));
            }
            _ => {}
        }
        let sequence = match &message {
            PbftMessage::PrePrepare { sequence, .. }
            | PbftMessage::Prepare { sequence, .. }
            | PbftMessage::Commit { sequence, .. } => Some(*sequence),
            _ => None,
        };
        let applied = self.driver.last_applied()?;
        self.sync_outbox()?;
        if let Some(sequence) = sequence
            && sequence <= applied
        {
            return Ok(PbftIngressOutcome::AlreadyApplied(sequence));
        }
        if let Some(inbox) = &self.reorder {
            inbox.lock().prune(applied);
            match &message {
                PbftMessage::PrePrepare { view, sequence, digest, batch, .. } => {
                    if MessageDigest::of(batch)? != *digest {
                        return Ok(PbftIngressOutcome::Rejected(PbftAuthError::Encoding));
                    }
                    let result = inbox.lock().proposal(*view, *sequence, digest, false, None);
                    if let Err(outcome) = result { return Ok(outcome); }
                }
                PbftMessage::Prepare { .. } | PbftMessage::Commit { .. } => {
                    let result = inbox.lock().vote(&message);
                    if let Err(outcome) = result { return Ok(outcome); }
                    self.drain_reordered(cx).await?;
                    return Ok(PbftIngressOutcome::Processed);
                }
                PbftMessage::Request(request) if !self.has_submission_credit(request)? => {
                    return Ok(PbftIngressOutcome::BufferFull);
                }
                _ => {}
            }
        }
        self.driver.process_message(cx, message).await?;
        self.drain_reordered(cx).await?;
        Ok(PbftIngressOutcome::Processed)
    }

    async fn drain_reordered(&self, cx: &Cx) -> Result<bool> {
        let Some(inbox) = &self.reorder else { return Ok(false) };
        let mut delivered = 0_usize;
        loop {
            self.sync_outbox()?;
            let applied = self.driver.last_applied()?;
            let next = {
                let mut inbox = inbox.lock();
                inbox.prune(applied);
                inbox.next()
            };
            let Some(next) = next else { return Ok(delivered != 0) };
            self.driver.process_message(cx, next.message()).await?;
            inbox.lock().acknowledge(&next);
            delivered += 1;
            if delivered % 64 == 0 { crate::runtime::yield_now().await; }
        }
    }

    fn has_submission_credit(&self, request: &ConsensusRequest) -> Result<bool> {
        if self.reorder.is_none() && self.outbox.is_none() {
            return Ok(true);
        }
        if self.driver.committed_response(request)?.is_some() {
            return Ok(true);
        }
        let digest = MessageDigest::of(request)?;
        if self.auth.local_replica().as_str() == "0" {
            if let Some(inbox) = &self.reorder {
                let applied = self.driver.last_applied()?;
                let mut inbox = inbox.lock();
                inbox.prune(applied);
                return Ok(inbox.can_propose(&digest));
            }
        } else if let Some(cache) = &self.outbox {
            return Ok(cache.lock().can_forward(&digest));
        }
        Ok(true)
    }

    fn prepare_submission(&self, request: &ConsensusRequest) -> Result<()> {
        self.preflight_request(request).map_err(protocol_error)?;
        self.sync_outbox()?;
        if !self.has_submission_credit(request)? {
            return Err(inbox_error(PbftIngressOutcome::BufferFull));
        }
        Ok(())
    }

    fn preflight_request(&self, request: &ConsensusRequest) -> std::result::Result<(), PbftAuthError> {
        let limit = self.auth.max_payload_bytes;
        if request.operation.len().checked_add(request.client_id.len())
            .is_none_or(|length| length > limit)
        {
            return Err(PbftAuthError::PayloadTooLarge);
        }
        // Check before cloning; then use bounded serialization just as the
        // actual authenticator does. The maximum decimal field widths cover
        // any subsequently assigned view/sequence/time/digest/replica id.
        let mut batch = ConsensusBatch::new(vec![request.clone()]);
        batch.timestamp = Time::from_nanos(u64::MAX);
        let proposal = PbftMessage::PrePrepare {
            view: ViewNumber::new(u64::MAX),
            sequence: SequenceNumber::new(u64::MAX),
            digest: MessageDigest::from_bytes([255; 32]),
            batch,
            replica_id: ReplicaId::new((self.auth.membership().replica_count() - 1).to_string()),
        };
        let mut sink = LimitedPayload { bytes: Vec::new(), limit };
        serde_json::to_writer(&mut sink, &proposal).map_err(|_| PbftAuthError::PayloadTooLarge)
    }
}

async fn until_stopped<T>(cx: &Cx, operation: impl Future<Output = Result<T>>) -> Result<T> {
    let mut cancelled = pin!(cx.cancelled());
    let mut operation = pin!(operation);
    poll_fn(|task| {
        if cancelled.as_mut().poll(task).is_ready() {
            let error = cx.cancel_reason().as_ref().map_or_else(
                || Error::new(ErrorKind::Cancelled),
                Error::cancelled,
            );
            return Poll::Ready(Err(error));
        }
        // A ready operation wins over a cancellation published during that
        // poll: its synchronous application effects may already have occurred.
        operation.as_mut().poll(task)
    }).await
}

#[cfg(test)]
#[path = "driver_inline_tests.rs"]
mod tests;
