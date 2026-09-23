//! Bounded retransmission of original signed packets, in the node's own task.

use super::{
    Arc, AuthenticatedPbftNode, ConsensusRequest, ConsensusResponse, Cx, Duration, Error,
    ErrorKind, InboxMutex, MessageDigest, PbftAuthError, PbftAuthenticator, PbftConfig,
    PbftIngressOutcome, PbftMessage, PbftPacketTransport, PbftStateMachine, ReorderBuffer,
    ReplicaId, Result, SequenceNumber, Time, inbox_error, protocol_error, reorder, until_stopped,
};
use std::collections::BTreeMap;
use std::ops::Bound::{Excluded, Unbounded};

const MAX_PACKET: usize = 65_507;
const MAX_FORWARDS: usize = 64;
const RETAIN_COMPLETED: u64 = 64;
const MAX_FRAMES: usize = 448; // 128 sequences * 3 phases + 64 forwards

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    Forward([u8; 32]),
    Protocol(u64, u8),
}

pub(super) struct Frame {
    key: Key,
    pub(super) bytes: Vec<u8>,
    pub(super) recipient: Option<ReplicaId>,
    request: Option<Arc<ConsensusRequest>>,
}

impl Frame {
    pub(super) fn signed(
        auth: &PbftAuthenticator,
        recipient: Option<&ReplicaId>,
        message: &PbftMessage,
    ) -> Result<Self> {
        let bytes = auth.seal(recipient, message).map_err(protocol_error)?;
        if bytes.len() > MAX_PACKET {
            return Err(protocol_error(PbftAuthError::PayloadTooLarge));
        }
        let (key, request) = match message {
            PbftMessage::Request(request) => (
                Key::Forward(*MessageDigest::of(request)?.as_bytes()),
                Some(Arc::new(request.clone())),
            ),
            PbftMessage::PrePrepare { view, sequence, .. }
            | PbftMessage::Prepare { view, sequence, .. }
            | PbftMessage::Commit { view, sequence, .. } => {
                if view.0 != 0 {
                    return Err(protocol_error(PbftAuthError::UnsupportedPhase));
                }
                let phase = match message {
                    PbftMessage::PrePrepare { .. } => 0,
                    PbftMessage::Prepare { .. } => 1,
                    _ => 2,
                };
                (Key::Protocol(sequence.0, phase), None)
            }
            _ => return Err(protocol_error(PbftAuthError::UnsupportedPhase)),
        };
        Ok(Self { key, bytes, recipient: recipient.cloned(), request })
    }
}

#[derive(Default)]
pub(super) struct Outbox {
    applied: u64,
    cursor: Option<Key>,
    frames: BTreeMap<Key, Arc<Frame>>,
}

impl Outbox {
    pub(super) fn can_forward(&self, request: &MessageDigest) -> bool {
        self.frames.contains_key(&Key::Forward(*request.as_bytes()))
            || self.frames.keys().filter(|key| matches!(key, Key::Forward(_))).count() < MAX_FORWARDS
    }

    /// Admit an entire outgoing group before the first send can yield. In
    /// particular, cancelling a primary proposal send cannot lose its prepare.
    pub(super) fn remember(&mut self, frames: Vec<Frame>) -> Result<Vec<Arc<Frame>>> {
        let mut new_forwards = 0;
        for (index, frame) in frames.iter().enumerate() {
            if frame.bytes.len() > MAX_PACKET {
                return Err(protocol_error(PbftAuthError::PayloadTooLarge));
            }
            if let Key::Protocol(sequence, phase) = frame.key {
                if sequence <= self.applied.saturating_sub(RETAIN_COMPLETED)
                    || sequence > self.applied.saturating_add(reorder::WINDOW)
                    || sequence == u64::MAX || phase > 2
                {
                    return Err(inbox_error(PbftIngressOutcome::OutsideWindow(SequenceNumber(sequence))));
                }
            }
            let previous = self.frames.get(&frame.key).map(Arc::as_ref)
                .or_else(|| frames[..index].iter().find(|old| old.key == frame.key));
            if let Some(old) = previous {
                if old.bytes != frame.bytes || old.recipient != frame.recipient {
                    return Err(Error::new(ErrorKind::InvalidStateTransition)
                        .with_message("PBFT retry slot cannot change its signed transcript"));
                }
            } else if matches!(frame.key, Key::Forward(_)) {
                new_forwards += 1;
            }
        }
        let forwards = self.frames.keys().filter(|key| matches!(key, Key::Forward(_))).count();
        if forwards + new_forwards > MAX_FORWARDS {
            return Err(inbox_error(PbftIngressOutcome::BufferFull));
        }
        let mut retained = Vec::with_capacity(frames.len());
        for frame in frames {
            let entry = self.frames.entry(frame.key).or_insert_with(|| Arc::new(frame));
            retained.push(Arc::clone(entry));
        }
        Ok(retained)
    }

    fn next(&self) -> Option<Arc<Frame>> {
        self.cursor.as_ref()
            .and_then(|cursor| self.frames.range((Excluded(cursor), Unbounded)).next())
            .or_else(|| self.frames.first_key_value())
            .map(|(_, frame)| Arc::clone(frame))
    }

    fn prune(&mut self, applied: SequenceNumber) {
        self.applied = self.applied.max(applied.0);
        let floor = self.applied.saturating_sub(RETAIN_COMPLETED);
        self.frames.retain(|key, _| match key {
            Key::Protocol(sequence, _) => *sequence > floor,
            Key::Forward(_) => true,
        });
    }
}

fn next_deadline(now: Time, interval: Duration) -> Result<Time> {
    let nanos = u64::try_from(interval.as_nanos())
        .ok().and_then(|nanos| now.as_nanos().checked_add(nanos))
        .filter(|deadline| *deadline > now.as_nanos())
        .ok_or_else(|| Error::new(ErrorKind::DeadlineExceeded))?;
    Ok(Time::from_nanos(nanos))
}

impl<T: PbftPacketTransport, S: PbftStateMachine> AuthenticatedPbftNode<T, S> {
    /// Enable bounded reordering and retention of original signed retry packets.
    ///
    /// Requires an authentication packet bound at most 65,507 bytes. The cache
    /// retains the next 64 active sequences, the last 64 applied sequences, and
    /// at most 64 outstanding forwarded requests: at most 448 signed frames,
    /// plus bounded request descriptors. Existing constructors remain unchanged.
    /// No timer or background task is created; call `run_with_retries`,
    /// `submit_with_retries`, or explicitly drive `retry_pending`.
    ///
    /// Recently applied votes remain available to lagging peers. A peer more
    /// than 64 completed sequences behind needs state transfer, which this
    /// adapter does not implement. This is finite-window packet-loss recovery,
    /// not durable recovery, congestion control, view change, or BFT signoff.
    pub fn new_with_recovery(
        config: PbftConfig,
        packets: T,
        auth: Arc<PbftAuthenticator>,
        machine: S,
    ) -> Result<Self> {
        if auth.max_packet_bytes() > MAX_PACKET {
            return Err(protocol_error(PbftAuthError::Configuration));
        }
        Self::build(
            config, packets, auth, machine,
            Some(Arc::new(InboxMutex::new(ReorderBuffer::default()))),
            Some(Arc::new(InboxMutex::new(Outbox::default()))),
        )
    }

    pub(super) fn sync_outbox(&self) -> Result<()> {
        let Some(cache) = &self.outbox else { return Ok(()) };
        let applied = self.driver.last_applied()?;
        let pending = {
            let mut cache = cache.lock();
            cache.prune(applied);
            cache.frames.iter().filter_map(|(key, frame)| {
                frame.request.as_ref().map(|request| (*key, Arc::clone(request)))
            }).collect::<Vec<_>>()
        };
        // Never hold the outbox lock while consulting the application ledger.
        for (key, request) in pending {
            if self.driver.committed_response(&request)?.is_some() {
                cache.lock().frames.remove(&key);
            }
        }
        Ok(())
    }

    fn validate_retries(&self, interval: Duration, max_packets: usize) -> Result<()> {
        if self.outbox.is_none() || interval.is_zero() || !(1..=MAX_FRAMES).contains(&max_packets) {
            return Err(protocol_error(PbftAuthError::Configuration));
        }
        Ok(())
    }

    /// Retransmit up to `max_packets` retained frames, without re-signing them.
    ///
    /// The bound is `1..=448`. A rotating cursor prevents a small budget from
    /// starving later frames. Cursor advancement follows successful send return;
    /// cancellation/error leaves that packet available for the next attempt.
    /// No packet is sent twice in one sweep. A broadcast is one frame operation
    /// and can fan out to every configured peer. Partial delivery is ambiguous.
    /// The caller owns cadence and must continue driving ingress separately.
    pub async fn retry_pending(&mut self, cx: &Cx, max_packets: usize) -> Result<usize> {
        self.validate_retries(Duration::from_nanos(1), max_packets)?;
        until_stopped(cx, async {
            self.sync_outbox()?;
            let cache = self.outbox.as_ref().expect("retry configuration checked");
            let budget = max_packets.min(cache.lock().frames.len());
            let mut sent = 0;
            for _ in 0..budget {
                let frame = cache.lock().next();
                let Some(frame) = frame else { break };
                if let Some(recipient) = &frame.recipient {
                    self.packets.send_packet(recipient, frame.bytes.clone()).await?;
                } else {
                    self.packets.broadcast_packet(frame.bytes.clone()).await?;
                }
                cache.lock().cursor = Some(frame.key);
                sent += 1;
                // Bound ready work, even for a transport completing inline.
                crate::runtime::yield_now().await;
            }
            Ok(sent)
        }).await
    }

    /// Drive ingress and paced retries in this caller-owned task until stopped.
    ///
    /// Each retry tick sends at most `max_packets` retained frames. Incoming
    /// traffic does not reset the absolute retry deadline, so a busy stream
    /// cannot starve repair. Ticks use delay semantics, not catch-up bursts.
    /// An idle receive is dropped before sending a retry, releasing transports
    /// with exclusive socket ownership. Protocol/application processing is not
    /// raced against the retry timer and is never interrupted just for a tick.
    /// Errors propagate with the cache intact. Cancellation leaves no detached
    /// receive or timer future. This adds no transport congestion controller.
    pub async fn run_with_retries(
        &mut self,
        cx: &Cx,
        interval: Duration,
        max_packets: usize,
    ) -> Result<()> {
        self.validate_retries(interval, max_packets)?;
        until_stopped(cx, async {
            let mut deadline = next_deadline(cx.now(), interval)?;
            loop {
                self.retry_step(cx, &mut deadline, interval, max_packets).await?;
                crate::runtime::yield_now().await;
            }
        }).await
    }

    /// Submit and await the actual application response with paced packet repair.
    ///
    /// One `duration` bounds the whole asynchronous call, including admission,
    /// retries, and result waiting. Synchronous application callbacks cannot be
    /// preempted. Timeout/cancellation do not roll back admitted or committed
    /// work. An interrupted initial admission may still require an exact request
    /// retry; retained packets alone are not a durable request queue.
    pub async fn submit_with_retries(
        &mut self,
        cx: &Cx,
        request: ConsensusRequest,
        duration: Duration,
        interval: Duration,
        max_packets: usize,
    ) -> Result<ConsensusResponse> {
        self.validate_retries(interval, max_packets)?;
        if duration.is_zero() { return Err(Error::new(ErrorKind::DeadlineExceeded)); }
        let operation = until_stopped(cx, async {
            self.prepare_submission(&request)?;
            self.driver.submit_request(cx, request.clone()).await?;
            self.drain_reordered(cx).await?;
            let mut deadline = next_deadline(cx.now(), interval)?;
            loop {
                if let Some(response) = self.driver.committed_response(&request)? {
                    return Ok(response);
                }
                self.retry_step(cx, &mut deadline, interval, max_packets).await?;
                crate::runtime::yield_now().await;
            }
        });
        crate::time::timeout(cx.now(), duration, operation).await
            .map_err(|_| Error::new(ErrorKind::DeadlineExceeded))?
    }

    async fn retry_step(
        &mut self,
        cx: &Cx,
        deadline: &mut Time,
        interval: Duration,
        max_packets: usize,
    ) -> Result<()> {
        self.drain_reordered(cx).await?;
        self.sync_outbox()?;
        let now = cx.now();
        if now < *deadline {
            let remaining = Duration::from_nanos(deadline.as_nanos() - now.as_nanos());
            // Only race IDLE reception. This block retires the borrowed receive
            // future before retry_pending can acquire the same socket for sends.
            let received = crate::time::timeout(
                now, remaining, self.packets.receive_packet(self.auth.max_packet_bytes()),
            ).await;
            if let Ok(packet) = received {
                let packet = packet?;
                self.admit_packet(cx, &packet).await?;
                return Ok(());
            }
        }
        self.retry_pending(cx, max_packets).await?;
        *deadline = next_deadline(cx.now(), interval)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::distributed::consensus::authenticated::PbftMembership;
    use crate::types::{CancelKind, Outcome};
    use nkeys::{KeyPair, KeyPairType};
    use sha2::{Digest, Sha256};
    use std::collections::VecDeque;
    use std::future::poll_fn;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::{Context, Poll, Waker};

    fn auth(local: u8) -> Arc<PbftAuthenticator> {
        let key = |i: u8| {
            let seed: [u8; 32] = Sha256::digest([i; 32]).into();
            KeyPair::new_from_raw(KeyPairType::User, seed).unwrap()
        };
        let keys: Vec<_> = (0..4).map(|i| key(i).public_key()).collect();
        Arc::new(PbftAuthenticator::new(
            PbftMembership::new([11; 32], 1, &keys).unwrap(),
            ReplicaId::new(local.to_string()), key(local), 4096,
        ).unwrap())
    }

    fn request() -> ConsensusRequest {
        ConsensusRequest::new("repair-client".into(), Time::from_millis(2), b"repair-effect".to_vec())
    }

    fn frame(sequence: u64, phase: u8) -> Frame {
        Frame {
            key: Key::Protocol(sequence, phase), bytes: vec![phase],
            recipient: None, request: None,
        }
    }

    #[test]
    fn retry_groups_are_atomic_and_cannot_change_an_existing_transcript() {
        let mut cache = Outbox::default();
        cache.remember(vec![frame(1, 0), frame(1, 1)]).unwrap();
        assert_eq!(cache.frames.len(), 2);
        let mut conflict = frame(1, 1);
        conflict.bytes.push(9);
        assert!(cache.remember(vec![frame(2, 0), conflict]).is_err());
        assert_eq!(cache.frames.len(), 2, "no partial group admission");
        cache.remember(vec![frame(1, 0), frame(1, 1)]).unwrap();
        assert_eq!(cache.frames.len(), 2, "deduplicate exact retransmissions");
    }

    #[test]
    fn cursor_is_fair_and_completed_tail_is_retained_then_bounded() {
        let mut cache = Outbox::default();
        cache.remember(vec![frame(1, 0), frame(1, 1), frame(1, 2)]).unwrap();
        let mut phases = Vec::new();
        for _ in 0..7 {
            let next = cache.next().unwrap();
            phases.push(next.bytes[0]);
            cache.cursor = Some(next.key);
        }
        assert_eq!(phases, vec![0, 1, 2, 0, 1, 2, 0]);
        cache.prune(SequenceNumber(64));
        assert_eq!(cache.frames.len(), 3, "assist peers behind the local commit");
        cache.prune(SequenceNumber(65));
        assert!(cache.frames.is_empty());
        for sequence in 2..=129 {
            cache.remember((0..3).map(|phase| frame(sequence, phase)).collect()).unwrap();
        }
        assert_eq!(cache.frames.len(), 384);
        assert!(cache.remember(vec![frame(130, 0)]).is_err());
        assert_eq!(cache.frames.len(), 384);
        for tag in 0..MAX_FORWARDS {
            cache.remember(vec![Frame {
                key: Key::Forward([u8::try_from(tag).unwrap(); 32]),
                bytes: vec![0], recipient: Some(ReplicaId::new("0".into())), request: None,
            }]).unwrap();
        }
        assert_eq!(cache.frames.len(), MAX_FRAMES);
        assert!(cache.can_forward(&MessageDigest::from_bytes([0; 32])));
        assert!(!cache.can_forward(&MessageDigest::from_bytes([255; 32])));
        assert!(cache.remember(vec![Frame {
            key: Key::Forward([255; 32]), bytes: vec![0], recipient: None, request: None,
        }]).is_err());
    }

    #[derive(Default)]
    struct Wire {
        blocked: AtomicBool,
        sent: InboxMutex<Vec<Vec<u8>>>,
    }

    impl PbftPacketTransport for Arc<Wire> {
        async fn send_packet(&self, _: &ReplicaId, packet: Vec<u8>) -> Result<()> {
            self.broadcast_packet(packet).await
        }
        async fn broadcast_packet(&self, packet: Vec<u8>) -> Result<()> {
            self.sent.lock().push(packet);
            if self.blocked.load(Ordering::SeqCst) { std::future::pending::<()>().await; }
            Ok(())
        }
        async fn receive_packet(&self, _: usize) -> Result<Vec<u8>> {
            std::future::pending().await
        }
    }

    #[test]
    fn cancelled_first_send_retains_primary_prepare_and_retries_identical_bytes() {
        let cx = Cx::for_testing();
        let wire = Arc::new(Wire::default());
        wire.blocked.store(true, Ordering::SeqCst);
        let mut node = AuthenticatedPbftNode::new_with_recovery(
            PbftConfig::new(4, 1).unwrap(), Arc::clone(&wire), auth(0),
            |request: &ConsensusRequest| Outcome::Ok(request.operation.clone()),
        ).unwrap();
        let mut submit = Box::pin(node.submit_request(&cx, request()));
        let mut task = Context::from_waker(Waker::noop());
        assert!(submit.as_mut().poll(&mut task).is_pending());
        assert_eq!(wire.sent.lock().len(), 1);
        cx.cancel_fast(CancelKind::User);
        let Poll::Ready(Err(error)) = submit.as_mut().poll(&mut task) else { panic!("cancelled initial send") };
        assert!(error.is_cancelled());
        drop(submit);
        let originals: Vec<_> = node.outbox.as_ref().unwrap().lock().frames.values()
            .map(|frame| frame.bytes.clone()).collect();
        assert_eq!(originals.len(), 2, "prepare retained before first send");
        assert!(matches!(auth(1).open(&originals[0]).unwrap(), PbftMessage::PrePrepare { .. }));
        assert!(matches!(auth(1).open(&originals[1]).unwrap(), PbftMessage::Prepare { .. }));

        let retry_cx = Cx::for_testing();
        let mut retry = Box::pin(node.retry_pending(&retry_cx, 1));
        assert!(retry.as_mut().poll(&mut task).is_pending());
        retry_cx.cancel_fast(CancelKind::User);
        let Poll::Ready(Err(error)) = retry.as_mut().poll(&mut task) else { panic!("cancelled retry") };
        assert!(error.is_cancelled());
        drop(retry);
        assert!(node.outbox.as_ref().unwrap().lock().cursor.is_none());
        wire.blocked.store(false, Ordering::SeqCst);
        let fresh = Cx::for_testing();
        let start = wire.sent.lock().len();
        assert_eq!(futures_lite::future::block_on(node.retry_pending(&fresh, 1)).unwrap(), 1);
        assert_eq!(futures_lite::future::block_on(node.retry_pending(&fresh, 1)).unwrap(), 1);
        assert_eq!(&wire.sent.lock()[start..], originals.as_slice());
        assert_eq!(futures_lite::future::block_on(node.retry_pending(&fresh, MAX_FRAMES)).unwrap(), 2);
    }

    #[derive(Default)]
    struct Network {
        attempts: BTreeMap<(usize, usize, [u8; 32]), usize>,
        queue: VecDeque<(usize, Vec<u8>)>,
    }

    struct LossyWire {
        network: Arc<InboxMutex<Network>>,
        local: usize,
        losses: usize,
        live: usize,
    }

    impl LossyWire {
        fn send(&self, recipient: usize, packet: Vec<u8>) {
            if recipient >= self.live { return; }
            let digest: [u8; 32] = Sha256::digest(&packet).into();
            let mut network = self.network.lock();
            let count = network.attempts.entry((self.local, recipient, digest)).or_default();
            *count += 1;
            if *count > self.losses { network.queue.push_back((recipient, packet)); }
        }
    }

    impl PbftPacketTransport for LossyWire {
        async fn send_packet(&self, recipient: &ReplicaId, packet: Vec<u8>) -> Result<()> {
            self.send(recipient.as_str().parse().unwrap(), packet);
            Ok(())
        }
        async fn broadcast_packet(&self, packet: Vec<u8>) -> Result<()> {
            for recipient in 0..4 {
                if recipient != self.local { self.send(recipient, packet.clone()); }
            }
            Ok(())
        }
        async fn receive_packet(&self, _: usize) -> Result<Vec<u8>> {
            std::future::pending().await
        }
    }

    #[test]
    fn signed_recovery_survives_lost_forwards_proposals_prepares_and_commits() {
        for live in [3, 4] {
            for losses in [1, 2, 3] {
                for reverse in [false, true] {
                    let network = Arc::new(InboxMutex::new(Network::default()));
                    let applications: Vec<_> = (0..live).map(|_| Arc::new(AtomicUsize::new(0))).collect();
                    let mut nodes: Vec<_> = (0..live).map(|local| {
                        let applied = Arc::clone(&applications[local]);
                        AuthenticatedPbftNode::new_with_recovery(
                            PbftConfig::new(4, 1).unwrap(),
                            LossyWire { network: Arc::clone(&network), local, losses, live },
                            auth(u8::try_from(local).unwrap()),
                            move |request: &ConsensusRequest| {
                                applied.fetch_add(1, Ordering::SeqCst);
                                Outcome::Ok(request.operation.clone())
                            },
                        ).unwrap()
                    }).collect();
                    let cx = Cx::for_testing();
                    let request = request();
                    futures_lite::future::block_on(nodes[2].submit_request(&cx, request.clone())).unwrap();
                    assert!(network.lock().queue.is_empty(), "initial forward was genuinely lost");
                    for _ in 0..64 {
                        for node in &mut nodes {
                            futures_lite::future::block_on(node.retry_pending(&cx, 1)).unwrap();
                        }
                        let mut delivered = 0;
                        loop {
                            let next = if reverse { network.lock().queue.pop_back() }
                                else { network.lock().queue.pop_front() };
                            let Some((recipient, packet)) = next else { break };
                            let outcome = futures_lite::future::block_on(nodes[recipient].process_packet(&cx, &packet)).unwrap();
                            assert!(matches!(outcome, PbftIngressOutcome::Processed | PbftIngressOutcome::AlreadyApplied(_)));
                            delivered += 1;
                            assert!(delivered < 1000, "deduplication bounds response amplification");
                        }
                        if applications.iter().all(|count| count.load(Ordering::SeqCst) == 1) { break; }
                    }
                    for (local, node) in nodes.iter_mut().enumerate() {
                        let response = node.committed_response(&request).unwrap().expect("repair reached every live replica");
                        assert_eq!(response.sequence, SequenceNumber(1));
                        assert_eq!(response.result, Outcome::Ok(b"repair-effect".to_vec()));
                        assert_eq!(applications[local].load(Ordering::SeqCst), 1);
                        node.sync_outbox().unwrap();
                        let cache = node.outbox.as_ref().unwrap().lock();
                        assert!(cache.frames.keys().all(|key| matches!(key, Key::Protocol(_, _))));
                        assert!(!cache.frames.is_empty(), "retain recent commits for lagging peers");
                    }
                }
            }
        }
    }

    #[test]
    fn stopped_or_invalid_retry_calls_produce_no_transport_operations() {
        let wire = Arc::new(Wire::default());
        let mut node = AuthenticatedPbftNode::new_with_recovery(
            PbftConfig::new(4, 1).unwrap(), Arc::clone(&wire), auth(0),
            |request: &ConsensusRequest| Outcome::Ok(request.operation.clone()),
        ).unwrap();
        let cx = Cx::for_testing();
        assert!(futures_lite::future::block_on(node.run_with_retries(&cx, Duration::ZERO, 1)).is_err());
        assert!(futures_lite::future::block_on(node.retry_pending(&cx, MAX_FRAMES + 1)).is_err());
        assert!(futures_lite::future::block_on(node.submit_with_retries(&cx, request(), Duration::ZERO, Duration::from_millis(1), 1)).is_err());
        cx.cancel_fast(CancelKind::User);
        assert!(futures_lite::future::block_on(node.run_with_retries(&cx, Duration::from_millis(1), 1)).unwrap_err().is_cancelled());
        assert!(wire.sent.lock().is_empty());
        assert!(next_deadline(Time::from_nanos(u64::MAX), Duration::from_nanos(1)).is_err());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn native_idle_udp_retry_ticks_recover_loss_and_retire_owned_receives() {
        use crate::distributed::consensus::udp::UdpPbftTransport;
        use crate::net::UdpSocket;
        use crate::runtime::RuntimeBuilder;
        use std::collections::BTreeSet;
        use std::net::UdpSocket as StdUdpSocket;

        struct LossyUdp {
            inner: UdpPbftTransport,
            seen: InboxMutex<BTreeSet<[u8; 32]>>,
        }
        impl LossyUdp {
            fn first(&self, packet: &[u8]) -> bool {
                self.seen.lock().insert(Sha256::digest(packet).into())
            }
        }
        impl PbftPacketTransport for LossyUdp {
            async fn send_packet(&self, recipient: &ReplicaId, packet: Vec<u8>) -> Result<()> {
                if self.first(&packet) { return Ok(()); }
                self.inner.send_packet(recipient, packet).await
            }
            async fn broadcast_packet(&self, packet: Vec<u8>) -> Result<()> {
                if self.first(&packet) { return Ok(()); }
                self.inner.broadcast_packet(packet).await
            }
            async fn receive_packet(&self, limit: usize) -> Result<Vec<u8>> {
                self.inner.receive_packet(limit).await
            }
        }

        for workers in [false, true] {
            let runtime = if workers {
                RuntimeBuilder::new().worker_threads(2).build().unwrap()
            } else { RuntimeBuilder::current_thread().build().unwrap() };
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let sockets: Vec<_> = (0..4).map(|_| StdUdpSocket::bind("127.0.0.1:0").unwrap()).collect();
                let routes: Vec<_> = sockets.iter().map(|socket| socket.local_addr().unwrap()).collect();
                let applications: Vec<_> = (0..3).map(|_| Arc::new(AtomicUsize::new(0))).collect();
                let mut nodes = Vec::new();
                let mut inactive = None;
                for (local, socket) in sockets.into_iter().enumerate() {
                    if local == 3 { inactive = Some(socket); continue; }
                    let authority = auth(u8::try_from(local).unwrap());
                    let wire = LossyUdp {
                        inner: UdpPbftTransport::new(UdpSocket::from_std(socket).unwrap(), &authority, routes.clone()).unwrap(),
                        seen: InboxMutex::new(BTreeSet::new()),
                    };
                    let applied = Arc::clone(&applications[local]);
                    nodes.push(AuthenticatedPbftNode::new_with_recovery(
                        PbftConfig::new(4, 1).unwrap(), wire, authority,
                        move |request: &ConsensusRequest| {
                            applied.fetch_add(1, Ordering::SeqCst);
                            Outcome::Ok(request.operation.clone())
                        },
                    ).unwrap());
                }
                let request = request();
                nodes[2].submit_request(&cx, request.clone()).await.unwrap();
                assert!(applications.iter().all(|count| count.load(Ordering::SeqCst) == 0));
                {
                    let mut pumps: Vec<_> = nodes.iter_mut().map(|node| {
                        Box::pin(node.run_with_retries(&cx, Duration::from_millis(5), 2))
                    }).collect();
                    let all_applied = poll_fn(|task| {
                        for pump in &mut pumps {
                            if let Poll::Ready(result) = pump.as_mut().poll(task) {
                                panic!("live recovery pump exited: {result:?}");
                            }
                        }
                        if applications.iter().all(|count| count.load(Ordering::SeqCst) == 1) {
                            Poll::Ready(())
                        } else { Poll::Pending }
                    });
                    crate::time::timeout(cx.now(), Duration::from_secs(5), all_applied)
                        .await.expect("native UDP loss recovery deadline");
                    // Dropping caller-owned pumps retires their pending idle
                    // receive/timer futures before inspecting nodes again.
                }
                for (local, node) in nodes.iter().enumerate() {
                    let response = node.committed_response(&request).unwrap().unwrap();
                    assert_eq!(response.result, Outcome::Ok(b"repair-effect".to_vec()));
                    assert_eq!(response.sequence, SequenceNumber(1));
                    assert_eq!(applications[local].load(Ordering::SeqCst), 1);
                }
                drop(inactive);
            });
            assert!(runtime.is_quiescent());
        }
    }
}
