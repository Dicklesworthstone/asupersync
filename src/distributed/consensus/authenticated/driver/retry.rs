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
#[path = "retry_inline_tests.rs"]
mod tests;
