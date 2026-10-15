use super::{DatagramIo, NodeId, SocketAddr, Swim, SwimDriverConfig, SwimDriverError, SwimDriverStats};
use crate::distributed::membership::{Outgoing, Packet, Payload, Rumor, decode_packet, encode_packet};
use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::task::{Context, Poll};

pub(super) struct Queued {
    pub(super) target: SocketAddr,
    pub(super) bytes: Vec<u8>,
    queued_at: u64,
    leave: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Turn { Park, Yield, Left }

pub(super) struct Engine {
    pub(super) swim: Swim,
    pub(super) peers: BTreeMap<NodeId, SocketAddr>,
    by_address: BTreeMap<SocketAddr, NodeId>,
    pub(super) config: SwimDriverConfig,
    mtu: usize,
    pub(super) outbox: VecDeque<Queued>,
    pub(super) stats: SwimDriverStats,
    leaving: Option<u64>,
}

impl Engine {
    pub(super) fn new(swim: Swim, peers: BTreeMap<NodeId, SocketAddr>, mtu: usize, config: SwimDriverConfig) -> Self {
        let by_address = peers.iter().map(|(node, addr)| (*addr, node.clone())).collect();
        Self {
            swim, peers, by_address, config, mtu,
            outbox: VecDeque::new(), stats: SwimDriverStats::default(), leaving: None,
        }
    }

    pub(super) fn is_leaving(&self) -> bool { self.leaving.is_some() }

    pub(super) fn discard_outbox(&mut self) {
        self.stats.discarded_datagrams = self.stats.discarded_datagrams.saturating_add(self.outbox.len() as u64);
        self.outbox.clear();
        self.stats.queued_datagrams = 0;
    }

    pub(super) fn begin_leave(&mut self, now: u64) -> Result<(), SwimDriverError> {
        if self.is_leaving() { return Ok(()); }
        let deadline = now.checked_add(self.config.leave_timeout_ms).ok_or(SwimDriverError::Clock)?;
        self.leaving = Some(deadline);
        self.discard_outbox();
        self.swim.declare_leave();
        let leave = Packet {
            payload: Payload::Ping { seq: 0 },
            gossip: vec![Rumor::leave(self.swim.local().clone(), self.swim.incarnation())],
        };
        // An explicit Leave per peer avoids waiting a randomized probe traversal
        // for dissemination. Local acceptance is all this shutdown can promise.
        let mut targets = Vec::new();
        targets.try_reserve_exact(self.peers.len()).map_err(|_| SwimDriverError::Allocation)?;
        targets.extend(self.peers.values().copied());
        for target in targets { self.queue(now, target, &leave, true)?; }
        Ok(())
    }

    fn allowed(&self, id: &NodeId) -> bool { id == self.swim.local() || self.peers.contains_key(id) }

    fn authorized_packet(&self, packet: &Packet) -> bool {
        if let Payload::PingReq { target, .. } = &packet.payload {
            if !self.allowed(target) { return false; }
        }
        packet.gossip.iter().all(|rumor| {
            self.allowed(rumor.node()) && match rumor {
                Rumor::Suspect { from, .. } | Rumor::Confirm { from, .. } => self.allowed(from),
                _ => true,
            }
        })
    }

    pub(super) fn receive(&mut self, now: u64, source: SocketAddr, bytes: &[u8]) -> Result<(), SwimDriverError> {
        self.stats.received_datagrams = self.stats.received_datagrams.saturating_add(1);
        let Some(node) = self.by_address.get(&source).cloned() else {
            self.stats.unknown_sources = self.stats.unknown_sources.saturating_add(1);
            return Ok(());
        };
        if bytes.len() > self.mtu {
            self.stats.oversized_datagrams = self.stats.oversized_datagrams.saturating_add(1);
            return Ok(());
        }
        let packet = match decode_packet(bytes) {
            Ok(packet) => packet,
            Err(_) => {
                self.stats.malformed_datagrams = self.stats.malformed_datagrams.saturating_add(1);
                return Ok(());
            }
        };
        // The legacy decoder accepts a valid prefix with trailing bytes. This
        // new ingress is strict without changing that decoder's public contract.
        if !encode_packet(&packet, self.mtu).is_ok_and(|encoded| encoded.bytes.as_slice() == bytes) {
            self.stats.malformed_datagrams = self.stats.malformed_datagrams.saturating_add(1);
            return Ok(());
        }
        if !self.authorized_packet(&packet) {
            self.stats.unauthorized_packets = self.stats.unauthorized_packets.saturating_add(1);
            return Ok(());
        }
        self.stats.accepted_packets = self.stats.accepted_packets.saturating_add(1);
        if matches!(&packet.payload, Payload::Ack { .. }) {
            self.stats.received_acks = self.stats.received_acks.saturating_add(1);
        }
        let outgoing = self.swim.handle(now, node, packet);
        self.enqueue(now, outgoing)
    }

    fn queue(&mut self, now: u64, target: SocketAddr, packet: &Packet, leave: bool) -> Result<(), SwimDriverError> {
        if self.outbox.len() == self.config.max_queued_datagrams { return Err(SwimDriverError::OutboxFull); }
        let datagram = encode_packet(packet, self.mtu)?;
        if leave && datagram.gossip_included != 1 {
            return Err(SwimDriverError::Configuration("Leave does not fit datagram budget"));
        }
        self.outbox.try_reserve(1).map_err(|_| SwimDriverError::Allocation)?;
        self.stats.omitted_gossip = self.stats.omitted_gossip.saturating_add(datagram.gossip_dropped as u64);
        self.outbox.push_back(Queued { target, bytes: datagram.bytes, queued_at: now, leave });
        self.stats.queued_datagrams = self.outbox.len();
        self.stats.queue_high_water = self.stats.queue_high_water.max(self.outbox.len());
        Ok(())
    }

    fn enqueue(&mut self, now: u64, outgoing: Vec<Outgoing>) -> Result<(), SwimDriverError> {
        for outgoing in outgoing {
            // No address learned from gossip can create a new network target.
            let target = self.peers.get(&outgoing.to).copied()
                .ok_or(SwimDriverError::Configuration("protocol output has no authorized route"))?;
            self.queue(now, target, &outgoing.packet, false)?;
        }
        Ok(())
    }

    fn expire(&mut self, now: u64) {
        while self.outbox.front().is_some_and(|front| {
            !front.leave && now.saturating_sub(front.queued_at) >= self.config.max_datagram_age_ms
        }) {
            self.outbox.pop_front();
            self.stats.expired_datagrams = self.stats.expired_datagrams.saturating_add(1);
        }
        self.stats.queued_datagrams = self.outbox.len();
    }

    pub(super) fn turn<D: DatagramIo>(
        &mut self, io: &mut D, task: &mut Context<'_>, now: u64, tick: bool,
    ) -> Result<Turn, SwimDriverError> {
        let mut busy = false;
        self.expire(now);
        if let Some(deadline) = self.leaving {
            if self.outbox.is_empty() { return Ok(Turn::Left); }
            if now >= deadline { return Err(SwimDriverError::LeaveTimeout); }
        } else {
            // A bounded ready receive batch gets a chance to acknowledge a probe
            // before maintenance concludes it failed. Floods cannot starve tick.
            for index in 0..self.config.io_batch {
                match io.poll_datagram(task) {
                    Poll::Pending => break,
                    Poll::Ready(Ok((source, bytes))) => self.receive(now, source, bytes)?,
                    Poll::Ready(Err(error)) if matches!(error.kind(), io::ErrorKind::Interrupted | io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionRefused) => {
                        self.stats.receive_errors = self.stats.receive_errors.saturating_add(1);
                    }
                    Poll::Ready(Err(error)) => return Err(SwimDriverError::Io(error)),
                }
                busy |= index + 1 == self.config.io_batch;
            }
            if tick {
                self.stats.ticks = self.stats.ticks.saturating_add(1);
                let outgoing = self.swim.tick(now);
                self.enqueue(now, outgoing)?;
            }
        }
        for index in 0..self.config.io_batch {
            let Some(front) = self.outbox.front() else { break; };
            match io.poll_send_datagram(task, front.target, &front.bytes) {
                Poll::Pending => break, // retain exactly the same bytes and age
                Poll::Ready(Ok(written)) if written == front.bytes.len() => {
                    self.stats.sent_datagrams = self.stats.sent_datagrams.saturating_add(1);
                    self.stats.sent_bytes = self.stats.sent_bytes.saturating_add(written as u64);
                }
                Poll::Ready(Ok(_)) => return Err(SwimDriverError::PartialDatagram),
                Poll::Ready(Err(error)) => {
                    self.stats.send_errors = self.stats.send_errors.saturating_add(1);
                    if front.leave { return Err(SwimDriverError::Io(error)); }
                    // Ordinary SWIM datagrams are best effort. Network failure
                    // is accounted as loss; it is not a successful packet send.
                }
            }
            self.outbox.pop_front();
            self.stats.queued_datagrams = self.outbox.len();
            busy |= index + 1 == self.config.io_batch && !self.outbox.is_empty();
        }
        if self.is_leaving() && self.outbox.is_empty() { Ok(Turn::Left) }
        else if busy { Ok(Turn::Yield) }
        else { Ok(Turn::Park) }
    }
}
