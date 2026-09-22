//! Bounded normal-case vote reordering. No unverified packet enters this inbox.

use super::{PbftIngressOutcome, PbftMessage};
use crate::distributed::consensus::types::{MessageDigest, ReplicaId, SequenceNumber, ViewNumber};
use std::collections::BTreeMap;

// Bounds on auxiliary inbox state, not on the legacy engine's committed log.
pub(super) const WINDOW: u64 = 64;
const MAX_VOTES: usize = 8192;

#[derive(Default)]
pub(super) struct ReorderBuffer {
    applied: u64,
    local_high: u64,
    votes: usize,
    slots: BTreeMap<u64, Slot>,
}

#[derive(Default)]
struct Slot {
    digest: Option<MessageDigest>,
    // Set by an outbound prepare/proposal AFTER the engine installs its entry,
    // but BEFORE the potentially pending transport send begins.
    installed: bool,
    local_request: Option<MessageDigest>,
    votes: BTreeMap<(u8, u32), Vote>,
}

struct Vote {
    digest: MessageDigest,
    delivered: bool,
}

pub(super) struct Delivery {
    sequence: u64,
    phase: u8,
    author: u32,
    digest: MessageDigest,
}

impl Delivery {
    pub(super) fn message(&self) -> PbftMessage {
        let view = ViewNumber::new(0);
        let sequence = SequenceNumber::new(self.sequence);
        let digest = self.digest.clone();
        let replica_id = ReplicaId::new(self.author.to_string());
        if self.phase == 0 {
            PbftMessage::Prepare { view, sequence, digest, replica_id }
        } else {
            PbftMessage::Commit { view, sequence, digest, replica_id }
        }
    }
}

impl ReorderBuffer {
    pub(super) fn prune(&mut self, applied: SequenceNumber) {
        self.applied = self.applied.max(applied.0);
        while self.slots.first_key_value().is_some_and(|(seq, _)| *seq <= self.applied) {
            if let Some((_, slot)) = self.slots.pop_first() {
                self.votes -= slot.votes.len();
            }
        }
    }

    fn check(&self, view: ViewNumber, sequence: SequenceNumber) -> Result<(), PbftIngressOutcome> {
        if view.0 != 0 {
            return Err(PbftIngressOutcome::Rejected(super::PbftAuthError::UnsupportedPhase));
        }
        if sequence.0 <= self.applied
            || sequence.0 > self.applied.saturating_add(WINDOW)
            || sequence.0 == u64::MAX
        {
            return Err(PbftIngressOutcome::OutsideWindow(sequence));
        }
        Ok(())
    }

    pub(super) fn proposal(
        &mut self,
        view: ViewNumber,
        sequence: SequenceNumber,
        digest: &MessageDigest,
        installed: bool,
        local_request: Option<MessageDigest>,
    ) -> Result<(), PbftIngressOutcome> {
        self.check(view, sequence)?;
        let slot = self.slots.entry(sequence.0).or_default();
        if slot.digest.as_ref().is_some_and(|existing| existing != digest) {
            return Err(PbftIngressOutcome::Equivocation(sequence));
        }
        slot.digest.get_or_insert_with(|| digest.clone());
        slot.installed |= installed;
        if let Some(request) = local_request {
            slot.local_request = Some(request);
            self.local_high = self.local_high.max(sequence.0);
        }
        Ok(())
    }

    /// Called only for engine-produced messages, never directly from ingress.
    pub(super) fn observe_outbound(&mut self, message: &PbftMessage) -> Result<(), PbftIngressOutcome> {
        match message {
            PbftMessage::PrePrepare { view, sequence, digest, batch, .. } => {
                let request = if let [request] = batch.requests.as_slice() {
                    Some(MessageDigest::of(request).map_err(|_| {
                        PbftIngressOutcome::Rejected(super::PbftAuthError::Encoding)
                    })?)
                } else {
                    None
                };
                self.proposal(*view, *sequence, digest, true, request)
            }
            PbftMessage::Prepare { view, sequence, digest, .. } => {
                self.proposal(*view, *sequence, digest, true, None)
            }
            _ => Ok(()),
        }
    }

    pub(super) fn can_propose(&self, request: &MessageDigest) -> bool {
        self.local_high < self.applied.saturating_add(WINDOW)
            || self.slots.values().any(|slot| slot.local_request.as_ref() == Some(request))
    }

    /// Keep at most one digest for each (sequence, phase, authenticated author).
    /// A conflicting vote cannot replace a retained or already delivered vote.
    pub(super) fn vote(&mut self, message: &PbftMessage) -> Result<(), PbftIngressOutcome> {
        let (phase, view, sequence, digest, replica) = match message {
            PbftMessage::Prepare { view, sequence, digest, replica_id } =>
                (0, *view, *sequence, digest, replica_id),
            PbftMessage::Commit { view, sequence, digest, replica_id } =>
                (1, *view, *sequence, digest, replica_id),
            _ => return Err(PbftIngressOutcome::Rejected(super::PbftAuthError::Encoding)),
        };
        self.check(view, sequence)?;
        // Authenticator already checked canonical form, membership and author.
        let author = replica.as_str().parse::<u32>().map_err(|_| {
            PbftIngressOutcome::Rejected(super::PbftAuthError::Author)
        })?;
        if let Some(old) = self.slots.get(&sequence.0).and_then(|slot| slot.votes.get(&(phase, author))) {
            return if old.digest == *digest {
                Ok(())
            } else {
                Err(PbftIngressOutcome::Equivocation(sequence))
            };
        }
        if self.votes == MAX_VOTES {
            return Err(PbftIngressOutcome::BufferFull);
        }
        self.slots.entry(sequence.0).or_default().votes.insert(
            (phase, author), Vote { digest: digest.clone(), delivered: false },
        );
        self.votes += 1;
        Ok(())
    }

    /// Borrow/clone without removal. Only acknowledge after the actual engine
    /// call returns; cancellation or a failed send leaves this delivery ready.
    pub(super) fn next(&self) -> Option<Delivery> {
        for (sequence, slot) in &self.slots {
            if !slot.installed { continue; }
            for ((phase, author), vote) in &slot.votes {
                if !vote.delivered && slot.digest.as_ref() == Some(&vote.digest) {
                    return Some(Delivery {
                        sequence: *sequence, phase: *phase, author: *author,
                        digest: vote.digest.clone(),
                    });
                }
            }
        }
        None
    }

    pub(super) fn acknowledge(&mut self, delivery: &Delivery) {
        if let Some(vote) = self.slots.get_mut(&delivery.sequence)
            .and_then(|slot| slot.votes.get_mut(&(delivery.phase, delivery.author)))
        {
            if vote.digest == delivery.digest { vote.delivered = true; }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vote(sequence: u64, author: u32, commit: bool, tag: u8) -> PbftMessage {
        let view = ViewNumber::new(0);
        let sequence = SequenceNumber::new(sequence);
        let digest = MessageDigest::from_bytes([tag; 32]);
        let replica_id = ReplicaId::new(author.to_string());
        if commit { PbftMessage::Commit { view, sequence, digest, replica_id } }
        else { PbftMessage::Prepare { view, sequence, digest, replica_id } }
    }

    #[test]
    fn votes_wait_for_installed_matching_proposal_and_acknowledgement() {
        let mut inbox = ReorderBuffer::default();
        inbox.vote(&vote(1, 2, true, 7)).unwrap();
        inbox.vote(&vote(1, 0, false, 7)).unwrap();
        inbox.vote(&vote(1, 3, false, 8)).unwrap();
        assert!(inbox.next().is_none());
        let digest = MessageDigest::from_bytes([7; 32]);
        inbox.proposal(ViewNumber(0), SequenceNumber(1), &digest, false, None).unwrap();
        assert!(inbox.next().is_none());
        inbox.proposal(ViewNumber(0), SequenceNumber(1), &digest, true, None).unwrap();
        let first = inbox.next().unwrap();
        assert_eq!(first.phase, 0);
        // Dropping a selected delivery must not consume the obligation to apply it.
        drop(first);
        let first = inbox.next().unwrap();
        assert_eq!(first.author, 0);
        inbox.acknowledge(&first);
        let second = inbox.next().unwrap();
        assert_eq!(second.phase, 1);
        inbox.acknowledge(&second);
        assert!(inbox.next().is_none());
        assert_eq!(inbox.votes, 3);
        inbox.prune(SequenceNumber(1));
        assert!(inbox.slots.is_empty());
        assert_eq!(inbox.votes, 0);
    }

    #[test]
    fn duplicate_flood_and_equivocation_do_not_expand_or_replace_votes() {
        let mut inbox = ReorderBuffer::default();
        for _ in 0..10_000 { inbox.vote(&vote(1, 2, false, 7)).unwrap(); }
        assert_eq!(inbox.votes, 1);
        assert_eq!(inbox.vote(&vote(1, 2, false, 8)), Err(PbftIngressOutcome::Equivocation(SequenceNumber(1))));
        inbox.proposal(ViewNumber(0), SequenceNumber(1), &MessageDigest::from_bytes([7; 32]), true, None).unwrap();
        assert_eq!(inbox.next().unwrap().digest, MessageDigest::from_bytes([7; 32]));
        assert_eq!(inbox.proposal(ViewNumber(0), SequenceNumber(1), &MessageDigest::from_bytes([9; 32]), true, None), Err(PbftIngressOutcome::Equivocation(SequenceNumber(1))));
    }

    #[test]
    fn global_vote_cap_and_sequence_window_are_enforced_before_insertion() {
        let mut inbox = ReorderBuffer::default();
        for sequence in 1..=WINDOW {
            for author in 0..64 {
                inbox.vote(&vote(sequence, author, false, 7)).unwrap();
                inbox.vote(&vote(sequence, author, true, 7)).unwrap();
            }
        }
        assert_eq!(inbox.votes, MAX_VOTES);
        assert_eq!(inbox.vote(&vote(1, 65, false, 7)), Err(PbftIngressOutcome::BufferFull));
        assert_eq!(inbox.vote(&vote(WINDOW + 1, 0, false, 7)), Err(PbftIngressOutcome::OutsideWindow(SequenceNumber(WINDOW + 1))));
        assert_eq!(inbox.slots.len(), WINDOW as usize);
        inbox.prune(SequenceNumber(1));
        inbox.vote(&vote(WINDOW + 1, 0, false, 7)).unwrap();
        assert_eq!(inbox.votes, MAX_VOTES - 128 + 1);
        inbox.prune(SequenceNumber(u64::MAX - 1));
        assert!(inbox.vote(&vote(u64::MAX, 0, false, 7)).is_err());
        assert!(inbox.slots.is_empty());
    }

    #[test]
    fn full_primary_window_still_admits_exact_retry_then_reopens_after_progress() {
        let mut inbox = ReorderBuffer::default();
        let request = MessageDigest::from_bytes([4; 32]);
        inbox.proposal(ViewNumber(0), SequenceNumber(WINDOW), &MessageDigest::from_bytes([7; 32]), true, Some(request.clone())).unwrap();
        assert!(inbox.can_propose(&request));
        assert!(!inbox.can_propose(&MessageDigest::from_bytes([5; 32])));
        inbox.prune(SequenceNumber(1));
        assert!(inbox.can_propose(&MessageDigest::from_bytes([5; 32])));
    }
}

#[cfg(test)]
mod integration_tests {
    use super::super::*;
    use crate::distributed::consensus::authenticated::PbftMembership;
    use crate::types::{CancelKind, Outcome};
    use nkeys::{KeyPair, KeyPairType};
    use sha2::{Digest, Sha256};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::{Context, Waker};

    #[derive(Default)]
    struct Wire {
        blocked: AtomicBool,
        receives: AtomicUsize,
        sends: AtomicUsize,
    }

    impl PbftPacketTransport for Arc<Wire> {
        async fn send_packet(&self, _: &ReplicaId, packet: Vec<u8>) -> Result<()> {
            self.broadcast_packet(packet).await
        }
        async fn broadcast_packet(&self, _: Vec<u8>) -> Result<()> {
            self.sends.fetch_add(1, Ordering::SeqCst);
            if self.blocked.load(Ordering::SeqCst) { std::future::pending::<()>().await; }
            Ok(())
        }
        async fn receive_packet(&self, _: usize) -> Result<Vec<u8>> {
            self.receives.fetch_add(1, Ordering::SeqCst);
            std::future::pending().await
        }
    }

    fn auth(local: u8) -> Arc<PbftAuthenticator> {
        let key = |i: u8| {
            let seed: [u8; 32] = Sha256::digest([i; 32]).into();
            KeyPair::new_from_raw(KeyPairType::User, seed).unwrap()
        };
        let keys: Vec<_> = (0..4).map(|i| key(i).public_key()).collect();
        Arc::new(PbftAuthenticator::new(
            PbftMembership::new([9; 32], 1, &keys).unwrap(),
            ReplicaId::new(local.to_string()), key(local), 4096,
        ).unwrap())
    }

    fn request() -> ConsensusRequest {
        ConsensusRequest::new("reordered".into(), Time::from_millis(1), b"effect".to_vec())
    }

    fn packets() -> Vec<Vec<u8>> {
        let batch = ConsensusBatch::new(vec![request()]);
        let digest = MessageDigest::of(&batch).unwrap();
        let proposal = PbftMessage::PrePrepare {
            view: ViewNumber(0), sequence: SequenceNumber(1), digest: digest.clone(),
            batch, replica_id: ReplicaId::new("0".into()),
        };
        let mut packets = vec![auth(0).seal(None, &proposal).unwrap()];
        for commit in [false, true] {
            for author in [0, 2] {
                let message = if commit {
                    PbftMessage::Commit { view: ViewNumber(0), sequence: SequenceNumber(1), digest: digest.clone(), replica_id: ReplicaId::new(author.to_string()) }
                } else {
                    PbftMessage::Prepare { view: ViewNumber(0), sequence: SequenceNumber(1), digest: digest.clone(), replica_id: ReplicaId::new(author.to_string()) }
                };
                packets.push(auth(author).seal(None, &message).unwrap());
            }
        }
        packets
    }

    fn permutations(items: &mut [usize], offset: usize, output: &mut Vec<Vec<usize>>) {
        if offset == items.len() { output.push(items.to_vec()); return; }
        for i in offset..items.len() {
            items.swap(offset, i);
            permutations(items, offset + 1, output);
            items.swap(offset, i);
        }
    }

    #[test]
    fn every_signed_proposal_prepare_commit_order_executes_exactly_once() {
        let packets = packets();
        let mut orders = Vec::new();
        permutations(&mut [0, 1, 2, 3, 4], 0, &mut orders);
        assert_eq!(orders.len(), 120);
        let cx = Cx::for_testing();
        for order in orders {
            let applied = Arc::new(AtomicUsize::new(0));
            let count = Arc::clone(&applied);
            let wire = Arc::new(Wire::default());
            let mut node = AuthenticatedPbftNode::new_with_reordering(
                PbftConfig::new(4, 1).unwrap(), Arc::clone(&wire), auth(1),
                move |request: &ConsensusRequest| {
                    count.fetch_add(1, Ordering::SeqCst);
                    Outcome::Ok(request.operation.clone())
                },
            ).unwrap();
            for (position, index) in order.iter().enumerate() {
                assert_eq!(futures_lite::future::block_on(node.process_packet(&cx, &packets[*index])).unwrap(), PbftIngressOutcome::Processed);
                assert_eq!(applied.load(Ordering::SeqCst), usize::from(position == 4), "order {order:?}");
            }
            let response = node.committed_response(&request()).unwrap().unwrap();
            assert_eq!(response.sequence, SequenceNumber(1));
            assert_eq!(response.result, Outcome::Ok(b"effect".to_vec()));
            let sends = wire.sends.load(Ordering::SeqCst);
            for packet in &packets {
                assert_eq!(futures_lite::future::block_on(node.process_packet(&cx, packet)).unwrap(), PbftIngressOutcome::AlreadyApplied(SequenceNumber(1)));
            }
            assert_eq!(wire.sends.load(Ordering::SeqCst), sends);
            assert_eq!(node.reorder.as_ref().unwrap().lock().votes, 0);
        }
    }

    #[test]
    fn cancelled_proposal_send_preserves_early_votes_and_resumes_without_new_input() {
        let cx = Cx::for_testing();
        let wire = Arc::new(Wire::default());
        let mut node = AuthenticatedPbftNode::new_with_reordering(
            PbftConfig::new(4, 1).unwrap(), Arc::clone(&wire), auth(1),
            |request: &ConsensusRequest| Outcome::Ok(request.operation.clone()),
        ).unwrap();
        let packets = packets();
        for packet in &packets[1..] {
            futures_lite::future::block_on(node.process_packet(&cx, packet)).unwrap();
        }
        assert!(node.committed_response(&request()).unwrap().is_none());
        wire.blocked.store(true, Ordering::SeqCst);
        let mut proposal = Box::pin(node.process_packet(&cx, &packets[0]));
        let mut task = Context::from_waker(Waker::noop());
        assert!(proposal.as_mut().poll(&mut task).is_pending());
        assert_eq!(wire.sends.load(Ordering::SeqCst), 1);
        cx.cancel_fast(CancelKind::User);
        let Poll::Ready(Err(error)) = proposal.as_mut().poll(&mut task) else { panic!("cancelled proposal") };
        assert!(error.is_cancelled());
        drop(proposal);
        wire.blocked.store(false, Ordering::SeqCst);
        let fresh = Cx::for_testing();
        assert_eq!(futures_lite::future::block_on(node.receive_one(&fresh)).unwrap(), PbftIngressOutcome::Processed);
        assert_eq!(wire.receives.load(Ordering::SeqCst), 0);
        assert_eq!(node.committed_response(&request()).unwrap().unwrap().result, Outcome::Ok(b"effect".to_vec()));
    }
}
