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
#[path = "reorder_inline_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "reorder_integration_tests_inline_tests.rs"]
mod integration_tests;
