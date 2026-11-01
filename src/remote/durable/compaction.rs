//! Explicit replacement-file compaction with an application-owned publication boundary.

use super::{
    Arc, CLOCK_FLOOR, COMMON_BYTES, COMPLETE, DurableRemoteError, DurableRemoteJournal,
    DurableRemoteJournalStatus, Entry, EntryState, File, IdempotencyKey, Journal, JournalIo,
    NodeId, RESERVATION_BYTES, RESERVE, TERMINAL_BYTES, add, add64, buffer, io, lock, record_size,
    size64,
};

/// The authenticated journal state installed by a successful compaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct DurableRemoteCompactionReport {
    /// Committed bytes in the previous journal, before replacement.
    pub previous_bytes: u64,
    /// Committed bytes in the replacement, including its persisted clock floor.
    pub committed_bytes: u64,
    /// Pending requests and terminal results retained at the supplied timestamp.
    pub retained_entries: usize,
}

impl DurableRemoteJournal {
    /// Reclaim expired records through an empty, caller-owned replacement file.
    ///
    /// Every pending reservation and unexpired terminal outcome is preserved,
    /// including its original input identity and expiry. Compaction grants no
    /// execution permission and never resolves an uncertain request. Live
    /// execution or reconciliation permits refuse `Busy`. Incomplete-tail and
    /// poisoned journals cannot be compacted.
    ///
    /// The replacement must be a distinct, empty regular read/write file with
    /// the intended access policy, on a filesystem where the caller can publish
    /// it atomically. Both files remain exclusively locked through publication.
    /// After completely writing and syncing the replacement, this method calls
    /// `publish` exactly once. The callback must atomically replace the service's
    /// authoritative journal path with that exact replacement and durably sync
    /// its directory linkage before returning `Ok(())`. It must not expose the
    /// replacement early, write either file, or leave a second service using an
    /// old path. The journal itself acquires no pathname authority.
    ///
    /// Preparation failures do not modify the original file. They can advance
    /// its in-process clock and expire terminal cache entries, as ordinary calls
    /// do. A failed source-length check poisons that owner. Immediately before
    /// calling `publish`, the old owner is poisoned: a callback error or panic
    /// may follow a successful rename, so further use requires dropping this
    /// owner and reopening the authoritative path. A successful callback installs
    /// the replacement without any further fallible operation.
    ///
    /// The clock floor is persisted even when no requests remain. Compacted
    /// journals contain a new authenticated record kind that older readers
    /// reject; ordinary, uncompacted journals keep their existing format.
    /// Compaction is bounded by the same immutable limits and can refuse `Limit`
    /// if retained state plus its clock record does not fit. It does not promise
    /// to reduce a file that contains only retained work.
    /// Preparation temporarily holds one additional bounded entry/outcome cache
    /// and at most one record's payload and encoding buffers.
    ///
    /// This operation and its publication callback are synchronous. Use
    /// [`super::DurableRemoteComputation::compact`] with an explicit blocking
    /// capability when operating inside the runtime.
    pub fn compact(
        &mut self,
        replacement: File,
        now_millis: u64,
        publish: impl FnOnce() -> io::Result<()>,
    ) -> Result<DurableRemoteCompactionReport, DurableRemoteError> {
        lock(&replacement)?;
        self.core.compact(replacement, now_millis, publish)
    }
}

impl<F: JournalIo> Journal<F> {
    pub(super) fn compact(
        &mut self,
        replacement: F,
        now: u64,
        publish: impl FnOnce() -> io::Result<()>,
    ) -> Result<DurableRemoteCompactionReport, DurableRemoteError> {
        if self.status != DurableRemoteJournalStatus::Writable {
            return Err(DurableRemoteError::NotWritable(self.status));
        }
        if Arc::strong_count(&self.instance) != 1 {
            return Err(DurableRemoteError::Busy);
        }
        self.observe(now)?;
        self.check_compaction_source()?;

        // Only bounded metadata is sorted. Outcomes are copied one record at a
        // time, with the same accounting and replay validation as an ordinary
        // reopen. Preserve original completion sequence, including ties in the
        // clock: rearranging small and large results at one timestamp could
        // otherwise require a larger intermediate outcome allowance.
        let mut terminals = Vec::new();
        terminals
            .try_reserve_exact(self.entries.len())
            .map_err(|_| DurableRemoteError::Allocation)?;
        for (id, entry) in &self.entries {
            if let EntryState::Terminal { expires_at, completion_sequence, .. } = &entry.state {
                let completed_at = expires_at
                    .checked_sub(self.config.limits.retention_ms)
                    .ok_or(DurableRemoteError::Format)?;
                terminals.push((*completion_sequence, completed_at, id, entry));
            }
        }
        terminals.sort_unstable_by_key(|terminal| terminal.0);

        let mut compacted = Self::create(replacement, self.config.clone())?;
        for (_, completed_at, (peer, raw_key), entry) in terminals {
            let key = IdempotencyKey::from_raw(*raw_key);
            compacted.copy_reservation(peer, key, entry, completed_at)?;
            let reservation_sequence = compacted.sequence;
            let EntryState::Terminal { expires_at, outcome, .. } = &entry.state else {
                unreachable!("terminal compaction index contains only terminal entries");
            };
            let mut payload = buffer(add(TERMINAL_BYTES, outcome.len())?)?;
            payload.extend_from_slice(&reservation_sequence.to_le_bytes());
            payload.extend_from_slice(&expires_at.to_le_bytes());
            payload.extend_from_slice(&size64(outcome.len())?.to_le_bytes());
            payload.extend_from_slice(outcome);
            compacted.copy_record(COMPLETE, peer, key, &payload, completed_at)?;
        }
        for ((peer, raw_key), entry) in &self.entries {
            if matches!(&entry.state, EntryState::Pending) {
                // Reconstructed pending fences need no fresh retention horizon.
                // Reuse the preceding completion clock (or zero), then persist
                // the trusted current clock separately. This remains valid even
                // when `now + retention_ms` would overflow.
                let pending_time = compacted.last_time;
                compacted.copy_reservation(
                    peer,
                    IdempotencyKey::from_raw(*raw_key),
                    entry,
                    pending_time,
                )?;
            }
        }
        compacted.copy_record(
            CLOCK_FLOOR,
            &NodeId::new(""),
            IdempotencyKey::from_raw(0),
            &[],
            now,
        )?;

        // A writer violating the exclusive-lock contract must not silently
        // leave this process using an obsolete prefix after publication.
        self.check_compaction_source()?;
        let report = DurableRemoteCompactionReport {
            previous_bytes: self.offset,
            committed_bytes: compacted.offset,
            retained_entries: compacted.entries.len(),
        };
        self.status = DurableRemoteJournalStatus::Poisoned;
        publish()?;
        *self = compacted;
        Ok(report)
    }

    fn check_compaction_source(&mut self) -> Result<(), DurableRemoteError> {
        self.status = DurableRemoteJournalStatus::Poisoned;
        if self.file.length()? != self.offset {
            return Err(DurableRemoteError::Changed);
        }
        self.status = DurableRemoteJournalStatus::Writable;
        Ok(())
    }

    fn copy_reservation(
        &mut self,
        peer: &NodeId,
        key: IdempotencyKey,
        entry: &Entry,
        now: u64,
    ) -> Result<(), DurableRemoteError> {
        let mut payload = [0; RESERVATION_BYTES];
        payload[..8].copy_from_slice(&entry.input_len.to_le_bytes());
        payload[8..].copy_from_slice(&entry.digest);
        self.copy_record(RESERVE, peer, key, &payload, now)
    }

    fn copy_record(
        &mut self,
        kind: u8,
        peer: &NodeId,
        key: IdempotencyKey,
        payload: &[u8],
        now: u64,
    ) -> Result<(), DurableRemoteError> {
        let mut body = buffer(add(add(COMMON_BYTES, peer.as_str().len())?, payload.len())?)?;
        let sequence = add64(self.sequence, 1)?;
        body.extend_from_slice(&sequence.to_le_bytes());
        body.extend_from_slice(self.last.as_bytes());
        body.extend_from_slice(&now.to_le_bytes());
        body.push(kind);
        body.push(peer.as_str().len() as u8);
        body.extend_from_slice(&key.raw().to_le_bytes());
        body.extend_from_slice(peer.as_str().as_bytes());
        body.extend_from_slice(payload);
        self.replay_record(
            &body,
            sequence,
            record_size(peer.as_str().len(), payload.len())?,
        )?;
        // Any replay/write failure discards this unpublished candidate. No
        // partially reconstructed state can become the active journal owner.
        self.append_record(kind, peer, key, payload, now)
    }
}
