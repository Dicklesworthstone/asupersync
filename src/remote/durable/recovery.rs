//! Explicit recovery of an authenticated prefix into a caller-owned replacement.

use super::{
    Arc, DurableRemoteError, DurableRemoteJournal, DurableRemoteJournalStatus, File, Journal,
    JournalIo, SeekFrom, buffer, io, lock,
};

const COPY_BYTES: usize = 64 * 1024;

/// The exact authenticated prefix installed after incomplete-tail recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct DurableRemoteRecoveryReport {
    /// Observed source length, including the incomplete trailing record.
    pub source_bytes: u64,
    /// Authenticated prefix length copied unchanged into the replacement.
    pub committed_bytes: u64,
    /// Source bytes excluded from the replacement; the original is not truncated.
    pub discarded_tail_bytes: u64,
    /// Unchanged authenticated record count, including any existing clock floor.
    pub records: u64,
    /// Pending and terminal entries retained by the current in-process owner.
    pub retained_entries: usize,
}

impl DurableRemoteJournal {
    /// Restore append access after an authenticated reopen found an incomplete tail.
    ///
    /// This explicit operation accepts only [`DurableRemoteJournalStatus::ReadOnlyTail`].
    /// A poisoned owner must first be dropped and reopened; a complete corrupt
    /// record still makes that reopen fail. No live execution or reconciliation
    /// permit may remain. The caller must fence other journal owners and any
    /// external work whose terminal outcome will later require reconciliation.
    /// Recovery does not itself determine or cancel an external effect.
    ///
    /// The replacement must be a distinct, empty regular read/write file. The
    /// exact authenticated prefix is copied in bounded chunks, then completely
    /// re-authenticated and synced. Its configuration, sequence and chained head
    /// must match this owner. No bytes from the incomplete record are interpreted
    /// as an outcome. Every authenticated pending reservation and terminal result,
    /// including its original expiry and reserved completion capacity, survives.
    /// Existing wire and journal record encodings are unchanged.
    ///
    /// Both files remain exclusively locked through `publish`. After preparing
    /// the replacement, this method calls that callback exactly once. It must
    /// atomically replace the authoritative journal path with this replacement
    /// and durably sync its directory linkage before returning `Ok(())`. Do not
    /// expose the candidate early, mutate either file, or retain an old owner.
    /// No path authority, truncation or deletion is acquired by this method.
    ///
    /// Preparation failures leave the source untouched and unpublished. Source
    /// read/length uncertainty or a mismatched authenticated prefix poisons the
    /// owner. Immediately before publication, the source owner is also poisoned:
    /// a callback error or panic may follow a successful rename, so continuing
    /// requires reopening the authoritative path. Success installs the already
    /// synced file without any further fallible operation.
    ///
    /// Recovery neither advances the clock nor expires entries. Existing clock
    /// floor records and this owner's later in-process observations are retained.
    /// As with ordinary reopen, observations not persisted in a record do not
    /// survive a subsequent process restart. No additional record capacity is
    /// consumed, even when all remaining capacity is reserved for pending work.
    /// This is not detection of rollback to an older authenticated file.
    ///
    /// Temporary memory consists of one bounded replay index/cache plus a copy
    /// buffer of at most 64 KiB and the existing decoder's record buffers. All
    /// file work and publication are synchronous; async callers should use
    /// [`super::DurableRemoteComputation::recover_tail`].
    pub fn recover_tail(
        &mut self,
        replacement: File,
        publish: impl FnOnce() -> io::Result<()>,
    ) -> Result<DurableRemoteRecoveryReport, DurableRemoteError> {
        lock(&replacement)?;
        self.core.recover_tail(replacement, publish)
    }
}

impl<F: JournalIo> Journal<F> {
    pub(super) fn recover_tail(
        &mut self,
        mut replacement: F,
        publish: impl FnOnce() -> io::Result<()>,
    ) -> Result<DurableRemoteRecoveryReport, DurableRemoteError> {
        if self.status != DurableRemoteJournalStatus::ReadOnlyTail {
            return Err(DurableRemoteError::NotWritable(self.status));
        }
        if Arc::strong_count(&self.instance) != 1 {
            return Err(DurableRemoteError::Busy);
        }
        let source_bytes = self
            .read_only_source_len
            .ok_or(DurableRemoteError::Format)?;
        let discarded_tail_bytes = source_bytes
            .checked_sub(self.offset)
            .filter(|bytes| *bytes != 0)
            .ok_or(DurableRemoteError::Format)?;
        self.check_recovery_source(source_bytes)?;
        if replacement.length()? != 0 {
            return Err(DurableRemoteError::NotEmpty);
        }
        replacement.seek(SeekFrom::Start(0))?;

        let capacity = self.offset.min(COPY_BYTES as u64) as usize;
        let mut bytes = buffer(capacity)?;
        bytes.resize(capacity, 0);
        self.status = DurableRemoteJournalStatus::Poisoned;
        self.file.seek(SeekFrom::Start(0))?;
        self.status = DurableRemoteJournalStatus::ReadOnlyTail;
        let mut remaining = self.offset;
        while remaining != 0 {
            let count = remaining.min(capacity as u64) as usize;
            self.status = DurableRemoteJournalStatus::Poisoned;
            self.file.read_exact(&mut bytes[..count])?;
            self.status = DurableRemoteJournalStatus::ReadOnlyTail;
            replacement.write_all(&bytes[..count])?;
            remaining -= count as u64;
        }
        drop(bytes);

        // Reuse the full decoder instead of trusting a copy or merely checking
        // its length. Open authenticates every record and syncs before returning.
        let recovered = match Self::open(replacement, self.config.clone()) {
            Ok(recovered) => recovered,
            Err(error) => {
                if !matches!(
                    &error,
                    DurableRemoteError::Io(_) | DurableRemoteError::Allocation
                ) {
                    self.status = DurableRemoteJournalStatus::Poisoned;
                }
                return Err(error);
            }
        };
        if recovered.status != DurableRemoteJournalStatus::Writable
            || recovered.offset != self.offset
            || recovered.sequence != self.sequence
            || recovered.last != self.last
            || recovered.last_time > self.last_time
        {
            self.status = DurableRemoteJournalStatus::Poisoned;
            return Err(DurableRemoteError::Changed);
        }
        self.check_recovery_source(source_bytes)?;
        let report = DurableRemoteRecoveryReport {
            source_bytes,
            committed_bytes: self.offset,
            discarded_tail_bytes,
            records: self.sequence,
            retained_entries: self.entries.len(),
        };
        self.status = DurableRemoteJournalStatus::Poisoned;
        publish()?;
        // Keep this owner's logical state, including transient clock/cache
        // observations. The candidate was replayed only to verify its bytes.
        self.file = recovered.file;
        self.read_only_source_len = None;
        self.status = DurableRemoteJournalStatus::Writable;
        Ok(report)
    }

    fn check_recovery_source(&mut self, source_bytes: u64) -> Result<(), DurableRemoteError> {
        self.status = DurableRemoteJournalStatus::Poisoned;
        if self.file.length()? != source_bytes {
            return Err(DurableRemoteError::Changed);
        }
        self.status = DurableRemoteJournalStatus::ReadOnlyTail;
        Ok(())
    }
}
