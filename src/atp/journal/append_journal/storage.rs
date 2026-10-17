//! Failure-aware journal storage. A failed frame is not a retryable buffer.

#[allow(clippy::wildcard_imports)]
use super::*;

/// Own the buffer until its complete storage result is known. `BufWriter`'s
/// ordinary destructor retries buffered writes; after an error or panic that
/// would perform additional unreported journal effects. Dismantle, never flush,
/// an abandoned buffer. Bytes already handed to the OS remain recovery evidence.
struct PendingWriter(Option<BufWriter<File>>);

impl PendingWriter {
    fn writer(&mut self) -> &mut BufWriter<File> {
        self.0.as_mut().expect("pending journal writer is present")
    }

    fn finish(mut self) -> BufWriter<File> {
        self.0.take().expect("pending journal writer is present")
    }
}

impl Drop for PendingWriter {
    fn drop(&mut self) {
        if let Some(writer) = self.0.take() {
            // into_parts performs no flush, including after a writer panic.
            drop(writer.into_parts());
        }
    }
}

pub(super) fn append_frame(
    writer: &mut BufWriter<File>,
    encoded: &[u8],
    force_sync: bool,
) -> Result<(), JournalError> {
    write_frame(writer, encoded)?;
    if force_sync {
        sync_writer_data(writer)
    } else {
        flush_writer_buffer(writer)
    }
}

// One canonical frame writer for appends and carry-forward copies. Durability
// belongs to the caller: compaction synchronizes the complete snapshot once.
pub(super) fn write_frame(writer: &mut impl Write, encoded: &[u8]) -> Result<(), JournalError> {
    let length = frame_length(encoded.len())?;
    writer.write_all(&length.to_le_bytes())
        .and_then(|()| writer.write_all(encoded))
        .map_err(|error| JournalError::WriteFailure(error.to_string()))
}

fn frame_length(length: usize) -> Result<u32, JournalError> {
    if length > MAX_JOURNAL_FRAME_BYTES {
        return Err(JournalError::Serialization(format!(
            "journal frame exceeds recovery limit of {MAX_JOURNAL_FRAME_BYTES} bytes: {length}",
        )));
    }
    checked_u32_len(length, "journal frame")
}

impl AppendJournal {
    pub(super) fn require_storage_ready(&self) -> Result<(), JournalError> {
        if self.storage_failed {
            Err(JournalError::WriteFailure(
                "journal storage outcome is unresolved; drop and reopen before mutation or resume"
                    .to_owned(),
            ))
        } else {
            Ok(())
        }
    }

    // The callback seam is private. Production always executes append_frame;
    // tests inject real partial/complete writes at this exact storage boundary.
    pub(super) fn append_with_storage(
        &mut self,
        record: JournalRecord,
        write: impl FnOnce(&mut BufWriter<File>, &[u8], bool) -> Result<(), JournalError>,
    ) -> Outcome<u64, JournalError> {
        if let Err(error) = self.require_storage_ready() {
            return Outcome::Err(error);
        }
        let Some(next_sequence) = self.sequence.checked_add(1) else {
            return Outcome::Err(JournalError::Serialization("journal sequence exhausted".to_owned()));
        };
        let is_boundary = matches!(record, JournalRecord::CompactionBoundary { .. });
        if let Err(error) = validate_record_lengths(&record) {
            return Outcome::Err(error);
        }
        let entry = match JournalEntry::try_new(self.sequence, record.with_signature(&self.auth_key)) {
            Ok(entry) => entry,
            Err(error) => return Outcome::Err(error),
        };
        let encoded = entry.encode();
        if let Err(error) = frame_length(encoded.len()) {
            return Outcome::Err(error);
        }
        // All effect-free refusal happens before creating a generation file.
        match self.ensure_writer() {
            Outcome::Ok(()) => {}
            Outcome::Err(error) => return Outcome::Err(error),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }
        self.storage_failed = true;
        let Some(writer) = self.writer.take() else {
            return Outcome::Err(JournalError::WriteFailure("journal writer is absent".to_owned()));
        };
        let mut pending = PendingWriter(Some(writer));
        if let Err(error) = write(pending.writer(), &encoded, self.config.force_sync) {
            return Outcome::Err(error);
        }
        self.writer = Some(pending.finish());
        let current_sequence = self.sequence;
        self.sequence = next_sequence;
        self.index_transfer_entry(&entry);
        self.recent_entries.push_back(entry);
        if self.recent_entries.len() > self.cache_limit {
            self.recent_entries.pop_front();
        }
        // A panic during index updates also leaves the instance fenced.
        self.storage_failed = false;
        if !is_boundary {
            match self.should_compact() {
                Outcome::Ok(true) => match self.trigger_compaction() {
                    Outcome::Ok(()) => {}
                    Outcome::Err(error) => return Outcome::Err(error),
                    Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
                    Outcome::Panicked(payload) => return Outcome::Panicked(payload),
                },
                Outcome::Ok(false) => {}
                Outcome::Err(error) => return Outcome::Err(error),
                Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
                Outcome::Panicked(payload) => return Outcome::Panicked(payload),
            }
        }
        Outcome::Ok(current_sequence)
    }

    pub(super) fn flush_with_storage(
        &mut self,
        sync: impl FnOnce(&mut BufWriter<File>) -> Result<(), JournalError>,
    ) -> Outcome<(), JournalError> {
        if let Err(error) = self.require_storage_ready() {
            return Outcome::Err(error);
        }
        let Some(writer) = self.writer.take() else {
            return Outcome::Ok(());
        };
        self.storage_failed = true;
        let mut pending = PendingWriter(Some(writer));
        if let Err(error) = sync(pending.writer()) {
            return Outcome::Err(error);
        }
        self.writer = Some(pending.finish());
        self.storage_failed = false;
        Outcome::Ok(())
    }
}

#[cfg(test)]
#[path = "storage_inline_tests.rs"]
mod tests;
