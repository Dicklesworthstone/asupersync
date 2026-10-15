//! Carry-forward generations: retention must never erase the only history.
//!
//! Reuse the journal's frame codec and signed records. A new generation is
//! independently created and fully synced before old files become disposable.
//! Incomplete copies coexist with their originals; readers merge equal sequence
//! copies and refuse contradictory ones. This is single-writer host filesystem
//! code, not a concurrent-writer lock or a cryptographic log-completeness proof.

#[allow(clippy::wildcard_imports)]
use super::*;
use std::collections::{BTreeMap, btree_map::Entry};
use std::io;

pub(super) struct StorageHistory {
    pub(super) entries: BTreeMap<u64, JournalEntry>,
    generations: Vec<u64>,
    damaged: HashSet<u64>,
    base_bytes: u64,
}

impl StorageHistory {
    fn next_sequence(&self) -> Result<u64, JournalError> {
        match self.entries.last_key_value() {
            Some((last, _)) => last.checked_add(1).ok_or_else(|| {
                JournalError::Deserialization("recovered journal sequence exhausted".to_owned())
            }),
            None => Ok(0),
        }
    }

    fn latest_generation(&self) -> u64 {
        self.generations.last().copied().unwrap_or(0)
    }
}

fn same_entry(a: &JournalEntry, b: &JournalEntry) -> bool {
    a.sequence == b.sequence && a.record == b.record
        && a.checksum == b.checksum && a.entry_size == b.entry_size
}

pub(super) fn write_entry(file: &mut File, entry: &JournalEntry) -> Result<(), JournalError> {
    storage::write_frame(file, &entry.encode())
}

impl AppendJournal {
    pub(super) fn read_storage_history(&self, frontier: Option<u64>) -> Outcome<StorageHistory, JournalError> {
        let mut generations = match self.discover_generations() {
            Ok(generations) => generations,
            Err(error) => return Outcome::Err(error),
        };
        if let Some(frontier) = frontier {
            generations.retain(|generation| *generation <= frontier);
        }
        let latest = generations.last().copied().unwrap_or(0);
        let mut history = StorageHistory {
            entries: BTreeMap::new(), generations, damaged: HashSet::new(), base_bytes: 0,
        };
        for generation in &history.generations {
            let path = journal_file_path(&self.config.base_dir, *generation);
            match path.try_exists() {
                Ok(true) => {}
                Ok(false) => continue,
                Err(error) => return Outcome::Err(JournalError::ReadFailure(error.to_string())),
            }
            let (entries, damaged) = match self.read_entries_from_file(&path) {
                Outcome::Ok(result) => result,
                Outcome::Err(error) => return Outcome::Err(error),
                Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
                Outcome::Panicked(payload) => return Outcome::Panicked(payload),
            };
            if damaged { history.damaged.insert(*generation); }
            let mut file_bytes = 0_u64;
            for entry in entries {
                file_bytes = match file_bytes.checked_add(20 + u64::from(entry.entry_size)) {
                    Some(bytes) => bytes,
                    None => return Outcome::Err(JournalError::Deserialization(
                        "journal generation length overflow".to_owned(),
                    )),
                };
                // This marker is only growth accounting, never permission to
                // ignore earlier generations or declare the log complete. Old
                // rotation markers name the NEXT generation, not their own file.
                if *generation == latest
                    && matches!(&entry.record, JournalRecord::CompactionBoundary {
                        generation: target, compacted_up_to_sequence, ..
                    } if target == generation && *compacted_up_to_sequence == entry.sequence)
                    && entry.record.verify_signature(&self.auth_key)
                {
                    history.base_bytes = file_bytes;
                }
                match history.entries.entry(entry.sequence) {
                    Entry::Vacant(slot) => { slot.insert(entry); }
                    Entry::Occupied(slot) if same_entry(slot.get(), &entry) => {}
                    Entry::Occupied(_) => return Outcome::Err(JournalError::Deserialization(
                        format!("conflicting journal copies at sequence {}", entry.sequence),
                    )),
                }
            }
        }
        Outcome::Ok(history)
    }

    pub(super) fn recover_storage_history(&mut self) -> Outcome<(), JournalError> {
        let history = match self.read_storage_history(None) {
            Outcome::Ok(history) => history,
            Outcome::Err(error) => return Outcome::Err(error),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        };
        let sequence = match history.next_sequence() {
            Ok(sequence) => sequence,
            Err(error) => return Outcome::Err(error),
        };
        let latest = history.latest_generation();
        let (generation, base_bytes) = if history.damaged.contains(&latest) {
            let Some(next) = latest.checked_add(1) else {
                return Outcome::Err(JournalError::Deserialization(
                    "cannot rotate corrupted journal: generation exhausted".to_owned(),
                ));
            };
            (next, 0)
        } else {
            (latest, history.base_bytes)
        };
        // Prepare complete replacement indexes before changing the live fields.
        let (recent, transfers) = self.index_history(history.entries);
        self.recent_entries = recent;
        self.transfer_entries = transfers;
        self.generation = generation;
        self.generation_base_bytes = base_bytes;
        self.sequence = sequence;
        Outcome::Ok(())
    }

    fn index_history(&self, entries: BTreeMap<u64, JournalEntry>)
        -> (VecDeque<JournalEntry>, HashMap<String, Vec<JournalEntry>>)
    {
        let mut recent = VecDeque::new();
        let mut transfers: HashMap<String, Vec<JournalEntry>> = HashMap::new();
        for entry in entries.into_values() {
            if let Some(id) = entry.record.transfer_id() {
                transfers.entry(id.to_owned()).or_default().push(entry.clone());
            }
            recent.push_back(entry);
            if recent.len() > self.cache_limit { recent.pop_front(); }
        }
        (recent, transfers)
    }

    // Private fault seams retain the actual codec, files, publication ordering
    // and retention driver. Production supplies only the three functions in
    // trigger_compaction; no caller can authorize an unsynchronized snapshot.
    pub(super) fn compact_with_storage(
        &mut self,
        write: impl FnMut(&mut File, &JournalEntry) -> Result<(), JournalError>,
        sync: impl FnOnce(&File) -> io::Result<()>,
        sync_directory: impl FnOnce(&Path) -> Result<(), JournalError>,
    ) -> Outcome<(), JournalError> {
        if let Err(error) = self.require_storage_ready() { return Outcome::Err(error); }
        match self.flush() {
            Outcome::Ok(()) => {}
            Outcome::Err(error) => return Outcome::Err(error),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }
        match self.carry_forward(write, sync, sync_directory) {
            Ok(()) => Outcome::Ok(()),
            Err(error) => {
                // Even an already persisted caller append may precede a failed
                // automatic rotation. Reopen to reconcile, never repeat it here.
                self.storage_failed = true;
                Outcome::Err(error)
            }
        }
    }

    fn carry_forward(
        &mut self,
        mut write: impl FnMut(&mut File, &JournalEntry) -> Result<(), JournalError>,
        sync: impl FnOnce(&File) -> io::Result<()>,
        sync_directory: impl FnOnce(&Path) -> Result<(), JournalError>,
    ) -> Result<(), JournalError> {
        let failed = |message: &str| JournalError::CompactionFailed(message.to_owned());
        let next_generation = self.generation.checked_add(1)
            .ok_or_else(|| failed("journal generation overflow"))?;
        let next_sequence = self.sequence.checked_add(1)
            .ok_or_else(|| failed("journal sequence exhausted"))?;
        let mut history = match self.read_storage_history(None) {
            Outcome::Ok(history) => history,
            Outcome::Err(error) => return Err(error),
            Outcome::Cancelled(_) | Outcome::Panicked(_) => return Err(failed("journal scan did not complete")),
        };
        if history.latest_generation() > self.generation || history.next_sequence()? != self.sequence {
            return Err(failed("journal disk frontier changed; reopen before compaction"));
        }
        // Do not copy an unauthenticated record and then delete its original.
        // Reopening still permits diagnostic reads with a different key, but
        // destructive retention requires authentication of EVERY carried entry.
        for entry in history.entries.values() {
            if !entry.record.verify_signature(&self.auth_key) || !entry.validate_checksum() {
                return Err(failed("journal history authentication failed"));
            }
            if entry.record.encode_payload().len() != entry.entry_size as usize {
                return Err(failed("journal entry length differs from its canonical payload"));
            }
        }
        for entry in self.transfer_entries.values().flatten() {
            if !history.entries.get(&entry.sequence).is_some_and(|disk| same_entry(disk, entry)) {
                return Err(failed("journal history is missing indexed transfer evidence"));
            }
        }
        let boundary = JournalEntry::try_new(self.sequence, JournalRecord::signed_compaction_boundary(
            next_generation, self.sequence,
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
            &self.auth_key,
        ))?;
        history.entries.insert(boundary.sequence, boundary);
        let path = journal_file_path(&self.config.base_dir, next_generation);
        // No existing generation is opened for append or truncated. An empty or
        // partially copied candidate can be discovered after a crash, but the
        // original generations remain intact until both barriers below settle.
        self.storage_failed = true;
        if let Some(writer) = self.writer.take() { drop(writer.into_parts()); }
        let mut file = OpenOptions::new().create_new(true).append(true).open(&path)
            .map_err(|error| JournalError::FileOpen(error.to_string()))?;
        let mut snapshot_bytes = 0_u64;
        for entry in history.entries.values() {
            write(&mut file, entry)?;
            snapshot_bytes = snapshot_bytes.checked_add(20 + u64::from(entry.entry_size))
                .ok_or_else(|| failed("compacted generation length overflow"))?;
        }
        sync(&file).map_err(|error| JournalError::SyncFailure(error.to_string()))?;
        sync_directory(&self.config.base_dir)?;
        let damaged = history.damaged;
        let (recent, transfers) = self.index_history(history.entries);
        self.writer = Some(BufWriter::with_capacity(self.config.write_buffer_size, file));
        self.current_file = Some(path);
        self.generation = next_generation;
        self.generation_base_bytes = snapshot_bytes;
        self.sequence = next_sequence;
        self.recent_entries = recent;
        self.transfer_entries = transfers;
        // This is the only path to destructive retention. The new generation
        // contains every complete prior record, including terminal evidence.
        self.cleanup_snapshotted_generations(&damaged)?;
        self.storage_failed = false;
        Ok(())
    }

    fn cleanup_snapshotted_generations(&self, damaged: &HashSet<u64>) -> Result<(), JournalError> {
        let cutoff = self.generation.saturating_sub(u64::from(self.config.max_generations));
        for generation in self.discover_generations()?.into_iter().take_while(|generation| *generation < cutoff) {
            if damaged.contains(&generation) { continue; } // Retain torn-frame evidence.
            let path = journal_file_path(&self.config.base_dir, generation);
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    // Keeping extra copies is safe. Preserve the established
                    // best-effort retention policy rather than sacrificing data.
                    if self.config.enable_detailed_logs {
                        eprintln!("Failed to remove old journal generation {generation}: {error}");
                    }
                }
            }
        }
        sync_journal_directory(&self.config.base_dir)
    }
}

#[cfg(test)]
mod tests;
