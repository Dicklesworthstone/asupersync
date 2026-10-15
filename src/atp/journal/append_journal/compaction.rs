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

    // Legacy retention may leave a nonzero first sequence. Within the retained
    // interval, however, a missing sequence could be a cancellation or commit
    // boundary. Copies in another generation may fill a gap; invented records
    // and a sorted map cannot. Check neighboring keys, not the numeric extent.
    fn validate_sequence_span(&self) -> Result<(), JournalError> {
        let mut previous: Option<u64> = None;
        for sequence in self.entries.keys().copied() {
            if let Some(previous) = previous
                && previous.checked_add(1) != Some(sequence)
            {
                return Err(JournalError::Deserialization(format!(
                    "journal sequence gap after {previous} before {sequence}",
                )));
            }
            previous = Some(sequence);
        }
        Ok(())
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
        let generations = match self.discover_storage_generations(frontier) {
            Ok(generations) => generations,
            Err(error) => return Outcome::Err(error),
        };
        self.read_generation_history(generations)
    }

    // Keep actual directory entries attached to discovery until their canonical
    // spelling and regular-file kind are checked. Parsing only a number and
    // reconstructing a different path can silently omit a terminal generation.
    fn discover_storage_generations(&self, frontier: Option<u64>) -> Result<Vec<u64>, JournalError> {
        let entries = std::fs::read_dir(&self.config.base_dir)
            .map_err(|error| JournalError::DirectoryRead(error.to_string()))?;
        let mut generations = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| JournalError::DirectoryRead(error.to_string()))?;
            let name = entry.file_name();
            let Some(generation) = name.to_str().and_then(parse_journal_generation) else {
                continue; // Unrelated files are not journal generations.
            };
            if frontier.is_some_and(|frontier| generation > frontier) {
                continue; // An existing reader does not advance its read frontier.
            }
            if name.as_os_str() != std::ffi::OsStr::new(&journal_file_name(generation)) {
                return Err(JournalError::Deserialization(format!(
                    "noncanonical journal filename for generation {generation}",
                )));
            }
            let kind = entry.file_type()
                .map_err(|error| JournalError::ReadFailure(error.to_string()))?;
            // Do not follow links (including dangling links), block opening a
            // FIFO, or interpret a directory/device/socket as empty history.
            // This is a discovery check, not protection against later path races.
            if !kind.is_file() {
                return Err(JournalError::ReadFailure(format!(
                    "journal generation {generation} is not a regular directory entry",
                )));
            }
            generations.push(generation);
        }
        generations.sort_unstable();
        // Canonical numeric spellings are unique; aliases are refused, not deduped.
        Ok(generations)
    }

    // The production caller supplies the just-discovered ordered generations.
    // Keeping the read boundary separate makes disappearance-after-listing
    // testable without deleting files or depending on a scheduling race.
    fn read_generation_history(&self, generations: Vec<u64>) -> Outcome<StorageHistory, JournalError> {
        let latest = generations.last().copied().unwrap_or(0);
        let mut history = StorageHistory {
            entries: BTreeMap::new(), generations, damaged: HashSet::new(), base_bytes: 0,
        };
        for generation in &history.generations {
            let path = journal_file_path(&self.config.base_dir, *generation);
            // Every enumerated generation must be read successfully. A missing
            // path is missing evidence, never permission to reuse an older prefix.
            let (entries, damaged) = match self.read_entries_from_file(&path) {
                Outcome::Ok(result) => result,
                Outcome::Err(error) => return Outcome::Err(error),
                Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
                Outcome::Panicked(payload) => return Outcome::Panicked(payload),
            };
            if damaged { history.damaged.insert(*generation); }
            let mut file_bytes = 0_u64;
            let mut previous_sequence: Option<u64> = None;
            for entry in entries {
                // The writer and snapshots emit strictly increasing sequences.
                // Identical copies across generations are expected; duplicates
                // or reversed frames WITHIN one generation are not snapshots.
                // Reject before BTreeMap sorting/deduplication can conceal them.
                if previous_sequence.is_some_and(|previous| entry.sequence <= previous) {
                    return Outcome::Err(JournalError::Deserialization(format!(
                        "journal generation {generation} has non-increasing sequence {}",
                        entry.sequence,
                    )));
                }
                previous_sequence = Some(entry.sequence);
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
        if let Err(error) = history.validate_sequence_span() {
            return Outcome::Err(error);
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

#[cfg(test)]
mod discovery_tests {
    #[allow(clippy::wildcard_imports)]
    use super::*;

    fn config(base: &Path) -> JournalConfig {
        JournalConfig {
            base_dir: base.to_owned(),
            force_sync: false,
            max_journal_size: u64::MAX,
            max_generations: 0,
            ..JournalConfig::default()
        }
    }

    fn key() -> AuthKey { AuthKey::from_seed(42) }

    fn accepted() -> JournalRecord {
        JournalRecord::Accept {
            transfer_id: "discovery".to_owned(), peer_id: "peer".to_owned(),
            timestamp: 1, auth_tag: AuthenticationTag::zero(),
        }
    }

    fn cancelled() -> JournalRecord {
        JournalRecord::Cancellation {
            transfer_id: "discovery".to_owned(), reason: "terminal evidence".to_owned(),
            timestamp: 2, auth_tag: AuthenticationTag::zero(),
        }
    }

    fn fixture(path: &Path, records: &[(u64, JournalRecord)]) -> Vec<u8> {
        let mut file = OpenOptions::new().create_new(true).write(true).open(path).unwrap();
        for (sequence, record) in records {
            let entry = JournalEntry::try_new(*sequence, record.clone().with_signature(&key())).unwrap();
            write_entry(&mut file, &entry).unwrap();
        }
        file.sync_all().unwrap();
        std::fs::read(path).unwrap()
    }

    #[test]
    fn noncanonical_generations_cannot_hide_terminal_records_or_alias_a_real_generation() {
        for alias in ["journal_gen_1.dat", "journal_gen_0000001.dat"] {
            for canonical_exists in [false, true] {
                let directory = tempfile::tempdir().unwrap();
                let base = directory.path();
                let original = fixture(&journal_file_path(base, 0), &[(0, accepted())]);
                let terminal = fixture(&base.join(alias), &[(1, cancelled())]);
                if canonical_exists {
                    fixture(&journal_file_path(base, 1), &[]);
                }
                assert!(matches!(AppendJournal::new(config(base), key()),
                    Outcome::Err(JournalError::Deserialization(reason)) if reason.contains("noncanonical")));
                assert_eq!(std::fs::read(journal_file_path(base, 0)).unwrap(), original);
                assert_eq!(std::fs::read(base.join(alias)).unwrap(), terminal);
                if canonical_exists {
                    assert!(std::fs::read(journal_file_path(base, 1)).unwrap().is_empty());
                } else {
                    assert!(!journal_file_path(base, 1).exists());
                }
                assert!(!journal_file_path(base, 2).exists());
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn generation_symlinks_are_refused_without_following_or_repairing_them() {
        for kind in ["dangling", "regular-target", "self-loop"] {
            let directory = tempfile::tempdir().unwrap();
            let base = directory.path();
            let original = fixture(&journal_file_path(base, 0), &[(0, accepted())]);
            let target = base.join("separate-evidence");
            let target_bytes = if kind == "regular-target" {
                Some(fixture(&target, &[(1, cancelled())]))
            } else { None };
            let link = journal_file_path(base, 1);
            let selected = if kind == "self-loop" { link.clone() } else { target.clone() };
            std::os::unix::fs::symlink(&selected, &link).unwrap();
            assert!(matches!(AppendJournal::new(config(base), key()),
                Outcome::Err(JournalError::ReadFailure(reason)) if reason.contains("regular")));
            assert_eq!(std::fs::read(journal_file_path(base, 0)).unwrap(), original);
            assert!(std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
            assert_eq!(std::fs::read_link(link).unwrap(), selected);
            if let Some(bytes) = target_bytes { assert_eq!(std::fs::read(target).unwrap(), bytes); }
            else { assert!(!target.exists()); }
            assert!(!journal_file_path(base, 2).exists());
        }
    }

    #[test]
    fn a_directory_named_as_a_generation_is_not_opened_as_a_journal() {
        let directory = tempfile::tempdir().unwrap();
        let base = directory.path();
        let original = fixture(&journal_file_path(base, 0), &[(0, accepted())]);
        std::fs::create_dir(journal_file_path(base, 1)).unwrap();
        assert!(matches!(AppendJournal::new(config(base), key()),
            Outcome::Err(JournalError::ReadFailure(reason)) if reason.contains("regular")));
        assert_eq!(std::fs::read(journal_file_path(base, 0)).unwrap(), original);
        assert!(journal_file_path(base, 1).is_dir());
        assert!(!journal_file_path(base, 2).exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_socket_named_as_a_generation_is_refused_during_discovery() {
        let directory = tempfile::tempdir().unwrap();
        let base = directory.path();
        fixture(&journal_file_path(base, 0), &[(0, accepted())]);
        let _socket = std::os::unix::net::UnixListener::bind(journal_file_path(base, 1)).unwrap();
        assert!(matches!(AppendJournal::new(config(base), key()),
            Outcome::Err(JournalError::ReadFailure(reason)) if reason.contains("regular")));
        assert!(!journal_file_path(base, 2).exists());
    }

    #[test]
    fn disappearance_after_discovery_is_not_a_successful_partial_history() {
        let directory = tempfile::tempdir().unwrap();
        let base = directory.path();
        let original = fixture(&journal_file_path(base, 0), &[(0, accepted())]);
        let journal = AppendJournal::new(config(base), key()).unwrap();
        // Pass the exact snapshot a scan would return before generation 1 was
        // lost. No timed race or destructive fixture operation is necessary.
        assert!(matches!(journal.read_generation_history(vec![0, 1]),
            Outcome::Err(JournalError::FileOpen(_))));
        assert_eq!(std::fs::read(journal_file_path(base, 0)).unwrap(), original);
        assert!(!journal_file_path(base, 1).exists());
    }

    #[test]
    fn compaction_discovery_failure_fences_the_writer_without_retiring_evidence() {
        let directory = tempfile::tempdir().unwrap();
        let base = directory.path();
        let mut journal = AppendJournal::new(config(base), key()).unwrap();
        journal.append(accepted()).unwrap();
        journal.append(cancelled()).unwrap();
        journal.flush().unwrap();
        let original = std::fs::read(journal_file_path(base, 0)).unwrap();
        let alias = base.join("journal_gen_1.dat");
        let alias_bytes = fixture(&alias, &[(2, accepted())]);
        assert!(matches!(journal.compact(),
            Outcome::Err(JournalError::Deserialization(reason)) if reason.contains("noncanonical")));
        assert!(journal.get_resume_summary("discovery").is_err());
        assert!(journal.append(accepted()).is_err());
        assert_eq!(std::fs::read(journal_file_path(base, 0)).unwrap(), original);
        assert_eq!(std::fs::read(alias).unwrap(), alias_bytes);
        assert!(!journal_file_path(base, 1).exists());
    }

    #[test]
    fn bounded_frontier_and_identical_snapshot_copies_keep_their_existing_semantics() {
        let directory = tempfile::tempdir().unwrap();
        let base = directory.path();
        fixture(&journal_file_path(base, 0), &[(0, accepted())]);
        let original_reader = AppendJournal::new(config(base), key()).unwrap();
        let high = 1_u64 << 40;
        fixture(&journal_file_path(base, high), &[(0, accepted()), (1, cancelled())]);
        fixture(&base.join("journal_gen_1.dat.backup"), &[(2, accepted())]);
        std::fs::create_dir(base.join("not-a-journal")).unwrap();
        assert_eq!(original_reader.read_all_entries_from_disk().unwrap().len(), 1);
        let recovered = AppendJournal::new(config(base), key()).unwrap();
        assert_eq!(recovered.get_stats().generation, high);
        assert_eq!(recovered.read_all_entries_from_disk().unwrap().len(), 2);
        assert!(matches!(recovered.get_resume_summary("discovery").unwrap().status,
            TransferResumeStatus::Cancelled { reason } if reason == "terminal evidence"));
        // An older frontier stays scoped even if a later generation is invalid.
        fixture(&base.join("journal_gen_2.dat"), &[(2, accepted())]);
        assert_eq!(original_reader.read_all_entries_from_disk().unwrap().len(), 1);
        assert!(AppendJournal::new(config(base), key()).is_err());
    }

    #[test]
    fn reordered_and_duplicate_frames_cannot_be_normalized_into_valid_history() {
        let orders: &[&[u64]] = &[
            &[0, 1, 2], &[0, 2, 1], &[1, 0, 2], &[1, 2, 0],
            &[2, 0, 1], &[2, 1, 0], &[0, 1, 1, 2],
        ];
        for order in orders {
            let directory = tempfile::tempdir().unwrap();
            let base = directory.path();
            let records: Vec<_> = order.iter().map(|sequence| {
                (*sequence, if *sequence == 2 { cancelled() } else { accepted() })
            }).collect();
            let original = fixture(&journal_file_path(base, 0), &records);
            let recovered = AppendJournal::new(config(base), key());
            if *order == &[0_u64, 1, 2][..] {
                assert_eq!(recovered.unwrap().read_all_entries_from_disk().unwrap().len(), 3);
            } else {
                assert!(matches!(recovered,
                    Outcome::Err(JournalError::Deserialization(reason)) if reason.contains("non-increasing")));
            }
            assert_eq!(std::fs::read(journal_file_path(base, 0)).unwrap(), original);
            assert!(!journal_file_path(base, 1).exists());
        }
    }

    #[test]
    fn missing_interior_sequences_refuse_even_with_valid_signed_ordered_frames() {
        for split in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let base = directory.path();
            let first = if split { vec![(0, accepted())] }
                else { vec![(0, accepted()), (2, cancelled())] };
            let original = fixture(&journal_file_path(base, 0), &first);
            let last = if split {
                Some(fixture(&journal_file_path(base, 9), &[(2, cancelled())]))
            } else { None };
            assert!(matches!(AppendJournal::new(config(base), key()),
                Outcome::Err(JournalError::Deserialization(reason)) if reason.contains("sequence gap")));
            assert_eq!(std::fs::read(journal_file_path(base, 0)).unwrap(), original);
            if let Some(last) = last { assert_eq!(std::fs::read(journal_file_path(base, 9)).unwrap(), last); }
            assert!(!journal_file_path(base, 10).exists());
        }
    }

    #[test]
    fn other_generations_can_fill_snapshot_gaps_without_duplicate_replay() {
        let directory = tempfile::tempdir().unwrap();
        let base = directory.path();
        let original = fixture(&journal_file_path(base, 0), &[
            (0, accepted()), (1, accepted()), (2, accepted()), (3, cancelled()),
        ]);
        fixture(&journal_file_path(base, 1), &[(0, accepted()), (2, accepted())]);
        let mut recovered = AppendJournal::new(config(base), key()).unwrap();
        assert_eq!(recovered.get_stats().sequence, 4);
        assert_eq!(recovered.read_all_entries_from_disk().unwrap().len(), 4);
        assert!(matches!(recovered.get_resume_summary("discovery").unwrap().status,
            TransferResumeStatus::Cancelled { .. }));
        let other = JournalRecord::Accept {
            transfer_id: "independent".to_owned(), peer_id: "peer".to_owned(),
            timestamp: 4, auth_tag: AuthenticationTag::zero(),
        };
        assert_eq!(recovered.append(other).unwrap(), 4);
        recovered.flush().unwrap();
        assert_eq!(std::fs::read(journal_file_path(base, 0)).unwrap(), original);
        drop(recovered);
        let mut reopened = AppendJournal::new(config(base), key()).unwrap();
        assert_eq!(reopened.read_all_entries_from_disk().unwrap().len(), 5);
        reopened.compact().unwrap();
        drop(reopened);
        let reopened = AppendJournal::new(config(base), key()).unwrap();
        assert_eq!(reopened.read_all_entries_from_disk().unwrap().len(), 6);
        assert!(matches!(reopened.get_resume_summary("discovery").unwrap().status,
            TransferResumeStatus::Cancelled { .. }));
        assert_eq!(reopened.get_transfer_entries("independent").unwrap().len(), 1);
    }

    #[test]
    fn nonzero_retained_origins_and_high_sequence_boundaries_do_not_expand_the_span() {
        for origin in [17, 1_u64 << 40, u64::MAX - 2] {
            let directory = tempfile::tempdir().unwrap();
            let base = directory.path();
            fixture(&journal_file_path(base, 0), &[(origin, accepted()), (origin + 1, cancelled())]);
            let recovered = AppendJournal::new(config(base), key()).unwrap();
            assert_eq!(recovered.get_stats().sequence, origin + 2);
            assert_eq!(recovered.read_all_entries_from_disk().unwrap().len(), 2);
        }
        let directory = tempfile::tempdir().unwrap();
        fixture(&journal_file_path(directory.path(), 0), &[(0, accepted()), (u64::MAX, cancelled())]);
        assert!(matches!(AppendJournal::new(config(directory.path()), key()),
            Outcome::Err(JournalError::Deserialization(reason)) if reason.contains("sequence gap")));
        let directory = tempfile::tempdir().unwrap();
        fixture(&journal_file_path(directory.path(), 0), &[(u64::MAX, accepted())]);
        assert!(matches!(AppendJournal::new(config(directory.path()), key()),
            Outcome::Err(JournalError::Deserialization(reason)) if reason.contains("exhausted")));
    }

    #[test]
    fn reordered_snapshot_discovered_after_open_cannot_authorize_retention() {
        let directory = tempfile::tempdir().unwrap();
        let base = directory.path();
        let original = fixture(&journal_file_path(base, 0), &[(0, accepted()), (1, cancelled())]);
        let snapshot_path = journal_file_path(base, 1);
        fixture(&snapshot_path, &[(0, accepted()), (1, cancelled())]);
        let mut journal = AppendJournal::new(config(base), key()).unwrap();
        let mut reversed = Vec::new();
        for (sequence, record) in [(1, cancelled()), (0, accepted())] {
            let entry = JournalEntry::try_new(sequence, record.with_signature(&key())).unwrap();
            storage::write_frame(&mut reversed, &entry.encode()).unwrap();
        }
        // Fault only a test-owned snapshot after the real reader has opened it.
        // The original generation remains available and is never deleted here.
        std::fs::write(&snapshot_path, &reversed).unwrap();
        assert!(matches!(journal.compact(),
            Outcome::Err(JournalError::Deserialization(reason)) if reason.contains("non-increasing")));
        assert!(journal.storage_failed);
        assert!(journal.get_resume_summary("discovery").is_err());
        assert_eq!(std::fs::read(journal_file_path(base, 0)).unwrap(), original);
        assert_eq!(std::fs::read(snapshot_path).unwrap(), reversed);
        assert!(!journal_file_path(base, 2).exists());
    }
}
