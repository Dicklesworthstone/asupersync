//! Revalidate the recorded local prefix before negotiating a receive restart.

use super::{ScopedSparseWriter, ScopedWriterResult, SparseWriter, SparseWriterError};
use crate::atp::journal::sparse_writer::VerificationState;
use crate::cx::Cx;
use crate::cx::cap::{CapSetRuntimeMask, HasIo, HasSpawn};
use crate::types::Outcome;

impl ScopedSparseWriter {
    /// Re-read recorded chunks and return the contiguous local receive offset.
    ///
    /// Call after a failed receive has terminated or its owner has been dropped.
    /// The shared admission gate waits for any earlier disk operation to finish,
    /// so this observes actual successful write receipts, not a borrowing wait's
    /// possibly stale `accepted_bytes` counter. Every retained chunk is rehashed
    /// on the existing blocking pool before its bytes count toward the offset.
    ///
    /// This is an in-process observation, not a reservation, authenticated sender
    /// proof, or durable crash-recovery checkpoint. It requires this writer's
    /// original live ledger and declared size. A fresh writer without a size,
    /// noncontiguous receipts, corrupt/truncated storage, cancellation, or sealed
    /// publication refuses. Detected inconsistency invalidates old verification;
    /// it never changes bytes, truncates a file, or repairs the receipt ledger.
    ///
    /// Another clone can change the writer after this call returns. A resumed
    /// receive must revalidate the expected offset while holding admission.
    /// Work is proportional to the recorded prefix; a running filesystem call
    /// is not preempted by cancellation. Host pathname races remain out of scope.
    pub async fn checked_receive_offset<Caps>(&self, cx: &Cx<Caps>) -> ScopedWriterResult<u64>
    where
        Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
    {
        self.run(cx, |writer| match checked_prefix(writer) {
            Ok(offset) => Outcome::Ok(offset),
            Err(error) => Outcome::Err(error),
        })
        .await
    }
}

pub(super) fn checked_prefix(writer: &SparseWriter) -> Result<u64, SparseWriterError> {
    let _operation = writer.operation.lock();
    let mut state = writer.lock_state();
    SparseWriter::require_accepting(&state)?;
    let result = (|| {
        let invalid = |message: &str| SparseWriterError::VerificationFailed(message.to_owned());
        let length = state.expected_size
            .ok_or_else(|| invalid("receive checkpoint requires a declared size"))?;
        let mut offset = 0_u64;
        for (start, chunk) in &state.written_chunks {
            if *start != offset || chunk.offset != *start || chunk.size == 0 {
                return Err(invalid("receive checkpoint requires contiguous write receipts"));
            }
            offset = offset.checked_add(chunk.size)
                .filter(|end| *end <= length)
                .ok_or_else(|| invalid("receive checkpoint range exceeds the declared size"))?;
        }
        if state.range_tracker.total_bytes() != offset
            || !state.range_tracker.is_contiguous_to(offset)
        {
            return Err(invalid("receive checkpoint ranges disagree with write receipts"));
        }
        let Some(file) = state.temp_file.as_ref() else {
            if offset == 0 && state.temp_path.is_none() {
                return Ok(offset);
            }
            return Err(SparseWriterError::NoTempFile);
        };
        if state.temp_path.is_none() {
            return Err(SparseWriterError::NoTempFile);
        }
        let file_length = file.metadata()
            .map_err(|error| SparseWriterError::VerificationFailed(error.to_string()))?.len();
        // Preallocation and an unreceipted partial write may extend past offset.
        // Those bytes do not count as received and must be supplied again.
        if file_length < offset || file_length > length {
            return Err(invalid("receive checkpoint storage length is inconsistent"));
        }
        let mut file = file.try_clone()
            .map_err(|error| SparseWriterError::VerificationFailed(error.to_string()))?;
        for (start, chunk) in &state.written_chunks {
            if SparseWriter::hash_file_range(&mut file, *start, chunk.size)? != chunk.hash {
                return Err(invalid("receive checkpoint chunk hash mismatch"));
            }
        }
        Ok(offset)
    })();
    if let Err(error) = &result {
        state.verification_state = VerificationState::Failed { reason: error.to_string() };
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atp::journal::{CommitPolicy, SparseWriterConfig, WriteOptions};
    use crate::atp::manifest::Manifest;
    use crate::atp::object::{MetadataPolicy, Object, ObjectGraph};
    use crate::runtime::{RootDrainOutcome, Runtime, RuntimeBuilder};
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;

    fn runtime(workers: usize) -> Runtime {
        let builder = if workers == 1 { RuntimeBuilder::current_thread() }
            else { RuntimeBuilder::new().worker_threads(workers) };
        builder.blocking_threads(1, 2).build().unwrap()
    }

    fn drained(runtime: &Runtime) {
        let report = runtime.shutdown_drained(Duration::from_secs(5));
        assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
        assert_eq!(report.live_tasks, 0);
        assert_eq!(report.pending_spawns, 0);
        assert_eq!(report.pending_obligations, 0);
    }

    async fn prepared(cx: &Cx, path: PathBuf) -> (ScopedSparseWriter, Arc<Manifest>) {
        let object = Object::file(b"abcdefgh".to_vec());
        let id = object.id.clone();
        let mut graph = ObjectGraph::new();
        graph.add_root(object).unwrap();
        let manifest = Arc::new(Manifest::from_graph(&graph, MetadataPolicy::portable()).unwrap());
        let writer = ScopedSparseWriter::new(cx, id, path, SparseWriterConfig {
            enable_preallocation: false,
            commit_policy: CommitPolicy::AtomicRename,
            ..SparseWriterConfig::default()
        }).await.unwrap().unwrap();
        writer.set_expected_size(cx, 8).await.unwrap().unwrap();
        (writer, manifest)
    }

    #[test]
    fn public_offset_rehashes_exact_receipts_on_both_native_schedulers() {
        for workers in [1, 2] {
            let runtime = runtime(workers);
            let directory = tempfile::tempdir().unwrap();
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let (writer, _) = prepared(&cx, directory.path().join("file")).await;
                assert_eq!(writer.checked_receive_offset(&cx).await.unwrap().unwrap(), 0);
                writer.write_chunk(&cx, 0, b"abcd".to_vec(), WriteOptions::default()).await.unwrap().unwrap();
                assert_eq!(writer.checked_receive_offset(&cx).await.unwrap().unwrap(), 4);
                writer.write_chunk(&cx, 4, b"efgh".to_vec(), WriteOptions::default()).await.unwrap().unwrap();
                assert_eq!(writer.checked_receive_offset(&cx).await.unwrap().unwrap(), 8);
            });
            drained(&runtime);
        }
    }

    #[test]
    fn unreceipted_file_tail_is_not_advertised_as_received() {
        let runtime = runtime(2);
        let directory = tempfile::tempdir().unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let (writer, _) = prepared(&cx, directory.path().join("file")).await;
            writer.write_chunk(&cx, 0, b"abcd".to_vec(), WriteOptions::default()).await.unwrap().unwrap();
            let staging = { writer.writer.lock_state().temp_path.clone().unwrap() };
            // Model a failed write that affected storage but returned no receipt.
            cx.scoped_fs().write(staging.clone(), b"abcdjunk".to_vec()).await.unwrap();
            assert_eq!(writer.checked_receive_offset(&cx).await.unwrap().unwrap(), 4);
            assert_eq!(cx.scoped_fs().read(staging).await.unwrap(), b"abcdjunk");
        });
        drained(&runtime);
    }

    #[test]
    fn corrupted_prefix_revokes_prior_verification_and_prevents_commit() {
        let runtime = runtime(2);
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("file");
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let (writer, manifest) = prepared(&cx, destination.clone()).await;
            writer.write_chunk(&cx, 0, b"abcdefgh".to_vec(), WriteOptions::default()).await.unwrap().unwrap();
            writer.verify(&cx, manifest).await.unwrap().unwrap();
            let staging = { writer.writer.lock_state().temp_path.clone().unwrap() };
            cx.scoped_fs().write(staging, b"Abcdefgh".to_vec()).await.unwrap();
            assert!(matches!(writer.checked_receive_offset(&cx).await,
                Ok(Outcome::Err(SparseWriterError::VerificationFailed(reason)))
                    if reason == "receive checkpoint chunk hash mismatch"));
            assert!(matches!(writer.commit(&cx).await, Ok(Outcome::Err(SparseWriterError::NotVerified))));
            assert!(!destination.exists());
        });
        drained(&runtime);
    }

    #[test]
    fn gaps_truncation_and_terminal_writers_cannot_supply_offsets() {
        let runtime = runtime(2);
        let directory = tempfile::tempdir().unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            for case in 0..4 {
                let (writer, manifest) = prepared(&cx, directory.path().join(format!("file-{case}"))).await;
                if case == 0 {
                    writer.write_chunk(&cx, 4, b"efgh".to_vec(), WriteOptions::default()).await.unwrap().unwrap();
                } else {
                    writer.write_chunk(&cx, 0, b"abcdefgh".to_vec(), WriteOptions::default()).await.unwrap().unwrap();
                }
                if case == 1 {
                    let staging = { writer.writer.lock_state().temp_path.clone().unwrap() };
                    cx.scoped_fs().write(staging, b"abc".to_vec()).await.unwrap();
                } else if case == 2 {
                    writer.verify_and_commit(&cx, manifest).await.unwrap().unwrap();
                } else if case == 3 {
                    writer.cancel(&cx).await.unwrap().unwrap();
                }
                let result = writer.checked_receive_offset(&cx).await.unwrap();
                if case < 2 {
                    assert!(matches!(result, Outcome::Err(SparseWriterError::VerificationFailed(_))));
                } else {
                    assert!(matches!(result, Outcome::Err(SparseWriterError::WriteFailed(_))));
                }
            }
        });
        drained(&runtime);
    }
}
