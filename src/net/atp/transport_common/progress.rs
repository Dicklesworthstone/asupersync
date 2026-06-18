//! Transfer progress reporting and dry-run planning (rsync UX parity).
//!
//! Two transport-agnostic UX primitives:
//!
//! - [`plan_transfer`] computes the *dry-run plan* — exactly what a real
//!   transfer would send (root name, file list, per-file size + SHA-256, total
//!   bytes, and the manifest merkle root) — by making the same streaming hash
//!   pass a real send does, but **without opening any socket**. This is the
//!   `--dry-run` "show me the plan" surface.
//! - [`TransferProgress`] is a monotonic progress accumulator that a transfer
//!   loop feeds as bytes/files complete, yielding a [`ProgressSnapshot`] with a
//!   completion fraction, throughput, and a plausible ETA. Elapsed time is
//!   supplied by the caller so progress is deterministic and unit-testable.
//!
//! Both reuse `transport_common`'s existing bounded-memory helpers and are
//! independent of the wire transport (TCP, RaptorQ, QUIC). Rendering a plan or a
//! progress line to a CLI is the consumer's job (Phase F).

use std::collections::HashSet;
use std::path::Path;
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::atp::object::{ContentId, MetadataPolicy, ObjectId};
use crate::cx::Cx;

use super::metadata::{FileKind, inode_key_if_regular, read_entry_metadata};
use super::streaming::{
    EntryDigest, StreamingError, collect_entries, flat_merkle_root_from_digests,
    hash_file_streaming, hex_encode,
};

/// One file in a [`TransferPlan`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PlanEntry {
    /// Path relative to the transfer root.
    pub rel_path: String,
    /// Entry size in bytes.
    pub size: u64,
    /// Lowercase hex SHA-256 of the entry content.
    pub sha256_hex: String,
}

/// The plan a transfer would execute, computed without touching the network.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct TransferPlan {
    /// Name of the transfer root (file or directory name).
    pub root_name: String,
    /// Whether the root is a directory (vs a single file).
    pub is_directory: bool,
    /// Total bytes across all entries.
    pub total_bytes: u64,
    /// Number of files in the plan.
    pub file_count: u64,
    /// Lowercase hex of the flat object-graph merkle root over the entries.
    pub merkle_root_hex: String,
    /// File entries in manifest order.
    pub entries: Vec<PlanEntry>,
}

/// Errors from [`plan_transfer`].
#[derive(Debug, thiserror::Error)]
pub enum PlanError {
    /// The source could not be read/walked/hashed.
    #[error("dry-run plan source error: {0}")]
    Source(String),
    /// The operation was cancelled via the capability context.
    #[error("dry-run plan cancelled")]
    Cancelled,
}

impl From<StreamingError> for PlanError {
    fn from(err: StreamingError) -> Self {
        Self::Source(err.into_message())
    }
}

/// Compute the dry-run plan for transferring `source`, without any network I/O.
///
/// Makes the same bounded-memory streaming hash pass as a real send (peak RSS is
/// `O(chunk_size)`), so the returned [`TransferPlan`] — file list, sizes,
/// SHA-256s, total bytes, and merkle root — matches exactly what a real transfer
/// would commit to. `chunk_size` is the streaming read-buffer size (clamped to
/// at least 1).
///
/// `metadata_policy` and `preserve_hardlinks` must match the real send's
/// [`TransferConfig`](crate::net::atp::transport_tcp::TransferConfig) so the plan
/// is faithful: like the sender's first pass, only regular, non-hardlink-secondary
/// files carry content. Symlinks (whose target is metadata), directories
/// (including explicit empty-dir entries), special files (FIFO/socket/device), and
/// hardlinks to an already-seen inode are zero-content and use the canonical empty
/// digest — they are **not** opened by [`hash_file_streaming`], which would
/// `EISDIR` on a directory or follow and hash a symlink's target. With these
/// inputs the per-entry digests, and hence the flat merkle root, are byte-for-byte
/// what the sender commits in the manifest.
pub async fn plan_transfer(
    cx: &Cx,
    source: &Path,
    chunk_size: usize,
    metadata_policy: &MetadataPolicy,
    preserve_hardlinks: bool,
) -> Result<TransferPlan, PlanError> {
    cx.checkpoint().map_err(|_| PlanError::Cancelled)?;

    let (root_name, is_directory, entries) = collect_entries(source).await?;

    let mut read_buf = vec![0u8; chunk_size.max(1)];
    let mut digests: Vec<EntryDigest> = Vec::with_capacity(entries.len());
    let mut total_bytes: u64 = 0;
    // Hardlink detection mirrors the sender: the first entry (by sorted path) for
    // a given inode is the primary that carries content; later entries sharing the
    // inode are hardlinks sent content-free.
    let mut seen_inodes: HashSet<(u64, u64)> = HashSet::new();
    for entry in &entries {
        cx.checkpoint().map_err(|_| PlanError::Cancelled)?;
        let metadata = read_entry_metadata(&entry.abs_path, metadata_policy).await?;
        let mut is_hardlink_secondary = false;
        if preserve_hardlinks && matches!(metadata.file_kind, FileKind::Regular) {
            if let Some(key) = inode_key_if_regular(&entry.abs_path).await? {
                // `insert` returns `false` when the inode was already seen, i.e.
                // this entry is a hardlink to an earlier primary (zero content).
                is_hardlink_secondary = !seen_inodes.insert(key);
            }
        }
        // Only regular, non-hardlink-secondary files carry content; everything
        // else gets the canonical empty digest — identical to the sender's first
        // pass — and is never opened by `hash_file_streaming`.
        let zero_content =
            !matches!(metadata.file_kind, FileKind::Regular) || is_hardlink_secondary;
        let (size, content_id, content_sha256) = if zero_content {
            let empty_sha: [u8; 32] = Sha256::digest(b"").into();
            (
                0u64,
                ObjectId::content(ContentId::from_bytes(b"")),
                empty_sha,
            )
        } else {
            hash_file_streaming(&entry.abs_path, &mut read_buf).await?
        };
        total_bytes = total_bytes.saturating_add(size);
        digests.push(EntryDigest {
            rel_path: entry.rel_path.clone(),
            size,
            content_id,
            content_sha256,
        });
    }

    let merkle_root_hex = flat_merkle_root_from_digests(&digests);
    let plan_entries: Vec<PlanEntry> = digests
        .iter()
        .map(|d| PlanEntry {
            rel_path: d.rel_path.clone(),
            size: d.size,
            sha256_hex: hex_encode(&d.content_sha256),
        })
        .collect();

    Ok(TransferPlan {
        root_name,
        is_directory,
        total_bytes,
        file_count: entries.len() as u64,
        merkle_root_hex,
        entries: plan_entries,
    })
}

/// A point-in-time view of transfer progress.
#[derive(Debug, Clone, PartialEq)]
pub struct ProgressSnapshot {
    /// Bytes transferred so far.
    pub bytes_done: u64,
    /// Total bytes to transfer.
    pub total_bytes: u64,
    /// Files completed so far.
    pub files_done: u64,
    /// Total files to transfer.
    pub total_files: u64,
    /// Completion fraction in `0.0..=1.0` (1.0 when there is nothing to do).
    pub fraction: f64,
    /// Observed throughput in bytes per second (0.0 until time elapses).
    pub rate_bytes_per_sec: f64,
    /// Estimated time remaining, or `None` when unknown (no rate yet) or done.
    pub eta: Option<Duration>,
}

/// Monotonic transfer progress accumulator.
///
/// A transfer loop calls [`record_bytes`](Self::record_bytes) /
/// [`record_file`](Self::record_file) as work completes, then
/// [`snapshot`](Self::snapshot) with the elapsed wall time to render progress.
/// Counters never exceed their totals and never decrease, so a rendered bar is
/// always monotonic.
#[derive(Debug, Clone)]
pub struct TransferProgress {
    total_bytes: u64,
    total_files: u64,
    bytes_done: u64,
    files_done: u64,
}

impl TransferProgress {
    /// Start tracking a transfer of `total_bytes` across `total_files`.
    #[must_use]
    pub fn new(total_bytes: u64, total_files: u64) -> Self {
        Self {
            total_bytes,
            total_files,
            bytes_done: 0,
            files_done: 0,
        }
    }

    /// Record `n` more transferred bytes (saturating at `total_bytes`).
    pub fn record_bytes(&mut self, n: u64) {
        self.bytes_done = self.bytes_done.saturating_add(n).min(self.total_bytes);
    }

    /// Record one more completed file (saturating at `total_files`).
    pub fn record_file(&mut self) {
        self.files_done = self.files_done.saturating_add(1).min(self.total_files);
    }

    /// Bytes transferred so far.
    #[must_use]
    pub fn bytes_done(&self) -> u64 {
        self.bytes_done
    }

    /// Files completed so far.
    #[must_use]
    pub fn files_done(&self) -> u64 {
        self.files_done
    }

    /// Whether all bytes have been transferred.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.bytes_done >= self.total_bytes
    }

    /// Snapshot progress given the wall time elapsed since the transfer started.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn snapshot(&self, elapsed: Duration) -> ProgressSnapshot {
        let fraction = if self.total_bytes == 0 {
            1.0
        } else {
            self.bytes_done as f64 / self.total_bytes as f64
        };
        let secs = elapsed.as_secs_f64();
        let rate = if secs > 0.0 {
            self.bytes_done as f64 / secs
        } else {
            0.0
        };
        let eta = if rate > 0.0 && self.bytes_done < self.total_bytes {
            let remaining = (self.total_bytes - self.bytes_done) as f64;
            // try_from avoids the panic from_secs_f64 raises on overflow/non-finite.
            Duration::try_from_secs_f64(remaining / rate).ok()
        } else {
            None
        };
        ProgressSnapshot {
            bytes_done: self.bytes_done,
            total_bytes: self.total_bytes,
            files_done: self.files_done,
            total_files: self.total_files,
            fraction,
            rate_bytes_per_sec: rate,
            eta,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_is_monotonic_and_capped() {
        let mut p = TransferProgress::new(1000, 3);
        p.record_bytes(400);
        assert_eq!(p.bytes_done(), 400);
        p.record_bytes(400);
        assert_eq!(p.bytes_done(), 800);
        // Over-recording saturates at the total (never exceeds, never wraps).
        p.record_bytes(9999);
        assert_eq!(p.bytes_done(), 1000);
        assert!(p.is_complete());

        p.record_file();
        p.record_file();
        p.record_file();
        p.record_file(); // beyond total_files -> capped
        assert_eq!(p.files_done(), 3);
    }

    #[test]
    fn snapshot_fraction_rate_and_eta() {
        let mut p = TransferProgress::new(1000, 4);
        p.record_bytes(250);
        let s = p.snapshot(Duration::from_secs(1));
        assert!((s.fraction - 0.25).abs() < 1e-9);
        assert!((s.rate_bytes_per_sec - 250.0).abs() < 1e-9);
        // 750 bytes left at 250 B/s -> ~3s ETA.
        let eta = s.eta.expect("eta while in flight");
        assert!((eta.as_secs_f64() - 3.0).abs() < 1e-6);
    }

    #[test]
    fn snapshot_no_eta_when_done_or_no_time() {
        let mut p = TransferProgress::new(100, 1);
        // No elapsed time yet -> no rate, no ETA.
        assert!(p.snapshot(Duration::ZERO).eta.is_none());
        // Complete -> no ETA.
        p.record_bytes(100);
        let s = p.snapshot(Duration::from_secs(2));
        assert!(s.eta.is_none());
        assert!((s.fraction - 1.0).abs() < 1e-9);
    }

    #[test]
    fn empty_transfer_is_fully_complete() {
        let p = TransferProgress::new(0, 0);
        let s = p.snapshot(Duration::from_secs(1));
        assert!((s.fraction - 1.0).abs() < 1e-9);
        assert!(s.eta.is_none());
        assert!(p.is_complete());
    }

    #[test]
    fn plan_error_maps_from_streaming() {
        let e: PlanError = StreamingError::new("boom").into();
        assert!(matches!(e, PlanError::Source(m) if m.contains("boom")));
    }
}
