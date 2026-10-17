//! B-8.6 — zero-scan change detection: don't re-hash what the OS already tells us
//! is unchanged.
//!
//! The incremental re-sync (B-8, the rsync-killer delta path) must not chunk-hash
//! an entire tree to discover the handful of changed files — that is O(tree) work
//! for an O(delta) result. This module is the cheap **pre-pass** that runs before
//! any content hashing:
//!
//! * [`FileSignature`] — the rsync-style quick-check fingerprint `(size, mtime)`
//!   plus an advisory `ctime`. It is the metadata the OS already tracks, so an
//!   unchanged file is recognised **without reading or hashing its bytes**.
//! * [`classify`] — compare a prior signature to the current one: [`ChangeVerdict::Unchanged`]
//!   (skip chunk-hashing entirely) vs [`ChangeVerdict::SuspectChanged`] (must
//!   chunk-hash to find the real delta). Faithful to rsync's quick-check: only
//!   `size` + `mtime` gate the decision; a `ctime`-only change (e.g. `chmod`,
//!   ownership) must **not** trigger a re-hash, so `ctime` is recorded for audit
//!   but excluded from the comparison.
//! * [`simhash64`] / [`hamming_similarity`] / [`best_rename_source`] — a
//!   locality-sensitive fingerprint over a file's FastCDC chunk-id set so a
//!   renamed or copied file can be deltaed against its best prior match instead of
//!   re-sent whole. Identical content (a pure rename) yields an identical simhash
//!   (similarity `1.0`); a small edit keeps most chunk-ids and stays highly
//!   similar.
//!
//! Persistent dirty-set maintenance via `inotify`/`fanotify`/an FS change-journal
//! is an optional, platform-specific layer that plugs in on top by feeding paths
//! into the same [`classify`]; this module is the portable, allocation-light core
//! plus its tests. Inputs are plain values, so the logic is deterministic and unit
//! testable without touching the filesystem.

use serde::{Deserialize, Serialize};

/// Cheap per-file fingerprint: the metadata the OS already maintains. Comparing
/// two signatures recognises an unchanged file without reading its content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileSignature {
    /// File length in bytes.
    pub size: u64,
    /// Modification time, nanoseconds since the Unix epoch. Part of the quick-check.
    pub mtime_nanos: u64,
    /// Inode change time, nanoseconds since the Unix epoch. Advisory only —
    /// recorded for forensics but deliberately excluded from [`classify`] so a
    /// metadata-only change (chmod/chown) does not force a content re-hash.
    pub ctime_nanos: u64,
}

impl FileSignature {
    /// Build a signature from raw parts (the unit-testable constructor).
    #[must_use]
    pub const fn new(size: u64, mtime_nanos: u64, ctime_nanos: u64) -> Self {
        Self {
            size,
            mtime_nanos,
            ctime_nanos,
        }
    }

    /// Build from `std::fs::Metadata`: `size` from the length, `mtime` from
    /// `modified()`, and `ctime` from the platform inode change-time where
    /// available (Unix); elsewhere `ctime` is `0` (advisory only, never gates
    /// [`classify`], so this is sound on every platform).
    #[must_use]
    pub fn from_metadata(meta: &std::fs::Metadata) -> Self {
        let mtime_nanos = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX));
        let ctime_nanos = platform_ctime_nanos(meta);
        Self {
            size: meta.len(),
            mtime_nanos,
            ctime_nanos,
        }
    }

    /// The rsync quick-check key: two files with the same `(size, mtime)` are
    /// presumed unchanged. `ctime` is intentionally not part of the key.
    #[must_use]
    const fn quick_check_key(&self) -> (u64, u64) {
        (self.size, self.mtime_nanos)
    }
}

#[cfg(unix)]
fn platform_ctime_nanos(meta: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    let secs = u64::try_from(meta.ctime()).unwrap_or(0);
    let nanos = u64::try_from(meta.ctime_nsec()).unwrap_or(0);
    secs.saturating_mul(1_000_000_000).saturating_add(nanos)
}

#[cfg(not(unix))]
fn platform_ctime_nanos(_meta: &std::fs::Metadata) -> u64 {
    0
}

/// Outcome of the pre-pass for one file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeVerdict {
    /// `(size, mtime)` match the prior signature → skip chunk-hashing entirely.
    Unchanged,
    /// New file, or `size`/`mtime` differs → must chunk-hash to find the delta.
    SuspectChanged,
}

impl ChangeVerdict {
    /// Whether the file may be skipped (no content read / no chunk-hashing).
    #[must_use]
    pub const fn is_skippable(self) -> bool {
        matches!(self, Self::Unchanged)
    }
}

/// Classify a file by comparing its current signature to the prior-sync baseline.
///
/// Returns [`ChangeVerdict::Unchanged`] only when a prior signature exists and its
/// `(size, mtime)` match — rsync's quick-check. A missing prior, or any `size`/
/// `mtime` difference, yields [`ChangeVerdict::SuspectChanged`]. A `ctime`-only
/// difference is treated as unchanged on purpose.
#[must_use]
pub fn classify(prior: Option<&FileSignature>, current: &FileSignature) -> ChangeVerdict {
    match prior {
        Some(p) if p.quick_check_key() == current.quick_check_key() => ChangeVerdict::Unchanged,
        _ => ChangeVerdict::SuspectChanged,
    }
}

const SIMHASH_BITS: usize = 64;

/// 64-bit SimHash over a multiset of `u64` features.
///
/// Each bit position accumulates `+1` when set in a feature and `-1` when clear;
/// the output bit is `1` iff the accumulator is positive. Similar feature sets
/// (e.g. two files sharing most FastCDC chunk-ids) collapse to similar hashes, so
/// near-duplicates are found by Hamming distance rather than exact match.
#[must_use]
pub fn simhash64(features: impl IntoIterator<Item = u64>) -> u64 {
    let mut acc = [0i64; SIMHASH_BITS];
    let mut any = false;
    for feature in features {
        any = true;
        for (bit, slot) in acc.iter_mut().enumerate() {
            if (feature >> bit) & 1 == 1 {
                *slot += 1;
            } else {
                *slot -= 1;
            }
        }
    }
    if !any {
        return 0;
    }
    let mut hash = 0u64;
    for (bit, slot) in acc.iter().enumerate() {
        if *slot > 0 {
            hash |= 1u64 << bit;
        }
    }
    hash
}

/// SimHash over a file's FastCDC chunk-id set.
///
/// Each 32-byte chunk content hash is folded to a `u64` feature (its leading 8
/// bytes), so a file's identity is the distribution of its chunk-ids —
/// order-independent and robust to local edits.
#[must_use]
pub fn simhash_of_chunk_ids<'a>(chunk_ids: impl IntoIterator<Item = &'a [u8; 32]>) -> u64 {
    simhash64(chunk_ids.into_iter().map(|id| {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&id[..8]);
        u64::from_le_bytes(bytes)
    }))
}

/// Similarity in `[0.0, 1.0]` between two SimHashes: `1 - hamming_distance / 64`.
/// `1.0` is identical; `0.5` is the expected value for unrelated inputs.
#[must_use]
pub fn hamming_similarity(a: u64, b: u64) -> f64 {
    let distance = (a ^ b).count_ones();
    1.0 - f64::from(distance) / SIMHASH_BITS as f64
}

/// A prior file proposed as the delta source for a renamed/copied current file.
#[derive(Debug, Clone, PartialEq)]
pub struct RenameMatch {
    /// Transfer-relative path of the prior file to delta against.
    pub prior_path: String,
    /// SimHash similarity in `[0.0, 1.0]`.
    pub similarity: f64,
}

/// Find the prior file whose SimHash is most similar to `current_simhash`.
///
/// The match must clear `min_similarity`. Use it to delta a renamed/copied file
/// against its nearest prior instead of re-sending it whole. Returns `None` when
/// nothing is similar enough (the file is genuinely new → send it).
#[must_use]
pub fn best_rename_source<'a>(
    current_simhash: u64,
    candidates: impl IntoIterator<Item = (&'a str, u64)>,
    min_similarity: f64,
) -> Option<RenameMatch> {
    let mut best: Option<RenameMatch> = None;
    for (path, simhash) in candidates {
        let similarity = hamming_similarity(current_simhash, simhash);
        if similarity < min_similarity {
            continue;
        }
        if best.as_ref().is_none_or(|b| similarity > b.similarity) {
            best = Some(RenameMatch {
                prior_path: path.to_string(),
                similarity,
            });
        }
    }
    best
}

#[cfg(test)]
#[path = "change_detect_inline_tests.rs"]
mod tests;
