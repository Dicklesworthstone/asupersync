//! Transport-agnostic filesystem-metadata fidelity for ATP manifests.
//!
//! Epic `b0k8qo` phase J1: a sync tool that silently drops permissions, mtimes,
//! symlinks, and xattrs is strictly worse than rsync. This module lets any ATP
//! transport capture per-entry filesystem metadata on the sender, carry it in the
//! manifest, and re-apply it on the receiver atomically with the file commit —
//! gated by a [`MetadataPolicy`] (reused from [`crate::atp::object`]).
//!
//! # Why a separate metadata commitment
//!
//! Content integrity already rides the content-addressed merkle root
//! ([`crate::net::atp::transport_common::flat_merkle_root_from_digests`]), which
//! is pinned byte-for-byte against the owned-graph builder and **must not change
//! shape**. Folding per-path metadata into it is also wrong: that root dedups by
//! content, so two files with identical bytes but different modes would collapse
//! and lose their distinct metadata. Instead, metadata is committed by an
//! independent [`metadata_commitment`] hash carried alongside the merkle root.
//! The receiver recomputes it over the manifest it received and rejects a
//! mismatch, so accidental corruption of the metadata block is detected the same
//! way a content mismatch is, while the content merkle stays oracle-stable.
//!
//! # Cross-platform posture
//!
//! Capturing and applying metadata is `#[cfg(unix)]`. On non-unix targets the
//! reader returns a bare [`EntryMetadata`] (file kind only) and the applier is a
//! no-op, so portable transfers still work. Fields the receiver cannot apply
//! (e.g. `uid`/`gid` without privilege) are reported as skipped, never fatal —
//! rsync-style graceful degradation.

use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::atp::object::MetadataPolicy;

use super::streaming::{StreamingError, hex_encode};

/// Kind of filesystem entry recorded in a manifest.
///
/// ATP's content layer only moves regular files; directories are reconstructed
/// implicitly from entry paths and symlinks carry no content (their target is
/// metadata). `Regular` is the default so a manifest entry with no captured
/// metadata deserializes to a plain file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileKind {
    /// A regular file whose bytes travel in the content stream.
    #[default]
    Regular,
    /// A symbolic link; its target is carried in [`EntryMetadata::symlink_target`]
    /// and it contributes zero content bytes.
    Symlink,
    /// A directory entry (structural; reserved for explicit empty-dir support).
    Directory,
    /// A named pipe (FIFO). Carries no content; recreated via `mkfifo` under an
    /// opt-in policy, otherwise skipped and logged.
    Fifo,
    /// A unix-domain socket file. Represented in the manifest but not recreated
    /// (sockets are runtime objects) — skipped and logged.
    Socket,
    /// A block device node. Represented in the manifest; recreating it needs
    /// privilege (`mknod`) so it is skipped and logged by default.
    BlockDevice,
    /// A character device node. Represented in the manifest; recreating it needs
    /// privilege (`mknod`) so it is skipped and logged by default.
    CharDevice,
}

impl FileKind {
    /// Stable byte tag for the metadata commitment encoding. Tags are append-only
    /// — never renumber an existing variant or the commitment would shift.
    const fn tag(self) -> u8 {
        match self {
            Self::Regular => 0,
            Self::Symlink => 1,
            Self::Directory => 2,
            Self::Fifo => 3,
            Self::Socket => 4,
            Self::BlockDevice => 5,
            Self::CharDevice => 6,
        }
    }

    /// Whether this kind is a "special" filesystem object (FIFO / socket / device
    /// node) — carries no content and is recreated only under an opt-in policy.
    #[must_use]
    pub const fn is_special(self) -> bool {
        matches!(
            self,
            Self::Fifo | Self::Socket | Self::BlockDevice | Self::CharDevice
        )
    }
}

/// Per-entry filesystem metadata captured on the sender and applied on the
/// receiver, subject to a [`MetadataPolicy`].
///
/// Every field except `file_kind` is optional: a portable transfer (or an
/// unsupported platform) simply omits them, and the whole struct is omitted from
/// the manifest when [`EntryMetadata::is_bare`] holds.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct EntryMetadata {
    /// File kind (regular / symlink / directory).
    #[serde(default)]
    pub file_kind: FileKind,
    /// Unix permission bits (`st_mode & 0o7777`), when permissions are preserved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unix_mode: Option<u32>,
    /// Modification time, whole seconds since the unix epoch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtime_unix_secs: Option<i64>,
    /// Modification time, sub-second nanoseconds (`0..1_000_000_000`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtime_nanos: Option<u32>,
    /// Owning user id, when ownership is preserved (apply needs privilege).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    /// Owning group id, when ownership is preserved (apply needs privilege).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gid: Option<u32>,
    /// Symlink target (forward-slash or platform path text) for `Symlink` kinds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symlink_target: Option<String>,
    /// Hardlink primary: when set, this entry is a hardlink to another entry in
    /// the same transfer (the value is that primary's transfer-relative path).
    /// Such an entry carries no content — the receiver `hard_link`s it to the
    /// primary (which sorts earlier and is committed first).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hardlink_target: Option<String>,
    /// Extended attributes captured from the entry when the metadata policy asks
    /// for xattr preservation. Attribute names are manifest strings and values
    /// are byte-identical payloads.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub xattrs: BTreeMap<String, Vec<u8>>,
}

impl EntryMetadata {
    /// Whether this carries no metadata beyond a plain regular-file kind, in which
    /// case it is omitted from the manifest entirely (portable round-trip).
    #[must_use]
    pub fn is_bare(&self) -> bool {
        matches!(self.file_kind, FileKind::Regular)
            && self.unix_mode.is_none()
            && self.mtime_unix_secs.is_none()
            && self.mtime_nanos.is_none()
            && self.uid.is_none()
            && self.gid.is_none()
            && self.symlink_target.is_none()
            && self.hardlink_target.is_none()
            && self.xattrs.is_empty()
    }

    /// Append this entry's canonical, domain-separated encoding to `hasher`. The
    /// presence byte before each optional field keeps "absent" distinct from a
    /// zero value so the commitment is collision-resistant across schemas.
    fn hash_into(&self, rel_path: &str, hasher: &mut Sha256) {
        hasher.update((rel_path.len() as u64).to_be_bytes());
        hasher.update(rel_path.as_bytes());
        hasher.update([self.file_kind.tag()]);
        hash_opt_u32(hasher, self.unix_mode);
        hash_opt_i64(hasher, self.mtime_unix_secs);
        hash_opt_u32(hasher, self.mtime_nanos);
        hash_opt_u32(hasher, self.uid);
        hash_opt_u32(hasher, self.gid);
        hash_opt_str(hasher, self.symlink_target.as_deref());
        hash_opt_str(hasher, self.hardlink_target.as_deref());
        hash_xattrs(hasher, &self.xattrs);
    }
}

/// Stable filesystem identity for a regular file on platforms that expose it.
///
/// A rename within the same filesystem preserves this identity, letting the
/// sender reuse the prior content plan without opening and chunk-hashing the
/// renamed path. Callers should omit it on platforms where `(device, inode)` is
/// not available or not stable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FileIdentity {
    /// Device identifier from the filesystem.
    pub device: u64,
    /// Inode/file index on that device.
    pub inode: u64,
}

impl FileIdentity {
    /// Construct a filesystem identity.
    #[must_use]
    pub const fn new(device: u64, inode: u64) -> Self {
        Self { device, inode }
    }
}

/// Optional similarity sketch supplied by a prior manifest or filesystem journal.
///
/// The zero-scan prefilter never derives this by reading file contents; doing so
/// would defeat its purpose. Instead, transports may carry forward a simhash or
/// MinHash learned during a previous verified chunk pass and use it to select a
/// strong delta base for renamed/copied files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimilaritySignature {
    /// SimHash over a prior verified content/chunk sketch.
    pub simhash: u64,
    /// Optional MinHash/minimum-chunk-sketch value for exact tie-breaking.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minhash: Option<u64>,
}

impl SimilaritySignature {
    /// Construct a similarity signature.
    #[must_use]
    pub const fn new(simhash: u64, minhash: Option<u64>) -> Self {
        Self { simhash, minhash }
    }

    fn distance_to(self, other: Self) -> u32 {
        (self.simhash ^ other.simhash).count_ones()
    }

    fn matches_within(self, other: Self, max_hamming_distance: u32) -> bool {
        self.minhash.zip(other.minhash).is_some_and(|(a, b)| a == b)
            || self.distance_to(other) <= max_hamming_distance
    }
}

/// Cheap, persistent identity used before content-defined chunking.
///
/// This is deliberately separate from [`EntryMetadata`]: it is sender-local
/// planning state, not a wire manifest field. Default policy requires ctime to
/// avoid trusting size+mtime alone on filesystems that can expose stronger
/// change evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZeroScanFingerprint {
    /// File kind represented by this fingerprint.
    pub file_kind: FileKind,
    /// File size in bytes.
    pub size_bytes: u64,
    /// Modification time, whole seconds since the unix epoch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtime_unix_secs: Option<i64>,
    /// Modification time, sub-second nanoseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtime_nanos: Option<u32>,
    /// Change time, whole seconds since the unix epoch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ctime_unix_secs: Option<i64>,
    /// Change time, sub-second nanoseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ctime_nanos: Option<u32>,
    /// Optional filesystem identity for rename detection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<FileIdentity>,
    /// Optional similarity sketch from prior verified chunk state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub similarity: Option<SimilaritySignature>,
}

impl ZeroScanFingerprint {
    /// Build a fingerprint from existing ATP metadata and a known content length.
    #[must_use]
    pub fn from_entry_metadata(size_bytes: u64, metadata: &EntryMetadata) -> Self {
        Self {
            file_kind: metadata.file_kind,
            size_bytes,
            mtime_unix_secs: metadata.mtime_unix_secs,
            mtime_nanos: metadata.mtime_nanos,
            ctime_unix_secs: None,
            ctime_nanos: None,
            identity: None,
            similarity: None,
        }
    }

    /// Attach ctime captured from local stat metadata.
    #[must_use]
    pub const fn with_ctime(mut self, secs: i64, nanos: u32) -> Self {
        self.ctime_unix_secs = Some(secs);
        self.ctime_nanos = Some(nanos);
        self
    }

    /// Attach a filesystem identity captured from local stat metadata.
    #[must_use]
    pub const fn with_identity(mut self, identity: FileIdentity) -> Self {
        self.identity = Some(identity);
        self
    }

    /// Attach a prior verified similarity signature.
    #[must_use]
    pub const fn with_similarity(mut self, signature: SimilaritySignature) -> Self {
        self.similarity = Some(signature);
        self
    }

    fn ctime_available(&self) -> bool {
        self.ctime_unix_secs.is_some()
    }

    fn mtime_matches(&self, prior: &Self) -> bool {
        self.mtime_unix_secs == prior.mtime_unix_secs
            && self.mtime_nanos.unwrap_or(0) == prior.mtime_nanos.unwrap_or(0)
    }

    fn ctime_matches(&self, prior: &Self, policy: &ZeroScanPolicy) -> bool {
        if policy.require_ctime && !(self.ctime_available() && prior.ctime_available()) {
            return false;
        }
        match (self.ctime_unix_secs, prior.ctime_unix_secs) {
            (Some(a), Some(b)) => {
                a == b && self.ctime_nanos.unwrap_or(0) == prior.ctime_nanos.unwrap_or(0)
            }
            (None, None) => !policy.require_ctime,
            _ => false,
        }
    }

    fn same_filesystem_identity(&self, prior: &Self) -> bool {
        self.identity
            .zip(prior.identity)
            .is_some_and(|(current, previous)| current == previous)
    }

    fn stat_identity_matches(&self, prior: &Self, policy: &ZeroScanPolicy) -> bool {
        self.file_kind == prior.file_kind
            && self.size_bytes == prior.size_bytes
            && self.mtime_matches(prior)
            && self.ctime_matches(prior, policy)
            && match (self.identity, prior.identity) {
                (Some(a), Some(b)) => a == b,
                _ => true,
            }
    }

    fn likely_same_prior_content(&self, prior: &Self, policy: &ZeroScanPolicy) -> bool {
        if self.file_kind != prior.file_kind || self.size_bytes != prior.size_bytes {
            return false;
        }
        if self.same_filesystem_identity(prior) || self.stat_identity_matches(prior, policy) {
            return true;
        }
        self.similarity
            .zip(prior.similarity)
            .is_some_and(|(current, previous)| {
                current.matches_within(previous, policy.max_similarity_hamming_distance)
            })
    }
}

/// One tree entry available to the zero-scan prefilter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZeroScanEntry {
    /// Transfer-relative path.
    pub rel_path: String,
    /// Cheap stat/journal-derived identity for the entry.
    pub fingerprint: ZeroScanFingerprint,
}

impl ZeroScanEntry {
    /// Construct an entry.
    #[must_use]
    pub fn new(rel_path: impl Into<String>, fingerprint: ZeroScanFingerprint) -> Self {
        Self {
            rel_path: rel_path.into(),
            fingerprint,
        }
    }
}

/// Optional filesystem-journal dirty set.
///
/// A clean entry is still stat-compared before it is skipped. A dirty hit always
/// schedules chunk hashing even if size/mtime/ctime happen to match, preserving
/// correctness when the journal reports a suspicious path.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirtyPathSet {
    paths: BTreeSet<String>,
}

impl DirtyPathSet {
    /// Construct an empty dirty set.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            paths: BTreeSet::new(),
        }
    }

    /// Construct a dirty set from transfer-relative paths.
    #[must_use]
    pub fn from_paths(paths: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            paths: paths.into_iter().map(Into::into).collect(),
        }
    }

    /// Mark a path as dirty.
    pub fn insert(&mut self, rel_path: impl Into<String>) {
        self.paths.insert(rel_path.into());
    }

    /// Whether a path was reported dirty by the filesystem journal.
    #[must_use]
    pub fn contains(&self, rel_path: &str) -> bool {
        self.paths.contains(rel_path)
    }

    /// Number of dirty paths tracked.
    #[must_use]
    pub fn len(&self) -> usize {
        self.paths.len()
    }

    /// Whether the dirty set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }
}

/// Zero-scan prefilter knobs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZeroScanPolicy {
    /// Require ctime on both prior and current entries before skipping hashing.
    pub require_ctime: bool,
    /// Maximum SimHash Hamming distance accepted for a prior-content match.
    pub max_similarity_hamming_distance: u32,
}

impl Default for ZeroScanPolicy {
    fn default() -> Self {
        Self {
            require_ctime: true,
            max_similarity_hamming_distance: 3,
        }
    }
}

/// Why an entry still needs content-defined chunk hashing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZeroScanHashReason {
    /// No prior entry or reusable prior content candidate exists.
    NoPriorEntry,
    /// Filesystem journal marked this path dirty.
    DirtySetHit,
    /// Same path exists but stat identity moved.
    StatChanged,
}

/// Per-entry prefilter decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "decision")]
pub enum ZeroScanDecision {
    /// Same path and same stat identity: no chunk hashing and no content bytes.
    Unchanged {
        /// Current transfer-relative path.
        rel_path: String,
    },
    /// Different path can reuse a verified prior content plan as delta base.
    ReusePriorContent {
        /// Current transfer-relative path.
        rel_path: String,
        /// Prior transfer-relative path to use as the delta/CAS base.
        prior_rel_path: String,
    },
    /// This entry must be chunk-hashed and reconciled normally.
    NeedsChunkHash {
        /// Current transfer-relative path.
        rel_path: String,
        /// Why zero-scan could not skip hashing.
        reason: ZeroScanHashReason,
        /// Estimated content bytes this entry contributes to the lower-bound
        /// transfer floor before CAS/delta reconciliation removes shared chunks.
        size_bytes: u64,
    },
}

impl ZeroScanDecision {
    fn skipped_chunk_hash(&self) -> bool {
        matches!(
            self,
            Self::Unchanged { .. } | Self::ReusePriorContent { .. }
        )
    }
}

/// Aggregate zero-scan plan output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZeroScanPlan {
    /// One decision per current entry, in current-entry order.
    pub decisions: Vec<ZeroScanDecision>,
    /// Number of entries whose chunk hashing was skipped.
    pub skipped_chunk_hashes: usize,
    /// Number of entries that still require chunk hashing.
    pub scheduled_chunk_hashes: usize,
    /// Bytes that would have been hashed but were skipped by zero-scan.
    pub skipped_chunk_hash_bytes: u64,
    /// Lower bound on content bytes requiring normal chunk/hash processing.
    pub estimated_content_bytes_floor: u64,
}

/// Pure zero-scan planner used before FastCDC/RaptorQ send preparation.
pub struct ZeroScanPrefilter;

impl ZeroScanPrefilter {
    /// Compare a prior verified tree snapshot with the current tree snapshot.
    ///
    /// This function never opens files and never hashes content. It only decides
    /// which entries can safely reuse prior verified content evidence and which
    /// entries must proceed to the normal chunk-hashing path.
    #[must_use]
    pub fn plan(
        prior: &[ZeroScanEntry],
        current: &[ZeroScanEntry],
        dirty_set: Option<&DirtyPathSet>,
        policy: ZeroScanPolicy,
    ) -> ZeroScanPlan {
        let prior_by_path: BTreeMap<&str, &ZeroScanEntry> = prior
            .iter()
            .map(|entry| (entry.rel_path.as_str(), entry))
            .collect();
        let mut decisions = Vec::with_capacity(current.len());

        for entry in current {
            let dirty = dirty_set.is_some_and(|set| set.contains(&entry.rel_path));
            let decision = match prior_by_path.get(entry.rel_path.as_str()) {
                Some(_) if dirty => ZeroScanDecision::NeedsChunkHash {
                    rel_path: entry.rel_path.clone(),
                    reason: ZeroScanHashReason::DirtySetHit,
                    size_bytes: entry.fingerprint.size_bytes,
                },
                Some(previous)
                    if entry
                        .fingerprint
                        .stat_identity_matches(&previous.fingerprint, &policy) =>
                {
                    ZeroScanDecision::Unchanged {
                        rel_path: entry.rel_path.clone(),
                    }
                }
                Some(_) => ZeroScanDecision::NeedsChunkHash {
                    rel_path: entry.rel_path.clone(),
                    reason: ZeroScanHashReason::StatChanged,
                    size_bytes: entry.fingerprint.size_bytes,
                },
                None => Self::best_prior_content_match(prior, entry, &policy).map_or_else(
                    || ZeroScanDecision::NeedsChunkHash {
                        rel_path: entry.rel_path.clone(),
                        reason: ZeroScanHashReason::NoPriorEntry,
                        size_bytes: entry.fingerprint.size_bytes,
                    },
                    |previous| ZeroScanDecision::ReusePriorContent {
                        rel_path: entry.rel_path.clone(),
                        prior_rel_path: previous.rel_path.clone(),
                    },
                ),
            };
            decisions.push(decision);
        }

        let mut skipped_chunk_hashes = 0usize;
        let mut scheduled_chunk_hashes = 0usize;
        let mut skipped_chunk_hash_bytes = 0u64;
        let mut estimated_content_bytes_floor = 0u64;

        for (entry, decision) in current.iter().zip(decisions.iter()) {
            if decision.skipped_chunk_hash() {
                skipped_chunk_hashes += 1;
                skipped_chunk_hash_bytes =
                    skipped_chunk_hash_bytes.saturating_add(entry.fingerprint.size_bytes);
            } else if let ZeroScanDecision::NeedsChunkHash { size_bytes, .. } = decision {
                scheduled_chunk_hashes += 1;
                estimated_content_bytes_floor =
                    estimated_content_bytes_floor.saturating_add(*size_bytes);
            }
        }

        ZeroScanPlan {
            decisions,
            skipped_chunk_hashes,
            scheduled_chunk_hashes,
            skipped_chunk_hash_bytes,
            estimated_content_bytes_floor,
        }
    }

    fn best_prior_content_match<'a>(
        prior: &'a [ZeroScanEntry],
        entry: &ZeroScanEntry,
        policy: &ZeroScanPolicy,
    ) -> Option<&'a ZeroScanEntry> {
        prior
            .iter()
            .filter(|previous| {
                entry
                    .fingerprint
                    .likely_same_prior_content(&previous.fingerprint, policy)
            })
            .min_by(|a, b| a.rel_path.cmp(&b.rel_path))
    }
}

fn hash_opt_str(hasher: &mut Sha256, v: Option<&str>) {
    match v {
        Some(s) => {
            hasher.update([1u8]);
            hasher.update((s.len() as u64).to_be_bytes());
            hasher.update(s.as_bytes());
        }
        None => hasher.update([0u8]),
    }
}

fn hash_opt_u32(hasher: &mut Sha256, v: Option<u32>) {
    match v {
        Some(x) => {
            hasher.update([1u8]);
            hasher.update(x.to_be_bytes());
        }
        None => hasher.update([0u8]),
    }
}

fn hash_opt_i64(hasher: &mut Sha256, v: Option<i64>) {
    match v {
        Some(x) => {
            hasher.update([1u8]);
            hasher.update(x.to_be_bytes());
        }
        None => hasher.update([0u8]),
    }
}

fn hash_xattrs(hasher: &mut Sha256, xattrs: &BTreeMap<String, Vec<u8>>) {
    hasher.update((xattrs.len() as u64).to_be_bytes());
    for (name, value) in xattrs {
        hasher.update((name.len() as u64).to_be_bytes());
        hasher.update(name.as_bytes());
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value);
    }
}

/// Compute the metadata commitment over `(rel_path, metadata)` pairs, or `None`
/// when every entry is [`EntryMetadata::is_bare`].
///
/// That means a portable transfer carries no commitment and stays
/// byte-identical to the pre-J1 manifest.
///
/// The pairs are sorted by `rel_path` for order-independence, mirroring the
/// content merkle, so sender and receiver agree regardless of entry order.
#[must_use]
pub fn metadata_commitment(entries: &[(&str, &EntryMetadata)]) -> Option<String> {
    if entries.iter().all(|(_, m)| m.is_bare()) {
        return None;
    }
    let mut sorted: Vec<&(&str, &EntryMetadata)> = entries.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(b.0));

    let mut hasher = Sha256::new();
    hasher.update(b"asupersync.atp.metadata-commitment.v1\0");
    hasher.update((sorted.len() as u64).to_be_bytes());
    for (rel_path, meta) in sorted {
        meta.hash_into(rel_path, &mut hasher);
    }
    Some(hex_encode(&hasher.finalize()))
}

/// Outcome of applying one entry's metadata: which fields were applied and which
/// were skipped (with a human-readable reason) so the caller can log graceful
/// degradation without failing the commit.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MetadataApplyReport {
    /// Field names successfully applied (e.g. `"mode"`, `"mtime"`, `"owner"`).
    pub applied: Vec<&'static str>,
    /// `(field, reason)` pairs for metadata that could not be applied.
    pub skipped: Vec<(&'static str, String)>,
}

impl MetadataApplyReport {
    fn mark_applied(&mut self, field: &'static str) {
        self.applied.push(field);
    }
    fn mark_skipped(&mut self, field: &'static str, reason: impl Into<String>) {
        self.skipped.push((field, reason.into()));
    }
}

/// Capture filesystem metadata for `abs_path`, honoring `policy`.
///
/// When `policy.preserve_symlinks` is set, a symlink is recorded as a
/// [`FileKind::Symlink`] carrying its target (never followed). Otherwise the link
/// is **followed** and the entry takes its target's kind/content/metadata — so a
/// non-preserved symlink to a file transfers as that file rather than being
/// silently dropped to an empty placeholder. Returns a bare [`EntryMetadata`] on
/// non-unix targets.
///
/// # Errors
///
/// Returns [`StreamingError`] if the path cannot be stat'd, a preserved symlink's
/// target cannot be read, or a non-preserved symlink dangles (stat through the
/// link fails).
#[cfg(unix)]
pub async fn read_entry_metadata(
    abs_path: &Path,
    policy: &MetadataPolicy,
) -> Result<EntryMetadata, StreamingError> {
    use std::os::unix::fs::MetadataExt;

    let lmeta = crate::fs::symlink_metadata(abs_path)
        .await
        .map_err(|e| StreamingError::new(format!("{}: {e}", abs_path.display())))?;

    let mut meta = EntryMetadata::default();

    if lmeta.is_symlink() && policy.preserve_symlinks {
        meta.file_kind = FileKind::Symlink;
        let target = crate::fs::read_link(abs_path)
            .await
            .map_err(|e| StreamingError::new(format!("{}: {e}", abs_path.display())))?;
        meta.symlink_target = Some(target.to_string_lossy().into_owned());
        // Mode/owner/time on a symlink itself are rarely meaningful and need
        // lchown/lutimes; ATP preserves the link + target, not link metadata.
        return Ok(meta);
    }

    // For a non-preserved symlink, stat through the link so the entry reflects
    // its target (the streaming hash also follows the link); otherwise use the
    // path's own metadata.
    let read_xattrs_through_symlink = lmeta.is_symlink();
    let effective = if read_xattrs_through_symlink {
        crate::fs::metadata(abs_path)
            .await
            .map_err(|e| StreamingError::new(format!("{}: {e}", abs_path.display())))?
    } else {
        lmeta
    };

    if effective.is_dir() {
        meta.file_kind = FileKind::Directory;
    } else if !effective.is_file() {
        use std::os::unix::fs::FileTypeExt;
        let ft = effective.inner.file_type();
        meta.file_kind = if ft.is_fifo() {
            FileKind::Fifo
        } else if ft.is_socket() {
            FileKind::Socket
        } else if ft.is_block_device() {
            FileKind::BlockDevice
        } else if ft.is_char_device() {
            FileKind::CharDevice
        } else {
            FileKind::Regular
        };
    }

    let inner = &effective.inner;
    if policy.preserve_unix_permissions {
        meta.unix_mode = Some(inner.mode() & 0o7777);
    }
    if policy.preserve_timestamps {
        meta.mtime_unix_secs = Some(inner.mtime());
        meta.mtime_nanos = u32::try_from(inner.mtime_nsec().rem_euclid(1_000_000_000)).ok();
    }
    if policy.record_platform_metadata {
        meta.uid = Some(inner.uid());
        meta.gid = Some(inner.gid());
    }
    if policy.preserve_extended_attributes {
        meta.xattrs = read_xattrs_best_effort(abs_path, read_xattrs_through_symlink).await;
    }
    Ok(meta)
}

#[cfg(unix)]
async fn read_xattrs_best_effort(
    abs_path: &Path,
    deref_symlink: bool,
) -> BTreeMap<String, Vec<u8>> {
    let path_buf = abs_path.to_path_buf();
    crate::runtime::spawn_blocking(move || {
        let listed = if deref_symlink {
            xattr::list_deref(&path_buf)
        } else {
            xattr::list(&path_buf)
        };
        let Ok(names) = listed else {
            return BTreeMap::new();
        };

        let mut attrs = BTreeMap::new();
        for name in names {
            let Some(name_str) = name.to_str().map(str::to_owned) else {
                continue;
            };
            let value = if deref_symlink {
                xattr::get_deref(&path_buf, &name)
            } else {
                xattr::get(&path_buf, &name)
            };
            if let Ok(Some(value)) = value {
                attrs.insert(name_str, value);
            }
        }
        attrs
    })
    .await
}

/// Non-unix capture: file kind only (regular vs directory), no platform
/// metadata. Symlinks are not represented on non-unix targets, so the link is
/// followed and the entry takes its target's kind (avoids an empty placeholder).
///
/// # Errors
///
/// Returns [`StreamingError`] if the path cannot be stat'd (a dangling symlink
/// fails closed here).
#[cfg(not(unix))]
pub async fn read_entry_metadata(
    abs_path: &Path,
    _policy: &MetadataPolicy,
) -> Result<EntryMetadata, StreamingError> {
    // `metadata` follows symlinks, so the recorded kind is the target's.
    let effective = crate::fs::metadata(abs_path)
        .await
        .map_err(|e| StreamingError::new(format!("{}: {e}", abs_path.display())))?;
    let mut meta = EntryMetadata::default();
    if effective.is_dir() {
        meta.file_kind = FileKind::Directory;
    }
    Ok(meta)
}

/// Returns the `(dev, ino)` identity of `abs_path` when it is a regular file.
///
/// This identity is the basis for detecting hardlinks within a transfer (two
/// entries sharing an inode are hardlinks). Returns `None` for
/// symlinks/dirs/special files, or on non-unix targets.
///
/// # Errors
///
/// Returns [`StreamingError`] if the path cannot be stat'd.
#[cfg(unix)]
pub async fn inode_key_if_regular(abs_path: &Path) -> Result<Option<(u64, u64)>, StreamingError> {
    use std::os::unix::fs::MetadataExt;
    let lmeta = crate::fs::symlink_metadata(abs_path)
        .await
        .map_err(|e| StreamingError::new(format!("{}: {e}", abs_path.display())))?;
    if lmeta.is_file() {
        Ok(Some((lmeta.inner.dev(), lmeta.inner.ino())))
    } else {
        Ok(None)
    }
}

/// Non-unix: hardlink detection is unsupported; never reports an inode identity.
///
/// # Errors
///
/// Never returns an error on non-unix targets.
#[cfg(not(unix))]
pub async fn inode_key_if_regular(_abs_path: &Path) -> Result<Option<(u64, u64)>, StreamingError> {
    Ok(None)
}

/// Apply captured metadata to a committed filesystem entry at `out_path`.
///
/// Applies in a safe order — times, then xattrs, then ownership, then mode last
/// — so a restrictive mode (e.g. `0o444`) does not block the earlier steps.
/// Ownership failures (typically `EPERM` without privilege) and unsupported
/// xattrs are recorded as skipped, not fatal. Open-based metadata operations are
/// skipped for special files such as FIFOs, where opening the path can block.
/// Symlink entries are created by the caller's commit step, not here.
///
/// # Errors
///
/// Returns [`StreamingError`] only for an unexpected mode/`set_permissions`
/// failure; best-effort fields degrade into the returned report instead.
#[cfg(unix)]
pub async fn apply_entry_metadata(
    out_path: &Path,
    meta: &EntryMetadata,
) -> Result<MetadataApplyReport, StreamingError> {
    let path_buf = out_path.to_path_buf();
    let meta = meta.clone();
    crate::runtime::spawn_blocking(move || apply_entry_metadata_sync(&path_buf, &meta)).await
}

/// Synchronous core of [`apply_entry_metadata`].
///
/// Every step runs on the caller's thread, so batch committers can apply
/// metadata for thousands of packed members inside ONE blocking-pool task
/// instead of paying pool round-trips per file (the same dispatch tail
/// MATRIX-211 eliminated for member writes).
///
/// # Errors
///
/// Returns [`StreamingError`] only for an unexpected mode/`set_permissions`
/// failure; best-effort fields degrade into the returned report instead.
#[cfg(unix)]
pub fn apply_entry_metadata_sync(
    out_path: &Path,
    meta: &EntryMetadata,
) -> Result<MetadataApplyReport, StreamingError> {
    use std::os::unix::fs::PermissionsExt;
    use std::time::{Duration, UNIX_EPOCH};

    let mut report = MetadataApplyReport::default();
    let special_file = meta.file_kind.is_special();

    // Applies in a safe order — times, then xattrs, then ownership, then mode
    // last — so a restrictive mode (e.g. `0o444`) does not block the earlier
    // steps. Open-based operations are skipped for special files such as
    // FIFOs, where opening the path can block.
    if let Some(secs) = (!special_file).then_some(meta.mtime_unix_secs).flatten() {
        let mtime_nanos = meta.mtime_nanos.unwrap_or(0);
        let applied = u64::try_from(secs)
            .map_err(|_| "pre-epoch mtime not representable".to_string())
            .and_then(|secs_u64| {
                // `secs`/`mtime_nanos` arrive off-wire and are untrusted.
                // Normalise the sub-second part into [0, 1e9) (mirroring the
                // read path's `rem_euclid`) so an out-of-range value can't
                // carry into the seconds count, and add via `checked_add` so a
                // crafted huge `secs` (up to i64::MAX, which passes the u64
                // conversion) degrades to a skipped mtime instead of panicking
                // the blocking pool by overflowing `SystemTime` (DoS via a
                // malicious manifest).
                let nanos = mtime_nanos % 1_000_000_000;
                let when = UNIX_EPOCH
                    .checked_add(Duration::new(secs_u64, nanos))
                    .ok_or_else(|| "mtime out of representable range".to_string())?;
                let times = std::fs::FileTimes::new().set_modified(when);
                std::fs::File::open(out_path)
                    .and_then(|f| f.set_times(times))
                    .map_err(|e| e.to_string())
            });
        match applied {
            Ok(()) => report.mark_applied("mtime"),
            Err(e) => report.mark_skipped("mtime", e),
        }
    }
    if special_file && meta.mtime_unix_secs.is_some() {
        report.mark_skipped(
            "mtime",
            "open-based timestamp apply skipped for special file".to_string(),
        );
    }

    if !meta.xattrs.is_empty() && !special_file {
        let mut any_applied = false;
        for (name, value) in &meta.xattrs {
            match xattr::set(out_path, name, value) {
                Ok(()) => any_applied = true,
                Err(e) => report.mark_skipped("xattr", format!("{name}: {e}")),
            }
        }
        if any_applied {
            report.mark_applied("xattr");
        }
    }
    if special_file && !meta.xattrs.is_empty() {
        report.mark_skipped("xattr", "xattr apply skipped for special file".to_string());
    }

    if let (Some(u), Some(g)) = (meta.uid, meta.gid) {
        match std::os::unix::fs::chown(out_path, Some(u), Some(g)) {
            Ok(()) => report.mark_applied("owner"),
            Err(e) => report.mark_skipped("owner", e.to_string()),
        }
    }

    if let Some(mode) = meta.unix_mode {
        std::fs::set_permissions(out_path, std::fs::Permissions::from_mode(mode))
            .map_err(|e| StreamingError::new(format!("{}: {e}", out_path.display())))?;
        report.mark_applied("mode");
    }

    Ok(report)
}

/// Non-unix apply: nothing to do; report every present field as skipped.
///
/// # Errors
///
/// Never returns an error on non-unix targets.
#[cfg(not(unix))]
pub async fn apply_entry_metadata(
    _out_path: &Path,
    meta: &EntryMetadata,
) -> Result<MetadataApplyReport, StreamingError> {
    apply_entry_metadata_sync(_out_path, meta)
}

/// Non-unix sync apply: nothing to do; report every present field as skipped.
///
/// # Errors
///
/// Never returns an error on non-unix targets.
#[cfg(not(unix))]
pub fn apply_entry_metadata_sync(
    _out_path: &Path,
    meta: &EntryMetadata,
) -> Result<MetadataApplyReport, StreamingError> {
    let mut report = MetadataApplyReport::default();
    if meta.unix_mode.is_some() {
        report.mark_skipped("mode", "unix permissions unsupported on this platform");
    }
    if meta.mtime_unix_secs.is_some() {
        report.mark_skipped("mtime", "timestamp apply unsupported on this platform");
    }
    if meta.uid.is_some() || meta.gid.is_some() {
        report.mark_skipped("owner", "ownership unsupported on this platform");
    }
    if !meta.xattrs.is_empty() {
        report.mark_skipped("xattr", "extended attributes unsupported on this platform");
    }
    Ok(report)
}

/// Recreate a FIFO (named pipe) at `out_path` with permission `mode`.
///
/// Uses `mkfifo` then `chmod` for the exact mode — neither opens the FIFO, so
/// this never blocks waiting for a peer. Only
/// FIFOs are recreated; sockets and device nodes are the caller's skip-and-log
/// responsibility (sockets are runtime objects, device nodes need privilege).
///
/// # Errors
///
/// Returns [`StreamingError`] if `mkfifo` or the mode application fails.
#[cfg(unix)]
pub async fn recreate_fifo(out_path: &Path, mode: u32) -> Result<(), StreamingError> {
    let perm_bits = mode & 0o7777;
    let path_buf = out_path.to_path_buf();
    crate::runtime::spawn_blocking(move || {
        use nix::sys::stat::Mode;
        // `mkfifo` honors the umask; the exact mode is set by `chmod` below.
        nix::unistd::mkfifo(
            &path_buf,
            Mode::from_bits_truncate(perm_bits as libc::mode_t),
        )
        .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| StreamingError::new(format!("{}: mkfifo: {e}", out_path.display())))?;
    crate::fs::set_permissions(out_path, crate::fs::Permissions::from_mode(perm_bits))
        .await
        .map_err(|e| StreamingError::new(format!("{}: {e}", out_path.display())))?;
    Ok(())
}

/// Non-unix FIFO recreation is unsupported and fails closed.
///
/// # Errors
///
/// Always returns [`StreamingError`] on non-unix targets.
#[cfg(not(unix))]
pub async fn recreate_fifo(_out_path: &Path, _mode: u32) -> Result<(), StreamingError> {
    Err(StreamingError::new(
        "FIFO recreation unsupported on this platform",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(mode: Option<u32>) -> EntryMetadata {
        EntryMetadata {
            unix_mode: mode,
            ..Default::default()
        }
    }

    fn zero_scan_entry(
        rel_path: &str,
        size_bytes: u64,
        mtime_secs: i64,
        ctime_secs: Option<i64>,
        identity: Option<FileIdentity>,
    ) -> ZeroScanEntry {
        let metadata = EntryMetadata {
            mtime_unix_secs: Some(mtime_secs),
            mtime_nanos: Some(0),
            ..Default::default()
        };
        let mut fingerprint =
            ZeroScanFingerprint::from_entry_metadata(size_bytes, &metadata).with_similarity(
                SimilaritySignature::new(size_bytes.rotate_left(7), Some(size_bytes)),
            );
        if let Some(secs) = ctime_secs {
            fingerprint = fingerprint.with_ctime(secs, 0);
        }
        if let Some(id) = identity {
            fingerprint = fingerprint.with_identity(id);
        }
        ZeroScanEntry::new(rel_path, fingerprint)
    }

    #[test]
    fn zero_scan_prefilter_skips_unchanged_tree() {
        let prior = vec![
            zero_scan_entry("alpha.bin", 10, 1_700_000_000, Some(1_700_000_010), None),
            zero_scan_entry(
                "nested/beta.bin",
                20,
                1_700_000_001,
                Some(1_700_000_011),
                None,
            ),
        ];
        let current = prior.clone();

        let plan = ZeroScanPrefilter::plan(&prior, &current, None, ZeroScanPolicy::default());

        assert_eq!(plan.scheduled_chunk_hashes, 0);
        assert_eq!(plan.skipped_chunk_hashes, 2);
        assert_eq!(plan.skipped_chunk_hash_bytes, 30);
        assert_eq!(plan.estimated_content_bytes_floor, 0);
        assert!(
            plan.decisions
                .iter()
                .all(|decision| matches!(decision, ZeroScanDecision::Unchanged { .. }))
        );
    }

    #[test]
    fn zero_scan_dirty_set_forces_chunk_hashing() {
        let prior = vec![
            zero_scan_entry("alpha.bin", 10, 1_700_000_000, Some(1_700_000_010), None),
            zero_scan_entry(
                "nested/beta.bin",
                20,
                1_700_000_001,
                Some(1_700_000_011),
                None,
            ),
        ];
        let current = prior.clone();
        let dirty = DirtyPathSet::from_paths(["nested/beta.bin"]);

        let plan =
            ZeroScanPrefilter::plan(&prior, &current, Some(&dirty), ZeroScanPolicy::default());

        assert_eq!(plan.skipped_chunk_hashes, 1);
        assert_eq!(plan.scheduled_chunk_hashes, 1);
        assert_eq!(plan.estimated_content_bytes_floor, 20);
        assert!(matches!(
            plan.decisions[1],
            ZeroScanDecision::NeedsChunkHash {
                reason: ZeroScanHashReason::DirtySetHit,
                ..
            }
        ));
    }

    #[test]
    fn zero_scan_detects_rename_without_resending_content() {
        let identity = FileIdentity::new(7, 42);
        let prior = vec![zero_scan_entry(
            "old-name.bin",
            64,
            1_700_000_000,
            Some(1_700_000_010),
            Some(identity),
        )];
        let current = vec![zero_scan_entry(
            "new-name.bin",
            64,
            1_700_000_000,
            Some(1_700_000_010),
            Some(identity),
        )];

        let plan = ZeroScanPrefilter::plan(&prior, &current, None, ZeroScanPolicy::default());

        assert_eq!(plan.scheduled_chunk_hashes, 0);
        assert_eq!(plan.skipped_chunk_hashes, 1);
        assert_eq!(plan.estimated_content_bytes_floor, 0);
        assert_eq!(
            plan.decisions,
            vec![ZeroScanDecision::ReusePriorContent {
                rel_path: "new-name.bin".to_string(),
                prior_rel_path: "old-name.bin".to_string(),
            }]
        );
    }

    #[test]
    fn zero_scan_requires_ctime_by_default() {
        let prior = vec![zero_scan_entry(
            "same-size-mtime.bin",
            64,
            1_700_000_000,
            None,
            None,
        )];
        let current = prior.clone();

        let plan = ZeroScanPrefilter::plan(&prior, &current, None, ZeroScanPolicy::default());

        assert_eq!(plan.scheduled_chunk_hashes, 1);
        assert!(matches!(
            plan.decisions[0],
            ZeroScanDecision::NeedsChunkHash {
                reason: ZeroScanHashReason::StatChanged,
                ..
            }
        ));

        let permissive = ZeroScanPolicy {
            require_ctime: false,
            ..ZeroScanPolicy::default()
        };
        let plan = ZeroScanPrefilter::plan(&prior, &current, None, permissive);
        assert_eq!(plan.scheduled_chunk_hashes, 0);
        assert!(matches!(
            plan.decisions[0],
            ZeroScanDecision::Unchanged { .. }
        ));
    }

    #[test]
    fn bare_metadata_yields_no_commitment() {
        let bare = EntryMetadata::default();
        assert!(bare.is_bare());
        assert_eq!(metadata_commitment(&[("a", &bare), ("b", &bare)]), None);
    }

    #[test]
    fn commitment_is_order_independent_and_64_hex() {
        let a = meta(Some(0o644));
        let b = meta(Some(0o755));
        let r1 = metadata_commitment(&[("a", &a), ("b", &b)]).expect("commitment");
        let r2 = metadata_commitment(&[("b", &b), ("a", &a)]).expect("commitment");
        assert_eq!(r1, r2, "commitment must be order-independent");
        assert_eq!(r1.len(), 64);
        assert!(r1.bytes().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn changing_a_mode_changes_the_commitment() {
        // The headline "merkle covers metadata" property: flip one mode bit and
        // the committed root must move.
        let before = metadata_commitment(&[("f", &meta(Some(0o644)))]).expect("c");
        let after = metadata_commitment(&[("f", &meta(Some(0o600)))]).expect("c");
        assert_ne!(before, after, "metadata change must change the commitment");
    }

    #[test]
    fn changing_mtime_or_symlink_changes_the_commitment() {
        let base = EntryMetadata {
            unix_mode: Some(0o644),
            mtime_unix_secs: Some(1000),
            ..Default::default()
        };
        let mut later = base.clone();
        later.mtime_unix_secs = Some(2000);
        assert_ne!(
            metadata_commitment(&[("f", &base)]),
            metadata_commitment(&[("f", &later)]),
        );
        let mut link = base.clone();
        link.file_kind = FileKind::Symlink;
        link.symlink_target = Some("target.txt".to_string());
        assert_ne!(
            metadata_commitment(&[("f", &base)]),
            metadata_commitment(&[("f", &link)]),
        );
    }

    #[test]
    fn changing_xattrs_changes_the_commitment() {
        let mut base = meta(Some(0o644));
        base.xattrs
            .insert("user.asupersync.alpha".to_string(), b"one".to_vec());
        let mut changed = base.clone();
        changed
            .xattrs
            .insert("user.asupersync.alpha".to_string(), b"two".to_vec());
        assert_ne!(
            metadata_commitment(&[("f", &base)]),
            metadata_commitment(&[("f", &changed)]),
            "xattr value changes must move the metadata commitment"
        );

        let mut renamed = base.clone();
        renamed.xattrs.clear();
        renamed
            .xattrs
            .insert("user.asupersync.beta".to_string(), b"one".to_vec());
        assert_ne!(
            metadata_commitment(&[("f", &base)]),
            metadata_commitment(&[("f", &renamed)]),
            "xattr name changes must move the metadata commitment"
        );
    }

    #[test]
    fn presence_distinguishes_absent_from_zero() {
        let absent = EntryMetadata {
            unix_mode: Some(0o644),
            ..Default::default()
        };
        let zero_uid = EntryMetadata {
            unix_mode: Some(0o644),
            uid: Some(0),
            gid: Some(0),
            ..Default::default()
        };
        assert_ne!(
            metadata_commitment(&[("f", &absent)]),
            metadata_commitment(&[("f", &zero_uid)]),
            "absent uid must hash differently from uid=0",
        );
    }

    #[test]
    fn entry_metadata_json_round_trips() {
        let m = EntryMetadata {
            file_kind: FileKind::Symlink,
            unix_mode: Some(0o777),
            mtime_unix_secs: Some(1_700_000_000),
            mtime_nanos: Some(123),
            uid: Some(1000),
            gid: Some(1000),
            symlink_target: Some("../t".to_string()),
            hardlink_target: None,
            xattrs: BTreeMap::from([("user.asupersync.note".to_string(), b"hello".to_vec())]),
        };
        let js = serde_json::to_string(&m).expect("ser");
        let back: EntryMetadata = serde_json::from_str(&js).expect("de");
        assert_eq!(m, back);
    }

    #[cfg(unix)]
    #[test]
    fn apply_metadata_huge_mtime_nanos_carry_does_not_panic() {
        let meta = EntryMetadata {
            mtime_unix_secs: Some(i64::MAX),
            mtime_nanos: Some(1_000_000_000),
            ..Default::default()
        };
        let path = Path::new("/asupersync-metadata-mtime-overflow-regression-missing-file");

        let report = futures_lite::future::block_on(apply_entry_metadata(path, &meta))
            .expect("out-of-range off-wire mtime must degrade into a metadata report");

        assert!(report.applied.is_empty());
        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.skipped[0].0, "mtime");
    }

    #[cfg(unix)]
    #[test]
    fn apply_metadata_pre_epoch_mtime_is_skipped() {
        let meta = EntryMetadata {
            mtime_unix_secs: Some(-1),
            mtime_nanos: Some(999_999_999),
            ..Default::default()
        };
        let path = Path::new("/asupersync-metadata-pre-epoch-regression-missing-file");

        let report = futures_lite::future::block_on(apply_entry_metadata(path, &meta))
            .expect("pre-epoch off-wire mtime must degrade into a metadata report");

        assert!(report.applied.is_empty());
        assert_eq!(
            report.skipped,
            vec![("mtime", "pre-epoch mtime not representable".to_string())]
        );
    }

    #[test]
    fn bare_regular_omits_optional_fields_in_json() {
        let m = EntryMetadata::default();
        let js = serde_json::to_string(&m).expect("ser");
        // Only file_kind survives; optionals are skipped.
        assert!(js.contains("file_kind"));
        assert!(!js.contains("unix_mode"));
        assert!(!js.contains("symlink_target"));
    }
}
