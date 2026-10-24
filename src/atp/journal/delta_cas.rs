//! Journal-backed content-addressed chunk store for incremental ATP re-sync.
//!
//! B-8 keeps the FastCDC chunker separate from persistence: the chunker decides
//! boundaries, while this module stores verified chunks by content id and records
//! a deterministic Merkle manifest for the receiver's prior tree state.

use crate::net::atp::chunk::dedupe::CdcChunkData;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const DELTA_CAS_SCHEMA: &str = "asupersync.atp.delta-cas.v1";
const EMPTY_ROOT_DOMAIN: &[u8] = b"asupersync.atp.delta-cas.empty-root.v1\0";
const LEAF_DOMAIN: &[u8] = b"asupersync.atp.delta-cas.leaf.v1\0";
const NODE_DOMAIN: &[u8] = b"asupersync.atp.delta-cas.node.v1\0";
const MANIFEST_PATH_DOMAIN: &[u8] = b"asupersync.atp.delta-cas.manifest-path.v1\0";

/// SHA-256 chunk identity used by the delta CAS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeltaChunkId([u8; 32]);

impl DeltaChunkId {
    /// Compute a chunk id from bytes.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Self(hasher.finalize().into())
    }

    /// Build an id from an already-verified SHA-256 digest.
    #[must_use]
    pub const fn from_hash(hash: [u8; 32]) -> Self {
        Self(hash)
    }

    /// Raw digest bytes.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Lowercase hex encoding.
    #[must_use]
    pub fn to_hex(self) -> String {
        hex_hash(&self.0)
    }
}

/// One chunk entry in a persistent delta manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeltaChunkRef {
    /// Content-addressed chunk id.
    pub id: DeltaChunkId,
    /// Byte offset in the logical tree/file stream.
    pub byte_offset: u64,
    /// Chunk length in bytes.
    pub size_bytes: u64,
}

impl DeltaChunkRef {
    /// Create a manifest chunk reference.
    #[must_use]
    pub const fn new(id: DeltaChunkId, byte_offset: u64, size_bytes: u64) -> Self {
        Self {
            id,
            byte_offset,
            size_bytes,
        }
    }

    /// Create a chunk reference by hashing bytes.
    #[must_use]
    pub fn from_bytes(byte_offset: u64, bytes: &[u8]) -> Self {
        Self::new(
            DeltaChunkId::from_bytes(bytes),
            byte_offset,
            bytes.len() as u64,
        )
    }
}

impl From<&CdcChunkData> for DeltaChunkRef {
    fn from(chunk: &CdcChunkData) -> Self {
        Self::new(
            DeltaChunkId::from_hash(chunk.content_hash),
            chunk.byte_offset,
            chunk.size_bytes,
        )
    }
}

/// Stable Merkle manifest over ordered content-defined chunks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaMerkleManifest {
    tree_id: String,
    chunks: Vec<DeltaChunkRef>,
    merkle_root: [u8; 32],
    total_bytes: u64,
}

impl DeltaMerkleManifest {
    /// Build a deterministic manifest for one tree/file version.
    ///
    /// Chunks are canonicalized by offset, size, then id before the Merkle root
    /// is computed, so repeated scans of the same bytes produce identical roots.
    pub fn new(
        tree_id: impl Into<String>,
        mut chunks: Vec<DeltaChunkRef>,
    ) -> Result<Self, DeltaCasError> {
        chunks.sort_by_key(|chunk| (chunk.byte_offset, chunk.size_bytes, chunk.id));
        let total_bytes = chunks.iter().try_fold(0u64, |max_end, chunk| {
            let end = chunk.byte_offset.checked_add(chunk.size_bytes).ok_or(
                DeltaCasError::ChunkOffsetOverflow {
                    byte_offset: chunk.byte_offset,
                    size_bytes: chunk.size_bytes,
                },
            )?;
            Ok::<u64, DeltaCasError>(max_end.max(end))
        })?;
        let merkle_root = merkle_root_for_chunks(&chunks);
        Ok(Self {
            tree_id: tree_id.into(),
            chunks,
            merkle_root,
            total_bytes,
        })
    }

    /// Tree or file identity this manifest describes.
    #[must_use]
    pub fn tree_id(&self) -> &str {
        &self.tree_id
    }

    /// Ordered chunk references.
    #[must_use]
    pub fn chunks(&self) -> &[DeltaChunkRef] {
        &self.chunks
    }

    /// Merkle root over all chunks.
    #[must_use]
    pub const fn merkle_root(&self) -> [u8; 32] {
        self.merkle_root
    }

    /// Logical byte length covered by the manifest.
    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Compute what the current manifest needs relative to a previous receiver baseline.
    #[must_use]
    pub fn diff_against(&self, previous: &Self) -> DeltaManifestDiff {
        let previous_set: BTreeSet<ChunkSetKey> =
            previous.chunks.iter().map(ChunkSetKey::from).collect();
        let current_set: BTreeSet<ChunkSetKey> =
            self.chunks.iter().map(ChunkSetKey::from).collect();
        let missing_chunks = self
            .chunks
            .iter()
            .copied()
            .filter(|chunk| !previous_set.contains(&ChunkSetKey::from(chunk)))
            .collect();
        let stale_chunks = previous
            .chunks
            .iter()
            .copied()
            .filter(|chunk| !current_set.contains(&ChunkSetKey::from(chunk)))
            .collect();
        let changed_subtrees = changed_leaf_ranges(&previous.chunks, &self.chunks);

        DeltaManifestDiff {
            missing_chunks,
            stale_chunks,
            changed_subtrees,
        }
    }

    /// Deterministic on-disk representation for the journal artifact.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut out = String::new();
        out.push_str(DELTA_CAS_SCHEMA);
        out.push('\n');
        out.push_str("tree_id=");
        out.push_str(&self.tree_id);
        out.push('\n');
        out.push_str("total_bytes=");
        out.push_str(&self.total_bytes.to_string());
        out.push('\n');
        out.push_str("merkle_root=");
        out.push_str(&hex_hash(&self.merkle_root));
        out.push('\n');
        out.push_str("chunks=");
        out.push_str(&self.chunks.len().to_string());
        out.push('\n');
        for chunk in &self.chunks {
            out.push_str("chunk=");
            out.push_str(&chunk.byte_offset.to_string());
            out.push(':');
            out.push_str(&chunk.size_bytes.to_string());
            out.push(':');
            out.push_str(&chunk.id.to_hex());
            out.push('\n');
        }
        out.into_bytes()
    }
}

/// Difference between a receiver baseline and a target tree manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaManifestDiff {
    /// Target chunks absent from the receiver baseline CAS.
    pub missing_chunks: Vec<DeltaChunkRef>,
    /// Receiver-baseline chunks absent from the target tree.
    pub stale_chunks: Vec<DeltaChunkRef>,
    /// Changed leaf ranges in canonical manifest order.
    pub changed_subtrees: Vec<DeltaSubtreeRange>,
}

/// Half-open range of changed manifest leaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeltaSubtreeRange {
    /// First changed leaf index.
    pub start_leaf: usize,
    /// First leaf index after the changed range.
    pub end_leaf: usize,
}

/// File-backed CAS rooted inside the ATP journal directory.
///
/// New files sync their data before atomic publication. Unix also syncs
/// validated dedup files, publication directories, and newly created store
/// ancestors; an unsupported or failed sync barrier is an error. On other
/// targets dedup only validates bytes, and directory-entry durability across
/// power loss is not promised. The store root must be privately controlled;
/// this path-based API is not a hostile-filesystem containment boundary.
#[derive(Debug, Clone)]
pub struct DeltaCasStore {
    root: PathBuf,
}

impl DeltaCasStore {
    /// Open or create a delta CAS at `root`.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, DeltaCasError> {
        let root = root.as_ref().to_path_buf();
        create_store_directories(&root)?;
        Ok(Self { root })
    }

    /// Store bytes under their content id. Existing identical bytes are a dedup hit.
    ///
    /// New content is written and synced in a private staging file, then
    /// published without replacing a winner. Readers never observe a partial
    /// write through its content-addressed name.
    pub fn put_chunk(&self, bytes: &[u8]) -> Result<DeltaCasWrite, DeltaCasError> {
        let id = DeltaChunkId::from_bytes(bytes);
        let size_bytes = bytes.len() as u64;
        let path = self.chunk_path(id, size_bytes);
        let inserted = if path.exists() {
            self.verify_existing_chunk(&path, id, bytes)?;
            false
        } else if publish_file_new(&path, |file| file.write_all(bytes))? {
            true
        } else {
            self.verify_existing_chunk(&path, id, bytes)?;
            false
        };

        Ok(DeltaCasWrite {
            id,
            size_bytes,
            inserted,
        })
    }

    /// Store a FastCDC chunk and fail closed if the supplied bytes do not match it.
    pub fn put_cdc_chunk(
        &self,
        chunk: &CdcChunkData,
        bytes: &[u8],
    ) -> Result<DeltaCasWrite, DeltaCasError> {
        let size_bytes = u64::try_from(bytes.len()).map_err(|_| DeltaCasError::ChunkTooLarge)?;
        if size_bytes != chunk.size_bytes {
            return Err(DeltaCasError::ChunkSizeMismatch {
                expected: chunk.size_bytes,
                actual: size_bytes,
            });
        }
        let id = DeltaChunkId::from_bytes(bytes);
        let expected = DeltaChunkId::from_hash(chunk.content_hash);
        if id != expected {
            return Err(DeltaCasError::ChunkHashMismatch {
                expected,
                actual: id,
            });
        }
        self.put_chunk(bytes)
    }

    /// Load a chunk by id and size.
    pub fn get_chunk(
        &self,
        id: DeltaChunkId,
        size_bytes: u64,
    ) -> Result<Option<Vec<u8>>, DeltaCasError> {
        let path = self.chunk_path(id, size_bytes);
        match fs::read(&path) {
            Ok(bytes) => {
                let actual = DeltaChunkId::from_bytes(&bytes);
                if actual != id {
                    return Err(DeltaCasError::ChunkHashMismatch {
                        expected: id,
                        actual,
                    });
                }
                Ok(Some(bytes))
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    /// Whether the chunk is present and hash-valid.
    pub fn has_chunk(&self, id: DeltaChunkId, size_bytes: u64) -> Result<bool, DeltaCasError> {
        self.get_chunk(id, size_bytes).map(|chunk| chunk.is_some())
    }

    /// Persist a manifest as a new journal artifact.
    ///
    /// Identical existing bytes are a dedup hit and return false. A different
    /// manifest under the same tree id is refused with an AlreadyExists I/O
    /// error; this operation never replaces an existing baseline or reports
    /// that an unwritten candidate was persisted.
    pub fn persist_manifest_new(
        &self,
        manifest: &DeltaMerkleManifest,
    ) -> Result<bool, DeltaCasError> {
        let bytes = manifest.to_canonical_bytes();
        let path = self.manifest_path(manifest.tree_id());
        if !path.exists() && publish_file_new(&path, |file| file.write_all(&bytes))? {
            return Ok(true);
        }
        let (identical, _) = inspect_file_bytes(&path, &bytes)?;
        if !identical {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "delta CAS tree id already has a different manifest",
            )
            .into());
        }
        sync_parent_directory(&path)?;
        Ok(false)
    }

    /// Load the persisted canonical manifest bytes for `tree_id`, if present.
    pub fn load_manifest_bytes(&self, tree_id: &str) -> Result<Option<Vec<u8>>, DeltaCasError> {
        let path = self.manifest_path(tree_id);
        match fs::read(path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    fn chunk_path(&self, id: DeltaChunkId, size_bytes: u64) -> PathBuf {
        let hash_hex = id.to_hex();
        self.root
            .join("chunks")
            .join(&hash_hex[..2])
            .join(format!("{hash_hex}-{size_bytes:016x}.chunk"))
    }

    fn manifest_path(&self, tree_id: &str) -> PathBuf {
        let name = hex_hash(&domain_hash(MANIFEST_PATH_DOMAIN, &[tree_id.as_bytes()]));
        self.root.join("manifests").join(format!("{name}.manifest"))
    }

    fn verify_existing_chunk(
        &self,
        path: &Path,
        id: DeltaChunkId,
        expected_bytes: &[u8],
    ) -> Result<(), DeltaCasError> {
        let (identical, actual) = inspect_file_bytes(path, expected_bytes)?;
        if !identical {
            return Err(DeltaCasError::ChunkHashMismatch {
                expected: id,
                actual: DeltaChunkId::from_hash(actual),
            });
        }
        sync_parent_directory(path)?;
        Ok(())
    }
}

/// Result of a CAS write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeltaCasWrite {
    /// Stored chunk id.
    pub id: DeltaChunkId,
    /// Stored chunk size.
    pub size_bytes: u64,
    /// True when the CAS created a new object; false on dedup hit.
    pub inserted: bool,
}

/// Delta CAS and manifest errors.
#[derive(Debug, thiserror::Error)]
pub enum DeltaCasError {
    /// Filesystem error.
    #[error("delta CAS I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Chunk byte length does not match the FastCDC record.
    #[error("delta CAS chunk size mismatch: expected {expected}, got {actual}")]
    ChunkSizeMismatch {
        /// Expected size.
        expected: u64,
        /// Actual size.
        actual: u64,
    },
    /// Chunk bytes do not hash to the expected id.
    #[error("delta CAS chunk hash mismatch: expected {expected:?}, got {actual:?}")]
    ChunkHashMismatch {
        /// Expected id.
        expected: DeltaChunkId,
        /// Actual id.
        actual: DeltaChunkId,
    },
    /// Chunk offset + size overflowed.
    #[error("delta manifest chunk offset overflow: offset {byte_offset}, size {size_bytes}")]
    ChunkOffsetOverflow {
        /// Chunk byte offset.
        byte_offset: u64,
        /// Chunk size.
        size_bytes: u64,
    },
    /// Chunk input was too large to represent.
    #[error("delta CAS chunk is too large to represent")]
    ChunkTooLarge,
}

// Private staging names are never accepted as chunk or manifest identities.
static NEXT_STAGING_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

struct StagingFile {
    path: PathBuf,
}

impl StagingFile {
    fn create(parent: &Path) -> std::io::Result<(Self, fs::File)> {
        for _ in 0..128 {
            let serial = NEXT_STAGING_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let path = parent.join(format!(
                ".delta-cas-staging-{}-{serial:016x}.tmp",
                std::process::id()
            ));
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(file) => return Ok((Self { path }, file)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "delta CAS could not reserve a unique staging file",
        ))
    }
}

impl Drop for StagingFile {
    fn drop(&mut self) {
        // Only this operation's create_new-owned staging name is removed.
        // An interrupted process may leave staging garbage, never a partial
        // object reachable through a content or manifest identity.
        let _ = fs::remove_file(&self.path);
    }
}

/// Publish one complete file without clobbering an already-published winner.
/// The callback keeps write-failure boundaries directly testable.
fn publish_file_new(
    path: &Path,
    write: impl FnOnce(&mut fs::File) -> std::io::Result<()>,
) -> std::io::Result<bool> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "CAS path has no parent")
    })?;
    // The store roots already exist. Only the one-level hash shard may be new.
    match fs::create_dir(parent) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    sync_parent_directory(parent)?;
    let (staging, mut file) = StagingFile::create(parent)?;
    let written = write(&mut file).and_then(|()| file.sync_all());
    // Close before publication or cleanup, including a short/failed write.
    drop(file);
    written?;
    let inserted = match fs::hard_link(&staging.path, path) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(error) => return Err(error),
    };
    drop(staging);
    sync_directory(parent)?;
    Ok(inserted)
}

/// Compare every byte and hash the existing object with fixed working memory.
fn inspect_file_bytes(path: &Path, expected: &[u8]) -> std::io::Result<(bool, [u8; 32])> {
    let mut file = fs::File::open(path)?;
    let mut buffer = [0_u8; 8192];
    let mut offset = 0_usize;
    let mut identical = true;
    let mut hasher = Sha256::new();
    loop {
        let count = match file.read(&mut buffer) {
            Ok(count) => count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        let end = offset.saturating_add(count);
        identical &= expected.get(offset..end) == Some(&buffer[..count]);
        offset = end;
    }
    let identical = identical && offset == expected.len();
    #[cfg(unix)]
    if identical {
        // Upgrade a valid legacy/imported object before acknowledging dedup.
        // Keep the same read-only handle used for byte validation.
        file.sync_all()?;
    }
    Ok((identical, hasher.finalize().into()))
}

fn sync_parent_directory(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> std::io::Result<()> {
    let path = if path.as_os_str().is_empty() {
        Path::new(".")
    } else {
        path
    };
    fs::File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> std::io::Result<()> {
    // File data is synced on every target; portable std has no equivalent
    // directory-entry durability barrier outside Unix.
    Ok(())
}

fn create_store_directories(root: &Path) -> std::io::Result<()> {
    fs::create_dir_all(root.join("chunks"))?;
    fs::create_dir_all(root.join("manifests"))?;
    #[cfg(unix)]
    {
        sync_directory(&root.join("chunks"))?;
        sync_directory(&root.join("manifests"))?;
        // Persist newly-created ancestors too, not just the leaf directory.
        let root = fs::canonicalize(if root.as_os_str().is_empty() {
            Path::new(".")
        } else {
            root
        })?;
        for ancestor in root.ancestors() {
            sync_directory(ancestor)?;
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct ChunkSetKey {
    id: DeltaChunkId,
    size_bytes: u64,
}

impl From<&DeltaChunkRef> for ChunkSetKey {
    fn from(chunk: &DeltaChunkRef) -> Self {
        Self {
            id: chunk.id,
            size_bytes: chunk.size_bytes,
        }
    }
}

impl From<DeltaChunkRef> for ChunkSetKey {
    fn from(chunk: DeltaChunkRef) -> Self {
        Self::from(&chunk)
    }
}

fn merkle_root_for_chunks(chunks: &[DeltaChunkRef]) -> [u8; 32] {
    subtree_hash(chunks, 0, chunks.len())
}

fn subtree_hash(chunks: &[DeltaChunkRef], start: usize, end: usize) -> [u8; 32] {
    if start >= end {
        return domain_hash(EMPTY_ROOT_DOMAIN, &[]);
    }
    if end - start == 1 {
        let chunk = chunks[start];
        return domain_hash(
            LEAF_DOMAIN,
            &[
                &chunk.byte_offset.to_be_bytes(),
                &chunk.size_bytes.to_be_bytes(),
                &chunk.id.as_bytes(),
            ],
        );
    }

    let mid = start + (end - start) / 2;
    let left = subtree_hash(chunks, start, mid);
    let right = subtree_hash(chunks, mid, end);
    domain_hash(NODE_DOMAIN, &[&left, &right])
}

fn changed_leaf_ranges(
    previous: &[DeltaChunkRef],
    current: &[DeltaChunkRef],
) -> Vec<DeltaSubtreeRange> {
    if subtree_hash(previous, 0, previous.len()) == subtree_hash(current, 0, current.len()) {
        return Vec::new();
    }
    if previous.len() != current.len() {
        return vec![DeltaSubtreeRange {
            start_leaf: 0,
            end_leaf: previous.len().max(current.len()),
        }];
    }

    let mut ranges = Vec::new();
    collect_changed_ranges(previous, current, 0, current.len(), &mut ranges);
    merge_adjacent_ranges(ranges)
}

fn collect_changed_ranges(
    previous: &[DeltaChunkRef],
    current: &[DeltaChunkRef],
    start: usize,
    end: usize,
    ranges: &mut Vec<DeltaSubtreeRange>,
) {
    if subtree_hash(previous, start, end) == subtree_hash(current, start, end) {
        return;
    }
    if end - start <= 1 {
        ranges.push(DeltaSubtreeRange {
            start_leaf: start,
            end_leaf: end,
        });
        return;
    }

    let mid = start + (end - start) / 2;
    collect_changed_ranges(previous, current, start, mid, ranges);
    collect_changed_ranges(previous, current, mid, end, ranges);
}

fn merge_adjacent_ranges(ranges: Vec<DeltaSubtreeRange>) -> Vec<DeltaSubtreeRange> {
    let mut merged: Vec<DeltaSubtreeRange> = Vec::new();
    for range in ranges {
        if let Some(last) = merged.last_mut()
            && last.end_leaf == range.start_leaf
        {
            last.end_leaf = range.end_leaf;
            continue;
        }
        merged.push(range);
    }
    merged
}

fn domain_hash(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn hex_hash(hash: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in hash {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
#[path = "delta_cas_inline_tests.rs"]
mod tests;
