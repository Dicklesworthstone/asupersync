//! Receiver-side reassembly for the B-8 delta chunk path.
//!
//! The receiver combines unchanged chunks already present in its local CAS with
//! newly decoded delta chunks, verifies the target CAS Merkle manifest, verifies
//! a whole-tree SHA-256 digest, and only then exposes bytes for commit.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use sha2::{Digest, Sha256};

use super::ChunkingProfileError;
use super::cas::{CasManifestChunk, CasMerkleManifest, ChunkAddress, ContentAddressedChunkStore};
use super::delta_stream::DeltaChunkPayload;

const TREE_DIGEST_DOMAIN: &[u8] = b"asupersync:atp:delta-reassembly:tree-digest:v1";

/// Source used for a manifest chunk during receiver reassembly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReassembledChunkSource {
    /// The chunk was already present in the receiver content-addressed store.
    Cas,
    /// The chunk came from the decoded B-8.4 RaptorQ delta stream.
    Decoded,
}

/// One manifest chunk selected for the final tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReassembledChunk {
    /// Transfer-relative path.
    pub rel_path: String,
    /// Byte offset within the file.
    pub byte_offset: u64,
    /// Content-addressed identity.
    pub address: ChunkAddress,
    /// Where the receiver obtained these bytes.
    pub source: ReassembledChunkSource,
}

/// Fully reassembled logical file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReassembledFile {
    /// Transfer-relative path.
    pub rel_path: String,
    /// Verified file bytes.
    pub bytes: Vec<u8>,
    /// Plain SHA-256 over `bytes`.
    pub sha256: [u8; 32],
}

/// Verified receiver reassembly output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReassembledTree {
    /// Stable CAS tree identifier.
    pub tree_id: String,
    /// Reassembled files in deterministic path order.
    pub files: Vec<ReassembledFile>,
    /// Target CAS Merkle root.
    pub manifest_root: [u8; 32],
    /// Domain-separated whole-tree SHA-256 over file paths and bytes.
    pub tree_sha256: [u8; 32],
    /// Sum of logical file bytes.
    pub logical_bytes: u64,
    /// Manifest chunks selected in target order.
    pub chunks: Vec<ReassembledChunk>,
}

impl ReassembledTree {
    /// Return the file for `rel_path`, if present.
    #[must_use]
    pub fn file(&self, rel_path: &str) -> Option<&ReassembledFile> {
        self.files.iter().find(|file| file.rel_path == rel_path)
    }

    /// Count chunks satisfied by the receiver CAS.
    #[must_use]
    pub fn cas_chunk_count(&self) -> usize {
        self.chunks
            .iter()
            .filter(|chunk| chunk.source == ReassembledChunkSource::Cas)
            .count()
    }

    /// Count chunks supplied by decoded delta data.
    #[must_use]
    pub fn decoded_chunk_count(&self) -> usize {
        self.chunks
            .iter()
            .filter(|chunk| chunk.source == ReassembledChunkSource::Decoded)
            .count()
    }
}

/// Receipt for an atomic staging-directory commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReassemblyCommitReceipt {
    /// Destination root renamed into place.
    pub destination_root: PathBuf,
    /// Committed relative file paths.
    pub committed_paths: Vec<String>,
    /// Whole-tree digest that passed the fail-closed gate.
    pub tree_sha256: [u8; 32],
    /// CAS Merkle root that passed the fail-closed gate.
    pub manifest_root: [u8; 32],
}

/// Combine receiver CAS chunks and decoded chunks into the target tree.
///
/// No bytes are returned unless every target manifest entry is present,
/// hash-correct, contiguous within its file, and the recomputed CAS Merkle root
/// plus whole-tree SHA-256 both match the caller's commitments.
pub fn reassemble_from_cas_and_decoded<I>(
    target_manifest: &CasMerkleManifest,
    receiver_cas: &ContentAddressedChunkStore,
    decoded_chunks: I,
    expected_tree_sha256: [u8; 32],
) -> Result<ReassembledTree, ChunkingProfileError>
where
    I: IntoIterator<Item = DeltaChunkPayload>,
{
    let decoded_by_address = decoded_chunk_map(decoded_chunks)?;
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut observed_manifest_chunks = Vec::with_capacity(target_manifest.entries().len());
    let mut chunks = Vec::with_capacity(target_manifest.entries().len());

    for entry in target_manifest.entries() {
        let (bytes, source) = if let Some(bytes) = receiver_cas.get(&entry.address) {
            (bytes, ReassembledChunkSource::Cas)
        } else if let Some(bytes) = decoded_by_address.get(&entry.address) {
            (bytes.as_slice(), ReassembledChunkSource::Decoded)
        } else {
            return Err(ChunkingProfileError::InvalidChunkParameters(format!(
                "target chunk for {} at offset {} is missing from receiver CAS and decoded delta",
                entry.rel_path, entry.byte_offset
            )));
        };

        verify_chunk_bytes(entry.address, bytes)?;
        let file = files.entry(entry.rel_path.clone()).or_default();
        let next_offset = u64::try_from(file.len()).map_err(|_| {
            ChunkingProfileError::InvalidChunkParameters(
                "reassembled file exceeds u64::MAX".to_string(),
            )
        })?;
        if entry.byte_offset != next_offset {
            return Err(ChunkingProfileError::InvalidChunkParameters(format!(
                "non-contiguous chunk layout for {}: expected offset {}, manifest offset {}",
                entry.rel_path, next_offset, entry.byte_offset
            )));
        }
        file.extend_from_slice(bytes);

        observed_manifest_chunks.push(CasManifestChunk {
            rel_path: entry.rel_path.clone(),
            byte_offset: entry.byte_offset,
            address: entry.address,
        });
        chunks.push(ReassembledChunk {
            rel_path: entry.rel_path.clone(),
            byte_offset: entry.byte_offset,
            address: entry.address,
            source,
        });
    }

    let recomputed_manifest = CasMerkleManifest::from_chunks(
        target_manifest.tree_id().to_string(),
        observed_manifest_chunks,
    )?;
    if recomputed_manifest.root() != target_manifest.root() {
        return Err(ChunkingProfileError::InvalidChunkParameters(
            "reassembled CAS Merkle root does not match target manifest".to_string(),
        ));
    }

    let mut files = files
        .into_iter()
        .map(|(rel_path, bytes)| {
            let sha256 = sha256(&bytes);
            ReassembledFile {
                rel_path,
                bytes,
                sha256,
            }
        })
        .collect::<Vec<_>>();
    files.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));

    let tree_sha256 = tree_digest(&files)?;
    if tree_sha256 != expected_tree_sha256 {
        return Err(ChunkingProfileError::InvalidChunkParameters(
            "reassembled whole-tree SHA-256 does not match target commitment".to_string(),
        ));
    }

    let logical_bytes = files.iter().try_fold(0u64, |total, file| {
        let len = u64::try_from(file.bytes.len()).map_err(|_| {
            ChunkingProfileError::InvalidChunkParameters(
                "reassembled file length exceeds u64::MAX".to_string(),
            )
        })?;
        total.checked_add(len).ok_or_else(|| {
            ChunkingProfileError::InvalidChunkParameters(
                "reassembled tree length exceeds u64::MAX".to_string(),
            )
        })
    })?;

    Ok(ReassembledTree {
        tree_id: target_manifest.tree_id().to_string(),
        files,
        manifest_root: target_manifest.root(),
        tree_sha256,
        logical_bytes,
        chunks,
    })
}

/// Reassemble, stage to a caller-provided directory, verify staged bytes, and
/// atomically rename the staging root to `destination_root`.
///
/// This helper never commits over an existing destination. Callers that need
/// version switching can point `destination_root` at a fresh version directory
/// and perform their higher-level pointer swap after this fail-closed receipt.
pub fn stage_and_commit_reassembled_tree<I>(
    target_manifest: &CasMerkleManifest,
    receiver_cas: &ContentAddressedChunkStore,
    decoded_chunks: I,
    expected_tree_sha256: [u8; 32],
    staging_root: &Path,
    destination_root: &Path,
) -> Result<ReassemblyCommitReceipt, ChunkingProfileError>
where
    I: IntoIterator<Item = DeltaChunkPayload>,
{
    let tree = reassemble_from_cas_and_decoded(
        target_manifest,
        receiver_cas,
        decoded_chunks,
        expected_tree_sha256,
    )?;

    if staging_root.exists() {
        return Err(ChunkingProfileError::InvalidChunkParameters(format!(
            "reassembly staging root already exists: {}",
            staging_root.display()
        )));
    }
    if destination_root.exists() {
        return Err(ChunkingProfileError::InvalidChunkParameters(format!(
            "reassembly destination already exists: {}",
            destination_root.display()
        )));
    }

    fs::create_dir_all(staging_root).map_err(io_error)?;
    for file in &tree.files {
        let safe_rel = safe_relative_path(&file.rel_path)?;
        let staged_path = staging_root.join(safe_rel);
        if let Some(parent) = staged_path.parent() {
            fs::create_dir_all(parent).map_err(io_error)?;
        }
        let mut staged = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staged_path)
            .map_err(io_error)?;
        staged.write_all(&file.bytes).map_err(io_error)?;
        staged.flush().map_err(io_error)?;
        staged.sync_all().map_err(io_error)?;
    }

    let staged_digest = digest_staged_tree(staging_root, &tree.files)?;
    if staged_digest != tree.tree_sha256 {
        return Err(ChunkingProfileError::InvalidChunkParameters(
            "staged reassembly digest does not match verified tree digest".to_string(),
        ));
    }

    fs::rename(staging_root, destination_root).map_err(io_error)?;
    Ok(ReassemblyCommitReceipt {
        destination_root: destination_root.to_path_buf(),
        committed_paths: tree
            .files
            .iter()
            .map(|file| file.rel_path.clone())
            .collect(),
        tree_sha256: tree.tree_sha256,
        manifest_root: tree.manifest_root,
    })
}

/// Deterministic whole-tree digest used by the B-8.5 fail-closed gate.
pub fn tree_digest(files: &[ReassembledFile]) -> Result<[u8; 32], ChunkingProfileError> {
    let mut ordered = files.iter().collect::<Vec<_>>();
    ordered.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));

    let mut hasher = Sha256::new();
    hasher.update(TREE_DIGEST_DOMAIN);
    let file_count = u64::try_from(ordered.len()).map_err(|_| {
        ChunkingProfileError::InvalidChunkParameters(
            "reassembled tree file count exceeds u64::MAX".to_string(),
        )
    })?;
    hasher.update(file_count.to_be_bytes());
    for file in ordered {
        let path = file.rel_path.as_bytes();
        let path_len = u64::try_from(path.len()).map_err(|_| {
            ChunkingProfileError::InvalidChunkParameters(
                "reassembled path length exceeds u64::MAX".to_string(),
            )
        })?;
        let byte_len = u64::try_from(file.bytes.len()).map_err(|_| {
            ChunkingProfileError::InvalidChunkParameters(
                "reassembled file length exceeds u64::MAX".to_string(),
            )
        })?;
        hasher.update(path_len.to_be_bytes());
        hasher.update(path);
        hasher.update(byte_len.to_be_bytes());
        hasher.update(file.sha256);
    }
    Ok(hasher.finalize().into())
}

fn decoded_chunk_map<I>(
    decoded_chunks: I,
) -> Result<BTreeMap<ChunkAddress, Vec<u8>>, ChunkingProfileError>
where
    I: IntoIterator<Item = DeltaChunkPayload>,
{
    let mut decoded = BTreeMap::new();
    for chunk in decoded_chunks {
        if sha256(&chunk.bytes) != *chunk.fingerprint.as_bytes() {
            return Err(ChunkingProfileError::InvalidChunkParameters(
                "decoded delta chunk bytes do not match fingerprint".to_string(),
            ));
        }
        let size_bytes = u64::try_from(chunk.bytes.len()).map_err(|_| {
            ChunkingProfileError::InvalidChunkParameters(
                "decoded delta chunk length exceeds u64::MAX".to_string(),
            )
        })?;
        let address = ChunkAddress {
            content_hash: *chunk.fingerprint.as_bytes(),
            size_bytes,
        };
        if let Some(existing) = decoded.insert(address, chunk.bytes.clone())
            && existing != chunk.bytes
        {
            return Err(ChunkingProfileError::InvalidChunkParameters(
                "decoded delta provider returned conflicting bytes for one chunk address"
                    .to_string(),
            ));
        }
    }
    Ok(decoded)
}

fn verify_chunk_bytes(address: ChunkAddress, bytes: &[u8]) -> Result<(), ChunkingProfileError> {
    let observed_size = u64::try_from(bytes.len()).map_err(|_| {
        ChunkingProfileError::InvalidChunkParameters(
            "reassembled chunk length exceeds u64::MAX".to_string(),
        )
    })?;
    if observed_size != address.size_bytes {
        return Err(ChunkingProfileError::InvalidChunkParameters(format!(
            "reassembled chunk size mismatch: expected {}, observed {}",
            address.size_bytes, observed_size
        )));
    }

    let observed_hash = sha256(bytes);
    if observed_hash != address.content_hash {
        return Err(ChunkingProfileError::InvalidChunkParameters(
            "reassembled chunk hash mismatch".to_string(),
        ));
    }
    Ok(())
}

fn digest_staged_tree(
    staging_root: &Path,
    expected_files: &[ReassembledFile],
) -> Result<[u8; 32], ChunkingProfileError> {
    let mut staged_files = Vec::with_capacity(expected_files.len());
    for file in expected_files {
        let path = staging_root.join(safe_relative_path(&file.rel_path)?);
        let bytes = fs::read(path).map_err(io_error)?;
        staged_files.push(ReassembledFile {
            rel_path: file.rel_path.clone(),
            sha256: sha256(&bytes),
            bytes,
        });
    }
    tree_digest(&staged_files)
}

fn safe_relative_path(rel_path: &str) -> Result<PathBuf, ChunkingProfileError> {
    if rel_path.is_empty() {
        return Err(ChunkingProfileError::InvalidChunkParameters(
            "reassembly relative path must not be empty".to_string(),
        ));
    }

    let path = Path::new(rel_path);
    if path.is_absolute() {
        return Err(ChunkingProfileError::InvalidChunkParameters(format!(
            "reassembly relative path is absolute: {rel_path}"
        )));
    }

    let mut safe = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => safe.push(part),
            Component::CurDir => {}
            _ => {
                return Err(ChunkingProfileError::InvalidChunkParameters(format!(
                    "reassembly relative path is not normalized: {rel_path}"
                )));
            }
        }
    }
    if safe.as_os_str().is_empty() {
        return Err(ChunkingProfileError::InvalidChunkParameters(
            "reassembly relative path has no normal components".to_string(),
        ));
    }
    Ok(safe)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn io_error(error: std::io::Error) -> ChunkingProfileError {
    ChunkingProfileError::InvalidChunkParameters(format!("reassembly I/O error: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest_chunk(path: &str, offset: u64, bytes: &[u8]) -> CasManifestChunk {
        CasManifestChunk {
            rel_path: path.to_string(),
            byte_offset: offset,
            address: ChunkAddress::from_bytes(bytes),
        }
    }

    fn expected_digest(path: &str, bytes: &[u8]) -> [u8; 32] {
        tree_digest(&[ReassembledFile {
            rel_path: path.to_string(),
            bytes: bytes.to_vec(),
            sha256: sha256(bytes),
        }])
        .expect("tree digest")
    }

    #[test]
    fn reassembles_from_cas_and_decoded_chunks_byte_identical() {
        let unchanged = b"hello ";
        let changed = b"delta";
        let manifest = CasMerkleManifest::from_chunks(
            "tree",
            [
                manifest_chunk("file.txt", 0, unchanged),
                manifest_chunk("file.txt", unchanged.len() as u64, changed),
            ],
        )
        .expect("manifest");
        let mut cas = ContentAddressedChunkStore::new();
        cas.insert_chunk(unchanged, Some("prior/file.txt".to_string()))
            .expect("cas insert");
        let expected = [unchanged.as_slice(), changed.as_slice()].concat();
        let decoded = DeltaChunkPayload::from_bytes(changed.to_vec());

        let tree = reassemble_from_cas_and_decoded(
            &manifest,
            &cas,
            [decoded],
            expected_digest("file.txt", &expected),
        )
        .expect("reassembly");

        assert_eq!(tree.file("file.txt").expect("file").bytes, expected);
        assert_eq!(tree.cas_chunk_count(), 1);
        assert_eq!(tree.decoded_chunk_count(), 1);
        assert_eq!(tree.manifest_root, manifest.root());
    }

    #[test]
    fn missing_chunk_fails_closed_before_reassembly() {
        let manifest =
            CasMerkleManifest::from_chunks("tree", [manifest_chunk("file.txt", 0, b"missing")])
                .expect("manifest");
        let cas = ContentAddressedChunkStore::new();

        let result = reassemble_from_cas_and_decoded(
            &manifest,
            &cas,
            [],
            expected_digest("file.txt", b"missing"),
        );

        assert!(matches!(
            result,
            Err(ChunkingProfileError::InvalidChunkParameters(message))
                if message.contains("missing from receiver CAS and decoded delta")
        ));
    }

    #[test]
    fn whole_tree_digest_mismatch_fails_closed() {
        let manifest =
            CasMerkleManifest::from_chunks("tree", [manifest_chunk("file.txt", 0, b"bytes")])
                .expect("manifest");
        let mut cas = ContentAddressedChunkStore::new();
        cas.insert_chunk(b"bytes", None).expect("cas insert");

        let result = reassemble_from_cas_and_decoded(&manifest, &cas, [], [9u8; 32]);

        assert!(matches!(
            result,
            Err(ChunkingProfileError::InvalidChunkParameters(message))
                if message.contains("whole-tree SHA-256")
        ));
    }

    #[test]
    fn atomic_commit_leaves_existing_destination_untouched() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let destination = tmp.path().join("dst");
        fs::create_dir(&destination).expect("destination");
        fs::write(destination.join("old.txt"), b"old").expect("old file");

        let staging = tmp.path().join("stage");
        let manifest =
            CasMerkleManifest::from_chunks("tree", [manifest_chunk("new.txt", 0, b"new")])
                .expect("manifest");
        let mut cas = ContentAddressedChunkStore::new();
        cas.insert_chunk(b"new", None).expect("cas insert");

        let result = stage_and_commit_reassembled_tree(
            &manifest,
            &cas,
            [],
            expected_digest("new.txt", b"new"),
            &staging,
            &destination,
        );

        assert!(matches!(
            result,
            Err(ChunkingProfileError::InvalidChunkParameters(message))
                if message.contains("destination already exists")
        ));
        assert_eq!(
            fs::read(destination.join("old.txt")).expect("old file"),
            b"old"
        );
        assert!(!staging.exists());
    }
}
