//! Channel bonding Phase A1 — the shared [`BondTransferDescriptor`] and the donor
//! byte-match (merkle) proof.
//!
//! A *bonded* transfer fetches one object from N donors at once: each donor sprays
//! a residue-disjoint slice of the same fountain (donor `i` emits ESI `e` with
//! `e ≡ i (mod N)`, defined in A2 / `z01bbr.1.2`). For that to be correct every
//! donor and the receiver must agree on the *exact same* object — same
//! `transfer_id`, same per-block `K`, same byte layout — so that a `(sbn, esi)`
//! pair denotes the same bytes everywhere and two donors hitting the same ESI are
//! pure duplicates rather than corruption.
//!
//! Phase A locks that invariant with types, not protocol code:
//!
//! * [`BondTransferDescriptor`] is the small, agreed object every participant
//!   shares. It is the existing [`TransferManifest`] (`transfer_id`, `root_name`,
//!   `is_directory`, `total_bytes`, `merkle_root_hex`, per-entry
//!   `{index, rel_path, size, sha256_hex}`) plus the object params every donor must
//!   agree on (`symbol_size`, `max_block_size`) and a reference to the shared
//!   symbol-auth key. Phase A's job is to confirm this is *sufficient*: every field
//!   here comes from the manifest or an agreed param.
//! * The identity helpers ([`BondTransferDescriptor::entry_object_id`] and
//!   [`BondTransferDescriptor::entry_block_geometry`]) make the agreed RaptorQ
//!   view explicit: for every entry and source block, all donors derive the same
//!   object id, block byte span, and per-block `K` before any symbol is emitted.
//! * Agreement is **free**. Because all donor copies are byte-identical, the merkle
//!   root — and thus `transfer_id` — is identical, so two donors that independently
//!   hold the same bytes produce *equal* descriptors ([`BondTransferDescriptor::agrees_with`]).
//! * The donor byte-match **proof** ([`BondTransferDescriptor::verify_local_digests`]
//!   / [`BondTransferDescriptor::prove_local_holding`]) recomputes the per-entry
//!   SHA-256 and the flat-graph merkle root over the donor's LOCAL copy and refuses
//!   to donate on any mismatch — the same fail-closed check the receiver applies on
//!   commit. A donor that participates is therefore *proven* to hold byte-identical
//!   content, so fungibility of `(sbn, esi)` holds and a tampered copy can never
//!   silently poison the fountain.
//!
//! Out of A1 scope (later beads): A2 ESI partition (`z01bbr.1.2`), A3
//! `DonorAssignment` + key distribution (`z01bbr.1.3`), A4 handshake negotiation
//! (`z01bbr.1.4`), then the donate/receive data path.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::net::atp::transport_common::{
    EntryDigest, flat_merkle_root_from_digests, hash_file_streaming, hex_encode,
};
use crate::net::atp::transport_rq::{ManifestEntry, TransferManifest};
use crate::types::symbol::ObjectId as RaptorqObjectId;

/// Reused streaming-hash buffer for the donor proof (per file, 64 KiB).
const BOND_HASH_BUFFER_SIZE: usize = 1 << 16;
/// Structured event schema for donor-side byte-proof refusal traces.
pub const BONDING_DONOR_REFUSAL_TRACE_SCHEMA: &str = "atp-bonding-donor-refusal-v1";

/// One file within a [`BondTransferDescriptor`].
///
/// Mirrors the content-bearing fields of [`ManifestEntry`]. The `members` packing
/// of E-15 coalescing is intentionally *not* carried: the descriptor commits to the
/// entry's content hash (`sha256_hex`), and how a donor materialises that entry's
/// bytes (a single file, or a coalesced object reassembled by offset) is a
/// donor-local concern that does not change the agreed `(sbn, esi)` → bytes map.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondEntry {
    /// Stable index within the transfer (manifest order).
    pub index: u32,
    /// Path relative to the transfer root (forward-slash separated).
    pub rel_path: String,
    /// Entry content length in bytes.
    pub size: u64,
    /// Lowercase hex SHA-256 of the entry content.
    pub sha256_hex: String,
}

impl BondEntry {
    fn from_manifest_entry(entry: &ManifestEntry) -> Self {
        Self {
            index: entry.index,
            rel_path: entry.rel_path.clone(),
            size: entry.size,
            sha256_hex: entry.sha256_hex.clone(),
        }
    }
}

/// The small, agreed object every donor and the receiver share for a bonded
/// transfer. See the module docs for the agreement + fungibility argument.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondTransferDescriptor {
    /// Stable transfer identifier (hex, merkle-derived) — identical across donors.
    pub transfer_id: String,
    /// Name of the transfer root (file or directory name).
    pub root_name: String,
    /// Whether the root is a directory (vs a single file).
    pub is_directory: bool,
    /// Total bytes across all entries.
    pub total_bytes: u64,
    /// Lowercase hex flat-graph merkle root over the object.
    pub merkle_root_hex: String,
    /// File entries in manifest order.
    pub entries: Vec<BondEntry>,
    /// RaptorQ symbol size in bytes — all donors must agree.
    pub symbol_size: u16,
    /// Maximum RaptorQ block size in bytes. Fixes per-block `K`, hence the
    /// `(sbn, esi)` layout, identically across donors.
    pub max_block_size: u64,
    /// Identifier of the shared symbol-auth key. The key *material* is distributed
    /// out of band (A3); only its id travels in the descriptor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_key_id: Option<String>,
}

/// The agreed RaptorQ identity and geometry for one descriptor source block.
///
/// This is the descriptor-side contract donors use before spraying symbols:
/// `object_id` names the entry's fountain, `source_block_number` names the
/// block within it, and `source_symbols` is that block's actual `K`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BondEntryBlockGeometry {
    /// Stable descriptor entry index.
    pub entry_index: u32,
    /// RaptorQ object id derived from `transfer_id` + `entry_index`.
    pub object_id: RaptorqObjectId,
    /// Source block number within the entry.
    pub source_block_number: u8,
    /// Total source blocks in this entry.
    pub source_block_count: u16,
    /// Byte offset of this block within the entry.
    pub block_start: u64,
    /// Bytes covered by this block.
    pub block_bytes: u64,
    /// Actual source symbols (`K`) required for this block.
    pub source_symbols: u16,
}

/// Proof token that a donor may participate in a bonded transfer.
///
/// This is intentionally small and non-secret: it can be logged or attached to a
/// control-plane receipt after [`BondTransferDescriptor::verify_local_digests`]
/// proves the donor's local bytes match the descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BondedDonorHoldingProof {
    /// Stable transfer identifier that was proven locally.
    pub transfer_id: String,
    /// Flat-graph merkle root proven over the local copy.
    pub merkle_root_hex: String,
    /// Total byte count proven over the local copy.
    pub total_bytes: u64,
    /// Number of descriptor entries covered by the proof.
    pub entry_count: usize,
}

/// Structured trace emitted when a donor refuses to participate.
///
/// This is intentionally serializable control-plane evidence, not a side-effecting
/// logger. Donor data paths can attach or log it when
/// [`BondTransferDescriptor::prove_local_digests_for_donation_traced`] fails.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BondedDonorRefusalTrace {
    /// Stable schema token for downstream log parsers.
    pub schema_version: &'static str,
    /// Stable event name.
    pub event: &'static str,
    /// Transfer whose local copy failed the byte-identical proof.
    pub transfer_id: String,
    /// Descriptor-committed flat-graph merkle root.
    pub expected_merkle_root_hex: String,
    /// Merkle root recomputed from the supplied local digests, when available.
    pub recomputed_merkle_root_hex: Option<String>,
    /// Stable machine-readable refusal reason.
    pub refusal_code: &'static str,
    /// Human-readable typed proof error.
    pub refusal_error: String,
    /// Entry associated with the refusal, when the error is entry-scoped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_rel_path: Option<String>,
    /// Descriptor entry count.
    pub descriptor_entry_count: usize,
    /// Number of local digests supplied by the donor proof caller.
    pub local_digest_count: usize,
    /// Descriptor-declared total bytes.
    pub descriptor_total_bytes: u64,
}

/// Why a donor (or the receiver) refused a bonded descriptor / failed its proof.
///
/// Every variant means **refuse to donate / fail closed**: a participant that
/// cannot prove byte-identical content must not spray symbols into the fountain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BondProofError {
    /// Two descriptor entries reuse the same manifest index.
    DuplicateEntryIndex {
        /// Reused entry index.
        index: u32,
    },
    /// Two descriptor entries reuse the same transfer-relative path.
    DuplicateEntryPath {
        /// Reused transfer-relative path.
        rel_path: String,
    },
    /// Descriptor entry sizes overflowed `u64`.
    TotalBytesOverflow,
    /// Descriptor total_bytes does not equal the sum of entry sizes.
    TotalBytesMismatch {
        /// Descriptor-declared total.
        expected: u64,
        /// Sum of entry sizes.
        actual: u64,
    },
    /// The local copy is missing an entry the descriptor requires.
    MissingEntry {
        /// Transfer-relative path of the absent entry.
        rel_path: String,
    },
    /// A local entry's size or SHA-256 disagrees with the descriptor.
    EntryMismatch {
        /// Transfer-relative path of the mismatched entry.
        rel_path: String,
    },
    /// The rebuilt flat-graph merkle root != the descriptor's. Refuse to donate.
    MerkleMismatch {
        /// The descriptor's committed merkle root.
        expected: String,
        /// The root recomputed over the local copy.
        recomputed: String,
    },
    /// A descriptor entry path is unsafe (absolute or escapes the root).
    UnsafePath {
        /// The offending transfer-relative path.
        rel_path: String,
    },
    /// Reading or hashing a local entry failed.
    Io {
        /// Transfer-relative path of the entry that failed.
        rel_path: String,
        /// Underlying error message.
        message: String,
    },
}

impl core::fmt::Display for BondProofError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DuplicateEntryIndex { index } => {
                write!(f, "bonded descriptor: duplicate entry index {index}")
            }
            Self::DuplicateEntryPath { rel_path } => {
                write!(f, "bonded descriptor: duplicate entry path {rel_path}")
            }
            Self::TotalBytesOverflow => f.write_str("bonded descriptor: total bytes overflow"),
            Self::TotalBytesMismatch { expected, actual } => write!(
                f,
                "bonded descriptor: total bytes mismatch (expected {expected}, actual {actual})"
            ),
            Self::MissingEntry { rel_path } => {
                write!(f, "bonded descriptor: local copy missing entry {rel_path}")
            }
            Self::EntryMismatch { rel_path } => {
                write!(
                    f,
                    "bonded descriptor: size/SHA-256 mismatch for entry {rel_path}"
                )
            }
            Self::MerkleMismatch {
                expected,
                recomputed,
            } => write!(
                f,
                "bonded descriptor: merkle root mismatch (expected {expected}, recomputed {recomputed})"
            ),
            Self::UnsafePath { rel_path } => {
                write!(f, "bonded descriptor: unsafe entry path {rel_path}")
            }
            Self::Io { rel_path, message } => {
                write!(
                    f,
                    "bonded descriptor: hashing entry {rel_path} failed: {message}"
                )
            }
        }
    }
}

impl std::error::Error for BondProofError {}

impl BondProofError {
    fn refusal_code(&self) -> &'static str {
        match self {
            Self::DuplicateEntryIndex { .. } => "duplicate_entry_index",
            Self::DuplicateEntryPath { .. } => "duplicate_entry_path",
            Self::TotalBytesOverflow => "total_bytes_overflow",
            Self::TotalBytesMismatch { .. } => "total_bytes_mismatch",
            Self::MissingEntry { .. } => "missing_entry",
            Self::EntryMismatch { .. } => "entry_mismatch",
            Self::MerkleMismatch { .. } => "merkle_mismatch",
            Self::UnsafePath { .. } => "unsafe_path",
            Self::Io { .. } => "io",
        }
    }

    fn entry_rel_path(&self) -> Option<&str> {
        match self {
            Self::DuplicateEntryPath { rel_path }
            | Self::MissingEntry { rel_path }
            | Self::EntryMismatch { rel_path }
            | Self::UnsafePath { rel_path }
            | Self::Io { rel_path, .. } => Some(rel_path),
            Self::DuplicateEntryIndex { .. }
            | Self::TotalBytesOverflow
            | Self::TotalBytesMismatch { .. }
            | Self::MerkleMismatch { .. } => None,
        }
    }
}

impl BondTransferDescriptor {
    /// Build the descriptor from an rq [`TransferManifest`] plus the object params
    /// every donor must agree on. Confirms (Phase A's job) the manifest is
    /// sufficient: every descriptor field comes from the manifest or an agreed param.
    #[must_use]
    pub fn from_manifest(
        manifest: &TransferManifest,
        symbol_size: u16,
        max_block_size: u64,
        auth_key_id: Option<String>,
    ) -> Self {
        Self {
            transfer_id: manifest.transfer_id.clone(),
            root_name: manifest.root_name.clone(),
            is_directory: manifest.is_directory,
            total_bytes: manifest.total_bytes,
            merkle_root_hex: manifest.merkle_root_hex.clone(),
            entries: manifest
                .entries
                .iter()
                .map(BondEntry::from_manifest_entry)
                .collect(),
            symbol_size,
            max_block_size,
            auth_key_id,
        }
    }

    /// Two donors agree iff they hold byte-identical content under identical params.
    ///
    /// Equivalent to `self == other`, named to document the bonding invariant: a
    /// receiver MUST reject a donor whose descriptor differs, because different
    /// bytes mean a `(sbn, esi)` pair would denote *different* content on that donor
    /// — silent corruption of the bonded fountain.
    #[must_use]
    pub fn agrees_with(&self, other: &Self) -> bool {
        self == other
    }

    /// Derive the RaptorQ object id for a descriptor entry.
    ///
    /// This mirrors the rq and quic transports exactly so bonded donors and the
    /// receiver address the same fountain without extra signaling.
    #[must_use]
    pub fn entry_object_id(&self, entry_index: u32) -> RaptorqObjectId {
        bonded_entry_object_id(&self.transfer_id, entry_index)
    }

    /// Return the descriptor entry with `entry_index`.
    #[must_use]
    pub fn entry_by_index(&self, entry_index: u32) -> Option<&BondEntry> {
        self.entries.iter().find(|entry| entry.index == entry_index)
    }

    /// Planned source-block count for `entry_index` under the descriptor's
    /// agreed RaptorQ block size.
    #[must_use]
    pub fn entry_source_block_count(&self, entry_index: u32) -> Option<u16> {
        let entry = self.entry_by_index(entry_index)?;
        Some(entry_source_block_count(entry.size, self.max_block_size))
    }

    /// Return the agreed RaptorQ geometry for one entry/source-block pair.
    ///
    /// Empty entries have zero source blocks and therefore no block geometry.
    /// Non-empty entries are split greedily into `max_block_size` chunks, matching
    /// the rq/quic transport object-parameter derivation. `source_symbols` is the
    /// actual per-block `K`, including a shorter final block.
    #[must_use]
    pub fn entry_block_geometry(
        &self,
        entry_index: u32,
        source_block_number: u8,
    ) -> Option<BondEntryBlockGeometry> {
        let entry = self.entry_by_index(entry_index)?;
        let block_count = entry_source_block_count(entry.size, self.max_block_size);
        let sbn = u16::from(source_block_number);
        if block_count == 0 || sbn >= block_count {
            return None;
        }

        let block_limit = self.max_block_size.max(1);
        let block_start = block_limit.checked_mul(u64::from(source_block_number))?;
        if block_start >= entry.size {
            return None;
        }
        let block_bytes = (entry.size - block_start).min(block_limit);
        let symbol_size = u64::from(self.symbol_size.max(1));
        let source_symbols = block_bytes.div_ceil(symbol_size).max(1);

        Some(BondEntryBlockGeometry {
            entry_index,
            object_id: self.entry_object_id(entry_index),
            source_block_number,
            source_block_count: block_count,
            block_start,
            block_bytes,
            source_symbols: u16::try_from(source_symbols).unwrap_or(u16::MAX),
        })
    }

    /// Validate descriptor-only invariants before comparing any donor proof.
    pub fn validate(&self) -> Result<(), BondProofError> {
        let mut indices = BTreeSet::new();
        let mut paths = BTreeSet::new();
        let mut total_bytes = 0u64;
        for entry in &self.entries {
            if !indices.insert(entry.index) {
                return Err(BondProofError::DuplicateEntryIndex { index: entry.index });
            }
            if !paths.insert(entry.rel_path.clone()) {
                return Err(BondProofError::DuplicateEntryPath {
                    rel_path: entry.rel_path.clone(),
                });
            }
            if safe_entry_path(Path::new("."), &entry.rel_path).is_none() {
                return Err(BondProofError::UnsafePath {
                    rel_path: entry.rel_path.clone(),
                });
            }
            total_bytes = total_bytes
                .checked_add(entry.size)
                .ok_or(BondProofError::TotalBytesOverflow)?;
        }
        if total_bytes != self.total_bytes {
            return Err(BondProofError::TotalBytesMismatch {
                expected: self.total_bytes,
                actual: total_bytes,
            });
        }
        Ok(())
    }

    /// Pure donor proof: given per-entry digests recomputed over the LOCAL copy,
    /// verify this donor holds the descriptor's exact bytes.
    ///
    /// Checks (1) every descriptor entry has a matching local digest (size +
    /// SHA-256) and (2) the rebuilt flat-graph merkle root equals
    /// `merkle_root_hex`. Any mismatch returns `Err` (refuse to donate). The
    /// receiver applies the identical check before committing, so this is the same
    /// fail-closed gate as `transport_rq`'s `verify_and_commit`.
    pub fn verify_local_digests(&self, digests: &[EntryDigest]) -> Result<(), BondProofError> {
        self.validate()?;
        for entry in &self.entries {
            let Some(digest) = digests.iter().find(|d| d.rel_path == entry.rel_path) else {
                return Err(BondProofError::MissingEntry {
                    rel_path: entry.rel_path.clone(),
                });
            };
            if digest.size != entry.size || hex_encode(&digest.content_sha256) != entry.sha256_hex {
                return Err(BondProofError::EntryMismatch {
                    rel_path: entry.rel_path.clone(),
                });
            }
        }
        let recomputed = flat_merkle_root_from_digests(digests);
        if recomputed != self.merkle_root_hex {
            return Err(BondProofError::MerkleMismatch {
                expected: self.merkle_root_hex.clone(),
                recomputed,
            });
        }
        Ok(())
    }

    /// Verify local digests and return the non-secret proof token needed before
    /// donor scheduling may begin.
    ///
    /// This is the B2 donor refusal gate in typed form: callers get a
    /// [`BondedDonorHoldingProof`] only when the local bytes are byte-identical to
    /// the descriptor. Any mismatch returns the same fail-closed error as
    /// [`Self::verify_local_digests`].
    pub fn prove_local_digests_for_donation(
        &self,
        digests: &[EntryDigest],
    ) -> Result<BondedDonorHoldingProof, BondProofError> {
        self.verify_local_digests(digests)?;
        Ok(BondedDonorHoldingProof {
            transfer_id: self.transfer_id.clone(),
            merkle_root_hex: self.merkle_root_hex.clone(),
            total_bytes: self.total_bytes,
            entry_count: self.entries.len(),
        })
    }

    /// Verify local digests and return either the donor proof token or a
    /// structured refusal trace suitable for control-plane logging.
    ///
    /// This is B2's "refuse before spray" API shape for donor paths that need a
    /// machine-readable receipt. It does not emit logs itself; callers decide
    /// whether to attach the trace to Agent Mail, structured tracing, or an
    /// operator artifact.
    pub fn prove_local_digests_for_donation_traced(
        &self,
        digests: &[EntryDigest],
    ) -> Result<BondedDonorHoldingProof, BondedDonorRefusalTrace> {
        self.prove_local_digests_for_donation(digests)
            .map_err(|error| self.refusal_trace(&error, digests))
    }

    /// Build a structured refusal trace for an already-classified proof error.
    #[must_use]
    pub fn refusal_trace(
        &self,
        error: &BondProofError,
        digests: &[EntryDigest],
    ) -> BondedDonorRefusalTrace {
        BondedDonorRefusalTrace {
            schema_version: BONDING_DONOR_REFUSAL_TRACE_SCHEMA,
            event: "bonding_donor_refused",
            transfer_id: self.transfer_id.clone(),
            expected_merkle_root_hex: self.merkle_root_hex.clone(),
            recomputed_merkle_root_hex: (!digests.is_empty())
                .then(|| flat_merkle_root_from_digests(digests)),
            refusal_code: error.refusal_code(),
            refusal_error: error.to_string(),
            entry_rel_path: error.entry_rel_path().map(str::to_string),
            descriptor_entry_count: self.entries.len(),
            local_digest_count: digests.len(),
            descriptor_total_bytes: self.total_bytes,
        }
    }

    /// Donor enrolment proof over an on-disk copy rooted at `root_dir`: stream-hash
    /// each entry's local file and run [`Self::verify_local_digests`]. Returns
    /// `Ok(())` only if every byte matches; otherwise refuse to donate.
    ///
    /// Covers single-file-per-entry copies (the common case and every directory
    /// tree). A coalesced (E-15 `members`) entry's bytes are reassembled by the
    /// donor before this call; that reassembly is out of Phase-A scope.
    pub async fn prove_local_holding(&self, root_dir: &Path) -> Result<(), BondProofError> {
        let mut buf = vec![0u8; BOND_HASH_BUFFER_SIZE];
        let mut digests: Vec<EntryDigest> = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            let path = safe_entry_path(root_dir, &entry.rel_path).ok_or_else(|| {
                BondProofError::UnsafePath {
                    rel_path: entry.rel_path.clone(),
                }
            })?;
            let (size, content_id, content_sha256) = hash_file_streaming(&path, &mut buf)
                .await
                .map_err(|e| BondProofError::Io {
                    rel_path: entry.rel_path.clone(),
                    message: e.into_message(),
                })?;
            digests.push(EntryDigest {
                rel_path: entry.rel_path.clone(),
                size,
                content_id,
                content_sha256,
            });
        }
        self.verify_local_digests(&digests)
    }
}

/// Derive the per-entry RaptorQ object id from a transfer id and entry index.
#[must_use]
pub fn bonded_entry_object_id(transfer_id: &str, entry_index: u32) -> RaptorqObjectId {
    let mut hasher = Sha256::new();
    hasher.update(b"asupersync.atp.rq.entry-object-id.v1\0");
    hasher.update(transfer_id.as_bytes());
    hasher.update(entry_index.to_be_bytes());
    let digest = hasher.finalize();
    let high = u64::from_be_bytes([
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
    ]);
    let low = u64::from_be_bytes([
        digest[8], digest[9], digest[10], digest[11], digest[12], digest[13], digest[14],
        digest[15],
    ]);
    RaptorqObjectId::new(high, low)
}

fn entry_source_block_count(entry_size: u64, max_block_size: u64) -> u16 {
    if entry_size == 0 {
        return 0;
    }
    let block_limit = max_block_size.max(1);
    let blocks = entry_size.div_ceil(block_limit).min(u64::from(u8::MAX) + 1);
    u16::try_from(blocks).unwrap_or(u16::from(u8::MAX) + 1)
}

/// Join a forward-slash transfer-relative path onto `root_dir`, rejecting any
/// component that would escape it (`..`, absolute, or a root/prefix component).
/// Returns `None` for an unsafe path so the donor refuses rather than hashing an
/// arbitrary file off disk.
fn safe_entry_path(root_dir: &Path, rel_path: &str) -> Option<PathBuf> {
    if Path::new(rel_path).is_absolute() {
        return None;
    }

    let mut out = root_dir.to_path_buf();
    let mut pushed = false;
    for component in rel_path.split('/') {
        if component.is_empty() || component == "." {
            continue;
        }
        if component == ".." {
            return None;
        }
        if Path::new(component).components().count() != 1 {
            // Backslash/drive/root smuggled inside one slash-delimited component.
            return None;
        }
        out.push(component);
        pushed = true;
    }
    if pushed { Some(out) } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atp::object::{ContentId, ObjectId};
    use sha2::{Digest, Sha256};

    fn sha_hex(bytes: &[u8]) -> String {
        let sha: [u8; 32] = Sha256::digest(bytes).into();
        hex_encode(&sha)
    }

    fn digest_for(rel_path: &str, bytes: &[u8]) -> EntryDigest {
        EntryDigest {
            rel_path: rel_path.to_string(),
            size: bytes.len() as u64,
            content_id: ObjectId::content(ContentId::from_bytes(bytes)),
            content_sha256: Sha256::digest(bytes).into(),
        }
    }

    fn descriptor_for(files: &[(u32, &str, &[u8])]) -> BondTransferDescriptor {
        let digests: Vec<EntryDigest> = files.iter().map(|(_, p, b)| digest_for(p, b)).collect();
        let entries: Vec<BondEntry> = files
            .iter()
            .map(|(i, p, b)| BondEntry {
                index: *i,
                rel_path: (*p).to_string(),
                size: b.len() as u64,
                sha256_hex: sha_hex(b),
            })
            .collect();
        let total: u64 = files.iter().map(|(_, _, b)| b.len() as u64).sum();
        BondTransferDescriptor {
            transfer_id: "tid-deadbeef".to_string(),
            root_name: "root".to_string(),
            is_directory: files.len() != 1,
            total_bytes: total,
            merkle_root_hex: flat_merkle_root_from_digests(&digests),
            entries,
            symbol_size: 1200,
            max_block_size: 8 << 20,
            auth_key_id: Some("key-1".to_string()),
        }
    }

    const FILES: &[(u32, &str, &[u8])] = &[
        (0, "a.bin", b"hello bonded world"),
        (1, "sub/b.bin", b"second donor file"),
    ];

    #[test]
    fn verify_local_digests_accepts_a_byte_identical_copy() {
        let desc = descriptor_for(FILES);
        let digests: Vec<EntryDigest> = FILES.iter().map(|(_, p, b)| digest_for(p, b)).collect();
        assert!(desc.verify_local_digests(&digests).is_ok());
    }

    #[test]
    fn donation_proof_token_requires_byte_identical_local_digests() {
        let desc = descriptor_for(FILES);
        let digests: Vec<EntryDigest> = FILES.iter().map(|(_, p, b)| digest_for(p, b)).collect();

        let proof = desc
            .prove_local_digests_for_donation(&digests)
            .expect("byte-identical donor proof");

        assert_eq!(proof.transfer_id, desc.transfer_id);
        assert_eq!(proof.merkle_root_hex, desc.merkle_root_hex);
        assert_eq!(proof.total_bytes, desc.total_bytes);
        assert_eq!(proof.entry_count, desc.entries.len());
    }

    #[test]
    fn traced_donation_proof_accepts_matching_local_digests() {
        let desc = descriptor_for(FILES);
        let digests: Vec<EntryDigest> = FILES.iter().map(|(_, p, b)| digest_for(p, b)).collect();

        let proof = desc
            .prove_local_digests_for_donation_traced(&digests)
            .expect("byte-identical donor proof");

        assert_eq!(proof.transfer_id, desc.transfer_id);
        assert_eq!(proof.merkle_root_hex, desc.merkle_root_hex);
    }

    #[test]
    fn traced_donation_proof_refuses_tampered_copy_with_merkle_evidence() {
        let desc = descriptor_for(FILES);
        let digests = vec![
            digest_for("a.bin", b"HELLO bonded world"),
            digest_for("sub/b.bin", b"second donor file"),
        ];
        let recomputed = flat_merkle_root_from_digests(&digests);

        let trace = desc
            .prove_local_digests_for_donation_traced(&digests)
            .expect_err("tampered donor copy must refuse before spray");

        assert_eq!(trace.schema_version, BONDING_DONOR_REFUSAL_TRACE_SCHEMA);
        assert_eq!(trace.event, "bonding_donor_refused");
        assert_eq!(trace.transfer_id, desc.transfer_id);
        assert_eq!(trace.expected_merkle_root_hex, desc.merkle_root_hex);
        assert_eq!(trace.recomputed_merkle_root_hex, Some(recomputed));
        assert_ne!(
            trace.recomputed_merkle_root_hex.as_deref(),
            Some(desc.merkle_root_hex.as_str())
        );
        assert_eq!(trace.refusal_code, "entry_mismatch");
        assert_eq!(trace.entry_rel_path.as_deref(), Some("a.bin"));
        assert_eq!(trace.descriptor_entry_count, desc.entries.len());
        assert_eq!(trace.local_digest_count, digests.len());

        let json = serde_json::to_value(&trace).expect("refusal trace serializes");
        assert_eq!(
            json["schema_version"].as_str(),
            Some(BONDING_DONOR_REFUSAL_TRACE_SCHEMA)
        );
        assert_eq!(json["event"].as_str(), Some("bonding_donor_refused"));
        assert_eq!(json["refusal_code"].as_str(), Some("entry_mismatch"));
    }

    #[test]
    fn donation_proof_token_refuses_descriptor_merkle_drift() {
        let mut desc = descriptor_for(FILES);
        let digests: Vec<EntryDigest> = FILES.iter().map(|(_, p, b)| digest_for(p, b)).collect();
        let forged_root = "00".repeat(32);
        desc.merkle_root_hex = forged_root.clone();

        assert!(matches!(
            desc.prove_local_digests_for_donation(&digests),
            Err(BondProofError::MerkleMismatch {
                expected,
                recomputed,
            }) if expected == forged_root && recomputed != expected
        ));
    }

    #[test]
    fn donation_proof_token_refuses_tampered_local_digests() {
        let desc = descriptor_for(FILES);
        let digests = vec![
            digest_for("a.bin", b"HELLO bonded world"),
            digest_for("sub/b.bin", b"second donor file"),
        ];

        assert_eq!(
            desc.prove_local_digests_for_donation(&digests),
            Err(BondProofError::EntryMismatch {
                rel_path: "a.bin".to_string(),
            })
        );
    }

    #[test]
    fn descriptor_validate_rejects_duplicate_index_path_and_bad_total() {
        let desc = descriptor_for(FILES);
        desc.validate().expect("baseline descriptor");

        let mut duplicate_index = desc.clone();
        duplicate_index.entries[1].index = duplicate_index.entries[0].index;
        assert!(matches!(
            duplicate_index.validate().unwrap_err(),
            BondProofError::DuplicateEntryIndex { .. }
        ));

        let mut duplicate_path = desc.clone();
        duplicate_path.entries[1].rel_path = duplicate_path.entries[0].rel_path.clone();
        assert!(matches!(
            duplicate_path.validate().unwrap_err(),
            BondProofError::DuplicateEntryPath { .. }
        ));

        let mut unsafe_path = desc.clone();
        unsafe_path.entries[0].rel_path = "../escape".to_string();
        assert!(matches!(
            unsafe_path.verify_local_digests(&[]).unwrap_err(),
            BondProofError::UnsafePath { .. }
        ));

        let mut absolute_path = desc.clone();
        absolute_path.entries[0].rel_path = "/abs/path".to_string();
        assert!(matches!(
            absolute_path.verify_local_digests(&[]).unwrap_err(),
            BondProofError::UnsafePath { .. }
        ));

        let mut bad_total = desc;
        bad_total.total_bytes += 1;
        assert!(matches!(
            bad_total.verify_local_digests(&[]).unwrap_err(),
            BondProofError::TotalBytesMismatch { .. }
        ));
    }

    #[test]
    fn verify_local_digests_rejects_a_tampered_entry() {
        let desc = descriptor_for(FILES);
        // Flip the first entry's bytes: per-entry SHA-256 disagrees → refuse.
        let digests = vec![
            digest_for("a.bin", b"HELLO bonded world"),
            digest_for("sub/b.bin", b"second donor file"),
        ];
        assert!(matches!(
            desc.verify_local_digests(&digests).unwrap_err(),
            BondProofError::EntryMismatch { .. }
        ));
    }

    #[test]
    fn verify_local_digests_rejects_a_missing_entry() {
        let desc = descriptor_for(FILES);
        let digests = vec![digest_for("sub/b.bin", b"second donor file")];
        assert!(matches!(
            desc.verify_local_digests(&digests).unwrap_err(),
            BondProofError::MissingEntry { .. }
        ));
    }

    #[test]
    fn identical_bytes_produce_equal_descriptors_and_agree() {
        let a = descriptor_for(FILES);
        let b = descriptor_for(FILES);
        assert_eq!(a, b);
        assert!(a.agrees_with(&b));

        let different = descriptor_for(&[
            (0, "a.bin", b"HELLO bonded world"),
            (1, "sub/b.bin", b"second donor file"),
        ]);
        assert!(!a.agrees_with(&different), "different bytes must not agree");
    }

    #[test]
    fn descriptor_serde_round_trips() {
        let desc = descriptor_for(FILES);
        let json = serde_json::to_string(&desc).expect("serialize");
        let back: BondTransferDescriptor = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(desc, back);
    }

    #[test]
    fn entry_object_id_matches_the_rq_transport_derivation() {
        let desc = descriptor_for(FILES);
        let first = desc.entry_object_id(0);

        assert_eq!(first, desc.entry_object_id(0));
        assert_eq!(
            first,
            crate::net::atp::channel_bonding::entry_object_id(&desc.transfer_id, 0)
        );
        assert_eq!(first, bonded_entry_object_id(&desc.transfer_id, 0));
        assert_ne!(first, desc.entry_object_id(1));
        assert_ne!(first, bonded_entry_object_id("different-transfer", 0));
    }

    #[test]
    fn entry_block_geometry_locks_actual_per_block_k() {
        let mut desc = descriptor_for(&[(7, "payload.bin", b"0123456789abc")]);
        desc.symbol_size = 4;
        desc.max_block_size = 6;

        assert_eq!(desc.entry_source_block_count(7), Some(3));

        let first = desc.entry_block_geometry(7, 0).expect("first block");
        assert_eq!(first.entry_index, 7);
        assert_eq!(first.object_id, desc.entry_object_id(7));
        assert_eq!(first.source_block_number, 0);
        assert_eq!(first.source_block_count, 3);
        assert_eq!(first.block_start, 0);
        assert_eq!(first.block_bytes, 6);
        assert_eq!(first.source_symbols, 2);

        let second = desc.entry_block_geometry(7, 1).expect("second block");
        assert_eq!(second.block_start, 6);
        assert_eq!(second.block_bytes, 6);
        assert_eq!(second.source_symbols, 2);

        let final_partial = desc.entry_block_geometry(7, 2).expect("partial block");
        assert_eq!(final_partial.block_start, 12);
        assert_eq!(final_partial.block_bytes, 1);
        assert_eq!(final_partial.source_symbols, 1);

        assert!(desc.entry_block_geometry(7, 3).is_none());
        assert!(desc.entry_block_geometry(99, 0).is_none());
    }

    #[test]
    fn empty_entries_have_no_source_block_geometry() {
        let desc = descriptor_for(&[(0, "empty.bin", b"")]);
        assert_eq!(desc.entry_source_block_count(0), Some(0));
        assert!(desc.entry_block_geometry(0, 0).is_none());
    }

    #[test]
    fn entry_block_geometry_clamps_zero_symbol_and_block_inputs() {
        let mut desc = descriptor_for(&[(2, "payload.bin", b"abc")]);
        desc.symbol_size = 0;
        desc.max_block_size = 0;

        assert_eq!(desc.entry_source_block_count(2), Some(3));

        let first = desc.entry_block_geometry(2, 0).expect("first byte block");
        assert_eq!(first.block_start, 0);
        assert_eq!(first.block_bytes, 1);
        assert_eq!(first.source_symbols, 1);

        let final_block = desc.entry_block_geometry(2, 2).expect("final byte block");
        assert_eq!(final_block.block_start, 2);
        assert_eq!(final_block.block_bytes, 1);
        assert_eq!(final_block.source_symbols, 1);
        assert_eq!(final_block.source_block_count, 3);
        assert!(desc.entry_block_geometry(2, 3).is_none());
    }

    #[test]
    fn from_manifest_carries_every_agreed_field() {
        let manifest = TransferManifest {
            transfer_id: "tid-deadbeef".to_string(),
            root_name: "root".to_string(),
            is_directory: true,
            total_bytes: 18,
            merkle_root_hex: "abc123".to_string(),
            entries: vec![ManifestEntry {
                index: 0,
                rel_path: "a.bin".to_string(),
                size: 18,
                sha256_hex: "00ff".to_string(),
                members: Vec::new(),
                fragment: None,
            }],
        };
        let desc = BondTransferDescriptor::from_manifest(
            &manifest,
            1200,
            8 << 20,
            Some("key-1".to_string()),
        );
        assert_eq!(desc.transfer_id, "tid-deadbeef");
        assert_eq!(desc.merkle_root_hex, "abc123");
        assert_eq!(desc.symbol_size, 1200);
        assert_eq!(desc.max_block_size, 8 << 20);
        assert_eq!(desc.entries.len(), 1);
        assert_eq!(desc.entries[0].rel_path, "a.bin");
        assert_eq!(desc.entries[0].sha256_hex, "00ff");
        assert_eq!(desc.auth_key_id.as_deref(), Some("key-1"));
    }

    #[test]
    fn safe_entry_path_rejects_traversal_and_absolute() {
        let root = Path::new("/tmp/donor-root");
        assert!(safe_entry_path(root, "a/b.bin").is_some());
        assert!(safe_entry_path(root, "../escape").is_none());
        assert!(safe_entry_path(root, "a/../../escape").is_none());
        assert!(safe_entry_path(root, "/abs/path").is_none());
        assert!(safe_entry_path(root, "").is_none());
    }
}
