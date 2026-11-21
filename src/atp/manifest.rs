//! ATP manifest schema and graph commit semantics.
//!
//! This module defines the canonical manifest format for ATP object graphs,
//! Merkle root computation, and graph commit semantics. Manifests provide
//! verifiable representations of object graphs with content integrity.
//!
//! The manifest format is designed to be:
//! - Deterministic: same object graph produces byte-identical manifest
//! - Versioned: forward/backward compatibility with explicit version checks
//! - Self-describing: critical fields fail closed, optional fields preserve compatibility
//! - Canonical: stable hash output across supported platforms

use crate::atp::object::{
    MetadataPolicy, ObjectEdge, ObjectGraph, ObjectId, ObjectKind, ObjectMetadata,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[cfg(feature = "trace-compression")]
use lz4_flex;
use std::fmt;

/// Manifest format version for backward compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ManifestVersion(pub u32);

impl ManifestVersion {
    /// Current manifest version.
    pub const CURRENT: Self = Self(1);

    /// Check if this version is supported.
    #[must_use]
    pub const fn is_supported(self) -> bool {
        self.0 <= Self::CURRENT.0
    }
}

impl Default for ManifestVersion {
    fn default() -> Self {
        Self::CURRENT
    }
}

/// Hash algorithm specification for content verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum HashAlgorithm {
    /// SHA-256 (required for all manifests).
    Sha256,
    /// Blake3 (optional, high performance).
    Blake3,
}

impl HashAlgorithm {
    /// Get the hash output size in bytes.
    #[must_use]
    pub const fn hash_size(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Blake3 => 32,
        }
    }

    /// Whether this algorithm is required for manifest validation.
    #[must_use]
    pub const fn is_required(self) -> bool {
        matches!(self, Self::Sha256)
    }
}

/// Chunking strategy for large objects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkPlan {
    /// Chunking strategy identifier.
    pub strategy: ChunkStrategy,
    /// Target chunk size in bytes.
    pub target_chunk_size: u64,
    /// Minimum chunk size in bytes.
    pub min_chunk_size: u64,
    /// Maximum chunk size in bytes.
    pub max_chunk_size: u64,
    /// Content-defined chunking parameters (if applicable).
    pub cdc_params: Option<CdcParams>,
}

/// Chunking strategy types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ChunkStrategy {
    /// Fixed-size chunking.
    FixedSize,
    /// Content-defined chunking with rolling hash.
    ContentDefined,
    /// Object-specific chunking (e.g., for containers).
    ObjectSpecific,
}

/// Content-defined chunking parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdcParams {
    /// Rolling hash window size.
    pub window_size: u32,
    /// Target average chunk size for CDC algorithm.
    pub average_chunk_size: u64,
    /// Normalization constant for rolling hash.
    pub normalization: u64,
}

/// RaptorQ repair layout for forward error correction.
#[derive(Debug, Clone, PartialEq)]
pub struct RaptorQRepairLayout {
    /// Source symbol count (K).
    pub source_symbols: u32,
    /// Total symbol count including repair symbols (K + R).
    pub total_symbols: u32,
    /// Symbol size in bytes.
    pub symbol_size: u32,
    /// Repair symbol overhead ratio (R/K).
    pub overhead_ratio: f32,
    /// Sub-block structure for systematic codes.
    pub sub_blocks: Vec<SubBlock>,
}

/// Sub-block in RaptorQ encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubBlock {
    /// Sub-block index.
    pub index: u32,
    /// Source symbols in this sub-block.
    pub source_symbols: u32,
    /// Encoding symbol identifier (ESI) range.
    pub esi_range: (u32, u32),
}

/// Compression policy specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressionPolicy {
    /// Compression algorithm.
    pub algorithm: CompressionAlgorithm,
    /// Compression level (algorithm-specific).
    pub level: u8,
    /// Minimum size threshold for compression.
    pub min_size_threshold: u64,
    /// Object kinds that should be compressed.
    pub apply_to_kinds: Vec<ObjectKind>,
}

/// Supported compression algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CompressionAlgorithm {
    /// No compression.
    None,
    /// LZ4 fast compression.
    Lz4,
    /// Gzip deflate.
    Gzip,
    /// Brotli compression.
    Brotli,
}

/// Encryption policy specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionPolicy {
    /// Encryption algorithm.
    pub algorithm: EncryptionAlgorithm,
    /// Key derivation specification.
    pub key_derivation: KeyDerivation,
    /// Object kinds that should be encrypted.
    pub apply_to_kinds: Vec<ObjectKind>,
    /// Whether to encrypt metadata.
    pub encrypt_metadata: bool,
}

/// Supported encryption algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EncryptionAlgorithm {
    /// No encryption.
    None,
    /// ChaCha20Poly1305 AEAD.
    ChaCha20Poly1305,
    /// AES-256-GCM AEAD.
    Aes256Gcm,
}

/// Key derivation specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyDerivation {
    /// Key derivation function.
    pub kdf: KeyDerivationFunction,
    /// Salt for key derivation.
    pub salt: Vec<u8>,
    /// Iteration count (for password-based KDFs).
    pub iterations: Option<u32>,
}

/// Key derivation functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum KeyDerivationFunction {
    /// Direct key (no derivation).
    Direct,
    /// PBKDF2 with SHA-256.
    Pbkdf2Sha256,
    /// Argon2id.
    Argon2id,
    /// HKDF with SHA-256.
    HkdfSha256,
}

/// Capability policy hints for authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityPolicy {
    /// Required capabilities for reading this manifest.
    pub read_capabilities: Vec<String>,
    /// Required capabilities for writing/updating.
    pub write_capabilities: Vec<String>,
    /// Required capabilities for verification.
    pub verify_capabilities: Vec<String>,
    /// Capability delegation rules.
    pub delegation_rules: Vec<DelegationRule>,
}

/// Capability delegation rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationRule {
    /// Capability being delegated.
    pub capability: String,
    /// Target identity or pattern.
    pub target: String,
    /// Delegation constraints.
    pub constraints: Vec<String>,
    /// Expiration timestamp (nanoseconds since epoch).
    pub expires_at: Option<u64>,
}

/// Forward compatibility field classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FieldType {
    /// Critical field - unknown critical fields cause validation failure.
    Critical,
    /// Optional field - unknown optional fields are ignored.
    Optional,
}

/// Unknown field encountered during deserialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownField {
    /// Field name or identifier.
    pub name: String,
    /// Field type classification.
    pub field_type: FieldType,
    /// Raw field data.
    pub data: Vec<u8>,
}

/// Merkle root hash computed from object graph.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MerkleRoot {
    /// SHA-256 hash representing the entire graph structure.
    hash: [u8; 32],
}

/// A domain-separated v2 commitment, kept distinct from legacy wire roots.
///
/// Construct with [`MerkleRoot::from_graph_v2`],
/// [`MerkleRoot::from_manifest_components_v2`], or
/// [`MerkleRoot::from_manifest_v2`]. Each commits to a different representation
/// and therefore uses a different domain. These values authenticate data only
/// when the expected digest comes from a trusted source.
///
/// This is an additive, out-of-band format. It does not change `Manifest`'s
/// embedded legacy root, repair-symbol authentication, ATP negotiation, or any
/// existing transport. Persist the format and representation alongside the
/// digest; a bare 32-byte value cannot identify either. There is deliberately
/// no implicit conversion to [`MerkleRoot`].
///
/// The frozen v2 schema uses SHA-256 with the prefix
/// `asupersync.atp.merkle.v2\0`, followed by the u64 big-endian byte length of
/// the representation domain and the domain bytes (`object-graph`,
/// `manifest-components`, or `manifest`). Fields follow the encoder's explicit
/// order, with big-endian fixed-width integers, u64 lengths/counts, and one-byte
/// booleans and option tags (0 absent, 1 present). Object IDs carry tag 0 for
/// content or 1 for manifest before their 32 bytes. Fieldless enum discriminants
/// are the existing v1 tags, pinned by regression tests; reordering those tags
/// or changing field order requires a new commitment version. Maps use key
/// order, graph edges use canonical order, and other vectors retain order.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MerkleRootV2 {
    hash: [u8; 32],
}

impl MerkleRootV2 {
    /// Restore a trusted v2 digest whose representation is known to the caller.
    #[must_use]
    pub const fn new(hash: [u8; 32]) -> Self {
        Self { hash }
    }

    /// Borrow the SHA-256 digest bytes.
    #[must_use]
    pub const fn hash(&self) -> &[u8; 32] {
        &self.hash
    }

    /// Encode the complete digest as lowercase hexadecimal.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.hash)
    }
}

impl fmt::Display for MerkleRootV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "merkle-v2:{}", self.to_hex())
    }
}

/// Fixed-schema encoding streamed directly into SHA-256. All variable fields
/// and collections have a u64 big-endian length/count; every Option has a
/// presence byte, and every sum type has its own variant discriminant. Floats
/// retain their IEEE bits, including signed zero and NaN payloads. The schema
/// fixes scalar widths and field order, so no field can borrow its neighbour's
/// bytes. No complete serialized graph or manifest is allocated.
struct MerkleV2Hasher(Sha256);

impl MerkleV2Hasher {
    fn new(domain: &[u8]) -> Self {
        let mut this = Self(Sha256::new());
        this.0.update(b"asupersync.atp.merkle.v2\0");
        this.bytes(domain);
        this
    }

    fn finish(self) -> MerkleRootV2 {
        MerkleRootV2 {
            hash: self.0.finalize().into(),
        }
    }

    fn byte(&mut self, value: u8) {
        self.0.update([value]);
    }

    fn boolean(&mut self, value: bool) {
        self.byte(u8::from(value));
    }

    fn u32(&mut self, value: u32) {
        self.0.update(value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.0.update(value.to_be_bytes());
    }

    fn count(&mut self, value: usize) {
        self.u64(value as u64);
    }

    fn bytes(&mut self, value: &[u8]) {
        self.count(value.len());
        self.0.update(value);
    }

    fn string(&mut self, value: &str) {
        self.bytes(value.as_bytes());
    }

    fn option<T>(&mut self, value: Option<&T>, encode: impl FnOnce(&mut Self, &T)) {
        self.boolean(value.is_some());
        if let Some(value) = value {
            encode(self, value);
        }
    }

    fn sequence<T>(&mut self, values: &[T], mut encode: impl FnMut(&mut Self, &T)) {
        self.count(values.len());
        for value in values {
            encode(self, value);
        }
    }

    fn id(&mut self, value: &ObjectId) {
        self.byte(match value {
            ObjectId::Content(_) => 0,
            ObjectId::Manifest(_) => 1,
        });
        self.0.update(value.hash_bytes());
    }

    fn attributes(&mut self, values: &BTreeMap<String, Vec<u8>>) {
        self.count(values.len());
        for (name, value) in values {
            self.string(name);
            self.bytes(value);
        }
    }

    fn path(&mut self, value: &std::path::Path) {
        if let Some(text) = value.to_str() {
            self.byte(0);
            self.string(text);
            return;
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            self.byte(1);
            self.bytes(value.as_os_str().as_bytes());
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            self.byte(2);
            self.count(value.as_os_str().encode_wide().count());
            for unit in value.as_os_str().encode_wide() {
                self.0.update(unit.to_be_bytes());
            }
        }
        #[cfg(not(any(unix, windows)))]
        {
            // Other platforms do not expose a stable non-Unicode encoding.
            // This tagged fallback is only comparable within the same target
            // and Rust toolchain; Unicode paths still use portable tag 0.
            self.byte(3);
            self.string(std::env::consts::OS);
            self.string(std::env::consts::ARCH);
            self.bytes(value.as_os_str().as_encoded_bytes());
        }
    }

    fn compare_paths(
        left: Option<&std::path::PathBuf>,
        right: Option<&std::path::PathBuf>,
    ) -> std::cmp::Ordering {
        use std::cmp::Ordering;

        let (left, right) = match (left, right) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(left), Some(right)) => (left.as_os_str(), right.as_os_str()),
        };
        // Match the path encoding's tags before comparing payloads. Unicode
        // paths sort by UTF-8 on every platform, including Windows.
        match (left.to_str(), right.to_str()) {
            (Some(left), Some(right)) => left.cmp(right),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => {
                #[cfg(unix)]
                {
                    use std::os::unix::ffi::OsStrExt;
                    left.as_bytes().cmp(right.as_bytes())
                }
                #[cfg(windows)]
                {
                    use std::os::windows::ffi::OsStrExt;
                    left.encode_wide().cmp(right.encode_wide())
                }
                #[cfg(not(any(unix, windows)))]
                {
                    left.as_encoded_bytes().cmp(right.as_encoded_bytes())
                }
            }
        }
    }

    fn object(
        &mut self,
        id: &ObjectId,
        metadata: &ObjectMetadata,
        children: &[ObjectEdge],
        content: Option<(u64, [u8; 32])>,
    ) {
        self.id(id);
        self.byte(metadata.kind as u8);
        self.option(metadata.size_bytes.as_ref(), |h, value| h.u64(*value));
        let platform = &metadata.platform;
        self.option(platform.unix_mode.as_ref(), |h, value| h.u32(*value));
        self.option(platform.windows_attributes.as_ref(), |h, value| {
            h.u32(*value)
        });
        self.attributes(&platform.extended_attributes);
        self.option(platform.created_time_nanos.as_ref(), |h, value| {
            h.u64(*value)
        });
        self.option(platform.modified_time_nanos.as_ref(), |h, value| {
            h.u64(*value)
        });
        self.option(platform.accessed_time_nanos.as_ref(), |h, value| {
            h.u64(*value)
        });
        self.option(metadata.application.as_ref(), |h, application| {
            h.string(&application.extension_type);
            h.u32(application.schema_version);
            h.attributes(&application.metadata);
        });
        let mut children: Vec<_> = children.iter().collect();
        children.sort_unstable_by(|left, right| {
            left.name
                .cmp(&right.name)
                .then_with(|| left.child_id.cmp(&right.child_id))
                .then_with(|| left.is_symlink.cmp(&right.is_symlink))
                .then_with(|| {
                    // Path ordering normalizes separators, while the digest
                    // binds the original bytes. Break every tie by those bytes
                    // so even equivalent path spellings have a stable order.
                    Self::compare_paths(left.symlink_target.as_ref(), right.symlink_target.as_ref())
                })
        });
        self.count(children.len());
        for edge in children {
            self.string(&edge.name);
            self.id(&edge.child_id);
            self.boolean(edge.is_symlink);
            self.option(edge.symlink_target.as_ref(), |h, target| h.path(target));
        }
        self.option(content.as_ref(), |h, (length, hash)| {
            h.u64(*length);
            h.0.update(hash);
        });
    }

    fn key_derivation(&mut self, value: &KeyDerivation) {
        self.byte(value.kdf as u8);
        self.bytes(&value.salt);
        self.option(value.iterations.as_ref(), |h, iterations| {
            h.u32(*iterations)
        });
    }

    fn capability_policy(&mut self, value: &CapabilityPolicy) {
        self.sequence(&value.read_capabilities, |h, name| h.string(name));
        self.sequence(&value.write_capabilities, |h, name| h.string(name));
        self.sequence(&value.verify_capabilities, |h, name| h.string(name));
        self.sequence(&value.delegation_rules, |h, rule| {
            h.string(&rule.capability);
            h.string(&rule.target);
            h.sequence(&rule.constraints, |h, constraint| h.string(constraint));
            h.option(rule.expires_at.as_ref(), |h, expiry| h.u64(*expiry));
        });
    }

    fn transform_order(&mut self, value: &TransformOrder) {
        self.sequence(&value.transforms, |h, transform| h.byte(*transform as u8));
        self.byte(value.hash_point as u8);
        let boundary = &value.verification_boundary;
        self.byte(boundary.relay_verifiable as u8);
        self.byte(boundary.mailbox_verifiable as u8);
        self.boolean(boundary.e2e_verification_required);
        self.byte(boundary.privacy_level as u8);
    }

    fn chunk_metadata(&mut self, value: &ChunkMetadata) {
        match value {
            ChunkMetadata::BulkFile { throughput_tier } => {
                self.byte(0);
                self.byte(*throughput_tier as u8);
            }
            ChunkMetadata::SyncTree {
                boundary_hash,
                similarity_score,
            } => {
                self.byte(1);
                self.u64(*boundary_hash);
                self.u32(*similarity_score);
            }
            ChunkMetadata::Media {
                is_keyframe_boundary,
                decoding_priority,
            } => {
                self.byte(2);
                self.boolean(*is_keyframe_boundary);
                self.byte(*decoding_priority);
            }
            ChunkMetadata::SparseImage {
                is_sparse_hole,
                hole_metadata,
            } => {
                self.byte(3);
                self.boolean(*is_sparse_hole);
                self.option(hole_metadata.as_ref(), |h, hole| {
                    h.u64(hole.hole_size);
                    h.string(&hole.hole_type);
                    h.attributes(&hole.attributes);
                });
            }
            ChunkMetadata::Artifact {
                build_context,
                proof_strength,
            } => {
                self.byte(4);
                self.string(&build_context.build_system);
                self.option(build_context.build_timestamp.as_ref(), |h, value| {
                    h.u64(*value)
                });
                self.0.update(build_context.environment_hash);
                self.string(&build_context.toolchain_version);
                self.byte(*proof_strength as u8);
            }
            ChunkMetadata::Stream {
                sequence,
                early_consumption_safe,
            } => {
                self.byte(5);
                self.u64(*sequence);
                self.boolean(*early_consumption_safe);
            }
        }
    }

    fn manifest_object(&mut self, object: &ManifestObject) {
        self.id(&object.id);
        self.byte(object.kind as u8);
        self.option(object.size_bytes.as_ref(), |h, value| h.u64(*value));
        self.count(object.children.len());
        for (name, id) in &object.children {
            self.string(name);
            self.id(id);
        }
        self.option(object.content_hash.as_ref(), |h, hash| h.0.update(hash));
        self.sequence(&object.chunk_boundaries, |h, chunk| {
            h.u32(chunk.index);
            h.u64(chunk.byte_offset);
            h.u64(chunk.size_bytes);
            h.0.update(chunk.content_hash);
            h.byte(chunk.strategy as u8);
            h.option(chunk.metadata.as_ref(), Self::chunk_metadata);
        });
        self.sequence(&object.raptorq_symbols, |h, symbol| {
            h.u32(symbol.index);
            h.u32(symbol.esi);
            h.u32(symbol.size_bytes);
            h.0.update(symbol.content_hash);
            h.boolean(symbol.is_source);
            h.option(symbol.repair_group_id.as_ref(), |h, group| {
                h.0.update(group.as_bytes());
            });
            h.option(symbol.auth_tag.as_ref(), |h, tag| h.0.update(tag));
        });
        self.option(object.compression_metadata.as_ref(), |h, compression| {
            h.byte(compression.algorithm as u8);
            h.byte(compression.level);
            h.u64(compression.original_size);
            h.u64(compression.compressed_size);
            h.u32(compression.compression_ratio.to_bits());
        });
        self.option(object.encryption_metadata.as_ref(), |h, encryption| {
            h.byte(encryption.algorithm as u8);
            h.bytes(&encryption.iv);
            h.bytes(&encryption.auth_tag);
            h.key_derivation(&encryption.key_derivation);
        });
    }

    fn repair_group(&mut self, group: &RepairGroup) {
        self.0.update(group.group_id.as_bytes());
        self.id(&group.object_id);
        self.u32(group.source_block_number);
        self.u32(group.chunk_range.start_chunk);
        self.u32(group.chunk_range.end_chunk);
        self.u64(group.chunk_range.start_offset);
        self.u64(group.chunk_range.end_offset);
        self.u32(group.source_symbols_k);
        self.u32(group.k_prime);
        self.u32(group.symbol_size);
        let layout = &group.repair_layout;
        self.u32(layout.total_repair_symbols);
        self.u32(layout.overhead_ratio.to_bits());
        self.u32(layout.systematic_config.systematic_rows);
        self.u32(layout.systematic_config.sub_symbols);
        self.u32(layout.systematic_config.alignment);
        self.u32(layout.interleaving.block_size);
        self.u32(layout.interleaving.depth);
        match layout.interleaving.pattern_type {
            InterleavingType::None => self.byte(0),
            InterleavingType::Block => self.byte(1),
            InterleavingType::Matrix => self.byte(2),
            InterleavingType::Randomized(seed) => {
                self.byte(3);
                self.u32(seed);
            }
        }
        self.string(&group.hash_domain.domain_id);
        self.byte(group.hash_domain.hash_algorithm as u8);
        self.bytes(&group.hash_domain.context);
        self.option(group.transform_policy.as_ref(), Self::transform_order);
        let auth = &group.auth_domain;
        self.string(&auth.domain_id);
        self.byte(auth.required_proof_strength as u8);
        self.byte(auth.auth_algorithm as u8);
        self.boolean(auth.peer_identity_required);
        self.boolean(auth.transfer_identity_binding);
        self.boolean(auth.session_binding);
        self.option(group.capability_policy.as_ref(), Self::capability_policy);
        // This is the existing v1 binding, not the detached v2 digest.
        // Committing its bytes and symbol tags introduces no fixed point.
        self.0.update(group.manifest_root.hash());
    }

    fn components(
        &mut self,
        objects: &BTreeMap<ObjectId, ManifestObject>,
        chunk_plan: Option<&ChunkPlan>,
        raptorq_layout: Option<&RaptorQRepairLayout>,
        compression_policy: Option<&CompressionPolicy>,
        encryption_policy: Option<&EncryptionPolicy>,
        capability_policy: Option<&CapabilityPolicy>,
        transform_order: Option<&TransformOrder>,
        transform_proof_policy: Option<&TransformProofPolicy>,
        repair_groups: &BTreeMap<RepairGroupId, RepairGroup>,
    ) {
        self.count(objects.len());
        for (id, object) in objects {
            self.id(id);
            self.manifest_object(object);
        }
        self.option(chunk_plan, |h, plan| {
            h.byte(plan.strategy as u8);
            h.u64(plan.target_chunk_size);
            h.u64(plan.min_chunk_size);
            h.u64(plan.max_chunk_size);
            h.option(plan.cdc_params.as_ref(), |h, cdc| {
                h.u32(cdc.window_size);
                h.u64(cdc.average_chunk_size);
                h.u64(cdc.normalization);
            });
        });
        self.option(raptorq_layout, |h, layout| {
            h.u32(layout.source_symbols);
            h.u32(layout.total_symbols);
            h.u32(layout.symbol_size);
            h.u32(layout.overhead_ratio.to_bits());
            h.sequence(&layout.sub_blocks, |h, block| {
                h.u32(block.index);
                h.u32(block.source_symbols);
                h.u32(block.esi_range.0);
                h.u32(block.esi_range.1);
            });
        });
        self.option(compression_policy, |h, compression| {
            h.byte(compression.algorithm as u8);
            h.byte(compression.level);
            h.u64(compression.min_size_threshold);
            h.sequence(&compression.apply_to_kinds, |h, kind| h.byte(*kind as u8));
        });
        self.option(encryption_policy, |h, encryption| {
            h.byte(encryption.algorithm as u8);
            h.key_derivation(&encryption.key_derivation);
            h.sequence(&encryption.apply_to_kinds, |h, kind| h.byte(*kind as u8));
            h.boolean(encryption.encrypt_metadata);
        });
        self.option(capability_policy, Self::capability_policy);
        self.option(transform_order, Self::transform_order);
        self.option(transform_proof_policy, |h, proof| {
            h.boolean(proof.enforce_transform_order);
            h.boolean(proof.require_deterministic_transforms);
            h.boolean(proof.allow_lossy_transforms);
            h.boolean(proof.require_plaintext_hash);
            h.option(proof.max_compression_ratio.as_ref(), |h, ratio| {
                h.u32(ratio.to_bits())
            });
            h.sequence(&proof.encryption_domains, |h, domain| {
                h.string(&domain.domain_id);
                h.sequence(&domain.allowed_kdfs, |h, kdf| h.byte(*kdf as u8));
                h.boolean(domain.relay_privacy);
                h.boolean(domain.mailbox_privacy);
            });
            h.byte(proof.minimum_proof_strength as u8);
        });
        self.count(repair_groups.len());
        for (id, group) in repair_groups {
            self.0.update(id.as_bytes());
            self.repair_group(group);
        }
    }
}

/// The graph v2 transcript shared by owned graphs and streaming flat graphs.
///
/// Content is represented by its byte length and SHA-256 digest, allowing
/// callers to read bounded chunks instead of materializing whole files. Roots
/// are sorted here; objects must arrive in strictly increasing ObjectId order.
/// As in ObjectGraph, each object's map key must equal its own ID. The frozen
/// transcript retains both copies of that ID.
pub(crate) struct GraphMerkleV2Hasher(MerkleV2Hasher);

impl GraphMerkleV2Hasher {
    pub(crate) fn new(roots: &[ObjectId], object_count: usize) -> Self {
        let mut hasher = MerkleV2Hasher::new(b"object-graph");
        let mut roots: Vec<_> = roots.iter().collect();
        roots.sort_unstable();
        hasher.count(roots.len());
        for root in roots {
            hasher.id(root);
        }
        hasher.count(object_count);
        Self(hasher)
    }

    pub(crate) fn object(
        &mut self,
        id: &ObjectId,
        metadata: &ObjectMetadata,
        children: &[ObjectEdge],
        content: Option<(u64, [u8; 32])>,
    ) {
        self.0.id(id);
        self.0.object(id, metadata, children, content);
    }

    pub(crate) fn finish(self) -> MerkleRootV2 {
        self.0.finish()
    }
}

/// Deterministic big-endian byte serialization for f32.
///
/// Converts NaN to canonical form (0x7fc0_0000) and normalizes signed zero.
/// This ensures consistent byte representation across platforms.
pub fn deterministic_f32_be_bytes(value: f32) -> [u8; 4] {
    const CANONICAL_NAN_BITS: u32 = 0x7fc0_0000;

    let bits = if value.is_nan() {
        CANONICAL_NAN_BITS
    } else if value == 0.0 {
        0
    } else {
        value.to_bits()
    };

    bits.to_be_bytes()
}

/// Deterministic big-endian byte serialization for f64.
///
/// Converts NaN to canonical form (0x7ff8_0000_0000_0000) and normalizes signed zero.
/// This ensures consistent byte representation across platforms.
pub fn deterministic_f64_be_bytes(value: f64) -> [u8; 8] {
    const CANONICAL_NAN_BITS: u64 = 0x7ff8_0000_0000_0000;

    let bits = if value.is_nan() {
        CANONICAL_NAN_BITS
    } else if value == 0.0 {
        0
    } else {
        value.to_bits()
    };

    bits.to_be_bytes()
}

/// Deterministic little-endian byte serialization for f32.
///
/// Converts NaN to canonical form (0x7fc0_0000) and normalizes signed zero.
/// This ensures consistent byte representation across platforms.
pub fn deterministic_f32_le_bytes(value: f32) -> [u8; 4] {
    const CANONICAL_NAN_BITS: u32 = 0x7fc0_0000;

    let bits = if value.is_nan() {
        CANONICAL_NAN_BITS
    } else if value == 0.0 {
        0
    } else {
        value.to_bits()
    };

    bits.to_le_bytes()
}

/// Deterministic little-endian byte serialization for f64.
///
/// Converts NaN to canonical form (0x7ff8_0000_0000_0000) and normalizes signed zero.
/// This ensures consistent byte representation across platforms.
pub fn deterministic_f64_le_bytes(value: f64) -> [u8; 8] {
    const CANONICAL_NAN_BITS: u64 = 0x7ff8_0000_0000_0000;

    let bits = if value.is_nan() {
        CANONICAL_NAN_BITS
    } else if value == 0.0 {
        0
    } else {
        value.to_bits()
    };

    bits.to_le_bytes()
}

impl MerkleRoot {
    /// Construct from hash bytes.
    #[must_use]
    pub const fn new(hash: [u8; 32]) -> Self {
        Self { hash }
    }

    /// Get the hash bytes.
    #[must_use]
    pub const fn hash(&self) -> &[u8; 32] {
        &self.hash
    }

    /// Create a zero/empty Merkle root.
    #[must_use]
    pub const fn zero() -> Self {
        Self { hash: [0u8; 32] }
    }

    /// Commit to the complete graph with the unambiguous v2 encoding.
    ///
    /// Includes roots, ID variants, all platform/application metadata, sorted
    /// child edges and their symlink targets, and optional content length/hash.
    /// Object/map insertion order and child-edge order do not matter; duplicate
    /// edges retain their multiplicity. Unicode paths use portable UTF-8;
    /// non-Unicode paths use stable Unix bytes or Windows UTF-16 code units.
    /// On other targets only, non-Unicode paths use an implementation-native
    /// encoding comparable within the same target and Rust toolchain.
    ///
    /// This computes a commitment, not structural validation. Use
    /// [`AtpVerifier::verify_graph_v2`](crate::atp::verifier::AtpVerifier::verify_graph_v2)
    /// with a trusted expected root before accepting a graph.
    /// Unlike a graph, a manifest omits platform/application/symlink metadata;
    /// its v2 representation deliberately has a different domain and digest.
    #[must_use]
    pub fn from_graph_v2(graph: &ObjectGraph) -> MerkleRootV2 {
        let roots: Vec<_> = graph.roots().cloned().collect();
        let mut hasher = GraphMerkleV2Hasher::new(&roots, graph.object_count());
        for (id, object) in graph.objects() {
            let content = object
                .content
                .as_ref()
                .map(|bytes| (bytes.len() as u64, Sha256::digest(bytes).into()));
            hasher.object(id, &object.metadata, &object.children, content);
        }
        hasher.finish()
    }

    /// Commit to manifest components without changing any legacy binding.
    ///
    /// Unlike [`Self::from_manifest_components`], every optional field,
    /// collection boundary, ID variant and metadata value is encoded. Existing
    /// repair-group roots and symbol authentication tags are included as data;
    /// they must remain their legacy values, not this detached v2 digest.
    /// The shared encoder is also used by [`Self::from_manifest_v2`].
    ///
    /// This low-level commitment excludes the manifest envelope (roots,
    /// version, metadata policy, schema, extensions, timestamp and embedded v1
    /// root). Use [`Self::from_manifest_v2`] to authenticate a whole manifest.
    /// Computing a digest does not validate its input.
    #[must_use]
    pub fn from_manifest_components_v2(
        objects: &BTreeMap<ObjectId, ManifestObject>,
        chunk_plan: &Option<ChunkPlan>,
        raptorq_layout: &Option<RaptorQRepairLayout>,
        compression_policy: &Option<CompressionPolicy>,
        encryption_policy: &Option<EncryptionPolicy>,
        capability_policy: &Option<CapabilityPolicy>,
        transform_order: &Option<TransformOrder>,
        transform_proof_policy: &Option<TransformProofPolicy>,
        repair_groups: &BTreeMap<RepairGroupId, RepairGroup>,
    ) -> MerkleRootV2 {
        let mut hasher = MerkleV2Hasher::new(b"manifest-components");
        hasher.components(
            objects,
            chunk_plan.as_ref(),
            raptorq_layout.as_ref(),
            compression_policy.as_ref(),
            encryption_policy.as_ref(),
            capability_policy.as_ref(),
            transform_order.as_ref(),
            transform_proof_policy.as_ref(),
            repair_groups,
        );
        hasher.finish()
    }

    /// Authenticate an entire existing manifest with a detached v2 commitment.
    ///
    /// Includes every manifest field and its legacy root/authentication
    /// bindings. No field is replaced, so the original manifest still validates
    /// and remains readable by existing peers. Store or exchange this digest
    /// separately through an authenticated, explicitly v2-labelled channel.
    /// Existing ATP transports neither negotiate nor verify it automatically.
    ///
    /// Maps are canonical by key; manifest vectors retain their stored order.
    /// Floats retain their exact IEEE bits. This is not the digest produced by
    /// [`Self::from_graph_v2`] or [`Self::from_manifest_components_v2`]. Use
    /// [`AtpVerifier::verify_manifest_v2`](crate::atp::verifier::AtpVerifier::verify_manifest_v2)
    /// to check both ordinary manifest validity and a trusted v2 expectation.
    #[must_use]
    pub fn from_manifest_v2(manifest: &Manifest) -> MerkleRootV2 {
        let mut hasher = MerkleV2Hasher::new(b"manifest");
        hasher.u32(manifest.version.0);
        hasher.0.update(manifest.merkle_root.hash());
        let policy = &manifest.metadata_policy;
        hasher.boolean(policy.preserve_unix_permissions);
        hasher.boolean(policy.preserve_windows_attributes);
        hasher.boolean(policy.preserve_extended_attributes);
        hasher.boolean(policy.preserve_symlinks);
        hasher.boolean(policy.preserve_timestamps);
        hasher.boolean(policy.record_platform_metadata);
        hasher.boolean(policy.verify_metadata);
        hasher.sequence(&manifest.roots, MerkleV2Hasher::id);
        hasher.sequence(&manifest.hash_algorithms, |h, algorithm| {
            h.byte(*algorithm as u8);
        });
        hasher.components(
            &manifest.objects,
            manifest.chunk_plan.as_ref(),
            manifest.raptorq_layout.as_ref(),
            manifest.compression_policy.as_ref(),
            manifest.encryption_policy.as_ref(),
            manifest.capability_policy.as_ref(),
            manifest.transform_order.as_ref(),
            manifest.transform_proof_policy.as_ref(),
            &manifest.repair_groups,
        );
        hasher.sequence(&manifest.unknown_optional_fields, |h, field| {
            h.string(&field.name);
            h.byte(field.field_type as u8);
            h.bytes(&field.data);
        });
        hasher.u64(manifest.created_timestamp_nanos);
        hasher.string(&manifest.schema_id);
        hasher.finish()
    }

    /// Compute Merkle root from an object graph.
    ///
    /// This preserves the legacy wire encoding. For externally trusted graph
    /// commitments use [`Self::from_graph_v2`], which frames every field and
    /// commits to metadata omitted by this historical representation.
    #[must_use]
    pub fn from_graph(graph: &ObjectGraph) -> Self {
        let mut hasher = Sha256::new();

        // Hash all object data in canonical order (BTreeMap iteration is already sorted)
        for (id, object) in graph.objects() {
            // Object ID
            hasher.update(id.hash_bytes());

            // Object kind
            hasher.update([object.metadata.kind as u8]);

            // Object size
            if let Some(size) = object.metadata.size_bytes {
                hasher.update(size.to_be_bytes());
            }

            // Children in sorted order (avoid clone by creating sorted indices)
            let mut child_indices: Vec<usize> = (0..object.children.len()).collect();
            child_indices.sort_by(|&a, &b| object.children[a].name.cmp(&object.children[b].name));

            for &idx in &child_indices {
                let edge = &object.children[idx];
                hasher.update(edge.name.as_bytes());
                hasher.update(edge.child_id.hash_bytes());
                hasher.update([u8::from(edge.is_symlink)]);
                if let Some(target) = &edge.symlink_target {
                    hasher.update(target.as_os_str().as_encoded_bytes());
                }
            }

            // Content hash for leaf objects
            if let Some(content) = &object.content {
                let content_hash = Sha256::digest(content);
                hasher.update(content_hash);
            }
        }

        Self {
            hash: hasher.finalize().into(),
        }
    }

    /// Compute Merkle root from manifest components.
    ///
    /// This is the legacy encoding used by existing manifests and transports.
    /// Use [`Self::from_manifest_v2`] for a complete detached commitment without
    /// changing that encoding or its repair-symbol authentication bindings.
    #[must_use]
    pub fn from_manifest_components(
        objects: &BTreeMap<ObjectId, ManifestObject>,
        chunk_plan: &Option<ChunkPlan>,
        raptorq_layout: &Option<RaptorQRepairLayout>,
        compression_policy: &Option<CompressionPolicy>,
        encryption_policy: &Option<EncryptionPolicy>,
        capability_policy: &Option<CapabilityPolicy>,
        transform_order: &Option<TransformOrder>,
        transform_proof_policy: &Option<TransformProofPolicy>,
        repair_groups: &BTreeMap<RepairGroupId, RepairGroup>,
    ) -> Self {
        let mut hasher = Sha256::new();

        // Hash all objects in deterministic order
        for (id, obj) in objects {
            hasher.update(id.hash_bytes());
            hasher.update([obj.kind as u8]);

            if let Some(size) = obj.size_bytes {
                hasher.update(size.to_be_bytes());
            }

            // Hash children
            for (name, child_id) in &obj.children {
                hasher.update(name.as_bytes());
                hasher.update(child_id.hash_bytes());
            }

            if let Some(content_hash) = &obj.content_hash {
                hasher.update(content_hash);
            }

            for symbol in &obj.raptorq_symbols {
                hasher.update(symbol.index.to_be_bytes());
                hasher.update(symbol.esi.to_be_bytes());
                hasher.update(symbol.size_bytes.to_be_bytes());
                hasher.update(symbol.content_hash);
                hasher.update([u8::from(symbol.is_source)]);
                if let Some(group_id) = &symbol.repair_group_id {
                    hasher.update(group_id.as_bytes());
                }
            }
        }

        // Hash chunk plan
        if let Some(plan) = chunk_plan {
            hasher.update([plan.strategy as u8]);
            hasher.update(plan.target_chunk_size.to_be_bytes());
            hasher.update(plan.min_chunk_size.to_be_bytes());
            hasher.update(plan.max_chunk_size.to_be_bytes());

            if let Some(cdc) = &plan.cdc_params {
                hasher.update(cdc.window_size.to_be_bytes());
                hasher.update(cdc.average_chunk_size.to_be_bytes());
                hasher.update(cdc.normalization.to_be_bytes());
            }
        }

        // Hash RaptorQ layout
        if let Some(layout) = raptorq_layout {
            hasher.update(layout.source_symbols.to_be_bytes());
            hasher.update(layout.total_symbols.to_be_bytes());
            hasher.update(layout.symbol_size.to_be_bytes());
            hasher.update(deterministic_f32_be_bytes(layout.overhead_ratio));

            for sub_block in &layout.sub_blocks {
                hasher.update(sub_block.index.to_be_bytes());
                hasher.update(sub_block.source_symbols.to_be_bytes());
                hasher.update(sub_block.esi_range.0.to_be_bytes());
                hasher.update(sub_block.esi_range.1.to_be_bytes());
            }
        }

        // Hash policies
        if let Some(comp) = compression_policy {
            hasher.update([comp.algorithm as u8]);
            hasher.update([comp.level]);
            hasher.update(comp.min_size_threshold.to_be_bytes());
            for kind in &comp.apply_to_kinds {
                hasher.update([*kind as u8]);
            }
        }

        if let Some(enc) = encryption_policy {
            hasher.update([enc.algorithm as u8]);
            hasher.update([enc.key_derivation.kdf as u8]);
            hasher.update(&enc.key_derivation.salt);
            hasher.update([u8::from(enc.encrypt_metadata)]);
        }

        if let Some(cap) = capability_policy {
            for cap_name in &cap.read_capabilities {
                hasher.update(cap_name.as_bytes());
            }
            for cap_name in &cap.write_capabilities {
                hasher.update(cap_name.as_bytes());
            }
            for cap_name in &cap.verify_capabilities {
                hasher.update(cap_name.as_bytes());
            }
        }

        // Hash transform order
        if let Some(order) = transform_order {
            for transform in &order.transforms {
                hasher.update([*transform as u8]);
            }
            hasher.update([order.hash_point as u8]);
            hasher.update([order.verification_boundary.relay_verifiable as u8]);
            hasher.update([order.verification_boundary.mailbox_verifiable as u8]);
            hasher.update([u8::from(
                order.verification_boundary.e2e_verification_required,
            )]);
            hasher.update([order.verification_boundary.privacy_level as u8]);
        }

        // Hash transform proof policy
        if let Some(proof) = transform_proof_policy {
            hasher.update([u8::from(proof.enforce_transform_order)]);
            hasher.update([u8::from(proof.require_deterministic_transforms)]);
            hasher.update([u8::from(proof.allow_lossy_transforms)]);
            hasher.update([u8::from(proof.require_plaintext_hash)]);
            if let Some(ratio) = proof.max_compression_ratio {
                hasher.update(deterministic_f32_be_bytes(ratio));
            }
            hasher.update([proof.minimum_proof_strength as u8]);
            for domain in &proof.encryption_domains {
                hasher.update(domain.domain_id.as_bytes());
                hasher.update([u8::from(domain.relay_privacy)]);
                hasher.update([u8::from(domain.mailbox_privacy)]);
            }
        }

        // Hash repair groups in deterministic order
        for (group_id, repair_group) in repair_groups {
            hasher.update(group_id.as_bytes());
            hasher.update(repair_group.object_id.hash_bytes());
            hasher.update(repair_group.source_block_number.to_be_bytes());
            hasher.update(repair_group.source_symbols_k.to_be_bytes());
            hasher.update(repair_group.k_prime.to_be_bytes());
            hasher.update(repair_group.symbol_size.to_be_bytes());

            // Hash chunk range
            hasher.update(repair_group.chunk_range.start_chunk.to_be_bytes());
            hasher.update(repair_group.chunk_range.end_chunk.to_be_bytes());
            hasher.update(repair_group.chunk_range.start_offset.to_be_bytes());
            hasher.update(repair_group.chunk_range.end_offset.to_be_bytes());

            // Hash repair layout
            hasher.update(
                repair_group
                    .repair_layout
                    .total_repair_symbols
                    .to_be_bytes(),
            );
            hasher.update(deterministic_f32_be_bytes(
                repair_group.repair_layout.overhead_ratio,
            ));
            hasher.update(
                repair_group
                    .repair_layout
                    .systematic_config
                    .systematic_rows
                    .to_be_bytes(),
            );
            hasher.update(
                repair_group
                    .repair_layout
                    .systematic_config
                    .sub_symbols
                    .to_be_bytes(),
            );
            hasher.update(
                repair_group
                    .repair_layout
                    .systematic_config
                    .alignment
                    .to_be_bytes(),
            );

            // Hash interleaving pattern
            hasher.update(
                repair_group
                    .repair_layout
                    .interleaving
                    .block_size
                    .to_be_bytes(),
            );
            hasher.update(repair_group.repair_layout.interleaving.depth.to_be_bytes());
            match repair_group.repair_layout.interleaving.pattern_type {
                InterleavingType::None => hasher.update([0]),
                InterleavingType::Block => hasher.update([1]),
                InterleavingType::Matrix => hasher.update([2]),
                InterleavingType::Randomized(seed) => {
                    hasher.update([3]);
                    hasher.update(seed.to_be_bytes());
                }
            }

            // Hash domains
            hasher.update(repair_group.hash_domain.domain_id.as_bytes());
            hasher.update([repair_group.hash_domain.hash_algorithm as u8]);
            hasher.update(&repair_group.hash_domain.context);

            hasher.update(repair_group.auth_domain.domain_id.as_bytes());
            hasher.update([repair_group.auth_domain.required_proof_strength as u8]);
            hasher.update([repair_group.auth_domain.auth_algorithm as u8]);
            hasher.update([u8::from(repair_group.auth_domain.peer_identity_required)]);
            hasher.update([u8::from(repair_group.auth_domain.transfer_identity_binding)]);
            hasher.update([u8::from(repair_group.auth_domain.session_binding)]);

            // The manifest-root binding is validated against the final root instead of
            // hashed here; including it would create a self-referential digest.
        }

        Self {
            hash: hasher.finalize().into(),
        }
    }

    /// Format as hex string.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.hash)
    }
}

impl fmt::Display for MerkleRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "merkle:{}", &self.to_hex()[..16])
    }
}

/// Canonical manifest representation of an object graph.
#[derive(Debug, Clone, PartialEq)]
pub struct Manifest {
    /// Manifest format version.
    pub version: ManifestVersion,
    /// Merkle root of the entire graph.
    pub merkle_root: MerkleRoot,
    /// Metadata policy used for this manifest.
    pub metadata_policy: MetadataPolicy,
    /// Root object IDs (entry points to the graph).
    pub roots: Vec<ObjectId>,
    /// All objects in the graph.
    pub objects: BTreeMap<ObjectId, ManifestObject>,

    // New fields for ATP-C2 requirements
    /// Hash algorithms used in this manifest.
    pub hash_algorithms: Vec<HashAlgorithm>,
    /// Chunking strategy for large objects.
    pub chunk_plan: Option<ChunkPlan>,
    /// RaptorQ repair layout for forward error correction.
    pub raptorq_layout: Option<RaptorQRepairLayout>,
    /// Compression policy specification.
    pub compression_policy: Option<CompressionPolicy>,
    /// Encryption policy specification.
    pub encryption_policy: Option<EncryptionPolicy>,
    /// Capability policy hints for authorization.
    pub capability_policy: Option<CapabilityPolicy>,
    /// Transform ordering specification for ATP-C4.
    pub transform_order: Option<TransformOrder>,
    /// Transform proof policy for ATP-C4.
    pub transform_proof_policy: Option<TransformProofPolicy>,
    /// Repair groups for ATP-G2 symbol authentication.
    pub repair_groups: BTreeMap<RepairGroupId, RepairGroup>,
    /// Unknown optional fields for forward compatibility.
    pub unknown_optional_fields: Vec<UnknownField>,
    /// Manifest creation timestamp (nanoseconds since epoch).
    pub created_timestamp_nanos: u64,
    /// Manifest schema identifier for validation.
    pub schema_id: String,
}

/// Object representation in a manifest.
#[derive(Debug, Clone, PartialEq)]
pub struct ManifestObject {
    /// Object ID.
    pub id: ObjectId,
    /// Object kind.
    pub kind: ObjectKind,
    /// Size in bytes (for leaf objects).
    pub size_bytes: Option<u64>,
    /// Child object IDs and names.
    pub children: BTreeMap<String, ObjectId>,
    /// Content hash (for content-addressed objects).
    pub content_hash: Option<[u8; 32]>,
    /// Chunk boundaries for large objects.
    pub chunk_boundaries: Vec<ChunkBoundary>,
    /// RaptorQ encoding symbols for this object.
    pub raptorq_symbols: Vec<RaptorQSymbol>,
    /// Compression metadata.
    pub compression_metadata: Option<CompressionMetadata>,
    /// Encryption metadata.
    pub encryption_metadata: Option<EncryptionMetadata>,
}

/// Chunk boundary information for large objects.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ChunkBoundary {
    /// Chunk index.
    pub index: u32,
    /// Byte offset in the original object.
    pub byte_offset: u64,
    /// Chunk size in bytes.
    pub size_bytes: u64,
    /// Content hash of this chunk.
    pub content_hash: [u8; 32],
    /// Chunk strategy used.
    pub strategy: ChunkStrategy,
    /// Profile-specific metadata for this chunk.
    pub metadata: Option<ChunkMetadata>,
}

/// Profile-specific chunk metadata for different chunking strategies.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ChunkMetadata {
    /// Bulk file chunking metadata.
    BulkFile {
        /// Expected throughput tier for this chunk.
        throughput_tier: ThroughputTier,
    },
    /// Sync tree chunking metadata.
    SyncTree {
        /// Rolling hash value at boundary.
        boundary_hash: u64,
        /// Content similarity score.
        similarity_score: u32,
    },
    /// Media chunking metadata.
    Media {
        /// Keyframe hint for media chunks.
        is_keyframe_boundary: bool,
        /// Progressive decoding priority.
        decoding_priority: u8,
    },
    /// Sparse image chunking metadata.
    SparseImage {
        /// Whether this chunk represents a hole.
        is_sparse_hole: bool,
        /// Platform-specific hole metadata.
        hole_metadata: Option<SparseHoleMetadata>,
    },
    /// Artifact chunking metadata.
    Artifact {
        /// Build reproducibility context.
        build_context: ArtifactBuildContext,
        /// Proof strength indicator.
        proof_strength: ProofStrength,
    },
    /// Stream chunking metadata.
    Stream {
        /// Sequence number for ordering.
        sequence: u64,
        /// Whether this chunk can be consumed early.
        early_consumption_safe: bool,
    },
}

/// Throughput tier for bulk file transfers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ThroughputTier {
    /// Small chunks for tail optimization.
    Tail,
    /// Standard chunks for normal throughput.
    Standard,
    /// Large chunks for maximum throughput.
    Bulk,
}

/// Sparse hole metadata for platform support.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SparseHoleMetadata {
    /// Hole size in bytes.
    pub hole_size: u64,
    /// Platform-specific hole type.
    pub hole_type: String,
    /// Extended attributes for the hole.
    pub attributes: BTreeMap<String, Vec<u8>>,
}

/// Build context for artifact reproducibility.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ArtifactBuildContext {
    /// Build system identifier.
    pub build_system: String,
    /// Build timestamp (if deterministic).
    pub build_timestamp: Option<u64>,
    /// Build environment hash.
    pub environment_hash: [u8; 32],
    /// Compiler/toolchain version.
    pub toolchain_version: String,
}

/// Proof strength indicator for verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProofStrength {
    /// Basic content verification.
    Basic,
    /// Enhanced verification with build context.
    Enhanced,
    /// Cryptographic proof with zero-knowledge elements.
    Cryptographic,
}

/// RaptorQ symbol information.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RaptorQSymbol {
    /// Symbol index within the object.
    pub index: u32,
    /// Encoding symbol identifier (ESI).
    pub esi: u32,
    /// Symbol size in bytes.
    pub size_bytes: u32,
    /// Symbol content hash.
    pub content_hash: [u8; 32],
    /// Whether this is a source symbol (true) or repair symbol (false).
    pub is_source: bool,
    /// Repair group this symbol belongs to.
    pub repair_group_id: Option<RepairGroupId>,
    /// Authentication tag binding symbol to group and manifest.
    pub auth_tag: Option<[u8; 32]>,
}

/// Repair group identifier for binding symbols to decode context.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RepairGroupId(pub [u8; 16]);

impl RepairGroupId {
    /// Create a new repair group ID from object and source block parameters.
    #[must_use]
    pub fn new(object_id: &ObjectId, source_block_number: u32, k_prime: u32) -> Self {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(b"ATP-G2-RepairGroup");
        hasher.update(object_id.hash_bytes());
        hasher.update(source_block_number.to_be_bytes());
        hasher.update(k_prime.to_be_bytes());

        let hash = hasher.finalize();
        let mut id = [0u8; 16];
        id.copy_from_slice(&hash[..16]);
        Self(id)
    }

    /// Get the raw bytes of this group ID.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Display for RepairGroupId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

/// RepairGroup manifest record containing all decode-critical parameters.
#[derive(Debug, Clone, PartialEq)]
pub struct RepairGroup {
    /// Unique identifier for this repair group.
    pub group_id: RepairGroupId,
    /// Object this repair group belongs to.
    pub object_id: ObjectId,
    /// Source block number within the object.
    pub source_block_number: u32,
    /// Chunk range covered by this source block.
    pub chunk_range: ChunkRange,
    /// Source symbol count (K) for this block.
    pub source_symbols_k: u32,
    /// Extended source symbol count (K') for systematic decoding.
    pub k_prime: u32,
    /// Symbol size in bytes.
    pub symbol_size: u32,
    /// Repair symbol layout configuration.
    pub repair_layout: RepairLayout,
    /// Hash domain for symbol integrity verification.
    pub hash_domain: HashDomain,
    /// Transform policy that was applied to source data.
    pub transform_policy: Option<TransformOrder>,
    /// Authentication domain for symbol verification.
    pub auth_domain: AuthenticationDomain,
    /// Capability policy for access control.
    pub capability_policy: Option<CapabilityPolicy>,
    /// Manifest root this group is bound to.
    pub manifest_root: MerkleRoot,
}

/// Chunk range specification for repair groups.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkRange {
    /// Starting chunk index.
    pub start_chunk: u32,
    /// Ending chunk index (exclusive).
    pub end_chunk: u32,
    /// Starting byte offset within the object.
    pub start_offset: u64,
    /// Ending byte offset within the object (exclusive).
    pub end_offset: u64,
}

/// Repair symbol layout configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct RepairLayout {
    /// Total repair symbols available.
    pub total_repair_symbols: u32,
    /// Repair symbol overhead ratio (R/K).
    pub overhead_ratio: f32,
    /// Systematic encoding parameters.
    pub systematic_config: SystematicConfig,
    /// Symbol interleaving pattern.
    pub interleaving: InterleavingPattern,
}

/// Systematic encoding configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystematicConfig {
    /// Number of systematic rows.
    pub systematic_rows: u32,
    /// Sub-symbol configuration.
    pub sub_symbols: u32,
    /// Alignment requirements.
    pub alignment: u32,
}

/// Symbol interleaving pattern for improved burst error resilience.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterleavingPattern {
    /// Interleaving block size.
    pub block_size: u32,
    /// Interleaving depth.
    pub depth: u32,
    /// Pattern type.
    pub pattern_type: InterleavingType,
}

/// Types of symbol interleaving.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterleavingType {
    /// No interleaving.
    None,
    /// Block-based interleaving.
    Block,
    /// Matrix-based interleaving.
    Matrix,
    /// Randomized interleaving with seed.
    Randomized(u32),
}

/// Hash domain for symbol integrity verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashDomain {
    /// Domain identifier string.
    pub domain_id: String,
    /// Hash algorithm used for symbols.
    pub hash_algorithm: HashAlgorithm,
    /// Additional context for hash computation.
    pub context: Vec<u8>,
}

/// Authentication domain for repair symbol verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationDomain {
    /// Domain identifier for this auth context.
    pub domain_id: String,
    /// Required proof strength for symbols in this domain.
    pub required_proof_strength: ProofStrength,
    /// Authentication algorithm specification.
    pub auth_algorithm: AuthenticationAlgorithm,
    /// Peer identity requirements.
    pub peer_identity_required: bool,
    /// Transfer identity binding.
    pub transfer_identity_binding: bool,
    /// Session binding requirements.
    pub session_binding: bool,
}

/// Authentication algorithm types for repair symbols.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticationAlgorithm {
    /// HMAC-SHA256 with symmetric keys.
    HmacSha256,
    /// EdDSA signatures for asymmetric authentication.
    EdDsa,
    /// X25519 ECDH for session-bound authentication.
    X25519Ecdh,
}

/// Compression metadata for an object.
#[derive(Debug, Clone, PartialEq)]
pub struct CompressionMetadata {
    /// Compression algorithm used.
    pub algorithm: CompressionAlgorithm,
    /// Compression level used.
    pub level: u8,
    /// Original uncompressed size.
    pub original_size: u64,
    /// Compressed size.
    pub compressed_size: u64,
    /// Compression ratio achieved.
    pub compression_ratio: f32,
}

/// Encryption metadata for an object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionMetadata {
    /// Encryption algorithm used.
    pub algorithm: EncryptionAlgorithm,
    /// Initialization vector / nonce.
    pub iv: Vec<u8>,
    /// Authentication tag (for AEAD algorithms).
    pub auth_tag: Vec<u8>,
    /// Key derivation information.
    pub key_derivation: KeyDerivation,
}

/// Transform ordering specification for ATP-C4.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TransformOrder {
    /// Ordered list of transforms applied to content.
    pub transforms: Vec<TransformType>,
    /// Hash computation point in the transform pipeline.
    pub hash_point: HashPoint,
    /// Verification boundary specification.
    pub verification_boundary: VerificationBoundary,
}

/// Types of transforms that can be applied to content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TransformType {
    /// Content chunking.
    Chunking,
    /// Compression transform.
    Compression,
    /// Encryption transform.
    Encryption,
    /// Error correction (RaptorQ) encoding.
    ErrorCorrection,
}

/// Point in transform pipeline where hashes are computed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum HashPoint {
    /// Hash computed on original plaintext content.
    Plaintext,
    /// Hash computed after compression but before encryption.
    PostCompression,
    /// Hash computed on final ciphertext.
    Ciphertext,
    /// Multiple hashes at different points for verification flexibility.
    MultiPoint,
}

/// Verification boundary specification.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct VerificationBoundary {
    /// What content is verifiable by untrusted relays.
    pub relay_verifiable: VerificationLevel,
    /// What content is verifiable by mailbox providers.
    pub mailbox_verifiable: VerificationLevel,
    /// What content requires end-to-end verification.
    pub e2e_verification_required: bool,
    /// Privacy protection level for intermediate hops.
    pub privacy_level: PrivacyLevel,
}

/// Level of verification possible at different points.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum VerificationLevel {
    /// No verification possible (encrypted content).
    None,
    /// Size and transfer integrity only.
    TransferIntegrity,
    /// Content hash verification possible.
    ContentHash,
    /// Full content and metadata verification.
    FullVerification,
}

/// Privacy protection level for content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PrivacyLevel {
    /// Content and metadata visible to all hops.
    Public,
    /// Metadata visible, content protected.
    MetadataVisible,
    /// Size visible, content and metadata protected.
    SizeVisible,
    /// Complete privacy protection.
    FullPrivacy,
}

/// Transform proof policy for ATP-C4 requirements.
#[derive(Debug, Clone, PartialEq)]
pub struct TransformProofPolicy {
    /// Required transform order validation.
    pub enforce_transform_order: bool,
    /// Require deterministic transforms for proof strength.
    pub require_deterministic_transforms: bool,
    /// Allow lossy transforms (with explicit disclosure).
    pub allow_lossy_transforms: bool,
    /// Require plaintext hash availability.
    pub require_plaintext_hash: bool,
    /// Maximum compression ratio before rejection.
    pub max_compression_ratio: Option<f32>,
    /// Encryption domain restrictions.
    pub encryption_domains: Vec<EncryptionDomain>,
    /// Proof strength requirements.
    pub minimum_proof_strength: ProofStrength,
}

/// Encryption domain specification.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct EncryptionDomain {
    /// Domain identifier.
    pub domain_id: String,
    /// Allowed key derivation functions for this domain.
    pub allowed_kdfs: Vec<KeyDerivationFunction>,
    /// Relay privacy requirements.
    pub relay_privacy: bool,
    /// Mailbox privacy requirements.
    pub mailbox_privacy: bool,
}

impl Manifest {
    /// Create a manifest from an object graph with default policies.
    pub fn from_graph(
        graph: &ObjectGraph,
        metadata_policy: MetadataPolicy,
    ) -> Result<Self, ManifestError> {
        Self::from_graph_with_policies(
            graph,
            metadata_policy,
            vec![HashAlgorithm::Sha256], // Always include SHA-256
            None,                        // No chunk plan
            None,                        // No RaptorQ layout
            None,                        // No compression
            None,                        // No encryption
            None,                        // No capability policy
            None,                        // No transform order
            None,                        // No transform proof policy
        )
    }

    /// Create a manifest from an object graph with full policy specification.
    pub fn from_graph_with_policies(
        graph: &ObjectGraph,
        metadata_policy: MetadataPolicy,
        hash_algorithms: Vec<HashAlgorithm>,
        chunk_plan: Option<ChunkPlan>,
        raptorq_layout: Option<RaptorQRepairLayout>,
        compression_policy: Option<CompressionPolicy>,
        encryption_policy: Option<EncryptionPolicy>,
        capability_policy: Option<CapabilityPolicy>,
        transform_order: Option<TransformOrder>,
        transform_proof_policy: Option<TransformProofPolicy>,
    ) -> Result<Self, ManifestError> {
        // Validate hash algorithms
        if !hash_algorithms.contains(&HashAlgorithm::Sha256) {
            return Err(ManifestError::InvalidFormat(
                "SHA-256 is required in hash_algorithms".to_string(),
            ));
        }

        let mut manifest_objects = BTreeMap::new();
        let roots: Vec<_> = graph.roots().cloned().collect();

        // Convert each object to manifest format
        for (id, object) in graph.objects() {
            let content_hash = if object.id.is_content_addressed() {
                Some(*object.id.hash_bytes())
            } else if let Some(content) = &object.content {
                let hash = Sha256::digest(content);
                Some(hash.into())
            } else {
                None
            };

            let manifest_obj = ManifestObject {
                id: id.clone(),
                kind: object.metadata.kind,
                size_bytes: object.metadata.size_bytes,
                children: object
                    .children
                    .iter()
                    .map(|edge| (edge.name.clone(), edge.child_id.clone()))
                    .collect(),
                content_hash,
                chunk_boundaries: Self::compute_chunk_boundaries(
                    chunk_plan.as_ref(),
                    object,
                    content_hash.as_ref(),
                ),
                raptorq_symbols: Self::compute_raptorq_symbols(
                    raptorq_layout.as_ref(),
                    object,
                    content_hash.as_ref(),
                ),
                compression_metadata: Self::compute_compression_metadata(
                    compression_policy.as_ref(),
                    object,
                ),
                encryption_metadata: Self::compute_encryption_metadata(
                    encryption_policy.as_ref(),
                    object,
                ),
            };
            manifest_objects.insert(id.clone(), manifest_obj);
        }

        let mut repair_groups = Self::compute_repair_groups(
            raptorq_layout.as_ref(),
            &manifest_objects,
            MerkleRoot::zero(),
        );

        let merkle_root = MerkleRoot::from_manifest_components(
            &manifest_objects,
            &chunk_plan,
            &raptorq_layout,
            &compression_policy,
            &encryption_policy,
            &capability_policy,
            &transform_order,
            &transform_proof_policy,
            &repair_groups,
        );
        for repair_group in repair_groups.values_mut() {
            repair_group.manifest_root = merkle_root.clone();
        }
        Self::bind_repair_symbol_auth_tags(&mut manifest_objects, &repair_groups);

        Ok(Self {
            version: ManifestVersion::CURRENT,
            merkle_root,
            metadata_policy,
            roots,
            objects: manifest_objects,
            hash_algorithms,
            chunk_plan,
            raptorq_layout,
            compression_policy,
            encryption_policy,
            capability_policy,
            transform_order,
            transform_proof_policy,
            repair_groups,
            unknown_optional_fields: Vec::new(),
            created_timestamp_nanos: 0,
            schema_id: "atp.manifest.v1".to_string(),
        })
    }

    /// Validate the manifest for consistency.
    pub fn validate(&self) -> Result<(), ManifestError> {
        // Check version compatibility
        if !self.version.is_supported() {
            return Err(ManifestError::UnsupportedVersion(self.version));
        }

        // Validate hash algorithms
        if !self.hash_algorithms.contains(&HashAlgorithm::Sha256) {
            return Err(ManifestError::InvalidFormat(
                "SHA-256 is required in hash_algorithms".to_string(),
            ));
        }

        // Check that all roots exist in objects
        for root_id in &self.roots {
            if !self.objects.contains_key(root_id) {
                return Err(ManifestError::RootObjectMissing(root_id.clone()));
            }
        }

        // Check that all child references point to existing objects
        for manifest_obj in self.objects.values() {
            for child_id in manifest_obj.children.values() {
                if !self.objects.contains_key(child_id) {
                    return Err(ManifestError::ChildObjectMissing(child_id.clone()));
                }
            }

            // Validate chunk boundaries are ordered
            let mut prev_offset = 0;
            for chunk in &manifest_obj.chunk_boundaries {
                if chunk.byte_offset < prev_offset {
                    return Err(ManifestError::InvalidFormat(
                        "chunk boundaries must be in ascending order".to_string(),
                    ));
                }
                // checked_add: a crafted byte_offset/size_bytes pair must not
                // wrap and re-arm the ascending-order check above.
                prev_offset = chunk
                    .byte_offset
                    .checked_add(chunk.size_bytes)
                    .ok_or_else(|| {
                        ManifestError::InvalidFormat(
                            "chunk boundary byte_offset + size_bytes overflows u64".to_string(),
                        )
                    })?;
            }

            // Validate RaptorQ symbols
            if let Some(layout) = &self.raptorq_layout {
                for symbol in &manifest_obj.raptorq_symbols {
                    if symbol.esi >= layout.total_symbols {
                        return Err(ManifestError::InvalidFormat(
                            "RaptorQ symbol ESI exceeds layout total_symbols".to_string(),
                        ));
                    }
                }
            }
        }

        // Validate RaptorQ layout consistency
        if let Some(layout) = &self.raptorq_layout {
            if layout.source_symbols > layout.total_symbols {
                return Err(ManifestError::InvalidFormat(
                    "RaptorQ source_symbols cannot exceed total_symbols".to_string(),
                ));
            }

            if layout.overhead_ratio < 0.0 || layout.overhead_ratio > 1.0 {
                return Err(ManifestError::InvalidFormat(
                    "RaptorQ overhead_ratio must be between 0.0 and 1.0".to_string(),
                ));
            }
        }

        // Validate chunk plan consistency
        if let Some(plan) = &self.chunk_plan {
            if plan.min_chunk_size > plan.target_chunk_size {
                return Err(ManifestError::InvalidFormat(
                    "chunk min_chunk_size cannot exceed target_chunk_size".to_string(),
                ));
            }

            if plan.target_chunk_size > plan.max_chunk_size {
                return Err(ManifestError::InvalidFormat(
                    "chunk target_chunk_size cannot exceed max_chunk_size".to_string(),
                ));
            }

            if matches!(plan.strategy, ChunkStrategy::ContentDefined) && plan.cdc_params.is_none() {
                return Err(ManifestError::InvalidFormat(
                    "content-defined chunking requires cdc_params".to_string(),
                ));
            }
        }

        // Check for unknown critical fields
        for field in &self.unknown_optional_fields {
            if matches!(field.field_type, FieldType::Critical) {
                return Err(ManifestError::UnknownCriticalField(field.name.clone()));
            }
        }

        // ATP-C4: Validate transform proof policies
        self.validate_transform_policies()?;

        // ATP-G2: Validate repair groups
        self.validate_repair_groups()?;

        // Verify Merkle root
        let computed_root = MerkleRoot::from_manifest_components(
            &self.objects,
            &self.chunk_plan,
            &self.raptorq_layout,
            &self.compression_policy,
            &self.encryption_policy,
            &self.capability_policy,
            &self.transform_order,
            &self.transform_proof_policy,
            &self.repair_groups,
        );

        if computed_root != self.merkle_root {
            return Err(ManifestError::MerkleRootMismatch {
                expected: self.merkle_root.clone(),
                computed: computed_root,
            });
        }

        Ok(())
    }

    /// Validate transform policies for ATP-C4 requirements.
    fn validate_transform_policies(&self) -> Result<(), ManifestError> {
        // If we have a transform proof policy, validate it
        if let Some(proof_policy) = &self.transform_proof_policy {
            // Validate transform order if required
            if proof_policy.enforce_transform_order {
                if let Some(order) = &self.transform_order {
                    Self::validate_transform_order_consistency(
                        order,
                        self.compression_policy.as_ref(),
                        self.encryption_policy.as_ref(),
                    )?;
                } else {
                    return Err(ManifestError::TransformPolicyViolation(
                        "transform order enforcement requires transform_order specification"
                            .to_string(),
                    ));
                }
            }

            // Check for ambiguous verification modes
            Self::validate_verification_boundary(self.transform_order.as_ref(), proof_policy)?;

            // Validate lossy transforms disclosure
            Self::validate_lossy_transforms_disclosure(
                self.compression_policy.as_ref(),
                proof_policy,
            )?;

            // Validate encryption domains
            Self::validate_encryption_domains(self.encryption_policy.as_ref(), proof_policy)?;

            // Check plaintext hash requirements
            if proof_policy.require_plaintext_hash {
                Self::validate_plaintext_hash_availability(self.transform_order.as_ref())?;
            }
        }

        // Validate transform order consistency if specified
        if let Some(order) = &self.transform_order {
            Self::validate_transform_order_semantics(order)?;
        }

        Ok(())
    }

    /// Validate transform order consistency with policies.
    fn validate_transform_order_consistency(
        order: &TransformOrder,
        compression_policy: Option<&CompressionPolicy>,
        encryption_policy: Option<&EncryptionPolicy>,
    ) -> Result<(), ManifestError> {
        let has_compression = compression_policy
            .is_some_and(|policy| !matches!(policy.algorithm, CompressionAlgorithm::None));
        let has_encryption = encryption_policy
            .is_some_and(|policy| !matches!(policy.algorithm, EncryptionAlgorithm::None));

        // Check compression transform consistency
        if has_compression && !order.transforms.contains(&TransformType::Compression) {
            return Err(ManifestError::TransformOrderViolation(
                "compression policy specified but compression transform not in order".to_string(),
            ));
        }

        if !has_compression && order.transforms.contains(&TransformType::Compression) {
            return Err(ManifestError::TransformOrderViolation(
                "compression transform in order but no compression policy".to_string(),
            ));
        }

        // Check encryption transform consistency
        if has_encryption && !order.transforms.contains(&TransformType::Encryption) {
            return Err(ManifestError::TransformOrderViolation(
                "encryption policy specified but encryption transform not in order".to_string(),
            ));
        }

        if !has_encryption && order.transforms.contains(&TransformType::Encryption) {
            return Err(ManifestError::TransformOrderViolation(
                "encryption transform in order but no encryption policy".to_string(),
            ));
        }

        // Validate standard transform ordering (compression before encryption)
        if let (Some(comp_pos), Some(enc_pos)) = (
            order
                .transforms
                .iter()
                .position(|&t| t == TransformType::Compression),
            order
                .transforms
                .iter()
                .position(|&t| t == TransformType::Encryption),
        ) {
            if comp_pos >= enc_pos {
                return Err(ManifestError::TransformOrderViolation(
                    "compression must come before encryption in transform order".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Validate verification boundary specifications.
    fn validate_verification_boundary(
        transform_order: Option<&TransformOrder>,
        _proof_policy: &TransformProofPolicy,
    ) -> Result<(), ManifestError> {
        if let Some(order) = transform_order {
            let boundary = &order.verification_boundary;

            // Check for ambiguous verification modes
            if boundary.relay_verifiable == VerificationLevel::ContentHash
                && order.transforms.contains(&TransformType::Encryption)
                && order.hash_point == HashPoint::Ciphertext
            {
                return Err(ManifestError::AmbiguousVerificationMode(
                    "relay cannot verify content hash of encrypted content".to_string(),
                ));
            }

            // Validate privacy protection consistency
            if boundary.privacy_level == PrivacyLevel::Public
                && order.transforms.contains(&TransformType::Encryption)
            {
                return Err(ManifestError::PrivacyPolicyViolation(
                    "public privacy level inconsistent with encryption".to_string(),
                ));
            }

            // Check for privacy downgrade protection
            if boundary.relay_verifiable == VerificationLevel::FullVerification
                && boundary.privacy_level != PrivacyLevel::Public
            {
                return Err(ManifestError::PrivacyPolicyViolation(
                    "full relay verification requires public privacy level".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Validate lossy transforms are properly disclosed.
    fn validate_lossy_transforms_disclosure(
        compression_policy: Option<&CompressionPolicy>,
        proof_policy: &TransformProofPolicy,
    ) -> Result<(), ManifestError> {
        if let Some(comp) = compression_policy {
            let is_lossy = matches!(comp.algorithm, CompressionAlgorithm::Brotli); // Example of potentially lossy

            if is_lossy && !proof_policy.allow_lossy_transforms {
                return Err(ManifestError::LossyTransformNotAllowed(
                    "lossy compression used but not allowed by proof policy".to_string(),
                ));
            }

            // Check compression ratio bounds
            if let Some(_max_ratio) = proof_policy.max_compression_ratio {
                // We'd need compression metadata to validate actual ratio
                // This is a policy check that would be enforced during compression
            }
        }

        Ok(())
    }

    /// Validate encryption domains and privacy requirements.
    fn validate_encryption_domains(
        encryption_policy: Option<&EncryptionPolicy>,
        proof_policy: &TransformProofPolicy,
    ) -> Result<(), ManifestError> {
        if let Some(enc) = encryption_policy {
            // Check that encryption algorithm is allowed in domains
            let allowed = proof_policy
                .encryption_domains
                .iter()
                .any(|domain| domain.allowed_kdfs.contains(&enc.key_derivation.kdf));

            if !proof_policy.encryption_domains.is_empty() && !allowed {
                return Err(ManifestError::EncryptionDomainViolation(
                    "encryption KDF not allowed in any specified domain".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Validate plaintext hash availability requirements.
    fn validate_plaintext_hash_availability(
        transform_order: Option<&TransformOrder>,
    ) -> Result<(), ManifestError> {
        if let Some(order) = transform_order {
            if order.hash_point == HashPoint::Ciphertext
                && order.transforms.contains(&TransformType::Encryption)
            {
                return Err(ManifestError::PlaintextHashUnavailable(
                    "plaintext hash required but only ciphertext hash computed".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Validate transform order semantic consistency.
    fn validate_transform_order_semantics(order: &TransformOrder) -> Result<(), ManifestError> {
        // Error correction must come after chunking if both are present
        if let (Some(chunk_pos), Some(ec_pos)) = (
            order
                .transforms
                .iter()
                .position(|&t| t == TransformType::Chunking),
            order
                .transforms
                .iter()
                .position(|&t| t == TransformType::ErrorCorrection),
        ) {
            if chunk_pos >= ec_pos {
                return Err(ManifestError::TransformOrderViolation(
                    "chunking must come before error correction".to_string(),
                ));
            }
        }

        // Validate hash point consistency with transforms
        match order.hash_point {
            HashPoint::Plaintext => {
                // Valid in all cases
            }
            HashPoint::PostCompression => {
                if !order.transforms.contains(&TransformType::Compression) {
                    return Err(ManifestError::TransformOrderViolation(
                        "post-compression hash point requires compression transform".to_string(),
                    ));
                }
            }
            HashPoint::Ciphertext => {
                if !order.transforms.contains(&TransformType::Encryption) {
                    return Err(ManifestError::TransformOrderViolation(
                        "ciphertext hash point requires encryption transform".to_string(),
                    ));
                }
            }
            HashPoint::MultiPoint => {
                // Valid if multiple transforms are present
                if order.transforms.len() < 2 {
                    return Err(ManifestError::TransformOrderViolation(
                        "multi-point hashing requires multiple transforms".to_string(),
                    ));
                }
            }
        }

        Ok(())
    }

    /// Validate repair groups for ATP-G2 requirements.
    fn validate_repair_groups(&self) -> Result<(), ManifestError> {
        // Validate each repair group individually
        for repair_group in self.repair_groups.values() {
            self.validate_repair_group(repair_group)?;
        }

        // Validate repair group symbol references
        for manifest_obj in self.objects.values() {
            for symbol in &manifest_obj.raptorq_symbols {
                if let Some(group_id) = &symbol.repair_group_id {
                    // Verify repair group exists
                    if !self.repair_groups.contains_key(group_id) {
                        return Err(ManifestError::RepairGroupReferenceError(format!(
                            "symbol references non-existent repair group: {group_id}"
                        )));
                    }

                    // Verify symbol belongs to correct object
                    let repair_group = &self.repair_groups[group_id];
                    if repair_group.object_id != manifest_obj.id {
                        return Err(ManifestError::RepairGroupReferenceError(format!(
                            "symbol in object {} references repair group for object {}",
                            manifest_obj.id, repair_group.object_id
                        )));
                    }

                    let Some(auth_tag) = symbol.auth_tag else {
                        return Err(ManifestError::RepairGroupAuthenticationError(format!(
                            "repair symbol missing authentication tag: group {group_id}"
                        )));
                    };
                    let expected_tag = Self::compute_repair_symbol_auth_tag(repair_group, symbol);
                    if auth_tag != expected_tag {
                        return Err(ManifestError::RepairGroupAuthenticationError(format!(
                            "repair symbol authentication tag mismatch: group {group_id}, symbol {}",
                            symbol.index
                        )));
                    }
                }
            }
        }

        // Validate repair group consistency with RaptorQ layout
        if let Some(layout) = &self.raptorq_layout {
            for repair_group in self.repair_groups.values() {
                self.validate_repair_group_layout_consistency(repair_group, layout)?;
            }
        }

        Ok(())
    }

    /// Validate individual repair group for ATP-G2 requirements.
    fn validate_repair_group(&self, repair_group: &RepairGroup) -> Result<(), ManifestError> {
        // Validate group ID matches computed value
        let expected_id = RepairGroupId::new(
            &repair_group.object_id,
            repair_group.source_block_number,
            repair_group.k_prime,
        );
        if repair_group.group_id != expected_id {
            return Err(ManifestError::RepairGroupValidationError(format!(
                "repair group ID mismatch: expected {expected_id}, got {}",
                repair_group.group_id
            )));
        }

        // Validate object exists in manifest
        if !self.objects.contains_key(&repair_group.object_id) {
            return Err(ManifestError::RepairGroupValidationError(format!(
                "repair group references non-existent object: {}",
                repair_group.object_id
            )));
        }

        // Validate K' >= K (extended source symbols)
        if repair_group.k_prime < repair_group.source_symbols_k {
            return Err(ManifestError::RepairGroupValidationError(format!(
                "k_prime ({}) must be >= source_symbols_k ({}) for group {}",
                repair_group.k_prime, repair_group.source_symbols_k, repair_group.group_id
            )));
        }

        // Validate symbol size is non-zero
        if repair_group.symbol_size == 0 {
            return Err(ManifestError::RepairGroupValidationError(format!(
                "symbol_size cannot be zero for group {}",
                repair_group.group_id
            )));
        }

        // Validate chunk range consistency
        if repair_group.chunk_range.end_chunk <= repair_group.chunk_range.start_chunk {
            return Err(ManifestError::RepairGroupValidationError(format!(
                "invalid chunk range for group {}: end <= start",
                repair_group.group_id
            )));
        }

        if repair_group.chunk_range.end_offset <= repair_group.chunk_range.start_offset {
            return Err(ManifestError::RepairGroupValidationError(format!(
                "invalid byte range for group {}: end <= start",
                repair_group.group_id
            )));
        }

        // Validate repair layout
        if repair_group.repair_layout.total_repair_symbols == 0 {
            return Err(ManifestError::RepairGroupValidationError(format!(
                "total_repair_symbols cannot be zero for group {}",
                repair_group.group_id
            )));
        }

        if repair_group.repair_layout.overhead_ratio < 0.0
            || repair_group.repair_layout.overhead_ratio > 10.0
        {
            return Err(ManifestError::RepairGroupValidationError(format!(
                "overhead_ratio ({}) out of range [0.0, 10.0] for group {}",
                repair_group.repair_layout.overhead_ratio, repair_group.group_id
            )));
        }

        // Validate systematic encoding parameters
        if repair_group.repair_layout.systematic_config.systematic_rows == 0 {
            return Err(ManifestError::RepairGroupValidationError(format!(
                "systematic_rows cannot be zero for group {}",
                repair_group.group_id
            )));
        }

        // Validate authentication domain
        if repair_group.auth_domain.domain_id.is_empty() {
            return Err(ManifestError::RepairGroupValidationError(format!(
                "authentication domain_id cannot be empty for group {}",
                repair_group.group_id
            )));
        }

        // Validate manifest root binding
        if repair_group.manifest_root != self.merkle_root {
            return Err(ManifestError::RepairGroupValidationError(format!(
                "repair group manifest_root mismatch for group {}: expected {}, got {}",
                repair_group.group_id, self.merkle_root, repair_group.manifest_root
            )));
        }

        Ok(())
    }

    /// Validate repair group consistency with RaptorQ layout.
    fn validate_repair_group_layout_consistency(
        &self,
        repair_group: &RepairGroup,
        layout: &RaptorQRepairLayout,
    ) -> Result<(), ManifestError> {
        // Verify symbol size matches layout
        if repair_group.symbol_size != layout.symbol_size {
            return Err(ManifestError::RepairGroupValidationError(format!(
                "repair group symbol_size ({}) does not match layout symbol_size ({}) for group {}",
                repair_group.symbol_size, layout.symbol_size, repair_group.group_id
            )));
        }

        // Verify K is within layout bounds
        if repair_group.source_symbols_k > layout.source_symbols {
            return Err(ManifestError::RepairGroupValidationError(format!(
                "repair group source_symbols_k ({}) exceeds layout source_symbols ({}) for group {}",
                repair_group.source_symbols_k, layout.source_symbols, repair_group.group_id
            )));
        }

        // Verify total repair symbols is reasonable
        if repair_group.repair_layout.total_repair_symbols > layout.total_symbols {
            return Err(ManifestError::RepairGroupValidationError(format!(
                "repair group total_repair_symbols ({}) exceeds layout total_symbols ({}) for group {}",
                repair_group.repair_layout.total_repair_symbols,
                layout.total_symbols,
                repair_group.group_id
            )));
        }

        Ok(())
    }

    /// Get the total number of objects in the manifest.
    #[must_use]
    pub fn object_count(&self) -> usize {
        self.objects.len()
    }

    /// Check if the manifest is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }

    /// Serialize manifest to canonical bytes for storage/transmission.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Canonical header with magic number and version
        bytes.extend_from_slice(b"ATPM"); // ATP Manifest magic
        bytes.extend_from_slice(&self.version.0.to_be_bytes());
        bytes.extend_from_slice(&self.created_timestamp_nanos.to_be_bytes());

        // Schema ID
        Self::write_string(&mut bytes, &self.schema_id);

        // Merkle root
        bytes.extend_from_slice(self.merkle_root.hash());

        // Hash algorithms
        bytes.extend_from_slice(
            &u32::try_from(self.hash_algorithms.len())
                .expect("length exceeds u32 limit")
                .to_be_bytes(),
        );
        for algo in &self.hash_algorithms {
            bytes.push(*algo as u8);
        }

        // Root object IDs
        bytes.extend_from_slice(
            &u32::try_from(self.roots.len())
                .expect("length exceeds u32 limit")
                .to_be_bytes(),
        );
        for root in &self.roots {
            bytes.extend_from_slice(root.hash_bytes());
        }

        // Objects in deterministic order
        bytes.extend_from_slice(
            &u32::try_from(self.objects.len())
                .expect("length exceeds u32 limit")
                .to_be_bytes(),
        );
        for (id, obj) in &self.objects {
            // Object ID and basic metadata
            bytes.extend_from_slice(id.hash_bytes());
            bytes.push(obj.kind as u8);

            // Size
            if let Some(size) = obj.size_bytes {
                bytes.push(1);
                bytes.extend_from_slice(&size.to_be_bytes());
            } else {
                bytes.push(0);
            }

            // Content hash
            if let Some(hash) = &obj.content_hash {
                bytes.push(1);
                bytes.extend_from_slice(hash);
            } else {
                bytes.push(0);
            }

            // Children in sorted order
            bytes.extend_from_slice(
                &u32::try_from(obj.children.len())
                    .expect("length exceeds u32 limit")
                    .to_be_bytes(),
            );
            for (name, child_id) in &obj.children {
                Self::write_string(&mut bytes, name);
                bytes.extend_from_slice(child_id.hash_bytes());
            }

            // Chunk boundaries
            bytes.extend_from_slice(
                &u32::try_from(obj.chunk_boundaries.len())
                    .expect("length exceeds u32 limit")
                    .to_be_bytes(),
            );
            for chunk in &obj.chunk_boundaries {
                bytes.extend_from_slice(&chunk.index.to_be_bytes());
                bytes.extend_from_slice(&chunk.byte_offset.to_be_bytes());
                bytes.extend_from_slice(&chunk.size_bytes.to_be_bytes());
                bytes.extend_from_slice(&chunk.content_hash);
                bytes.push(chunk.strategy as u8);
            }

            // RaptorQ symbols
            bytes.extend_from_slice(
                &u32::try_from(obj.raptorq_symbols.len())
                    .expect("length exceeds u32 limit")
                    .to_be_bytes(),
            );
            for symbol in &obj.raptorq_symbols {
                bytes.extend_from_slice(&symbol.index.to_be_bytes());
                bytes.extend_from_slice(&symbol.esi.to_be_bytes());
                bytes.extend_from_slice(&symbol.size_bytes.to_be_bytes());
                bytes.extend_from_slice(&symbol.content_hash);
                bytes.push(u8::from(symbol.is_source));
            }
        }

        // Chunk plan
        if let Some(plan) = &self.chunk_plan {
            bytes.push(1); // Present flag
            bytes.push(plan.strategy as u8);
            bytes.extend_from_slice(&plan.target_chunk_size.to_be_bytes());
            bytes.extend_from_slice(&plan.min_chunk_size.to_be_bytes());
            bytes.extend_from_slice(&plan.max_chunk_size.to_be_bytes());

            if let Some(cdc) = &plan.cdc_params {
                bytes.push(1);
                bytes.extend_from_slice(&cdc.window_size.to_be_bytes());
                bytes.extend_from_slice(&cdc.average_chunk_size.to_be_bytes());
                bytes.extend_from_slice(&cdc.normalization.to_be_bytes());
            } else {
                bytes.push(0);
            }
        } else {
            bytes.push(0); // Not present flag
        }

        // RaptorQ layout
        if let Some(layout) = &self.raptorq_layout {
            bytes.push(1);
            bytes.extend_from_slice(&layout.source_symbols.to_be_bytes());
            bytes.extend_from_slice(&layout.total_symbols.to_be_bytes());
            bytes.extend_from_slice(&layout.symbol_size.to_be_bytes());
            bytes.extend_from_slice(&deterministic_f32_be_bytes(layout.overhead_ratio));

            bytes.extend_from_slice(
                &u32::try_from(layout.sub_blocks.len())
                    .expect("length exceeds u32 limit")
                    .to_be_bytes(),
            );
            for sub_block in &layout.sub_blocks {
                bytes.extend_from_slice(&sub_block.index.to_be_bytes());
                bytes.extend_from_slice(&sub_block.source_symbols.to_be_bytes());
                bytes.extend_from_slice(&sub_block.esi_range.0.to_be_bytes());
                bytes.extend_from_slice(&sub_block.esi_range.1.to_be_bytes());
            }
        } else {
            bytes.push(0);
        }

        // Compression policy
        if let Some(comp) = &self.compression_policy {
            bytes.push(1);
            bytes.push(comp.algorithm as u8);
            bytes.push(comp.level);
            bytes.extend_from_slice(&comp.min_size_threshold.to_be_bytes());
            bytes.extend_from_slice(
                &u32::try_from(comp.apply_to_kinds.len())
                    .expect("length exceeds u32 limit")
                    .to_be_bytes(),
            );
            for kind in &comp.apply_to_kinds {
                bytes.push(*kind as u8);
            }
        } else {
            bytes.push(0);
        }

        // Encryption policy
        if let Some(enc) = &self.encryption_policy {
            bytes.push(1);
            bytes.push(enc.algorithm as u8);
            bytes.push(enc.key_derivation.kdf as u8);
            Self::write_bytes(&mut bytes, &enc.key_derivation.salt);
            if let Some(iterations) = enc.key_derivation.iterations {
                bytes.push(1);
                bytes.extend_from_slice(&iterations.to_be_bytes());
            } else {
                bytes.push(0);
            }
            bytes.push(u8::from(enc.encrypt_metadata));
            bytes.extend_from_slice(
                &u32::try_from(enc.apply_to_kinds.len())
                    .expect("length exceeds u32 limit")
                    .to_be_bytes(),
            );
            for kind in &enc.apply_to_kinds {
                bytes.push(*kind as u8);
            }
        } else {
            bytes.push(0);
        }

        // Capability policy
        if let Some(cap) = &self.capability_policy {
            bytes.push(1);
            Self::write_string_vec(&mut bytes, &cap.read_capabilities);
            Self::write_string_vec(&mut bytes, &cap.write_capabilities);
            Self::write_string_vec(&mut bytes, &cap.verify_capabilities);
        } else {
            bytes.push(0);
        }

        bytes
    }

    fn write_string(bytes: &mut Vec<u8>, s: &str) {
        bytes.extend_from_slice(
            &u32::try_from(s.len())
                .expect("length exceeds u32 limit")
                .to_be_bytes(),
        );
        bytes.extend_from_slice(s.as_bytes());
    }

    fn write_bytes(bytes: &mut Vec<u8>, data: &[u8]) {
        bytes.extend_from_slice(
            &u32::try_from(data.len())
                .expect("length exceeds u32 limit")
                .to_be_bytes(),
        );
        bytes.extend_from_slice(data);
    }

    fn write_string_vec(bytes: &mut Vec<u8>, strings: &[String]) {
        bytes.extend_from_slice(
            &u32::try_from(strings.len())
                .expect("length exceeds u32 limit")
                .to_be_bytes(),
        );
        for s in strings {
            Self::write_string(bytes, s);
        }
    }

    /// Compute chunk boundaries for an object based on chunk plan.
    fn compute_chunk_boundaries(
        chunk_plan: Option<&ChunkPlan>,
        object: &crate::atp::object::Object,
        _content_hash: Option<&[u8; 32]>,
    ) -> Vec<ChunkBoundary> {
        let Some(plan) = chunk_plan else {
            return Vec::new();
        };
        let Some(size) = object.metadata.size_bytes else {
            return Vec::new();
        };

        if size < plan.min_chunk_size {
            return Vec::new();
        }

        let chunk_size = plan
            .cdc_params
            .as_ref()
            .map_or(plan.target_chunk_size, |cdc| cdc.average_chunk_size);

        let mut boundaries = Vec::new();
        let mut offset = 0u64;
        let mut index = 0u32;

        while offset < size {
            let chunk_end = std::cmp::min(offset + chunk_size, size);

            // Compute real content hash from actual chunk data
            let content_hash = if let Some(ref content) = object.content {
                let chunk_start = offset as usize;
                let chunk_end_usize = chunk_end as usize;
                if chunk_end_usize <= content.len() {
                    let chunk_data = &content[chunk_start..chunk_end_usize];
                    let mut hasher = Sha256::new();
                    hasher.update(chunk_data);
                    let result = hasher.finalize();
                    result.into()
                } else {
                    [0u8; 32] // Fallback if chunk exceeds content length
                }
            } else {
                [0u8; 32] // Fallback if no content available
            };

            boundaries.push(ChunkBoundary {
                index,
                byte_offset: offset,
                size_bytes: chunk_end - offset,
                content_hash,
                strategy: ChunkStrategy::FixedSize,
                metadata: None,
            });
            offset = chunk_end;
            index += 1;
        }

        boundaries
    }

    /// Compute RaptorQ symbols for an object based on repair layout.
    fn compute_raptorq_symbols(
        raptorq_layout: Option<&RaptorQRepairLayout>,
        object: &crate::atp::object::Object,
        content_hash: Option<&[u8; 32]>,
    ) -> Vec<RaptorQSymbol> {
        let Some(layout) = raptorq_layout else {
            return Vec::new();
        };
        let Some(content_hash) = content_hash else {
            return Vec::new();
        };
        let Some(size) = object.metadata.size_bytes else {
            return Vec::new();
        };

        let symbol_size = layout.symbol_size.max(1);
        let symbol_size_u64 = u64::from(symbol_size);
        let num_symbols = size.div_ceil(symbol_size_u64) as u32;
        let group_id = RepairGroupId::new(&object.id, 0, num_symbols);

        let mut symbols = Vec::new();
        for i in 0..num_symbols {
            let symbol_hash = if let Some(ref content) = object.content {
                // Symbol count derives from declared size_bytes, which may
                // exceed the actual content length; guard the start offset so
                // a mismatch cannot produce an inverted slice range.
                let symbol_start_u64 = u64::from(i) * symbol_size_u64;
                if symbol_start_u64 < content.len() as u64 {
                    let symbol_start = symbol_start_u64 as usize;
                    let symbol_end =
                        std::cmp::min(symbol_start + symbol_size as usize, content.len());
                    let symbol_data = &content[symbol_start..symbol_end];
                    let mut hasher = Sha256::new();
                    hasher.update(symbol_data);
                    let result = hasher.finalize();
                    result.into()
                } else {
                    *content_hash // Fallback if symbol lies beyond the content
                }
            } else {
                *content_hash // Fallback if no content available
            };

            symbols.push(RaptorQSymbol {
                index: i,
                esi: i, // Encoding Symbol ID matches index for systematic symbols
                size_bytes: symbol_size,
                content_hash: symbol_hash,
                is_source: true, // These are systematic source symbols
                repair_group_id: Some(group_id.clone()),
                auth_tag: None,
            });
        }

        symbols
    }

    fn compute_repair_groups(
        raptorq_layout: Option<&RaptorQRepairLayout>,
        objects: &BTreeMap<ObjectId, ManifestObject>,
        manifest_root: MerkleRoot,
    ) -> BTreeMap<RepairGroupId, RepairGroup> {
        let Some(layout) = raptorq_layout else {
            return BTreeMap::new();
        };

        let mut repair_groups = BTreeMap::new();
        for object in objects.values() {
            let Some(first_symbol) = object.raptorq_symbols.first() else {
                continue;
            };
            let Some(group_id) = first_symbol.repair_group_id.clone() else {
                continue;
            };
            let source_symbols_k = object.raptorq_symbols.len() as u32;
            if source_symbols_k == 0 {
                continue;
            }
            let total_repair_symbols = layout.total_symbols.saturating_sub(layout.source_symbols);
            let object_size = object.size_bytes.unwrap_or(0);
            repair_groups.insert(
                group_id.clone(),
                RepairGroup {
                    group_id,
                    object_id: object.id.clone(),
                    source_block_number: 0,
                    chunk_range: ChunkRange {
                        start_chunk: 0,
                        end_chunk: source_symbols_k,
                        start_offset: 0,
                        end_offset: object_size,
                    },
                    source_symbols_k,
                    k_prime: source_symbols_k,
                    symbol_size: layout.symbol_size.max(1),
                    repair_layout: RepairLayout {
                        total_repair_symbols: total_repair_symbols.max(1),
                        overhead_ratio: layout.overhead_ratio,
                        systematic_config: SystematicConfig {
                            systematic_rows: source_symbols_k,
                            sub_symbols: 1,
                            alignment: 8,
                        },
                        interleaving: InterleavingPattern {
                            block_size: source_symbols_k.max(1),
                            depth: 1,
                            pattern_type: InterleavingType::None,
                        },
                    },
                    hash_domain: HashDomain {
                        domain_id: "atp-g2-symbol-sha256-v1".to_string(),
                        hash_algorithm: HashAlgorithm::Sha256,
                        context: object.id.hash_bytes().to_vec(),
                    },
                    transform_policy: None,
                    auth_domain: AuthenticationDomain {
                        domain_id: "atp-g2-symbol-auth-v1".to_string(),
                        required_proof_strength: ProofStrength::Basic,
                        auth_algorithm: AuthenticationAlgorithm::HmacSha256,
                        peer_identity_required: false,
                        transfer_identity_binding: true,
                        session_binding: true,
                    },
                    capability_policy: None,
                    manifest_root: manifest_root.clone(),
                },
            );
        }

        repair_groups
    }

    fn bind_repair_symbol_auth_tags(
        objects: &mut BTreeMap<ObjectId, ManifestObject>,
        repair_groups: &BTreeMap<RepairGroupId, RepairGroup>,
    ) {
        for object in objects.values_mut() {
            for symbol in &mut object.raptorq_symbols {
                let Some(group_id) = &symbol.repair_group_id else {
                    continue;
                };
                if let Some(repair_group) = repair_groups.get(group_id) {
                    symbol.auth_tag =
                        Some(Self::compute_repair_symbol_auth_tag(repair_group, symbol));
                }
            }
        }
    }

    fn compute_repair_symbol_auth_tag(
        repair_group: &RepairGroup,
        symbol: &RaptorQSymbol,
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"ATP-G2-RepairSymbolAuth-v1");
        hasher.update(repair_group.group_id.as_bytes());
        hasher.update(repair_group.object_id.hash_bytes());
        hasher.update(repair_group.source_block_number.to_be_bytes());
        hasher.update(repair_group.k_prime.to_be_bytes());
        hasher.update(repair_group.symbol_size.to_be_bytes());
        hasher.update(repair_group.manifest_root.hash());
        hasher.update(repair_group.auth_domain.domain_id.as_bytes());
        hasher.update([repair_group.auth_domain.auth_algorithm as u8]);
        hasher.update(symbol.index.to_be_bytes());
        hasher.update(symbol.esi.to_be_bytes());
        hasher.update(symbol.size_bytes.to_be_bytes());
        hasher.update(symbol.content_hash);
        hasher.update([u8::from(symbol.is_source)]);
        hasher.finalize().into()
    }

    /// Compute compression metadata for an object based on compression policy.
    fn compute_compression_metadata(
        compression_policy: Option<&CompressionPolicy>,
        object: &crate::atp::object::Object,
    ) -> Option<CompressionMetadata> {
        let policy = compression_policy?;
        let size = object.metadata.size_bytes?;

        // Check if compression should be applied
        if size < policy.min_size_threshold {
            return None;
        }

        if size == 0 {
            return None;
        }

        if !policy.apply_to_kinds.contains(&object.metadata.kind) {
            return None;
        }

        let content = object.content.as_deref()?;
        if content.len() as u64 != size {
            return None;
        }

        let compressed_len = Self::compressed_len_for_policy(policy, content)?;
        Some(CompressionMetadata {
            algorithm: policy.algorithm,
            level: policy.level,
            original_size: size,
            compressed_size: compressed_len as u64,
            compression_ratio: compressed_len as f32 / size as f32,
        })
    }

    fn compressed_len_for_policy(policy: &CompressionPolicy, content: &[u8]) -> Option<usize> {
        match policy.algorithm {
            CompressionAlgorithm::None => None,
            CompressionAlgorithm::Lz4 => Self::lz4_compressed_len(content),
            CompressionAlgorithm::Gzip => Self::gzip_compressed_len(content, policy.level),
            CompressionAlgorithm::Brotli => Self::brotli_compressed_len(content, policy.level),
        }
    }

    #[cfg(feature = "trace-compression")]
    fn lz4_compressed_len(content: &[u8]) -> Option<usize> {
        Some(lz4_flex::compress_prepend_size(content).len())
    }

    #[cfg(not(feature = "trace-compression"))]
    fn lz4_compressed_len(_content: &[u8]) -> Option<usize> {
        None
    }

    #[cfg(feature = "compression")]
    fn gzip_compressed_len(content: &[u8], level: u8) -> Option<usize> {
        use flate2::{Compression, write::GzEncoder};
        use std::io::Write;

        let mut encoder = GzEncoder::new(Vec::new(), Compression::new(u32::from(level.min(9))));
        encoder.write_all(content).ok()?;
        Some(encoder.finish().ok()?.len())
    }

    #[cfg(not(feature = "compression"))]
    fn gzip_compressed_len(_content: &[u8], _level: u8) -> Option<usize> {
        None
    }

    #[cfg(feature = "compression")]
    fn brotli_compressed_len(content: &[u8], level: u8) -> Option<usize> {
        use std::io::Write;

        let mut encoder =
            brotli::CompressorWriter::new(Vec::new(), 4096, u32::from(level.min(11)), 22);
        encoder.write_all(content).ok()?;
        encoder.flush().ok()?;
        Some(encoder.into_inner().len())
    }

    #[cfg(not(feature = "compression"))]
    fn brotli_compressed_len(_content: &[u8], _level: u8) -> Option<usize> {
        None
    }

    /// Compute encryption metadata for an object based on encryption policy.
    fn compute_encryption_metadata(
        encryption_policy: Option<&EncryptionPolicy>,
        object: &crate::atp::object::Object,
    ) -> Option<EncryptionMetadata> {
        let policy = encryption_policy?;

        // Check if encryption should be applied
        if !policy.apply_to_kinds.contains(&object.metadata.kind) {
            return None;
        }

        match policy.algorithm {
            EncryptionAlgorithm::None => None,
            EncryptionAlgorithm::ChaCha20Poly1305 | EncryptionAlgorithm::Aes256Gcm => {
                Some(Self::derive_encryption_metadata(policy, object))
            }
        }
    }

    fn derive_encryption_metadata(
        policy: &EncryptionPolicy,
        object: &crate::atp::object::Object,
    ) -> EncryptionMetadata {
        let mut iv_hasher = Sha256::new();
        iv_hasher.update(b"ATP-C4-EncryptionNonce-v1");
        iv_hasher.update(object.id.hash_bytes());
        iv_hasher.update([policy.algorithm as u8]);
        iv_hasher.update([policy.key_derivation.kdf as u8]);
        iv_hasher.update(&policy.key_derivation.salt);
        let iv_digest: [u8; 32] = iv_hasher.finalize().into();
        let iv = iv_digest[..12].to_vec();

        let mut tag_hasher = Sha256::new();
        tag_hasher.update(b"ATP-C4-EncryptionMetadataTag-v1");
        tag_hasher.update(object.id.hash_bytes());
        tag_hasher.update([policy.algorithm as u8]);
        tag_hasher.update([policy.key_derivation.kdf as u8]);
        tag_hasher.update(&policy.key_derivation.salt);
        tag_hasher.update(&iv);
        if let Some(content) = &object.content {
            tag_hasher.update(Sha256::digest(content));
        }
        let auth_digest: [u8; 32] = tag_hasher.finalize().into();

        EncryptionMetadata {
            algorithm: policy.algorithm,
            iv,
            auth_tag: auth_digest[..16].to_vec(),
            key_derivation: policy.key_derivation.clone(),
        }
    }
}

/// Errors in manifest operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    /// Unsupported manifest version.
    UnsupportedVersion(ManifestVersion),
    /// Root object referenced but not found in objects.
    RootObjectMissing(ObjectId),
    /// Child object referenced but not found in objects.
    ChildObjectMissing(ObjectId),
    /// Invalid manifest format.
    InvalidFormat(String),
    /// Merkle root verification failed.
    MerkleRootMismatch {
        /// Expected Merkle root from the manifest.
        expected: MerkleRoot,
        /// Merkle root computed from the graph.
        computed: MerkleRoot,
    },
    /// Unknown critical field encountered - validation fails closed.
    UnknownCriticalField(String),
    /// Capability policy violation.
    CapabilityPolicyViolation(String),
    /// Chunk plan validation failed.
    ChunkPlanError(String),
    /// RaptorQ layout validation failed.
    RaptorQLayoutError(String),
    /// Compression policy validation failed.
    CompressionPolicyError(String),
    /// Encryption policy validation failed.
    EncryptionPolicyError(String),
    /// Transform policy validation failed.
    TransformPolicyViolation(String),
    /// Transform order validation failed.
    TransformOrderViolation(String),
    /// Ambiguous verification mode detected.
    AmbiguousVerificationMode(String),
    /// Privacy policy violation.
    PrivacyPolicyViolation(String),
    /// Lossy transform not allowed by policy.
    LossyTransformNotAllowed(String),
    /// Encryption domain policy violation.
    EncryptionDomainViolation(String),
    /// Plaintext hash unavailable when required.
    PlaintextHashUnavailable(String),
    /// Repair group validation failed.
    RepairGroupValidationError(String),
    /// Repair group reference error.
    RepairGroupReferenceError(String),
    /// Repair group authentication error.
    RepairGroupAuthenticationError(String),
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported manifest version: {}", version.0)
            }
            Self::RootObjectMissing(id) => {
                write!(f, "root object missing: {id}")
            }
            Self::ChildObjectMissing(id) => {
                write!(f, "child object missing: {id}")
            }
            Self::InvalidFormat(msg) => {
                write!(f, "invalid manifest format: {msg}")
            }
            Self::MerkleRootMismatch { expected, computed } => {
                write!(
                    f,
                    "merkle root mismatch: expected {expected}, computed {computed}"
                )
            }
            Self::UnknownCriticalField(field) => {
                write!(
                    f,
                    "unknown critical field: {field} (validation fails closed)"
                )
            }
            Self::CapabilityPolicyViolation(msg) => {
                write!(f, "capability policy violation: {msg}")
            }
            Self::ChunkPlanError(msg) => {
                write!(f, "chunk plan error: {msg}")
            }
            Self::RaptorQLayoutError(msg) => {
                write!(f, "RaptorQ layout error: {msg}")
            }
            Self::CompressionPolicyError(msg) => {
                write!(f, "compression policy error: {msg}")
            }
            Self::EncryptionPolicyError(msg) => {
                write!(f, "encryption policy error: {msg}")
            }
            Self::TransformPolicyViolation(msg) => {
                write!(f, "transform policy violation: {msg}")
            }
            Self::TransformOrderViolation(msg) => {
                write!(f, "transform order violation: {msg}")
            }
            Self::AmbiguousVerificationMode(msg) => {
                write!(f, "ambiguous verification mode: {msg}")
            }
            Self::PrivacyPolicyViolation(msg) => {
                write!(f, "privacy policy violation: {msg}")
            }
            Self::LossyTransformNotAllowed(msg) => {
                write!(f, "lossy transform not allowed: {msg}")
            }
            Self::EncryptionDomainViolation(msg) => {
                write!(f, "encryption domain violation: {msg}")
            }
            Self::PlaintextHashUnavailable(msg) => {
                write!(f, "plaintext hash unavailable: {msg}")
            }
            Self::RepairGroupValidationError(msg) => {
                write!(f, "repair group validation error: {msg}")
            }
            Self::RepairGroupReferenceError(msg) => {
                write!(f, "repair group reference error: {msg}")
            }
            Self::RepairGroupAuthenticationError(msg) => {
                write!(f, "repair group authentication error: {msg}")
            }
        }
    }
}

impl std::error::Error for ManifestError {}

/// Graph commit semantics for atomic updates.
#[derive(Debug, Clone, PartialEq)]
pub struct GraphCommit {
    /// Commit identifier.
    pub id: CommitId,
    /// Parent commit (for versioning).
    pub parent: Option<CommitId>,
    /// Manifest being committed.
    pub manifest: Manifest,
    /// Commit metadata.
    pub metadata: CommitMetadata,
}

/// Unique identifier for a graph commit.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CommitId {
    hash: [u8; 32],
}

impl CommitId {
    /// Create from hash.
    #[must_use]
    pub const fn new(hash: [u8; 32]) -> Self {
        Self { hash }
    }

    /// Get hash bytes.
    #[must_use]
    pub const fn hash(&self) -> &[u8; 32] {
        &self.hash
    }

    /// Compute commit ID from manifest and metadata.
    #[must_use]
    pub fn from_commit(manifest: &Manifest, metadata: &CommitMetadata) -> Self {
        let mut hasher = Sha256::new();

        // Include manifest's canonical representation
        let manifest_bytes = manifest.to_canonical_bytes();
        hasher.update(&manifest_bytes);

        // Include commit metadata
        hasher.update(metadata.timestamp_nanos.to_be_bytes());
        hasher.update(metadata.author.as_bytes());
        hasher.update(metadata.message.as_bytes());

        Self {
            hash: hasher.finalize().into(),
        }
    }

    /// Format as hex string.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.hash)
    }
}

impl fmt::Display for CommitId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "commit:{}", &self.to_hex()[..16])
    }
}

/// Metadata for a graph commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitMetadata {
    /// Timestamp in nanoseconds since epoch.
    pub timestamp_nanos: u64,
    /// Author identifier.
    pub author: String,
    /// Commit message.
    pub message: String,
}

impl GraphCommit {
    /// Create a new commit.
    #[must_use]
    pub fn new(parent: Option<CommitId>, manifest: Manifest, metadata: CommitMetadata) -> Self {
        let id = CommitId::from_commit(&manifest, &metadata);
        Self {
            id,
            parent,
            manifest,
            metadata,
        }
    }

    /// Validate the commit.
    pub fn validate(&self) -> Result<(), ManifestError> {
        self.manifest.validate()?;

        // Verify commit ID
        let expected_id = CommitId::from_commit(&self.manifest, &self.metadata);
        if self.id != expected_id {
            return Err(ManifestError::InvalidFormat(
                "commit ID does not match content".to_string(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
#[path = "manifest_inline_tests.rs"]
mod tests;
