//! ATP ObjectGraph model and object kinds.
//!
//! ATP moves verified object graphs, not just files. This module defines the
//! type foundation for object identity, metadata policy, canonical ordering,
//! and graph commit semantics used by CLI, SDK, daemon, proofs, mailbox,
//! swarm, and dogfood components.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

const CONTENT_ID_DOMAIN: &[u8] = b"asupersync.atp.content-id.v1\0";
const MANIFEST_ID_DOMAIN: &[u8] = b"asupersync.atp.manifest-id.v1\0";
const STREAM_ID_DOMAIN: &[u8] = b"asupersync.atp.stream-id.v1\0";
static STREAM_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

fn domain_separated_sha256(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(payload);
    hasher.finalize().into()
}

/// Content-addressed object identifier using cryptographic hash.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ContentId {
    /// SHA-256 hash of the object's canonical content representation.
    hash: [u8; 32],
}

impl ContentId {
    /// Construct from a SHA-256 hash.
    #[must_use]
    pub const fn new(hash: [u8; 32]) -> Self {
        Self { hash }
    }

    /// Return the underlying hash bytes.
    #[must_use]
    pub const fn hash(&self) -> &[u8; 32] {
        &self.hash
    }

    /// Compute content id from canonical bytes.
    #[must_use]
    pub fn from_bytes(content: &[u8]) -> Self {
        Self {
            hash: domain_separated_sha256(CONTENT_ID_DOMAIN, content),
        }
    }

    /// Start an incremental [`ContentIdHasher`] for content streamed in chunks.
    ///
    /// Feeding the same total byte sequence through [`ContentIdHasher::update`]
    /// and finalizing yields exactly the same id as [`ContentId::from_bytes`]
    /// over the concatenation, but without ever holding the whole content in
    /// memory. Bounded-memory transports (e.g. ATP-over-TCP/QUIC) use this to
    /// compute object ids while streaming files chunk-by-chunk.
    #[must_use]
    pub fn streaming() -> ContentIdHasher {
        ContentIdHasher::new()
    }

    /// Format as hex string for debugging.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.hash)
    }
}

/// Incremental, domain-separated SHA-256 hasher that produces a [`ContentId`]
/// from chunked input. Equivalent to [`ContentId::from_bytes`] over the
/// concatenation of all `update` calls, with O(1) memory.
#[derive(Clone)]
pub struct ContentIdHasher {
    hasher: Sha256,
}

impl ContentIdHasher {
    /// Create a hasher pre-seeded with the content-id domain separator.
    #[must_use]
    pub fn new() -> Self {
        let mut hasher = Sha256::new();
        hasher.update(CONTENT_ID_DOMAIN);
        Self { hasher }
    }

    /// Absorb the next chunk of content.
    pub fn update(&mut self, chunk: &[u8]) {
        self.hasher.update(chunk);
    }

    /// Finalize into the content-addressed id.
    #[must_use]
    pub fn finalize(self) -> ContentId {
        ContentId {
            hash: self.hasher.finalize().into(),
        }
    }
}

impl Default for ContentIdHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ContentIdHasher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContentIdHasher").finish_non_exhaustive()
    }
}

impl fmt::Display for ContentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "content:{}", &self.to_hex()[..16])
    }
}

/// Manifest-addressed object identifier using deterministic manifest hash.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ManifestId {
    /// SHA-256 hash of the object's canonical manifest representation.
    hash: [u8; 32],
}

impl ManifestId {
    /// Construct from a SHA-256 hash.
    #[must_use]
    pub const fn new(hash: [u8; 32]) -> Self {
        Self { hash }
    }

    /// Return the underlying hash bytes.
    #[must_use]
    pub const fn hash(&self) -> &[u8; 32] {
        &self.hash
    }

    /// Compute manifest id from canonical manifest bytes.
    #[must_use]
    pub fn from_manifest_bytes(manifest: &[u8]) -> Self {
        Self {
            hash: domain_separated_sha256(MANIFEST_ID_DOMAIN, manifest),
        }
    }

    /// Format as hex string for debugging.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.hash)
    }
}

impl fmt::Display for ManifestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "manifest:{}", &self.to_hex()[..16])
    }
}

impl From<ContentId> for ManifestId {
    fn from(content_id: ContentId) -> Self {
        Self {
            hash: content_id.hash,
        }
    }
}

/// Object identifier that can be either content-addressed or manifest-addressed.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum ObjectId {
    /// Content-addressed object (immutable content).
    Content(ContentId),
    /// Manifest-addressed object (mutable streams, application-defined).
    Manifest(ManifestId),
}

impl ObjectId {
    /// Create a content-addressed object ID.
    #[must_use]
    pub const fn content(content_id: ContentId) -> Self {
        Self::Content(content_id)
    }

    /// Create a manifest-addressed object ID.
    #[must_use]
    pub const fn manifest(manifest_id: ManifestId) -> Self {
        Self::Manifest(manifest_id)
    }

    /// Whether this is a content-addressed object.
    #[must_use]
    pub const fn is_content_addressed(&self) -> bool {
        matches!(self, Self::Content(_))
    }

    /// Whether this is a manifest-addressed object.
    #[must_use]
    pub const fn is_manifest_addressed(&self) -> bool {
        matches!(self, Self::Manifest(_))
    }

    /// Return the underlying hash bytes.
    #[must_use]
    pub const fn hash_bytes(&self) -> &[u8; 32] {
        match self {
            Self::Content(content_id) => content_id.hash(),
            Self::Manifest(manifest_id) => manifest_id.hash(),
        }
    }

    /// Format as hex string for debugging and display.
    #[must_use]
    pub fn as_hex(&self) -> String {
        hex::encode(self.hash_bytes())
    }
}

impl fmt::Display for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Content(content_id) => write!(f, "{content_id}"),
            Self::Manifest(manifest_id) => write!(f, "{manifest_id}"),
        }
    }
}

/// Metadata policy for handling platform-specific vs portable metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataPolicy {
    /// Whether to preserve Unix permissions.
    pub preserve_unix_permissions: bool,
    /// Whether to preserve Windows attributes.
    pub preserve_windows_attributes: bool,
    /// Whether to preserve extended attributes (xattrs).
    pub preserve_extended_attributes: bool,
    /// Whether to preserve symbolic links.
    pub preserve_symlinks: bool,
    /// Whether to preserve timestamps.
    pub preserve_timestamps: bool,
    /// Whether to record platform-specific metadata in manifest.
    pub record_platform_metadata: bool,
    /// Whether to verify metadata integrity.
    pub verify_metadata: bool,
}

impl Default for MetadataPolicy {
    fn default() -> Self {
        Self {
            preserve_unix_permissions: true,
            preserve_windows_attributes: true,
            preserve_extended_attributes: false,
            preserve_symlinks: true,
            preserve_timestamps: false, // Portable by default
            record_platform_metadata: true,
            verify_metadata: true,
        }
    }
}

impl MetadataPolicy {
    /// Portable policy that only preserves cross-platform metadata.
    #[must_use]
    pub const fn portable() -> Self {
        Self {
            preserve_unix_permissions: false,
            preserve_windows_attributes: false,
            preserve_extended_attributes: false,
            preserve_symlinks: false,
            preserve_timestamps: false,
            record_platform_metadata: false,
            verify_metadata: true,
        }
    }

    /// Full preservation policy for maximum fidelity.
    #[must_use]
    pub const fn full_preservation() -> Self {
        Self {
            preserve_unix_permissions: true,
            preserve_windows_attributes: true,
            preserve_extended_attributes: true,
            preserve_symlinks: true,
            preserve_timestamps: true,
            record_platform_metadata: true,
            verify_metadata: true,
        }
    }
}

/// Object kinds that ATP can move and verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ObjectKind {
    /// Regular file with content.
    FileObject,
    /// Directory containing other objects.
    DirectoryObject,
    /// Mutable stream with rolling manifests.
    StreamObject,
    /// Point-in-time snapshot of a directory tree.
    SnapshotObject,
    /// Collection of related objects with metadata.
    DatasetObject,
    /// Bundled artifacts for deployment or distribution.
    ArtifactBundle,
    /// Sparse representation of large images or filesystems.
    SparseImage,
    /// Container layer with diff semantics.
    ContainerLayer,
    /// Application-defined object with extension metadata.
    ApplicationDefinedObject,
}

impl ObjectKind {
    /// All object kinds in canonical order.
    pub const ALL: [Self; 9] = [
        Self::FileObject,
        Self::DirectoryObject,
        Self::StreamObject,
        Self::SnapshotObject,
        Self::DatasetObject,
        Self::ArtifactBundle,
        Self::SparseImage,
        Self::ContainerLayer,
        Self::ApplicationDefinedObject,
    ];

    /// Whether this object kind is mutable.
    #[must_use]
    pub const fn is_mutable(self) -> bool {
        matches!(self, Self::StreamObject | Self::ApplicationDefinedObject)
    }

    /// Whether this object kind requires manifest addressing.
    #[must_use]
    pub const fn requires_manifest_addressing(self) -> bool {
        self.is_mutable()
    }

    /// Whether this object kind can contain child objects.
    #[must_use]
    pub const fn can_contain_children(self) -> bool {
        matches!(
            self,
            Self::DirectoryObject
                | Self::SnapshotObject
                | Self::DatasetObject
                | Self::ArtifactBundle
                | Self::SparseImage
                | Self::ContainerLayer
                | Self::ApplicationDefinedObject
        )
    }
}

impl fmt::Display for ObjectKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::FileObject => "file",
            Self::DirectoryObject => "directory",
            Self::StreamObject => "stream",
            Self::SnapshotObject => "snapshot",
            Self::DatasetObject => "dataset",
            Self::ArtifactBundle => "artifact-bundle",
            Self::SparseImage => "sparse-image",
            Self::ContainerLayer => "container-layer",
            Self::ApplicationDefinedObject => "application-defined",
        };
        write!(f, "{name}")
    }
}

/// Application-defined metadata for extension objects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationMetadata {
    /// Extension type identifier.
    pub extension_type: String,
    /// Version of the extension schema.
    pub schema_version: u32,
    /// Extension-specific metadata.
    pub metadata: BTreeMap<String, Vec<u8>>,
}

/// Platform-specific metadata.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PlatformMetadata {
    /// Unix file permissions (mode bits).
    pub unix_mode: Option<u32>,
    /// Windows file attributes.
    pub windows_attributes: Option<u32>,
    /// Extended attributes.
    pub extended_attributes: BTreeMap<String, Vec<u8>>,
    /// File creation time (nanoseconds since epoch).
    pub created_time_nanos: Option<u64>,
    /// File modification time (nanoseconds since epoch).
    pub modified_time_nanos: Option<u64>,
    /// File access time (nanoseconds since epoch).
    pub accessed_time_nanos: Option<u64>,
}

/// Core object metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectMetadata {
    /// Object kind.
    pub kind: ObjectKind,
    /// Object size in bytes (for leaf objects).
    pub size_bytes: Option<u64>,
    /// Platform-specific metadata.
    pub platform: PlatformMetadata,
    /// Application-defined metadata (for ApplicationDefinedObject).
    pub application: Option<ApplicationMetadata>,
}

/// Edge in the object graph linking parent to child.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ObjectEdge {
    /// Child object ID.
    pub child_id: ObjectId,
    /// Name/path component for this edge.
    pub name: String,
    /// Whether this edge represents a symbolic link.
    pub is_symlink: bool,
    /// Target path for symbolic links.
    pub symlink_target: Option<PathBuf>,
}

impl ObjectEdge {
    /// Create a regular file/directory edge.
    #[must_use]
    pub fn new(child_id: ObjectId, name: String) -> Self {
        Self {
            child_id,
            name,
            is_symlink: false,
            symlink_target: None,
        }
    }

    /// Create a symbolic link edge.
    #[must_use]
    pub fn symlink(child_id: ObjectId, name: String, target: PathBuf) -> Self {
        Self {
            child_id,
            name,
            is_symlink: true,
            symlink_target: Some(target),
        }
    }
}

/// Object in the graph with its metadata and children.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Object {
    /// Object identifier.
    pub id: ObjectId,
    /// Object metadata.
    pub metadata: ObjectMetadata,
    /// Child edges (for container objects).
    pub children: Vec<ObjectEdge>,
    /// Content for leaf objects (files, streams).
    pub content: Option<Vec<u8>>,
}

impl Object {
    /// Create a new file object.
    #[must_use]
    pub fn file(content: Vec<u8>) -> Self {
        let content_id = ContentId::from_bytes(&content);
        Self {
            id: ObjectId::content(content_id),
            metadata: ObjectMetadata {
                kind: ObjectKind::FileObject,
                size_bytes: Some(content.len() as u64),
                platform: PlatformMetadata::default(),
                application: None,
            },
            children: Vec::new(),
            content: Some(content),
        }
    }

    /// Create a new directory object.
    #[must_use]
    pub fn directory(mut children: Vec<ObjectEdge>) -> Self {
        children.sort();

        // Compute manifest ID from canonical representation of children
        let manifest_bytes = Self::canonical_children_bytes(&children);
        let manifest_id = ManifestId::from_manifest_bytes(&manifest_bytes);

        Self {
            id: ObjectId::manifest(manifest_id),
            metadata: ObjectMetadata {
                kind: ObjectKind::DirectoryObject,
                size_bytes: None,
                platform: PlatformMetadata::default(),
                application: None,
            },
            children,
            content: None,
        }
    }

    /// Create a stream object with rolling manifests.
    #[must_use]
    pub fn stream() -> Self {
        let manifest_bytes = Self::stream_identity_bytes();
        let manifest_id = ManifestId::from_manifest_bytes(&manifest_bytes);

        Self {
            id: ObjectId::manifest(manifest_id),
            metadata: ObjectMetadata {
                kind: ObjectKind::StreamObject,
                size_bytes: None,
                platform: PlatformMetadata::default(),
                application: None,
            },
            children: Vec::new(),
            content: None,
        }
    }

    fn stream_identity_bytes() -> Vec<u8> {
        let counter = STREAM_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
        let timestamp_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let process_id = u64::from(std::process::id());

        let mut bytes = Vec::with_capacity(STREAM_ID_DOMAIN.len() + 32);
        bytes.extend_from_slice(STREAM_ID_DOMAIN);
        bytes.extend_from_slice(&counter.to_be_bytes());
        bytes.extend_from_slice(&process_id.to_be_bytes());
        bytes.extend_from_slice(&timestamp_nanos.to_be_bytes());
        bytes
    }

    /// Create an application-defined object.
    #[must_use]
    pub fn application_defined(
        extension_type: String,
        schema_version: u32,
        metadata: BTreeMap<String, Vec<u8>>,
    ) -> Self {
        let app_metadata = ApplicationMetadata {
            extension_type,
            schema_version,
            metadata,
        };

        // Use manifest addressing for application-defined objects
        let manifest_bytes = Self::canonical_app_metadata_bytes(&app_metadata);
        let manifest_id = ManifestId::from_manifest_bytes(&manifest_bytes);

        Self {
            id: ObjectId::manifest(manifest_id),
            metadata: ObjectMetadata {
                kind: ObjectKind::ApplicationDefinedObject,
                size_bytes: None,
                platform: PlatformMetadata::default(),
                application: Some(app_metadata),
            },
            children: Vec::new(),
            content: None,
        }
    }

    /// Whether this object can have children.
    #[must_use]
    pub fn can_have_children(&self) -> bool {
        self.metadata.kind.can_contain_children()
    }

    /// Add a child edge to this object.
    pub fn add_child(&mut self, edge: ObjectEdge) -> Result<(), ObjectGraphError> {
        if !self.can_have_children() {
            return Err(ObjectGraphError::CannotAddChildren(self.metadata.kind));
        }

        // Check for duplicate names
        if self.children.iter().any(|e| e.name == edge.name) {
            return Err(ObjectGraphError::DuplicateChildName(edge.name));
        }

        self.children.push(edge);
        self.children.sort();
        Ok(())
    }

    /// Append a variable-length field to a canonical encoding with a u64
    /// big-endian length prefix.
    ///
    /// Every variable-length field in the canonical bytes MUST be
    /// length-prefixed: bare concatenation lets adjacent fields trade bytes
    /// (e.g. `name="a", target="xy"` followed by `name="b"` encodes to the
    /// same bytes as `name="a", target="x"` followed by `name="yb"`), which
    /// would let two different structures collide on the same manifest ID.
    fn push_canonical_field(bytes: &mut Vec<u8>, field: &[u8]) {
        bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
        bytes.extend_from_slice(field);
    }

    /// Get canonical bytes representation for children (for manifest computation).
    fn canonical_children_bytes(children: &[ObjectEdge]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(children.len() as u64).to_be_bytes());
        for edge in children {
            Self::push_canonical_field(&mut bytes, edge.name.as_bytes());
            // Fixed 32-byte hash: no length prefix needed.
            bytes.extend_from_slice(edge.child_id.hash_bytes());
            bytes.push(u8::from(edge.is_symlink));
            match &edge.symlink_target {
                Some(target) => {
                    bytes.push(1);
                    Self::push_canonical_field(&mut bytes, target.as_os_str().as_encoded_bytes());
                }
                None => bytes.push(0),
            }
        }
        bytes
    }

    /// Get canonical bytes representation for application metadata.
    fn canonical_app_metadata_bytes(metadata: &ApplicationMetadata) -> Vec<u8> {
        let mut bytes = Vec::new();
        Self::push_canonical_field(&mut bytes, metadata.extension_type.as_bytes());
        bytes.extend_from_slice(&metadata.schema_version.to_be_bytes());
        bytes.extend_from_slice(&(metadata.metadata.len() as u64).to_be_bytes());
        for (key, value) in &metadata.metadata {
            Self::push_canonical_field(&mut bytes, key.as_bytes());
            Self::push_canonical_field(&mut bytes, value);
        }
        bytes
    }
}

/// Errors in object graph operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectGraphError {
    /// Object kind cannot have children.
    CannotAddChildren(ObjectKind),
    /// Duplicate child name in parent.
    DuplicateChildName(String),
    /// Object not found in graph.
    ObjectNotFound(ObjectId),
    /// Circular reference detected.
    CircularReference(ObjectId),
    /// Invalid path in graph.
    InvalidPath(String),
}

impl fmt::Display for ObjectGraphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CannotAddChildren(kind) => {
                write!(f, "object kind {kind} cannot have children")
            }
            Self::DuplicateChildName(name) => {
                write!(f, "duplicate child name: {name}")
            }
            Self::ObjectNotFound(id) => {
                write!(f, "object not found: {id}")
            }
            Self::CircularReference(id) => {
                write!(f, "circular reference detected: {id}")
            }
            Self::InvalidPath(path) => {
                write!(f, "invalid path: {path}")
            }
        }
    }
}

impl std::error::Error for ObjectGraphError {}

/// Object graph containing objects and their relationships.
#[derive(Debug, Clone, Default)]
pub struct ObjectGraph {
    /// All objects in the graph, indexed by ID.
    objects: BTreeMap<ObjectId, Object>,
    /// Root objects (entry points).
    roots: BTreeSet<ObjectId>,
    /// Objects that have at least one parent (for O(1) parent lookup).
    objects_with_parents: BTreeSet<ObjectId>,
}

impl ObjectGraph {
    /// Create a new empty object graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an object to the graph.
    pub fn add_object(&mut self, object: Object) -> Result<(), ObjectGraphError> {
        let id = object.id.clone();

        // Update parent index for all children of this object
        for edge in &object.children {
            self.objects_with_parents.insert(edge.child_id.clone());
            // Remove child from roots if it was previously a root
            self.roots.remove(&edge.child_id);
        }

        self.objects.insert(id.clone(), object);

        // If this object has no parents, it's a root
        if !self.has_parent(&id) {
            self.roots.insert(id);
        }

        Ok(())
    }

    /// Add a root object to the graph.
    pub fn add_root(&mut self, object: Object) -> Result<(), ObjectGraphError> {
        let id = object.id.clone();
        self.add_object(object)?;
        self.roots.insert(id);
        Ok(())
    }

    /// Get an object by ID.
    #[must_use]
    pub fn get_object(&self, id: &ObjectId) -> Option<&Object> {
        self.objects.get(id)
    }

    /// Get all root objects.
    pub fn roots(&self) -> impl Iterator<Item = &ObjectId> {
        self.roots.iter()
    }

    /// Get all objects in the graph.
    pub fn objects(&self) -> impl Iterator<Item = (&ObjectId, &Object)> {
        self.objects.iter()
    }

    /// Check if an object exists in the graph.
    #[must_use]
    pub fn contains_object(&self, id: &ObjectId) -> bool {
        self.objects.contains_key(id)
    }

    /// Check if an object has a parent.
    #[must_use]
    /// Check if an object has any parents (O(1) lookup using parent index).
    pub fn has_parent(&self, id: &ObjectId) -> bool {
        self.objects_with_parents.contains(id)
    }

    /// Validate the graph for consistency.
    pub fn validate(&self) -> Result<(), ObjectGraphError> {
        // Check that all child references point to existing objects
        for object in self.objects.values() {
            for edge in &object.children {
                if !self.contains_object(&edge.child_id) {
                    return Err(ObjectGraphError::ObjectNotFound(edge.child_id.clone()));
                }
            }
        }

        // Check for circular references using DFS
        let mut visiting = BTreeSet::new();
        let mut visited = BTreeSet::new();

        for object_id in self.objects.keys() {
            if !visited.contains(object_id) {
                self.detect_cycles(object_id, &mut visiting, &mut visited)?;
            }
        }

        Ok(())
    }

    /// Get the total number of objects.
    #[must_use]
    pub fn object_count(&self) -> usize {
        self.objects.len()
    }

    /// Check if the graph is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }

    fn detect_cycles(
        &self,
        id: &ObjectId,
        visiting: &mut BTreeSet<ObjectId>,
        visited: &mut BTreeSet<ObjectId>,
    ) -> Result<(), ObjectGraphError> {
        if visiting.contains(id) {
            return Err(ObjectGraphError::CircularReference(id.clone()));
        }
        if visited.contains(id) {
            return Ok(());
        }

        visiting.insert(id.clone());

        if let Some(object) = self.get_object(id) {
            for edge in &object.children {
                self.detect_cycles(&edge.child_id, visiting, visited)?;
            }
        }

        visiting.remove(id);
        visited.insert(id.clone());
        Ok(())
    }
}

/// Convenience function to compute ATP content ID hash from content bytes.
pub fn compute_hash(content: &[u8]) -> [u8; 32] {
    ContentId::from_bytes(content).hash
}

// Temporary hex module until we add a proper crypto dependency
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[cfg(test)]
#[path = "object_inline_tests.rs"]
mod tests;
