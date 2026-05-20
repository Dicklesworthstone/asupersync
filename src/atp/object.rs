//! ATP ObjectGraph model and object kinds.
//!
//! ATP moves verified object graphs, not just files. This module defines the
//! type foundation for object identity, metadata policy, canonical ordering,
//! and graph commit semantics used by CLI, SDK, daemon, proofs, mailbox,
//! swarm, and dogfood components.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;

/// Content-addressed object identifier using cryptographic hash.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
        use std::collections::hash_map::DefaultHasher;
        let mut hasher = DefaultHasher::new();
        content.hash(&mut hasher);
        // For now, use a simplified hash computation
        // TODO: Replace with proper SHA-256 when crypto dep is added
        let hash_val = hasher.finish();
        let mut hash = [0u8; 32];
        hash[..8].copy_from_slice(&hash_val.to_be_bytes());
        Self { hash }
    }

    /// Format as hex string for debugging.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.hash)
    }
}

impl fmt::Display for ContentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "content:{}", &self.to_hex()[..16])
    }
}

/// Manifest-addressed object identifier using deterministic manifest hash.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
        ContentId::from_bytes(manifest).into()
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
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
    pub fn directory(children: Vec<ObjectEdge>) -> Self {
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
        // Stream gets a unique manifest ID that will be updated
        let manifest_bytes = b"stream-placeholder";
        let manifest_id = ManifestId::from_manifest_bytes(manifest_bytes);

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

    /// Get canonical bytes representation for children (for manifest computation).
    fn canonical_children_bytes(children: &[ObjectEdge]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for edge in children {
            bytes.extend_from_slice(edge.name.as_bytes());
            bytes.extend_from_slice(edge.child_id.hash_bytes());
            bytes.push(u8::from(edge.is_symlink));
            if let Some(target) = &edge.symlink_target {
                bytes.extend_from_slice(target.as_os_str().as_encoded_bytes());
            }
        }
        bytes
    }

    /// Get canonical bytes representation for application metadata.
    fn canonical_app_metadata_bytes(metadata: &ApplicationMetadata) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(metadata.extension_type.as_bytes());
        bytes.extend_from_slice(&metadata.schema_version.to_be_bytes());
        for (key, value) in &metadata.metadata {
            bytes.extend_from_slice(key.as_bytes());
            bytes.extend_from_slice(value);
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
    pub fn has_parent(&self, id: &ObjectId) -> bool {
        self.objects
            .values()
            .any(|obj| obj.children.iter().any(|edge| &edge.child_id == id))
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

        for root_id in &self.roots {
            if !visited.contains(root_id) {
                self.detect_cycles(root_id, &mut visiting, &mut visited)?;
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

// Temporary hex module until we add a proper crypto dependency
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_id_from_bytes_is_deterministic() {
        let content = b"hello world";
        let id1 = ContentId::from_bytes(content);
        let id2 = ContentId::from_bytes(content);
        assert_eq!(id1, id2);
    }

    #[test]
    fn object_kinds_have_expected_properties() {
        assert!(ObjectKind::StreamObject.is_mutable());
        assert!(ObjectKind::ApplicationDefinedObject.is_mutable());
        assert!(!ObjectKind::FileObject.is_mutable());

        assert!(ObjectKind::DirectoryObject.can_contain_children());
        assert!(!ObjectKind::FileObject.can_contain_children());
        assert!(ObjectKind::ApplicationDefinedObject.can_contain_children());
    }

    #[test]
    fn file_object_creation_works() {
        let content = b"test content".to_vec();
        let file = Object::file(content.clone());

        assert_eq!(file.metadata.kind, ObjectKind::FileObject);
        assert_eq!(file.metadata.size_bytes, Some(content.len() as u64));
        assert_eq!(file.content, Some(content));
        assert!(file.children.is_empty());
        assert!(file.id.is_content_addressed());
    }

    #[test]
    fn directory_object_creation_works() {
        let child_id = ObjectId::content(ContentId::from_bytes(b"child"));
        let edge = ObjectEdge::new(child_id, "child.txt".to_string());
        let dir = Object::directory(vec![edge]);

        assert_eq!(dir.metadata.kind, ObjectKind::DirectoryObject);
        assert_eq!(dir.metadata.size_bytes, None);
        assert_eq!(dir.content, None);
        assert_eq!(dir.children.len(), 1);
        assert!(dir.id.is_manifest_addressed());
    }

    #[test]
    fn stream_object_creation_works() {
        let stream = Object::stream();

        assert_eq!(stream.metadata.kind, ObjectKind::StreamObject);
        assert!(stream.id.is_manifest_addressed());
        assert!(stream.children.is_empty());
    }

    #[test]
    fn application_defined_object_creation_works() {
        let mut metadata = BTreeMap::new();
        metadata.insert("key".to_string(), b"value".to_vec());

        let obj = Object::application_defined("test-extension".to_string(), 1, metadata.clone());

        assert_eq!(obj.metadata.kind, ObjectKind::ApplicationDefinedObject);
        assert!(obj.id.is_manifest_addressed());
        assert!(obj.metadata.application.is_some());

        let app_meta = obj.metadata.application.as_ref().unwrap();
        assert_eq!(app_meta.extension_type, "test-extension");
        assert_eq!(app_meta.schema_version, 1);
        assert_eq!(app_meta.metadata, metadata);
    }

    #[test]
    fn object_graph_basic_operations_work() {
        let mut graph = ObjectGraph::new();

        let file1 = Object::file(b"content1".to_vec());
        let file2 = Object::file(b"content2".to_vec());

        let file1_id = file1.id.clone();
        let file2_id = file2.id.clone();

        graph.add_root(file1).unwrap();
        graph.add_object(file2).unwrap();

        assert_eq!(graph.object_count(), 2);
        assert!(!graph.is_empty());
        assert!(graph.contains_object(&file1_id));
        assert!(graph.contains_object(&file2_id));

        let roots: Vec<_> = graph.roots().cloned().collect();
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0], file1_id);
    }

    #[test]
    fn object_graph_validation_detects_missing_children() {
        let mut graph = ObjectGraph::new();

        let missing_id = ObjectId::content(ContentId::from_bytes(b"missing"));
        let edge = ObjectEdge::new(missing_id.clone(), "missing.txt".to_string());
        let dir = Object::directory(vec![edge]);

        graph.add_root(dir).unwrap();

        let result = graph.validate();
        assert!(matches!(result, Err(ObjectGraphError::ObjectNotFound(id)) if id == missing_id));
    }

    #[test]
    fn object_graph_validation_detects_cycles() {
        let mut graph = ObjectGraph::new();

        // Create a cycle: dir1 -> dir2 -> dir1
        let dir1_id = ObjectId::content(ContentId::from_bytes(b"dir1"));
        let dir2_id = ObjectId::content(ContentId::from_bytes(b"dir2"));

        let edge1 = ObjectEdge::new(dir2_id.clone(), "dir2".to_string());
        let edge2 = ObjectEdge::new(dir1_id.clone(), "dir1".to_string());

        let mut dir1 = Object::directory(vec![edge1]);
        dir1.id = dir1_id.clone();

        let mut dir2 = Object::directory(vec![edge2]);
        dir2.id = dir2_id;

        graph.add_root(dir1).unwrap();
        graph.add_object(dir2).unwrap();

        let result = graph.validate();
        assert!(matches!(
            result,
            Err(ObjectGraphError::CircularReference(_))
        ));
    }

    #[test]
    fn metadata_policy_presets_work() {
        let portable = MetadataPolicy::portable();
        assert!(!portable.preserve_unix_permissions);
        assert!(!portable.preserve_timestamps);
        assert!(portable.verify_metadata);

        let full = MetadataPolicy::full_preservation();
        assert!(full.preserve_unix_permissions);
        assert!(full.preserve_timestamps);
        assert!(full.preserve_extended_attributes);

        let default = MetadataPolicy::default();
        assert!(default.preserve_unix_permissions);
        assert!(!default.preserve_timestamps);
    }

    #[test]
    fn object_edge_creation_works() {
        let id = ObjectId::content(ContentId::from_bytes(b"test"));
        let edge = ObjectEdge::new(id.clone(), "test.txt".to_string());

        assert_eq!(edge.child_id, id);
        assert_eq!(edge.name, "test.txt");
        assert!(!edge.is_symlink);
        assert!(edge.symlink_target.is_none());

        let symlink_edge = ObjectEdge::symlink(
            id.clone(),
            "link.txt".to_string(),
            PathBuf::from("/target/path"),
        );

        assert_eq!(symlink_edge.child_id, id);
        assert_eq!(symlink_edge.name, "link.txt");
        assert!(symlink_edge.is_symlink);
        assert_eq!(
            symlink_edge.symlink_target,
            Some(PathBuf::from("/target/path"))
        );
    }

    #[test]
    fn cannot_add_children_to_file_objects() {
        let mut file = Object::file(b"content".to_vec());
        let child_id = ObjectId::content(ContentId::from_bytes(b"child"));
        let edge = ObjectEdge::new(child_id, "child".to_string());

        let result = file.add_child(edge);
        assert!(matches!(
            result,
            Err(ObjectGraphError::CannotAddChildren(ObjectKind::FileObject))
        ));
    }

    #[test]
    fn duplicate_child_names_are_rejected() {
        let child_id1 = ObjectId::content(ContentId::from_bytes(b"child1"));
        let child_id2 = ObjectId::content(ContentId::from_bytes(b"child2"));

        let edge1 = ObjectEdge::new(child_id1, "same_name".to_string());
        let edge2 = ObjectEdge::new(child_id2, "same_name".to_string());

        let mut dir = Object::directory(vec![edge1]);
        let result = dir.add_child(edge2);

        assert!(matches!(
            result,
            Err(ObjectGraphError::DuplicateChildName(name)) if name == "same_name"
        ));
    }

    #[test]
    fn children_are_kept_sorted() {
        let child_id1 = ObjectId::content(ContentId::from_bytes(b"child1"));
        let child_id2 = ObjectId::content(ContentId::from_bytes(b"child2"));

        let edge1 = ObjectEdge::new(child_id1, "z_last".to_string());
        let edge2 = ObjectEdge::new(child_id2, "a_first".to_string());

        let dir = Object::directory(vec![edge1, edge2]);

        assert_eq!(dir.children.len(), 2);
        assert_eq!(dir.children[0].name, "a_first");
        assert_eq!(dir.children[1].name, "z_last");
    }

    #[test]
    fn all_object_kinds_are_listed() {
        assert_eq!(ObjectKind::ALL.len(), 9);
        assert!(ObjectKind::ALL.contains(&ObjectKind::FileObject));
        assert!(ObjectKind::ALL.contains(&ObjectKind::DirectoryObject));
        assert!(ObjectKind::ALL.contains(&ObjectKind::StreamObject));
        assert!(ObjectKind::ALL.contains(&ObjectKind::SnapshotObject));
        assert!(ObjectKind::ALL.contains(&ObjectKind::DatasetObject));
        assert!(ObjectKind::ALL.contains(&ObjectKind::ArtifactBundle));
        assert!(ObjectKind::ALL.contains(&ObjectKind::SparseImage));
        assert!(ObjectKind::ALL.contains(&ObjectKind::ContainerLayer));
        assert!(ObjectKind::ALL.contains(&ObjectKind::ApplicationDefinedObject));
    }
}
