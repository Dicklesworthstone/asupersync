//! ATP manifest schema and graph commit semantics.
//!
//! This module defines the canonical manifest format for ATP object graphs,
//! Merkle root computation, and graph commit semantics. Manifests provide
//! verifiable representations of object graphs with content integrity.

use crate::atp::object::{MetadataPolicy, ObjectGraph, ObjectId, ObjectKind};
use std::collections::BTreeMap;
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

/// Merkle root hash computed from object graph.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MerkleRoot {
    /// SHA-256 hash representing the entire graph structure.
    hash: [u8; 32],
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

    /// Compute Merkle root from an object graph.
    #[must_use]
    pub fn from_graph(graph: &ObjectGraph) -> Self {
        // Simplified Merkle root computation
        // In a real implementation, this would use proper cryptographic hashing
        let mut combined = Vec::new();

        // Collect all object IDs in deterministic order
        let mut object_ids: Vec<_> = graph.objects().map(|(id, _)| id).collect();
        object_ids.sort();

        for id in object_ids {
            combined.extend_from_slice(id.hash_bytes());
        }

        // Simple hash (would use SHA-256 in real implementation)
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        combined.hash(&mut hasher);
        let hash_val = hasher.finish();

        let mut hash = [0u8; 32];
        hash[..8].copy_from_slice(&hash_val.to_be_bytes());

        Self { hash }
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
}

/// Object representation in a manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
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
}

impl Manifest {
    /// Create a manifest from an object graph.
    pub fn from_graph(
        graph: &ObjectGraph,
        metadata_policy: MetadataPolicy,
    ) -> Result<Self, ManifestError> {
        let mut manifest_objects = BTreeMap::new();
        let roots: Vec<_> = graph.roots().cloned().collect();

        // Convert each object to manifest format
        for (id, object) in graph.objects() {
            let manifest_obj = ManifestObject {
                id: id.clone(),
                kind: object.metadata.kind,
                size_bytes: object.metadata.size_bytes,
                children: object
                    .children
                    .iter()
                    .map(|edge| (edge.name.clone(), edge.child_id.clone()))
                    .collect(),
                content_hash: if object.id.is_content_addressed() {
                    Some(*object.id.hash_bytes())
                } else {
                    None
                },
            };
            manifest_objects.insert(id.clone(), manifest_obj);
        }

        let merkle_root = MerkleRoot::from_graph(graph);

        Ok(Self {
            version: ManifestVersion::CURRENT,
            merkle_root,
            metadata_policy,
            roots,
            objects: manifest_objects,
        })
    }

    /// Validate the manifest for consistency.
    pub fn validate(&self) -> Result<(), ManifestError> {
        // Check version compatibility
        if !self.version.is_supported() {
            return Err(ManifestError::UnsupportedVersion(self.version));
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
        // Simplified canonical serialization
        // Real implementation would use a proper binary format or protobuf
        let mut bytes = Vec::new();

        // Version
        bytes.extend_from_slice(&self.version.0.to_be_bytes());

        // Merkle root
        bytes.extend_from_slice(self.merkle_root.hash());

        // Roots (count + IDs)
        bytes.extend_from_slice(&(self.roots.len() as u32).to_be_bytes());
        for root in &self.roots {
            bytes.extend_from_slice(root.hash_bytes());
        }

        // Objects (count + serialized objects)
        bytes.extend_from_slice(&(self.objects.len() as u32).to_be_bytes());
        for (id, obj) in &self.objects {
            bytes.extend_from_slice(id.hash_bytes());
            bytes.push(obj.kind as u8);
            if let Some(size) = obj.size_bytes {
                bytes.push(1);
                bytes.extend_from_slice(&size.to_be_bytes());
            } else {
                bytes.push(0);
            }

            // Children
            bytes.extend_from_slice(&(obj.children.len() as u32).to_be_bytes());
            for (name, child_id) in &obj.children {
                bytes.extend_from_slice(&(name.len() as u32).to_be_bytes());
                bytes.extend_from_slice(name.as_bytes());
                bytes.extend_from_slice(child_id.hash_bytes());
            }
        }

        bytes
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
        }
    }
}

impl std::error::Error for ManifestError {}

/// Graph commit semantics for atomic updates.
#[derive(Debug, Clone, PartialEq, Eq)]
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
        let mut combined = Vec::new();
        combined.extend_from_slice(manifest.merkle_root.hash());
        combined.extend_from_slice(&metadata.timestamp_nanos.to_be_bytes());
        combined.extend_from_slice(metadata.author.as_bytes());
        combined.extend_from_slice(metadata.message.as_bytes());

        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        combined.hash(&mut hasher);
        let hash_val = hasher.finish();

        let mut hash = [0u8; 32];
        hash[..8].copy_from_slice(&hash_val.to_be_bytes());

        Self { hash }
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

// Temporary hex module
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atp::object::{ContentId, Object};

    #[test]
    fn manifest_version_support_check_works() {
        assert!(ManifestVersion::CURRENT.is_supported());
        assert!(ManifestVersion(0).is_supported());
        assert!(!ManifestVersion(100).is_supported());
    }

    #[test]
    fn merkle_root_from_empty_graph() {
        let graph = ObjectGraph::new();
        let root = MerkleRoot::from_graph(&graph);

        // Empty graph should have consistent root
        let root2 = MerkleRoot::from_graph(&graph);
        assert_eq!(root, root2);
    }

    #[test]
    fn merkle_root_from_simple_graph() {
        let mut graph = ObjectGraph::new();
        let file = Object::file(b"test content".to_vec());
        let _file_id = file.id.clone();
        graph.add_root(file).unwrap();

        let root = MerkleRoot::from_graph(&graph);

        // Adding same content should give same root
        let mut graph2 = ObjectGraph::new();
        let file2 = Object::file(b"test content".to_vec());
        graph2.add_root(file2).unwrap();
        let root2 = MerkleRoot::from_graph(&graph2);

        assert_eq!(root, root2);

        // Different content should give different root
        let mut graph3 = ObjectGraph::new();
        let file3 = Object::file(b"different content".to_vec());
        graph3.add_root(file3).unwrap();
        let root3 = MerkleRoot::from_graph(&graph3);

        assert_ne!(root, root3);
    }

    #[test]
    fn manifest_from_graph_works() {
        let mut graph = ObjectGraph::new();

        let file1 = Object::file(b"content1".to_vec());
        let file2 = Object::file(b"content2".to_vec());

        let file1_id = file1.id.clone();
        let file2_id = file2.id.clone();

        graph.add_root(file1).unwrap();
        graph.add_object(file2).unwrap();

        let policy = MetadataPolicy::default();
        let manifest = Manifest::from_graph(&graph, policy.clone()).unwrap();

        assert_eq!(manifest.version, ManifestVersion::CURRENT);
        assert_eq!(manifest.metadata_policy, policy);
        assert_eq!(manifest.object_count(), 2);
        assert_eq!(manifest.roots.len(), 1);
        assert_eq!(manifest.roots[0], file1_id);
        assert!(manifest.objects.contains_key(&file1_id));
        assert!(manifest.objects.contains_key(&file2_id));
    }

    #[test]
    fn manifest_validation_works() {
        let mut graph = ObjectGraph::new();
        let file = Object::file(b"test".to_vec());
        graph.add_root(file).unwrap();

        let policy = MetadataPolicy::default();
        let manifest = Manifest::from_graph(&graph, policy).unwrap();

        // Valid manifest should pass validation
        assert!(manifest.validate().is_ok());
    }

    #[test]
    fn manifest_validation_catches_missing_root() {
        let graph = ObjectGraph::new();
        let policy = MetadataPolicy::default();
        let mut manifest = Manifest::from_graph(&graph, policy).unwrap();

        // Add a root that doesn't exist in objects
        let fake_id = ObjectId::content(ContentId::from_bytes(b"fake"));
        manifest.roots.push(fake_id.clone());

        let result = manifest.validate();
        assert!(matches!(result, Err(ManifestError::RootObjectMissing(id)) if id == fake_id));
    }

    #[test]
    fn commit_creation_and_validation_works() {
        let mut graph = ObjectGraph::new();
        let file = Object::file(b"test content".to_vec());
        graph.add_root(file).unwrap();

        let policy = MetadataPolicy::default();
        let manifest = Manifest::from_graph(&graph, policy).unwrap();

        let metadata = CommitMetadata {
            timestamp_nanos: 1234567890,
            author: "test_author".to_string(),
            message: "test commit".to_string(),
        };

        let commit = GraphCommit::new(None, manifest, metadata);

        // Commit should validate successfully
        assert!(commit.validate().is_ok());
        assert!(commit.parent.is_none());
    }

    #[test]
    fn commit_with_parent_works() {
        let mut graph = ObjectGraph::new();
        let file = Object::file(b"test content".to_vec());
        graph.add_root(file).unwrap();

        let policy = MetadataPolicy::default();
        let manifest = Manifest::from_graph(&graph, policy).unwrap();

        let metadata = CommitMetadata {
            timestamp_nanos: 1234567890,
            author: "test_author".to_string(),
            message: "test commit".to_string(),
        };

        let parent_id = CommitId::new([1; 32]);
        let commit = GraphCommit::new(Some(parent_id.clone()), manifest, metadata);

        assert_eq!(commit.parent, Some(parent_id));
        assert!(commit.validate().is_ok());
    }

    #[test]
    fn manifest_canonical_bytes_are_deterministic() {
        let mut graph = ObjectGraph::new();
        let file = Object::file(b"test content".to_vec());
        graph.add_root(file).unwrap();

        let policy = MetadataPolicy::default();
        let manifest1 = Manifest::from_graph(&graph, policy.clone()).unwrap();
        let manifest2 = Manifest::from_graph(&graph, policy).unwrap();

        let bytes1 = manifest1.to_canonical_bytes();
        let bytes2 = manifest2.to_canonical_bytes();

        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn commit_id_is_deterministic() {
        let mut graph = ObjectGraph::new();
        let file = Object::file(b"test content".to_vec());
        graph.add_root(file).unwrap();

        let policy = MetadataPolicy::default();
        let manifest = Manifest::from_graph(&graph, policy).unwrap();

        let metadata = CommitMetadata {
            timestamp_nanos: 1234567890,
            author: "test_author".to_string(),
            message: "test commit".to_string(),
        };

        let id1 = CommitId::from_commit(&manifest, &metadata);
        let id2 = CommitId::from_commit(&manifest, &metadata);

        assert_eq!(id1, id2);
    }
}
