//! Transport-agnostic bounded-memory streaming + merkle-digest helpers.
//!
//! These are the load-bearing primitives that let an ATP transport build a
//! transfer manifest, hash file content, and reproduce the canonical flat
//! object-graph merkle root **without ever holding a whole file — let alone a
//! whole transfer — in memory**. Peak resident memory is `O(chunk_size)` for the
//! streaming hash and `O(number_of_entries)` digests for the merkle, never
//! `O(total_bytes)`.
//!
//! They were first written private to [`crate::net::atp::transport_tcp`]
//! (`82f15fb65`, "stream files for O(chunk) memory — beat rsync RSS"). They are
//! extracted here verbatim (byte-identical behavior) so the native QUIC transport
//! (`transport_quic`, epic `b0k8qo` phase B) reuses exactly the same manifest,
//! content-id, and merkle computation — identical roots on both transports — and
//! inherits the same bounded-memory discipline. The existing
//! `atp_tcp_loopback_e2e` / `atp_tcp_bounded_memory` suites plus the in-module
//! differential oracle (owned `ObjectGraph` vs [`flat_merkle_root_from_digests`])
//! pin the byte-identical guarantee.
//!
//! # Error mapping
//!
//! The walk/hash helpers fail closed with a [`StreamingError`] carrying a
//! pre-formatted, source-path-scoped message. A transport maps it into its own
//! taxonomy with a `From` impl — e.g. transport_tcp maps it to
//! `TransportError::Source`, preserving the exact message — so relocating the
//! code changes neither the success path nor the error strings.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::atp::object::{
    ContentId, ContentIdHasher, MetadataPolicy, Object, ObjectEdge, ObjectId, ObjectKind,
};
use crate::atp::safety::validate_portable_path_component;
use crate::io::AsyncReadExt;

use super::metadata::{PathLinkKind, classify_path_link};

/// Failure from a transport-agnostic streaming/walk helper.
///
/// Carries a pre-formatted, source-path-scoped message (the same string the
/// original transport_tcp helpers embedded in `TransportError::Source`). A
/// transport converts it into its own error type with a `From<StreamingError>`
/// impl, keeping error messages byte-identical to the pre-extraction code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamingError(String);

impl StreamingError {
    /// Wrap an already-formatted, source-scoped failure message.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }

    /// Borrow the failure message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.0
    }

    /// Consume the error, yielding its message (for `From` conversions that wrap
    /// the string in a transport-specific variant without copying).
    #[must_use]
    pub fn into_message(self) -> String {
        self.0
    }
}

impl std::fmt::Display for StreamingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for StreamingError {}

/// Per-entry content digests sufficient to reproduce the flat object-graph
/// merkle root without holding any file content in memory.
///
/// The sender fills these while streaming each file off disk; the receiver
/// fills them while streaming incoming chunks. Both then call
/// [`flat_merkle_root_from_digests`].
#[derive(Debug, Clone)]
pub struct EntryDigest {
    /// Transfer-relative path (forward-slash separated).
    pub rel_path: String,
    /// Content length in bytes.
    pub size: u64,
    /// Content-addressed object id (`ContentId::from_bytes` over the content).
    pub content_id: ObjectId,
    /// Plain SHA-256 of the content. Matches the manifest entry hash and the
    /// `Sha256::digest(content)` term the owned-graph merkle hashes per file.
    pub content_sha256: [u8; 32],
}

/// One node in the flattened object graph used for merkle hashing.
enum FlatNode<'a> {
    File {
        size: u64,
        content_sha256: &'a [u8; 32],
    },
    Dir {
        kind: ObjectKind,
        size_bytes: Option<u64>,
        children: Vec<ObjectEdge>,
    },
}

/// Reproduce `MerkleRoot::from_graph` over the flat object graph from per-entry
/// digests alone.
///
/// The hashing is byte-identical to the owned-graph builder, but it never
/// materializes file content, so peak memory is `O(number_of_entries)` digests
/// rather than `O(total_bytes)`. Identical builders on both sides produce
/// identical roots.
#[must_use]
pub fn flat_merkle_root_from_digests(entries: &[EntryDigest]) -> String {
    let mut sorted: Vec<&EntryDigest> = entries.iter().collect();
    sorted.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));

    let mut objects: BTreeMap<ObjectId, FlatNode<'_>> = BTreeMap::new();
    let mut edges = Vec::with_capacity(sorted.len());
    for entry in sorted {
        // Content-addressed: identical files collapse to one node (idempotent).
        objects
            .entry(entry.content_id.clone())
            .or_insert(FlatNode::File {
                size: entry.size,
                content_sha256: &entry.content_sha256,
            });
        edges.push(ObjectEdge::new(
            entry.content_id.clone(),
            entry.rel_path.clone(),
        ));
    }

    let root = Object::directory(edges);
    objects.insert(
        root.id,
        FlatNode::Dir {
            kind: root.metadata.kind,
            size_bytes: root.metadata.size_bytes,
            children: root.children,
        },
    );

    let mut hasher = Sha256::new();
    for (id, node) in objects {
        hasher.update(id.hash_bytes());
        match node {
            FlatNode::File {
                size,
                content_sha256,
            } => {
                hasher.update([ObjectKind::FileObject as u8]);
                hasher.update(size.to_be_bytes());
                // A file object has no children; its content term is the plain
                // SHA-256 of the bytes, identical to `Sha256::digest(content)`.
                hasher.update(content_sha256);
            }
            FlatNode::Dir {
                kind,
                size_bytes,
                children,
            } => {
                hasher.update([kind as u8]);
                if let Some(size) = size_bytes {
                    hasher.update(size.to_be_bytes());
                }
                let mut child_indices: Vec<usize> = (0..children.len()).collect();
                child_indices.sort_by(|&a, &b| children[a].name.cmp(&children[b].name));
                for idx in child_indices {
                    let edge = &children[idx];
                    hasher.update(edge.name.as_bytes());
                    hasher.update(edge.child_id.hash_bytes());
                    hasher.update([u8::from(edge.is_symlink)]);
                    if let Some(target) = &edge.symlink_target {
                        hasher.update(target.as_os_str().as_encoded_bytes());
                    }
                }
            }
        }
    }

    hex_encode(&hasher.finalize())
}

/// Compute the flat object-graph merkle root from in-memory `(rel_path, bytes)`
/// slices.
///
/// This is useful for tests, golden vectors, and callers that already hold
/// content; streaming transports should prefer
/// [`flat_merkle_root_from_digests`].
#[must_use]
pub fn flat_merkle_root_from_slices<'a>(
    entries: impl IntoIterator<Item = (&'a str, &'a [u8])>,
) -> String {
    let digests: Vec<EntryDigest> = entries
        .into_iter()
        .map(|(rel_path, bytes)| EntryDigest {
            rel_path: rel_path.to_string(),
            size: bytes.len() as u64,
            content_id: ObjectId::content(ContentId::from_bytes(bytes)),
            content_sha256: Sha256::digest(bytes).into(),
        })
        .collect();
    flat_merkle_root_from_digests(&digests)
}

/// Lowercase hex encoding, two chars per byte. Shared so the merkle root and any
/// transport's per-entry SHA-256 comparison render identically.
#[must_use]
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap_or('0'));
    }
    out
}

/// One source file discovered by [`collect_entries`]: its transfer-relative
/// path and absolute on-disk path.
///
/// Crucially this carries no content: files are streamed off disk later (size is
/// computed during the streaming hash pass), never slurped into RAM.
#[derive(Debug, Clone)]
pub struct SourceEntry {
    /// Transfer-relative path (forward-slash separated).
    pub rel_path: String,
    /// Absolute on-disk path the bytes are streamed from.
    pub abs_path: PathBuf,
}

/// Walk a path into [`SourceEntry`] metadata (paths only). A single file yields
/// one entry keyed by its file name.
///
/// A directory yields one entry per regular file keyed by path relative to the
/// directory. No bytes are read here.
///
/// Returns `(root_name, is_directory, entries)`.
///
/// # Errors
///
/// Returns [`StreamingError`] if `root` cannot be stat'd, a directory cannot be
/// read, or `root` is neither a regular file nor a directory.
pub async fn collect_entries(
    root: &Path,
) -> Result<(String, bool, Vec<SourceEntry>), StreamingError> {
    collect_entries_with_policy(root, &MetadataPolicy::default()).await
}

/// Policy-aware source walk used by metadata-preserving transports.
///
/// Symbolic links are emitted as leaves when preservation is enabled. Other
/// reparse points and links disallowed by policy fail closed before traversal.
pub async fn collect_entries_with_policy(
    root: &Path,
    policy: &MetadataPolicy,
) -> Result<(String, bool, Vec<SourceEntry>), StreamingError> {
    let root_link_kind = classify_path_link(root)
        .await
        .map_err(|e| StreamingError::new(format!("{}: {e}", root.display())))?;

    let root_name = match root.file_name() {
        None => "transfer".to_string(),
        Some(name) => name
            .to_str()
            .ok_or_else(|| {
                StreamingError::new(format!(
                    "{}: source file name is not valid Unicode",
                    root.display()
                ))
            })?
            .to_string(),
    };
    validate_portable_path_component(&root_name).map_err(|_| {
        StreamingError::new(format!(
            "{}: source file name is not portable: {root_name:?}",
            root.display()
        ))
    })?;

    match root_link_kind {
        PathLinkKind::Symlink(_) if policy.preserve_symlinks => {
            return Ok((
                root_name.clone(),
                false,
                vec![SourceEntry {
                    rel_path: root_name,
                    abs_path: root.to_path_buf(),
                }],
            ));
        }
        PathLinkKind::Symlink(_) => {
            return Err(StreamingError::new(format!(
                "{}: source symlink rejected by metadata policy",
                root.display()
            )));
        }
        PathLinkKind::UnsupportedReparse => {
            return Err(StreamingError::new(format!(
                "{}: unsupported Windows reparse point",
                root.display()
            )));
        }
        PathLinkKind::NotLink => {}
    }

    let meta = crate::fs::metadata(root)
        .await
        .map_err(|e| StreamingError::new(format!("{}: {e}", root.display())))?;

    if meta.is_file() {
        return Ok((
            root_name.clone(),
            false,
            vec![SourceEntry {
                rel_path: root_name,
                abs_path: root.to_path_buf(),
            }],
        ));
    }
    if meta.is_dir() {
        let mut entries = Vec::new();
        collect_dir(root, String::new(), policy, &mut entries).await?;
        entries.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
        return Ok((root_name, true, entries));
    }
    Err(StreamingError::new(format!(
        "{}: not a regular file or directory",
        root.display()
    )))
}

/// Recursive directory walk producing [`SourceEntry`] metadata with
/// forward-slash relative paths. Reads directory entries and file types, never
/// file content.
fn collect_dir<'a>(
    dir: &'a Path,
    prefix: String,
    policy: &'a MetadataPolicy,
    out: &'a mut Vec<SourceEntry>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), StreamingError>> + Send + 'a>> {
    Box::pin(async move {
        let mut read_dir = crate::fs::read_dir(dir)
            .await
            .map_err(|e| StreamingError::new(format!("{}: {e}", dir.display())))?;
        // Collect child names first for deterministic ordering.
        let mut children: Vec<(String, PathBuf, bool)> = Vec::new();
        while let Some(entry) = read_dir
            .next_entry()
            .await
            .map_err(|e| StreamingError::new(format!("{}: {e}", dir.display())))?
        {
            let path = entry.path();
            let link_kind = classify_path_link(&path)
                .await
                .map_err(|e| StreamingError::new(format!("{}: {e}", path.display())))?;
            let name = entry
                .file_name()
                .to_str()
                .ok_or_else(|| {
                    StreamingError::new(format!(
                        "{}: source entry name is not valid Unicode",
                        path.display()
                    ))
                })?
                .to_string();
            validate_portable_path_component(&name).map_err(|_| {
                StreamingError::new(format!(
                    "{}: source entry name is not portable: {name:?}",
                    path.display()
                ))
            })?;
            let ft = entry
                .file_type()
                .await
                .map_err(|e| StreamingError::new(format!("{}: {e}", path.display())))?;
            let is_dir = match link_kind {
                PathLinkKind::NotLink => ft.is_dir(),
                PathLinkKind::Symlink(_) if policy.preserve_symlinks => false,
                PathLinkKind::Symlink(_) => {
                    return Err(StreamingError::new(format!(
                        "{}: source symlink rejected by metadata policy",
                        path.display()
                    )));
                }
                PathLinkKind::UnsupportedReparse => {
                    return Err(StreamingError::new(format!(
                        "{}: unsupported Windows reparse point",
                        path.display()
                    )));
                }
            };
            children.push((name, path, is_dir));
        }
        children.sort_by(|a, b| a.0.cmp(&b.0));

        // An empty subdirectory is otherwise lost — the walk emits only regular
        // files, so a structural/empty dir would vanish on the receiver. Emit an
        // explicit entry for it (J2, `b0k8qo.11.2`); the receiver recreates it
        // from the dir-kind manifest metadata. A non-empty dir stays implicit
        // (reconstructed when its descendant files commit), so existing transfers
        // and their merkle roots are unchanged. The transfer root's own emptiness
        // is the caller's concern (`is_directory` with no entries).
        if children.is_empty() && !prefix.is_empty() {
            out.push(SourceEntry {
                rel_path: prefix,
                abs_path: dir.to_path_buf(),
            });
            return Ok(());
        }

        for (name, path, is_dir) in children {
            let rel = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            if is_dir {
                collect_dir(&path, rel, policy, out).await?;
            } else {
                out.push(SourceEntry {
                    rel_path: rel,
                    abs_path: path,
                });
            }
        }
        Ok(())
    })
}

/// Stream a file off disk in `buf`-sized chunks, computing its size, content id,
/// and plain SHA-256 without ever holding more than one chunk in memory.
///
/// # Errors
///
/// Returns [`StreamingError`] if the file cannot be opened or a read fails.
pub async fn hash_file_streaming(
    path: &Path,
    buf: &mut [u8],
) -> Result<(u64, ObjectId, [u8; 32]), StreamingError> {
    let mut file = crate::fs::File::open(path)
        .await
        .map_err(|e| StreamingError::new(format!("{}: {e}", path.display())))?;
    let mut sha = Sha256::new();
    let mut cid: ContentIdHasher = ContentId::streaming();
    let mut size: u64 = 0;
    loop {
        let n = file
            .read(buf)
            .await
            .map_err(|e| StreamingError::new(format!("{}: {e}", path.display())))?;
        if n == 0 {
            break;
        }
        sha.update(&buf[..n]);
        cid.update(&buf[..n]);
        size = size.saturating_add(n as u64);
    }
    let content_sha256: [u8; 32] = sha.finalize().into();
    let content_id = ObjectId::content(cid.finalize());
    Ok((size, content_id, content_sha256))
}

/// Incremental receive-side state for one staged manifest entry.
///
/// Transports use this while writing incoming chunks to disk. It keeps only
/// per-entry counters and hash state in memory, so the caller can verify the
/// entry digest after the final chunk without materializing the entry bytes.
pub struct StagedEntryReceive {
    /// Staging file path for this entry.
    pub staging_path: PathBuf,
    /// Bytes accepted for this entry so far.
    pub bytes_written: u64,
    /// Whether a non-empty staging file has been created by incoming data.
    pub created: bool,
    sha: Sha256,
    cid: ContentIdHasher,
}

impl StagedEntryReceive {
    /// Build an empty receive state for `staging_path`.
    #[must_use]
    pub fn new(staging_path: PathBuf) -> Self {
        Self {
            staging_path,
            bytes_written: 0,
            created: false,
            sha: Sha256::new(),
            cid: ContentId::streaming(),
        }
    }

    /// Mark that the caller has created the staging file for this entry.
    pub fn mark_created(&mut self) {
        self.created = true;
    }

    /// Fold one received chunk into the incremental SHA-256, content id, and
    /// byte counter. The caller remains responsible for enforcing offsets and
    /// manifest size limits before accepting the chunk.
    pub fn update_with_chunk(&mut self, chunk: &[u8]) {
        self.sha.update(chunk);
        self.cid.update(chunk);
        self.bytes_written = self.bytes_written.saturating_add(chunk.len() as u64);
    }

    /// Finalize the staged entry into the shared merkle digest plus the staging
    /// path and `created` flag the caller still needs for commit handling.
    #[must_use]
    pub fn finalize(self, rel_path: String) -> (EntryDigest, PathBuf, bool) {
        let content_sha256: [u8; 32] = self.sha.finalize().into();
        let content_id = ObjectId::content(self.cid.finalize());
        (
            EntryDigest {
                rel_path,
                size: self.bytes_written,
                content_id,
                content_sha256,
            },
            self.staging_path,
            self.created,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest_of(rel: &str, bytes: &[u8]) -> EntryDigest {
        EntryDigest {
            rel_path: rel.to_string(),
            size: bytes.len() as u64,
            content_id: ObjectId::content(ContentId::from_bytes(bytes)),
            content_sha256: Sha256::digest(bytes).into(),
        }
    }

    #[test]
    fn hex_encode_is_lowercase_two_chars_per_byte() {
        assert_eq!(hex_encode(&[0x00, 0x0f, 0xa0, 0xff]), "000fa0ff");
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn merkle_root_is_deterministic_order_independent_and_64_hex() {
        let a = vec![digest_of("a.txt", b"alpha"), digest_of("b.txt", b"bravo")];
        let b = vec![digest_of("b.txt", b"bravo"), digest_of("a.txt", b"alpha")];
        let ra = flat_merkle_root_from_digests(&a);
        let rb = flat_merkle_root_from_digests(&b);
        assert_eq!(ra, rb, "merkle root must be independent of entry order");
        assert_eq!(ra.len(), 64, "sha-256 hex root is 64 chars");
        assert!(
            ra.bytes().all(|c| c.is_ascii_hexdigit()),
            "root must be lowercase hex"
        );
    }

    #[test]
    fn matches_canonical_owned_object_graph_root() {
        // Self-contained differential oracle: the streaming per-entry-digest root
        // must equal the canonical `MerkleRoot::from_graph` over an owned
        // `ObjectGraph` built from the same content — the independent path. This
        // is the byte-identical proof that the relocated math is unchanged, and
        // it covers content-dedup (two distinct paths, identical bytes).
        use crate::atp::manifest::MerkleRoot;
        use crate::atp::object::ObjectGraph;

        let files: [(&str, &[u8]); 3] = [
            ("a.txt", b"alpha"),
            ("b.txt", b"bravo"),
            ("nested/dup", b"alpha"),
        ];

        let digests: Vec<EntryDigest> = files.iter().map(|(p, b)| digest_of(p, b)).collect();
        let streamed = flat_merkle_root_from_digests(&digests);

        let mut graph = ObjectGraph::new();
        let mut sorted: Vec<&(&str, &[u8])> = files.iter().collect();
        sorted.sort_by(|a, b| a.0.cmp(b.0));
        let mut edges = Vec::new();
        for (rel, bytes) in sorted {
            let obj = Object::file(bytes.to_vec());
            let id = obj.id.clone();
            if !graph.contains_object(&id) {
                let _ = graph.add_object(obj);
            }
            edges.push(ObjectEdge::new(id, (*rel).to_string()));
        }
        let root = Object::directory(edges);
        let _ = graph.add_root(root);
        let owned = MerkleRoot::from_graph(&graph).to_hex();

        assert_eq!(
            streamed, owned,
            "streaming digest root must equal canonical owned-graph root"
        );
    }

    #[test]
    fn duplicate_content_collapses_but_path_is_committed() {
        // Two distinct paths, identical content: content-addressed dedup to a
        // single file node, yet the distinct paths still alter the root via the
        // directory edges (path is committed, content is shared).
        let dup = vec![digest_of("x", b"same"), digest_of("y", b"same")];
        let moved = vec![digest_of("x", b"same"), digest_of("z", b"same")];
        let root_dup = flat_merkle_root_from_digests(&dup);
        assert_eq!(root_dup.len(), 64);
        assert_ne!(
            root_dup,
            flat_merkle_root_from_digests(&moved),
            "renaming a committed path must change the root"
        );
    }

    #[test]
    fn empty_transfer_has_a_stable_root() {
        let r = flat_merkle_root_from_digests(&[]);
        assert_eq!(r.len(), 64);
        assert_eq!(r, flat_merkle_root_from_digests(&[]));
    }

    #[test]
    fn flat_merkle_root_from_slices_matches_digest_path() {
        let root_from_slices =
            flat_merkle_root_from_slices([("a", b"alpha".as_slice()), ("b", b"bravo".as_slice())]);
        let digests = vec![digest_of("a", b"alpha"), digest_of("b", b"bravo")];
        assert_eq!(root_from_slices, flat_merkle_root_from_digests(&digests));
    }

    #[test]
    fn staged_receive_finalizes_incremental_digest() {
        let mut recv = StagedEntryReceive::new(PathBuf::from("stage/0"));
        recv.mark_created();
        recv.update_with_chunk(b"hel");
        recv.update_with_chunk(b"lo");
        let (digest, path, created) = recv.finalize("greeting.txt".to_string());

        assert!(created);
        assert_eq!(path, PathBuf::from("stage/0"));
        assert_eq!(digest.rel_path, "greeting.txt");
        assert_eq!(digest.size, 5);
        let expected_sha: [u8; 32] = Sha256::digest(b"hello").into();
        assert_eq!(digest.content_sha256, expected_sha);
        assert_eq!(
            digest.content_id,
            ObjectId::content(ContentId::from_bytes(b"hello"))
        );
    }

    #[test]
    fn streaming_error_preserves_message() {
        let e = StreamingError::new("path/to/x: No such file or directory (os error 2)");
        assert_eq!(
            e.message(),
            "path/to/x: No such file or directory (os error 2)"
        );
        assert_eq!(
            e.clone().into_message(),
            "path/to/x: No such file or directory (os error 2)"
        );
        assert_eq!(
            format!("{e}"),
            "path/to/x: No such file or directory (os error 2)"
        );
    }

    #[cfg(unix)]
    #[test]
    fn policy_aware_walk_emits_directory_symlink_as_leaf() {
        let root = tempfile::tempdir().expect("temporary source root");
        std::fs::create_dir(root.path().join("target")).expect("create target dir");
        std::fs::create_dir(root.path().join("dir")).expect("create link parent");
        std::os::unix::fs::symlink("../target", root.path().join("dir/nested-link"))
            .expect("create directory symlink");

        let (_, is_directory, entries) = futures_lite::future::block_on(
            collect_entries_with_policy(root.path(), &MetadataPolicy::default()),
        )
        .expect("walk preserved symlink");
        assert!(is_directory);
        assert_eq!(
            entries
                .iter()
                .map(|entry| entry.rel_path.as_str())
                .collect::<Vec<_>>(),
            vec!["dir/nested-link", "target"]
        );

        let error = futures_lite::future::block_on(collect_entries_with_policy(
            root.path(),
            &MetadataPolicy::portable(),
        ))
        .expect_err("non-preserving policy must fail closed on source links");
        assert!(error.message().contains("metadata policy"));
    }

    #[cfg(windows)]
    #[test]
    fn collect_entries_rejects_non_unicode_windows_names() {
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt;

        let root = tempfile::tempdir().expect("temporary source root");
        let invalid_name = OsString::from_wide(&[0xd800, b'.' as u16, b'b' as u16]);
        std::fs::write(root.path().join(invalid_name), b"payload")
            .expect("create non-Unicode Windows path");

        let error = futures_lite::future::block_on(collect_entries(root.path()))
            .expect_err("non-Unicode source names must fail closed");
        assert!(error.message().contains("not valid Unicode"), "{error}");
    }

    #[cfg(windows)]
    #[test]
    fn collect_entries_rejects_windows_junctions() {
        let root = tempfile::tempdir().expect("temporary source root");
        let target = tempfile::tempdir().expect("temporary reparse target");
        std::fs::write(target.path().join("outside.txt"), b"outside")
            .expect("write target payload");
        let link = root.path().join("real-junction");
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(target.path())
            .status()
            .expect("run mklink /J");
        assert!(status.success(), "mklink /J fixture must succeed");

        let error = futures_lite::future::block_on(collect_entries(root.path()))
            .expect_err("junction source entries must fail closed");
        assert!(error.message().contains("reparse point"), "{error}");
    }
}
