//! Owned native directory inventories and reviewable reconciliation.
//!
//! This Linux/glibc profile synchronizes ordinary file bytes and directory
//! structure. It does not preserve permissions, timestamps, symlinks, hard-link
//! topology, sparse layout, or platform metadata. Manifests carrying those
//! semantics are refused rather than silently downgraded.
//!
//! All filesystem work runs through the caller's scoped blocking gateway.
//! Root descriptors are retained; descendants are opened relative to their
//! parents with O_NOFOLLOW. The caller must exclusively own both roots during
//! prepare/apply. Descriptor confinement and revalidation detect stale plans,
//! but do not provide a transaction against a hostile process with equal write
//! authority. Mounted descendants on another filesystem are refused.

use super::{
    BidirectionalSyncError, BidirectionalSyncPlan, DirectoryEntryKind,
    DirectoryEntryMetadata, DirectoryManifest, DirectoryManifestEntry,
    DirectoryPath, DirectorySyncError, PathNormalizationRules, plan_bidirectional_sync,
};
use crate::cx::Cx;
use crate::fs::ScopedFsError;
use nix::dir::Dir;
use nix::errno::Errno;
use nix::fcntl::{AtFlags, OFlag, open, openat};
use nix::sys::stat::{FileStat, Mode, SFlag, fstatat};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, Metadata};
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

/// Resource limits for each root inventory and each copied file.
///
/// Publicly constructed values are checked at every operation boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeDirectoryLimits {
    /// Maximum entries, including explicit directory ancestors.
    pub max_entries: usize,
    /// Maximum relative path component count.
    pub max_depth: usize,
    /// Maximum bytes in one regular file.
    pub max_file_bytes: u64,
    /// Maximum sum of regular-file bytes in one root.
    pub max_total_bytes: u64,
    /// Scratch buffer size for incremental hashing and copying.
    pub buffer_bytes: usize,
}

impl Default for NativeDirectoryLimits {
    fn default() -> Self {
        Self {
            max_entries: 100_000,
            max_depth: 64,
            max_file_bytes: 16 * 1024 * 1024 * 1024,
            max_total_bytes: 64 * 1024 * 1024 * 1024,
            buffer_bytes: 64 * 1024,
        }
    }
}

impl NativeDirectoryLimits {
    fn validate(self) -> Result<(), NativeDirectoryError> {
        if self.max_entries == 0
            || self.max_entries > 1_000_000
            || self.max_depth == 0
            || self.max_depth > 256
            || self.max_file_bytes == 0
            || self.max_total_bytes == 0
            || self.buffer_bytes == 0
            || self.buffer_bytes > 1024 * 1024
        {
            return Err(refused(
                Path::new(""),
                "limits require 1..=1000000 entries, 1..=256 depth, positive byte bounds, and 1..=1048576 buffer bytes",
            ));
        }
        Ok(())
    }
}

/// A refused or failed native directory operation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NativeDirectoryError {
    /// Runtime authority, admission, or retirement failed.
    #[error("native directory runtime: {0}")]
    Runtime(#[source] ScopedFsError),
    /// An actual filesystem operation failed.
    #[error("native directory I/O at {path}: {source}")]
    Io {
        /// Rooted diagnostic path.
        path: PathBuf,
        /// Original operating-system error.
        #[source]
        source: io::Error,
    },
    /// The profile cannot safely execute this request.
    #[error("native directory refused {path}: {reason}")]
    Refused {
        /// Root or relative diagnostic path.
        path: PathBuf,
        /// Stable refusal explanation.
        reason: &'static str,
    },
    /// A configured bound would be exceeded.
    #[error("native directory limit {limit} exceeded at {path}")]
    Limit {
        /// Path at which the bound was reached.
        path: PathBuf,
        /// Configured bound name.
        limit: &'static str,
    },
    /// A retained observation no longer identifies the same object or bytes.
    #[error("native directory precondition changed at {path}")]
    Changed {
        /// Changed path.
        path: PathBuf,
    },
    /// Cancellation or a budget checkpoint refused further work.
    #[error("native directory checkpoint: {0}")]
    Checkpoint(#[source] crate::error::Error),
    /// The existing reconciliation planner rejected a manifest.
    #[error("native directory reconciliation: {0}")]
    Plan(#[source] BidirectionalSyncError),
    /// Path or manifest canonical validation failed.
    #[error("native directory manifest: {0}")]
    Manifest(#[source] DirectorySyncError),
}

/// A complete content-verified inventory retaining its root descriptor.
///
/// Local inode/device identities remain private guards. They do not enter the
/// semantic manifest: copying to another inode must still allow convergence.
#[derive(Debug)]
pub struct NativeDirectorySnapshot {
    root: NativeRoot,
    manifest: DirectoryManifest,
    root_stamp: Stamp,
    guards: BTreeMap<DirectoryPath, Stamp>,
    total_bytes: u64,
}

impl NativeDirectorySnapshot {
    /// Complete content-only inventory captured by this scan.
    #[must_use]
    pub fn manifest(&self) -> &DirectoryManifest {
        &self.manifest
    }

    /// Absolute retained root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root.path
    }

    /// Total logical file bytes hashed.
    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }
}

/// An opaque single-use plan prepared from actual native inventories.
///
/// A cloned or deserialized BidirectionalSyncPlan is never accepted as apply
/// authority. Review preview() and retain this value for application.
/// Preparation is read-only and may return a preview containing conflicts.
#[derive(Debug)]
pub struct PreparedNativeDirectorySync {
    local: NativeDirectorySnapshot,
    remote: NativeDirectorySnapshot,
    limits: NativeDirectoryLimits,
    preview: BidirectionalSyncPlan,
    plan_id: String,
}

impl PreparedNativeDirectorySync {
    /// Read-only decisions from the existing three-way planner.
    #[must_use]
    pub fn preview(&self) -> &BidirectionalSyncPlan {
        &self.preview
    }

    /// Identity binding the review to these roots and captured contents.
    #[must_use]
    pub fn plan_id(&self) -> &str {
        &self.plan_id
    }

    /// Actual local inventory used for this review.
    #[must_use]
    pub fn local(&self) -> &NativeDirectorySnapshot {
        &self.local
    }

    /// Actual remote inventory used for this review.
    #[must_use]
    pub fn remote(&self) -> &NativeDirectorySnapshot {
        &self.remote
    }

    /// Work bounds retained for revalidation and application.
    #[must_use]
    pub const fn limits(&self) -> NativeDirectoryLimits {
        self.limits
    }
}

/// Hash an actual directory tree through owned cancellable blocking work.
///
/// The root must be an absolute directory path without symlink components.
/// Names must be UTF-8 and canonical, without backslashes. Symlinks, multiply
/// linked files, special files, and mounted cross-filesystem descendants are
/// refused. Files are hashed incrementally with checkpoints between chunks.
/// Changed entries refuse the scan; incomplete manifests are never returned.
///
/// # Errors
///
/// Refuses missing capabilities, unsupported entries, exceeded limits,
/// replacement or instability of a root or entry, and cancellation.
pub async fn scan_native_directory(
    cx: &Cx,
    root: impl Into<PathBuf>,
    limits: NativeDirectoryLimits,
) -> Result<NativeDirectorySnapshot, NativeDirectoryError> {
    limits.validate()?;
    let root = root.into();
    cx.scoped_fs()
        .run_io(move |worker| {
            Ok(NativeRoot::open(&root).and_then(|root| scan_root(&worker, root, limits)))
        })
        .await
        .map_err(NativeDirectoryError::Runtime)?
}

/// Capture two actual trees and prepare a three-way reconciliation.
///
/// Baseline is the last successfully verified common content-only inventory,
/// or an empty default-rules inventory for first synchronization. Roots must
/// be distinct, nonoverlapping, and exclusively owned during prepare/apply.
/// No inode identity is imported from the baseline.
///
/// # Errors
///
/// Refuses invalid limits, unsupported baseline semantics, overlapping roots,
/// unstable or unsupported entries, and planner validation failures.
pub async fn prepare_native_directory_sync(
    cx: &Cx,
    baseline: DirectoryManifest,
    local_root: impl Into<PathBuf>,
    remote_root: impl Into<PathBuf>,
    limits: NativeDirectoryLimits,
) -> Result<PreparedNativeDirectorySync, NativeDirectoryError> {
    limits.validate()?;
    validate_profile(&baseline, limits)?;
    let local_path = local_root.into();
    let remote_path = remote_root.into();
    cx.scoped_fs()
        .run_io(move |worker| {
            Ok((|| {
                let local_root = NativeRoot::open(&local_path)?;
                let remote_root = NativeRoot::open(&remote_path)?;
                disjoint_roots(&local_root, &remote_root)?;
                let local = scan_root(&worker, local_root, limits)?;
                let remote = scan_root(&worker, remote_root, limits)?;
                disjoint_inventories(&local, &remote)?;
                // Local may have changed while remote was being scanned.
                local.root.revalidate()?;
                revalidate_stamps(&worker, &local)?;
                let preview =
                    plan_bidirectional_sync(&baseline, &local.manifest, &remote.manifest)
                        .map_err(NativeDirectoryError::Plan)?;
                let mut identity = Sha256::new();
                identity.update(b"asupersync.native-directory-plan.v1\0");
                identity.update(baseline.tree_root());
                for snapshot in [&local, &remote] {
                    identity.update(snapshot.root.path.as_os_str().as_encoded_bytes());
                    identity.update([0]);
                    identity.update(snapshot.root.identity.device.to_be_bytes());
                    identity.update(snapshot.root.identity.inode.to_be_bytes());
                    identity.update(snapshot.manifest.tree_root());
                }
                Ok(PreparedNativeDirectorySync {
                    local,
                    remote,
                    limits,
                    preview,
                    plan_id: hex::encode(identity.finalize()),
                })
            })())
        })
        .await
        .map_err(NativeDirectoryError::Runtime)?
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Identity {
    device: u64,
    inode: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Stamp {
    identity: Identity,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl Stamp {
    fn metadata(metadata: &Metadata) -> Self {
        Self {
            identity: Identity {
                device: metadata.dev(),
                inode: metadata.ino(),
            },
            mode: metadata.mode(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            links: metadata.nlink(),
            size: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }

    // Linux libc field widths vary between 32-bit and 64-bit targets.
    #[allow(clippy::useless_conversion)]
    fn stat(stat: &FileStat, path: &Path) -> Result<Self, NativeDirectoryError> {
        Ok(Self {
            identity: Identity {
                device: u64::from(stat.st_dev),
                inode: u64::from(stat.st_ino),
            },
            mode: stat.st_mode,
            uid: stat.st_uid,
            gid: stat.st_gid,
            links: u64::from(stat.st_nlink),
            size: u64::try_from(stat.st_size)
                .map_err(|_| refused(path, "negative filesystem object size"))?,
            modified: (i64::from(stat.st_mtime), i64::from(stat.st_mtime_nsec)),
            changed: (i64::from(stat.st_ctime), i64::from(stat.st_ctime_nsec)),
        })
    }

    fn kind(self, path: &Path) -> Result<DirectoryEntryKind, NativeDirectoryError> {
        let kind = SFlag::from_bits_truncate(self.mode) & SFlag::S_IFMT;
        if kind == SFlag::S_IFDIR {
            Ok(DirectoryEntryKind::Directory)
        } else if kind == SFlag::S_IFREG && self.links == 1 {
            Ok(DirectoryEntryKind::File)
        } else {
            Err(refused(
                path,
                "only directories and singly linked regular files are supported",
            ))
        }
    }
}

#[derive(Debug)]
struct NativeRoot {
    path: PathBuf,
    file: File,
    identity: Identity,
}

impl NativeRoot {
    fn open(path: &Path) -> Result<Self, NativeDirectoryError> {
        if !path.is_absolute() || path == Path::new("/") {
            return Err(refused(path, "root must be an absolute non-root directory"));
        }
        let mut normalized = PathBuf::from("/");
        let mut directory = File::from(
            open(Path::new("/"), directory_flags(), Mode::empty())
                .map_err(|error| os_error(path, error))?,
        );
        for component in path.components() {
            match component {
                Component::RootDir => {}
                Component::Normal(name) => {
                    let next = File::from(
                        openat(&directory, Path::new(name), directory_flags(), Mode::empty())
                            .map_err(|error| os_error(path, error))?,
                    );
                    normalized.push(name);
                    directory = next;
                }
                _ => return Err(refused(path, "root contains a noncanonical component")),
            }
        }
        if normalized == Path::new("/") {
            return Err(refused(path, "filesystem root is not a synchronization root"));
        }
        let stamp = metadata_stamp(&directory, &normalized)?;
        Ok(Self {
            path: normalized,
            file: directory,
            identity: stamp.identity,
        })
    }

    fn revalidate(&self) -> Result<(), NativeDirectoryError> {
        let reopened = Self::open(&self.path)?;
        if reopened.identity != self.identity
            || metadata_stamp(&self.file, &self.path)?.identity != self.identity
        {
            return Err(changed(&self.path));
        }
        Ok(())
    }
}

fn directory_flags() -> OFlag {
    OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW
}

fn file_flags() -> OFlag {
    OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK
}

fn disjoint_roots(left: &NativeRoot, right: &NativeRoot) -> Result<(), NativeDirectoryError> {
    if left.identity == right.identity
        || left.path.starts_with(&right.path)
        || right.path.starts_with(&left.path)
    {
        return Err(refused(&right.path, "synchronization roots overlap"));
    }
    Ok(())
}

fn disjoint_inventories(
    local: &NativeDirectorySnapshot,
    remote: &NativeDirectorySnapshot,
) -> Result<(), NativeDirectoryError> {
    let mut local_objects: BTreeSet<_> = local.guards.values().map(|stamp| stamp.identity).collect();
    local_objects.insert(local.root.identity);
    if local_objects.contains(&remote.root.identity)
        || remote.guards.values().any(|stamp| local_objects.contains(&stamp.identity))
    {
        return Err(refused(&remote.root.path, "synchronization roots alias filesystem objects"));
    }
    Ok(())
}

fn scan_root(
    cx: &Cx,
    root: NativeRoot,
    limits: NativeDirectoryLimits,
) -> Result<NativeDirectorySnapshot, NativeDirectoryError> {
    checkpoint(cx)?;
    root.revalidate()?;
    let root_stamp = metadata_stamp(&root.file, &root.path)?;
    let mut manifest = DirectoryManifest::new(PathNormalizationRules::default());
    let mut guards = BTreeMap::new();
    let mut total_bytes = 0;
    scan_children(
        cx, &root, &root.file, "", 0, limits, &mut manifest, &mut guards, &mut total_bytes,
    )?;
    if metadata_stamp(&root.file, &root.path)? != root_stamp {
        return Err(changed(&root.path));
    }
    root.revalidate()?;
    let snapshot = NativeDirectorySnapshot {
        root, manifest, root_stamp, guards, total_bytes,
    };
    revalidate_stamps(cx, &snapshot)?;
    Ok(snapshot)
}

#[allow(clippy::too_many_arguments)]
fn scan_children(
    cx: &Cx,
    root: &NativeRoot,
    directory: &File,
    prefix: &str,
    depth: usize,
    limits: NativeDirectoryLimits,
    manifest: &mut DirectoryManifest,
    guards: &mut BTreeMap<DirectoryPath, Stamp>,
    total_bytes: &mut u64,
) -> Result<(), NativeDirectoryError> {
    checkpoint(cx)?;
    let display = root.path.join(prefix);
    let before = metadata_stamp(directory, &display)?;
    let mut entries = Dir::openat(directory, ".", directory_flags(), Mode::empty())
        .map_err(|error| os_error(&display, error))?;
    for item in entries.iter() {
        checkpoint(cx)?;
        let item = item.map_err(|error| os_error(&display, error))?;
        let name = item.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        let name = std::str::from_utf8(name)
            .map_err(|_| refused(&display, "directory entry name is not UTF-8"))?;
        if name.contains('\\') || name.contains('/') || name.is_empty() {
            return Err(refused(&display, "directory entry name is not canonical"));
        }
        let relative = if prefix.is_empty() { name.to_owned() } else { format!("{prefix}/{name}") };
        let path = DirectoryPath::normalize(&relative, PathNormalizationRules::default())
            .map_err(NativeDirectoryError::Manifest)?;
        if path.as_str() != relative {
            return Err(refused(&display, "directory entry path is not canonical"));
        }
        let display = root.path.join(&relative);
        if depth >= limits.max_depth {
            return Err(limit(&display, "max_depth"));
        }
        if manifest.entries.len() >= limits.max_entries {
            return Err(limit(&display, "max_entries"));
        }
        let observed = stat_at(directory, name, &display)?.ok_or_else(|| changed(&display))?;
        if observed.identity.device != root.identity.device {
            return Err(refused(&display, "mounted descendant crosses the root filesystem"));
        }
        let kind = observed.kind(&display)?;
        let child = File::from(
            openat(
                directory,
                name,
                if kind == DirectoryEntryKind::Directory { directory_flags() } else { file_flags() },
                Mode::empty(),
            )
            .map_err(|error| os_error(&display, error))?,
        );
        if metadata_stamp(&child, &display)? != observed {
            return Err(changed(&display));
        }
        let (content_id, metadata) = if kind == DirectoryEntryKind::File {
            if observed.size > limits.max_file_bytes {
                return Err(limit(&display, "max_file_bytes"));
            }
            *total_bytes = total_bytes
                .checked_add(observed.size)
                .filter(|total| *total <= limits.max_total_bytes)
                .ok_or_else(|| limit(&display, "max_total_bytes"))?;
            (
                Some(hash_file(cx, &child, observed, &display, limits)?),
                DirectoryEntryMetadata {
                    size_bytes: Some(observed.size),
                    ..DirectoryEntryMetadata::default()
                },
            )
        } else {
            (None, DirectoryEntryMetadata::default())
        };
        manifest
            .insert(DirectoryManifestEntry::new(path.clone(), kind, content_id, metadata))
            .map_err(NativeDirectoryError::Manifest)?;
        guards.insert(path, observed);
        if kind == DirectoryEntryKind::Directory {
            scan_children(
                cx, root, &child, &relative, depth + 1, limits, manifest, guards, total_bytes,
            )?;
        }
        if stat_at(directory, name, &display)? != Some(observed) {
            return Err(changed(&display));
        }
    }
    if metadata_stamp(directory, &display)? != before {
        return Err(changed(&display));
    }
    Ok(())
}

fn hash_file(
    cx: &Cx,
    file: &File,
    expected: Stamp,
    path: &Path,
    limits: NativeDirectoryLimits,
) -> Result<String, NativeDirectoryError> {
    let mut file = file;
    let mut hash = Sha256::new();
    let mut buffer = vec![0; limits.buffer_bytes];
    let mut total = 0_u64;
    loop {
        checkpoint(cx)?;
        let read = file.read(&mut buffer).map_err(|source| io_error(path, source))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(read).map_err(|_| limit(path, "max_file_bytes"))?)
            .filter(|total| *total <= expected.size && *total <= limits.max_file_bytes)
            .ok_or_else(|| changed(path))?;
        hash.update(&buffer[..read]);
    }
    if total != expected.size || metadata_stamp(file, path)? != expected {
        return Err(changed(path));
    }
    Ok(format!("sha256:{}", hex::encode(hash.finalize())))
}

fn validate_profile(
    manifest: &DirectoryManifest,
    limits: NativeDirectoryLimits,
) -> Result<(), NativeDirectoryError> {
    if manifest.path_rules != PathNormalizationRules::default() {
        return Err(refused(Path::new(""), "native content profile requires default path rules"));
    }
    if manifest.entries.len() > limits.max_entries {
        return Err(limit(Path::new(""), "max_entries"));
    }
    let mut total_bytes = 0_u64;
    for (path, entry) in &manifest.entries {
        let display = Path::new(path.as_str());
        if path.as_str().contains('\\') || path.as_str().split('/').count() > limits.max_depth {
            return Err(refused(display, "baseline path exceeds the native path profile"));
        }
        let expected_metadata = match entry.kind {
            DirectoryEntryKind::File => {
                let size = entry.metadata.size_bytes.ok_or_else(|| {
                    refused(display, "native file baseline requires size_bytes")
                })?;
                if size > limits.max_file_bytes {
                    return Err(limit(display, "max_file_bytes"));
                }
                total_bytes = total_bytes
                    .checked_add(size)
                    .filter(|total| *total <= limits.max_total_bytes)
                    .ok_or_else(|| limit(display, "max_total_bytes"))?;
                let digest = entry.content_id.as_deref().unwrap_or_default();
                if !digest.starts_with("sha256:")
                    || digest.len() != 71
                    || !digest.as_bytes()[7..].iter()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
                {
                    return Err(refused(display, "native file baseline requires a SHA-256 content id"));
                }
                DirectoryEntryMetadata { size_bytes: Some(size), ..DirectoryEntryMetadata::default() }
            }
            DirectoryEntryKind::Directory if entry.content_id.is_none() => {
                DirectoryEntryMetadata::default()
            }
            _ => return Err(refused(display, "baseline kind is outside the native content profile")),
        };
        if entry.metadata != expected_metadata || !entry.caveats.is_empty() {
            return Err(refused(display, "native content profile cannot preserve baseline metadata"));
        }
    }
    // Also checks forged map keys, missing ancestors, and noncanonical paths.
    plan_bidirectional_sync(manifest, manifest, manifest).map_err(NativeDirectoryError::Plan)?;
    Ok(())
}

fn revalidate_stamps(
    cx: &Cx,
    snapshot: &NativeDirectorySnapshot,
) -> Result<(), NativeDirectoryError> {
    if metadata_stamp(&snapshot.root.file, &snapshot.root.path)? != snapshot.root_stamp {
        return Err(changed(&snapshot.root.path));
    }
    for (path, expected) in &snapshot.guards {
        checkpoint(cx)?;
        let (parent, name) = open_parent(&snapshot.root, path)?;
        let display = snapshot.root.path.join(path.as_str());
        if stat_at(&parent, name, &display)? != Some(*expected) {
            return Err(changed(&display));
        }
    }
    Ok(())
}

fn open_parent<'a>(
    root: &NativeRoot,
    path: &'a DirectoryPath,
) -> Result<(File, &'a str), NativeDirectoryError> {
    let mut components = path.as_str().split('/').peekable();
    let mut directory = root.file.try_clone().map_err(|source| io_error(&root.path, source))?;
    let mut display = root.path.clone();
    while let Some(name) = components.next() {
        if name.is_empty() || name == "." || name == ".." || name.contains('\\') {
            return Err(refused(&display, "relative path is not canonical"));
        }
        if components.peek().is_none() {
            return Ok((directory, name));
        }
        display.push(name);
        directory = File::from(
            openat(&directory, name, directory_flags(), Mode::empty())
                .map_err(|error| os_error(&display, error))?,
        );
    }
    Err(refused(&root.path, "relative path is empty"))
}

fn stat_at(
    directory: &File,
    name: &str,
    path: &Path,
) -> Result<Option<Stamp>, NativeDirectoryError> {
    match fstatat(directory, name, AtFlags::AT_SYMLINK_NOFOLLOW) {
        Ok(stat) => Stamp::stat(&stat, path).map(Some),
        Err(Errno::ENOENT) => Ok(None),
        Err(error) => Err(os_error(path, error)),
    }
}

fn metadata_stamp(file: &File, path: &Path) -> Result<Stamp, NativeDirectoryError> {
    file.metadata()
        .map(|metadata| Stamp::metadata(&metadata))
        .map_err(|source| io_error(path, source))
}

fn checkpoint(cx: &Cx) -> Result<(), NativeDirectoryError> {
    cx.checkpoint().map_err(NativeDirectoryError::Checkpoint)
}

fn refused(path: &Path, reason: &'static str) -> NativeDirectoryError {
    NativeDirectoryError::Refused { path: path.to_owned(), reason }
}

fn changed(path: &Path) -> NativeDirectoryError {
    NativeDirectoryError::Changed { path: path.to_owned() }
}

fn limit(path: &Path, limit: &'static str) -> NativeDirectoryError {
    NativeDirectoryError::Limit { path: path.to_owned(), limit }
}

fn io_error(path: &Path, source: io::Error) -> NativeDirectoryError {
    NativeDirectoryError::Io { path: path.to_owned(), source }
}

fn os_error(path: &Path, source: Errno) -> NativeDirectoryError {
    io_error(path, io::Error::from_raw_os_error(source as i32))
}

#[cfg(test)]
mod tests;
