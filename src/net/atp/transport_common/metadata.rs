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
//! Unix and Windows capture the metadata their native filesystems can represent.
//! Targets without native metadata support retain the portable bare-entry
//! fallback. Fields the receiver cannot apply (for example `uid`/`gid` without
//! privilege) are reported as skipped, never fatal.

use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use crate::atp::object::MetadataPolicy;
use crate::atp::safety::validate_portable_path_component;
use crate::util::entropy::{EntropySource, OsEntropy};

use super::streaming::{StreamingError, hex_encode};

#[cfg(any(windows, test))]
const WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

#[cfg(windows)]
const WINDOWS_IO_REPARSE_TAG_SYMLINK: u32 = 0xa000_000c;

const WINDOWS_SETTABLE_ATTRIBUTE_MASK: u32 =
    0x0000_0001 | 0x0000_0002 | 0x0000_0004 | 0x0000_0020 | 0x0000_2000;

#[cfg(any(windows, test))]
#[inline]
const fn windows_attributes_contain_reparse_point(attributes: u32) -> bool {
    attributes & WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT != 0
}

/// Return whether `path` is a symbolic link or a Windows reparse point without
/// following it.
///
/// Windows junctions and mount-point reparse records are not reported by
/// `Metadata::is_symlink`, but following either while walking a source or
/// committing a destination can escape the selected transfer root. ATP treats
/// every reparse point as link-like until a tag-specific policy is implemented.
///
/// # Errors
///
/// Returns the underlying `symlink_metadata` error when the path cannot be
/// inspected.
pub async fn path_is_link_or_reparse(path: &Path) -> std::io::Result<bool> {
    let path = path.to_path_buf();
    crate::runtime::spawn_blocking(move || path_is_link_or_reparse_sync(&path)).await
}

/// Synchronous counterpart of [`path_is_link_or_reparse`] for filesystem walks
/// that already run outside the async runtime.
///
/// # Errors
///
/// Returns the underlying `symlink_metadata` error when the path cannot be
/// inspected.
pub fn path_is_link_or_reparse_sync(path: &Path) -> std::io::Result<bool> {
    classify_path_link_sync(path).map(|kind| !matches!(kind, PathLinkKind::NotLink))
}

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

/// File-versus-directory semantics required when creating a Windows symlink.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SymlinkTargetKind {
    /// File-target symlink semantics.
    File,
    /// Directory-target symlink semantics.
    Directory,
}

impl SymlinkTargetKind {
    const fn tag(self) -> u8 {
        match self {
            Self::File => 0,
            Self::Directory => 1,
        }
    }
}

/// Lstat-level classification used by source walks and destination guards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathLinkKind {
    /// A regular filesystem entry rather than a link or reparse point.
    NotLink,
    /// A real symbolic link with its declared file-versus-directory type.
    Symlink(SymlinkTargetKind),
    /// A Windows junction, mount point, or other unsupported reparse record.
    UnsupportedReparse,
}

/// Classify a path without following it.
///
/// # Errors
///
/// Returns the underlying metadata or Windows reparse-tag inspection error.
pub async fn classify_path_link(path: &Path) -> io::Result<PathLinkKind> {
    let path = path.to_path_buf();
    crate::runtime::spawn_blocking(move || classify_path_link_sync(&path)).await
}

/// Synchronous counterpart of [`classify_path_link`].
///
/// # Errors
///
/// Returns the underlying metadata or Windows reparse-tag inspection error.
pub fn classify_path_link_sync(path: &Path) -> io::Result<PathLinkKind> {
    let metadata = std::fs::symlink_metadata(path)?;

    #[cfg(windows)]
    {
        use std::os::windows::fs::{FileTypeExt, MetadataExt};

        let attributes = metadata.file_attributes();
        if !windows_attributes_contain_reparse_point(attributes) {
            return Ok(PathLinkKind::NotLink);
        }
        if windows_reparse_tag(path)? != WINDOWS_IO_REPARSE_TAG_SYMLINK {
            return Ok(PathLinkKind::UnsupportedReparse);
        }
        let file_type = metadata.file_type();
        if file_type.is_symlink_dir() {
            return Ok(PathLinkKind::Symlink(SymlinkTargetKind::Directory));
        }
        if file_type.is_symlink_file() {
            return Ok(PathLinkKind::Symlink(SymlinkTargetKind::File));
        }
        return Ok(PathLinkKind::UnsupportedReparse);
    }

    #[cfg(not(windows))]
    {
        if metadata.file_type().is_symlink() {
            let kind = std::fs::metadata(path)
                .ok()
                .map_or(SymlinkTargetKind::File, |target| {
                    if target.is_dir() {
                        SymlinkTargetKind::Directory
                    } else {
                        SymlinkTargetKind::File
                    }
                });
            Ok(PathLinkKind::Symlink(kind))
        } else {
            Ok(PathLinkKind::NotLink)
        }
    }
}

#[cfg(windows)]
#[allow(unsafe_code)] // Win32 tag query over an RAII-owned std::fs::File handle.
fn windows_reparse_tag(path: &Path) -> io::Result<u32> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_TAG_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        FileAttributeTagInfo, GetFileInformationByHandleEx,
    };

    let mut options = std::fs::OpenOptions::new();
    let file = options
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;

    let mut info = FILE_ATTRIBUTE_TAG_INFO::default();
    let queried = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileAttributeTagInfo,
            std::ptr::addr_of_mut!(info).cast::<std::ffi::c_void>(),
            u32::try_from(std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>()).unwrap_or(u32::MAX),
        )
    };
    if queried == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(info.ReparseTag)
}

/// Path interpretation used by a captured symlink target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SymlinkTargetSemantics {
    /// A portable, relative, forward-slash path.
    PortableRelative,
    /// A Unix-native target that is not portable across operating systems.
    Unix,
    /// A Windows-native target that is not portable across operating systems.
    Windows,
}

impl SymlinkTargetSemantics {
    const fn tag(self) -> u8 {
        match self {
            Self::PortableRelative => 0,
            Self::Unix => 1,
            Self::Windows => 2,
        }
    }
}

/// Versioned symlink target information carried by metadata commitment v2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymlinkTargetInfo {
    /// Declared Windows link type. POSIX dangling links may leave this unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<SymlinkTargetKind>,
    /// Target path interpretation on the sender.
    pub semantics: SymlinkTargetSemantics,
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
    /// Safe Win32 file-attribute bits (read-only, hidden, system, archive, and
    /// not-content-indexed). Structural/storage-management bits are never replayed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub windows_attributes: Option<u32>,
    /// Symlink target (forward-slash or platform path text) for `Symlink` kinds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symlink_target: Option<String>,
    /// Explicit target semantics/type for portable cross-platform recreation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symlink_target_info: Option<SymlinkTargetInfo>,
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
            && self.windows_attributes.is_none()
            && self.symlink_target.is_none()
            && self.symlink_target_info.is_none()
            && self.hardlink_target.is_none()
            && self.xattrs.is_empty()
    }

    /// Append this entry's canonical, domain-separated encoding to `hasher`. The
    /// presence byte before each optional field keeps "absent" distinct from a
    /// zero value so the commitment is collision-resistant across schemas.
    fn hash_v1_into(&self, rel_path: &str, hasher: &mut Sha256) {
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

    fn hash_v2_into(&self, rel_path: &str, hasher: &mut Sha256) {
        self.hash_v1_into(rel_path, hasher);
        hash_opt_u32(hasher, self.windows_attributes);
        match &self.symlink_target_info {
            Some(info) => {
                hasher.update([1]);
                match info.kind {
                    Some(kind) => hasher.update([1, kind.tag()]),
                    None => hasher.update([0]),
                }
                hasher.update([info.semantics.tag()]);
            }
            None => hasher.update([0]),
        }
    }
}

fn classify_symlink_target_semantics(target: &str) -> SymlinkTargetSemantics {
    if validate_portable_symlink_target_syntax(target).is_ok() {
        SymlinkTargetSemantics::PortableRelative
    } else if cfg!(windows) {
        SymlinkTargetSemantics::Windows
    } else {
        SymlinkTargetSemantics::Unix
    }
}

fn validate_portable_symlink_target_syntax(target: &str) -> Result<(), String> {
    if target.is_empty()
        || target.starts_with('/')
        || target.starts_with('\\')
        || target.contains('\\')
    {
        return Err(target.to_string());
    }
    for component in target.split('/') {
        if component.is_empty() {
            return Err(target.to_string());
        }
        if matches!(component, "." | "..") {
            continue;
        }
        validate_portable_path_component(component).map_err(|_| target.to_string())?;
    }
    Ok(())
}

fn validate_contained_symlink_target(rel_path: &str, target: &str) -> Result<(), String> {
    validate_portable_symlink_target_syntax(target)?;
    let mut resolved = rel_path.split('/').collect::<Vec<_>>();
    if resolved.pop().is_none() {
        return Err("symlink entry path is empty".to_string());
    }
    for component in target.split('/') {
        match component {
            "." => {}
            ".." => {
                if resolved.pop().is_none() {
                    return Err("symlink target escapes the transfer root".to_string());
                }
            }
            component => resolved.push(component),
        }
    }
    Ok(())
}

/// Validate symlink metadata before any receiver filesystem mutation.
///
/// ATP v2 accepts only contained portable-relative targets. Native absolute,
/// parent-traversing, drive/UNC, backslash, device, and ambiguous targets fail
/// closed rather than changing meaning across operating systems.
pub fn validate_symlink_metadata_for_receive(
    rel_path: &str,
    metadata: &EntryMetadata,
) -> Result<(), String> {
    if let Some(attributes) = metadata.windows_attributes {
        if attributes & !WINDOWS_SETTABLE_ATTRIBUTE_MASK != 0 {
            return Err("metadata declares unsafe Windows attribute bits".to_string());
        }
        if matches!(metadata.file_kind, FileKind::Symlink) {
            return Err("symlink metadata must not declare Windows attributes".to_string());
        }
    }
    if !matches!(metadata.file_kind, FileKind::Symlink) {
        if metadata.symlink_target.is_some() || metadata.symlink_target_info.is_some() {
            return Err("non-symlink metadata declares a symlink target".to_string());
        }
        return Ok(());
    }

    let target = metadata
        .symlink_target
        .as_deref()
        .filter(|target| !target.is_empty())
        .ok_or_else(|| "symlink metadata is missing its target".to_string())?;
    let Some(info) = &metadata.symlink_target_info else {
        #[cfg(windows)]
        return Err("legacy symlink metadata has no explicit Windows target type".to_string());
        #[cfg(not(windows))]
        return validate_contained_symlink_target(rel_path, target);
    };
    if !matches!(info.semantics, SymlinkTargetSemantics::PortableRelative) {
        return Err("symlink target uses non-portable native path semantics".to_string());
    }
    validate_contained_symlink_target(rel_path, target)
        .map_err(|error| format!("symlink target is not contained and portable: {error}"))?;
    #[cfg(windows)]
    if info.kind.is_none() {
        return Err("symlink target type is ambiguous on Windows".to_string());
    }
    Ok(())
}

/// Validate an entry's committed metadata against receiver policy.
///
/// # Errors
///
/// Returns a field-specific rejection before the receiver creates staging or
/// destination filesystem state.
pub fn validate_entry_metadata_for_receive(
    rel_path: &str,
    metadata: &EntryMetadata,
    policy: &MetadataPolicy,
) -> Result<(), String> {
    validate_symlink_metadata_for_receive(rel_path, metadata)?;
    if metadata.unix_mode.is_some() && !policy.preserve_unix_permissions {
        return Err("Unix permissions are denied by receiver metadata policy".to_string());
    }
    if (metadata.mtime_unix_secs.is_some() || metadata.mtime_nanos.is_some())
        && !policy.preserve_timestamps
    {
        return Err("timestamps are denied by receiver metadata policy".to_string());
    }
    if (metadata.uid.is_some() || metadata.gid.is_some()) && !policy.record_platform_metadata {
        return Err("platform ownership is denied by receiver metadata policy".to_string());
    }
    if metadata.windows_attributes.is_some() && !policy.preserve_windows_attributes {
        return Err("Windows attributes are denied by receiver metadata policy".to_string());
    }
    if !metadata.xattrs.is_empty() && !policy.preserve_extended_attributes {
        return Err("extended attributes are denied by receiver metadata policy".to_string());
    }
    if matches!(metadata.file_kind, FileKind::Symlink) && !policy.preserve_symlinks {
        return Err("symlinks are denied by receiver metadata policy".to_string());
    }
    Ok(())
}

/// Map committed metadata to the explicit filesystem symlink kind.
pub fn filesystem_symlink_kind(
    rel_path: &str,
    metadata: &EntryMetadata,
) -> Result<crate::fs::SymlinkKind, String> {
    validate_symlink_metadata_for_receive(rel_path, metadata)?;
    match metadata
        .symlink_target_info
        .as_ref()
        .and_then(|info| info.kind)
    {
        Some(SymlinkTargetKind::Directory) => Ok(crate::fs::SymlinkKind::Directory),
        Some(SymlinkTargetKind::File) => Ok(crate::fs::SymlinkKind::File),
        None if cfg!(not(windows)) => Ok(crate::fs::SymlinkKind::File),
        None => Err("symlink target type is ambiguous on Windows".to_string()),
    }
}

static SYMLINK_COMMIT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy)]
enum ReplaceableLeafKind {
    RegularFile,
    Symlink(crate::fs::SymlinkKind),
}

/// Create and transactionally install a typed symbolic link.
///
/// The new link is created at a unique sibling before the existing leaf is
/// moved aside. A failed final rename rolls the old leaf back into place.
/// Existing real directories and unsupported reparse points fail closed.
///
/// # Errors
///
/// Returns a validation or filesystem error without following the destination
/// leaf.
pub async fn commit_symlink_transactionally(
    rel_path: &str,
    out_path: &Path,
    metadata: &EntryMetadata,
) -> Result<(), StreamingError> {
    let target = metadata.symlink_target.as_deref().ok_or_else(|| {
        StreamingError::new(format!(
            "{rel_path}: symlink metadata is missing its target"
        ))
    })?;
    let kind = filesystem_symlink_kind(rel_path, metadata)
        .map_err(|error| StreamingError::new(format!("{rel_path}: {error}")))?;
    let existing = replaceable_leaf_kind(out_path).await?;

    let mut temporary = None;
    for _ in 0..32 {
        let candidate = unique_symlink_sibling(out_path, "new")?;
        match crate::fs::symlink_typed(target, &candidate, kind).await {
            Ok(()) => {
                temporary = Some(candidate);
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(StreamingError::new(format!(
                    "{}: create typed symlink: {error}",
                    out_path.display()
                )));
            }
        }
    }
    let temporary = temporary.ok_or_else(|| {
        StreamingError::new(format!(
            "{}: unable to allocate unique symlink staging leaf",
            out_path.display()
        ))
    })?;

    let backup = if existing.is_some() {
        let backup = unique_absent_symlink_sibling(out_path, "backup").await?;
        if let Err(error) = crate::fs::rename(out_path, &backup).await {
            let _ = remove_typed_symlink(&temporary, kind).await;
            return Err(StreamingError::new(format!(
                "{}: move existing leaf to backup: {error}",
                out_path.display()
            )));
        }
        Some(backup)
    } else {
        None
    };

    if let Err(error) = crate::fs::rename(&temporary, out_path).await {
        let _ = remove_typed_symlink(&temporary, kind).await;
        let rollback = if let Some(backup) = &backup {
            crate::fs::rename(backup, out_path).await
        } else {
            Ok(())
        };
        let rollback = rollback.err().map_or_else(String::new, |rollback| {
            format!("; rollback failed: {rollback}")
        });
        return Err(StreamingError::new(format!(
            "{}: install typed symlink: {error}{rollback}",
            out_path.display()
        )));
    }

    if let (Some(backup), Some(existing)) = (backup, existing) {
        remove_replaceable_leaf(&backup, existing).await?;
    }
    Ok(())
}

async fn replaceable_leaf_kind(path: &Path) -> Result<Option<ReplaceableLeafKind>, StreamingError> {
    let link_kind = match classify_path_link(path).await {
        Ok(kind) => kind,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(StreamingError::new(format!("{}: {error}", path.display())));
        }
    };
    match link_kind {
        PathLinkKind::Symlink(SymlinkTargetKind::File) => Ok(Some(ReplaceableLeafKind::Symlink(
            crate::fs::SymlinkKind::File,
        ))),
        PathLinkKind::Symlink(SymlinkTargetKind::Directory) => Ok(Some(
            ReplaceableLeafKind::Symlink(crate::fs::SymlinkKind::Directory),
        )),
        PathLinkKind::UnsupportedReparse => Err(StreamingError::new(format!(
            "{}: destination leaf is an unsupported reparse point",
            path.display()
        ))),
        PathLinkKind::NotLink => {
            let metadata = crate::fs::symlink_metadata(path)
                .await
                .map_err(|error| StreamingError::new(format!("{}: {error}", path.display())))?;
            if metadata.is_dir() {
                Err(StreamingError::new(format!(
                    "{}: refusing to replace a real directory with a symlink",
                    path.display()
                )))
            } else {
                Ok(Some(ReplaceableLeafKind::RegularFile))
            }
        }
    }
}

fn unique_symlink_sibling(path: &Path, label: &str) -> Result<PathBuf, StreamingError> {
    let parent = path.parent().ok_or_else(|| {
        StreamingError::new(format!(
            "{}: symlink destination has no parent",
            path.display()
        ))
    })?;
    let sequence = SYMLINK_COMMIT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let nonce = OsEntropy.next_u64();
    Ok(parent.join(format!(
        ".atp-sym-{label}-{}-{nonce:016x}-{sequence}",
        std::process::id()
    )))
}

async fn unique_absent_symlink_sibling(
    path: &Path,
    label: &str,
) -> Result<PathBuf, StreamingError> {
    for _ in 0..32 {
        let candidate = unique_symlink_sibling(path, label)?;
        match crate::fs::symlink_metadata(&candidate).await {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(candidate),
            Ok(_) => {}
            Err(error) => {
                return Err(StreamingError::new(format!(
                    "{}: inspect backup candidate: {error}",
                    candidate.display()
                )));
            }
        }
    }
    Err(StreamingError::new(format!(
        "{}: unable to allocate unique symlink backup leaf",
        path.display()
    )))
}

async fn remove_typed_symlink(path: &Path, kind: crate::fs::SymlinkKind) -> io::Result<()> {
    #[cfg(windows)]
    if matches!(kind, crate::fs::SymlinkKind::Directory) {
        return crate::fs::remove_dir(path).await;
    }
    let _ = kind;
    crate::fs::remove_file(path).await
}

async fn remove_replaceable_leaf(
    path: &Path,
    kind: ReplaceableLeafKind,
) -> Result<(), StreamingError> {
    let mut result = match kind {
        ReplaceableLeafKind::RegularFile => crate::fs::remove_file(path).await,
        ReplaceableLeafKind::Symlink(kind) => remove_typed_symlink(path, kind).await,
    };
    #[cfg(windows)]
    if result
        .as_ref()
        .is_err_and(|error| error.kind() == io::ErrorKind::PermissionDenied)
        && matches!(kind, ReplaceableLeafKind::RegularFile)
        && set_windows_attributes(path, 0).is_ok()
    {
        result = crate::fs::remove_file(path).await;
    }
    result.map_err(|error| {
        StreamingError::new(format!(
            "{}: remove replaced backup: {error}",
            path.display()
        ))
    })
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
    let v2 = sorted.iter().any(|(_, metadata)| {
        metadata.symlink_target_info.is_some() || metadata.windows_attributes.is_some()
    });
    if v2 {
        hasher.update(b"asupersync.atp.metadata-commitment.v2\0");
    } else {
        hasher.update(b"asupersync.atp.metadata-commitment.v1\0");
    }
    hasher.update((sorted.len() as u64).to_be_bytes());
    for (rel_path, meta) in sorted {
        if v2 {
            meta.hash_v2_into(rel_path, &mut hasher);
        } else {
            meta.hash_v1_into(rel_path, &mut hasher);
        }
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
    #[cfg(any(unix, windows))]
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
/// fails closed so a policy change cannot silently turn a link into traversal of
/// the sender's filesystem namespace.
///
/// # Errors
///
/// Returns [`StreamingError`] if the path cannot be stat'd, a preserved symlink's
/// target cannot be read, or a symlink is denied by policy.
#[cfg(unix)]
pub async fn read_entry_metadata(
    abs_path: &Path,
    policy: &MetadataPolicy,
) -> Result<EntryMetadata, StreamingError> {
    let path_buf = abs_path.to_path_buf();
    let policy = policy.clone();
    crate::runtime::spawn_blocking(move || read_entry_metadata_sync(&path_buf, &policy)).await
}

/// Synchronous core of [`read_entry_metadata`].
///
/// One blocking-pool dispatch can capture a whole tree's metadata instead of
/// paying 2-3 pool round-trips per member (~4000 dispatches on a 2000-file tree
/// — the pass-1 tail measured in MATRIX-215; batched for br-asupersync-i7pdxb).
/// Callers already on the blocking pool (or batching many entries) call this
/// directly.
///
/// # Errors
///
/// Same contract as [`read_entry_metadata`].
#[cfg(unix)]
pub fn read_entry_metadata_sync(
    abs_path: &Path,
    policy: &MetadataPolicy,
) -> Result<EntryMetadata, StreamingError> {
    use std::os::unix::fs::MetadataExt;

    let lmeta = std::fs::symlink_metadata(abs_path)
        .map_err(|e| StreamingError::new(format!("{}: {e}", abs_path.display())))?;

    let mut meta = EntryMetadata::default();

    if lmeta.is_symlink() {
        if !policy.preserve_symlinks {
            return Err(StreamingError::new(format!(
                "{}: source symlink rejected by metadata policy",
                abs_path.display()
            )));
        }
        meta.file_kind = FileKind::Symlink;
        let target = std::fs::read_link(abs_path)
            .map_err(|e| StreamingError::new(format!("{}: {e}", abs_path.display())))?;
        let target = target.to_str().ok_or_else(|| {
            StreamingError::new(format!(
                "{}: symlink target is not valid Unicode",
                abs_path.display()
            ))
        })?;
        meta.symlink_target = Some(target.to_string());
        meta.symlink_target_info = Some(SymlinkTargetInfo {
            kind: std::fs::metadata(abs_path).ok().map(|target_metadata| {
                if target_metadata.is_dir() {
                    SymlinkTargetKind::Directory
                } else {
                    SymlinkTargetKind::File
                }
            }),
            semantics: classify_symlink_target_semantics(target),
        });
        // Mode/owner/time on a symlink itself are rarely meaningful and need
        // lchown/lutimes; ATP preserves the link + target, not link metadata.
        return Ok(meta);
    }

    let effective = lmeta;

    if effective.is_dir() {
        meta.file_kind = FileKind::Directory;
    } else if !effective.is_file() {
        use std::os::unix::fs::FileTypeExt;
        let ft = effective.file_type();
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

    if policy.preserve_unix_permissions {
        meta.unix_mode = Some(effective.mode() & 0o7777);
    }
    if policy.preserve_timestamps {
        meta.mtime_unix_secs = Some(effective.mtime());
        meta.mtime_nanos = u32::try_from(effective.mtime_nsec().rem_euclid(1_000_000_000)).ok();
    }
    if policy.record_platform_metadata {
        meta.uid = Some(effective.uid());
        meta.gid = Some(effective.gid());
    }
    if policy.preserve_extended_attributes {
        meta.xattrs = read_xattrs_best_effort_sync(abs_path, false);
    }
    Ok(meta)
}

#[cfg(unix)]
fn read_xattrs_best_effort_sync(abs_path: &Path, deref_symlink: bool) -> BTreeMap<String, Vec<u8>> {
    let listed = if deref_symlink {
        xattr::list_deref(abs_path)
    } else {
        xattr::list(abs_path)
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
            xattr::get_deref(abs_path, &name)
        } else {
            xattr::get(abs_path, &name)
        };
        if let Ok(Some(value)) = value {
            attrs.insert(name_str, value);
        }
    }
    attrs
}

#[cfg(windows)]
fn system_time_to_unix_parts(time: std::time::SystemTime) -> Option<(i64, u32)> {
    use std::time::UNIX_EPOCH;

    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => Some((
            i64::try_from(duration.as_secs()).ok()?,
            duration.subsec_nanos(),
        )),
        Err(error) => {
            let duration = error.duration();
            let seconds = i64::try_from(duration.as_secs()).ok()?;
            if duration.subsec_nanos() == 0 {
                Some((seconds.checked_neg()?, 0))
            } else {
                Some((
                    seconds.checked_neg()?.checked_sub(1)?,
                    1_000_000_000 - duration.subsec_nanos(),
                ))
            }
        }
    }
}

/// Windows capture: regular/directory metadata plus typed symbolic links.
///
/// # Errors
///
/// Returns [`StreamingError`] if the path cannot be inspected or is an
/// unsupported reparse point.
#[cfg(windows)]
pub async fn read_entry_metadata(
    abs_path: &Path,
    policy: &MetadataPolicy,
) -> Result<EntryMetadata, StreamingError> {
    let path_buf = abs_path.to_path_buf();
    let policy = policy.clone();
    crate::runtime::spawn_blocking(move || read_entry_metadata_sync(&path_buf, &policy)).await
}

/// Synchronous core of [`read_entry_metadata`] on Windows.
///
/// # Errors
///
/// Same contract as [`read_entry_metadata`].
#[cfg(windows)]
pub fn read_entry_metadata_sync(
    abs_path: &Path,
    policy: &MetadataPolicy,
) -> Result<EntryMetadata, StreamingError> {
    use std::os::windows::fs::MetadataExt;

    let link_kind = classify_path_link_sync(abs_path)
        .map_err(|error| StreamingError::new(format!("{}: {error}", abs_path.display())))?;
    if let PathLinkKind::UnsupportedReparse = link_kind {
        return Err(StreamingError::new(format!(
            "{}: unsupported Windows reparse point",
            abs_path.display()
        )));
    }
    if let PathLinkKind::Symlink(kind) = link_kind {
        if !policy.preserve_symlinks {
            return Err(StreamingError::new(format!(
                "{}: source symlink rejected by metadata policy",
                abs_path.display()
            )));
        }
        let target = std::fs::read_link(abs_path)
            .map_err(|error| StreamingError::new(format!("{}: {error}", abs_path.display())))?;
        let target = target.to_str().ok_or_else(|| {
            StreamingError::new(format!(
                "{}: symlink target is not valid Unicode",
                abs_path.display()
            ))
        })?;
        return Ok(EntryMetadata {
            file_kind: FileKind::Symlink,
            symlink_target: Some(target.to_string()),
            symlink_target_info: Some(SymlinkTargetInfo {
                kind: Some(kind),
                semantics: classify_symlink_target_semantics(target),
            }),
            ..EntryMetadata::default()
        });
    }

    let effective = std::fs::symlink_metadata(abs_path)
        .map_err(|e| StreamingError::new(format!("{}: {e}", abs_path.display())))?;
    let mut meta = EntryMetadata::default();
    if effective.is_dir() {
        meta.file_kind = FileKind::Directory;
    }
    if policy.preserve_windows_attributes {
        meta.windows_attributes =
            Some(effective.file_attributes() & WINDOWS_SETTABLE_ATTRIBUTE_MASK);
    }
    if policy.preserve_timestamps
        && let Ok(modified) = effective.modified()
        && let Some((seconds, nanos)) = system_time_to_unix_parts(modified)
    {
        meta.mtime_unix_secs = Some(seconds);
        meta.mtime_nanos = Some(nanos);
    }
    Ok(meta)
}

/// Portable fallback for targets that are neither Unix nor Windows.
#[cfg(not(any(unix, windows)))]
pub async fn read_entry_metadata(
    abs_path: &Path,
    policy: &MetadataPolicy,
) -> Result<EntryMetadata, StreamingError> {
    let path_buf = abs_path.to_path_buf();
    let policy = policy.clone();
    crate::runtime::spawn_blocking(move || read_entry_metadata_sync(&path_buf, &policy)).await
}

/// Synchronous portable fallback: regular-versus-directory kind only.
#[cfg(not(any(unix, windows)))]
pub fn read_entry_metadata_sync(
    abs_path: &Path,
    _policy: &MetadataPolicy,
) -> Result<EntryMetadata, StreamingError> {
    let effective = std::fs::metadata(abs_path)
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
    let path_buf = abs_path.to_path_buf();
    crate::runtime::spawn_blocking(move || inode_key_if_regular_sync(&path_buf)).await
}

/// Synchronous core of [`inode_key_if_regular`] for batched pass-1 capture
/// (br-asupersync-i7pdxb).
///
/// # Errors
///
/// Same contract as [`inode_key_if_regular`].
#[cfg(unix)]
pub fn inode_key_if_regular_sync(abs_path: &Path) -> Result<Option<(u64, u64)>, StreamingError> {
    use std::os::unix::fs::MetadataExt;
    let lmeta = std::fs::symlink_metadata(abs_path)
        .map_err(|e| StreamingError::new(format!("{}: {e}", abs_path.display())))?;
    if lmeta.is_file() {
        Ok(Some((lmeta.dev(), lmeta.ino())))
    } else {
        Ok(None)
    }
}

/// Windows hardlink identity from volume serial number and file index.
///
/// # Errors
///
/// Returns [`StreamingError`] if the path cannot be inspected.
#[cfg(windows)]
pub async fn inode_key_if_regular(abs_path: &Path) -> Result<Option<(u64, u64)>, StreamingError> {
    let path_buf = abs_path.to_path_buf();
    crate::runtime::spawn_blocking(move || inode_key_if_regular_sync(&path_buf)).await
}

/// Synchronous Windows hardlink identity capture.
///
/// # Errors
///
/// Returns [`StreamingError`] if the path cannot be inspected.
#[cfg(windows)]
pub fn inode_key_if_regular_sync(abs_path: &Path) -> Result<Option<(u64, u64)>, StreamingError> {
    use std::os::windows::fs::MetadataExt;

    match classify_path_link_sync(abs_path)
        .map_err(|error| StreamingError::new(format!("{}: {error}", abs_path.display())))?
    {
        PathLinkKind::NotLink => {}
        PathLinkKind::Symlink(_) | PathLinkKind::UnsupportedReparse => return Ok(None),
    }
    let metadata = std::fs::symlink_metadata(abs_path)
        .map_err(|error| StreamingError::new(format!("{}: {error}", abs_path.display())))?;
    if !metadata.is_file() {
        return Ok(None);
    }
    Ok(metadata
        .volume_serial_number()
        .zip(metadata.file_index())
        .map(|(volume, index)| (u64::from(volume), index)))
}

/// Unsupported-platform hardlink fallback.
#[cfg(not(any(unix, windows)))]
pub async fn inode_key_if_regular(_abs_path: &Path) -> Result<Option<(u64, u64)>, StreamingError> {
    Ok(None)
}

/// Synchronous unsupported-platform hardlink fallback.
#[cfg(not(any(unix, windows)))]
pub fn inode_key_if_regular_sync(_abs_path: &Path) -> Result<Option<(u64, u64)>, StreamingError> {
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

    if meta.windows_attributes.is_some() {
        report.mark_skipped(
            "windows_attributes",
            "Windows attributes unsupported on this platform",
        );
    }

    if let Some(mode) = meta.unix_mode {
        std::fs::set_permissions(out_path, std::fs::Permissions::from_mode(mode))
            .map_err(|e| StreamingError::new(format!("{}: {e}", out_path.display())))?;
        report.mark_applied("mode");
    }

    Ok(report)
}

/// Apply supported metadata on Windows.
///
/// # Errors
///
/// Returns an error only when the blocking task cannot complete.
#[cfg(windows)]
pub async fn apply_entry_metadata(
    out_path: &Path,
    meta: &EntryMetadata,
) -> Result<MetadataApplyReport, StreamingError> {
    let path = out_path.to_path_buf();
    let meta = meta.clone();
    crate::runtime::spawn_blocking(move || apply_entry_metadata_sync(&path, &meta)).await
}

/// Synchronous Windows metadata application.
///
/// # Errors
///
/// Invalid or unsupported fields are reported as skipped.
#[cfg(windows)]
pub fn apply_entry_metadata_sync(
    out_path: &Path,
    meta: &EntryMetadata,
) -> Result<MetadataApplyReport, StreamingError> {
    let mut report = MetadataApplyReport::default();
    if let Some(seconds) = meta.mtime_unix_secs {
        let nanos = meta.mtime_nanos.unwrap_or(0) % 1_000_000_000;
        let applied = u64::try_from(seconds)
            .map_err(|_| "pre-epoch mtime not representable".to_string())
            .and_then(|seconds| {
                let modified = std::time::UNIX_EPOCH
                    .checked_add(std::time::Duration::new(seconds, nanos))
                    .ok_or_else(|| "mtime out of representable range".to_string())?;
                open_windows_metadata_handle(out_path)
                    .and_then(|file| {
                        file.set_times(std::fs::FileTimes::new().set_modified(modified))
                    })
                    .map_err(|error| error.to_string())
            });
        match applied {
            Ok(()) => report.mark_applied("mtime"),
            Err(error) => report.mark_skipped("mtime", error),
        }
    }
    if let Some(attributes) = meta.windows_attributes {
        if attributes & !WINDOWS_SETTABLE_ATTRIBUTE_MASK != 0 {
            report.mark_skipped("windows_attributes", "unsafe attribute bits rejected");
        } else {
            match set_windows_attributes(out_path, attributes) {
                Ok(()) => report.mark_applied("windows_attributes"),
                Err(error) => report.mark_skipped("windows_attributes", error.to_string()),
            }
        }
    }
    if meta.unix_mode.is_some() {
        report.mark_skipped("mode", "unix permissions unsupported on this platform");
    }
    if meta.uid.is_some() || meta.gid.is_some() {
        report.mark_skipped("owner", "ownership unsupported on this platform");
    }
    if !meta.xattrs.is_empty() {
        report.mark_skipped("xattr", "extended attributes unsupported on this platform");
    }
    Ok(report)
}

#[cfg(windows)]
fn open_windows_metadata_handle(path: &Path) -> io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        FILE_WRITE_ATTRIBUTES,
    };

    let mut options = std::fs::OpenOptions::new();
    options
        .access_mode(FILE_WRITE_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
}

#[cfg(windows)]
#[allow(unsafe_code)] // SetFileAttributesW requires a NUL-terminated UTF-16 path.
fn set_windows_attributes(path: &Path, attributes: u32) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::SetFileAttributesW;

    const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
    let wide = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let attributes = if attributes == 0 {
        FILE_ATTRIBUTE_NORMAL
    } else {
        attributes
    };
    if unsafe { SetFileAttributesW(wide.as_ptr(), attributes) } == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Portable fallback: report metadata that cannot be applied.
#[cfg(not(any(unix, windows)))]
pub async fn apply_entry_metadata(
    out_path: &Path,
    meta: &EntryMetadata,
) -> Result<MetadataApplyReport, StreamingError> {
    apply_entry_metadata_sync(out_path, meta)
}

/// Synchronous portable metadata fallback.
#[cfg(not(any(unix, windows)))]
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
    if meta.windows_attributes.is_some() {
        report.mark_skipped(
            "windows_attributes",
            "Windows attributes unsupported on this platform",
        );
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

    #[test]
    fn windows_reparse_attribute_is_treated_as_link_like() {
        assert!(windows_attributes_contain_reparse_point(
            WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT
        ));
        assert!(!windows_attributes_contain_reparse_point(0));
    }

    #[cfg(unix)]
    #[test]
    fn transactional_symlink_commit_replaces_file_without_temp_leaks() {
        let root = tempfile::tempdir().expect("temporary directory");
        let target = root.path().join("target");
        let link = root.path().join("link");
        std::fs::write(&target, b"target").expect("write target");
        std::fs::write(&link, b"old").expect("write old destination");
        let metadata = EntryMetadata {
            file_kind: FileKind::Symlink,
            symlink_target: Some("target".to_string()),
            symlink_target_info: Some(SymlinkTargetInfo {
                kind: Some(SymlinkTargetKind::File),
                semantics: SymlinkTargetSemantics::PortableRelative,
            }),
            ..EntryMetadata::default()
        };

        futures_lite::future::block_on(commit_symlink_transactionally("link", &link, &metadata))
            .expect("commit symlink");
        assert_eq!(
            std::fs::read_link(&link).expect("read link"),
            Path::new("target")
        );
        assert!(
            std::fs::read_dir(root.path())
                .expect("read root")
                .all(|entry| !entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".atp-sym-"))
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_capture_distinguishes_file_and_directory_symlinks() {
        let root = tempfile::tempdir().expect("temporary directory");
        std::fs::write(root.path().join("file-target"), b"target").expect("write file target");
        std::fs::create_dir(root.path().join("dir-target")).expect("create dir target");
        let file_link = root.path().join("file-link");
        let dir_link = root.path().join("dir-link");
        std::os::windows::fs::symlink_file("file-target", &file_link)
            .expect("create Windows file symlink");
        std::os::windows::fs::symlink_dir("dir-target", &dir_link)
            .expect("create Windows directory symlink");

        let file = read_entry_metadata_sync(&file_link, &MetadataPolicy::default())
            .expect("capture file link");
        let directory = read_entry_metadata_sync(&dir_link, &MetadataPolicy::default())
            .expect("capture directory link");
        assert_eq!(
            file.symlink_target_info.and_then(|info| info.kind),
            Some(SymlinkTargetKind::File)
        );
        assert_eq!(
            directory.symlink_target_info.and_then(|info| info.kind),
            Some(SymlinkTargetKind::Directory)
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_hardlinks_share_the_same_identity() {
        let root = tempfile::tempdir().expect("temporary directory");
        let first = root.path().join("first");
        let second = root.path().join("second");
        std::fs::write(&first, b"same inode").expect("write primary");
        std::fs::hard_link(&first, &second).expect("create hardlink");
        let first_key = inode_key_if_regular_sync(&first)
            .expect("first identity query")
            .expect("first identity available");
        let second_key = inode_key_if_regular_sync(&second)
            .expect("second identity query")
            .expect("second identity available");
        assert_eq!(first_key, second_key);
    }

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
    fn legacy_v1_symlink_commitment_is_frozen() {
        let legacy = EntryMetadata {
            file_kind: FileKind::Symlink,
            symlink_target: Some("../t".to_string()),
            ..EntryMetadata::default()
        };
        assert_eq!(
            metadata_commitment(&[("f", &legacy)]).as_deref(),
            Some("4af5addb7e13dbcad54a31d2b2c2567f17c5954026294388e8051e76a4f4efe0")
        );
    }

    #[test]
    fn v2_commitment_covers_symlink_kind_semantics_and_windows_attributes() {
        let mut file_link = EntryMetadata {
            file_kind: FileKind::Symlink,
            symlink_target: Some("target".to_string()),
            symlink_target_info: Some(SymlinkTargetInfo {
                kind: Some(SymlinkTargetKind::File),
                semantics: SymlinkTargetSemantics::PortableRelative,
            }),
            ..EntryMetadata::default()
        };
        let file_root = metadata_commitment(&[("link", &file_link)]).expect("v2 root");

        file_link.symlink_target_info.as_mut().expect("info").kind =
            Some(SymlinkTargetKind::Directory);
        let directory_root = metadata_commitment(&[("link", &file_link)]).expect("v2 root");
        assert_ne!(file_root, directory_root);

        file_link
            .symlink_target_info
            .as_mut()
            .expect("info")
            .semantics = SymlinkTargetSemantics::Unix;
        let native_root = metadata_commitment(&[("link", &file_link)]).expect("v2 root");
        assert_ne!(directory_root, native_root);

        let attributes = EntryMetadata {
            windows_attributes: Some(0x21),
            ..EntryMetadata::default()
        };
        assert_ne!(
            metadata_commitment(&[("f", &attributes)]),
            metadata_commitment(&[("f", &EntryMetadata::default())])
        );
    }

    #[test]
    fn symlink_target_validation_normalizes_against_manifest_parent() {
        let metadata = EntryMetadata {
            file_kind: FileKind::Symlink,
            symlink_target: Some("../target".to_string()),
            symlink_target_info: Some(SymlinkTargetInfo {
                kind: Some(SymlinkTargetKind::File),
                semantics: SymlinkTargetSemantics::PortableRelative,
            }),
            ..EntryMetadata::default()
        };
        assert!(validate_symlink_metadata_for_receive("dir/link", &metadata).is_ok());
        assert!(validate_symlink_metadata_for_receive("link", &metadata).is_err());

        for target in ["/rooted", "\\rooted", "C:relative", "dir\\file", "../NUL"] {
            let mut invalid = metadata.clone();
            invalid.symlink_target = Some(target.to_string());
            assert!(
                validate_symlink_metadata_for_receive("dir/link", &invalid).is_err(),
                "target {target:?} must fail closed"
            );
        }
    }

    #[test]
    fn unsafe_windows_attribute_bits_are_rejected() {
        let metadata = EntryMetadata {
            windows_attributes: Some(WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT),
            ..EntryMetadata::default()
        };
        assert!(validate_symlink_metadata_for_receive("file", &metadata).is_err());
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
            windows_attributes: None,
            symlink_target: Some("../t".to_string()),
            symlink_target_info: Some(SymlinkTargetInfo {
                kind: Some(SymlinkTargetKind::Directory),
                semantics: SymlinkTargetSemantics::PortableRelative,
            }),
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
