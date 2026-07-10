//! Receiver-side mirror (`rsync --delete`) reconciliation, with safety rails.
//!
//! After a verified transfer commits, *mirror mode* makes the destination an
//! exact one-way copy of the sender by deleting receiver files/dirs that are
//! absent from the sender's manifest. This is `rsync --delete`: required for
//! true one-way sync (backups, deploys), but dangerous without rails — so this
//! module is built around the project's no-delete ethos:
//!
//! - **Opt-in.** [`MirrorPolicy::default`] is a dry-run that deletes nothing; a
//!   caller must explicitly set [`MirrorPolicy::enabled`] to remove anything.
//! - **Previewable.** A dry-run returns the exact list of would-be deletions
//!   ([`MirrorReport::planned`]) without touching the filesystem.
//! - **Contained.** The walk never follows symlinks (a symlink is a leaf, so a
//!   link is removed, never its target), every deletion path is verified to be
//!   strictly under the destination root, and the destination root itself is
//!   never removed.
//! - **Bounded.** A max-delete fraction guard aborts before deleting anything if
//!   more than [`MirrorPolicy::max_delete_fraction`] of the destination entries
//!   would be removed — the classic "empty/corrupt manifest would wipe the
//!   receiver" guard.
//! - **Audited.** Every deletion (or, in dry-run, every would-be deletion) is
//!   traced via [`Cx::trace_with_fields`].
//!
//! `mirror_dest` is transport-agnostic: the TCP, RaptorQ, and QUIC receive paths
//! all build the manifest rel-path set and call it post-commit.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::atp::safety::portable_path_collision_key;
use crate::cx::Cx;

use super::metadata::path_is_link_or_reparse;

/// What kind of destination entry a mirror deletion targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MirrorEntryKind {
    /// A regular file.
    File,
    /// A directory (removed only once its extra children are gone).
    Dir,
    /// A symlink (the link itself is removed; its target is never followed).
    Symlink,
}

impl MirrorEntryKind {
    /// Stable lowercase label for tracing/reporting.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Dir => "dir",
            Self::Symlink => "symlink",
        }
    }
}

/// One destination entry absent from the sender manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorExtra {
    /// Forward-slash path relative to the destination root.
    pub rel_path: String,
    /// Absolute path under the destination root.
    pub abs_path: PathBuf,
    /// The entry kind.
    pub kind: MirrorEntryKind,
}

/// Mirror deletion policy. The default deletes nothing (dry-run preview).
#[derive(Debug, Clone, Copy)]
pub struct MirrorPolicy {
    /// When `false` (default) the reconciliation is a dry-run: it computes the
    /// would-be deletions but never touches the filesystem. Must be explicitly
    /// set `true` to actually delete.
    pub enabled: bool,
    /// Abort (delete nothing) if the would-be deletions exceed this fraction of
    /// the total destination entries. `1.0` disables the guard; values are
    /// clamped to `[0.0, 1.0]`. Only enforced when `enabled` is `true`.
    pub max_delete_fraction: f64,
}

impl Default for MirrorPolicy {
    fn default() -> Self {
        // Safe by default: dry-run, and a conservative guard for opt-in callers.
        Self {
            enabled: false,
            max_delete_fraction: 0.5,
        }
    }
}

/// Outcome of a [`mirror_dest`] reconciliation.
#[derive(Debug, Clone)]
pub struct MirrorReport {
    /// Whether this was a dry-run (nothing deleted).
    pub dry_run: bool,
    /// Total destination entries scanned (files + dirs + symlinks).
    pub dest_entries: usize,
    /// Every extra found (absent from the manifest), in deletion order
    /// (deepest first).
    pub planned: Vec<MirrorExtra>,
    /// Number of extras actually deleted (`0` for a dry-run).
    pub deleted: usize,
}

/// Errors from [`mirror_dest`].
#[derive(Debug, thiserror::Error)]
pub enum MirrorError {
    /// A filesystem error while scanning or deleting.
    #[error("mirror io error: {0}")]
    Io(#[from] std::io::Error),
    /// A deletion path escaped the destination root — refused (should be
    /// impossible given the no-follow walk; a defensive last line).
    #[error("mirror refused: path {path} is not contained under destination root {root}")]
    PathEscape {
        /// The offending path.
        path: String,
        /// The destination root it escaped.
        root: String,
    },
    /// The max-delete fraction guard tripped; nothing was deleted.
    #[error(
        "mirror max-delete guard tripped: {would_delete} of {dest_entries} entries \
         ({fraction:.1}%) exceed the {limit:.1}% limit; refusing to delete"
    )]
    MaxDeleteGuard {
        /// Entries that would be deleted.
        would_delete: usize,
        /// Total destination entries.
        dest_entries: usize,
        /// Percentage that would be deleted.
        fraction: f64,
        /// Configured limit percentage.
        limit: f64,
    },
    /// The operation was cancelled via the capability context.
    #[error("mirror cancelled")]
    Cancelled,
    /// A destination path was not valid Unicode and therefore cannot be
    /// compared safely across case-folding/canonicalizing filesystems.
    #[error("mirror refused non-Unicode destination path: {0}")]
    NonUnicode(String),
    /// The destination root itself is link-like and must never be traversed.
    #[error("mirror refused symlink or reparse-point destination root: {0}")]
    ReparseRoot(String),
    /// An ancestor was replaced with a symlink or Windows reparse point after
    /// the mirror plan was built.
    #[error("mirror refused symlink or reparse-point destination ancestor: {0}")]
    ReparseAncestor(String),
}

/// Revalidate every existing path component that an operation would traverse.
///
/// Mirror planning and deletion are separated by async suspension points. A
/// local process can replace a previously scanned directory with a symlink or
/// Windows junction during that interval, so lexical containment alone is not
/// sufficient. `include_target` is true before reading a directory and false
/// before deleting a leaf (a symlink leaf itself is safe to unlink).
async fn reject_mirror_reparse_ancestors(
    dest_base: &Path,
    target: &Path,
    include_target: bool,
) -> Result<(), MirrorError> {
    let rel = target
        .strip_prefix(dest_base)
        .map_err(|_| MirrorError::PathEscape {
            path: target.display().to_string(),
            root: dest_base.display().to_string(),
        })?;

    let components = rel.components().collect::<Vec<_>>();
    let mut current = dest_base.to_path_buf();
    reject_mirror_reparse_component(&current).await?;
    let component_count = components.len();
    for (index, component) in components.into_iter().enumerate() {
        let std::path::Component::Normal(component) = component else {
            return Err(MirrorError::PathEscape {
                path: target.display().to_string(),
                root: dest_base.display().to_string(),
            });
        };
        current.push(component);
        if include_target || index + 1 < component_count {
            reject_mirror_reparse_component(&current).await?;
        }
    }
    Ok(())
}

async fn reject_mirror_reparse_component(path: &Path) -> Result<(), MirrorError> {
    match path_is_link_or_reparse(path).await {
        Ok(false) => Ok(()),
        Ok(true) => Err(MirrorError::ReparseAncestor(path.display().to_string())),
        Err(error) => Err(MirrorError::Io(error)),
    }
}

async fn remove_mirror_entry(
    dest_base: &Path,
    path: &Path,
    expected_kind: MirrorEntryKind,
) -> Result<(), MirrorError> {
    #[cfg(windows)]
    {
        let dest_base = dest_base.to_path_buf();
        let path = path.to_path_buf();
        return crate::runtime::spawn_blocking_io(move || {
            remove_mirror_entry_windows(&dest_base, &path, expected_kind)
        })
        .await
        .map_err(MirrorError::Io);
    }

    #[cfg(not(windows))]
    {
        let _ = dest_base;
        let metadata = crate::fs::symlink_metadata(path).await?;
        let kind_matches = match expected_kind {
            MirrorEntryKind::File => metadata.is_file() && !metadata.file_type().is_symlink(),
            MirrorEntryKind::Dir => metadata.is_dir() && !metadata.file_type().is_symlink(),
            MirrorEntryKind::Symlink => metadata.file_type().is_symlink(),
        };
        if !kind_matches {
            return Err(MirrorError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "mirror deletion target changed filesystem kind: {}",
                    path.display()
                ),
            )));
        }
        match expected_kind {
            MirrorEntryKind::Dir => crate::fs::remove_dir(path).await?,
            MirrorEntryKind::File | MirrorEntryKind::Symlink => {
                crate::fs::remove_file(path).await?;
            }
        }
        Ok(())
    }
}

#[cfg(windows)]
fn windows_final_path_is_strict_descendant(root: &[u16], target: &[u16]) -> bool {
    const BACKSLASH: u16 = b'\\' as u16;
    const SLASH: u16 = b'/' as u16;

    let mut root_len = root.len();
    while root_len > 0 && matches!(root[root_len - 1], BACKSLASH | SLASH) {
        root_len -= 1;
    }
    target.len() > root_len
        && target.get(..root_len) == root.get(..root_len)
        && matches!(target[root_len], BACKSLASH | SLASH)
}

#[cfg(windows)]
#[allow(unsafe_code)] // Query the kernel-resolved name for an RAII-owned handle.
fn windows_final_path(file: &std::fs::File) -> std::io::Result<Vec<u16>> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_NAME_NORMALIZED, GetFinalPathNameByHandleW, VOLUME_NAME_DOS,
    };

    const INITIAL_PATH_UNITS: usize = 512;
    const MAX_PATH_UNITS: usize = 1024 * 1024;

    let mut capacity = INITIAL_PATH_UNITS;
    loop {
        let mut path = vec![0_u16; capacity];
        let path_capacity = u32::try_from(path.len()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "mirror handle path buffer exceeds Win32 limits",
            )
        })?;
        let len = unsafe {
            GetFinalPathNameByHandleW(
                file.as_raw_handle(),
                path.as_mut_ptr(),
                path_capacity,
                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
            )
        };
        if len == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let len = usize::try_from(len).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "mirror handle path length does not fit usize",
            )
        })?;
        if len < path.len() {
            path.truncate(len);
            return Ok(path);
        }
        capacity = len
            .checked_add(1)
            .filter(|len| *len <= MAX_PATH_UNITS)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "mirror handle path exceeds the containment-proof limit",
                )
            })?;
    }
}

#[cfg(windows)]
fn windows_handle_path_display(path: &[u16]) -> String {
    String::from_utf16_lossy(path)
}

#[cfg(windows)]
fn open_mirror_windows_handle(path: &Path, access: u32) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let mut options = std::fs::OpenOptions::new();
    options
        .access_mode(access)
        // Deliberately omit FILE_SHARE_DELETE. A successful open pins this
        // namespace entry against rename/delete until the containment proof and
        // handle-based disposition complete.
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
}

#[cfg(windows)]
#[allow(unsafe_code)] // Delete one proven-contained no-follow handle without mutating inode attrs.
fn remove_mirror_entry_windows(
    dest_base: &Path,
    path: &Path,
    expected_kind: MirrorEntryKind,
) -> std::io::Result<()> {
    use std::os::windows::fs::MetadataExt as _;
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_ATTRIBUTE_REPARSE_POINT, FILE_DISPOSITION_FLAG_DELETE,
        FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE, FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
        FILE_DISPOSITION_INFO_EX, FILE_READ_ATTRIBUTES, FileDispositionInfoEx,
        SetFileInformationByHandle,
    };

    let root = open_mirror_windows_handle(dest_base, FILE_READ_ATTRIBUTES)?;
    let root_metadata = root.metadata()?;
    if root_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || !root_metadata.is_dir()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "mirror destination root handle is not a real directory",
        ));
    }

    let file = open_mirror_windows_handle(path, DELETE | FILE_READ_ATTRIBUTES)?;
    let metadata = file.metadata()?;
    let reparse = metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0;
    let kind_matches = match expected_kind {
        MirrorEntryKind::File => !reparse && metadata.is_file(),
        MirrorEntryKind::Dir => !reparse && metadata.is_dir(),
        MirrorEntryKind::Symlink => reparse,
    };
    if !kind_matches {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "mirror deletion target changed from expected {} kind: {}",
                expected_kind.as_str(),
                path.display()
            ),
        ));
    }

    let root_path = windows_final_path(&root)?;
    let target_path = windows_final_path(&file)?;
    if !windows_final_path_is_strict_descendant(&root_path, &target_path) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "mirror target handle {} is not strictly under root handle {}",
                windows_handle_path_display(&target_path),
                windows_handle_path_display(&root_path)
            ),
        ));
    }

    // IGNORE_READONLY deletes this directory entry without clearing the inode's
    // shared READONLY attribute, so hardlinks outside the mirror root retain it.
    let disposition = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE
            | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS
            | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
    };
    let disposition_size = u32::try_from(std::mem::size_of::<FILE_DISPOSITION_INFO_EX>())
        .expect("FILE_DISPOSITION_INFO_EX size fits in u32");
    if unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfoEx,
            std::ptr::from_ref(&disposition).cast(),
            disposition_size,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    drop(file);
    drop(root);
    Ok(())
}

/// Reconcile `dest_base` against the sender manifest's kept paths.
///
/// Deletes (or, in dry-run, lists) destination entries absent from
/// `keep_rel_paths` — the set of forward-slash file paths the sender sent
/// (manifest entry `rel_path`s). Their ancestor directories are kept implicitly.
/// Everything else under `dest_base` is an extra.
///
/// Returns the [`MirrorReport`]. With [`MirrorPolicy::enabled`] `false` this is a
/// pure dry-run. With it `true`, deletions happen deepest-first after the
/// max-delete guard passes — otherwise [`MirrorError::MaxDeleteGuard`] is
/// returned and nothing is removed.
pub async fn mirror_dest(
    cx: &Cx,
    dest_base: &Path,
    keep_rel_paths: &BTreeSet<String>,
    policy: MirrorPolicy,
) -> Result<MirrorReport, MirrorError> {
    cx.checkpoint().map_err(|_| MirrorError::Cancelled)?;

    match path_is_link_or_reparse(dest_base).await {
        Ok(true) => {
            return Err(MirrorError::ReparseRoot(dest_base.display().to_string()));
        }
        Ok(false) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(MirrorReport {
                dry_run: !policy.enabled,
                dest_entries: 0,
                planned: Vec::new(),
                deleted: 0,
            });
        }
        Err(error) => return Err(MirrorError::Io(error)),
    }

    // Nothing to reconcile if the destination is missing or not a directory.
    match crate::fs::symlink_metadata(dest_base).await {
        Ok(md) if md.is_dir() => {}
        Ok(_) => {
            return Ok(MirrorReport {
                dry_run: !policy.enabled,
                dest_entries: 0,
                planned: Vec::new(),
                deleted: 0,
            });
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(MirrorReport {
                dry_run: !policy.enabled,
                dest_entries: 0,
                planned: Vec::new(),
                deleted: 0,
            });
        }
        Err(e) => return Err(MirrorError::Io(e)),
    }

    let keep = expand_keep_set(keep_rel_paths);
    let mut keep_aliases = BTreeMap::<String, Vec<String>>::new();
    for path in &keep {
        keep_aliases
            .entry(portable_path_collision_key(path))
            .or_default()
            .push(path.clone());
    }

    // Walk the whole destination tree (recursing into real directories only,
    // never following symlinks). Classify every entry; collect the extras.
    let mut dest_entries: usize = 0;
    let mut scanned: Vec<MirrorExtra> = Vec::new();
    // Stack of directories to scan: (absolute path, forward-slash rel path).
    let mut stack: Vec<(PathBuf, String)> = vec![(dest_base.to_path_buf(), String::new())];

    while let Some((dir_abs, dir_rel)) = stack.pop() {
        cx.checkpoint().map_err(|_| MirrorError::Cancelled)?;
        reject_mirror_reparse_ancestors(dest_base, &dir_abs, true).await?;
        let mut rd = crate::fs::read_dir(&dir_abs).await?;
        while let Some(entry) = rd.next_entry().await? {
            let abs = entry.path();
            let name = entry
                .file_name()
                .to_str()
                .ok_or_else(|| MirrorError::NonUnicode(abs.display().to_string()))?
                .to_string();
            let rel = if dir_rel.is_empty() {
                name
            } else {
                format!("{dir_rel}/{name}")
            };
            let link_like = path_is_link_or_reparse(&abs).await?;
            let md = crate::fs::symlink_metadata(&abs).await?;
            let kind = if link_like {
                MirrorEntryKind::Symlink
            } else if md.is_dir() {
                MirrorEntryKind::Dir
            } else {
                MirrorEntryKind::File
            };

            dest_entries += 1;

            // Recurse only into real directories (never into symlinks), whether
            // kept or extra, so we enumerate extras nested inside kept dirs and
            // the full subtree of extra dirs (needed for deepest-first removal).
            if kind == MirrorEntryKind::Dir {
                stack.push((abs.clone(), rel.clone()));
            }

            scanned.push(MirrorExtra {
                rel_path: rel,
                abs_path: abs,
                kind,
            });
        }
    }

    let destination_paths = scanned
        .iter()
        .map(|entry| entry.rel_path.clone())
        .collect::<BTreeSet<_>>();
    let mut extras = scanned
        .into_iter()
        .filter(|entry| {
            !destination_entry_is_kept(&entry.rel_path, &keep, &keep_aliases, &destination_paths)
        })
        .collect::<Vec<_>>();

    // Deepest-first so an extra directory's children are removed before it.
    extras.sort_by(|a, b| {
        depth(&b.rel_path)
            .cmp(&depth(&a.rel_path))
            .then_with(|| b.rel_path.cmp(&a.rel_path))
    });

    let would_delete = extras.len();
    let dry_run = !policy.enabled;

    if dry_run {
        for x in &extras {
            cx.trace_with_fields(
                "atp.mirror.dry_run",
                &[("rel_path", x.rel_path.as_str()), ("kind", x.kind.as_str())],
            );
        }
        return Ok(MirrorReport {
            dry_run: true,
            dest_entries,
            planned: extras,
            deleted: 0,
        });
    }

    // Max-delete guard: refuse to delete a suspiciously large fraction.
    let limit = policy.max_delete_fraction.clamp(0.0, 1.0);
    if dest_entries > 0 {
        #[allow(clippy::cast_precision_loss)]
        let fraction = would_delete as f64 / dest_entries as f64;
        if fraction > limit {
            return Err(MirrorError::MaxDeleteGuard {
                would_delete,
                dest_entries,
                fraction: fraction * 100.0,
                limit: limit * 100.0,
            });
        }
    }

    let mut deleted = 0usize;
    for x in &extras {
        cx.checkpoint().map_err(|_| MirrorError::Cancelled)?;
        // Defensive containment check: never delete outside the destination root.
        if !x.abs_path.starts_with(dest_base) {
            return Err(MirrorError::PathEscape {
                path: x.abs_path.display().to_string(),
                root: dest_base.display().to_string(),
            });
        }
        cx.trace_with_fields(
            "atp.mirror.delete",
            &[("rel_path", x.rel_path.as_str()), ("kind", x.kind.as_str())],
        );
        // Re-check the complete real-directory chain immediately before the
        // leaf operation. The earlier scan is planning evidence, not an
        // authority to traverse a path that another process may have swapped.
        reject_mirror_reparse_ancestors(dest_base, &x.abs_path, false).await?;
        let current_link_like = path_is_link_or_reparse(&x.abs_path).await?;
        let delete_kind = match (x.kind, current_link_like) {
            // Files and symlinks: remove the entry itself (a symlink is unlinked,
            // never its target).
            (MirrorEntryKind::File, false) => MirrorEntryKind::File,
            (_, true) => MirrorEntryKind::Symlink,
            // Directories are empty by now (deepest-first ordering removed their
            // extra children); remove_dir refuses a non-empty dir, which would
            // surface an unexpected kept child rather than silently nuking it.
            (MirrorEntryKind::Dir, false) => MirrorEntryKind::Dir,
            (MirrorEntryKind::Symlink, false) => {
                return Err(MirrorError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "mirror entry changed from link-like to regular: {}",
                        x.abs_path.display()
                    ),
                )));
            }
        };
        remove_mirror_entry(dest_base, &x.abs_path, delete_kind).await?;
        deleted += 1;
    }

    Ok(MirrorReport {
        dry_run: false,
        dest_entries,
        planned: extras,
        deleted,
    })
}

/// Expand the manifest's file rel-paths into the full keep set.
///
/// Each file plus all of its ancestor directories, so a kept file is never
/// orphaned by deleting a parent directory.
fn expand_keep_set(keep_rel_paths: &BTreeSet<String>) -> BTreeSet<String> {
    let mut keep = BTreeSet::new();
    for path in keep_rel_paths {
        let normalized = path.trim_matches('/');
        if normalized.is_empty() {
            continue;
        }
        let mut prefix = String::new();
        for component in normalized.split('/') {
            if component.is_empty() {
                continue;
            }
            if prefix.is_empty() {
                prefix = component.to_string();
            } else {
                prefix.push('/');
                prefix.push_str(component);
            }
            keep.insert(prefix.clone());
        }
    }
    keep
}

fn destination_entry_is_kept(
    rel_path: &str,
    keep: &BTreeSet<String>,
    keep_aliases: &BTreeMap<String, Vec<String>>,
    destination_paths: &BTreeSet<String>,
) -> bool {
    if keep.contains(rel_path) {
        return true;
    }
    let Some(candidates) = keep_aliases.get(&portable_path_collision_key(rel_path)) else {
        return false;
    };

    // A case-sensitive/canonical-sensitive filesystem enumerates both the kept
    // spelling and a stale alias as separate directory entries. A folding
    // filesystem enumerates only its stored spelling. Keep the alias only in
    // the latter case; this preserves exact mirror deletion on Linux while
    // avoiding deletion of a just-committed file whose spelling Windows/APFS
    // retained from an older name.
    candidates
        .iter()
        .any(|candidate| !destination_paths.contains(candidate))
}

/// Depth of a forward-slash rel-path (number of path components).
fn depth(rel: &str) -> usize {
    rel.split('/').filter(|c| !c.is_empty()).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keep_set(paths: &[&str]) -> BTreeSet<String> {
        paths.iter().map(|p| (*p).to_string()).collect()
    }

    #[cfg(unix)]
    fn create_directory_link(target: &Path, link: &Path) {
        std::os::unix::fs::symlink(target, link).expect("create directory symlink");
    }

    #[cfg(windows)]
    fn create_directory_link(target: &Path, link: &Path) {
        std::os::windows::fs::symlink_dir(target, link).expect("create directory symlink");
    }

    #[cfg(unix)]
    fn create_file_link(target: &Path, link: &Path) {
        std::os::unix::fs::symlink(target, link).expect("create file symlink");
    }

    #[cfg(windows)]
    fn create_file_link(target: &Path, link: &Path) {
        std::os::windows::fs::symlink_file(target, link).expect("create file symlink");
    }

    #[test]
    fn expand_keep_adds_all_ancestors() {
        let keep = expand_keep_set(&keep_set(&["a/b/c.txt", "a/d.txt"]));
        assert!(keep.contains("a"));
        assert!(keep.contains("a/b"));
        assert!(keep.contains("a/b/c.txt"));
        assert!(keep.contains("a/d.txt"));
        assert!(!keep.contains("a/b/c.txt/extra"));
    }

    #[test]
    fn expand_keep_ignores_empty_and_slashes() {
        let keep = expand_keep_set(&keep_set(&["", "/", "x//y/"]));
        assert!(keep.contains("x"));
        assert!(keep.contains("x/y"));
        assert_eq!(keep.len(), 2);
    }

    #[test]
    fn depth_counts_components() {
        assert_eq!(depth(""), 0);
        assert_eq!(depth("a"), 1);
        assert_eq!(depth("a/b/c"), 3);
        assert_eq!(depth("a//b"), 2);
    }

    #[test]
    fn mirror_entry_kind_labels() {
        assert_eq!(MirrorEntryKind::File.as_str(), "file");
        assert_eq!(MirrorEntryKind::Dir.as_str(), "dir");
        assert_eq!(MirrorEntryKind::Symlink.as_str(), "symlink");
    }

    #[test]
    fn default_policy_is_dry_run() {
        let p = MirrorPolicy::default();
        assert!(!p.enabled);
        assert!(p.max_delete_fraction > 0.0 && p.max_delete_fraction <= 1.0);
    }

    #[cfg(windows)]
    #[test]
    fn windows_handle_paths_require_a_strict_component_descendant() {
        let wide = |value: &str| value.encode_utf16().collect::<Vec<_>>();
        let root = wide(r"\\?\C:\mirror\root");

        assert!(windows_final_path_is_strict_descendant(
            &root,
            &wide(r"\\?\C:\mirror\root\child.txt")
        ));
        assert!(windows_final_path_is_strict_descendant(
            &wide(r"\\?\C:\mirror\root\"),
            &wide(r"\\?\C:\mirror\root\nested\child.txt")
        ));
        assert!(!windows_final_path_is_strict_descendant(&root, &root));
        assert!(!windows_final_path_is_strict_descendant(
            &root,
            &wide(r"\\?\C:\mirror\root-sibling\child.txt")
        ));
        assert!(!windows_final_path_is_strict_descendant(
            &root,
            &wide(r"\\?\D:\mirror\root\child.txt")
        ));
    }

    #[cfg(windows)]
    #[test]
    fn windows_handle_delete_checks_containment_and_filesystem_kind() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let dest = temp.path().join("dest");
        let outside = temp.path().join("outside.txt");
        let stale_dir = dest.join("stale-dir");
        std::fs::create_dir_all(&stale_dir).expect("create stale directory");
        std::fs::write(&outside, b"outside").expect("write outside file");

        remove_mirror_entry_windows(&dest, &outside, MirrorEntryKind::File)
            .expect_err("outside handle must fail containment proof");
        assert_eq!(
            std::fs::read(&outside).expect("outside file remains"),
            b"outside"
        );

        remove_mirror_entry_windows(&dest, &stale_dir, MirrorEntryKind::File)
            .expect_err("wrong-kind directory handle must fail closed");
        assert!(stale_dir.is_dir());

        remove_mirror_entry_windows(&dest, &stale_dir, MirrorEntryKind::Dir)
            .expect("empty contained directory is deleted by handle");
        assert!(!stale_dir.exists());
    }

    #[test]
    fn destination_keep_matching_preserves_folding_spelling_but_deletes_real_alias() {
        let keep = keep_set(&["Docs/Readme.txt"]);
        let keep_aliases = BTreeMap::from([(
            portable_path_collision_key("Docs/Readme.txt"),
            vec!["Docs/Readme.txt".to_string()],
        )]);

        let folding_destination = keep_set(&["docs/README.TXT"]);
        assert!(destination_entry_is_kept(
            "docs/README.TXT",
            &keep,
            &keep_aliases,
            &folding_destination,
        ));

        let case_sensitive_destination = keep_set(&["Docs/Readme.txt", "docs/README.TXT"]);
        assert!(destination_entry_is_kept(
            "Docs/Readme.txt",
            &keep,
            &keep_aliases,
            &case_sensitive_destination,
        ));
        assert!(!destination_entry_is_kept(
            "docs/README.TXT",
            &keep,
            &keep_aliases,
            &case_sensitive_destination,
        ));
    }

    #[test]
    fn destination_keep_matching_uses_unicode_normalization_and_rejects_unrelated_paths() {
        let composed = "caf\u{e9}.txt";
        let decomposed = "cafe\u{301}.txt";
        let keep = keep_set(&[composed]);
        let keep_aliases = BTreeMap::from([(
            portable_path_collision_key(composed),
            vec![composed.to_string()],
        )]);
        let destination = keep_set(&[decomposed]);

        assert!(destination_entry_is_kept(
            decomposed,
            &keep,
            &keep_aliases,
            &destination,
        ));
        assert!(!destination_entry_is_kept(
            "unrelated.txt",
            &keep,
            &keep_aliases,
            &destination,
        ));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn mirror_ancestor_recheck_rejects_reparse_before_delete() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let dest = temp.path().join("dest");
        let outside = temp.path().join("outside");
        std::fs::create_dir_all(&dest).expect("create destination");
        std::fs::create_dir_all(&outside).expect("create outside directory");
        let victim = outside.join("victim.txt");
        std::fs::write(&victim, b"outside").expect("write outside victim");
        let pivot = dest.join("pivot");
        create_directory_link(&outside, &pivot);

        let read_error =
            futures_lite::future::block_on(reject_mirror_reparse_ancestors(&dest, &pivot, true))
                .expect_err("reparse directory must be rejected before read_dir");
        assert!(matches!(read_error, MirrorError::ReparseAncestor(_)));

        let error = futures_lite::future::block_on(reject_mirror_reparse_ancestors(
            &dest,
            &pivot.join("victim.txt"),
            false,
        ))
        .expect_err("reparse ancestor must fail closed");
        assert!(matches!(error, MirrorError::ReparseAncestor(_)));
        assert_eq!(
            std::fs::read(&victim).expect("outside victim remains readable"),
            b"outside"
        );

        #[cfg(windows)]
        {
            let error = remove_mirror_entry_windows(
                &dest,
                &pivot.join("victim.txt"),
                MirrorEntryKind::File,
            )
            .expect_err("resolved outside handle must fail containment proof");
            assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
            assert_eq!(
                std::fs::read(&victim).expect("outside victim survives handle guard"),
                b"outside"
            );
        }
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn mirror_deletes_link_leaf_without_touching_outside_target() {
        let cx = Cx::for_testing();
        let temp = tempfile::tempdir().expect("temporary directory");
        let dest = temp.path().join("dest");
        std::fs::create_dir_all(&dest).expect("create destination");
        let outside = temp.path().join("outside.txt");
        std::fs::write(&outside, b"outside").expect("write outside target");
        let link = dest.join("stale-link");
        create_file_link(&outside, &link);

        let report = futures_lite::future::block_on(mirror_dest(
            &cx,
            &dest,
            &BTreeSet::new(),
            MirrorPolicy {
                enabled: true,
                max_delete_fraction: 1.0,
            },
        ))
        .expect("mirror removes only link leaf");
        assert_eq!(report.deleted, 1);
        assert!(!link.exists());
        assert_eq!(
            std::fs::read(&outside).expect("outside target remains readable"),
            b"outside"
        );
    }

    #[cfg(windows)]
    #[test]
    fn mirror_deletes_readonly_name_without_mutating_external_hardlink() {
        let cx = Cx::for_testing();
        let temp = tempfile::tempdir().expect("temporary directory");
        let dest = temp.path().join("dest");
        std::fs::create_dir_all(&dest).expect("create destination");
        let stale = dest.join("stale.txt");
        let external = temp.path().join("external.txt");
        std::fs::write(&stale, b"shared").expect("write stale file");
        std::fs::hard_link(&stale, &external).expect("create external hardlink");
        let mut permissions = std::fs::metadata(&stale)
            .expect("stale metadata")
            .permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(&stale, permissions).expect("make shared inode read-only");

        let report = futures_lite::future::block_on(mirror_dest(
            &cx,
            &dest,
            &BTreeSet::new(),
            MirrorPolicy {
                enabled: true,
                max_delete_fraction: 1.0,
            },
        ))
        .expect("mirror deletes read-only stale name");
        assert_eq!(report.deleted, 1);
        assert!(!stale.exists());
        assert_eq!(
            std::fs::read(&external).expect("external hardlink remains readable"),
            b"shared"
        );
        assert!(
            std::fs::metadata(&external)
                .expect("external hardlink metadata")
                .permissions()
                .readonly(),
            "mirror must not clear shared READONLY attributes"
        );

        let mut permissions = std::fs::metadata(&external)
            .expect("external cleanup metadata")
            .permissions();
        permissions.set_readonly(false);
        std::fs::set_permissions(&external, permissions)
            .expect("clear external read-only attribute for cleanup");
    }
}
