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

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::cx::Cx;

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

    // Walk the whole destination tree (recursing into real directories only,
    // never following symlinks). Classify every entry; collect the extras.
    let mut dest_entries: usize = 0;
    let mut extras: Vec<MirrorExtra> = Vec::new();
    // Stack of directories to scan: (absolute path, forward-slash rel path).
    let mut stack: Vec<(PathBuf, String)> = vec![(dest_base.to_path_buf(), String::new())];

    while let Some((dir_abs, dir_rel)) = stack.pop() {
        cx.checkpoint().map_err(|_| MirrorError::Cancelled)?;
        let mut rd = crate::fs::read_dir(&dir_abs).await?;
        while let Some(entry) = rd.next_entry().await? {
            let abs = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            let rel = if dir_rel.is_empty() {
                name
            } else {
                format!("{dir_rel}/{name}")
            };
            // `DirEntry::metadata` preserves symlink semantics (does not follow),
            // so a symlink is reported as a symlink, not its target.
            let md = entry.metadata().await?;
            let kind = if md.is_symlink() {
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

            if !keep.contains(&rel) {
                extras.push(MirrorExtra {
                    rel_path: rel,
                    abs_path: abs,
                    kind,
                });
            }
        }
    }

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
        match x.kind {
            // Files and symlinks: remove the entry itself (a symlink is unlinked,
            // never its target).
            MirrorEntryKind::File | MirrorEntryKind::Symlink => {
                crate::fs::remove_file(&x.abs_path).await?;
            }
            // Directories are empty by now (deepest-first ordering removed their
            // extra children); remove_dir refuses a non-empty dir, which would
            // surface an unexpected kept child rather than silently nuking it.
            MirrorEntryKind::Dir => {
                crate::fs::remove_dir(&x.abs_path).await?;
            }
        }
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
}
