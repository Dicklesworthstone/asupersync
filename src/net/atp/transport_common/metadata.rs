//! Transport-agnostic filesystem-metadata fidelity for ATP manifests.
//!
//! Epic `b0k8qo` phase J1: a sync tool that silently drops permissions, mtimes,
//! and symlinks is strictly worse than rsync. This module lets any ATP transport
//! capture per-entry filesystem metadata on the sender, carry it in the manifest,
//! and re-apply it on the receiver atomically with the file commit — gated by a
//! [`MetadataPolicy`] (reused from [`crate::atp::object`]).
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
//! Capturing and applying metadata is `#[cfg(unix)]`. On non-unix targets the
//! reader returns a bare [`EntryMetadata`] (file kind only) and the applier is a
//! no-op, so portable transfers still work. Fields the receiver cannot apply
//! (e.g. `uid`/`gid` without privilege) are reported as skipped, never fatal —
//! rsync-style graceful degradation.

use sha2::{Digest, Sha256};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::atp::object::MetadataPolicy;

use super::streaming::{StreamingError, hex_encode};

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
    /// Symlink target (forward-slash or platform path text) for `Symlink` kinds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symlink_target: Option<String>,
    /// Hardlink primary: when set, this entry is a hardlink to another entry in
    /// the same transfer (the value is that primary's transfer-relative path).
    /// Such an entry carries no content — the receiver `hard_link`s it to the
    /// primary (which sorts earlier and is committed first).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hardlink_target: Option<String>,
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
            && self.symlink_target.is_none()
            && self.hardlink_target.is_none()
    }

    /// Append this entry's canonical, domain-separated encoding to `hasher`. The
    /// presence byte before each optional field keeps "absent" distinct from a
    /// zero value so the commitment is collision-resistant across schemas.
    fn hash_into(&self, rel_path: &str, hasher: &mut Sha256) {
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
    hasher.update(b"asupersync.atp.metadata-commitment.v1\0");
    hasher.update((sorted.len() as u64).to_be_bytes());
    for (rel_path, meta) in sorted {
        meta.hash_into(rel_path, &mut hasher);
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
/// is **followed** and the entry takes its target's kind/content/metadata — so a
/// non-preserved symlink to a file transfers as that file rather than being
/// silently dropped to an empty placeholder. Returns a bare [`EntryMetadata`] on
/// non-unix targets.
///
/// # Errors
///
/// Returns [`StreamingError`] if the path cannot be stat'd, a preserved symlink's
/// target cannot be read, or a non-preserved symlink dangles (stat through the
/// link fails).
#[cfg(unix)]
pub async fn read_entry_metadata(
    abs_path: &Path,
    policy: &MetadataPolicy,
) -> Result<EntryMetadata, StreamingError> {
    use std::os::unix::fs::MetadataExt;

    let lmeta = crate::fs::symlink_metadata(abs_path)
        .await
        .map_err(|e| StreamingError::new(format!("{}: {e}", abs_path.display())))?;

    let mut meta = EntryMetadata::default();

    if lmeta.is_symlink() && policy.preserve_symlinks {
        meta.file_kind = FileKind::Symlink;
        let target = crate::fs::read_link(abs_path)
            .await
            .map_err(|e| StreamingError::new(format!("{}: {e}", abs_path.display())))?;
        meta.symlink_target = Some(target.to_string_lossy().into_owned());
        // Mode/owner/time on a symlink itself are rarely meaningful and need
        // lchown/lutimes; ATP preserves the link + target, not link metadata.
        return Ok(meta);
    }

    // For a non-preserved symlink, stat through the link so the entry reflects
    // its target (the streaming hash also follows the link); otherwise use the
    // path's own metadata.
    let effective = if lmeta.is_symlink() {
        crate::fs::metadata(abs_path)
            .await
            .map_err(|e| StreamingError::new(format!("{}: {e}", abs_path.display())))?
    } else {
        lmeta
    };

    if effective.is_dir() {
        meta.file_kind = FileKind::Directory;
    } else if !effective.is_file() {
        use std::os::unix::fs::FileTypeExt;
        let ft = effective.inner.file_type();
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

    let inner = &effective.inner;
    if policy.preserve_unix_permissions {
        meta.unix_mode = Some(inner.mode() & 0o7777);
    }
    if policy.preserve_timestamps {
        meta.mtime_unix_secs = Some(inner.mtime());
        meta.mtime_nanos = u32::try_from(inner.mtime_nsec().rem_euclid(1_000_000_000)).ok();
    }
    if policy.record_platform_metadata {
        meta.uid = Some(inner.uid());
        meta.gid = Some(inner.gid());
    }
    Ok(meta)
}

/// Non-unix capture: file kind only (regular vs directory), no platform
/// metadata. Symlinks are not represented on non-unix targets, so the link is
/// followed and the entry takes its target's kind (avoids an empty placeholder).
///
/// # Errors
///
/// Returns [`StreamingError`] if the path cannot be stat'd (a dangling symlink
/// fails closed here).
#[cfg(not(unix))]
pub async fn read_entry_metadata(
    abs_path: &Path,
    _policy: &MetadataPolicy,
) -> Result<EntryMetadata, StreamingError> {
    // `metadata` follows symlinks, so the recorded kind is the target's.
    let effective = crate::fs::metadata(abs_path)
        .await
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
    use std::os::unix::fs::MetadataExt;
    let lmeta = crate::fs::symlink_metadata(abs_path)
        .await
        .map_err(|e| StreamingError::new(format!("{}: {e}", abs_path.display())))?;
    if lmeta.is_file() {
        Ok(Some((lmeta.inner.dev(), lmeta.inner.ino())))
    } else {
        Ok(None)
    }
}

/// Non-unix: hardlink detection is unsupported; never reports an inode identity.
///
/// # Errors
///
/// Never returns an error on non-unix targets.
#[cfg(not(unix))]
pub async fn inode_key_if_regular(_abs_path: &Path) -> Result<Option<(u64, u64)>, StreamingError> {
    Ok(None)
}

/// Apply captured metadata to a committed regular file at `out_path`.
///
/// Applies in a safe order — times, then ownership, then mode last — so a
/// restrictive mode (e.g. `0o444`) does not block the earlier steps. Ownership
/// failures (typically `EPERM` without privilege) are recorded as skipped, not
/// fatal. Symlink entries are created by the caller's commit step, not here.
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
    use std::time::{Duration, UNIX_EPOCH};

    let mut report = MetadataApplyReport::default();

    // Times + ownership run on the blocking pool (sync std/`std::os::unix`).
    let path_buf = out_path.to_path_buf();
    let mtime_secs = meta.mtime_unix_secs;
    let mtime_nanos = meta.mtime_nanos.unwrap_or(0);
    let owner = match (meta.uid, meta.gid) {
        (Some(u), Some(g)) => Some((u, g)),
        _ => None,
    };

    let blocking: (Option<Result<(), String>>, Option<Result<(), String>>) =
        crate::runtime::spawn_blocking(move || {
            let time_res = mtime_secs.map(|secs| {
                let secs_u64 = u64::try_from(secs)
                    .map_err(|_| "pre-epoch mtime not representable".to_string())?;
                // `secs`/`mtime_nanos` arrive off-wire and are untrusted. Normalise
                // the sub-second part into [0, 1e9) (mirroring the read path's
                // `rem_euclid`) so an out-of-range value can't carry into the
                // seconds count, and add via `checked_add` so a crafted huge `secs`
                // (up to i64::MAX, which passes the u64 conversion) degrades to a
                // skipped mtime instead of panicking the blocking pool by
                // overflowing `SystemTime` (DoS via a malicious manifest).
                let nanos = mtime_nanos % 1_000_000_000;
                let when = UNIX_EPOCH
                    .checked_add(Duration::new(secs_u64, nanos))
                    .ok_or_else(|| "mtime out of representable range".to_string())?;
                let times = std::fs::FileTimes::new().set_modified(when);
                std::fs::File::open(&path_buf)
                    .and_then(|f| f.set_times(times))
                    .map_err(|e| e.to_string())
            });
            let owner_res = owner.map(|(u, g)| {
                std::os::unix::fs::chown(&path_buf, Some(u), Some(g)).map_err(|e| e.to_string())
            });
            (time_res, owner_res)
        })
        .await;

    match blocking.0 {
        Some(Ok(())) => report.mark_applied("mtime"),
        Some(Err(e)) => report.mark_skipped("mtime", e),
        None => {}
    }
    match blocking.1 {
        Some(Ok(())) => report.mark_applied("owner"),
        Some(Err(e)) => report.mark_skipped("owner", e),
        None => {}
    }

    if let Some(mode) = meta.unix_mode {
        crate::fs::set_permissions(out_path, crate::fs::Permissions::from_mode(mode))
            .await
            .map_err(|e| StreamingError::new(format!("{}: {e}", out_path.display())))?;
        report.mark_applied("mode");
    }

    Ok(report)
}

/// Non-unix apply: nothing to do; report every present field as skipped.
///
/// # Errors
///
/// Never returns an error on non-unix targets.
#[cfg(not(unix))]
pub async fn apply_entry_metadata(
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
    if meta.uid.is_some() || meta.gid.is_some() {
        report.mark_skipped("owner", "ownership unsupported on this platform");
    }
    Ok(report)
}

/// Recreate a FIFO (named pipe) at `out_path` with permission `mode`.
///
/// Uses `mkfifo` then `chmod` for the exact mode — neither opens the FIFO, so
/// this never blocks waiting for a peer (unlike `File::open` on a FIFO). Only
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

    fn meta(mode: Option<u32>) -> EntryMetadata {
        EntryMetadata {
            unix_mode: mode,
            ..Default::default()
        }
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
            symlink_target: Some("../t".to_string()),
            hardlink_target: None,
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
