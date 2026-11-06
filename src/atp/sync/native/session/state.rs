//! Bounded two-slot snapshots. This is not a transfer or replay journal.

use super::NativeDirectoryStatePublication;
use super::super::{
    DirectoryEntryKind, DirectoryEntryMetadata, DirectoryManifest, DirectoryManifestEntry,
    DirectoryPath, NativeDirectoryError, NativeDirectoryLimits, NativeDirectorySnapshot,
    NativeRoot, PathNormalizationRules, PreparedNativeDirectorySync, Stamp, changed, checkpoint,
    directory_flags, disjoint_inventories, disjoint_roots, file_flags, io_error, limit,
    metadata_stamp, os_error, refused, revalidate_stamps, scan_root, stat_at, validate_profile,
};
use crate::cx::Cx;
use nix::dir::Dir;
use nix::fcntl::{OFlag, RenameFlags, openat, renameat2};
use nix::sys::stat::{Mode, SFlag};
use nix::unistd::{getegid, geteuid};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{File, TryLockError};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;
use std::sync::Arc;
use xattr::FileExt;

const MAGIC: &[u8] = b"ASUPERSYNC\0NATIVE_SYNC_STATE\0\x01";
const LOCK: &str = "lock";
const CURRENT: &str = "current.state";
const NEXT: &str = "next.state";
const SLOTS: [&str; 3] = [LOCK, CURRENT, NEXT];
const MAX_STATE_BYTES: usize = 64 * 1024 * 1024;
const IO_QUANTUM: usize = 16 * 1024;
const FOOTER_BYTES: usize = 32;
const BINDING_BYTES: usize = 48;

pub(super) struct Opened {
    pub(super) lease: Arc<Lease>,
    pub(super) baseline: DirectoryManifest,
    pub(super) generation: u64,
    pub(super) current: Stamp,
}

#[derive(Debug)]
pub(super) struct Lease {
    pub(super) directory: NativeRoot,
    pub(super) local: NativeRoot,
    pub(super) remote: NativeRoot,
    lock: File,
    lock_stamp: Stamp,
}

pub(super) fn validate_bound(maximum: usize) -> Result<(), NativeDirectoryError> {
    if maximum == 0 || maximum > MAX_STATE_BYTES {
        return Err(refused(Path::new(""), "max_state_bytes must be in 1..=67108864"));
    }
    Ok(())
}

pub(super) fn open(
    cx: &Cx,
    local: &Path,
    remote: &Path,
    directory: &Path,
    limits: NativeDirectoryLimits,
    maximum: usize,
    create: bool,
) -> Result<Opened, NativeDirectoryError> {
    checkpoint(cx)?;
    let empty = DirectoryManifest::new(PathNormalizationRules::default());
    if create { encoded_size(cx, &empty, maximum)?; }
    let local = NativeRoot::open(local)?;
    let remote = NativeRoot::open(remote)?;
    let directory = NativeRoot::open(directory)?;
    disjoint_roots(&local, &remote)?;
    disjoint_roots(&local, &directory)?;
    disjoint_roots(&remote, &directory)?;
    let slots = check_directory(cx, &directory, maximum)?;
    if create && slots.iter().any(Option::is_some) {
        return Err(refused(&directory.path, "create requires an empty state directory"));
    }
    // Existing sessions are locked before scanning. A new session first proves
    // that its empty directory is outside both complete native inventories.
    let lock = if create { None } else { Some(open_lock(&directory, false)?) };
    let local = scan_root(cx, local, limits)?;
    let remote = scan_root(cx, remote, limits)?;
    disjoint_inventories(&local, &remote)?;
    check_inventory(&local, &directory, &slots)?;
    check_inventory(&remote, &directory, &slots)?;
    revalidate_stamps(cx, &local)?;
    revalidate_stamps(cx, &remote)?;
    checkpoint(cx)?;
    let lock = match lock {
        Some(lock) => lock,
        None => open_lock(&directory, true)?,
    };
    let lock_stamp = private_file(&lock, &directory.path.join(LOCK))?;
    let lease = Arc::new(Lease {
        directory, local: local.root, remote: remote.root, lock, lock_stamp,
    });
    if create {
        let mut publication = NativeDirectoryStatePublication::Unchanged;
        let current = publish(cx, &lease, None, 0, &empty, limits, maximum, &mut publication)?;
        Ok(Opened { lease, baseline: empty, generation: 0, current })
    } else {
        let slots = lease.validate(cx, maximum)?;
        let expected = slots[1].ok_or_else(|| {
            refused(&lease.directory.path, "reopen requires a current state snapshot")
        })?;
        let (generation, baseline, current) = read_snapshot(cx, &lease, limits, maximum)?;
        if current != expected { return Err(changed(&lease.directory.path.join(CURRENT))); }
        lease.validate_current(cx, current, maximum)?;
        Ok(Opened { lease, baseline, generation, current })
    }
}

fn open_lock(directory: &NativeRoot, create: bool) -> Result<File, NativeDirectoryError> {
    let path = directory.path.join(LOCK);
    let lock = open_writable(directory, LOCK, create)?;
    let stamp = private_file(&lock, &path)?;
    if stamp.size != 0 { return Err(refused(&path, "state lock must be empty")); }
    match lock.try_lock() {
        Ok(()) => {
            if create { lock.sync_all().map_err(|error| io_error(&path, error))?; }
            Ok(lock)
        }
        Err(TryLockError::WouldBlock) => Err(refused(&path, "another session holds the state writer lease")),
        Err(TryLockError::Error(error)) => Err(io_error(&path, error)),
    }
}

fn open_writable(directory: &NativeRoot, name: &str, create: bool) -> Result<File, NativeDirectoryError> {
    let mut flags = OFlag::O_RDWR | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK;
    if create { flags |= OFlag::O_CREAT | OFlag::O_EXCL; }
    openat(&directory.file, name, flags, Mode::S_IRUSR | Mode::S_IWUSR)
        .map(File::from).map_err(|error| os_error(&directory.path.join(name), error))
}

fn private_file(file: &File, path: &Path) -> Result<Stamp, NativeDirectoryError> {
    let stamp = metadata_stamp(file, path)?;
    if stamp.kind(path)? != DirectoryEntryKind::File
        || stamp.mode & 0o7777 != 0o600
        || stamp.uid != geteuid().as_raw()
        || stamp.gid != getegid().as_raw()
        || file.list_xattr().map_err(|error| io_error(path, error))?.next().is_some()
    {
        return Err(refused(path, "state files require private singly linked owned regular files without visible xattrs"));
    }
    Ok(stamp)
}

fn check_directory(
    cx: &Cx,
    directory: &NativeRoot,
    maximum: usize,
) -> Result<[Option<Stamp>; 3], NativeDirectoryError> {
    directory.revalidate()?;
    let stamp = metadata_stamp(&directory.file, &directory.path)?;
    if stamp.mode & 0o7777 != 0o700
        || stamp.uid != geteuid().as_raw()
        || stamp.gid != getegid().as_raw()
        || directory.file.list_xattr().map_err(|error| io_error(&directory.path, error))?.next().is_some()
    {
        return Err(refused(&directory.path, "state directory requires mode 0700, effective ownership and no visible xattrs"));
    }
    let mut slots = [None; 3];
    let mut entries = Dir::openat(&directory.file, ".", directory_flags(), Mode::empty())
        .map_err(|error| os_error(&directory.path, error))?;
    for entry in entries.iter() {
        checkpoint(cx)?;
        let entry = entry.map_err(|error| os_error(&directory.path, error))?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." { continue; }
        let index = SLOTS.iter().position(|slot| slot.as_bytes() == name).ok_or_else(|| {
            refused(&directory.path, "state directory may contain only lock, current.state and next.state")
        })?;
        let path = directory.path.join(SLOTS[index]);
        let file = File::from(openat(&directory.file, SLOTS[index], file_flags(), Mode::empty())
            .map_err(|error| os_error(&path, error))?);
        let observed = private_file(&file, &path)?;
        if stat_at(&directory.file, SLOTS[index], &path)? != Some(observed) {
            return Err(changed(&path));
        }
        if index == 0 && observed.size != 0 { return Err(refused(&path, "state lock must be empty")); }
        if index != 0 && observed.size > maximum as u64 { return Err(limit(&path, "max_state_bytes")); }
        slots[index] = Some(observed);
    }
    if metadata_stamp(&directory.file, &directory.path)? != stamp {
        return Err(changed(&directory.path));
    }
    distinct_slots(&directory.path, &slots)?;
    Ok(slots)
}

fn distinct_slots(path: &Path, slots: &[Option<Stamp>; 3]) -> Result<(), NativeDirectoryError> {
    for (index, slot) in slots.iter().enumerate() {
        if let Some(slot) = slot {
            if slots[..index].iter().flatten().any(|other| other.identity == slot.identity) {
                return Err(refused(path, "state slots alias the same filesystem object"));
            }
        }
    }
    Ok(())
}

fn check_inventory(
    inventory: &NativeDirectorySnapshot,
    directory: &NativeRoot,
    slots: &[Option<Stamp>; 3],
) -> Result<(), NativeDirectoryError> {
    let overlaps = |identity| identity == directory.identity
        || slots.iter().flatten().any(|stamp| stamp.identity == identity);
    if overlaps(inventory.root.identity) || inventory.guards.values().any(|stamp| overlaps(stamp.identity)) {
        return Err(refused(&directory.path, "state aliases a synchronization inventory"));
    }
    Ok(())
}

impl Lease {
    fn validate(&self, cx: &Cx, maximum: usize) -> Result<[Option<Stamp>; 3], NativeDirectoryError> {
        checkpoint(cx)?;
        self.local.revalidate()?;
        self.remote.revalidate()?;
        let slots = check_directory(cx, &self.directory, maximum)?;
        if slots[0] != Some(self.lock_stamp)
            || private_file(&self.lock, &self.directory.path.join(LOCK))? != self.lock_stamp
        {
            return Err(changed(&self.directory.path.join(LOCK)));
        }
        Ok(slots)
    }

    pub(super) fn validate_current(
        &self, cx: &Cx, expected: Stamp, maximum: usize,
    ) -> Result<(), NativeDirectoryError> {
        if self.validate(cx, maximum)?[1] != Some(expected) {
            return Err(changed(&self.directory.path.join(CURRENT)));
        }
        Ok(())
    }

    pub(super) fn check_prepared(
        &self, cx: &Cx, prepared: &PreparedNativeDirectorySync, maximum: usize,
    ) -> Result<(), NativeDirectoryError> {
        let slots = self.validate(cx, maximum)?;
        for (snapshot, bound) in [(&prepared.local, &self.local), (&prepared.remote, &self.remote)] {
            if snapshot.root.path != bound.path || snapshot.root.identity != bound.identity {
                return Err(changed(&bound.path));
            }
            check_inventory(snapshot, &self.directory, &slots)?;
        }
        Ok(())
    }

    pub(super) fn check_staging(
        &self, cx: &Cx, path: &Path, limits: NativeDirectoryLimits,
    ) -> Result<(), NativeDirectoryError> {
        let staging = NativeRoot::open(path)?;
        disjoint_roots(&self.directory, &staging)?;
        // Retained jobs can be large: inspect bounded metadata, never hash their
        // contents. This catches a bind-mounted state directory hidden below an
        // otherwise disjoint staging path as well as direct ancestor overlap.
        let mut seen = BTreeSet::new();
        let mut count = 0;
        check_staging_children(cx, &staging.file, &staging.path, self, limits, 0, &mut count, &mut seen)?;
        staging.revalidate()
    }
}

#[allow(clippy::too_many_arguments)]
fn check_staging_children(
    cx: &Cx,
    directory: &File,
    path: &Path,
    lease: &Lease,
    limits: NativeDirectoryLimits,
    depth: usize,
    count: &mut usize,
    seen: &mut BTreeSet<super::super::Identity>,
) -> Result<(), NativeDirectoryError> {
    checkpoint(cx)?;
    let before = metadata_stamp(directory, path)?;
    if before.identity == lease.directory.identity || !seen.insert(before.identity) {
        return Err(refused(path, "staging contains state or an aliased directory"));
    }
    let mut entries = Dir::openat(directory, ".", directory_flags(), Mode::empty())
        .map_err(|error| os_error(path, error))?;
    for entry in entries.iter() {
        checkpoint(cx)?;
        let entry = entry.map_err(|error| os_error(path, error))?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." { continue; }
        *count = count.checked_add(1).ok_or_else(|| limit(path, "max_entries"))?;
        if *count > limits.max_entries { return Err(limit(path, "max_entries")); }
        let name = std::str::from_utf8(name).map_err(|_| refused(path, "staging names must be UTF-8"))?;
        let display = path.join(name);
        let stamp = stat_at(directory, name, &display)?.ok_or_else(|| changed(&display))?;
        if SFlag::from_bits_truncate(stamp.mode) & SFlag::S_IFMT != SFlag::S_IFDIR { continue; }
        if depth >= limits.max_depth { return Err(limit(&display, "max_depth")); }
        let child = File::from(openat(directory, name, directory_flags(), Mode::empty())
            .map_err(|error| os_error(&display, error))?);
        if metadata_stamp(&child, &display)? != stamp { return Err(changed(&display)); }
        check_staging_children(cx, &child, &display, lease, limits, depth + 1, count, seen)?;
    }
    if metadata_stamp(directory, path)? != before { return Err(changed(path)); }
    Ok(())
}

// Fixed-size bindings keep arbitrary native root spellings out of the decoder's
// allocation surface while still binding their exact canonical encoded bytes.
fn binding(root: &NativeRoot) -> [u8; BINDING_BYTES] {
    let mut hash = Sha256::new();
    hash.update(b"asupersync.native-directory-state-path.v1\0");
    hash.update(root.path.as_os_str().as_encoded_bytes());
    let mut bytes = [0; BINDING_BYTES];
    bytes[..32].copy_from_slice(&hash.finalize());
    bytes[32..40].copy_from_slice(&root.identity.device.to_be_bytes());
    bytes[40..].copy_from_slice(&root.identity.inode.to_be_bytes());
    bytes
}

pub(super) fn encoded_size(
    cx: &Cx, manifest: &DirectoryManifest, maximum: usize,
) -> Result<usize, NativeDirectoryError> {
    let mut size = MAGIC.len() + 8 + 3 * BINDING_BYTES + 8 + FOOTER_BYTES;
    if size > maximum { return Err(limit(Path::new(CURRENT), "max_state_bytes")); }
    for entry in manifest.entries.values() {
        checkpoint(cx)?;
        let path = entry.path.as_str();
        let _length = u32::try_from(path.len()).map_err(|_| limit(Path::new(path), "max_state_bytes"))?;
        let fixed = match entry.kind {
            DirectoryEntryKind::Directory => 5,
            DirectoryEntryKind::File => 45,
            _ => return Err(refused(Path::new(path), "state supports only native files and directories")),
        };
        size = size.checked_add(fixed).and_then(|size| size.checked_add(path.len()))
            .filter(|size| *size <= maximum).ok_or_else(|| limit(Path::new(path), "max_state_bytes"))?;
    }
    Ok(size)
}

/// Current is preserved until the complete inactive slot has been synced. After
/// exchange, prior current remains at NEXT even if directory synchronization fails.
#[allow(clippy::too_many_arguments)]
pub(super) fn publish(
    cx: &Cx,
    lease: &Lease,
    expected: Option<Stamp>,
    generation: u64,
    baseline: &DirectoryManifest,
    limits: NativeDirectoryLimits,
    maximum: usize,
    publication: &mut NativeDirectoryStatePublication,
) -> Result<Stamp, NativeDirectoryError> {
    publish_with_directory_sync(cx, lease, expected, generation, baseline, limits, maximum,
        publication, File::sync_all)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn publish_with_directory_sync<F>(
    cx: &Cx,
    lease: &Lease,
    expected: Option<Stamp>,
    generation: u64,
    baseline: &DirectoryManifest,
    limits: NativeDirectoryLimits,
    maximum: usize,
    publication: &mut NativeDirectoryStatePublication,
    sync_directory: F,
) -> Result<Stamp, NativeDirectoryError>
where
    F: FnOnce(&File) -> std::io::Result<()>,
{
    validate_profile(baseline, limits)?;
    let size = encoded_size(cx, baseline, maximum)?;
    let slots = lease.validate(cx, maximum)?;
    if slots[1] != expected || (expected.is_none() && slots[2].is_some()) {
        return Err(changed(&lease.directory.path.join(CURRENT)));
    }
    checkpoint(cx)?;
    let path = lease.directory.path.join(NEXT);
    *publication = NativeDirectoryStatePublication::Staging { generation };
    let file = open_writable(&lease.directory, NEXT, slots[2].is_none())?;
    let before = private_file(&file, &path)?;
    // nlink == 1 does not exclude a bind-mounted alias of current or the lock.
    // Assert the actual opened inode is distinct before any truncation.
    if expected.is_some_and(|current| current.identity == before.identity)
        || before.identity == lease.lock_stamp.identity
    {
        return Err(refused(&path, "inactive state slot aliases current or the writer lock"));
    }
    if slots[2].is_some_and(|stamp| stamp != before) { return Err(changed(&path)); }
    if stat_at(&lease.directory.file, NEXT, &path)? != Some(before) { return Err(changed(&path)); }
    file.set_len(0).map_err(|error| io_error(&path, error))?;
    let mut writer = SnapshotWriter {
        pending: Some(BufWriter::with_capacity(limits.buffer_bytes.min(maximum), file)),
        hash: Sha256::new(),
        remaining: size - FOOTER_BYTES,
        cx,
        path: &path,
    };
    writer.bytes(MAGIC)?;
    writer.bytes(&generation.to_be_bytes())?;
    for root in [&lease.local, &lease.remote, &lease.directory] { writer.bytes(&binding(root))?; }
    writer.bytes(&(baseline.entries.len() as u64).to_be_bytes())?;
    for entry in baseline.entries.values() {
        let path = entry.path.as_str().as_bytes();
        let length = u32::try_from(path.len()).map_err(|_| limit(&lease.directory.path, "max_state_bytes"))?;
        writer.bytes(&length.to_be_bytes())?;
        writer.bytes(path)?;
        writer.bytes(&[u8::from(entry.kind == DirectoryEntryKind::File)])?;
        if entry.kind == DirectoryEntryKind::File {
            let size = entry.metadata.size_bytes.ok_or_else(|| refused(&lease.directory.path, "state file has no size"))?;
            let digest = entry.content_id.as_deref().and_then(|id| id.strip_prefix("sha256:"))
                .ok_or_else(|| refused(&lease.directory.path, "state file has no SHA-256 digest"))?;
            let mut digest_bytes = [0; 32];
            hex::decode_to_slice(digest, &mut digest_bytes)
                .map_err(|_| refused(&lease.directory.path, "state file digest is invalid"))?;
            writer.bytes(&size.to_be_bytes())?;
            writer.bytes(&digest_bytes)?;
        }
    }
    if writer.remaining != 0 { return Err(refused(&path, "state encoded length differs from preflight")); }
    checkpoint(cx)?;
    let digest = writer.hash.clone().finalize();
    writer.writer().write_all(&digest).map_err(|error| io_error(&path, error))?;
    writer.writer().flush().map_err(|error| io_error(&path, error))?;
    writer.writer().get_ref().sync_all().map_err(|error| io_error(&path, error))?;
    let staged = private_file(writer.writer().get_ref(), &path)?;
    if staged.size != size as u64 { return Err(changed(&path)); }
    let slots = lease.validate(cx, maximum)?;
    if slots[1] != expected || slots[2] != Some(staged) {
        return Err(changed(&lease.directory.path));
    }
    checkpoint(cx)?;
    renameat2(
        &lease.directory.file, NEXT, &lease.directory.file, CURRENT,
        if expected.is_some() { RenameFlags::RENAME_EXCHANGE } else { RenameFlags::RENAME_NOREPLACE },
    ).map_err(|error| os_error(&lease.directory.path, error))?;
    *publication = NativeDirectoryStatePublication::Published { generation };
    // No checkpoints from exchange through durable directory publication.
    let current_path = lease.directory.path.join(CURRENT);
    let current = private_file(writer.writer().get_ref(), &current_path)?;
    if current.identity != staged.identity
        || current.size != staged.size
        || stat_at(&lease.directory.file, CURRENT, &current_path)? != Some(current)
    {
        return Err(changed(&current_path));
    }
    if let Some(previous) = expected {
        if stat_at(&lease.directory.file, NEXT, &path)?.map(|stamp| stamp.identity) != Some(previous.identity) {
            return Err(changed(&path));
        }
    }
    sync_directory(&lease.directory.file).map_err(|error| io_error(&lease.directory.path, error))?;
    *publication = NativeDirectoryStatePublication::Durable { generation };
    Ok(current)
}

struct SnapshotWriter<'a> {
    pending: Option<BufWriter<File>>,
    hash: Sha256,
    remaining: usize,
    cx: &'a Cx,
    path: &'a Path,
}

impl SnapshotWriter<'_> {
    fn writer(&mut self) -> &mut BufWriter<File> {
        self.pending.as_mut().expect("snapshot writer is present until drop")
    }

    fn bytes(&mut self, bytes: &[u8]) -> Result<(), NativeDirectoryError> {
        if bytes.len() > self.remaining { return Err(limit(self.path, "max_state_bytes")); }
        for chunk in bytes.chunks(IO_QUANTUM) {
            checkpoint(self.cx)?;
            let path = self.path;
            self.writer().write_all(chunk).map_err(|error| io_error(path, error))?;
            self.hash.update(chunk);
        }
        self.remaining -= bytes.len();
        Ok(())
    }
}

impl Drop for SnapshotWriter<'_> {
    fn drop(&mut self) {
        // An abandoned/error buffer must never retry writes from its destructor.
        if let Some(writer) = self.pending.take() { drop(writer.into_parts()); }
    }
}

struct SnapshotReader<'a> {
    reader: BufReader<File>,
    hash: Sha256,
    remaining: usize,
    cx: &'a Cx,
    path: &'a Path,
}

impl SnapshotReader<'_> {
    fn bytes(&mut self, bytes: &mut [u8]) -> Result<(), NativeDirectoryError> {
        if bytes.len() > self.remaining { return Err(refused(self.path, "truncated state record")); }
        for chunk in bytes.chunks_mut(IO_QUANTUM) {
            checkpoint(self.cx)?;
            self.reader.read_exact(chunk).map_err(|error| io_error(self.path, error))?;
            self.hash.update(&*chunk);
        }
        self.remaining -= bytes.len();
        Ok(())
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], NativeDirectoryError> {
        let mut bytes = [0; N];
        self.bytes(&mut bytes)?;
        Ok(bytes)
    }
}

fn read_snapshot(
    cx: &Cx, lease: &Lease, limits: NativeDirectoryLimits, maximum: usize,
) -> Result<(u64, DirectoryManifest, Stamp), NativeDirectoryError> {
    let path = lease.directory.path.join(CURRENT);
    let file = File::from(openat(&lease.directory.file, CURRENT, file_flags(), Mode::empty())
        .map_err(|error| os_error(&path, error))?);
    let before = private_file(&file, &path)?;
    let size = usize::try_from(before.size).ok().filter(|size| *size <= maximum)
        .ok_or_else(|| limit(&path, "max_state_bytes"))?;
    if size < MAGIC.len() + 8 + 3 * BINDING_BYTES + 8 + FOOTER_BYTES {
        return Err(refused(&path, "truncated state header"));
    }
    let mut reader = SnapshotReader {
        reader: BufReader::with_capacity(limits.buffer_bytes.min(size), file),
        hash: Sha256::new(), remaining: size - FOOTER_BYTES, cx, path: &path,
    };
    let mut magic = [0; MAGIC.len()];
    reader.bytes(&mut magic)?;
    if magic.as_slice() != MAGIC { return Err(refused(&path, "unknown state schema")); }
    let generation = u64::from_be_bytes(reader.array()?);
    for root in [&lease.local, &lease.remote, &lease.directory] {
        if reader.array::<BINDING_BYTES>()? != binding(root) {
            return Err(refused(&path, "state root identity or canonical path binding differs"));
        }
    }
    let count = u64::from_be_bytes(reader.array()?);
    let count = usize::try_from(count).ok()
        .filter(|count| *count <= limits.max_entries && *count <= reader.remaining / 5)
        .ok_or_else(|| limit(&path, "max_entries"))?;
    let mut manifest = DirectoryManifest::new(PathNormalizationRules::default());
    let mut total = 0_u64;
    for _ in 0..count {
        let length = u32::from_be_bytes(reader.array()?) as usize;
        if length == 0 || length >= reader.remaining {
            return Err(refused(&path, "state path length exceeds its bounded record"));
        }
        // The declared length is checked against the already bounded file before
        // this sole variable-sized decode allocation. No whole-file buffer exists.
        let mut bytes = vec![0; length];
        reader.bytes(&mut bytes)?;
        let name = String::from_utf8(bytes).map_err(|_| refused(&path, "state path is not UTF-8"))?;
        if name.contains('\\') || name.split('/').count() > limits.max_depth {
            return Err(refused(&path, "state path exceeds the native path profile"));
        }
        let relative = DirectoryPath::normalize(&name, manifest.path_rules)
            .map_err(NativeDirectoryError::Manifest)?;
        if relative.as_str() != name {
            return Err(refused(&path, "state path is not canonical in the native profile"));
        }
        if manifest.entries.last_key_value().is_some_and(|(previous, _)| previous >= &relative) {
            return Err(refused(&path, "state entries must be strictly ordered and unique"));
        }
        let (kind, content_id, metadata) = match reader.array::<1>()?[0] {
            0 => (DirectoryEntryKind::Directory, None, DirectoryEntryMetadata::default()),
            1 => {
                let bytes = u64::from_be_bytes(reader.array()?);
                if bytes > limits.max_file_bytes { return Err(limit(&path, "max_file_bytes")); }
                total = total.checked_add(bytes).filter(|total| *total <= limits.max_total_bytes)
                    .ok_or_else(|| limit(&path, "max_total_bytes"))?;
                let digest = reader.array::<32>()?;
                (DirectoryEntryKind::File, Some(format!("sha256:{}", hex::encode(digest))),
                    DirectoryEntryMetadata { size_bytes: Some(bytes), ..DirectoryEntryMetadata::default() })
            }
            _ => return Err(refused(&path, "state entry kind is outside the native profile")),
        };
        manifest.insert(DirectoryManifestEntry::new(relative, kind, content_id, metadata))
            .map_err(NativeDirectoryError::Manifest)?;
    }
    if reader.remaining != 0 { return Err(refused(&path, "state has trailing payload bytes")); }
    checkpoint(cx)?;
    let mut expected_digest = [0; FOOTER_BYTES];
    reader.reader.read_exact(&mut expected_digest).map_err(|error| io_error(&path, error))?;
    if reader.hash.clone().finalize()[..] != expected_digest[..] {
        return Err(refused(&path, "state checksum differs"));
    }
    let mut extra = [0; 1];
    if reader.reader.read(&mut extra).map_err(|error| io_error(&path, error))? != 0
        || private_file(reader.reader.get_ref(), &path)? != before
        || stat_at(&lease.directory.file, CURRENT, &path)? != Some(before)
    {
        return Err(changed(&path));
    }
    if generation == 0 && !manifest.entries.is_empty() {
        return Err(refused(&path, "generation zero cannot assert prior common history"));
    }
    validate_profile(&manifest, limits)?;
    // Reopen also resolves a previous process's unobserved/failed final directory
    // sync. Merely seeing valid cached bytes would not establish durability.
    checkpoint(cx)?;
    reader.reader.get_ref().sync_all().map_err(|error| io_error(&path, error))?;
    lease.directory.file.sync_all().map_err(|error| io_error(&lease.directory.path, error))?;
    Ok((generation, manifest, before))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_state_slots_refuse_single_link_inode_aliases_before_writing() {
        let first = Stamp {
            identity: super::super::super::Identity { device: 7, inode: 11 },
            mode: SFlag::S_IFREG.bits() | 0o600,
            uid: geteuid().as_raw(), gid: getegid().as_raw(), links: 1, size: 64,
            modified: (0, 0), changed: (0, 0),
        };
        let second = Stamp {
            identity: super::super::super::Identity { device: 7, inode: 12 }, ..first
        };
        let third = Stamp {
            identity: super::super::super::Identity { device: 7, inode: 13 }, ..first
        };
        let path = Path::new("/private/session");
        assert!(distinct_slots(path, &[Some(first), Some(second), Some(third)]).is_ok());
        assert!(distinct_slots(path, &[Some(first), None, None]).is_ok());
        for slots in [
            [Some(first), Some(first), None],
            [Some(first), Some(second), Some(second)],
            [Some(first), Some(second), Some(first)],
        ] {
            assert!(distinct_slots(path, &slots).is_err(), "separate names cannot authorize inode aliasing");
        }
    }
}
