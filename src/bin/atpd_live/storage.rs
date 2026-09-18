//! Conservative restart-aware inbox quotas, without deleting retained files.
//!
//! Charge both staging and destination entries at the full per-transfer limit
//! before creating either. Reservations are never refunded within a process:
//! failed/cancelled filesystem operations can still finish after their awaiter.
//! Restart rescans actual retained entries under the same exclusive lock. This
//! overcounts hard-link aliases deliberately; it is not physical block billing.

use super::settings::{InboxConfig, invalid, selector};
use asupersync::net::atp::sdk::NativeClientCertificateId;
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::Arc;

const LOCK_NAME: &str = ".atpd-live.lock";

#[derive(Debug)]
struct Usage {
    bytes: u64,
    entries: u64,
}

#[derive(Debug)]
pub(super) struct Inbox {
    pub directory: PathBuf,
    _lock: File,
    maximum_bytes: u64,
    maximum_entries: u64,
    usage: Mutex<Usage>,
}

pub(super) type Inboxes = BTreeMap<NativeClientCertificateId, Arc<Inbox>>;

pub(super) fn load(configs: &[InboxConfig]) -> io::Result<Inboxes> {
    if configs.is_empty() || configs.len() > 1024 {
        return Err(invalid("configure 1..=1024 client inboxes"));
    }
    let scan_limit = configs
        .iter()
        .try_fold(0_u64, |total, config| {
            total.checked_add(config.max_retained_entries)
        })
        .ok_or_else(|| invalid("aggregate inbox entry limit overflow"))?;
    if scan_limit > 1_000_000 {
        return Err(invalid(
            "aggregate inbox scan limit exceeds one million entries",
        ));
    }
    let mut result = BTreeMap::new();
    for config in configs {
        let id = selector(&config.certificate_sha256)?;
        if result.contains_key(&id) {
            return Err(invalid("duplicate client certificate selector"));
        }
        // Duplicate directories/aliases fail the exclusive lock instead of
        // creating independent quota domains over the same retained files.
        result.insert(id, Arc::new(Inbox::open(config)?));
    }
    Ok(result)
}

impl Inbox {
    fn open(config: &InboxConfig) -> io::Result<Self> {
        if !config.directory.is_absolute()
            || !(1..=1_000_000).contains(&config.max_retained_entries)
        {
            return Err(invalid(
                "inbox requires an absolute private directory and bounded entry count",
            ));
        }
        let metadata = std::fs::symlink_metadata(&config.directory)?;
        if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "inbox directory must be private and not a symlink",
            ));
        }
        let directory = std::fs::canonicalize(&config.directory)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(directory.join(LOCK_NAME))?;
        let held = lock.metadata()?;
        if !held.is_file() || held.nlink() != 1 || held.permissions().mode() & 0o077 != 0 {
            return Err(invalid(
                "inbox lock must be a private, single-link regular file",
            ));
        }
        lock.try_lock().map_err(io::Error::from)?;
        let named = std::fs::symlink_metadata(directory.join(LOCK_NAME))?;
        if (held.dev(), held.ino()) != (named.dev(), named.ino()) {
            return Err(invalid("inbox lock identity changed"));
        }
        let mut usage = Usage {
            bytes: 0,
            entries: 0,
        };
        for entry in std::fs::read_dir(&directory)? {
            let entry = entry?;
            usage.entries = usage
                .entries
                .checked_add(1)
                .ok_or_else(|| invalid("inbox entry count overflow"))?;
            if usage.entries > config.max_retained_entries {
                return Err(invalid("retained inbox entry limit exceeded"));
            }
            let metadata = std::fs::symlink_metadata(entry.path())?;
            if !metadata.is_file() {
                return Err(invalid(
                    "inbox contains a directory, symlink or special file",
                ));
            }
            usage.bytes = usage
                .bytes
                .checked_add(metadata.len())
                .ok_or_else(|| invalid("inbox byte count overflow"))?;
            if usage.bytes > config.max_retained_bytes {
                return Err(invalid("retained inbox byte limit exceeded"));
            }
        }
        Ok(Self {
            directory,
            _lock: lock,
            maximum_bytes: config.max_retained_bytes,
            maximum_entries: config.max_retained_entries,
            usage: Mutex::new(usage),
        })
    }

    pub fn reserve(&self, transfer_bytes: u64) -> io::Result<()> {
        let charge = transfer_bytes
            .checked_mul(2)
            .ok_or_else(|| invalid("inbox charge overflow"))?;
        self.reserve_charge(charge, 2)
    }

    /// Charge one in-place journaled data file, or only its remaining growth.
    /// For resume, `existing_bytes` must belong to the exclusively owned file
    /// already counted by this owner's startup scan. Call once before binding;
    /// connection retries reuse the reservation. No charges are ever refunded.
    pub fn reserve_private_file(&self, maximum: u64, existing_bytes: Option<u64>) -> io::Result<()> {
        let (bytes, entries) = match existing_bytes {
            Some(existing) => (maximum.checked_sub(existing)
                .ok_or_else(|| invalid("retained data exceeds transfer ceiling"))?, 0),
            None => (maximum, 1),
        };
        self.reserve_charge(bytes, entries)
    }

    fn reserve_charge(&self, charge: u64, entry_charge: u64) -> io::Result<()> {
        let mut usage = self.usage.lock();
        let bytes = usage
            .bytes
            .checked_add(charge)
            .filter(|bytes| *bytes <= self.maximum_bytes);
        let entries = usage
            .entries
            .checked_add(entry_charge)
            .filter(|entries| *entries <= self.maximum_entries);
        let (Some(bytes), Some(entries)) = (bytes, entries) else {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "inbox retention budget exhausted",
            ));
        };
        usage.bytes = bytes;
        usage.entries = entries;
        Ok(())
    }
}

#[cfg(test)]
mod journal_tests {
    use super::*;

    fn config(bytes: u64, entries: u64) -> InboxConfig {
        let directory = tempfile::tempdir().unwrap().keep();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        InboxConfig { certificate_sha256: "11".repeat(32), directory,
            max_retained_bytes: bytes, max_retained_entries: entries }
    }

    #[test]
    fn fresh_private_file_charges_one_entry_and_keeps_legacy_two_alias_accounting() {
        let config = config(10, 2); // lock plus one data file
        let inbox = Inbox::open(&config).unwrap();
        inbox.reserve_private_file(10, None).unwrap();
        assert_eq!((inbox.usage.lock().bytes, inbox.maximum_entries), (10, 2));
        assert_eq!(inbox.usage.lock().entries, 2);
        assert_eq!(inbox.reserve_private_file(0, None).unwrap_err().kind(), io::ErrorKind::StorageFull);
        drop(inbox);
        let legacy = Inbox::open(&config).unwrap();
        assert_eq!(legacy.reserve(5).unwrap_err().kind(), io::ErrorKind::StorageFull);
        assert_eq!((legacy.usage.lock().bytes, legacy.maximum_bytes), (0, 10));
        assert_eq!(legacy.usage.lock().entries, 1);
    }

    #[test]
    fn resumed_private_file_reserves_only_unwritten_bytes_without_another_entry() {
        let config = config(10, 2);
        std::fs::write(config.directory.join("partial"), b"abc").unwrap();
        let inbox = Inbox::open(&config).unwrap();
        assert_eq!(inbox.usage.lock().bytes, 3);
        inbox.reserve_private_file(10, Some(3)).unwrap();
        assert_eq!(inbox.usage.lock().bytes, 10);
        assert_eq!(inbox.usage.lock().entries, 2);
        assert_eq!(inbox.reserve_private_file(2, Some(3)).unwrap_err().kind(), io::ErrorKind::InvalidInput);
        assert_eq!(inbox.usage.lock().bytes, 10);
    }

    #[test]
    fn restart_cannot_ignore_other_retained_files_when_reserving_growth() {
        let config = config(10, 3);
        std::fs::write(config.directory.join("partial"), b"abc").unwrap();
        std::fs::write(config.directory.join("unrelated"), b"1234567").unwrap();
        let inbox = Inbox::open(&config).unwrap();
        assert_eq!(inbox.reserve_private_file(10, Some(3)).unwrap_err().kind(), io::ErrorKind::StorageFull);
        assert_eq!(inbox.usage.lock().bytes, 10);
        assert_eq!(inbox.usage.lock().entries, 3);
    }
}
