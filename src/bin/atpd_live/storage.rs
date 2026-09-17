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
        let mut usage = self.usage.lock();
        let bytes = usage
            .bytes
            .checked_add(charge)
            .filter(|bytes| *bytes <= self.maximum_bytes);
        let entries = usage
            .entries
            .checked_add(2)
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
