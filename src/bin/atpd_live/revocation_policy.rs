//! Protected, monotonic operator policy for the shared receiver.
//!
//! Read and synchronize a complete snapshot before changing authority. Reload
//! never grants a certificate or removes a prior denial. No policy file is
//! created or repaired, and no transfer result is consumed by a policy change.

use super::super::settings::{invalid, selector};
use asupersync::Cx;
use asupersync::net::atp::sdk::native_auth::live::commit::resume::service::{
    MAX_REVOKED_RESUME_CLIENTS, ResumableService,
};
use asupersync::net::atp::sdk::{NativeClientAuthorization, NativeClientCertificateId};
use asupersync::runtime::spawn_blocking_io;
use asupersync::types::CancelReason;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs::{Metadata, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

const MAX_POLICY_BYTES: usize = 128 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    schema_version: u32,
    generation: u64,
    revoked_certificates: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Snapshot {
    generation: u64,
    revoked: BTreeSet<NativeClientCertificateId>,
}

impl Snapshot {
    fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() > MAX_POLICY_BYTES {
            return Err(invalid("revocation policy exceeds its byte limit"));
        }
        let document: Document = serde_json::from_slice(bytes)
            .map_err(|_| invalid("invalid revocation policy document"))?;
        if document.schema_version != 1
            || document.generation == 0
            || document.revoked_certificates.len() > MAX_REVOKED_RESUME_CLIENTS
        {
            return Err(invalid(
                "invalid revocation policy version, generation or count",
            ));
        }
        let mut revoked = BTreeSet::new();
        for certificate in document.revoked_certificates {
            if !revoked.insert(selector(&certificate)?) {
                return Err(invalid("duplicate revocation certificate"));
            }
        }
        Ok(Self {
            generation: document.generation,
            revoked,
        })
    }

    fn follows(&self, previous: &Self) -> io::Result<()> {
        if self.generation < previous.generation
            || (self.generation == previous.generation && self != previous)
            || !self.revoked.is_superset(&previous.revoked)
        {
            return Err(invalid(
                "revocation policy cannot roll back or remove a denial",
            ));
        }
        Ok(())
    }
}

struct Loaded {
    snapshot: Snapshot,
    directory: (u64, u64),
}

fn stamp(metadata: &Metadata) -> (u64, u64, u64, i64, i64, i64, i64, u32, u64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
        metadata.permissions().mode(),
        metadata.nlink(),
    )
}

fn read_policy(path: &Path) -> io::Result<Loaded> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(invalid("revocation policy requires an absolute file path"));
    }
    let parent = path
        .parent()
        .ok_or_else(|| invalid("revocation policy parent required"))?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_NONBLOCK)
        .open(parent)?;
    let directory_meta = directory.metadata()?;
    if directory_meta.permissions().mode() & 0o077 != 0 {
        return Err(invalid("revocation policy directory must be private"));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file()
        || before.nlink() != 1
        || before.permissions().mode() & 0o077 != 0
        || before.len() > MAX_POLICY_BYTES as u64
    {
        return Err(invalid(
            "revocation policy must be a bounded private single-link file",
        ));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(before.len()).unwrap_or(MAX_POLICY_BYTES));
    (&mut file)
        .take(MAX_POLICY_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    let snapshot = Snapshot::decode(&bytes)?;
    // Do not announce an applied policy before its file/name synchronization.
    // This is not malicious-writer protection or universal power-loss proof.
    file.sync_all()?;
    directory.sync_all()?;
    let named = std::fs::symlink_metadata(path)?;
    let parent_named = std::fs::symlink_metadata(parent)?;
    if stamp(&file.metadata()?) != stamp(&before)
        || !named.is_file()
        || (named.dev(), named.ino()) != (before.dev(), before.ino())
        || !parent_named.is_dir()
        || parent_named.permissions().mode() & 0o077 != 0
        || (parent_named.dev(), parent_named.ino()) != (directory_meta.dev(), directory_meta.ino())
    {
        return Err(invalid("revocation policy changed while being read"));
    }
    Ok(Loaded {
        snapshot,
        directory: (directory_meta.dev(), directory_meta.ino()),
    })
}

/// One policy owner; its immutable configured allowlist prevents privilege gain.
pub(super) struct RevocationPolicy {
    path: PathBuf,
    current: Loaded,
    configured: Vec<NativeClientCertificateId>,
    authorization: NativeClientAuthorization,
}

impl RevocationPolicy {
    pub(super) fn open(
        path: PathBuf,
        configured: Vec<NativeClientCertificateId>,
        authorization: NativeClientAuthorization,
    ) -> io::Result<Self> {
        let current = read_policy(&path)?;
        let policy = Self {
            path,
            current,
            configured,
            authorization,
        };
        policy.apply_tls(&policy.current.snapshot)?;
        Ok(policy)
    }

    pub(super) fn generation(&self) -> u64 {
        self.current.snapshot.generation
    }

    fn apply_tls(&self, snapshot: &Snapshot) -> io::Result<()> {
        self.authorization
            .replace_allowed(
                self.configured
                    .iter()
                    .copied()
                    .filter(|id| !snapshot.revoked.contains(id)),
            )
            .map_err(|_| invalid("revocation TLS policy could not be applied"))
    }

    fn install_snapshot<W>(
        snapshot: &Snapshot,
        service: &mut ResumableService<W>,
    ) -> io::Result<Value> {
        let mut newly_revoked = 0;
        let mut signalled_connections = 0;
        let mut retained_sessions = 0;
        for certificate in &snapshot.revoked {
            let changed = service
                .revoke_client(
                    *certificate,
                    CancelReason::user("atpd-live client revocation policy"),
                )
                .map_err(|_| invalid("revocation service policy could not be applied"))?;
            newly_revoked += usize::from(changed.newly_revoked);
            signalled_connections += changed.signalled_connections;
            retained_sessions += changed.retained_sessions;
        }
        Ok(
            json!({"schema_version": 1, "event": "revocation_policy_applied",
            "generation": snapshot.generation, "revoked_clients": snapshot.revoked.len(),
            "newly_revoked": newly_revoked, "signalled_connections": signalled_connections,
            "retained_sessions": retained_sessions, "drained": false}),
        )
    }

    pub(super) fn install<W>(&self, service: &mut ResumableService<W>) -> io::Result<()> {
        Self::install_snapshot(&self.current.snapshot, service).map(|_| ())
    }

    /// One bounded read on the blocking pool. Caller stops the service on ANY
    /// error; a failed requested revocation must not silently keep serving.
    pub(super) async fn reload<W>(
        &mut self,
        cx: &Cx,
        timeout: Duration,
        service: &mut ResumableService<W>,
    ) -> io::Result<Value> {
        let path = self.path.clone();
        let candidate = asupersync::time::timeout(
            cx.now(),
            timeout,
            spawn_blocking_io(move || read_policy(&path)),
        )
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        candidate.snapshot.follows(&self.current.snapshot)?;
        if candidate.directory != self.current.directory {
            return Err(invalid("revocation policy directory identity changed"));
        }
        // Do not yield admission between TLS tightening and service revocation.
        self.apply_tls(&candidate.snapshot)?;
        let event = Self::install_snapshot(&candidate.snapshot, service)?;
        self.current = candidate;
        Ok(event)
    }

    pub(super) fn fail_closed<W>(&self, service: &mut ResumableService<W>) {
        // Empty replacement cannot exceed the verifier's input bound.
        let _ = self.authorization.replace_allowed(std::iter::empty());
        service.cancel(CancelReason::user(
            "atpd-live revocation policy unavailable",
        ));
    }
}

#[cfg(test)]
#[path = "revocation_policy_inline_tests.rs"]
mod tests;
