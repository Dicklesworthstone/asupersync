//! Durable, finite upload preparation and restart recovery on Unix filesystems.
//!
//! Checkpoints live under an explicitly trusted private local directory. They
//! retain plaintext payload bytes and a versioned journal, not TLS keys or peer
//! authority. File and directory fsync plus atomic journal replacement define
//! the persistence boundary; the underlying filesystem must honor those calls.
//! A checkpoint becomes usable only after complete source EOF. This is not
//! recovery of a partially consumed producer or remote byte-offset resumption.
//! Durable cancellation revokes later local attempts. It retains the source
//! and any uncertain delivery evidence; it cannot undo a remote publication.

use super::{
    BufferReader, MAX_UPLOAD_BUFFER, NativeAdmission, NativeTransferClient, NativeTransferError,
    NativeUploadCleanupError, NativeUploadError, NativeUploadOptions, SPOOL_CREATE_ATTEMPTS, Spool,
    SpoolProgress, checkpoint, spool_source, validate_upload,
};
use crate::cx::{Cx, Scope};
use crate::io::AsyncRead;
use crate::net::atp::transport_quic::{self, ReceiveReceipt, SendReport};
use crate::runtime::{TaskHandle, spawn_blocking_io};
use crate::types::Policy;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{DirBuilder, File, OpenOptions, TryLockError};
use std::future::Future;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

const JOURNAL_VERSION: u32 = 1;
// Older readers must refuse a cancelled checkpoint, rather than silently
// ignoring a sidecar and admitting another send from its retained payload.
const CANCELLED_JOURNAL_VERSION: u32 = 2;
const JOURNAL_LIMIT: u64 = 128 * 1024;
/// Finite lifetime network-attempt ceiling for one durable checkpoint.
pub const MAX_CHECKPOINT_ATTEMPTS: u64 = 32;

/// Persistence, input, ownership, or recovery-policy refusal.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NativeCheckpointError {
    /// The original input or spool failure.
    #[error(transparent)]
    Upload(#[from] NativeUploadError),
    /// The original native admission or transport failure.
    #[error(transparent)]
    Native(#[from] NativeTransferError),
    /// Original local filesystem error.
    #[error("checkpoint I/O failed: {0}")]
    Io(#[from] io::Error),
    /// A malformed, oversized, unsupported, or inconsistent checkpoint.
    #[error("invalid checkpoint: {0}")]
    Invalid(&'static str),
    /// Another cooperating handle/process owns this checkpoint.
    ///
    /// The lock is an OS file lock on an open file description. A subprocess
    /// spawned while a handle holds it keeps a copy until the child executes its
    /// program, so `Busy` can be transient if another thread spawns processes.
    #[error("checkpoint is already in use")]
    Busy,
    /// Current endpoint, TLS server name, or local SDK identity differs.
    #[error("checkpoint destination or client identity does not match")]
    BindingMismatch,
    /// Retained bytes differ from the fully prepared source.
    #[error("checkpoint payload size or SHA-256 does not match")]
    SourceChanged,
    /// The previous send may have committed remotely. No implicit retry.
    #[error("attempt {attempt} has uncertain delivery; explicit retry acknowledgement required")]
    Uncertain {
        /// The exact attempt an operator must reconcile or acknowledge.
        attempt: u64,
    },
    /// A stale retry decision cannot authorize another attempt.
    #[error("checkpoint retry decision names a different attempt")]
    StaleAttempt,
    /// The caller's snapshot names different source or checkpoint facts.
    #[error("checkpoint cancellation snapshot does not match the retained source")]
    SnapshotMismatch,
    /// A durable cancellation forbids every later network attempt.
    #[error("checkpoint cancelled at attempt {attempt}; delivery uncertain: {delivery_uncertain}")]
    Cancelled {
        /// Last admitted attempt, or zero if no send was ever admitted.
        attempt: u64,
        /// An earlier attempt may already have published remotely.
        delivery_uncertain: bool,
    },
    /// This checkpoint used its finite lifetime attempt budget.
    #[error("checkpoint network-attempt budget exhausted")]
    AttemptsExhausted,
    /// Retains a real but inconsistent native report for reconciliation.
    #[error("native receipt does not match the prepared upload")]
    ReceiptMismatch(Box<SendReport>),
    /// Publication may have partially completed. The retained path is explicit.
    #[error("checkpoint publication failed at {directory:?}: {error}")]
    Publication {
        /// Newly created private directory, possibly incomplete; never auto-deleted.
        directory: PathBuf,
        /// Original filesystem error.
        error: io::Error,
    },
}

/// Persisted lifecycle, independent of task handles and diagnostic progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeCheckpointState {
    /// Entire source was fsynced; no network attempt has been admitted.
    Prepared,
    /// A durable intent exists; delivery may have occurred, even after a crash.
    Sending,
    /// The actual native peer receipt was durably retained.
    Acknowledged,
}

/// Inspectable facts, not a capability to redirect or rewrite a checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NativeUploadCheckpoint {
    /// Canonical private checkpoint directory. Payload and journal are retained.
    pub directory: PathBuf,
    /// Explicitly bound destination socket address.
    pub remote: SocketAddr,
    /// Original portable remote filename.
    pub file_name: String,
    /// Complete logical source size, not network progress.
    pub source_bytes: u64,
    /// SHA-256 of the entire prepared source.
    pub source_sha256: [u8; 32],
    /// Persisted lifecycle, with `Sending` interpreted as uncertain delivery.
    pub state: NativeCheckpointState,
    /// Zero before any attempt; monotonically increases before each send.
    pub attempt: u64,
}

/// Durable checkpoint status, including local revocation and actual receipts.
///
/// The original lifecycle is retained in `checkpoint.state`: a cancelled
/// `Sending` checkpoint still has uncertain remote delivery. Cancellation
/// prevents later local sends; it neither erases that fact nor claims remote
/// rollback. An acknowledged checkpoint is never changed into a cancellation.
#[derive(Debug)]
#[non_exhaustive]
pub struct NativeCheckpointStatus {
    /// Last durably recorded source, destination and network-attempt facts.
    pub checkpoint: NativeUploadCheckpoint,
    /// True only for a durable terminal cancellation journal.
    pub cancelled: bool,
    /// Retained actual native receipt, if delivery was durably acknowledged.
    pub receipt: Option<SendReport>,
}

impl NativeCheckpointStatus {
    /// Whether a prior attempt may have committed without a retained receipt.
    #[must_use]
    pub fn delivery_uncertain(&self) -> bool {
        self.checkpoint.state == NativeCheckpointState::Sending
    }
}

/// Successfully published checkpoint plus independent ephemeral-spool cleanup.
#[derive(Debug)]
#[must_use = "retain the checkpoint directory and inspect local cleanup diagnostics"]
pub struct NativeCheckpointPreparation {
    /// Source and destination facts loaded from the published journal.
    pub checkpoint: NativeUploadCheckpoint,
    /// Failure cleaning the old ephemeral spool; does not invalidate checkpoint.
    pub cleanup_error: Option<NativeUploadCleanupError>,
}

/// Explicit policy for a new attempt; never inferred from an elapsed timeout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NativeCheckpointRetry {
    /// Send only a prepared, never-attempted source. Reuse a saved receipt.
    #[default]
    Never,
    /// The caller accepts that this specific earlier attempt may have committed.
    /// The exact attempt fences stale or concurrently reused retry decisions.
    AcknowledgeUncertain {
        /// Attempt returned by checkpoint inspection, not an arbitrary retry count.
        attempt: u64,
    },
}

/// Network outcome and local receipt persistence are independent terminal facts.
#[derive(Debug)]
#[must_use = "inspect the network outcome, persistence failure and cached-receipt flag"]
pub struct NativeCheckpointAttempt {
    /// Last durably confirmed local state; persistence failure may leave a newer
    /// journal visible but is never reported as confirmed durability here.
    pub checkpoint: NativeUploadCheckpoint,
    /// Full native result, including partial/ambiguous publication diagnostics.
    pub outcome: Result<SendReport, NativeCheckpointError>,
    /// True only when returning a historical saved receipt without networking.
    pub cached_receipt: bool,
    /// Saving a successful peer receipt failed. Never discard that receipt or
    /// automatically retry because of this independent local failure.
    pub persistence_error: Option<io::Error>,
}

/// Scope-owned retry task. Outer join errors do not forge an inner receipt.
pub type NativeCheckpointTask = TaskHandle<Result<NativeCheckpointAttempt, NativeCheckpointError>>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredReceipt {
    transfer_id: String,
    bytes_sent: u64,
    files: u32,
    symbols_sent: u64,
    feedback_rounds: u32,
    merkle_root_hex: String,
    receipt: ReceiveReceipt,
    peer: SocketAddr,
}

impl StoredReceipt {
    fn capture(report: &SendReport) -> Self {
        Self {
            transfer_id: report.transfer_id.clone(),
            bytes_sent: report.bytes_sent,
            files: report.files,
            symbols_sent: report.symbols_sent,
            feedback_rounds: report.feedback_rounds,
            merkle_root_hex: report.merkle_root_hex.clone(),
            receipt: report.receipt.clone(),
            peer: report.peer,
        }
    }

    fn report(&self) -> SendReport {
        SendReport {
            transfer_id: self.transfer_id.clone(),
            bytes_sent: self.bytes_sent,
            files: self.files,
            symbols_sent: self.symbols_sent,
            feedback_rounds: self.feedback_rounds,
            merkle_root_hex: self.merkle_root_hex.clone(),
            receipt: self.receipt.clone(),
            peer: self.peer,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u32,
    file_name: String,
    source_bytes: u64,
    source_sha256: [u8; 32],
    remote: SocketAddr,
    server_name: String,
    local_peer_label: String,
    state: NativeCheckpointState,
    attempt: u64,
    receipt: Option<StoredReceipt>,
    #[serde(default, skip_serializing_if = "is_false")]
    cancelled: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

impl Journal {
    fn next_attempt(&self, retry: NativeCheckpointRetry) -> Result<u64, NativeCheckpointError> {
        self.require_active()?;
        match (self.state, retry) {
            (NativeCheckpointState::Prepared, NativeCheckpointRetry::Never) => {}
            (NativeCheckpointState::Sending, NativeCheckpointRetry::Never) => {
                return Err(NativeCheckpointError::Uncertain {
                    attempt: self.attempt,
                });
            }
            (
                NativeCheckpointState::Sending,
                NativeCheckpointRetry::AcknowledgeUncertain { attempt },
            ) if attempt == self.attempt => {}
            _ => return Err(NativeCheckpointError::StaleAttempt),
        }
        if self.attempt >= MAX_CHECKPOINT_ATTEMPTS {
            return Err(NativeCheckpointError::AttemptsExhausted);
        }
        Ok(self.attempt + 1)
    }

    fn validate(&self) -> Result<(), NativeCheckpointError> {
        if !matches!(
            (self.version, self.cancelled),
            (JOURNAL_VERSION, false) | (CANCELLED_JOURNAL_VERSION, true)
        ) {
            return Err(NativeCheckpointError::Invalid("unsupported schema version"));
        }
        if self.cancelled && self.state == NativeCheckpointState::Acknowledged {
            return Err(NativeCheckpointError::Invalid(
                "acknowledged delivery cannot be cancelled",
            ));
        }
        NativeUploadOptions::new("unused", &self.file_name).validate()?;
        if self.server_name.is_empty()
            || self.server_name.len() > 253
            || self.local_peer_label.len() != 64
            || !self.local_peer_label.bytes().all(|b| b.is_ascii_hexdigit())
            || self.remote.port() == 0
            || self.remote.ip().is_unspecified()
        {
            return Err(NativeCheckpointError::Invalid(
                "invalid endpoint or identity",
            ));
        }
        let valid = match self.state {
            NativeCheckpointState::Prepared => self.attempt == 0 && self.receipt.is_none(),
            NativeCheckpointState::Sending => {
                (1..=MAX_CHECKPOINT_ATTEMPTS).contains(&self.attempt) && self.receipt.is_none()
            }
            NativeCheckpointState::Acknowledged => {
                (1..=MAX_CHECKPOINT_ATTEMPTS).contains(&self.attempt)
                    && self
                        .receipt
                        .as_ref()
                        .is_some_and(|r| self.receipt_matches(&r.report()))
            }
        };
        if !valid {
            return Err(NativeCheckpointError::Invalid(
                "inconsistent lifecycle or receipt",
            ));
        }
        Ok(())
    }

    fn receipt_matches(&self, report: &SendReport) -> bool {
        report.peer == self.remote
            && report.files == 1
            && report.receipt.files == 1
            && report.receipt.bytes_received == self.source_bytes
            && report.receipt.committed
            && report.receipt.sha_ok
            && report.receipt.merkle_ok
            && report.receipt.reason.is_none()
            && !report.transfer_id.is_empty()
            && report.merkle_root_hex.len() == 64
            && report
                .merkle_root_hex
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
    }

    fn info(&self, directory: PathBuf) -> NativeUploadCheckpoint {
        NativeUploadCheckpoint {
            directory,
            remote: self.remote,
            file_name: self.file_name.clone(),
            source_bytes: self.source_bytes,
            source_sha256: self.source_sha256,
            state: self.state,
            attempt: self.attempt,
        }
    }

    fn status(&self, directory: PathBuf) -> NativeCheckpointStatus {
        NativeCheckpointStatus {
            checkpoint: self.info(directory),
            cancelled: self.cancelled,
            receipt: self.receipt.as_ref().map(StoredReceipt::report),
        }
    }

    fn require_active(&self) -> Result<(), NativeCheckpointError> {
        if self.cancelled {
            return Err(NativeCheckpointError::Cancelled {
                attempt: self.attempt,
                delivery_uncertain: self.state == NativeCheckpointState::Sending,
            });
        }
        Ok(())
    }

    fn check_cancellation_snapshot(
        &self,
        directory: &Path,
        expected: &NativeUploadCheckpoint,
    ) -> Result<(), NativeCheckpointError> {
        if directory != expected.directory.as_path()
            || self.remote != expected.remote
            || self.file_name != expected.file_name
            || self.source_bytes != expected.source_bytes
            || self.source_sha256 != expected.source_sha256
        {
            return Err(NativeCheckpointError::SnapshotMismatch);
        }
        // A committed winner is immutable and can be reported to a stale
        // observer of this exact source/binding. It is never cancelled. Every
        // nonterminal decision requires the exact observed attempt and phase.
        if self.receipt.is_none()
            && (self.attempt != expected.attempt || self.state != expected.state)
        {
            return Err(NativeCheckpointError::StaleAttempt);
        }
        Ok(())
    }

    fn check_binding(
        &self,
        admission: &NativeAdmission,
        remote: SocketAddr,
    ) -> Result<(), NativeCheckpointError> {
        if self.remote != remote
            || self.server_name != server_name(admission)?
            || self.local_peer_label != admission.shared.peer_label
        {
            return Err(NativeCheckpointError::BindingMismatch);
        }
        if self.source_bytes > admission.shared.config.max_transfer_bytes {
            return Err(NativeUploadError::TooLarge {
                limit: admission.shared.config.max_transfer_bytes,
            }
            .into());
        }
        Ok(())
    }
}

fn server_name(admission: &NativeAdmission) -> Result<String, NativeCheckpointError> {
    let tls = admission
        .shared
        .config
        .client_tls
        .as_ref()
        .ok_or(NativeTransferError::MissingClientTls)?;
    Ok(tls.server_name.to_str().into_owned())
}

fn authorize(cx: &Cx) -> Result<(), NativeCheckpointError> {
    let caps = cx.capabilities();
    if !caps.io || !caps.entropy || !caps.time {
        return Err(NativeUploadError::MissingCapability.into());
    }
    checkpoint(cx)?;
    Ok(())
}

fn regular_file(path: &Path) -> io::Result<()> {
    if !std::fs::symlink_metadata(path)?.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "checkpoint path is not a regular file",
        ));
    }
    Ok(())
}

fn read_journal(directory: &Path) -> Result<Journal, NativeCheckpointError> {
    let path = directory.join("journal.json");
    regular_file(&path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let mut bytes = Vec::new();
    file.take(JOURNAL_LIMIT + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > JOURNAL_LIMIT {
        return Err(NativeCheckpointError::Invalid("journal exceeds size limit"));
    }
    let record: Journal = serde_json::from_slice(&bytes)
        .map_err(|_| NativeCheckpointError::Invalid("malformed journal"))?;
    record.validate()?;
    Ok(record)
}

fn write_journal(directory: &Path, record: &Journal, nonce: &[u8; 16]) -> io::Result<()> {
    let bytes = serde_json::to_vec(record).map_err(io::Error::other)?;
    if bytes.len() as u64 > JOURNAL_LIMIT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "journal exceeds size limit",
        ));
    }
    let temporary = directory.join(format!(".journal-{}.next", hex::encode(nonce)));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(temporary, directory.join("journal.json"))?;
    File::open(directory)?.sync_all()
}

// Never remove or replace the lock inode. The OS releases it on close/process
// exit; a crashed owner cannot strand a create-new lockfile. Blocking jobs hold
// Arc<Lease> so dropping an async wait cannot admit a competing journal writer.
struct Lease {
    _lock: File,
    directory: PathBuf,
    admission: NativeAdmission,
}

impl Lease {
    fn open(
        directory: &Path,
        admission: NativeAdmission,
    ) -> Result<(Arc<Self>, Journal), NativeCheckpointError> {
        let meta = std::fs::symlink_metadata(directory)?;
        if !meta.file_type().is_dir() || meta.mode() & 0o077 != 0 {
            return Err(NativeCheckpointError::Invalid(
                "checkpoint directory must be private and not a symlink",
            ));
        }
        let directory = directory.canonicalize()?;
        let path = directory.join("lock");
        regular_file(&path)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(NativeCheckpointError::Busy),
            Err(TryLockError::Error(error)) => return Err(error.into()),
        }
        let record = read_journal(&directory)?;
        Ok((
            Arc::new(Self {
                _lock: lock,
                directory,
                admission,
            }),
            record,
        ))
    }
}

fn publish_prepared(
    spool: &Spool,
    record: &Journal,
    nonce: &[u8; 16],
) -> Result<PathBuf, NativeCheckpointError> {
    let parent = spool
        .directory
        .parent()
        .ok_or(NativeCheckpointError::Invalid("spool has no parent"))?;
    let directory = parent.join(format!(".atp-checkpoint-{}", hex::encode(nonce)));
    // Collision never touches a pre-existing checkpoint or claims its ownership.
    DirBuilder::new().mode(0o700).create(&directory)?;
    let publish = || -> io::Result<()> {
        let payload = directory.join("payload");
        DirBuilder::new().mode(0o700).create(&payload)?;
        let path = payload.join(&record.file_name);
        std::fs::hard_link(&spool.path, &path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400))?;
        File::open(&path)?.sync_all()?;
        File::open(&payload)?.sync_all()?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.join("lock"))?;
        lock.try_lock().map_err(io::Error::from)?;
        lock.sync_all()?;
        write_journal(&directory, record, nonce)?;
        File::open(parent)?.sync_all()
    };
    publish().map_err(|error| NativeCheckpointError::Publication {
        directory: directory.clone(),
        error,
    })?;
    Ok(directory)
}

impl NativeTransferClient {
    /// Prepare an entire source for sending after restart, without networking.
    ///
    /// The input is spooled with the existing byte bound, cancellation and idle
    /// timeout. At EOF its fsynced file is hard-linked into a fresh checkpoint
    /// directory on the same filesystem, and a versioned journal is atomically
    /// published. No object-sized copy or second buffer is made. The checkpoint
    /// remains after this client/process exits and is never auto-deleted.
    /// Retain its directory; it contains plaintext under Unix 0700/0400 modes.
    /// The parent must be trusted against concurrent local replacement.
    ///
    /// A crash before publication may leave an incomplete directory, never a
    /// fabricated valid checkpoint. Remote byte-offset resume and recovery of
    /// a producer interrupted before EOF are not supplied by this API.
    pub async fn prepare_reader<R: AsyncRead + Unpin>(
        &self,
        cx: &Cx,
        remote: SocketAddr,
        options: NativeUploadOptions,
        mut reader: R,
    ) -> Result<NativeCheckpointPreparation, NativeCheckpointError> {
        validate_upload(cx, &options)?;
        let admission = Arc::new(self.admit_sender()?);
        let mut record = Journal {
            version: JOURNAL_VERSION,
            file_name: options.file_name.clone(),
            source_bytes: 0,
            source_sha256: [0; 32],
            remote,
            server_name: server_name(&admission)?,
            local_peer_label: admission.shared.peer_label.clone(),
            state: NativeCheckpointState::Prepared,
            attempt: 0,
            receipt: None,
            cancelled: false,
        };
        record.validate()?;
        let mut created = None;
        for _ in 0..SPOOL_CREATE_ATTEMPTS {
            checkpoint(cx)?;
            let mut nonce = [0; 16];
            cx.random_bytes(&mut nonce);
            let parent = options.spool_parent.clone();
            let name = options.file_name.clone();
            let owner = Arc::clone(&admission);
            match spawn_blocking_io(move || Spool::create(&parent, &name, &nonce, owner)).await {
                Ok(spool) => {
                    created = Some(spool);
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        let spool = created.ok_or(NativeCheckpointError::Invalid(
            "spool collision budget exhausted",
        ))?;
        let limit = options
            .max_bytes
            .unwrap_or(u64::MAX)
            .min(admission.shared.config.max_transfer_bytes);
        let digest = spool_source(
            cx,
            &mut reader,
            &spool,
            limit,
            admission.shared.config.chunk_size.min(MAX_UPLOAD_BUFFER),
            options.source_idle_timeout,
            SpoolProgress {
                written: &mut record.source_bytes,
                observer: None,
            },
        )
        .await;
        let published = match digest {
            Err(error) => Err(error.into()),
            Ok(digest) => {
                record.source_sha256 = digest;
                let owner = Arc::clone(&spool);
                let saved = record.clone();
                let mut nonce = [0; 16];
                cx.random_bytes(&mut nonce);
                spawn_blocking_io(move || Ok(publish_prepared(&owner, &saved, &nonce)))
                    .await
                    .map_err(NativeCheckpointError::from)
                    .and_then(|result| result)
            }
        };
        let owner = Arc::clone(&spool);
        let cleanup_error = spawn_blocking_io(move || owner.cleanup())
            .await
            .err()
            .map(|error| NativeUploadCleanupError {
                directory: spool.directory.clone(),
                error,
            });
        let directory = published?;
        Ok(NativeCheckpointPreparation {
            checkpoint: record.info(directory),
            cleanup_error,
        })
    }

    /// Prepare a borrowed buffer with the same bounded, durable source path.
    pub async fn prepare_buffer(
        &self,
        cx: &Cx,
        remote: SocketAddr,
        options: NativeUploadOptions,
        data: &[u8],
    ) -> Result<NativeCheckpointPreparation, NativeCheckpointError> {
        self.prepare_reader(cx, remote, options, BufferReader(data))
            .await
    }

    /// Inspect the journal under an exclusive, nonblocking OS lock. No send.
    ///
    /// Rechecks the explicitly supplied endpoint, current TLS server name,
    /// diagnostic local identity, and current byte ceiling. These comparisons
    /// do not turn local metadata or a peer label into remote authorization.
    /// This is journal inspection, not a rehash of the retained source.
    /// A cancelled checkpoint returns [`NativeCheckpointError::Cancelled`];
    /// use [`Self::inspect_checkpoint_status`] to inspect its terminal facts.
    pub async fn inspect_checkpoint(
        &self,
        cx: &Cx,
        directory: &Path,
        remote: SocketAddr,
    ) -> Result<NativeUploadCheckpoint, NativeCheckpointError> {
        authorize(cx)?;
        let admission = self.admit_sender()?;
        let directory = directory.to_path_buf();
        let (lease, record) =
            spawn_blocking_io(move || Ok(Lease::open(&directory, admission))).await??;
        record.check_binding(&lease.admission, remote)?;
        record.require_active()?;
        Ok(record.info(lease.directory.clone()))
    }

    /// Inspect active or durably cancelled state without sending or rehashing.
    ///
    /// Like [`Self::inspect_checkpoint`], this acquires the checkpoint's
    /// exclusive, nonblocking OS lease and validates the current client,
    /// endpoint and byte ceiling before exposing status or a saved receipt.
    /// Corrupt, oversized or unsupported journals remain errors.
    pub async fn inspect_checkpoint_status(
        &self,
        cx: &Cx,
        directory: &Path,
        remote: SocketAddr,
    ) -> Result<NativeCheckpointStatus, NativeCheckpointError> {
        authorize(cx)?;
        let admission = self.admit_sender()?;
        let directory = directory.to_path_buf();
        let (lease, record) =
            spawn_blocking_io(move || Ok(Lease::open(&directory, admission))).await??;
        record.check_binding(&lease.admission, remote)?;
        if record.cancelled {
            confirm_cancellation(&lease).await?;
        }
        Ok(record.status(lease.directory.clone()))
    }

    /// Durably forbid future sends from this exact checkpoint snapshot.
    ///
    /// Obtain `expected` from preparation or inspection. Its canonical path,
    /// endpoint, filename, byte count and source digest must still match; a
    /// non-acknowledged checkpoint also requires its exact attempt and phase.
    /// The current client's TLS name, local identity and byte ceiling are
    /// revalidated before returning any status, including a cached receipt.
    ///
    /// A never-sent source becomes locally cancelled with no network effects.
    /// A `Sending` source becomes locally cancelled with delivery uncertainty
    /// preserved: an earlier attempt may already have committed remotely.
    /// An acknowledged winner is returned unchanged, even to an older snapshot
    /// of the same source. Repeated cancellation of the same snapshot returns
    /// the same durable state and does not replace the journal again.
    ///
    /// An active sender holds the same lease, so an admitted cancellation
    /// returns `Busy` instead of racing its commit. The shared client capacity
    /// can reject even earlier. Cancel and join that owning task before
    /// retrying this operation with freshly inspected uncertain state. This
    /// method does not abort a live task or send a remote rollback request.
    ///
    /// A version-2 terminal journal is fsynced and atomically published before
    /// success. Older version-1 readers refuse it and cannot silently resend.
    /// Payloads and journals are retained. Dropping this future during blocking
    /// persistence leaves its lease and admission owned until the write ends;
    /// inspect afterward to resolve whether cancellation became durable.
    pub async fn cancel_checkpoint(
        &self,
        cx: &Cx,
        expected: &NativeUploadCheckpoint,
    ) -> Result<NativeCheckpointStatus, NativeCheckpointError> {
        authorize(cx)?;
        let admission = self.admit_sender()?;
        let directory = expected.directory.clone();
        let (lease, mut record) =
            spawn_blocking_io(move || Ok(Lease::open(&directory, admission))).await??;
        record.check_binding(&lease.admission, expected.remote)?;
        record.check_cancellation_snapshot(&lease.directory, expected)?;
        if record.cancelled {
            confirm_cancellation(&lease).await?;
            return Ok(record.status(lease.directory.clone()));
        }
        if record.receipt.is_some() {
            return Ok(record.status(lease.directory.clone()));
        }
        checkpoint(cx)?;
        let mut nonce = [0; 16];
        cx.random_bytes(&mut nonce);
        record.version = CANCELLED_JOURNAL_VERSION;
        record.cancelled = true;
        record.validate()?;
        persist_record(&lease, &record, nonce)
            .await
            .map_err(|error| NativeCheckpointError::Publication {
                directory: lease.directory.clone(),
                error,
            })?;
        // Once publication completed, report that durable fact even if the
        // caller's cancellation arrived during the owned blocking operation.
        Ok(record.status(lease.directory.clone()))
    }

    /// Send a fully prepared source, including after the producer/process exits.
    ///
    /// Requires the caller's expected endpoint and current TLS policy. Rehashes
    /// the entire bounded source before networking; never trusts saved progress
    /// as data. A file lock spans validation, intent, native transfer and receipt
    /// persistence. A durable `Sending` intent precedes every network attempt.
    /// A crash or any failed send leaves delivery uncertain, requiring an exact
    /// `AcknowledgeUncertain` decision before another send. Attempts are bounded
    /// over the checkpoint's lifetime, not reset when a client restarts.
    /// A durable cancellation refuses all retry policies before source access
    /// or networking, including explicit acknowledgement of an earlier attempt.
    ///
    /// A saved success returns its historical receipt without another transfer.
    /// This resumes from retained local bytes, not a remote byte offset, and
    /// cannot guarantee exactly-once publication after a lost acknowledgement.
    /// Do not mutate or replace checkpoint files while an operation owns them.
    pub async fn send_checkpoint(
        &self,
        cx: &Cx,
        directory: &Path,
        remote: SocketAddr,
        retry: NativeCheckpointRetry,
    ) -> Result<NativeCheckpointAttempt, NativeCheckpointError> {
        authorize(cx)?;
        let admission = self.admit_sender()?;
        Self::send_checkpoint_admitted(cx, directory.to_path_buf(), remote, retry, admission).await
    }

    /// Reserve capacity before enqueueing a restart/retry as a scope-owned task.
    ///
    /// Immediate rejection or pre-poll cancellation releases admission without
    /// opening the checkpoint. The actual child context controls cancellation.
    /// During a blocking journal write, its owner retains both lock and credit
    /// until that write finishes, even if the async wrapper is hard-dropped.
    pub fn spawn_send_checkpoint<P: Policy>(
        &self,
        cx: &Cx,
        scope: &Scope<'_, P>,
        directory: impl Into<PathBuf>,
        remote: SocketAddr,
        retry: NativeCheckpointRetry,
    ) -> Result<NativeCheckpointTask, NativeCheckpointError> {
        authorize(cx)?;
        let admission = self.admit_sender()?;
        let directory = directory.into();
        cx.spawn_in(scope, move |child| {
            let future: Pin<
                Box<
                    dyn Future<Output = Result<NativeCheckpointAttempt, NativeCheckpointError>>
                        + Send,
                >,
            > = Box::pin(async move {
                Self::send_checkpoint_admitted(&child, directory, remote, retry, admission).await
            });
            future
        })
        .map_err(|error| NativeTransferError::Spawn(error).into())
    }

    async fn send_checkpoint_admitted(
        cx: &Cx,
        directory: PathBuf,
        remote: SocketAddr,
        retry: NativeCheckpointRetry,
        admission: NativeAdmission,
    ) -> Result<NativeCheckpointAttempt, NativeCheckpointError> {
        authorize(cx)?;
        let (lease, mut record) =
            spawn_blocking_io(move || Ok(Lease::open(&directory, admission))).await??;
        record.check_binding(&lease.admission, remote)?;
        record.require_active()?;
        if let Some(receipt) = &record.receipt {
            return Ok(NativeCheckpointAttempt {
                checkpoint: record.info(lease.directory.clone()),
                outcome: Ok(receipt.report()),
                cached_receipt: true,
                persistence_error: None,
            });
        }
        let next_attempt = record.next_attempt(retry)?;
        let source = verify_source(cx, &lease, &record).await?;
        checkpoint(cx)?;
        record.attempt = next_attempt;
        record.state = NativeCheckpointState::Sending;
        let mut intent_nonce = [0; 16];
        let mut receipt_nonce = [0; 16];
        cx.random_bytes(&mut intent_nonce);
        cx.random_bytes(&mut receipt_nonce);
        persist_record(&lease, &record, intent_nonce)
            .await
            .map_err(|error| NativeCheckpointError::Publication {
                directory: lease.directory.clone(),
                error,
            })?;
        // Cancellation during intent persistence cannot start network work.
        checkpoint(cx)?;
        let outcome = transport_quic::send_path_with_options(
            cx,
            remote,
            &source,
            lease.admission.shared.config.clone(),
            &lease.admission.shared.peer_label,
            lease.admission.shared.send_options,
        )
        .await
        .map_err(NativeTransferError::from)
        .map_err(NativeCheckpointError::from)
        .and_then(|report| {
            if record.receipt_matches(&report) {
                Ok(report)
            } else {
                Err(NativeCheckpointError::ReceiptMismatch(Box::new(report)))
            }
        });
        let mut persistence_error = None;
        if let Ok(report) = &outcome {
            let mut completed = record.clone();
            completed.state = NativeCheckpointState::Acknowledged;
            completed.receipt = Some(StoredReceipt::capture(report));
            // Terminal publication must not discard a real result merely
            // because cancellation arrived after the native operation returned.
            match persist_record(&lease, &completed, receipt_nonce).await {
                Ok(()) => record = completed,
                Err(error) => persistence_error = Some(error),
            }
        }
        Ok(NativeCheckpointAttempt {
            checkpoint: record.info(lease.directory.clone()),
            outcome,
            cached_receipt: false,
            persistence_error,
        })
    }
}

async fn persist_record(lease: &Arc<Lease>, record: &Journal, nonce: [u8; 16]) -> io::Result<()> {
    let owner = Arc::clone(lease);
    let record = record.clone();
    spawn_blocking_io(move || write_journal(&owner.directory, &record, &nonce)).await
}

async fn confirm_cancellation(lease: &Arc<Lease>) -> Result<(), NativeCheckpointError> {
    let owner = Arc::clone(lease);
    // A previous cancellation may have returned a publication error after
    // rename but before directory fsync. Reconfirm that visible tombstone's
    // durability on inspection/repetition without replacing its inode again.
    spawn_blocking_io(move || {
        let path = owner.directory.join("journal.json");
        regular_file(&path)?;
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?
            .sync_all()?;
        File::open(&owner.directory)?.sync_all()
    })
    .await
    .map_err(|error| NativeCheckpointError::Publication {
        directory: lease.directory.clone(),
        error,
    })
}

async fn verify_source(
    cx: &Cx,
    lease: &Arc<Lease>,
    record: &Journal,
) -> Result<PathBuf, NativeCheckpointError> {
    let owner = Arc::clone(lease);
    let name = record.file_name.clone();
    let (path, mut file) = spawn_blocking_io(move || {
        let payload = owner.directory.join("payload");
        let meta = std::fs::symlink_metadata(&payload)?;
        if !meta.file_type().is_dir() || meta.mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid checkpoint payload directory",
            ));
        }
        let path = payload.join(name);
        regular_file(&path)?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)?;
        Ok((path, file))
    })
    .await?;
    let mut buffer = vec![
        0;
        lease
            .admission
            .shared
            .config
            .chunk_size
            .min(MAX_UPLOAD_BUFFER)
    ];
    let mut hash = Sha256::new();
    let mut total = 0;
    loop {
        checkpoint(cx)?;
        let owner = Arc::clone(lease);
        let window = super::read_window(buffer.len(), record.source_bytes, total);
        let (returned_file, returned_buffer, read) = spawn_blocking_io(move || {
            let _owner = owner;
            let read = file.read(&mut buffer[..window]);
            Ok((file, buffer, read))
        })
        .await?;
        file = returned_file;
        buffer = returned_buffer;
        let count = read?;
        if count == 0 {
            break;
        }
        if count as u64 > record.source_bytes - total {
            return Err(NativeCheckpointError::SourceChanged);
        }
        total += count as u64;
        hash.update(&buffer[..count]);
    }
    let digest: [u8; 32] = hash.finalize().into();
    if total != record.source_bytes || digest != record.source_sha256 {
        return Err(NativeCheckpointError::SourceChanged);
    }
    Ok(path)
}

#[cfg(test)]
#[path = "checkpoint_inline_tests.rs"]
mod tests;
