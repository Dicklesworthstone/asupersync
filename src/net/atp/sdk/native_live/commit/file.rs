//! No-clobber file publication for explicitly committing live receivers.
//!
//! Unix only. The caller supplies an existing private directory and must keep
//! it, its ancestors and staged files trusted and unchanged for the operation.
//! Mode checks do not defend against a hostile same-user process or permissive
//! ACLs. No peer-provided path is interpreted. Staging and final files share one
//! directory/filesystem; there is no copy/overwrite fallback.
//!
//! Epoch flush never publishes the destination. Commit seals writes, rehashes
//! the actual staged inode with a 64 KiB buffer, syncs the file, creates a new
//! hard link at the destination, then syncs the directory. A failed directory
//! sync can leave a visible complete file: Published and Durable are distinct.
//! These are syscall results, not a proof of power-loss behavior on every FS.
//!
//! Staging aliases are deliberately retained on success, failure and Drop.
//! They contain plaintext and, after publication, alias the final inode. The
//! owner must protect them, account for retained disk usage, and never mutate
//! either alias after commit. Nothing is automatically removed or retried.
//! Filesystem work uses the runtime blocking-I/O path; configure a blocking
//! pool to avoid its inline fallback. A hard-dropped started syscall can finish
//! later. Retain the publication handle to inspect its observed local status.

use super::super::{MAX_LIVE_EPOCH_BYTES, authorize};
use super::{LiveStreamCommitSink, LiveStreamReceipt};
use crate::cx::Cx;
use crate::fs::File;
use crate::io::AsyncWrite;
use crate::runtime::spawn_blocking_io;
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use std::fmt;
use std::fmt::Write as _;
use std::future::Future;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

/// Last observed local publication milestone, independent of peer delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveFileState {
    /// Only the private staging path was created; no commit was started.
    Staged,
    /// Commit was admitted, but destination creation has not been observed.
    Committing,
    /// Destination link exists; successful directory synchronization is unconfirmed.
    Published,
    /// File and destination-directory synchronization both returned success.
    Durable,
}

/// Local state and a terminal error category, including after the sink is dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveFileStatus {
    /// Last successful milestone; a later error never erases publication.
    pub state: LiveFileState,
    /// Last observed operation error; not a remote-delivery result.
    pub error_kind: Option<io::ErrorKind>,
}

#[derive(Debug)]
struct Publication {
    staging: PathBuf,
    destination: PathBuf,
    directory: std::fs::File,
    status: Mutex<LiveFileStatus>,
}

/// Read-only observation of a sink's retained files and publication state.
#[derive(Debug, Clone)]
pub struct LiveFilePublication(Arc<Publication>);

impl LiveFilePublication {
    /// Retained private plaintext path; after publication this aliases the final inode.
    #[must_use]
    pub fn staging_path(&self) -> &Path {
        &self.0.staging
    }

    /// Caller-selected destination. Its existence alone is not this transfer's receipt.
    #[must_use]
    pub fn destination_path(&self) -> &Path {
        &self.0.destination
    }

    /// Snapshot local effects without polling, retrying or modifying the sink.
    #[must_use]
    pub fn status(&self) -> LiveFileStatus {
        *self.0.status.lock()
    }
}

type CommitJob = Pin<Box<dyn Future<Output = io::Result<()>> + Send>>;
type StoredResult = Result<(), (io::ErrorKind, Option<i32>)>;

/// Bounded file sink that publishes only through LiveStreamCommitSink.
///
/// Use receive_committing/spawn_receive_committing or service.next_committing.
/// Passing this to a legacy flush-only API intentionally leaves it staged.
pub struct LiveFileSink {
    file: Option<File>,
    publication: LiveFilePublication,
    limit: u64,
    written: u64,
    write_failed: bool,
    receipt: Option<LiveStreamReceipt>,
    job: Option<CommitJob>,
    terminal: Option<StoredResult>,
}

impl fmt::Debug for LiveFileSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LiveFileSink")
            .field("publication", &self.publication)
            .field("written", &self.written)
            .field("limit", &self.limit)
            .field("sealed", &self.receipt.is_some())
            .finish_non_exhaustive()
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

impl LiveFileSink {
    /// Create a mode-0600 staging file in an existing absolute private Unix directory.
    ///
    /// The directory must deny group/other permission bits and must not itself
    /// be a symlink. Its trusted ancestors and ACLs remain the caller's duty.
    /// The single-component ASCII filename is selected locally, not by a peer.
    /// Existing destinations are never overwritten. File creation may finish
    /// after an awaiting future is dropped; any staging file is retained.
    pub async fn create(
        cx: &Cx,
        directory: PathBuf,
        filename: String,
        max_bytes: u64,
    ) -> io::Result<Self> {
        authorize(cx).map_err(io::Error::other)?;
        if !directory.is_absolute() {
            return Err(invalid("absolute private directory required"));
        }
        if filename.is_empty()
            || filename.len() > 200
            || matches!(filename.as_str(), "." | "..")
            || filename.starts_with(".atp-live-")
            || !filename
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Err(invalid("invalid local live-file name"));
        }
        let mut nonce = [0_u8; 16];
        cx.random_bytes(&mut nonce);
        let mut suffix = String::with_capacity(32);
        for byte in nonce {
            write!(&mut suffix, "{byte:02x}").expect("write to String");
        }
        let (file, publication) = spawn_blocking_io(move || {
            let metadata = std::fs::symlink_metadata(&directory)?;
            if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "live-file directory must be private",
                ));
            }
            let directory = std::fs::canonicalize(directory)?;
            let handle = std::fs::File::open(&directory)?;
            let staging = directory.join(format!(".atp-live-{suffix}.part"));
            let destination = directory.join(filename);
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&staging)?;
            let publication = LiveFilePublication(Arc::new(Publication {
                staging,
                destination,
                directory: handle,
                status: Mutex::new(LiveFileStatus {
                    state: LiveFileState::Staged,
                    error_kind: None,
                }),
            }));
            Ok((File::from_std(file), publication))
        })
        .await?;
        Ok(Self {
            file: Some(file),
            publication,
            limit: max_bytes,
            written: 0,
            write_failed: false,
            receipt: None,
            job: None,
            terminal: None,
        })
    }

    /// Retain this before moving the sink into a service or scoped receiver.
    #[must_use]
    pub fn publication(&self) -> LiveFilePublication {
        self.publication.clone()
    }

    fn completed(&mut self, result: io::Result<()>) -> Poll<io::Result<()>> {
        self.terminal = Some(
            result
                .as_ref()
                .copied()
                .map_err(|e| (e.kind(), e.raw_os_error())),
        );
        if let Err(error) = &result {
            self.publication.0.status.lock().error_kind = Some(error.kind());
        }
        Poll::Ready(result)
    }
}

impl AsyncWrite for LiveFileSink {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.receipt.is_some() || this.write_failed {
            return Poll::Ready(Err(invalid("live-file sink is sealed or failed")));
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let remaining = this.limit.saturating_sub(this.written);
        let count = bytes
            .len()
            .min(MAX_LIVE_EPOCH_BYTES)
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        if count == 0 {
            return Poll::Ready(Err(invalid("live-file byte limit exceeded")));
        }
        let result = ready!(
            Pin::new(this.file.as_mut().expect("unsealed file")).poll_write(cx, &bytes[..count])
        );
        match &result {
            Ok(written) => this.written += *written as u64,
            Err(_) => this.write_failed = true,
        }
        Poll::Ready(result)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.receipt.is_some() {
            return Poll::Ready(Err(invalid("live-file sink is sealed")));
        }
        let result = ready!(Pin::new(this.file.as_mut().expect("unsealed file")).poll_flush(cx));
        if result.is_err() {
            this.write_failed = true;
        }
        Poll::Ready(result)
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "explicit verified commit required",
        )))
    }
}

impl LiveStreamCommitSink for LiveFileSink {
    fn poll_commit(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        receipt: &LiveStreamReceipt,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.receipt.as_ref().is_some_and(|bound| bound != receipt) {
            return Poll::Ready(Err(invalid("live-file commit receipt changed")));
        }
        if let Some(result) = this.terminal {
            return Poll::Ready(result.map_err(|(kind, raw)| {
                raw.map_or_else(|| io::Error::from(kind), io::Error::from_raw_os_error)
            }));
        }
        if this.receipt.is_none() {
            this.receipt = Some(receipt.clone());
            if this.write_failed || receipt.prefix.bytes != this.written {
                return this
                    .completed(Err(invalid("live-file byte count or write state mismatch")));
            }
        }
        if this.job.is_none() {
            let flushed =
                ready!(Pin::new(this.file.as_mut().expect("uncommitted file")).poll_flush(cx));
            if let Err(error) = flushed {
                return this.completed(Err(error));
            }
            let file = this.file.take().expect("uncommitted file");
            let publication = this.publication.clone();
            let receipt = receipt.clone();
            publication.0.status.lock().state = LiveFileState::Committing;
            this.job = Some(Box::pin(async move {
                let observed = publication.clone();
                let result = spawn_blocking_io(move || {
                    let result = publish(file, &publication.0, &receipt);
                    if let Err(error) = &result {
                        publication.0.status.lock().error_kind = Some(error.kind());
                    }
                    result
                })
                .await;
                if let Err(error) = &result {
                    observed.0.status.lock().error_kind = Some(error.kind());
                }
                result
            }));
        }
        let result = ready!(this.job.as_mut().expect("commit job").as_mut().poll(cx));
        this.job = None;
        this.completed(result)
    }
}

fn publish(file: File, publication: &Publication, receipt: &LiveStreamReceipt) -> io::Result<()> {
    // poll_commit completed the async flush before this transfer of ownership.
    let mut file = file.into_std()?;
    let metadata = file.metadata()?;
    let path_metadata = std::fs::symlink_metadata(&publication.staging)?;
    let parent = publication
        .destination
        .parent()
        .ok_or_else(|| invalid("missing parent"))?;
    let parent_metadata = std::fs::symlink_metadata(parent)?;
    let held_parent = publication.directory.metadata()?;
    if !metadata.is_file()
        || !path_metadata.is_file()
        || (metadata.dev(), metadata.ino()) != (path_metadata.dev(), path_metadata.ino())
        || !parent_metadata.is_dir()
        || (parent_metadata.dev(), parent_metadata.ino()) != (held_parent.dev(), held_parent.ino())
        || parent_metadata.permissions().mode() & 0o077 != 0
        || metadata.len() != receipt.prefix.bytes
    {
        return Err(invalid("live-file staging or directory identity changed"));
    }
    file.seek(SeekFrom::Start(0))?;
    let mut hash = Sha256::new();
    let mut remaining = receipt.prefix.bytes;
    let mut buffer = vec![0_u8; MAX_LIVE_EPOCH_BYTES].into_boxed_slice();
    while remaining != 0 {
        let window = buffer
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        let count = file.read(&mut buffer[..window])?;
        if count == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        hash.update(&buffer[..count]);
        remaining -= count as u64;
    }
    let digest: [u8; 32] = hash.finalize().into();
    if file.read(&mut buffer[..1])? != 0 || digest != receipt.source_sha256 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "live-file content changed",
        ));
    }
    file.sync_all()?;
    std::fs::hard_link(&publication.staging, &publication.destination)?;
    publication.status.lock().state = LiveFileState::Published;
    publication.directory.sync_all()?;
    publication.status.lock().state = LiveFileState::Durable;
    Ok(())
}
