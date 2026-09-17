//! Bounded uploads from buffers and asynchronous readers.
//!
//! The current native manifest precedes object data, so an unknown-size input
//! must reach EOF before transmission. This adapter spools to a caller-selected
//! private directory, then uses the existing verified native transfer. It does
//! not claim live delivery before EOF, resumable stream epochs, or crash recovery.

#[cfg(unix)]
#[path = "checkpoint.rs"]
pub mod recovery;

#[path = "writer.rs"]
mod writer;
pub use writer::{NativeUploadWriter, NativeUploadWriterTerminal};

use super::{NativeAdmission, NativeTransferClient, NativeTransferError, committed_send};
use crate::atp::safety::validate_portable_path_component;
use crate::cx::{CancelWakerToken, Cx, Scope};
use crate::io::{AsyncRead, ReadBuf};
use crate::net::atp::transport_quic::{self, SendReport};
use crate::runtime::{TaskHandle, spawn_blocking_io};
use crate::types::{CancelReason, Policy};
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use std::fs::{DirBuilder, File, OpenOptions};
use std::future::{Future, poll_fn};
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

const MAX_UPLOAD_BUFFER: usize = 64 * 1024;
const SPOOL_CREATE_ATTEMPTS: usize = 16;

/// Explicit local storage and input limits for an upload.
///
/// `spool_parent` must already exist and be trusted against local replacement.
/// Input bytes are temporarily stored there in plaintext. On Unix the unique
/// child directory and file are created with modes 0700 and 0600 respectively;
/// on other platforms the caller must supply appropriate parent ACLs.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct NativeUploadOptions {
    /// Existing, caller-owned directory under which a unique spool is created.
    pub spool_parent: PathBuf,
    /// Portable single filename to publish remotely; never a path or directory.
    pub file_name: String,
    /// Optional stricter input ceiling. Zero permits only an empty input.
    pub max_bytes: Option<u64>,
    /// Maximum wait for each source read, including the final EOF probe.
    /// This does not preempt a thread stuck inside a user `poll_read` or disk I/O.
    pub source_idle_timeout: Duration,
}

impl NativeUploadOptions {
    /// Select an existing spool parent and a single remote filename.
    #[must_use]
    pub fn new(spool_parent: impl Into<PathBuf>, file_name: impl Into<String>) -> Self {
        Self {
            spool_parent: spool_parent.into(),
            file_name: file_name.into(),
            max_bytes: None,
            source_idle_timeout: Duration::from_secs(30),
        }
    }

    fn validate(&self) -> Result<(), NativeUploadError> {
        validate_portable_path_component(&self.file_name)
            .map_err(NativeUploadError::InvalidName)?;
        if self.file_name.len() > 255 {
            return Err(NativeUploadError::InvalidName(
                "filename exceeds 255 bytes".into(),
            ));
        }
        if self.spool_parent.as_os_str().is_empty() || self.source_idle_timeout.is_zero() {
            return Err(NativeUploadError::InvalidOptions);
        }
        Ok(())
    }
}

/// Input/admission failure or the original native transfer error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NativeUploadError {
    /// The filename is unsafe or not portable.
    #[error("invalid upload filename: {0}")]
    InvalidName(String),
    /// The spool parent or timeout was empty/zero.
    #[error("upload requires a spool parent and a nonzero source timeout")]
    InvalidOptions,
    /// The supplied context cannot authorize the host-boundary operations.
    #[error("upload requires I/O, entropy and time capabilities")]
    MissingCapability,
    /// Cancellation was observed; retain attribution when available.
    #[error("upload cancelled: {reason:?}")]
    Cancelled {
        /// Actual context cancellation reason, not a fabricated transport error.
        reason: Option<CancelReason>,
    },
    /// Input exceeded the stricter upload/native byte ceiling.
    #[error("upload input exceeds {limit} bytes")]
    TooLarge {
        /// Maximum admitted input bytes.
        limit: u64,
    },
    /// A pending source read did not finish in its configured window.
    #[error("upload source read timed out")]
    SourceTimeout,
    /// Source read, spool creation, write, or flush failed.
    #[error("upload source/spool I/O failed: {0}")]
    Io(#[from] io::Error),
    /// Full native admission, transport, or receipt failure.
    #[error(transparent)]
    Native(#[from] NativeTransferError),
}

/// A local cleanup failure, independent of remote publication.
#[derive(Debug)]
pub struct NativeUploadCleanupError {
    /// Unique spool directory that may require local cleanup.
    pub directory: PathBuf,
    /// Original filesystem or blocking-pool error.
    pub error: io::Error,
}

/// Terminal upload facts. Inspect `outcome`, not local byte counts, for success.
///
/// A cleanup error does not erase a successful remote receipt and must not
/// trigger an automatic upload retry. On a transfer error the peer may already
/// have published the object. No automatic retry is performed here.
#[derive(Debug)]
#[must_use = "inspect the actual transfer outcome and local cleanup result"]
pub struct NativeUploadReport {
    /// Actual verified peer receipt, or input/admission/transport failure.
    pub outcome: Result<SendReport, NativeUploadError>,
    /// Bytes in fully completed spool writes; excludes any partial failed write.
    pub spooled_bytes: u64,
    /// SHA-256 of the entire source only after admitted EOF and successful flush.
    pub source_sha256: Option<[u8; 32]>,
    /// Failed local cleanup without changing the independent transfer result.
    pub cleanup_error: Option<NativeUploadCleanupError>,
}

impl NativeUploadReport {
    fn failed(error: NativeUploadError) -> Self {
        Self {
            outcome: Err(error),
            spooled_bytes: 0,
            source_sha256: None,
            cleanup_error: None,
        }
    }
}

/// Scope-owned input-spooling and native-transfer task.
pub type NativeUploadTask = TaskHandle<NativeUploadReport>;

// Every in-flight blocking job retains this owner, including its admission
// credit. Hard-dropping the async wrapper cannot unlink its spool or release
// the slot while a write still uses it. There is only one disk job per upload
// at a time; the async task never locks `file` on a runtime worker.
struct Spool {
    file: Mutex<Option<File>>,
    path: PathBuf,
    directory: PathBuf,
    owns_file: bool,
    cleanup_attempted: AtomicBool,
    _admission: Arc<NativeAdmission>,
}

impl Spool {
    fn create(
        parent: &Path,
        name: &str,
        nonce: &[u8; 16],
        admission: Arc<NativeAdmission>,
    ) -> io::Result<Arc<Self>> {
        let directory = parent
            .canonicalize()?
            .join(format!(".atp-upload-{}", hex::encode(nonce)));
        let mut builder = DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.recursive(false).create(&directory)?;
        let mut spool = Self {
            path: directory.join(name),
            directory,
            file: Mutex::new(None),
            owns_file: false,
            cleanup_attempted: AtomicBool::new(false),
            _admission: admission,
        };
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&spool.path)?;
        *spool.file.get_mut() = Some(file);
        spool.owns_file = true;
        Ok(Arc::new(spool))
    }

    fn cleanup(&self) -> io::Result<()> {
        if self.cleanup_attempted.swap(true, Ordering::Relaxed) {
            return Ok(());
        }
        drop(self.file.lock().take());
        // Never recursively remove a directory or touch a path not created by
        // this operation. In particular, collisions never remove existing data.
        if self.owns_file {
            ignore_missing(std::fs::remove_file(&self.path))?;
        }
        ignore_missing(std::fs::remove_dir(&self.directory))
    }
}

impl Drop for Spool {
    fn drop(&mut self) {
        // Last-owner backstop for a hard drop/panic. Ordinary returns explicitly
        // await cleanup and surface errors. A hard drop has no result channel;
        // cleanup is best effort, not a crash-durability or rollback guarantee.
        let _ = self.cleanup();
    }
}

fn ignore_missing(result: io::Result<()>) -> io::Result<()> {
    match result {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

fn checkpoint(cx: &Cx) -> Result<(), NativeUploadError> {
    cx.checkpoint().map_err(|_| NativeUploadError::Cancelled {
        reason: cx.cancel_reason(),
    })
}

fn validate_upload(cx: &Cx, options: &NativeUploadOptions) -> Result<(), NativeUploadError> {
    options.validate()?;
    let caps = cx.capabilities();
    if !caps.io || !caps.entropy || !caps.time {
        return Err(NativeUploadError::MissingCapability);
    }
    checkpoint(cx)
}

struct ReadCancellation {
    cx: Cx,
    token: Option<CancelWakerToken>,
}

impl Drop for ReadCancellation {
    fn drop(&mut self) {
        if let Some(token) = self.token.take() {
            self.cx.clear_cancel_waker(token);
        }
    }
}

async fn read_source<R: AsyncRead + Unpin>(
    cx: &Cx,
    reader: &mut R,
    buffer: &mut [u8],
    timeout: Duration,
) -> Result<usize, NativeUploadError> {
    let mut cancellation = ReadCancellation {
        cx: cx.clone(),
        token: None,
    };
    let read = poll_fn(|ctx| {
        cancellation.token = Some(cx.refresh_cancel_waker(cancellation.token.take(), ctx.waker()));
        // Register then check: publication in between cannot lose the wake.
        if let Err(error) = checkpoint(cx) {
            return Poll::Ready(Err(error));
        }
        let mut read_buf = ReadBuf::new(buffer);
        match Pin::new(&mut *reader).poll_read(ctx, &mut read_buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(NativeUploadError::Io(error))),
        }
    });
    crate::time::timeout(cx.now(), timeout, read)
        .await
        .map_err(|_| NativeUploadError::SourceTimeout)?
}

// Leave room for exactly one over-limit probe; it is never written to disk.
fn read_window(buffer_len: usize, limit: u64, written: u64) -> usize {
    let remaining = limit.saturating_sub(written);
    buffer_len.min(usize::try_from(remaining.saturating_add(1)).unwrap_or(usize::MAX))
}

impl NativeTransferClient {
    /// Upload a finite asynchronous source using bounded disk spooling.
    ///
    /// Waits for real EOF, not temporary unavailability. At most 64 KiB of
    /// adapter read/write buffering and one blocking write are in flight.
    /// Both the source and spool byte count are bounded by the stricter native
    /// and upload limit; an over-limit input never opens a remote connection.
    /// Source reads register cancellation wakes and have an idle timeout.
    /// Cancellation during a disk operation waits for that operation to finish
    /// before cleanup. A non-returning user poll or OS write cannot be preempted.
    ///
    /// The manifest-first native wire format requires complete local spooling
    /// before network delivery; this is not a live unknown-length wire stream.
    /// This host-boundary API uses real files below the explicit spool parent,
    /// not deterministic lab I/O. Hard drop may consume an input prefix; only
    /// a returned peer receipt establishes delivery. Prefer the scope-owned
    /// variant and join it when cancellation/cleanup completion matters.
    pub async fn send_reader<R: AsyncRead + Unpin>(
        &self,
        cx: &Cx,
        remote: SocketAddr,
        options: NativeUploadOptions,
        reader: R,
    ) -> NativeUploadReport {
        let admitted =
            validate_upload(cx, &options).and_then(|()| self.admit_sender().map_err(Into::into));
        match admitted {
            Ok(admission) => {
                Self::upload_admitted(cx, remote, options, reader, admission, None).await
            }
            Err(error) => NativeUploadReport::failed(error),
        }
    }

    /// Upload a borrowed buffer without allocating a second object-sized buffer.
    /// Uses the same bounded spool, limits, receipt checks and cleanup as readers.
    pub async fn send_buffer(
        &self,
        cx: &Cx,
        remote: SocketAddr,
        options: NativeUploadOptions,
        data: &[u8],
    ) -> NativeUploadReport {
        self.send_reader(cx, remote, options, BufferReader(data))
            .await
    }

    /// Admit the entire input and transfer journey as one scope-owned task.
    ///
    /// Capacity is held before enqueue and across spooling, network transfer,
    /// and cleanup. The factory receives its actual child `Cx`. Cancelling the
    /// handle wakes even an otherwise permanently pending source read.
    ///
    /// # Errors
    /// Refuses invalid options, absent capabilities/TLS, saturation or immediate
    /// spawn failure before polling the source or creating a spool file.
    pub fn spawn_send_reader<P, R>(
        &self,
        cx: &Cx,
        scope: &Scope<'_, P>,
        remote: SocketAddr,
        options: NativeUploadOptions,
        reader: R,
    ) -> Result<NativeUploadTask, NativeUploadError>
    where
        P: Policy,
        R: AsyncRead + Unpin + Send + 'static,
    {
        validate_upload(cx, &options)?;
        let admission = self.admit_sender()?;
        cx.spawn_in(scope, move |child| {
            let future: Pin<Box<dyn Future<Output = NativeUploadReport> + Send>> =
                Box::pin(async move {
                    Self::upload_admitted(&child, remote, options, reader, admission, None).await
                });
            future
        })
        .map_err(|error| NativeTransferError::Spawn(error).into())
    }

    async fn upload_admitted<R: AsyncRead + Unpin>(
        cx: &Cx,
        remote: SocketAddr,
        options: NativeUploadOptions,
        mut reader: R,
        admission: NativeAdmission,
        observer: Option<Arc<dyn SpoolObserver>>,
    ) -> NativeUploadReport {
        // Recheck the actual child authority/cancellation after admission.
        if let Err(error) = validate_upload(cx, &options) {
            return NativeUploadReport::failed(error);
        }
        let admission = Arc::new(admission);
        let mut created = Err(NativeUploadError::Io(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "unique upload spool names exhausted",
        )));
        for _ in 0..SPOOL_CREATE_ATTEMPTS {
            if let Err(error) = checkpoint(cx) {
                return NativeUploadReport::failed(error);
            }
            let mut nonce = [0u8; 16];
            cx.random_bytes(&mut nonce);
            let parent = options.spool_parent.clone();
            let name = options.file_name.clone();
            let owner = Arc::clone(&admission);
            match spawn_blocking_io(move || Spool::create(&parent, &name, &nonce, owner)).await {
                Ok(spool) => {
                    created = Ok(spool);
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    created = Err(error.into());
                    break;
                }
            }
        }
        let spool = match created {
            Ok(spool) => spool,
            Err(error) => return NativeUploadReport::failed(error),
        };
        let mut report = NativeUploadReport::failed(NativeUploadError::InvalidOptions);
        let limit = options
            .max_bytes
            .unwrap_or(u64::MAX)
            .min(admission.shared.config.max_transfer_bytes);
        let buffer_len = admission.shared.config.chunk_size.min(MAX_UPLOAD_BUFFER);
        let source = spool_source(
            cx,
            &mut reader,
            &spool,
            limit,
            buffer_len,
            options.source_idle_timeout,
            SpoolProgress {
                written: &mut report.spooled_bytes,
                observer: observer.as_deref(),
            },
        )
        .await;
        report.outcome = match source {
            Err(error) => Err(error),
            Ok(digest) => {
                report.source_sha256 = Some(digest);
                match checkpoint(cx) {
                    Err(error) => Err(error),
                    Ok(()) => transport_quic::send_path(
                        cx,
                        remote,
                        &spool.path,
                        admission.shared.config.clone(),
                        &admission.shared.peer_label,
                    )
                    .await
                    .map_err(NativeTransferError::from)
                    .and_then(committed_send)
                    .map_err(Into::into),
                }
            }
        };
        let cleanup_owner = Arc::clone(&spool);
        if let Err(error) = spawn_blocking_io(move || cleanup_owner.cleanup()).await {
            report.cleanup_error = Some(NativeUploadCleanupError {
                directory: spool.directory.clone(),
                error,
            });
        }
        // `spool` and every disk job retain the slot, so hard-drop cleanup also
        // completes before that last owner's admission credit can be released.
        report
    }
}

// Internal completion notification, never exposed as a user callback. Writers
// use it for flush barriers only after a whole spool write has succeeded.
trait SpoolObserver: Send + Sync {
    fn on_spooled(&self, bytes: u64);
}

struct SpoolProgress<'a> {
    written: &'a mut u64,
    observer: Option<&'a dyn SpoolObserver>,
}

async fn spool_source<R: AsyncRead + Unpin>(
    cx: &Cx,
    reader: &mut R,
    spool: &Arc<Spool>,
    limit: u64,
    buffer_len: usize,
    timeout: Duration,
    progress: SpoolProgress<'_>,
) -> Result<[u8; 32], NativeUploadError> {
    let mut buffer = vec![0u8; buffer_len];
    let mut hash = Sha256::new();
    loop {
        let window = read_window(buffer.len(), limit, *progress.written);
        let count = read_source(cx, reader, &mut buffer[..window], timeout).await?;
        checkpoint(cx)?;
        if count == 0 {
            break;
        }
        if u64::try_from(count).unwrap_or(u64::MAX) > limit - *progress.written {
            return Err(NativeUploadError::TooLarge { limit });
        }
        let owner = Arc::clone(spool);
        let (returned, result) = spawn_blocking_io(move || {
            let mut file = owner.file.lock();
            let result = file
                .as_mut()
                .ok_or_else(|| io::Error::other("upload spool closed"))
                .and_then(|file| file.write_all(&buffer[..count]));
            Ok((buffer, result))
        })
        .await?;
        buffer = returned;
        result?;
        hash.update(&buffer[..count]);
        *progress.written += count as u64;
        if let Some(observer) = progress.observer {
            observer.on_spooled(*progress.written);
        }
    }
    let owner = Arc::clone(spool);
    spawn_blocking_io(move || {
        let mut file = owner
            .file
            .lock()
            .take()
            .ok_or_else(|| io::Error::other("upload spool closed"))?;
        file.flush()?;
        file.sync_data()
    })
    .await?;
    checkpoint(cx)?;
    Ok(hash.finalize().into())
}

struct BufferReader<'a>(&'a [u8]);

impl AsyncRead for BufferReader<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let count = self.0.len().min(buf.remaining());
        buf.put_slice(&self.0[..count]);
        self.0 = &self.0[count..];
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upload_names_cannot_escape_the_spool_or_alias_windows_devices() {
        for name in [
            "", ".", "..", "../file", "a/b", "a\\b", "C:foo", "NUL", "x.", "x ",
        ] {
            assert!(
                NativeUploadOptions::new("spool", name).validate().is_err(),
                "{name:?}"
            );
        }
        assert!(
            NativeUploadOptions::new("spool", "payload.bin")
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn bounded_reads_probe_only_one_byte_past_the_limit_without_overflow() {
        assert_eq!(read_window(65536, 0, 0), 1);
        assert_eq!(read_window(65536, 100, 99), 2);
        assert_eq!(read_window(65536, 100, 100), 1);
        assert_eq!(read_window(65536, u64::MAX, 0), 65536);
        assert_eq!(read_window(65536, u64::MAX, u64::MAX), 1);
        for limit in 0..128 {
            for written in 0..=limit {
                let window = read_window(17, limit, written);
                assert!((1..=17).contains(&window));
                assert!(window as u64 <= limit - written + 1);
            }
        }
    }

    #[test]
    fn buffer_reader_delivers_exact_prefixes_and_only_then_eof() {
        let mut reader = BufferReader(b"abcdefg");
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut output = Vec::new();
        loop {
            let mut bytes = [0u8; 3];
            let mut buf = ReadBuf::new(&mut bytes);
            assert!(matches!(
                Pin::new(&mut reader).poll_read(&mut cx, &mut buf),
                Poll::Ready(Ok(()))
            ));
            if buf.filled().is_empty() {
                break;
            }
            output.extend_from_slice(buf.filled());
        }
        assert_eq!(output, b"abcdefg");
    }
}
