//! Bounded writable preparation for a durable, restartable native upload.
//!
//! The queue is shared with the immediate-send writer. EOF publishes the same
//! checkpoint as prepare_reader; it never admits a network attempt.

use super::super::super::{NativeTransferClient, NativeTransferError};
use super::super::recovery::{NativeCheckpointError, NativeCheckpointPreparation};
use super::super::{
    MAX_UPLOAD_BUFFER, NativeUploadError, NativeUploadOptions, SpoolObserver, validate_upload,
};
use super::{Input, InputReader, closed_input, notify};
use crate::cx::{Cx, Scope};
use crate::io::AsyncWrite;
use crate::runtime::{JoinError, TaskHandle};
use crate::types::{CancelReason, Policy};
use parking_lot::Mutex;
use std::future::{Future, poll_fn};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

type PreparationResult = Result<NativeCheckpointPreparation, NativeCheckpointError>;

/// Independent canonical worker join and durable preparation facts.
///
/// A late cancellation may reject the worker's return after its checkpoint was
/// already published. The preparation remains available in that case; a join
/// error never silently discards a durable path or implies publication rollback.
#[derive(Debug)]
#[must_use = "inspect both worker retirement and any retained preparation result"]
pub struct NativeCheckpointWriterTerminal {
    /// Canonical worker retirement, including cancellation or panic.
    pub join: Result<(), JoinError>,
    /// Actual preparation result if the worker reached its publication result.
    /// None means admission/cancellation/panic prevented it from returning one.
    pub outcome: Option<Result<NativeCheckpointPreparation, NativeCheckpointError>>,
}

/// Writable, bounded input whose explicit EOF prepares a durable checkpoint.
///
/// Successful writes acknowledge only an accepted prefix. Flush waits for
/// completed local spool writes; it does not publish a checkpoint or claim
/// crash durability. Shutdown and finish wait for complete EOF, source fsync,
/// journal publication, and ephemeral-spool cleanup. The checkpoint can then be
/// sent by a new client or process with send_checkpoint.
///
/// Dropping an unfinished writer requests cancellation, never successful EOF.
/// The owning region still drains its worker. Cancellation racing with completed
/// publication may return a valid checkpoint; retain and inspect that result.
#[derive(Debug)]
#[must_use = "finish or cancel_and_wait the writer and retain any published checkpoint"]
pub struct NativeCheckpointWriter {
    input: Arc<Input>,
    worker: TaskHandle<()>,
    prepared: Arc<Mutex<Option<PreparationResult>>>,
    terminal: Option<NativeCheckpointWriterTerminal>,
}

impl NativeTransferClient {
    /// Open bounded writable input for durable preparation in scope.
    ///
    /// No network traffic is sent, even at EOF. Retain the checkpoint directory
    /// returned by finish, then use send_checkpoint when delivery is desired.
    /// Preparation binds the current TLS identity, destination, byte limit and
    /// portable filename exactly as prepare_reader does. Partial producer input
    /// cannot be resumed after a crash; durability begins at successful EOF.
    ///
    /// Capacity is reserved before the pipe and worker are allocated. The pipe
    /// holds at most the smaller of the configured chunk size and 64 KiB. The
    /// source idle timeout applies while the producer has no bytes to write.
    ///
    /// # Errors
    /// Refuses invalid options, missing authority/TLS, exhausted capacity and
    /// immediate runtime admission failure. Deferred worker and storage failures
    /// remain available through the canonical finish result.
    pub fn open_checkpoint_writer<P: Policy>(
        &self,
        cx: &Cx,
        scope: &Scope<'_, P>,
        remote: SocketAddr,
        options: NativeUploadOptions,
    ) -> Result<NativeCheckpointWriter, NativeCheckpointError> {
        validate_upload(cx, &options)?;
        let admission = self.admit_sender()?;
        let input = Input::new(self.shared.config.chunk_size.min(MAX_UPLOAD_BUFFER));
        let reader = InputReader(Arc::clone(&input));
        let observer: Arc<dyn SpoolObserver> = input.clone();
        let prepared = Arc::new(Mutex::new(None));
        let worker_prepared = Arc::clone(&prepared);
        let worker = cx
            .spawn_in(scope, move |child| {
                let future: Pin<Box<dyn Future<Output = ()> + Send>> = Box::pin(async move {
                    let result = Self::prepare_reader_admitted(
                        &child,
                        remote,
                        options,
                        reader,
                        admission,
                        Some(observer),
                    )
                    .await;
                    // Publish evidence independently before task completion.
                    // The runtime may cancel a late return after this point;
                    // its canonical join cannot erase a durable checkpoint.
                    *worker_prepared.lock() = Some(result);
                });
                future
            })
            .map_err(NativeTransferError::Spawn)?;
        Ok(NativeCheckpointWriter {
            input,
            worker,
            prepared,
            terminal: None,
        })
    }
}

impl NativeCheckpointWriter {
    /// Maximum unread producer bytes in the queue, excluding the spool buffer.
    #[must_use]
    pub fn buffer_capacity(&self) -> usize {
        self.input.capacity
    }

    /// Current unread producer bytes; queue emptiness does not mean durability.
    #[must_use]
    pub fn buffered_bytes(&self) -> usize {
        self.input.state.lock().bytes.len()
    }

    /// Peak unread bytes retained in this pipe.
    #[must_use]
    pub fn buffer_high_water(&self) -> usize {
        self.input.state.lock().high_water
    }

    /// Total bytes accepted by successful writes.
    #[must_use]
    pub fn accepted_bytes(&self) -> u64 {
        self.input.state.lock().accepted
    }

    /// Bytes acknowledged by completed local spool writes, before source fsync.
    #[must_use]
    pub fn spooled_bytes(&self) -> u64 {
        self.input.state.lock().spooled
    }

    /// Inspect terminal facts, collecting a ready canonical join without blocking.
    #[must_use]
    pub fn terminal(&mut self) -> Option<&NativeCheckpointWriterTerminal> {
        if self.terminal.is_none() {
            match self.worker.try_join() {
                Ok(None) => {}
                Ok(Some(())) => self.settle(Ok(())),
                Err(error) => self.settle(Err(error)),
            }
        }
        self.terminal.as_ref()
    }

    /// Stop accepting input and await durable publication and local cleanup.
    ///
    /// Dropping this wait leaves EOF and worker ownership intact. A later call
    /// resumes the same join and repeated calls retain the same checkpoint.
    pub async fn finish(&mut self) -> &NativeCheckpointWriterTerminal {
        notify(self.input.stop(false));
        poll_fn(|ctx| self.poll_terminal(ctx)).await;
        self.terminal.as_ref().expect("joined checkpoint writer")
    }

    /// Request cancellation and await the worker, including its spool cleanup.
    ///
    /// Cancellation is cooperative and cannot interrupt an OS operation that
    /// never returns. A completed publication is retained independently from
    /// the canonical join; use cancel_checkpoint to revoke future sends from
    /// any returned checkpoint. Cancellation does not undo local publication.
    pub async fn cancel_and_wait(&mut self, reason: CancelReason) -> &NativeCheckpointWriterTerminal {
        if self.terminal().is_none() {
            self.worker.abort_with_reason(reason);
            notify(self.input.stop(true));
        }
        poll_fn(|ctx| self.poll_terminal(ctx)).await;
        self.terminal.as_ref().expect("joined checkpoint writer")
    }

    fn settle(&mut self, join: Result<(), JoinError>) {
        let outcome = self.prepared.lock().take();
        self.terminal = Some(NativeCheckpointWriterTerminal { join, outcome });
        let retired = self.input.state.lock().writer_waker.take();
        drop(retired);
    }

    fn poll_terminal(&mut self, ctx: &mut Context<'_>) -> Poll<()> {
        if self.terminal.is_some() {
            return Poll::Ready(());
        }
        match self.worker.poll_join(ctx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.settle(result);
                Poll::Ready(())
            }
        }
    }

    fn terminal_io_result(&self) -> io::Result<()> {
        let terminal = self.terminal.as_ref().expect("terminal join observed");
        if let Err(error) = &terminal.join {
            let kind = if matches!(error, JoinError::Cancelled(_)) {
                io::ErrorKind::Interrupted
            } else {
                io::ErrorKind::Other
            };
            return Err(io::Error::new(
                kind,
                format!("checkpoint worker failed; inspect retained outcome: {error}"),
            ));
        }
        match terminal.outcome.as_ref() {
            Some(Err(error)) => {
                let kind = match error {
                    NativeCheckpointError::Upload(NativeUploadError::Cancelled { .. }) => {
                        io::ErrorKind::Interrupted
                    }
                    NativeCheckpointError::Upload(NativeUploadError::SourceTimeout) => {
                        io::ErrorKind::TimedOut
                    }
                    NativeCheckpointError::Upload(NativeUploadError::TooLarge { .. }) => {
                        io::ErrorKind::InvalidInput
                    }
                    NativeCheckpointError::Upload(NativeUploadError::Io(error))
                    | NativeCheckpointError::Io(error) => error.kind(),
                    _ => io::ErrorKind::Other,
                };
                Err(io::Error::new(kind, error.to_string()))
            }
            Some(Ok(prepared)) => {
                if let Some(cleanup) = &prepared.cleanup_error {
                    return Err(io::Error::new(
                        cleanup.error.kind(),
                        format!(
                            "checkpoint retained, but local spool cleanup failed: {}",
                            cleanup.error,
                        ),
                    ));
                }
                Ok(())
            }
            None => Err(io::Error::other(
                "checkpoint worker retired without a preparation result",
            )),
        }
    }
}

impl AsyncWrite for NativeCheckpointWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Register for admission/storage failure as well as queue space, even
        // if the worker fails before it ever polls the input reader.
        if self.poll_terminal(ctx).is_ready() {
            return Poll::Ready(self.terminal_io_result().and_then(|()| Err(closed_input())));
        }
        self.input.poll_write(ctx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.poll_terminal(ctx).is_ready() {
            return Poll::Ready(self.terminal_io_result());
        }
        self.input.poll_flush(ctx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        notify(self.input.stop(false));
        match self.poll_terminal(ctx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(()) => Poll::Ready(self.terminal_io_result()),
        }
    }
}

impl Drop for NativeCheckpointWriter {
    fn drop(&mut self) {
        if self.terminal.is_none() && !self.worker.is_finished() {
            self.worker
                .abort_with_reason(CancelReason::user("native checkpoint writer dropped"));
        }
        notify(self.input.stop(true));
        let retired = self.input.state.lock().writer_waker.take();
        drop(retired);
    }
}
