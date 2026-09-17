//! Application commit barriers after whole-stream verification and before Proof.
//!
//! Epoch flushes still acknowledge a prefix only. Opt-in committing receivers
//! additionally finish the sink's transaction before sending the final Proof.
//! A cancelled/timed-out commit is drained once it has started: cancellation
//! cannot roll back a filesystem publication or abandon its resource ownership.
//! This drain may outlive the operation timeout. A sink that never completes
//! cannot be safely preempted. Hard-dropping the entire receive still provides
//! no terminal report; use a scope-owned task and join it.

use super::{
    LiveStreamError, LiveStreamListener, LiveStreamReceipt, LiveStreamReport, LiveStreamTask,
    Progress, authorize, bounded,
};
use crate::cx::{Cx, Scope};
use crate::io::AsyncWrite;
use crate::types::Policy;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

/// A sink with a separate application publication/transaction boundary.
///
/// The receiver calls this only after checking ObjectComplete, the complete
/// chain/hash/length, and the final flush. Pending calls receive the same receipt;
/// there is no automatic retry after Ready. Returning Ok asserts only the
/// implementation's documented commit contract, not universal crash durability.
/// An Err can still follow externally visible effects and MUST NOT imply rollback.
///
/// Once polled, completion must remain driveable after cooperative Cx
/// cancellation. Keep in-flight state in the sink, register a completion waker,
/// and do not require fresh cancelled-context authority to finish admitted work.
/// The owner drains this operation on timeout/cancellation before releasing its
/// sink or admission credit. Implementations must bound their own commit work.
pub trait LiveStreamCommitSink: AsyncWrite {
    /// Finish publication for exactly this verified stream, not an epoch prefix.
    fn poll_commit(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        receipt: &LiveStreamReceipt,
    ) -> Poll<io::Result<()>>;
}

/// Independent application-commit and transport outcomes.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LiveStreamCommitError {
    /// The sink returned an error. Its external effects may be partial or final;
    /// reconcile with the sink rather than automatically retransmitting.
    #[error("live sink did not confirm application commit")]
    Unconfirmed {
        /// Validated whole-stream metadata, NOT an application commit receipt.
        receipt: Box<LiveStreamReceipt>,
        /// A timeout/cancellation observed before draining the commit, if any.
        interruption: Option<Box<LiveStreamError>>,
        /// Actual terminal sink failure, retained independently of interruption.
        #[source]
        source: io::Error,
    },
    /// The sink confirmed commit, but cancellation, timeout or transport failure
    /// prevented final Proof completion. Do not duplicate the committed effects.
    #[error("live sink committed but final peer proof did not complete")]
    CommittedWithoutProof {
        /// Metadata of the stream the sink actually acknowledged as committed.
        receipt: Box<LiveStreamReceipt>,
        /// Original interruption or Proof transmission failure.
        #[source]
        source: Box<LiveStreamError>,
    },
}

pub(super) fn proof_failed(
    receipt: &LiveStreamReceipt,
    source: LiveStreamError,
) -> LiveStreamError {
    LiveStreamError::Commit(Box::new(LiveStreamCommitError::CommittedWithoutProof {
        receipt: Box::new(receipt.clone()),
        source: Box::new(source),
    }))
}

struct Commit<'a, W> {
    sink: &'a mut W,
    receipt: &'a LiveStreamReceipt,
    started: bool,
}

impl<W: LiveStreamCommitSink + Unpin> Future for Commit<'_, W> {
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.started = true;
        Pin::new(&mut *this.sink).poll_commit(cx, this.receipt)
    }
}

pub(super) async fn finish<W: LiveStreamCommitSink + Unpin>(
    cx: &Cx,
    timeout: Duration,
    sink: &mut W,
    receipt: &LiveStreamReceipt,
) -> Result<(), LiveStreamError> {
    let mut commit = std::pin::pin!(Commit {
        sink,
        receipt,
        started: false
    });
    let observed = bounded(cx, timeout, "sink commit", commit.as_mut()).await;
    let (result, interruption) = match observed {
        Ok(()) => return Ok(()),
        Err(LiveStreamError::Io(source)) => (Err(source), None),
        Err(error) => {
            if !commit.as_ref().get_ref().started {
                // Never start a transaction merely to drain a cancelled wait.
                return Err(error);
            }
            // Only bounded() supplies this interruption. Do not poll an already
            // Ready sink again, restart its transaction, or detach its work.
            (commit.as_mut().await, Some(error))
        }
    };
    match result {
        Ok(()) => Err(proof_failed(
            receipt,
            interruption.expect("interrupted commit"),
        )),
        Err(source) => Err(LiveStreamError::Commit(Box::new(
            LiveStreamCommitError::Unconfirmed {
                receipt: Box::new(receipt.clone()),
                interruption: interruption.map(Box::new),
                source,
            },
        ))),
    }
}

// Preserve existing APIs' exact flush-only contract without specialization or
// a blanket implementation that would prevent a caller's own commit method.
pub(super) struct FlushOnly<W>(pub(super) W);

impl<W: AsyncWrite + Unpin> AsyncWrite for FlushOnly<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, bytes)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

impl<W: AsyncWrite + Unpin> LiveStreamCommitSink for FlushOnly<W> {
    fn poll_commit(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &LiveStreamReceipt,
    ) -> Poll<io::Result<()>> {
        // The compatibility path passes require_commit=false and never calls us.
        Poll::Ready(Ok(()))
    }
}

impl LiveStreamListener {
    /// Receive and commit verified content before transmitting final Proof.
    ///
    /// Unlike receive_into, this explicitly opts into the sink's commit contract.
    /// Epoch acknowledgements remain prefix flushes; no wire format changes.
    /// Inspect LiveStreamError::Commit on failure: a committed sink must not be
    /// retried simply because the peer did not receive its Proof. A started
    /// commit is drained even after cancellation/timeout; see LiveStreamCommitSink.
    pub async fn receive_committing<W: LiveStreamCommitSink + Unpin>(
        self,
        cx: &Cx,
        sink: &mut W,
    ) -> LiveStreamReport {
        let mut progress = Progress::default();
        let outcome = async {
            authorize(cx)?;
            let timeout = self.receiver.config.operation_timeout;
            let (tcp, _) = bounded(cx, timeout, "accept", self.listener.accept()).await?;
            let tls = bounded(
                cx,
                timeout,
                "TLS handshake",
                self.receiver.acceptor.accept(tcp),
            )
            .await?;
            self.receiver
                .receive_authenticated_with_commit(cx, tls, sink, &mut progress, true)
                .await
        }
        .await;
        progress.report(outcome)
    }

    /// Move the bound listener, committing sink and credit into a scoped child.
    ///
    /// Join the real child to observe its drained commit and transfer outcome.
    /// Pre-start cancellation never invokes the sink's commit method.
    pub fn spawn_receive_committing<P, W>(
        self,
        cx: &Cx,
        scope: &Scope<'_, P>,
        mut sink: W,
    ) -> Result<LiveStreamTask, LiveStreamError>
    where
        P: Policy,
        W: LiveStreamCommitSink + Unpin + Send + 'static,
    {
        authorize(cx)?;
        cx.spawn_in(scope, move |child| {
            let future: Pin<Box<dyn Future<Output = LiveStreamReport> + Send>> =
                Box::pin(async move { self.receive_committing(&child, &mut sink).await });
            future
        })
        .map_err(LiveStreamError::Spawn)
    }
}

/// Explicit no-overwrite publication in a caller-owned private Unix directory.
#[cfg(unix)]
#[path = "commit/file.rs"]
pub mod file;

/// Authenticated connection recovery with retained source and committing sink state.
#[path = "resume.rs"]
pub mod resume;
