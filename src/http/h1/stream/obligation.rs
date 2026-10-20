//! Checked ownership of one protocol-side incoming request body.
//!
//! The consumer never owns this token. Its early drop transfers the remaining
//! framing work to the same protocol writer, which must synchronize or close.
//! Framed protocols may keep the writer in their connection pump; their token
//! stays in the actual request task and observes the writer's terminal state.

use super::IncomingBodyError;
use crate::cx::Cx;
use crate::record::{ObligationAbortReason, ObligationKind};
use crate::runtime::obligation_mailbox::{ObligationAdmissionError, ObligationToken};
use crate::types::CancelKind;

/// Refusal before a checked request body becomes visible to application code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum IncomingBodyAdmissionError {
    Policy(IncomingBodyError),
    Cancelled { kind: CancelKind },
    Runtime(ObligationAdmissionError),
    RuntimeRequired,
}

impl std::fmt::Display for IncomingBodyAdmissionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Policy(error) => std::fmt::Display::fmt(error, formatter),
            Self::Cancelled { kind } => {
                write!(formatter, "incoming body admission cancelled ({kind:?})")
            }
            Self::Runtime(error) => std::fmt::Display::fmt(error, formatter),
            Self::RuntimeRequired => {
                formatter.write_str("checked incoming body requires a runtime-owned task")
            }
        }
    }
}

impl std::error::Error for IncomingBodyAdmissionError {}

/// Holds the credit even while the consumer is gone and no sender remains.
/// All settlement is synchronous and independent of a cancelled channel send.
#[derive(Debug)]
pub(super) struct IncomingBodyObligation {
    token: Option<ObligationToken>,
    owner: Cx,
}

impl IncomingBodyObligation {
    pub(super) fn admit(cx: &Cx) -> Result<Self, IncomingBodyAdmissionError> {
        checkpoint(cx)?;
        let token = cx
            .try_register_obligation_checked(ObligationKind::IoOp, cx.task_id())
            .map_err(IncomingBodyAdmissionError::Runtime)?
            .ok_or(IncomingBodyAdmissionError::RuntimeRequired)?;
        // Install the abort backstop before a second checkpoint or liveness
        // check: admission notifications may themselves cancel the owner.
        let admitted = Self {
            token: Some(token),
            owner: cx.clone(),
        };
        checkpoint(cx)?;
        let (gateway, holder) = cx
            .obligation_transfer_destination()
            .map_err(IncomingBodyAdmissionError::Runtime)?;
        let token = admitted.token.as_ref().expect("admitted body credit");
        let refusal = if !gateway.is_runtime_available() {
            Some(ObligationAdmissionError::RuntimeUnavailable)
        } else if !holder.is_live() {
            Some(ObligationAdmissionError::HolderNotLive)
        } else if token.holder() != holder.holder()
            || token.region() != holder.region()
            || token.holder() != cx.task_id()
            || token.region() != cx.region_id()
        {
            Some(ObligationAdmissionError::HolderMismatch)
        } else {
            None
        };
        if let Some(error) = refusal {
            return Err(IncomingBodyAdmissionError::Runtime(error));
        }
        Ok(admitted)
    }

    pub(super) fn commit(&mut self) {
        if let Some(token) = self.token.take() {
            let _ = token.commit();
        }
    }

    pub(super) fn abort(&mut self, error: &IncomingBodyError) {
        if let Some(token) = self.token.take() {
            let reason = if matches!(error, IncomingBodyError::Cancelled { .. }) {
                ObligationAbortReason::Cancel
            } else {
                ObligationAbortReason::Error
            };
            let _ = token.abort(reason);
        }
    }

    pub(super) fn abandoned_error(&self) -> IncomingBodyError {
        if self.owner.is_cancel_requested() {
            IncomingBodyError::cancelled(&self.owner)
        } else {
            IncomingBodyError::SourceDisconnected
        }
    }
}

impl Drop for IncomingBodyObligation {
    fn drop(&mut self) {
        let error = self.abandoned_error();
        self.abort(&error);
    }
}

/// Request-local settlement for a writer polled by another protocol task.
///
/// The token is never handed to that task. In particular, a writer cannot
/// detach it to settle outside a lock while the named holder retires. EOF and
/// failure only publish a shared verdict; this guard settles on the holder's
/// next poll, or synchronously when the holder drops its work.
#[cfg(any(feature = "http2-streaming", all(feature = "http3", feature = "tls")))]
#[derive(Debug)]
pub(crate) struct FramedIncomingBodyGuard {
    obligation: Option<IncomingBodyObligation>,
    shared: std::sync::Arc<super::IncomingBodyShared>,
    sender: crate::channel::mpsc::WeakSender<super::QueuedIncomingFrame>,
}

#[cfg(any(feature = "http2-streaming", all(feature = "http3", feature = "tls")))]
#[pin_project::pin_project]
struct GuardedFramedBodyWork<F> {
    // Fields drop in declaration order. Publish the owner's failure and
    // settle its token before structural body Drop can look like an ordinary
    // early response to a connection driver running on another worker.
    guard: FramedIncomingBodyGuard,
    #[pin]
    work: F,
}

#[cfg(any(feature = "http2-streaming", all(feature = "http3", feature = "tls")))]
impl<F: std::future::Future> std::future::Future for GuardedFramedBodyWork<F> {
    type Output = F::Output;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        task_cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.project();
        this.guard.observe(task_cx.waker());
        let result = this.work.poll(task_cx);
        this.guard.observe(task_cx.waker());
        if result.is_ready() {
            this.guard.stop_unfinished(true);
        }
        result
    }
}

#[cfg(any(feature = "http2-streaming", all(feature = "http3", feature = "tls")))]
impl FramedIncomingBodyGuard {
    pub(super) fn new(
        obligation: IncomingBodyObligation,
        shared: std::sync::Arc<super::IncomingBodyShared>,
        sender: crate::channel::mpsc::WeakSender<super::QueuedIncomingFrame>,
    ) -> Self {
        Self {
            obligation: Some(obligation),
            shared,
            sender,
        }
    }

    /// Run the whole request work under its original obligation holder.
    ///
    /// This includes any response producer and transport-completion wait that
    /// keeps the request alive. Protocol EOF can settle while application
    /// work remains parked. Returning with unread input abandons only that
    /// input; it does not cancel a legitimate early response.
    pub(crate) fn run<F: std::future::Future>(self, work: F) -> impl std::future::Future<Output = F::Output> {
        // Construct ownership synchronously so even a wrapper dropped before
        // its first poll retires the guard before the captured user future.
        GuardedFramedBodyWork { guard: self, work }
    }

    fn observe(&mut self, waker: &std::task::Waker) {
        if self.obligation.is_none() {
            return;
        }
        // Register before reading terminal state. A racing writer either
        // wakes this registration or leaves a verdict that settle observes.
        // Clone and retire caller-supplied wakers outside every shared lock.
        let mut incoming = Some(waker.clone());
        let retired = {
            let mut registered = self.shared.framed_holder_waker.lock();
            if registered
                .as_ref()
                .is_some_and(|registered| registered.will_wake(waker))
            {
                None
            } else {
                std::mem::replace(&mut *registered, incoming.take())
            }
        };
        drop(retired);
        drop(incoming);
        self.settle();
    }

    fn settle(&mut self) {
        let Some(terminal) = self.shared.framed_terminal() else {
            return;
        };
        if let Some(mut obligation) = self.obligation.take() {
            match terminal {
                Ok(()) => obligation.commit(),
                Err(error) => obligation.abort(&error),
            }
        }
        let retired = self.shared.framed_holder_waker.lock().take();
        drop(retired);
    }

    fn stop_unfinished(&mut self, completed: bool) {
        let error = self.shared.framed_consumer_error.lock().clone();
        let error = error.unwrap_or_else(|| {
            self.obligation.as_ref().map_or(
                IncomingBodyError::SourceDisconnected,
                |obligation| {
                    if obligation.owner.is_cancel_requested() {
                        IncomingBodyError::cancelled(&obligation.owner)
                    } else if completed {
                        IncomingBodyError::ConsumerDropped
                    } else {
                        IncomingBodyError::SourceDisconnected
                    }
                },
            )
        });
        // Never hold the consumer-error lock while entering the terminal
        // lock. A concurrent FIN, earlier transport error, or earlier stop
        // keeps its first verdict, regardless of which observer runs next.
        let terminal = self.shared.set_framed_terminal(Err(error));
        self.settle();
        if terminal.is_err() {
            // A weak sender does not keep a clean EOF open. On unfinished
            // retirement, seal the live channel even if the connection pump
            // still holds its writer or a pending send. Descendant readers
            // and capacity waiters must wake without another peer packet.
            if let Some(sender) = self.sender.upgrade() {
                sender.close_receiver();
            }
            self.shared.wake_framed_producer();
        }
    }
}

#[cfg(any(feature = "http2-streaming", all(feature = "http3", feature = "tls")))]
impl Drop for FramedIncomingBodyGuard {
    fn drop(&mut self) {
        self.stop_unfinished(false);
    }
}

fn checkpoint(cx: &Cx) -> Result<(), IncomingBodyAdmissionError> {
    cx.checkpoint()
        .map_err(|_| IncomingBodyAdmissionError::Cancelled {
            kind: cx
                .cancel_reason()
                .map_or(CancelKind::User, |reason| reason.kind()),
        })
}
