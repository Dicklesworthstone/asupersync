//! Per-collection completion for bounded native export admission.

use super::{ExportError, ExportQueue, OtlpGrpcExportReport, OtlpGrpcResponse};
use crate::grpc::Code;
use parking_lot::Mutex;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

// The decoder bounds collector diagnostics at 4096 bytes. Reserve twice that
// allowance plus container/token space per batch, before publication. The
// budget is conservative. The whole collection's reservation stays charged
// until its last token retires, including diagnostics from earlier requests.
pub(super) const RESERVED_BYTES_PER_BATCH: usize = 8192
    + std::mem::size_of::<OtlpGrpcResponse>()
    + std::mem::size_of::<Completion>()
    + std::mem::size_of::<CompletionToken>();

#[derive(Clone, Copy)]
struct Failure {
    code: &'static str,
    grpc_code: Option<Code>,
}

/// Terminal failure of an admitted collection, with its earlier receipts.
///
/// Completed responses must not be replayed. An interrupted request may also
/// have reached the collector. No error or Debug output includes peer text.
#[derive(Clone)]
pub struct OtlpGrpcQueueReceiptError {
    failure: Failure,
    completed: Vec<OtlpGrpcResponse>,
}

impl OtlpGrpcQueueReceiptError {
    /// Static failure code, never an endpoint or collector diagnostic.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.failure.code
    }

    /// Terminal gRPC status, if a native call returned one.
    #[must_use]
    pub const fn grpc_code(&self) -> Option<Code> {
        self.failure.grpc_code
    }

    /// Validated full/partial acknowledgements in original request order.
    #[must_use]
    pub fn completed_responses(&self) -> &[OtlpGrpcResponse] {
        &self.completed
    }
}

impl fmt::Debug for OtlpGrpcQueueReceiptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OtlpGrpcQueueReceiptError")
            .field("code", &self.code())
            .field("grpc_code", &self.grpc_code())
            .field("completed_requests", &self.completed.len())
            .finish()
    }
}

impl fmt::Display for OtlpGrpcQueueReceiptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for OtlpGrpcQueueReceiptError {}

struct CompletionState {
    responses: Vec<Option<OtlpGrpcResponse>>,
    remaining: usize,
    ready: bool,
    failure: Option<(usize, Failure)>,
    observer: bool,
    waiter: Option<Waker>,
}

struct Completion {
    state: Mutex<CompletionState>,
    queue: Weak<ExportQueue>,
    reserved_bytes: usize,
}

/// Await actual delivery of one atomically admitted native collection.
///
/// This future starts no task. The caller must drive the queue explicitly or
/// run its managed exporter. Success includes terminal partial-success
/// responses, whose rejected-item counts must be inspected. Every batch has
/// retired its payload and queue credit before the receipt becomes ready.
///
/// Dropping this observation leaves admitted work owned by the queue; it does
/// not cancel or replay it. A failed or abandoned batch makes the receipt fail
/// after the collection retires. The ordinary unmanaged queue keeps its
/// documented retry/retained-backlog behavior; a managed owner's exit retires
/// the whole remaining backlog and resolves all its receipts.
/// Once ready, the returned responses are caller-owned and no longer consume
/// queue credit. Retaining completed reports is the caller's responsibility.
#[must_use = "await the collection receipt to observe collector completion"]
pub struct OtlpGrpcQueueReceipt {
    completion: Arc<Completion>,
    completed: bool,
}

impl fmt::Debug for OtlpGrpcQueueReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.completion.state.lock();
        f.debug_struct("OtlpGrpcQueueReceipt")
            .field("remaining_requests", &state.remaining)
            .field("failed", &state.failure.is_some())
            .field("observed", &self.completed)
            .finish()
    }
}

impl OtlpGrpcQueueReceipt {
    pub(super) fn empty() -> Self {
        ReceiptRegistration::new(0, Weak::new(), 0).into_receipt()
    }
}

impl Future for OtlpGrpcQueueReceipt {
    type Output = Result<OtlpGrpcExportReport, OtlpGrpcQueueReceiptError>;

    fn poll(mut self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<Self::Output> {
        assert!(
            !self.completed,
            "collection receipt polled after completion"
        );
        // User waker clone/drop callbacks stay outside the completion lock.
        let incoming = task.waker().clone();
        let mut state = self.completion.state.lock();
        if !state.ready {
            let old = state.waiter.replace(incoming);
            drop(state);
            drop(old);
            return Poll::Pending;
        }
        let responses = std::mem::take(&mut state.responses)
            .into_iter()
            .flatten()
            .collect();
        let failure = state.failure.map(|(_, failure)| failure);
        let old = state.waiter.take();
        state.observer = false;
        drop(state);
        drop(old);
        drop(incoming);
        self.completed = true;
        Poll::Ready(match failure {
            Some(failure) => Err(OtlpGrpcQueueReceiptError {
                failure,
                completed: responses,
            }),
            None => Ok(OtlpGrpcExportReport::from_responses(responses)),
        })
    }
}

impl Drop for OtlpGrpcQueueReceipt {
    fn drop(&mut self) {
        let mut state = self.completion.state.lock();
        state.observer = false;
        let waiter = state.waiter.take();
        let responses = std::mem::take(&mut state.responses);
        drop(state);
        drop(waiter);
        drop(responses);
    }
}

pub(super) struct ReceiptRegistration {
    completion: Arc<Completion>,
}

impl ReceiptRegistration {
    pub(super) fn new(count: usize, queue: Weak<ExportQueue>, reserved_bytes: usize) -> Self {
        Self {
            completion: Arc::new(Completion {
                state: Mutex::new(CompletionState {
                    responses: (0..count).map(|_| None).collect(),
                    remaining: count,
                    ready: count == 0,
                    failure: None,
                    observer: true,
                    waiter: None,
                }),
                queue,
                reserved_bytes,
            }),
        }
    }

    pub(super) fn token(&self, index: usize) -> CompletionToken {
        CompletionToken {
            completion: Arc::clone(&self.completion),
            index,
            outcome: None,
        }
    }

    pub(super) fn into_receipt(self) -> OtlpGrpcQueueReceipt {
        OtlpGrpcQueueReceipt {
            completion: self.completion,
            completed: false,
        }
    }
}

pub(super) struct CompletionToken {
    completion: Arc<Completion>,
    index: usize,
    outcome: Option<Result<OtlpGrpcResponse, Failure>>,
}

impl fmt::Debug for CompletionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompletionToken")
            .field("index", &self.index)
            .finish_non_exhaustive()
    }
}

impl CompletionToken {
    pub(super) fn acknowledge(&mut self, response: OtlpGrpcResponse) {
        self.outcome = Some(Ok(response));
    }

    pub(super) fn fail(&mut self, code: &'static str, grpc_code: Option<Code>) {
        self.outcome = Some(Err(Failure { code, grpc_code }));
    }
}

impl Drop for CompletionToken {
    fn drop(&mut self) {
        let outcome = self.outcome.take().unwrap_or(Err(Failure {
            code: "otlp.queue.abandoned",
            grpc_code: None,
        }));
        let mut state = self.completion.state.lock();
        match outcome {
            Ok(response) if state.observer => state.responses[self.index] = Some(response),
            Ok(_) => {}
            Err(failure) => {
                if state.failure.is_none_or(|(index, _)| self.index < index) {
                    state.failure = Some((self.index, failure));
                }
            }
        }
        state.remaining -= 1;
        let terminal = state.remaining == 0;
        drop(state);
        if !terminal {
            return;
        }
        // Completed responses from earlier requests still occupy this
        // collection's reservation. Release that aggregate credit only when
        // every token has retired. The weak reference cannot retain a queue
        // through its own pending batches.
        if let Some(queue) = self.completion.queue.upgrade() {
            let mut state = queue.state.lock();
            state.stats.retained_bytes -= self.completion.reserved_bytes;
            drop(state);
            queue.retired.notify_all();
        }
        let waiter = {
            let mut state = self.completion.state.lock();
            state.ready = true;
            state.waiter.take()
        };
        if let Some(waiter) = waiter {
            // Keep the owner outside the first unwind boundary: wake and its
            // last-owner destructor may each panic. A swallowed panic payload
            // can also have a panicking destructor, so do not drop it here.
            if let Err(payload) =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| waiter.wake_by_ref()))
            {
                std::mem::forget(payload);
            }
            if let Err(payload) =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(waiter)))
            {
                std::mem::forget(payload);
            }
        }
    }
}

impl ExportQueue {
    pub(super) fn ensure_managed_active(&self) -> Result<(), ExportError> {
        let state = self.state.lock();
        if state.sealed {
            return Err(ExportError::new("otlp.queue.closed"));
        }
        if !state.acknowledged_owner_ready || !state.stats.consumer_active {
            return Err(ExportError::new("otlp.sdk.managed_owner_required"));
        }
        Ok(())
    }

    pub(super) fn wait_flushed_blocking(
        &self,
        timeout: Duration,
        shutdown: bool,
    ) -> Result<(), ExportError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| ExportError::new("otlp.sdk.invalid_timeout"))?;
        let mut state = self.state.lock();
        if shutdown {
            state.sealed = true;
            drop(state);
            self.ready.notify_one();
            state = self.state.lock();
        }
        loop {
            let done = state.stats.retained_batches == 0
                && state.stats.retained_bytes == 0
                && (!shutdown || !state.stats.consumer_active);
            if done {
                return if state.stats.failed_batches == 0 {
                    Ok(())
                } else {
                    Err(ExportError::new("otlp.queue.delivery_failed"))
                };
            }
            // A synchronous SDK callback must never park the native task that
            // owns delivery. Its caller can use managed drain/join instead.
            if crate::Cx::current().is_some() {
                return Err(ExportError::new("otlp.sdk.blocking_on_runtime"));
            }
            if !state.acknowledged_owner_ready || !state.stats.consumer_active {
                return Err(ExportError::new("otlp.sdk.managed_owner_required"));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(ExportError::new("otlp.sdk.flush_timeout"));
            }
            self.retired.wait_for(&mut state, remaining);
        }
    }
}

#[cfg(test)]
#[path = "queued_receipt_tests.rs"]
mod tests;
