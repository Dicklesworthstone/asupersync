//! Explicit retry policy with one owner-clock budget for the whole delivery.

use super::{
    Bytes, Code, Cx, Duration, OtlpGrpcError, OtlpGrpcErrorKind, OtlpGrpcExporter,
    OtlpGrpcResponse, OtlpGrpcSignal, checkpoint,
};
use crate::observability::otel::OtlpCancelWakerGuard;
use crate::time::{Sleep, TimerDriverHandle};
use crate::types::Time;
use std::future::{Future, poll_fn};
use std::pin::{Pin, pin};
use std::task::Poll;

/// Maximum additional native unary invocations for one explicit retry policy.
pub const OTLP_GRPC_MAX_RETRIES: u32 = 16;

/// Opt-in retry policy for a single encoded OTLP request.
///
/// The initial attempt is followed by at most `max_retries` additional logical
/// unary calls. The caller's channel retains its own recovery of calls proven
/// unprocessed on reused connections. All attempts and waiting share the
/// exporter's existing timeout, further tightened by its channel and owner.
///
/// Client delays double up to `max_delay`. With jitter enabled, each delay is
/// chosen in its upper half from the explicit owner's entropy; a deterministic
/// runtime therefore reproduces the same sequence. A collector RetryInfo is a
/// minimum delay and is never reduced to the client cap. If the delay cannot
/// fit the remaining budget, no further request is made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OtlpGrpcRetryPolicy {
    max_retries: u32,
    initial_delay: Duration,
    max_delay: Duration,
    jitter: bool,
}

impl Default for OtlpGrpcRetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(2),
            jitter: true,
        }
    }
}

impl OtlpGrpcRetryPolicy {
    /// Validate a finite retry count and nonzero exponential delay range.
    /// Durations must fit the runtime's nanosecond clock representation.
    pub fn new(
        max_retries: u32,
        initial_delay: Duration,
        max_delay: Duration,
    ) -> Result<Self, OtlpGrpcError> {
        if max_retries > OTLP_GRPC_MAX_RETRIES
            || initial_delay.is_zero()
            || initial_delay > max_delay
            || max_delay.as_nanos() > u128::from(u64::MAX)
        {
            return Err(OtlpGrpcError::new(OtlpGrpcErrorKind::InvalidRetryPolicy));
        }
        Ok(Self {
            max_retries,
            initial_delay,
            max_delay,
            jitter: true,
        })
    }

    /// Enable owner-entropy jitter, or use the exact exponential delay.
    /// Disabling jitter removes the entropy capability requirement.
    #[must_use]
    pub const fn with_jitter(mut self, enabled: bool) -> Self {
        self.jitter = enabled;
        self
    }

    /// Maximum retries after the initial attempt.
    #[must_use]
    pub const fn max_retries(&self) -> u32 {
        self.max_retries
    }

    /// Initial exponential client delay, before optional jitter.
    #[must_use]
    pub const fn initial_delay(&self) -> Duration {
        self.initial_delay
    }

    /// Cap on the client exponential delay, not on collector throttle hints.
    #[must_use]
    pub const fn max_delay(&self) -> Duration {
        self.max_delay
    }

    /// Whether delays use the explicit owner's entropy.
    #[must_use]
    pub const fn jitter(&self) -> bool {
        self.jitter
    }

    fn delay(&self, base: Duration, random: u64) -> Duration {
        if !self.jitter {
            return base;
        }
        let nanos = u64::try_from(base.as_nanos()).expect("validated retry duration");
        let lower = nanos.div_ceil(2);
        let width = nanos - lower + 1;
        // Multiply-high sampling is bounded without an unbounded rejection
        // loop. It uses exactly one owner-entropy draw for each delayed retry.
        let offset = u64::try_from((u128::from(random) * u128::from(width)) >> 64)
            .expect("multiply-high result fits u64");
        Duration::from_nanos(lower + offset)
    }
}

impl OtlpGrpcExporter {
    /// Export one request with an explicit bounded retry policy.
    ///
    /// This leaves [`Self::send_once`] and existing owned conveniences unchanged.
    /// It requires the supplied context's timer before I/O; a policy that can
    /// retry with jitter also requires its entropy authority. It starts no task
    /// or runtime, uses no ambient timer/entropy, and retains one shared encoded
    /// body across attempts rather than copying it for each retry.
    ///
    /// Retry classification follows OTLP's gRPC status table. ResourceExhausted
    /// is retried only with valid collector RetryInfo. Invalid/mismatched rich
    /// status details fail closed. Every successful receipt is terminal,
    /// including partial rejection, warnings, and rejection of all items.
    /// A failed or cancelled request may already have reached the collector;
    /// the finite retry policy does not provide exactly-once delivery.
    ///
    /// The total timeout is fixed at entry, covering admission, DNS/TLS, every
    /// attempt, and all backoff. It never resets when another attempt starts.
    pub async fn send_with_retry(
        &self,
        cx: &Cx,
        signal: OtlpGrpcSignal,
        request_body: Vec<u8>,
        policy: &OtlpGrpcRetryPolicy,
    ) -> Result<OtlpGrpcResponse, OtlpGrpcError> {
        let operation: Pin<
            Box<dyn Future<Output = Result<OtlpGrpcResponse, OtlpGrpcError>> + Send + '_>,
        > = Box::pin(run(self, cx, signal, request_body, policy));
        operation.await
    }
}

async fn run(
    exporter: &OtlpGrpcExporter,
    cx: &Cx,
    signal: OtlpGrpcSignal,
    request_body: Vec<u8>,
    policy: &OtlpGrpcRetryPolicy,
) -> Result<OtlpGrpcResponse, OtlpGrpcError> {
    checkpoint(cx)?;
    exporter.validate_request_size(request_body.len())?;
    let timer = cx
        .timer_driver()
        .ok_or_else(|| OtlpGrpcError::new(OtlpGrpcErrorKind::RetryTimerUnavailable))?;
    if policy.max_retries != 0 && policy.jitter && !cx.capabilities().entropy {
        return Err(OtlpGrpcError::new(
            OtlpGrpcErrorKind::RetryEntropyUnavailable,
        ));
    }
    let now = timer.now();
    let deadline = now.saturating_add_nanos(
        u64::try_from(exporter.effective_timeout().as_nanos()).unwrap_or(u64::MAX),
    );
    let deadline = cx
        .budget()
        .deadline
        .map_or(deadline, |owner| owner.min(deadline));
    let body = Bytes::from(request_body);
    let mut retries = 0;
    let mut base_delay = policy.initial_delay;
    loop {
        checkpoint(cx)?;
        let attempt_timeout = remaining(&timer, deadline)?;
        let operation = exporter.send_attempt(cx, signal, body.clone(), attempt_timeout);
        let error = match drive_attempt(cx, &timer, deadline, operation).await {
            Ok(receipt) => return Ok(receipt),
            Err(error) => error,
        };
        // A peer error or an entropy provider may race owner cancellation.
        // No later attempt or wait may survive that owner's checkpoint.
        checkpoint(cx)?;
        if !retryable(&error) {
            return Err(error);
        }
        if retries == policy.max_retries {
            return Err(OtlpGrpcError {
                kind: OtlpGrpcErrorKind::RetryExhausted,
                ..error
            });
        }
        remaining(&timer, deadline)?;
        let random = if policy.jitter { cx.random_u64() } else { 0 };
        checkpoint(cx)?;
        let client_delay = policy.delay(base_delay, random);
        let delay = error
            .retry_delay
            .map_or(client_delay, |hint| hint.max(client_delay));
        if delay >= remaining(&timer, deadline)? {
            return Err(OtlpGrpcError {
                kind: OtlpGrpcErrorKind::RetryBudgetExhausted,
                ..error
            });
        }
        wait_delay(cx, &timer, deadline, delay).await?;
        retries += 1;
        base_delay = base_delay.saturating_mul(2).min(policy.max_delay);
    }
}

fn retryable(error: &OtlpGrpcError) -> bool {
    if error.kind != OtlpGrpcErrorKind::Rpc || !error.retry_info_valid {
        return false;
    }
    match error.grpc_code {
        Some(
            Code::Cancelled
            | Code::DeadlineExceeded
            | Code::Aborted
            | Code::OutOfRange
            | Code::Unavailable
            | Code::DataLoss,
        ) => true,
        Some(Code::ResourceExhausted) => error.retry_delay.is_some(),
        _ => false,
    }
}

fn exhausted_budget() -> OtlpGrpcError {
    OtlpGrpcError {
        grpc_code: Some(Code::DeadlineExceeded),
        ..OtlpGrpcError::new(OtlpGrpcErrorKind::RetryBudgetExhausted)
    }
}

fn remaining(timer: &TimerDriverHandle, deadline: Time) -> Result<Duration, OtlpGrpcError> {
    let now = timer.now();
    if now >= deadline {
        return Err(exhausted_budget());
    }
    Ok(Duration::from_nanos(deadline.duration_since(now)))
}

async fn drive_attempt(
    cx: &Cx,
    timer: &TimerDriverHandle,
    deadline: Time,
    future: impl Future<Output = Result<OtlpGrpcResponse, OtlpGrpcError>>,
) -> Result<OtlpGrpcResponse, OtlpGrpcError> {
    let mut future = pin!(future);
    let mut deadline = Sleep::with_timer_driver(deadline, timer.clone());
    let mut cancel = OtlpCancelWakerGuard::new(cx);
    poll_fn(|task| {
        cancel.refresh(task.waker());
        if let Err(error) = checkpoint(cx) {
            return Poll::Ready(Err(error));
        }
        // A completed receipt wins the timer boundary. Pending transport is
        // dropped on timeout, releasing its native I/O and admission guards.
        if let Poll::Ready(result) = future.as_mut().poll(task) {
            return Poll::Ready(result);
        }
        if Pin::new(&mut deadline).poll_deadline(task).is_ready() {
            Poll::Ready(Err(exhausted_budget()))
        } else {
            Poll::Pending
        }
    })
    .await
}

async fn wait_delay(
    cx: &Cx,
    timer: &TimerDriverHandle,
    deadline: Time,
    delay: Duration,
) -> Result<(), OtlpGrpcError> {
    checkpoint(cx)?;
    let now = timer.now();
    let wake = now.saturating_add_nanos(u64::try_from(delay.as_nanos()).unwrap_or(u64::MAX));
    if wake >= deadline {
        return Err(exhausted_budget());
    }
    let mut sleeper = Sleep::with_timer_driver(wake, timer.clone());
    let mut cancel = OtlpCancelWakerGuard::new(cx);
    poll_fn(|task| {
        cancel.refresh(task.waker());
        if let Err(error) = checkpoint(cx) {
            return Poll::Ready(Err(error));
        }
        if timer.now() >= deadline {
            return Poll::Ready(Err(exhausted_budget()));
        }
        Pin::new(&mut sleeper).poll_deadline(task).map(|()| Ok(()))
    })
    .await
}

#[cfg(test)]
#[path = "retry_tests.rs"]
mod tests;
