//! Bounded, wake-driven fanout. Every send future is owned by this invocation.

use super::{DistributionConfig, DistributorTransport, ReplicaAck, ReplicaFailure};
use crate::cx::Cx;
use crate::distributed::assignment::ReplicaAssignment;
use crate::distributed::encoding::EncodedState;
use crate::error::ErrorKind;
use crate::security::SecurityContext;
use crate::time::{Sleep, TimerDriverHandle};
use crate::types::{Outcome, Time};
use std::collections::BTreeSet;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::task::{Context, Poll};

mod hedge;

type SendResult = Result<ReplicaAck, ReplicaFailure>;
type SendFuture<'a> = Pin<Box<dyn Future<Output = SendResult> + Send + 'a>>;

pub(super) fn now(timer: Option<&TimerDriverHandle>) -> Time {
    timer.map_or_else(crate::time::wall_now, TimerDriverHandle::now)
}

fn failure(replica_id: &str, kind: ErrorKind, message: &'static str) -> ReplicaFailure {
    ReplicaFailure {
        replica_id: replica_id.to_owned(),
        error: message.to_owned(),
        error_kind: kind,
    }
}

struct Attempt<'a> {
    index: usize,
    replica_id: String,
    expected_symbols: u32,
    deadline: Time,
    timeout: Option<Pin<Box<Sleep>>>,
    future: SendFuture<'a>,
    attempted: bool,
}

impl Attempt<'_> {
    fn poll(&mut self, task: &mut Context<'_>, timer: Option<&TimerDriverHandle>, cx: &Cx) -> Poll<SendResult> {
        // Deadline wins ties. Do not invoke the transport for a zero budget, or
        // accept an acknowledgement after this attempt's deadline has passed.
        if now(timer) >= self.deadline {
            return Poll::Ready(Err(failure(
                &self.replica_id,
                ErrorKind::DeadlineExceeded,
                "replica acknowledgement deadline exceeded; delivery may be partial",
            )));
        }
        self.attempted = true;
        let result = self.future.as_mut().poll(task);
        if cx.is_cancel_requested() {
            return Poll::Ready(Err(failure(
                &self.replica_id, ErrorKind::Cancelled,
                "distribution cancelled during send; delivery may be partial",
            )));
        }
        match result {
            Poll::Ready(Ok(ack)) => {
                if now(timer) >= self.deadline {
                    return Poll::Ready(Err(failure(
                        &self.replica_id, ErrorKind::DeadlineExceeded,
                        "replica acknowledgement arrived at or after its deadline",
                    )));
                }
                if ack.replica_id != self.replica_id || ack.symbols_received != self.expected_symbols {
                    Poll::Ready(Err(failure(
                        &self.replica_id,
                        ErrorKind::ProtocolError,
                        "replica acknowledgement does not match the assigned replica and symbol count",
                    )))
                } else {
                    Poll::Ready(Ok(ack))
                }
            }
            Poll::Ready(Err(mut error)) => {
                // Attribution belongs to the assignment, never a peer-supplied ID.
                error.replica_id.clone_from(&self.replica_id);
                Poll::Ready(Err(error))
            }
            Poll::Pending => {
                // Ready-only transports need no registered timer. For pending
                // work Sleep provides the deadline wake, not a busy poll loop.
                let Some(timeout) = &mut self.timeout else {
                    return Poll::Ready(Err(failure(
                        &self.replica_id, ErrorKind::ConfigError,
                        "pending distribution requires an explicit context timer driver",
                    )));
                };
                if timeout.as_mut().poll(task).is_ready() {
                    Poll::Ready(Err(failure(
                        &self.replica_id,
                        ErrorKind::DeadlineExceeded,
                        "replica acknowledgement deadline exceeded; delivery may be partial",
                    )))
                } else {
                    Poll::Pending
                }
            }
        }
    }
}

#[derive(Debug)]
pub(super) struct FanoutResult {
    pub(super) outcomes: Vec<Outcome<ReplicaAck, ReplicaFailure>>,
    pub(super) symbols_attempted: u64,
    pub(super) eligible_replicas: usize,
}

pub(super) async fn run<T: DistributorTransport>(
    config: &DistributionConfig,
    cx: &Cx,
    encoded: &EncodedState,
    assignments: Vec<ReplicaAssignment>,
    transport: &T,
    auth_context: &SecurityContext,
    timer: Option<TimerDriverHandle>,
) -> FanoutResult {
    // One vote per eligible identity, even if the caller repeats a replica.
    // Retain first-occurrence order so completion timing cannot reorder reports.
    let mut seen = BTreeSet::new();
    let assignments: Vec<_> = assignments.into_iter().filter(|assignment| {
        !assignment.symbol_indices.is_empty() && seen.insert(assignment.replica_id.clone())
    }).collect();
    if config.hedge_enabled {
        return hedge::run(config, cx, encoded, assignments, transport, auth_context, timer).await;
    }
    let count = assignments.len();
    let mut outcomes: Vec<Option<Outcome<ReplicaAck, ReplicaFailure>>> =
        (0..count).map(|_| None).collect();
    let capacity = config.max_concurrent.min(count);
    let mut slots: Vec<Option<Attempt<'_>>> = (0..capacity).map(|_| None).collect();
    let mut cancelled = std::pin::pin!(cx.cancelled());
    let mut next = 0;
    let mut finished = 0;
    let mut symbols_attempted = 0_u64;

    poll_fn(|task| {
        if cancelled.as_mut().poll(task).is_ready() || capacity == 0 {
            // Retire admitted futures/timers before reporting, including futures
            // retaining buffers or socket registrations. Unstarted work never
            // reaches signing or the transport. This is not a remote rollback.
            for slot in &mut slots {
                if let Some(attempt) = slot.take() {
                    let index = attempt.index;
                    let id = attempt.replica_id.clone();
                    drop(attempt);
                    outcomes[index] = Some(Outcome::Err(failure(
                        &id, ErrorKind::Cancelled,
                        "distribution cancelled; admitted delivery may be partial",
                    )));
                }
            }
            let (kind, message) = if cx.is_cancel_requested() {
                (ErrorKind::Cancelled, "distribution cancelled before replica admission")
            } else {
                (ErrorKind::AdmissionDenied, "distribution concurrency limit is zero")
            };
            for (index, assignment) in assignments.iter().enumerate() {
                if outcomes[index].is_none() {
                    outcomes[index] = Some(Outcome::Err(failure(&assignment.replica_id, kind, message)));
                }
            }
            return Poll::Ready(());
        }

        // Fill at most the available slots. Deferred plans retain only indices;
        // signed payload copies exist only for admitted attempts.
        for slot in &mut slots {
            if slot.is_some() || next == count { continue; }
            if cx.is_cancel_requested() { break; }
            let index = next;
            next += 1;
            let assignment = &assignments[index];
            let Ok(expected_symbols) = u32::try_from(assignment.symbol_indices.len()) else {
                outcomes[index] = Some(Outcome::Err(failure(
                    &assignment.replica_id, ErrorKind::DataTooLarge,
                    "assigned symbol count cannot be represented by an acknowledgement",
                )));
                finished += 1;
                continue;
            };
            let deadline = now(timer.as_ref()) + config.ack_timeout;
            // Even signing is avoided for an explicitly zero acknowledgement budget.
            if config.ack_timeout.is_zero() {
                outcomes[index] = Some(Outcome::Err(failure(
                    &assignment.replica_id, ErrorKind::DeadlineExceeded,
                    "replica acknowledgement budget is zero; no send attempted",
                )));
                finished += 1;
                continue;
            }
            let symbols = assignment.symbol_indices.iter()
                .map(|&index| auth_context.sign_symbol(&encoded.symbols[index]))
                .collect();
            let replica_id = assignment.replica_id.clone();
            let send_id = replica_id.clone();
            // Construct the transport's future only when first polled. A queued
            // assignment must not acquire a socket or trigger eager provider work.
            let future = Box::pin(async move { transport.send_symbols(&send_id, symbols).await });
            let timeout = timer.as_ref().map(|timer| {
                Box::pin(Sleep::with_timer_driver(deadline, timer.clone()))
            });
            *slot = Some(Attempt {
                index, replica_id, expected_symbols, deadline,
                timeout, future, attempted: false,
            });
        }

        // Poll every active peer once per outer poll. No slow first peer can
        // prevent another admitted peer from transmitting or acknowledging.
        for slot in &mut slots {
            if cx.is_cancel_requested() { break; }
            let Some(attempt) = slot.as_mut() else { continue; };
            let was_attempted = attempt.attempted;
            let result = attempt.poll(task, timer.as_ref(), cx);
            if !was_attempted && attempt.attempted {
                symbols_attempted = symbols_attempted.saturating_add(u64::from(attempt.expected_symbols));
            }
            if let Poll::Ready(result) = result {
                let index = attempt.index;
                // Drop the entire attempt BEFORE credit is reused or a result
                // escapes. A completed future can still own transport resources.
                drop(slot.take());
                outcomes[index] = Some(match result {
                    Ok(ack) => Outcome::Ok(ack),
                    Err(error) => Outcome::Err(error),
                });
                finished += 1;
            }
        }
        if finished == count { return Poll::Ready(()); }
        if cx.is_cancel_requested() || (next < count && slots.iter().any(Option::is_none)) {
            // Refill on a fresh turn to bound immediate completions per poll.
            task.waker().wake_by_ref();
        }
        Poll::Pending
    }).await;

    // No active send is left behind, including on cancellation. On external
    // drop, ordinary ownership drops slots and the owned cancellation observer.
    drop(slots);
    FanoutResult {
        outcomes: outcomes.into_iter().map(|outcome| outcome.expect("all replica plans resolved")).collect(),
        symbols_attempted,
        eligible_replicas: count,
    }
}
