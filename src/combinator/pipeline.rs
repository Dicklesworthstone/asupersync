//! Pipeline combinator for staged processing.
//!
//! The pipeline combinator chains a sequence of transformations where each
//! stage's output feeds the next stage's input. The existing folds and macro
//! retain their sequential behavior. [`PipelineExecution`] additionally runs
//! typed streaming stages as scope-owned workers with bounded checked channels.
//!
//! # Design Philosophy
//!
//! Two modes of pipeline operation:
//! 1. **Sequential pipeline**: Stage N+1 starts only after stage N completes.
//! 2. **Streaming pipeline**: Concurrent workers preserve each input's order,
//!    and a whole-pipeline work window lasts through asynchronous consumption.
//!
//! # Behavior
//!
//! ```text
//! pipeline(input, [stage1, stage2, stage3]):
//!   r1 <- stage1(input)
//!   if r1 is Err/Cancelled/Panicked: return r1
//!   r2 <- stage2(r1.value)
//!   if r2 is Err/Cancelled/Panicked: return r2
//!   r3 <- stage3(r2.value)
//!   return r3
//! ```
//!
//! # Cancellation Handling
//!
//! - Check cancellation between stages
//! - If cancelled before stage N: return Cancelled, stages N..end never execute
//! - Stage cleanup runs if stage was started
//!
//! # Invariants
//!
//! - **Sequential ordering**: Output of stage N is input to stage N+1
//! - **Error short-circuit**: First error stops pipeline
//! - **Streaming publication**: A sink can observe a successful prefix before a
//!   later failure; its acknowledged prefix count is retained in the report
//! - **Cancel-correctness**: Respects cancellation at stage boundaries

use crate::channel::mpsc;
use crate::cx::{Cx, Scope};
use crate::record::{ObligationAbortReason, ObligationKind};
use crate::runtime::obligation_mailbox::{ObligationAdmissionError, ObligationToken};
use crate::runtime::{JoinError, SpawnError, TaskHandle};
use crate::types::Outcome;
use crate::types::Policy;
use crate::types::cancel::CancelReason;
use crate::types::outcome::PanicPayload;
use core::fmt;
use std::collections::VecDeque;
use std::future::Future;
use std::marker::PhantomData;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Independent input-edge and whole-pipeline work limits.
///
/// The work limit counts every pulled item until its async sink acknowledges
/// it, including queued, active and completed-but-unacknowledged items. It is
/// an item bound, not a byte bound on caller-owned input storage or allocations
/// made by transforms and the sink. Every configured edge has its own bound.
/// Runtime obligation quota must also allow transient checked channel permits.
/// A work credit is admitted before `Iterator::next`, including the final EOF
/// probe, whose unused credit is explicitly aborted. Thus even empty input
/// needs authority to inspect the iterator; a zero runtime quota refuses first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PipelineExecutionConfig {
    input_capacity: NonZeroUsize,
    max_in_flight: NonZeroUsize,
}

impl PipelineExecutionConfig {
    /// Creates explicit, nonzero bounds without changing legacy pipeline config.
    #[must_use]
    pub const fn new(input_capacity: NonZeroUsize, max_in_flight: NonZeroUsize) -> Self {
        Self {
            input_capacity,
            max_in_flight,
        }
    }

    /// Capacity of the initial bounded channel.
    #[must_use]
    pub const fn input_capacity(self) -> NonZeroUsize {
        self.input_capacity
    }

    /// Maximum pulled items not yet acknowledged by the sink.
    #[must_use]
    pub const fn max_in_flight(self) -> NonZeroUsize {
        self.max_in_flight
    }
}

/// Counts from a successfully drained executing pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct PipelineExecutionSummary {
    /// Inputs actually pulled and admitted to the work window.
    pub admitted: usize,
    /// Async sink completions acknowledged exactly once, in input order.
    pub consumed: usize,
    /// Maximum occupied work-window slots, including pending channel sends.
    pub max_in_flight: usize,
    /// Transform workers, excluding the single sink worker.
    pub stages: usize,
}

/// The full severity join plus bounded diagnostics from the initiating failure.
///
/// Cancelling and draining a sibling can strengthen a domain/admission error
/// into `Cancelled`, or a cleanup panic can strengthen it into `Panicked`.
/// That does not erase the original typed error: [`Self::error`] exposes it
/// without requiring `E: Clone`. Only one suppressed error is retained; this
/// report never accumulates a per-input outcome history.
#[derive(Debug)]
#[non_exhaustive]
pub struct PipelineExecutionReport<E> {
    /// Actual four-way join of coordinator and drained worker outcomes.
    pub outcome: Outcome<PipelineExecutionSummary, PipelineExecutionError<E>>,
    /// Counters also available on partial/failing execution.
    pub summary: PipelineExecutionSummary,
    /// First observed typed error displaced by stage ordering or a stronger outcome.
    /// A channel disconnection is a consequence of another party's exit, never
    /// an initiating failure, so it is not retained here.
    pub suppressed_error: Option<PipelineExecutionError<E>>,
}

impl<E> PipelineExecutionReport<E> {
    /// Returns the typed outer error, or the retained initiating error if stronger severity won.
    #[must_use]
    pub fn error(&self) -> Option<&PipelineExecutionError<E>> {
        match &self.outcome {
            Outcome::Err(error) => Some(error),
            _ => self.suppressed_error.as_ref(),
        }
    }
}

/// Failure of an executing pipeline, separate from legacy fold errors.
#[derive(Debug)]
#[non_exhaustive]
pub enum PipelineExecutionError<E> {
    /// A transform or sink returned a domain error.
    Stage {
        /// Transform index; the sink follows the last transform.
        stage: usize,
        /// Original input position.
        input: usize,
        /// The unchanged domain error.
        error: E,
    },
    /// The actual runtime refused spawning a worker.
    Spawn(SpawnError),
    /// Checked obligation admission refused a work or channel credit.
    Admission {
        /// Transform index, the sink index, or `None` for coordinator ingress.
        stage: Option<usize>,
        /// Original input position, including the next-position EOF probe.
        input: usize,
        /// The unchanged authoritative refusal.
        error: ObligationAdmissionError,
    },
    /// An owned edge closed before its documented terminal boundary.
    Disconnected,
    /// The sink acknowledgement did not name the next original input.
    Acknowledgement {
        /// Next expected position, or no outstanding item.
        expected: Option<usize>,
        /// Position received from the sink.
        actual: usize,
    },
    /// A finite position counter could not represent another input.
    InputIndexExhausted,
}

impl<E: fmt::Display> fmt::Display for PipelineExecutionError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stage {
                stage,
                input,
                error,
            } => write!(f, "pipeline stage {stage}, input {input}: {error}"),
            Self::Spawn(error) => write!(f, "pipeline spawn: {error}"),
            Self::Admission {
                stage,
                input,
                error,
            } => write!(
                f,
                "pipeline admission at stage {stage:?}, input {input}: {error}"
            ),
            Self::Disconnected => f.write_str("pipeline edge closed before delivery completed"),
            Self::Acknowledgement { expected, actual } => write!(
                f,
                "pipeline acknowledgement {actual}, expected {expected:?}"
            ),
            Self::InputIndexExhausted => f.write_str("pipeline input index exhausted"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for PipelineExecutionError<E> {}

struct PipelineItem<T> {
    index: usize,
    value: T,
}

type PipelineWorker<E> = Box<
    dyn FnOnce(Cx) -> Pin<Box<dyn Future<Output = Outcome<(), PipelineExecutionError<E>>> + Send>>
        + Send,
>;

/// Lazy, typed stages executed as real tasks in an existing scope.
///
/// [`Self::then`] can change the item type at every bounded channel edge.
/// Building does not spawn tasks or pull inputs. [`Self::run`] creates one
/// worker per transform and one async sink worker; each worker processes its
/// inputs sequentially, preserving FIFO order. Zero transforms streams the
/// inputs straight to the sink. Empty input never invokes a transform or sink.
///
/// Every normal or failing return joins all admitted workers. Cancellation,
/// errors and panics stop admission, request cancellation of remaining workers
/// and drain their actual outcomes under `Panicked > Cancelled > Err > Ok`.
/// A noncooperative worker keeps the operation pending and region-owned.
/// Dropping the running future requests cancellation; synchronous drop cannot
/// drain, and the region remains the quiescence boundary.
#[must_use = "a pipeline executes only when run is awaited"]
pub struct PipelineExecution<'scope, I: IntoIterator, T, E, P: Policy> {
    scope: Scope<'scope, P>,
    cx: Cx,
    inputs: I,
    config: PipelineExecutionConfig,
    ingress: mpsc::Sender<PipelineItem<I::Item>>,
    output: mpsc::Receiver<PipelineItem<T>>,
    workers: Vec<PipelineWorker<E>>,
}

impl<'scope, I, E, P> PipelineExecution<'scope, I, I::Item, E, P>
where
    I: IntoIterator,
    I::Item: Send + 'static,
    E: Send + 'static,
    P: Policy,
{
    /// Creates an identity pipeline using the scope's existing runtime wiring.
    #[must_use]
    pub fn new(
        scope: &Scope<'scope, P>,
        cx: &Cx,
        inputs: I,
        config: PipelineExecutionConfig,
    ) -> Self {
        let (ingress, output) = mpsc::channel(config.input_capacity.get());
        let scope = Scope::new_with_capability_budget(
            scope.region_id(),
            scope.budget(),
            scope.capability_budget(),
        )
        .with_pending_spawn_counter(scope.pending_spawn_counter_handle());
        Self {
            scope,
            cx: cx.clone(),
            inputs,
            config,
            ingress,
            output,
            workers: Vec::new(),
        }
    }
}

impl<'scope, I, T, E, P> PipelineExecution<'scope, I, T, E, P>
where
    I: IntoIterator,
    I::Item: Send + 'static,
    T: Send + 'static,
    E: Send + 'static,
    P: Policy,
{
    /// Appends one typed, sequential transform with its own bounded output edge.
    ///
    /// The transform receives its actual worker context. A checked send permit
    /// is acquired and settled by that worker, never moved between holders.
    #[must_use]
    pub fn then<U, F, Fut>(
        self,
        output_capacity: NonZeroUsize,
        mut transform: F,
    ) -> PipelineExecution<'scope, I, U, E, P>
    where
        U: Send + 'static,
        F: FnMut(Cx, T) -> Fut + Send + 'static,
        Fut: Future<Output = Outcome<U, E>> + Send + 'static,
    {
        let Self {
            scope,
            cx,
            inputs,
            config,
            ingress,
            mut output,
            mut workers,
        } = self;
        let stage = workers.len();
        let (sender, next_output) = mpsc::channel(output_capacity.get());
        workers.push(Box::new(move |worker_cx| {
            Box::pin(async move {
                let mut quantum = 0;
                loop {
                    let item = match output.recv(&worker_cx).await {
                        Ok(item) => item,
                        Err(mpsc::RecvError::Disconnected) => return Outcome::Ok(()),
                        Err(_) => return pipeline_cancelled(&worker_cx),
                    };
                    let value = match transform(worker_cx.clone(), item.value).await {
                        Outcome::Ok(value) => value,
                        Outcome::Err(error) => {
                            return Outcome::Err(PipelineExecutionError::Stage {
                                stage,
                                input: item.index,
                                error,
                            });
                        }
                        Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
                        Outcome::Panicked(payload) => return Outcome::Panicked(payload),
                    };
                    if let Err(error) = sender
                        .send_checked(
                            &worker_cx,
                            PipelineItem {
                                index: item.index,
                                value,
                            },
                        )
                        .await
                    {
                        return pipeline_send_failure(&worker_cx, Some(stage), item.index, error);
                    }
                    quantum += 1;
                    if quantum == PIPELINE_QUANTUM {
                        quantum = 0;
                        crate::runtime::yield_now().await;
                    }
                }
            })
        }));
        PipelineExecution {
            scope,
            cx,
            inputs,
            config,
            ingress,
            output: next_output,
            workers,
        }
    }

    /// Executes all stages and an async sink, retaining credits until sink ack.
    ///
    /// User-created iterator/transform/sink panics become `Outcome::Panicked`
    /// only after every owned worker has terminated. Input order determines
    /// publication and equal-severity stage attribution. An induced loser
    /// cancellation remains a real `Cancelled` outcome in the severity join.
    pub async fn run<F, Fut>(self, mut sink: F) -> PipelineExecutionReport<E>
    where
        I: Send,
        I::IntoIter: Send,
        F: FnMut(Cx, T) -> Fut + Send + 'static,
        Fut: Future<Output = Outcome<(), E>> + Send + 'static,
    {
        let Self {
            scope,
            cx,
            inputs,
            config,
            ingress,
            mut output,
            mut workers,
        } = self;
        let stages = workers.len();
        let (ack_sender, mut acknowledgements) = mpsc::channel(config.max_in_flight.get());
        workers.push(Box::new(move |worker_cx| {
            Box::pin(async move {
                let mut quantum = 0;
                loop {
                    let item = match output.recv(&worker_cx).await {
                        Ok(item) => item,
                        Err(mpsc::RecvError::Disconnected) => return Outcome::Ok(()),
                        Err(_) => return pipeline_cancelled(&worker_cx),
                    };
                    match sink(worker_cx.clone(), item.value).await {
                        Outcome::Ok(()) => {}
                        Outcome::Err(error) => {
                            return Outcome::Err(PipelineExecutionError::Stage {
                                stage: stages,
                                input: item.index,
                                error,
                            });
                        }
                        Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
                        Outcome::Panicked(payload) => return Outcome::Panicked(payload),
                    }
                    // The sink effect happened: acknowledge it even when
                    // cancellation is now pending, so drain commits its credit
                    // and counts it as consumed instead of aborting it. A
                    // checked send refuses at its first checkpoint once the
                    // pipeline is cancelled. The ack channel holds
                    // max_in_flight entries, at least the outstanding credits,
                    // and the sink is its only sender, so the non-blocking send
                    // fails only when the coordinator is gone.
                    match ack_sender.try_send(item.index) {
                        Ok(()) => {}
                        Err(mpsc::SendError::Full(index)) => {
                            if let Err(error) = ack_sender.send_checked(&worker_cx, index).await {
                                return pipeline_send_failure(
                                    &worker_cx,
                                    Some(stages),
                                    index,
                                    error,
                                );
                            }
                        }
                        Err(error) => {
                            return pipeline_send_failure(
                                &worker_cx,
                                Some(stages),
                                item.index,
                                mpsc::CheckedSendError::Channel(error),
                            );
                        }
                    }
                    quantum += 1;
                    if quantum == PIPELINE_QUANTUM {
                        quantum = 0;
                        crate::runtime::yield_now().await;
                    }
                }
            })
        }));
        let mut owner = PipelineOwner::new(cx.clone(), stages);
        let mut execution = Box::pin(crate::cx::scope::CatchUnwind {
            inner: async {
                for worker in workers {
                    if cx.checkpoint().is_err() {
                        owner.record(usize::MAX, pipeline_cancelled(&cx));
                        return;
                    }
                    let terminal = std::sync::Arc::new(std::sync::Mutex::new(None));
                    let worker_terminal = std::sync::Arc::clone(&terminal);
                    // Moved into the future at spawn so it fires on every
                    // terminal path, including cancellation before the
                    // first poll.
                    match super::TerminationTally::track_spawn(&owner.terminated, |tally| {
                        cx.spawn_in_cancellation_dominant(&scope, move |worker_cx| async move {
                            let _tally = tally;
                            let outcome = worker(worker_cx).await;
                            *worker_terminal
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(outcome);
                        })
                    }) {
                        Ok(handle) => owner.handles.push(Some(PipelineChild { handle, terminal })),
                        Err(error) => {
                            owner.record(
                                usize::MAX,
                                Outcome::Err(PipelineExecutionError::Spawn(error)),
                            );
                            return;
                        }
                    }
                    crate::runtime::yield_now().await;
                }
                pipeline_coordinate(
                    &cx,
                    inputs,
                    ingress,
                    config,
                    &mut acknowledgements,
                    &mut owner,
                )
                .await;
            },
        });
        let execution_result = execution.as_mut().await;
        // A panicking poll can leave captured iterator/value state in the
        // future. Destroy it under a separate catch before draining children;
        // directly consuming CatchUnwind with await would drop outside its
        // poll-only catch and skip asynchronous drain on a second panic.
        let destruction =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(execution)));
        if let Err(payload) = execution_result {
            owner.record(usize::MAX, Outcome::Panicked(pipeline_panic(payload)));
        }
        if let Err(payload) = destruction {
            owner.record(usize::MAX, Outcome::Panicked(pipeline_panic(payload)));
        }
        owner.drain(&mut acknowledgements).await;
        owner.finish()
    }
}

const PIPELINE_QUANTUM: usize = 32;

fn pipeline_cancelled<T, E>(cx: &Cx) -> Outcome<T, E> {
    Outcome::Cancelled(
        cx.cancel_reason()
            .unwrap_or_else(|| CancelReason::user("pipeline cancelled")),
    )
}

fn pipeline_panic(payload: Box<dyn std::any::Any + Send>) -> PanicPayload {
    let message = crate::cx::scope::payload_to_string(&payload);
    // Panic payload destructors are arbitrary code; never double-panic while
    // the owner is still responsible for draining its real children.
    std::mem::forget(payload);
    PanicPayload::new(message)
}

fn pipeline_send_failure<T, E>(
    cx: &Cx,
    stage: Option<usize>,
    input: usize,
    error: mpsc::CheckedSendError<T>,
) -> Outcome<(), PipelineExecutionError<E>> {
    match error {
        mpsc::CheckedSendError::Admission { error, .. } => {
            Outcome::Err(PipelineExecutionError::Admission {
                stage,
                input,
                error,
            })
        }
        mpsc::CheckedSendError::Channel(mpsc::SendError::Cancelled(_)) => pipeline_cancelled(cx),
        mpsc::CheckedSendError::Channel(_) => Outcome::Err(PipelineExecutionError::Disconnected),
    }
}

struct PipelineCredit {
    index: usize,
    token: Option<ObligationToken>,
}

impl PipelineCredit {
    fn abort(&mut self) {
        if let Some(token) = self.token.take() {
            token.abort(ObligationAbortReason::Cancel);
        }
    }
}

impl Drop for PipelineCredit {
    fn drop(&mut self) {
        if let Err(payload) =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.abort()))
        {
            if std::thread::panicking() {
                std::mem::forget(payload);
            } else {
                std::panic::resume_unwind(payload);
            }
        }
    }
}

struct PipelineOwner<E> {
    cx: Cx,
    handles: Vec<Option<PipelineChild<E>>>,
    credits: VecDeque<PipelineCredit>,
    failure: Option<(usize, Outcome<(), PipelineExecutionError<E>>)>,
    suppressed_error: Option<PipelineExecutionError<E>>,
    summary: PipelineExecutionSummary,
    cancel_registration: Option<crate::cx::CancelWakerToken>,
    next_scan: usize,
    scan_remaining: usize,
    ingress_closed: bool,
    acknowledgements_closed: bool,
    /// Worker terminations counted by the guard each worker future carries
    /// (see [`super::TerminationTally`]); compared against `joined_total` so a
    /// bounded child scan never parks on a termination it already passed.
    terminated: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    joined_total: usize,
}

struct PipelineChild<E> {
    handle: TaskHandle<()>,
    // Read only after the actual task joins. Cancellation-dominant task joins
    // must not erase a logical panic returned during asynchronous cleanup.
    terminal: std::sync::Arc<std::sync::Mutex<Option<Outcome<(), PipelineExecutionError<E>>>>>,
}

impl<E> PipelineOwner<E> {
    fn new(cx: Cx, stages: usize) -> Self {
        Self {
            cx,
            handles: Vec::new(),
            credits: VecDeque::new(),
            failure: None,
            suppressed_error: None,
            summary: PipelineExecutionSummary {
                admitted: 0,
                consumed: 0,
                max_in_flight: 0,
                stages,
            },
            cancel_registration: None,
            next_scan: 0,
            scan_remaining: 0,
            ingress_closed: false,
            acknowledgements_closed: false,
            terminated: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            joined_total: 0,
        }
    }

    fn record(&mut self, index: usize, outcome: Outcome<(), PipelineExecutionError<E>>) {
        if outcome.is_ok() {
            return;
        }
        if let Some((_, Outcome::Cancelled(existing))) = &mut self.failure {
            if let Outcome::Cancelled(reason) = &outcome {
                existing.strengthen(reason);
                return;
            }
        }
        if self.failure.as_ref().is_none_or(|(old_index, old)| {
            outcome.severity() > old.severity()
                || (outcome.severity() == old.severity()
                    && match (&outcome, old) {
                        (Outcome::Err(new), Outcome::Err(previous)) => {
                            // A worker dropping its receiver can make an upstream
                            // send fail before either worker is joined. Preserve
                            // the concrete failure regardless of join order.
                            let new_disconnected =
                                matches!(new, PipelineExecutionError::Disconnected);
                            let old_disconnected =
                                matches!(previous, PipelineExecutionError::Disconnected);
                            if new_disconnected == old_disconnected {
                                index < *old_index
                            } else {
                                old_disconnected
                            }
                        }
                        _ => index < *old_index,
                    })
        }) {
            if let Some((_, old)) = self.failure.replace((index, outcome)) {
                self.retain_suppressed(old, true);
            }
        } else {
            self.retain_suppressed(outcome, false);
        }
    }

    fn retain_suppressed(
        &mut self,
        outcome: Outcome<(), PipelineExecutionError<E>>,
        was_current: bool,
    ) {
        let outcome = match outcome {
            // A disconnection is only ever the consequence of another party's
            // exit, never the initiating failure. Whether a sibling observes
            // it before its own cancellation depends on scheduling, so
            // retaining it made `error()` report `Disconnected` beside a
            // panic or cancellation on some runs and nothing on others.
            Outcome::Err(error)
                if !matches!(&error, PipelineExecutionError::Disconnected)
                    && self.suppressed_error.is_none()
                    && (was_current
                        || self.failure.as_ref().is_some_and(|(_, current)| {
                            current.severity() > crate::types::outcome::Severity::Err
                        })) =>
            {
                self.suppressed_error = Some(error);
                return;
            }
            other => other,
        };
        // Domain-error destructors are user code too. A discarded result must
        // not prevent the owner from joining its other admitted workers.
        if let Err(payload) =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(outcome)))
        {
            self.record(usize::MAX, Outcome::Panicked(pipeline_panic(payload)));
        }
    }

    fn joined(&mut self, index: usize, result: Result<(), JoinError>) {
        self.joined_total = self.joined_total.saturating_add(1);
        let child = self.handles[index].take().expect("joined an owned child");
        let logical = child
            .terminal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(outcome) = logical {
            self.record(index, outcome);
        } else if result.is_ok() {
            self.record(
                index,
                Outcome::Panicked(PanicPayload::new(
                    "pipeline worker completed without its terminal outcome",
                )),
            );
        }
        let outcome = match result {
            Ok(()) => Outcome::Ok(()),
            Err(JoinError::Cancelled(reason)) => Outcome::Cancelled(reason),
            Err(JoinError::Panicked(payload)) => Outcome::Panicked(payload),
            Err(JoinError::PolledAfterCompletion) => {
                Outcome::Panicked(PanicPayload::new("pipeline joined a worker twice"))
            }
        };
        self.record(index, outcome);
    }

    fn poll_children(&mut self, cx: &mut Context<'_>) -> bool {
        self.cancel_registration = Some(
            self.cx
                .refresh_cancel_waker(self.cancel_registration, cx.waker()),
        );
        if self.cx.checkpoint().is_err() {
            self.record(usize::MAX, pipeline_cancelled(&self.cx));
        }
        if self.handles.is_empty() {
            return false;
        }
        if self.scan_remaining == 0 {
            self.scan_remaining = self.handles.len();
        }
        let mut progress = false;
        for _ in 0..PIPELINE_QUANTUM.min(self.scan_remaining) {
            let index = self.next_scan % self.handles.len();
            self.next_scan = (index + 1) % self.handles.len();
            self.scan_remaining -= 1;
            if let Some(child) = &mut self.handles[index] {
                if let Poll::Ready(result) = child.handle.poll_join(cx) {
                    self.joined(index, result);
                    progress = true;
                }
            }
        }
        // Finish each bounded scan before sleeping. Once all handles have
        // registered this waker, an entirely Pending set does not self-wake,
        // except when a worker terminated at an index this scan already
        // passed: that wake was coalesced with the scan's own, so rescan.
        let unobserved_terminations =
            self.terminated.load(std::sync::atomic::Ordering::Acquire) > self.joined_total;
        if self.scan_remaining != 0 || unobserved_terminations {
            cx.waker().wake_by_ref();
        }
        progress
    }

    fn acknowledge(&mut self, index: usize) {
        let expected = self.credits.front().map(|credit| credit.index);
        if expected != Some(index) {
            self.record(
                usize::MAX,
                Outcome::Err(PipelineExecutionError::Acknowledgement {
                    expected,
                    actual: index,
                }),
            );
            return;
        }
        let mut credit = self.credits.pop_front().expect("front was checked");
        self.summary.consumed += 1;
        if let Some(token) = credit.token.take() {
            if !token.commit() {
                self.record(
                    usize::MAX,
                    Outcome::Err(PipelineExecutionError::Disconnected),
                );
            }
        }
    }

    async fn pump<F: Future>(
        &mut self,
        acknowledgements: &mut mpsc::Receiver<usize>,
        mut operation: Pin<&mut F>,
    ) -> Result<Option<F::Output>, ()> {
        std::future::poll_fn(|cx| {
            let mut progress = self.poll_children(cx);
            if self.failure.is_some() {
                return Poll::Ready(Err(()));
            }
            if !self.acknowledgements_closed {
                for _ in 0..PIPELINE_QUANTUM {
                    match acknowledgements.poll_recv(&self.cx, cx) {
                        Poll::Ready(Ok(index)) => {
                            self.acknowledge(index);
                            progress = true;
                        }
                        Poll::Ready(Err(mpsc::RecvError::Disconnected)) => {
                            self.acknowledgements_closed = true;
                            progress = true;
                            if !self.ingress_closed || !self.credits.is_empty() {
                                self.record(
                                    usize::MAX,
                                    Outcome::Err(PipelineExecutionError::Disconnected),
                                );
                            }
                            break;
                        }
                        Poll::Ready(Err(_)) => {
                            self.record(usize::MAX, pipeline_cancelled(&self.cx));
                            break;
                        }
                        Poll::Pending => break,
                    }
                }
            }
            if self.failure.is_some() {
                return Poll::Ready(Err(()));
            }
            match operation.as_mut().poll(cx) {
                Poll::Ready(output) => Poll::Ready(Ok(Some(output))),
                Poll::Pending if progress => Poll::Ready(Ok(None)),
                Poll::Pending => Poll::Pending,
            }
        })
        .await
    }

    async fn drain(&mut self, acknowledgements: &mut mpsc::Receiver<usize>) {
        if self.failure.is_some() {
            let reason = self
                .cx
                .cancel_reason()
                .unwrap_or_else(CancelReason::sibling_failed);
            for index in 0..self.handles.len() {
                if let Some(child) = &self.handles[index] {
                    if let Err(payload) =
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            child.handle.abort_with_reason(reason.clone())
                        }))
                    {
                        self.record(index, Outcome::Panicked(pipeline_panic(payload)));
                    }
                }
                if index % PIPELINE_QUANTUM == PIPELINE_QUANTUM - 1 {
                    crate::runtime::yield_now().await;
                }
            }
        }
        for index in 0..self.handles.len() {
            while let Some(child) = &mut self.handles[index] {
                let result = crate::cx::scope::CatchUnwind {
                    inner: std::future::poll_fn(|cx| child.handle.poll_join(cx)),
                }
                .await;
                match result {
                    Ok(joined) => {
                        self.joined(index, joined);
                    }
                    Err(payload) => self.record(index, Outcome::Panicked(pipeline_panic(payload))),
                }
            }
            if index % PIPELINE_QUANTUM == PIPELINE_QUANTUM - 1 {
                crate::runtime::yield_now().await;
            }
        }
        // All producers have joined. Even if cancellation won the severity
        // join, the finite queued ACK prefix still describes completed sink
        // effects. Commit those exact IDs before aborting the unresolved tail.
        let mut acknowledged = 0;
        loop {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                match acknowledgements.try_recv() {
                    Ok(index) => {
                        self.acknowledge(index);
                        true
                    }
                    Err(mpsc::RecvError::Disconnected) => {
                        self.acknowledgements_closed = true;
                        false
                    }
                    Err(mpsc::RecvError::Empty) => false,
                    Err(mpsc::RecvError::Cancelled) => {
                        self.record(
                            usize::MAX,
                            Outcome::Err(PipelineExecutionError::Disconnected),
                        );
                        false
                    }
                }
            }));
            match result {
                Ok(false) => break,
                Ok(true) => {}
                Err(payload) => self.record(usize::MAX, Outcome::Panicked(pipeline_panic(payload))),
            }
            acknowledged += 1;
            if acknowledged == PIPELINE_QUANTUM {
                acknowledged = 0;
                crate::runtime::yield_now().await;
            }
        }
        let mut released = 0;
        while let Some(mut credit) = self.credits.pop_front() {
            if let Err(payload) =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| credit.abort()))
            {
                self.record(usize::MAX, Outcome::Panicked(pipeline_panic(payload)));
            }
            released += 1;
            if released == PIPELINE_QUANTUM {
                released = 0;
                crate::runtime::yield_now().await;
            }
        }
        if let Some(token) = self.cancel_registration.take() {
            if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.cx.clear_cancel_waker(token)
            })) {
                self.record(usize::MAX, Outcome::Panicked(pipeline_panic(payload)));
            }
        }
    }

    fn finish(mut self) -> PipelineExecutionReport<E> {
        // The owned execution future and every worker have now retired their
        // iterator/transform/sink captures. Their destructors can request caller
        // cancellation after the last input or ACK poll, so include that request
        // in the same severity join before publishing the terminal report.
        if self.cx.checkpoint().is_err() {
            self.record(usize::MAX, pipeline_cancelled(&self.cx));
        }
        let outcome = match self.failure.take().map(|(_, outcome)| outcome) {
            None | Some(Outcome::Ok(())) => Outcome::Ok(self.summary),
            Some(Outcome::Err(error)) => Outcome::Err(error),
            Some(Outcome::Cancelled(reason)) => Outcome::Cancelled(reason),
            Some(Outcome::Panicked(payload)) => Outcome::Panicked(payload),
        };
        PipelineExecutionReport {
            outcome,
            summary: self.summary,
            suppressed_error: self.suppressed_error.take(),
        }
    }
}

impl<E> Drop for PipelineOwner<E> {
    fn drop(&mut self) {
        let mut panic = None;
        let mut capture = |result: std::thread::Result<()>| {
            if let Err(payload) = result {
                if panic.is_none() && !std::thread::panicking() {
                    panic = Some(payload);
                } else {
                    std::mem::forget(payload);
                }
            }
        };
        for handle in &mut self.handles {
            if let Some(handle) = handle.take() {
                capture(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                    || handle.handle.abort(),
                )));
                capture(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                    || drop(handle),
                )));
            }
        }
        while let Some(mut credit) = self.credits.pop_front() {
            capture(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                || credit.abort(),
            )));
        }
        if let Some(token) = self.cancel_registration.take() {
            capture(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                || self.cx.clear_cancel_waker(token),
            )));
        }
        capture(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || drop(self.failure.take()),
        )));
        capture(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || drop(self.suppressed_error.take()),
        )));
        if let Some(payload) = panic {
            std::panic::resume_unwind(payload);
        }
    }
}

async fn pipeline_coordinate<I, E>(
    cx: &Cx,
    inputs: I,
    ingress: mpsc::Sender<PipelineItem<I::Item>>,
    config: PipelineExecutionConfig,
    acknowledgements: &mut mpsc::Receiver<usize>,
    owner: &mut PipelineOwner<E>,
) where
    I: IntoIterator,
{
    let mut inputs = inputs.into_iter();
    let mut ingress = Some(ingress);
    let mut quantum = 0;
    loop {
        if owner.failure.is_some() {
            break;
        }
        if owner.ingress_closed
            && owner.credits.is_empty()
            && owner.handles.iter().all(Option::is_none)
        {
            break;
        }
        if !owner.ingress_closed && owner.credits.len() < config.max_in_flight.get() {
            if cx.checkpoint().is_err() {
                owner.record(usize::MAX, pipeline_cancelled(cx));
                break;
            }
            // The RAII credit exists before pulling the next input, including
            // while next() or a checked channel reservation is in progress.
            let index = owner.summary.admitted;
            let token =
                match cx.try_register_obligation_checked(ObligationKind::Lease, cx.task_id()) {
                    Ok(Some(token)) => token,
                    Ok(None) => {
                        owner.record(
                            usize::MAX,
                            Outcome::Err(PipelineExecutionError::Admission {
                                stage: None,
                                input: index,
                                error: ObligationAdmissionError::RuntimeUnavailable,
                            }),
                        );
                        break;
                    }
                    Err(error) => {
                        owner.record(
                            usize::MAX,
                            Outcome::Err(PipelineExecutionError::Admission {
                                stage: None,
                                input: index,
                                error,
                            }),
                        );
                        break;
                    }
                };
            let mut credit = PipelineCredit {
                index,
                token: Some(token),
            };
            let Some(value) = inputs.next() else {
                credit.abort();
                owner.ingress_closed = true;
                drop(ingress.take());
                continue;
            };
            let Some(next_index) = index.checked_add(1) else {
                owner.record(
                    usize::MAX,
                    Outcome::Err(PipelineExecutionError::InputIndexExhausted),
                );
                break;
            };
            owner.credits.push_back(credit);
            owner.summary.admitted = next_index;
            owner.summary.max_in_flight = owner.summary.max_in_flight.max(owner.credits.len());
            let sender = ingress.as_ref().expect("open ingress");
            let mut reservation = std::pin::pin!(sender.reserve_checked(cx));
            let permit = loop {
                match owner.pump(acknowledgements, reservation.as_mut()).await {
                    Ok(Some(Ok(permit))) => break Some(permit),
                    Ok(Some(Err(error))) => {
                        owner.record(usize::MAX, pipeline_send_failure(cx, None, index, error));
                        break None;
                    }
                    Ok(None) => crate::runtime::yield_now().await,
                    Err(()) => break None,
                }
            };
            let Some(permit) = permit else {
                break;
            };
            if let Err(error) = permit.try_send(PipelineItem { index, value }) {
                owner.record(
                    usize::MAX,
                    pipeline_send_failure(cx, None, index, mpsc::CheckedSendError::Channel(error)),
                );
                break;
            }
        } else {
            let mut waiting = std::pin::pin!(std::future::pending::<()>());
            if owner
                .pump(acknowledgements, waiting.as_mut())
                .await
                .is_err()
            {
                break;
            }
        }
        quantum += 1;
        if quantum == PIPELINE_QUANTUM {
            quantum = 0;
            crate::runtime::yield_now().await;
        }
    }
}

/// Configuration for a pipeline operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PipelineConfig {
    /// Whether to check cancellation between stages.
    pub check_cancellation: bool,
    /// Whether to continue after recoverable errors (vs short-circuit).
    /// Default is false (short-circuit on first error).
    pub continue_on_error: bool,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl PipelineConfig {
    /// Creates a new pipeline configuration with default settings.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            check_cancellation: true,
            continue_on_error: false,
        }
    }

    /// Creates a configuration that checks cancellation between stages.
    #[must_use]
    pub const fn with_cancellation_check() -> Self {
        Self {
            check_cancellation: true,
            continue_on_error: false,
        }
    }

    /// Creates a configuration that skips cancellation checks (for tight loops).
    #[must_use]
    pub const fn without_cancellation_check() -> Self {
        Self {
            check_cancellation: false,
            continue_on_error: false,
        }
    }
}

/// A pipeline combinator marker type.
///
/// This is a builder/marker type; actual execution happens via the runtime.
#[derive(Debug)]
pub struct Pipeline<T> {
    /// Pipeline configuration.
    pub config: PipelineConfig,
    _t: PhantomData<T>,
}

impl<T> Pipeline<T> {
    /// Creates a new pipeline with default configuration.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            config: PipelineConfig::new(),
            _t: PhantomData,
        }
    }

    /// Creates a pipeline with the given configuration.
    #[must_use]
    pub const fn with_config(config: PipelineConfig) -> Self {
        Self {
            config,
            _t: PhantomData,
        }
    }
}

impl<T> Clone for Pipeline<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for Pipeline<T> {}

impl<T> Default for Pipeline<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// Which stage failed in a pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailedStage {
    /// Zero-based index of the failed stage.
    pub index: usize,
    /// Total number of stages in the pipeline.
    pub total_stages: usize,
}

impl FailedStage {
    /// Creates a new failed stage indicator.
    #[must_use]
    pub const fn new(index: usize, total_stages: usize) -> Self {
        Self {
            index,
            total_stages,
        }
    }

    /// Returns true if this is the first stage (index 0).
    #[must_use]
    pub const fn is_first(&self) -> bool {
        self.index == 0
    }

    /// Returns true if this is the last stage.
    #[must_use]
    pub const fn is_last(&self) -> bool {
        self.index + 1 == self.total_stages
    }

    /// Returns the stage number (1-based for display).
    #[must_use]
    pub const fn stage_number(&self) -> usize {
        self.index + 1
    }
}

impl fmt::Display for FailedStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "stage {}/{}", self.stage_number(), self.total_stages)
    }
}

/// The result of a pipeline operation.
#[derive(Debug, Clone)]
pub enum PipelineResult<T, E> {
    /// Pipeline completed successfully.
    Completed {
        /// The final output value.
        value: T,
        /// Number of stages executed.
        stages_completed: usize,
    },
    /// Pipeline failed at a specific stage with an error.
    Failed {
        /// The error from the failed stage.
        error: E,
        /// Which stage failed.
        failed_at: FailedStage,
    },
    /// Pipeline was cancelled at a stage boundary.
    Cancelled {
        /// The cancellation reason.
        reason: CancelReason,
        /// Which stage was about to run (or was running).
        cancelled_at: FailedStage,
    },
    /// A stage panicked.
    Panicked {
        /// The panic payload.
        payload: PanicPayload,
        /// Which stage panicked.
        panicked_at: FailedStage,
    },
}

impl<T, E> PipelineResult<T, E> {
    /// Creates a completed result.
    #[must_use]
    pub const fn completed(value: T, stages_completed: usize) -> Self {
        Self::Completed {
            value,
            stages_completed,
        }
    }

    /// Creates a failed result.
    #[must_use]
    pub const fn failed(error: E, failed_at: FailedStage) -> Self {
        Self::Failed { error, failed_at }
    }

    /// Creates a cancelled result.
    #[must_use]
    pub const fn cancelled(reason: CancelReason, cancelled_at: FailedStage) -> Self {
        Self::Cancelled {
            reason,
            cancelled_at,
        }
    }

    /// Creates a panicked result.
    #[must_use]
    pub const fn panicked(payload: PanicPayload, panicked_at: FailedStage) -> Self {
        Self::Panicked {
            payload,
            panicked_at,
        }
    }

    /// Returns true if the pipeline completed successfully.
    #[must_use]
    pub const fn is_completed(&self) -> bool {
        matches!(self, Self::Completed { .. })
    }

    /// Returns true if the pipeline failed with an error.
    #[must_use]
    pub const fn is_failed(&self) -> bool {
        matches!(self, Self::Failed { .. })
    }

    /// Returns true if the pipeline was cancelled.
    #[must_use]
    pub const fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancelled { .. })
    }

    /// Returns true if a stage panicked.
    #[must_use]
    pub const fn is_panicked(&self) -> bool {
        matches!(self, Self::Panicked { .. })
    }

    /// Converts to an Outcome.
    pub fn into_outcome(self) -> Outcome<T, E> {
        match self {
            Self::Completed { value, .. } => Outcome::Ok(value),
            Self::Failed { error, .. } => Outcome::Err(error),
            Self::Cancelled { reason, .. } => Outcome::Cancelled(reason),
            Self::Panicked { payload, .. } => Outcome::Panicked(payload),
        }
    }

    /// Returns the number of stages that were executed (successfully or not).
    #[must_use]
    pub const fn stages_executed(&self) -> usize {
        match self {
            Self::Completed {
                stages_completed, ..
            } => *stages_completed,
            Self::Failed { failed_at, .. } => failed_at.index + 1,
            Self::Cancelled { cancelled_at, .. } => cancelled_at.index,
            Self::Panicked { panicked_at, .. } => panicked_at.index + 1,
        }
    }
}

/// Error type for pipeline operations.
#[derive(Debug, Clone)]
pub enum PipelineError<E> {
    /// A stage failed with an error.
    StageError {
        /// The error from the stage.
        error: E,
        /// Which stage failed.
        stage: FailedStage,
    },
    /// The pipeline was cancelled.
    Cancelled {
        /// The cancellation reason.
        reason: CancelReason,
        /// Which stage was cancelled at.
        stage: FailedStage,
    },
    /// A stage panicked.
    Panicked {
        /// The panic payload.
        payload: PanicPayload,
        /// Which stage panicked.
        stage: FailedStage,
    },
}

impl<E: fmt::Display> fmt::Display for PipelineError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StageError { error, stage } => {
                write!(f, "pipeline failed at {stage}: {error}")
            }
            Self::Cancelled { reason, stage } => {
                write!(f, "pipeline cancelled at {stage}: {reason}")
            }
            Self::Panicked { payload, stage } => {
                write!(f, "pipeline panicked at {stage}: {payload}")
            }
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for PipelineError<E> {}

/// Constructs a pipeline result from the outcome of a specific stage.
///
/// # Arguments
/// * `outcome` - The outcome from the stage
/// * `stage_index` - Zero-based index of the current stage
/// * `total_stages` - Total number of stages in the pipeline
///
/// # Example
/// ```
/// use asupersync::combinator::pipeline::stage_outcome_to_result;
/// use asupersync::types::Outcome;
///
/// // Stage 0 succeeded in a 3-stage pipeline
/// let result = stage_outcome_to_result::<i32, &str>(
///     Outcome::Ok(42),
///     0,
///     3,
/// );
/// // This returns None because the stage succeeded - continue to next stage
/// assert!(result.is_none());
///
/// // Stage 1 failed in a 3-stage pipeline
/// let result = stage_outcome_to_result::<i32, &str>(
///     Outcome::Err("failed"),
///     1,
///     3,
/// );
/// // This returns Some because the stage failed - pipeline should stop
/// assert!(result.is_some());
/// assert!(result.unwrap().is_failed());
/// ```
#[must_use]
pub fn stage_outcome_to_result<T, E>(
    outcome: Outcome<T, E>,
    stage_index: usize,
    total_stages: usize,
) -> Option<PipelineResult<T, E>> {
    let stage = FailedStage::new(stage_index, total_stages);

    match outcome {
        Outcome::Ok(_) => None, // Success - continue to next stage
        Outcome::Err(e) => Some(PipelineResult::failed(e, stage)),
        Outcome::Cancelled(r) => Some(PipelineResult::cancelled(r, stage)),
        Outcome::Panicked(p) => Some(PipelineResult::panicked(p, stage)),
    }
}

/// Creates a pipeline result for a 2-stage pipeline.
///
/// # Arguments
/// * `o1` - Outcome from stage 1
/// * `o2` - Outcome from stage 2 (only evaluated if o1 succeeded)
///
/// # Example
/// ```
/// use asupersync::combinator::pipeline::pipeline2_outcomes;
/// use asupersync::types::Outcome;
///
/// // Both stages succeed
/// let result = pipeline2_outcomes::<i32, &str>(
///     Outcome::Ok(1),
///     Some(Outcome::Ok(2)),
/// );
/// assert!(result.is_completed());
///
/// // First stage fails (second not evaluated)
/// let result = pipeline2_outcomes::<i32, &str>(
///     Outcome::Err("stage1 failed"),
///     None,
/// );
/// assert!(result.is_failed());
/// ```
#[must_use]
pub fn pipeline2_outcomes<T, E>(
    o1: Outcome<T, E>,
    o2: Option<Outcome<T, E>>,
) -> PipelineResult<T, E> {
    const TOTAL_STAGES: usize = 2;

    // Check first stage
    if let Some(result) = stage_outcome_to_result(o1, 0, TOTAL_STAGES) {
        return result;
    }

    // First stage succeeded, check second
    match o2 {
        Some(Outcome::Ok(v)) => PipelineResult::completed(v, TOTAL_STAGES),
        Some(outcome) => {
            // Second stage failed - convert to result
            stage_outcome_to_result(outcome, 1, TOTAL_STAGES)
                .expect("non-Ok should return Some result")
        }
        None => PipelineResult::panicked(
            PanicPayload::new("o2 must be provided when o1 succeeds"),
            FailedStage::new(1, TOTAL_STAGES),
        ),
    }
}

/// Creates a pipeline result for a 3-stage pipeline.
///
/// # Arguments
/// * `o1` - Outcome from stage 1
/// * `o2` - Outcome from stage 2 (only evaluated if o1 succeeded)
/// * `o3` - Outcome from stage 3 (only evaluated if o1 and o2 succeeded)
///
/// # Example
/// ```
/// use asupersync::combinator::pipeline::pipeline3_outcomes;
/// use asupersync::types::Outcome;
///
/// // All stages succeed
/// let result = pipeline3_outcomes::<i32, &str>(
///     Outcome::Ok(1),
///     Some(Outcome::Ok(2)),
///     Some(Outcome::Ok(3)),
/// );
/// assert!(result.is_completed());
///
/// // Second stage fails
/// let result = pipeline3_outcomes::<i32, &str>(
///     Outcome::Ok(1),
///     Some(Outcome::Err("stage2 failed")),
///     None,
/// );
/// assert!(result.is_failed());
/// ```
#[must_use]
pub fn pipeline3_outcomes<T, E>(
    o1: Outcome<T, E>,
    o2: Option<Outcome<T, E>>,
    o3: Option<Outcome<T, E>>,
) -> PipelineResult<T, E> {
    const TOTAL_STAGES: usize = 3;

    // Check first stage
    if let Some(result) = stage_outcome_to_result(o1, 0, TOTAL_STAGES) {
        return result;
    }

    // Check second stage
    match o2 {
        Some(outcome) => {
            if let Some(result) = stage_outcome_to_result(outcome, 1, TOTAL_STAGES) {
                return result;
            }
        }
        None => {
            return PipelineResult::panicked(
                PanicPayload::new("o2 must be provided when o1 succeeds"),
                FailedStage::new(1, TOTAL_STAGES),
            );
        }
    }

    // Check third stage
    match o3 {
        Some(Outcome::Ok(v)) => PipelineResult::completed(v, TOTAL_STAGES),
        Some(outcome) => {
            // Third stage failed - convert to result
            stage_outcome_to_result(outcome, 2, TOTAL_STAGES)
                .expect("non-Ok should return Some result")
        }
        None => PipelineResult::panicked(
            PanicPayload::new("o3 must be provided when o1 and o2 succeed"),
            FailedStage::new(2, TOTAL_STAGES),
        ),
    }
}

/// Creates a pipeline result from a vector of outcomes.
///
/// # Arguments
/// * `outcomes` - Vector of outcomes from each stage (only includes stages that were executed)
///
/// A short vector is valid only when its final outcome explains why later
/// stages did not execute (error, cancellation, or panic). If every provided
/// outcome is successful, omitting later outcomes violates this constructor's
/// input contract and panics rather than returning a partial result.
///
/// # Example
/// ```
/// use asupersync::combinator::pipeline::pipeline_n_outcomes;
/// use asupersync::types::Outcome;
///
/// // All 4 stages succeed
/// let outcomes: Vec<Outcome<i32, &str>> = vec![
///     Outcome::Ok(1),
///     Outcome::Ok(2),
///     Outcome::Ok(3),
///     Outcome::Ok(4),
/// ];
/// let result = pipeline_n_outcomes(outcomes, 4);
/// assert!(result.is_completed());
///
/// // Third stage fails
/// let outcomes: Vec<Outcome<i32, &str>> = vec![
///     Outcome::Ok(1),
///     Outcome::Ok(2),
///     Outcome::Err("stage3 failed"),
/// ];
/// let result = pipeline_n_outcomes(outcomes, 5);
/// assert!(result.is_failed());
/// ```
#[must_use]
pub fn pipeline_n_outcomes<T, E>(
    outcomes: Vec<Outcome<T, E>>,
    total_stages: usize,
) -> PipelineResult<T, E> {
    assert!(!outcomes.is_empty(), "outcomes must not be empty");
    assert!(outcomes.len() <= total_stages, "more outcomes than stages");

    let num_provided = outcomes.len();
    let mut last_ok_value: Option<T> = None;

    for (index, outcome) in outcomes.into_iter().enumerate() {
        match outcome {
            Outcome::Ok(v) => {
                // Track the last Ok value
                last_ok_value = Some(v);
            }
            Outcome::Err(e) => {
                return PipelineResult::failed(e, FailedStage::new(index, total_stages));
            }
            Outcome::Cancelled(r) => {
                return PipelineResult::cancelled(r, FailedStage::new(index, total_stages));
            }
            Outcome::Panicked(p) => {
                return PipelineResult::panicked(p, FailedStage::new(index, total_stages));
            }
        }
    }

    // All provided outcomes were Ok. A short vector cannot represent a
    // finished pipeline because the next stage has no outcome.
    assert_eq!(
        num_provided, total_stages,
        "all successful outcomes must cover every pipeline stage"
    );

    PipelineResult::completed(
        last_ok_value.expect("at least one outcome was provided"),
        total_stages,
    )
}

/// Creates a pipeline result from a vector of outcomes, with the final value provided separately.
///
/// This is the preferred function when the final value needs to be preserved.
///
/// # Arguments
/// * `intermediate_outcomes` - Outcomes from stages 0..N-1 (should all be Ok, or first failure)
/// * `final_outcome` - Outcome from the final stage (only checked if all intermediates succeeded)
/// * `total_stages` - Total number of stages
///
/// # Example
/// ```
/// use asupersync::combinator::pipeline::pipeline_with_final;
/// use asupersync::types::Outcome;
///
/// // All stages succeed
/// let intermediates: Vec<Outcome<i32, &str>> = vec![
///     Outcome::Ok(1),
///     Outcome::Ok(2),
/// ];
/// let result = pipeline_with_final(intermediates, Outcome::Ok(42), 3);
/// assert!(result.is_completed());
/// ```
#[must_use]
pub fn pipeline_with_final<T, E>(
    intermediate_outcomes: Vec<Outcome<T, E>>,
    final_outcome: Outcome<T, E>,
    total_stages: usize,
) -> PipelineResult<T, E> {
    assert!(total_stages > 0, "total_stages must be positive");
    assert!(
        intermediate_outcomes.len() + 1 == total_stages,
        "intermediate_outcomes.len() ({}) + 1 must equal total_stages ({})",
        intermediate_outcomes.len(),
        total_stages
    );

    // Check intermediate stages
    for (index, outcome) in intermediate_outcomes.into_iter().enumerate() {
        if let Some(result) = stage_outcome_to_result(outcome, index, total_stages) {
            return result;
        }
    }

    // Check final stage
    let final_index = total_stages - 1;
    match final_outcome {
        Outcome::Ok(v) => PipelineResult::completed(v, total_stages),
        Outcome::Err(e) => PipelineResult::failed(e, FailedStage::new(final_index, total_stages)),
        Outcome::Cancelled(r) => {
            PipelineResult::cancelled(r, FailedStage::new(final_index, total_stages))
        }
        Outcome::Panicked(p) => {
            PipelineResult::panicked(p, FailedStage::new(final_index, total_stages))
        }
    }
}

/// Converts a pipeline result to a standard Result for fail-fast handling.
///
/// If the pipeline completed, returns `Ok` with the final value.
/// If the pipeline failed, returns `Err` with the appropriate error.
///
/// # Example
/// ```
/// use asupersync::combinator::pipeline::{pipeline_to_result, PipelineResult, FailedStage};
/// use asupersync::types::Outcome;
///
/// // Completed pipeline
/// let result: PipelineResult<i32, &str> = PipelineResult::completed(42, 3);
/// assert_eq!(pipeline_to_result(result).unwrap(), 42);
///
/// // Failed pipeline
/// let result: PipelineResult<i32, &str> = PipelineResult::failed(
///     "error",
///     FailedStage::new(1, 3),
/// );
/// assert!(pipeline_to_result(result).is_err());
/// ```
pub fn pipeline_to_result<T, E>(result: PipelineResult<T, E>) -> Result<T, PipelineError<E>> {
    match result {
        PipelineResult::Completed { value, .. } => Ok(value),
        PipelineResult::Failed { error, failed_at } => Err(PipelineError::StageError {
            error,
            stage: failed_at,
        }),
        PipelineResult::Cancelled {
            reason,
            cancelled_at,
        } => Err(PipelineError::Cancelled {
            reason,
            stage: cancelled_at,
        }),
        PipelineResult::Panicked {
            payload,
            panicked_at,
        } => Err(PipelineError::Panicked {
            payload,
            stage: panicked_at,
        }),
    }
}

/// Macro for creating a sequential async pipeline.
///
/// Each stage is invoked as `stage(cx, value)` and must return a future whose
/// output becomes the next stage input.
///
/// The macro does not check cancellation between stages: every stage takes
/// and returns the same value type, which has no cancelled form. Stages that
/// should stop when the task is cancelled check `cx` themselves (the
/// cancellation rules in the module docs describe `PipelineResult`).
///
/// # Example (API shape)
/// ```ignore
/// let result = pipeline!(cx, input,
///     |cx, x| stage1(cx, x),
///     |cx, x| stage2(cx, x),
///     |cx, x| stage3(cx, x),
/// );
/// ```
#[macro_export]
macro_rules! pipeline {
    ($cx:expr, $input:expr, $($stage:expr),+ $(,)?) => {
        {
            let __pipeline_cx = &$cx;
            async move {
                let mut __pipeline_value = $input;
                $(
                    __pipeline_value = ($stage)(__pipeline_cx, __pipeline_value).await;
                )+
                __pipeline_value
            }
        }
    };
}

#[cfg(test)]
#[path = "pipeline_inline_tests.rs"]
mod tests;
