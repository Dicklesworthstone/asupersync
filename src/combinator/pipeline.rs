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
                    if let Err(error) = ack_sender.send_checked(&worker_cx, item.index).await {
                        return pipeline_send_failure(&worker_cx, Some(stages), item.index, error);
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
                    match cx.spawn_in_cancellation_dominant(&scope, move |worker_cx| async move {
                        let outcome = worker(worker_cx).await;
                        *worker_terminal
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(outcome);
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
                || (outcome.severity() == old.severity() && index < *old_index)
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
            Outcome::Err(error)
                if self.suppressed_error.is_none()
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
        // registered this waker, an entirely Pending set does not self-wake.
        if self.scan_remaining != 0 {
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
                return;
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
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    use crate::lab::{LabConfig, LabRuntime};
    use crate::record::{ObligationState, RegionLimits};
    use crate::types::{Budget, RegionId};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::Waker;

    #[derive(Default)]
    struct ExecutionGate {
        open: AtomicBool,
        waiter: Mutex<Option<Waker>>,
    }

    impl ExecutionGate {
        fn poll(&self, cx: &mut Context<'_>) -> Poll<()> {
            if self.open.load(Ordering::SeqCst) {
                return Poll::Ready(());
            }
            *self.waiter.lock().unwrap() = Some(cx.waker().clone());
            if self.open.load(Ordering::SeqCst) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }

        async fn wait(&self) {
            std::future::poll_fn(|cx| self.poll(cx)).await;
        }

        fn release(&self) {
            self.open.store(true, Ordering::SeqCst);
            let wake = self.waiter.lock().unwrap().take();
            if let Some(waker) = wake {
                waker.wake();
            }
        }

        fn is_parked(&self) -> bool {
            self.waiter.lock().unwrap().is_some()
        }
    }

    struct ExecutionInputs {
        end: u32,
        pulled: Arc<AtomicUsize>,
        panic_factory: bool,
        panic_next: Option<u32>,
    }

    struct ExecutionIter {
        next: u32,
        inputs: ExecutionInputs,
    }

    impl IntoIterator for ExecutionInputs {
        type Item = u32;
        type IntoIter = ExecutionIter;

        fn into_iter(self) -> Self::IntoIter {
            assert!(!self.panic_factory, "executing iterator factory panic");
            ExecutionIter {
                next: 0,
                inputs: self,
            }
        }
    }

    impl Iterator for ExecutionIter {
        type Item = u32;

        fn next(&mut self) -> Option<Self::Item> {
            assert_ne!(
                self.inputs.panic_next,
                Some(self.next),
                "executing iterator next panic"
            );
            if self.next == self.inputs.end {
                return None;
            }
            let value = self.next;
            self.next += 1;
            self.inputs.pulled.fetch_add(1, Ordering::SeqCst);
            Some(value)
        }
    }

    fn execution_config(window: usize) -> PipelineExecutionConfig {
        PipelineExecutionConfig::new(
            NonZeroUsize::new(1).unwrap(),
            NonZeroUsize::new(window).unwrap(),
        )
    }

    fn execution_lab(seed: u64) -> LabRuntime {
        LabRuntime::new(
            LabConfig::new(seed)
                .max_steps(100_000)
                .trace_capacity(200_000),
        )
    }

    fn execution_cleanup(lab: &mut LabRuntime, region: RegionId) {
        assert_eq!(
            lab.state.tasks_iter().count(),
            0,
            "every actual child joined"
        );
        assert_eq!(lab.state.pending_obligation_count(), 0);
        assert_eq!(lab.state.leak_count(), 0);
        let gateway = lab.state.obligation_gateway().unwrap();
        let mailbox = gateway.mailbox();
        let stats = mailbox.stats();
        assert_eq!(stats.posted, stats.applied, "no unapplied lifecycle suffix");
        assert_eq!(stats.reserved, stats.committed + stats.aborted);
        assert_eq!(mailbox.open_tickets(), 0);
        assert!(mailbox.is_empty());
        for (_, obligation) in lab.state.obligations.iter() {
            assert!(matches!(
                obligation.state,
                ObligationState::Committed | ObligationState::Aborted
            ));
        }
        let record = lab.state.region(region).unwrap();
        assert_eq!(record.pending_obligations(), 0);
        assert_eq!(record.unapplied_obligation_count(), 0);
        lab.state.close_region_command(
            region,
            &CancelReason::user("executing pipeline test complete"),
        );
        assert!(lab.state.region(region).is_none());
        let report = lab.run_until_quiescent_with_report();
        assert!(report.lab_test_passed(), "{report:?}");
        assert!(!report.refinement_firewall_skipped_due_to_trace_truncation);
        eprintln!("executing_pipeline_cleanup region={region:?} stats={stats:?} report={report:?}");
    }

    #[test]
    fn executing_pipeline_heterogeneous_sink_ack_bounds_all_work() {
        for seed in [7, 71, 701] {
            let mut lab = execution_lab(seed);
            let region = lab.state.create_root_region(Budget::INFINITE);
            let gate = Arc::new(ExecutionGate::default());
            let sink_gate = Arc::clone(&gate);
            let outputs = Arc::new(Mutex::new(Vec::new()));
            let sink_outputs = Arc::clone(&outputs);
            let pulled = Arc::new(AtomicUsize::new(0));
            let inputs = ExecutionInputs {
                end: 9,
                pulled: Arc::clone(&pulled),
                panic_factory: false,
                panic_next: None,
            };
            let lazy_pulls = Arc::clone(&pulled);
            let (task, mut handle) = lab
                .state
                .create_task(region, Budget::INFINITE, async move {
                    let cx = Cx::current().unwrap();
                    let scope = cx.scope();
                    let pipeline = scope
                        .pipeline::<_, &'static str>(&cx, execution_config(2), inputs)
                        .then(NonZeroUsize::new(1).unwrap(), |_, value| async move {
                            Outcome::Ok(format!("value={value}"))
                        })
                        .then(
                            NonZeroUsize::new(1).unwrap(),
                            |_, value: String| async move { Outcome::Ok(value.into_bytes()) },
                        );
                    assert_eq!(lazy_pulls.load(Ordering::SeqCst), 0, "building is lazy");
                    pipeline
                        .run(move |_, value: Vec<u8>| {
                            let gate = Arc::clone(&sink_gate);
                            let outputs = Arc::clone(&sink_outputs);
                            async move {
                                if value == b"value=0" {
                                    gate.wait().await;
                                }
                                outputs.lock().unwrap().push(value);
                                Outcome::Ok(())
                            }
                        })
                        .await
                })
                .unwrap();
            lab.scheduler.lock().schedule(task, 0);
            assert!(lab.run_until_idle() > 0);
            assert!(gate.is_parked(), "the actual async sink reached Pending");
            assert!(handle.try_join().unwrap().is_none());
            assert_eq!(
                pulled.load(Ordering::SeqCst),
                2,
                "sink ack controls the total window"
            );
            assert!(outputs.lock().unwrap().is_empty());
            let live_credits: Vec<_> = lab
                .state
                .obligations
                .iter()
                .filter_map(|(_, record)| {
                    (record.holder == task
                        && record.kind == ObligationKind::Lease
                        && record.state == ObligationState::Reserved)
                        .then_some(record.id)
                })
                .collect();
            assert_eq!(
                live_credits.len(),
                2,
                "both IDs remain owned by the coordinator"
            );
            assert_ne!(live_credits[0], live_credits[1]);
            gate.release();
            lab.run_until_quiescent();
            let report = handle.try_join().unwrap().expect("actual pipeline joined");
            assert!(report.outcome.is_ok(), "{report:?}");
            assert_eq!(
                report.summary,
                PipelineExecutionSummary {
                    admitted: 9,
                    consumed: 9,
                    max_in_flight: 2,
                    stages: 2
                }
            );
            assert!(report.error().is_none());
            assert_eq!(
                *outputs.lock().unwrap(),
                (0..9)
                    .map(|value| format!("value={value}").into_bytes())
                    .collect::<Vec<_>>()
            );
            assert_eq!(pulled.load(Ordering::SeqCst), 9);
            let leases: Vec<_> = lab
                .state
                .obligations
                .iter()
                .filter(|(_, record)| record.kind == ObligationKind::Lease)
                .collect();
            assert_eq!(leases.len(), 10, "nine inputs plus one aborted EOF probe");
            assert_eq!(
                leases
                    .iter()
                    .filter(|(_, record)| record.state == ObligationState::Committed)
                    .count(),
                9
            );
            assert_eq!(
                leases
                    .iter()
                    .filter(|(_, record)| record.state == ObligationState::Aborted)
                    .count(),
                1
            );
            assert!(
                leases
                    .iter()
                    .all(|(_, record)| record.holder == task && record.region == region)
            );
            for id in live_credits {
                assert_eq!(
                    lab.state.obligation(id).unwrap().state,
                    ObligationState::Committed
                );
            }
            execution_cleanup(&mut lab, region);
        }
    }

    #[test]
    fn executing_pipeline_identity_and_empty_inputs_do_real_bounded_work() {
        for count in [0_u32, 1, 97] {
            for stages in [false, true] {
                let mut lab = execution_lab(190 + u64::from(count));
                let region = lab.state.create_root_region(Budget::INFINITE);
                let outputs = Arc::new(Mutex::new(Vec::new()));
                let actual = Arc::clone(&outputs);
                let calls = Arc::new(AtomicUsize::new(0));
                let transforms = Arc::clone(&calls);
                let (task, mut handle) = lab
                    .state
                    .create_task(region, Budget::INFINITE, async move {
                        let cx = Cx::current().unwrap();
                        let scope = cx.scope();
                        let pipeline =
                            scope.pipeline::<_, &'static str>(&cx, execution_config(1), 0..count);
                        let pipeline = if stages {
                            pipeline.then(NonZeroUsize::new(1).unwrap(), move |_, value| {
                                transforms.fetch_add(1, Ordering::SeqCst);
                                async move { Outcome::Ok(value + 10) }
                            })
                        } else {
                            pipeline
                        };
                        pipeline
                            .run(move |_, value| {
                                actual.lock().unwrap().push(value);
                                async { Outcome::Ok(()) }
                            })
                            .await
                    })
                    .unwrap();
                lab.scheduler.lock().schedule(task, 0);
                lab.run_until_quiescent();
                let report = handle.try_join().unwrap().expect("identity/empty executed");
                assert!(report.outcome.is_ok(), "{report:?}");
                assert_eq!(report.summary.admitted, count as usize);
                assert_eq!(report.summary.consumed, count as usize);
                assert_eq!(report.summary.stages, usize::from(stages));
                assert_eq!(report.summary.max_in_flight, usize::from(count != 0));
                assert_eq!(
                    calls.load(Ordering::SeqCst),
                    if stages { count as usize } else { 0 }
                );
                assert_eq!(
                    *outputs.lock().unwrap(),
                    (0..count)
                        .map(|value| value + if stages { 10 } else { 0 })
                        .collect::<Vec<_>>()
                );
                execution_cleanup(&mut lab, region);
            }
        }
    }

    #[test]
    fn executing_pipeline_owned_capture_retirement_precedes_terminal_publication() {
        struct Capture {
            cx: Cx,
            drops: Arc<[AtomicUsize; 3]>,
            index: usize,
            cancel: bool,
            panic: bool,
        }

        impl Capture {
            fn observe(&self) {
                assert_eq!(self.drops[self.index].load(Ordering::SeqCst), 0);
            }
        }

        impl Drop for Capture {
            fn drop(&mut self) {
                assert_eq!(self.drops[self.index].fetch_add(1, Ordering::SeqCst), 0);
                if self.cancel {
                    self.cx.cancel_with(
                        crate::types::CancelKind::User,
                        Some("pipeline owned-capture retirement"),
                    );
                }
                if self.panic {
                    panic!("pipeline capture {} retirement panic", self.index);
                }
            }
        }

        struct Inputs {
            capture: Capture,
            fail_construction: bool,
        }

        struct Iter {
            capture: Capture,
            next: u32,
        }

        impl IntoIterator for Inputs {
            type Item = u32;
            type IntoIter = Iter;

            fn into_iter(self) -> Iter {
                assert!(
                    !self.fail_construction,
                    "pipeline primary construction panic"
                );
                Iter {
                    capture: self.capture,
                    next: 0,
                }
            }
        }

        impl Iterator for Iter {
            type Item = u32;

            fn next(&mut self) -> Option<u32> {
                self.capture.observe();
                let value = self.next;
                self.next += 1;
                (value < 3).then_some(value)
            }
        }

        for mode in 0..10 {
            let mut lab = execution_lab(0x32_1900 + mode);
            let root = lab.state.create_root_region(Budget::INFINITE);
            let drops = Arc::new(std::array::from_fn::<_, 3, _>(|_| AtomicUsize::new(0)));
            let outputs = Arc::new(Mutex::new(Vec::new()));
            let publication = Arc::new(Mutex::new(None));
            let task_drops = Arc::clone(&drops);
            let task_outputs = Arc::clone(&outputs);
            let task_publication = Arc::clone(&publication);
            let future: Pin<Box<dyn Future<Output = ()> + Send>> = Box::pin(async move {
                let cx = Cx::current().expect("actual pipeline retirement coordinator");
                let capture = |index| Capture {
                    cx: cx.clone(),
                    drops: Arc::clone(&task_drops),
                    index,
                    cancel: mode == index as u64 + 1 || (mode >= 7 && index == 0),
                    panic: mode == index as u64 + 4 || (mode == 7 && index == 0),
                };
                let inputs = Inputs {
                    capture: capture(0),
                    fail_construction: mode == 9,
                };
                let transform = capture(1);
                let sink = capture(2);
                let report = cx
                    .scope()
                    .pipeline::<_, &'static str>(&cx, execution_config(1), inputs)
                    .then(NonZeroUsize::new(1).unwrap(), move |_, value| {
                        transform.observe();
                        async move {
                            if value == 1 && mode == 7 {
                                Outcome::Panicked(PanicPayload::new("pipeline primary stage panic"))
                            } else if value == 1 && mode == 8 {
                                Outcome::Err("pipeline primary error")
                            } else {
                                Outcome::Ok(value)
                            }
                        }
                    })
                    .run(move |_, value| {
                        sink.observe();
                        task_outputs.lock().unwrap().push(value);
                        async { Outcome::Ok(()) }
                    })
                    .await;
                *task_publication.lock().unwrap() = Some((report, cx.cancel_reason()));
            });
            let (parent, mut join) = lab
                .state
                .create_task(root, Budget::INFINITE, future)
                .unwrap();
            lab.scheduler.lock().schedule(parent, 0);
            lab.run_until_idle();
            let (report, reason) = publication
                .lock()
                .unwrap()
                .take()
                .expect("actual terminal report");
            match &reason {
                Some(reason) => {
                    assert_eq!(reason.kind(), crate::types::CancelKind::User);
                    assert_eq!(
                        reason.message.as_deref(),
                        Some("pipeline owned-capture retirement")
                    );
                    assert_eq!(join.try_join(), Err(JoinError::Cancelled(reason.clone())));
                }
                None => assert_eq!(join.try_join(), Ok(Some(()))),
            }
            assert!(drops.iter().all(|count| count.load(Ordering::SeqCst) == 1));
            let (admitted, consumed) = match mode {
                7 | 8 => (2, 1),
                9 => (0, 0),
                _ => (3, 3),
            };
            assert_eq!(report.summary.admitted, admitted);
            assert_eq!(report.summary.consumed, consumed);
            assert_eq!(report.summary.stages, 1);
            assert_eq!(report.summary.max_in_flight, usize::from(admitted != 0));
            assert_eq!(
                *outputs.lock().unwrap(),
                (0..consumed as u32).collect::<Vec<_>>()
            );
            let credits: Vec<_> = lab
                .state
                .obligations
                .iter()
                .filter_map(|(_, record)| {
                    (record.holder == parent && record.kind == ObligationKind::Lease)
                        .then_some(record)
                })
                .collect();
            assert_eq!(credits.len(), admitted + usize::from(mode < 7));
            assert_eq!(
                credits
                    .iter()
                    .filter(|record| record.state == ObligationState::Committed)
                    .count(),
                consumed
            );
            assert_eq!(
                credits
                    .iter()
                    .filter(|record| record.state == ObligationState::Aborted)
                    .count(),
                credits.len() - consumed
            );
            let trace = lab.state.trace_handle().snapshot();
            let completion =
                |expected| {
                    let matches: Vec<_> = trace.iter().filter(|event| {
                    event.kind == crate::trace::TraceEventKind::Complete
                        && matches!(event.data, crate::trace::TraceData::Task { task, region }
                            if task == expected && region == root)
                }).collect();
                    assert_eq!(matches.len(), 1, "exact terminal for {expected:?}");
                    matches[0].seq
                };
            let parent_complete = completion(parent);
            let children: Vec<_> = trace
                .iter()
                .filter_map(|event| {
                    if event.kind == crate::trace::TraceEventKind::Spawn {
                        if let crate::trace::TraceData::Task { task, region } = event.data {
                            if task != parent && region == root {
                                return Some(task);
                            }
                        }
                    }
                    None
                })
                .collect();
            assert_eq!(children.len(), 2, "actual transform and sink admissions");
            assert_ne!(children[0], children[1]);
            assert!(
                children
                    .iter()
                    .all(|child| completion(*child) < parent_complete)
            );
            execution_cleanup(&mut lab, root);
            eprintln!(
                "pipeline capture retirement mode={mode} parent={parent:?} children={children:?} report={report:?} reason={reason:?}"
            );
            match mode {
                0 => assert!(
                    matches!(report.outcome, Outcome::Ok(summary) if summary == report.summary)
                ),
                1..=3 | 8 => {
                    assert!(
                        matches!(&report.outcome, Outcome::Cancelled(actual) if Some(actual) == reason.as_ref())
                    );
                    if mode == 8 {
                        assert!(matches!(
                            report.error(),
                            Some(PipelineExecutionError::Stage {
                                stage: 0,
                                input: 1,
                                error: "pipeline primary error"
                            })
                        ));
                    }
                }
                _ => {
                    let message = match mode {
                        4..=6 => format!("pipeline capture {} retirement panic", mode - 4),
                        7 => "pipeline primary stage panic".to_owned(),
                        9 => "pipeline primary construction panic".to_owned(),
                        _ => unreachable!(),
                    };
                    assert!(
                        matches!(&report.outcome, Outcome::Panicked(payload) if payload.message() == message)
                    );
                }
            }
        }
    }

    #[test]
    fn executing_pipeline_quota_refusal_remains_typed_after_cancelled_drain() {
        let mut lab = execution_lab(290);
        let region = lab.state.create_root_region(Budget::INFINITE);
        lab.state.region(region).unwrap().set_limits(RegionLimits {
            max_obligations: Some(0),
            ..RegionLimits::UNLIMITED
        });
        let pulled = Arc::new(AtomicUsize::new(0));
        let inputs = ExecutionInputs {
            end: 8,
            pulled: Arc::clone(&pulled),
            panic_factory: false,
            panic_next: None,
        };
        let (task, mut handle) = lab
            .state
            .create_task(region, Budget::INFINITE, async move {
                let cx = Cx::current().unwrap();
                cx.scope()
                    .pipeline::<_, &'static str>(&cx, execution_config(1), inputs)
                    .run(|_, _| async {
                        panic!("quota zero must not call the sink");
                    })
                    .await
            })
            .unwrap();
        lab.scheduler.lock().schedule(task, 0);
        lab.run_until_quiescent();
        let report = handle
            .try_join()
            .unwrap()
            .expect("refusal drained its real sink task");
        assert!(
            report.outcome.is_cancelled(),
            "the aborted pending sink contributes its actual severity: {report:?}"
        );
        assert!(matches!(
            report.error(),
            Some(PipelineExecutionError::Admission {
                stage: None,
                input: 0,
                error: ObligationAdmissionError::LimitReached { limit: 0, live: 0 }
            })
        ));
        assert_eq!(report.summary.admitted, 0);
        assert_eq!(report.summary.consumed, 0);
        assert_eq!(
            pulled.load(Ordering::SeqCst),
            0,
            "authority is checked before iterator.next"
        );
        assert_eq!(lab.state.obligations.iter().count(), 0);
        execution_cleanup(&mut lab, region);
    }

    #[test]
    fn executing_pipeline_factory_poll_and_domain_failures_drain_all_tasks() {
        for cause in 0..7 {
            let mut lab = execution_lab(390 + cause);
            let region = lab.state.create_root_region(Budget::INFINITE);
            let pulled = Arc::new(AtomicUsize::new(0));
            let inputs = ExecutionInputs {
                end: 8,
                pulled,
                panic_factory: cause == 0,
                panic_next: (cause == 1).then_some(0),
            };
            let outputs = Arc::new(Mutex::new(Vec::new()));
            let actual = Arc::clone(&outputs);
            let (task, mut handle) = lab
                .state
                .create_task(region, Budget::INFINITE, async move {
                    let cx = Cx::current().unwrap();
                    cx.scope()
                        .pipeline::<_, &'static str>(&cx, execution_config(1), inputs)
                        .then(NonZeroUsize::new(1).unwrap(), move |_, value| {
                            assert_ne!(cause, 2, "executing transform factory panic");
                            async move {
                                assert_ne!(cause, 3, "executing transform poll panic");
                                if cause == 6 {
                                    Outcome::Err("typed stage refusal")
                                } else {
                                    Outcome::Ok(value)
                                }
                            }
                        })
                        .run(move |_, value| {
                            assert_ne!(cause, 4, "executing sink factory panic");
                            let actual = Arc::clone(&actual);
                            async move {
                                assert_ne!(cause, 5, "executing sink poll panic");
                                actual.lock().unwrap().push(value);
                                Outcome::Ok(())
                            }
                        })
                        .await
                })
                .unwrap();
            lab.scheduler.lock().schedule(task, 0);
            lab.run_until_quiescent();
            let report = handle
                .try_join()
                .unwrap()
                .expect("failure returned only after joining its children");
            if cause == 6 {
                assert!(matches!(
                    report.error(),
                    Some(PipelineExecutionError::Stage {
                        stage: 0,
                        input: 0,
                        error: "typed stage refusal"
                    })
                ));
                assert!(
                    matches!(report.outcome, Outcome::Err(_) | Outcome::Cancelled(_)),
                    "{report:?}"
                );
            } else {
                let Outcome::Panicked(payload) = &report.outcome else {
                    panic!("expected actual panic for cause {cause}: {report:?}");
                };
                assert!(payload.message().contains("executing"), "{payload:?}");
            }
            assert_eq!(report.summary.consumed, 0);
            assert!(report.summary.admitted <= 1);
            assert!(outputs.lock().unwrap().is_empty());
            execution_cleanup(&mut lab, region);
        }
    }

    #[test]
    fn executing_pipeline_cancel_and_future_drop_leave_async_cleanup_owned() {
        for drop_future in [false, true] {
            let mut lab = execution_lab(490 + u64::from(drop_future));
            let region = lab.state.create_root_region(Budget::INFINITE);
            let entered = Arc::new(AtomicBool::new(false));
            let cancelled = Arc::new(AtomicBool::new(false));
            let cleanup = Arc::new(ExecutionGate::default());
            let drop_request = Arc::new(ExecutionGate::default());
            let result = Arc::new(Mutex::new(None));
            let worker_entered = Arc::clone(&entered);
            let worker_cancelled = Arc::clone(&cancelled);
            let worker_cleanup = Arc::clone(&cleanup);
            let request = Arc::clone(&drop_request);
            let returned = Arc::clone(&result);
            let (task, mut handle) = lab
                .state
                .create_task(region, Budget::INFINITE, async move {
                    let cx = Cx::current().unwrap();
                    let scope = cx.scope();
                    let pipeline = scope
                        .pipeline::<_, &'static str>(&cx, execution_config(1), 0..8_u32)
                        .then(NonZeroUsize::new(1).unwrap(), move |worker_cx, value| {
                            let entered = Arc::clone(&worker_entered);
                            let cancelled = Arc::clone(&worker_cancelled);
                            let cleanup = Arc::clone(&worker_cleanup);
                            async move {
                                entered.store(true, Ordering::SeqCst);
                                let mut registration = None;
                                std::future::poll_fn(|poll| {
                                    registration = Some(
                                        worker_cx.refresh_cancel_waker(registration, poll.waker()),
                                    );
                                    if worker_cx.checkpoint().is_err() {
                                        Poll::Ready(())
                                    } else {
                                        Poll::Pending
                                    }
                                })
                                .await;
                                worker_cx.clear_cancel_waker(registration.take().unwrap());
                                cancelled.store(true, Ordering::SeqCst);
                                // This is user async cleanup: it deliberately needs
                                // a separate event after observing cancellation.
                                cleanup.wait().await;
                                let _: u32 = value;
                                pipeline_cancelled(&worker_cx)
                            }
                        });
                    let mut execution = Box::pin(pipeline.run(|_, _: u32| async {
                        panic!("cancelled transform cannot publish a value");
                    }));
                    if drop_future {
                        std::future::poll_fn(|poll| {
                            if request.poll(poll).is_ready() {
                                return Poll::Ready(());
                            }
                            assert!(
                                execution.as_mut().poll(poll).is_pending(),
                                "execution cannot finish while its transform is parked"
                            );
                            Poll::Pending
                        })
                        .await;
                        drop(execution);
                    } else {
                        *returned.lock().unwrap() = Some(execution.await);
                    }
                })
                .unwrap();
            lab.scheduler.lock().schedule(task, 0);
            lab.run_until_idle();
            assert!(entered.load(Ordering::SeqCst));
            assert!(!cancelled.load(Ordering::SeqCst));
            assert!(handle.try_join().unwrap().is_none());
            if drop_future {
                drop_request.release();
            } else {
                handle.abort();
            }
            lab.run_until_idle();
            assert!(
                cancelled.load(Ordering::SeqCst),
                "actual child cancellation waker fired"
            );
            assert!(
                cleanup.is_parked(),
                "cleanup crossed a separate Pending boundary"
            );
            assert!(
                result.lock().unwrap().is_none(),
                "no report may claim a drained operation yet"
            );
            assert!(
                lab.state.tasks_iter().count() > 0,
                "region still owns actual cleanup"
            );
            if drop_future {
                assert_eq!(
                    handle.try_join().unwrap(),
                    Some(()),
                    "dropping the operation requests abort without pretending to drain"
                );
            } else {
                assert!(handle.try_join().unwrap().is_none());
                assert_eq!(
                    lab.state
                        .obligations
                        .iter()
                        .filter(|(_, record)| record.kind == ObligationKind::Lease
                            && record.state == ObligationState::Reserved)
                        .count(),
                    1,
                    "the coordinator retains its original work credit while draining"
                );
            }
            cleanup.release();
            lab.run_until_quiescent();
            if !drop_future {
                let report = result
                    .lock()
                    .unwrap()
                    .take()
                    .expect("cancelled operation drained after real cleanup completion");
                assert!(report.outcome.is_cancelled(), "{report:?}");
                assert_eq!(report.summary.admitted, 1);
                assert_eq!(report.summary.consumed, 0);
                match handle.try_join() {
                    Ok(Some(())) | Err(JoinError::Cancelled(_)) => {}
                    other => panic!("unexpected owner completion: {other:?}"),
                }
            }
            execution_cleanup(&mut lab, region);
        }
    }

    #[test]
    fn executing_pipeline_late_logical_cleanup_panic_dominates_cancelled_join() {
        for late_panic in [true, false] {
            let mut lab = execution_lab(590 + u64::from(late_panic));
            let region = lab.state.create_root_region(Budget::INFINITE);
            let second_entered = Arc::new(ExecutionGate::default());
            let first_gate = Arc::clone(&second_entered);
            let second_gate = Arc::clone(&second_entered);
            let cleanup = Arc::new(ExecutionGate::default());
            let actual_cleanup = Arc::clone(&cleanup);
            let cancelled = Arc::new(AtomicBool::new(false));
            let actual_cancelled = Arc::clone(&cancelled);
            let (task, mut handle) = lab
                .state
                .create_task(region, Budget::INFINITE, async move {
                    let cx = Cx::current().unwrap();
                    cx.scope()
                        .pipeline::<_, &'static str>(&cx, execution_config(2), 0..2_u32)
                        .then(NonZeroUsize::new(1).unwrap(), move |worker_cx, value| {
                            let entered = Arc::clone(&first_gate);
                            let cleanup = Arc::clone(&actual_cleanup);
                            let cancelled = Arc::clone(&actual_cancelled);
                            async move {
                                if value == 0 {
                                    return Outcome::Ok(value);
                                }
                                entered.release();
                                let mut registration = None;
                                std::future::poll_fn(|poll| {
                                    registration = Some(
                                        worker_cx.refresh_cancel_waker(registration, poll.waker()),
                                    );
                                    if worker_cx.checkpoint().is_err() {
                                        Poll::Ready(())
                                    } else {
                                        Poll::Pending
                                    }
                                })
                                .await;
                                worker_cx.clear_cancel_waker(registration.take().unwrap());
                                cancelled.store(true, Ordering::SeqCst);
                                cleanup.wait().await;
                                if late_panic {
                                    Outcome::Panicked(PanicPayload::new(
                                        "logical cleanup panic after sibling failure",
                                    ))
                                } else {
                                    Outcome::Err("secondary cleanup error")
                                }
                            }
                        })
                        .then(NonZeroUsize::new(1).unwrap(), move |_, _: u32| {
                            let gate = Arc::clone(&second_gate);
                            async move {
                                gate.wait().await;
                                Outcome::<u32, _>::Err("initiating stage failure")
                            }
                        })
                        .run(|_, _: u32| async {
                            panic!("failing stage cannot publish to the sink")
                        })
                        .await
                })
                .unwrap();
            lab.scheduler.lock().schedule(task, 0);
            lab.run_until_idle();
            assert!(second_entered.open.load(Ordering::SeqCst));
            assert!(cancelled.load(Ordering::SeqCst));
            assert!(cleanup.is_parked());
            assert!(
                handle.try_join().unwrap().is_none(),
                "the first worker has not finished cleanup"
            );
            cleanup.release();
            lab.run_until_quiescent();
            let report = handle
                .try_join()
                .unwrap()
                .expect("both logical and task terminals collected");
            if late_panic {
                let Outcome::Panicked(payload) = &report.outcome else {
                    panic!("cleanup panic was erased by cancellation: {report:?}");
                };
                assert_eq!(
                    payload.message(),
                    "logical cleanup panic after sibling failure"
                );
            } else {
                assert!(
                    report.outcome.is_cancelled(),
                    "actual cancellation dominates the later logical cleanup Err: {report:?}"
                );
            }
            assert!(matches!(
                report.error(),
                Some(PipelineExecutionError::Stage {
                    stage: 1,
                    input: 0,
                    error: "initiating stage failure"
                })
            ));
            assert_eq!(report.summary.admitted, 2);
            assert_eq!(report.summary.consumed, 0);
            execution_cleanup(&mut lab, region);
        }
    }

    #[test]
    fn executing_pipeline_failed_sink_keeps_same_poll_acknowledged_prefix() {
        let mut lab = execution_lab(690);
        let region = lab.state.create_root_region(Budget::INFINITE);
        let gate = Arc::new(ExecutionGate::default());
        let sink_gate = Arc::clone(&gate);
        let outputs = Arc::new(Mutex::new(Vec::new()));
        let actual = Arc::clone(&outputs);
        let (task, mut handle) = lab
            .state
            .create_task(region, Budget::INFINITE, async move {
                let cx = Cx::current().unwrap();
                cx.scope()
                    .pipeline::<_, &'static str>(&cx, execution_config(2), 0..2_u32)
                    .run(move |_, value| {
                        let gate = Arc::clone(&sink_gate);
                        let actual = Arc::clone(&actual);
                        async move {
                            if value == 0 {
                                gate.wait().await;
                                actual.lock().unwrap().push(value);
                                Outcome::Ok(())
                            } else {
                                Outcome::Err("failure after delivered prefix")
                            }
                        }
                    })
                    .await
            })
            .unwrap();
        lab.scheduler.lock().schedule(task, 0);
        lab.run_until_idle();
        assert!(gate.is_parked());
        assert!(handle.try_join().unwrap().is_none());
        let original: Vec<_> = lab
            .state
            .obligations
            .iter()
            .filter_map(|(_, record)| {
                (record.holder == task && record.kind == ObligationKind::Lease).then_some(record.id)
            })
            .collect();
        assert_eq!(original.len(), 2);
        assert!(outputs.lock().unwrap().is_empty());
        // Input 1 is already queued behind the pending input-0 callback.
        // The sink can publish ack0 and return Err(1) in this single poll,
        // before the coordinator observes either event.
        gate.release();
        lab.run_until_quiescent();
        let report = handle
            .try_join()
            .unwrap()
            .expect("sink error and queued ACK both drained");
        assert!(matches!(
            report.error(),
            Some(PipelineExecutionError::Stage {
                stage: 0,
                input: 1,
                error: "failure after delivered prefix"
            })
        ));
        assert_eq!(*outputs.lock().unwrap(), vec![0]);
        assert_eq!(report.summary.admitted, 2);
        assert_eq!(report.summary.consumed, 1);
        assert_eq!(
            lab.state.obligation(original[0]).unwrap().state,
            ObligationState::Committed
        );
        assert_eq!(
            lab.state.obligation(original[1]).unwrap().state,
            ObligationState::Aborted
        );
        assert_eq!(
            lab.state
                .obligations
                .iter()
                .filter(|(_, record)| record.kind == ObligationKind::Lease)
                .count(),
            2,
            "failure did not pull another input or an EOF probe"
        );
        execution_cleanup(&mut lab, region);
    }

    #[test]
    fn executing_pipeline_captured_iterator_drop_panic_still_joins_admitted_workers() {
        struct PanickingIterator {
            pulled: Arc<AtomicUsize>,
            dropped: Arc<AtomicUsize>,
        }

        impl Iterator for PanickingIterator {
            type Item = u32;
            fn next(&mut self) -> Option<Self::Item> {
                self.pulled.fetch_add(1, Ordering::SeqCst);
                Some(0)
            }
        }

        impl Drop for PanickingIterator {
            fn drop(&mut self) {
                self.dropped.fetch_add(1, Ordering::SeqCst);
                panic!("captured iterator destruction panic after cancellation");
            }
        }

        let mut lab = execution_lab(790);
        let region = lab.state.create_root_region(Budget::INFINITE);
        let dropped = Arc::new(AtomicUsize::new(0));
        let pulled = Arc::new(AtomicUsize::new(0));
        let inputs = PanickingIterator {
            pulled: Arc::clone(&pulled),
            dropped: Arc::clone(&dropped),
        };
        let result = Arc::new(Mutex::new(None));
        let returned = Arc::clone(&result);
        let (task, mut handle) = lab
            .state
            .create_task(region, Budget::INFINITE, async move {
                let cx = Cx::current().unwrap();
                let report = cx
                    .scope()
                    .pipeline::<_, &'static str>(&cx, execution_config(1), inputs)
                    .then(NonZeroUsize::new(1).unwrap(), |_, value| async move {
                        Outcome::Ok(value)
                    })
                    .then(NonZeroUsize::new(1).unwrap(), |_, value| async move {
                        Outcome::Ok(value)
                    })
                    .run(|_, _| async {
                        panic!("cancellation during spawning precedes all inputs")
                    })
                    .await;
                *returned.lock().unwrap() = Some(report);
            })
            .unwrap();
        lab.scheduler.lock().schedule(task, 0);
        // Each actual coordinator poll spawns at most one worker before
        // yielding. Two scheduler steps admit at least the first worker,
        // while three total workers are needed before the iterator is used.
        lab.step_for_test();
        lab.step_for_test();
        assert!(lab.state.tasks_iter().count() >= 2);
        assert_eq!(pulled.load(Ordering::SeqCst), 0);
        assert_eq!(dropped.load(Ordering::SeqCst), 0);
        assert!(handle.try_join().unwrap().is_none());
        handle.abort();
        lab.run_until_quiescent();
        let report = result
            .lock()
            .unwrap()
            .take()
            .expect("iterator destruction must not bypass async drain");
        let Outcome::Panicked(payload) = &report.outcome else {
            panic!("iterator destruction must remain the stronger failure: {report:?}");
        };
        assert_eq!(
            payload.message(),
            "captured iterator destruction panic after cancellation"
        );
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        assert_eq!(pulled.load(Ordering::SeqCst), 0);
        assert_eq!(report.summary.admitted, 0);
        assert_eq!(report.summary.consumed, 0);
        assert_eq!(lab.state.obligations.iter().count(), 0);
        match handle.try_join() {
            Ok(Some(())) | Err(JoinError::Cancelled(_)) => {}
            other => panic!("unexpected cancelled coordinator completion: {other:?}"),
        }
        execution_cleanup(&mut lab, region);
    }

    // =========================================================================
    // PipelineConfig Tests
    // =========================================================================

    #[test]
    fn pipeline_config_default() {
        let config = PipelineConfig::default();
        assert!(config.check_cancellation);
        assert!(!config.continue_on_error);
    }

    #[test]
    fn pipeline_config_with_cancellation_check() {
        let config = PipelineConfig::with_cancellation_check();
        assert!(config.check_cancellation);
    }

    #[test]
    fn pipeline_config_without_cancellation_check() {
        let config = PipelineConfig::without_cancellation_check();
        assert!(!config.check_cancellation);
    }

    // =========================================================================
    // Pipeline Type Tests
    // =========================================================================

    #[test]
    fn pipeline_creation() {
        let pipeline = Pipeline::<()>::new();
        assert!(pipeline.config.check_cancellation);
    }

    #[test]
    fn pipeline_with_config() {
        let config = PipelineConfig::without_cancellation_check();
        let pipeline = Pipeline::<()>::with_config(config);
        assert!(!pipeline.config.check_cancellation);
    }

    #[test]
    fn pipeline_clone_and_copy() {
        let p1 = Pipeline::<()>::new();
        let p2 = p1; // Copy
        let p3 = p1; // Also copy

        assert_eq!(p1.config.check_cancellation, p2.config.check_cancellation);
        assert_eq!(p1.config.check_cancellation, p3.config.check_cancellation);
    }

    #[test]
    fn pipeline_macro_chains_stages_sequentially() {
        let cx = crate::cx::Cx::for_testing();
        let fut = crate::pipeline!(cx, 2usize, |_, x| async move { x + 3 }, |_, x| async move {
            x * 4
        });
        let out = futures_lite::future::block_on(fut);
        assert_eq!(out, 20);
    }

    // =========================================================================
    // FailedStage Tests
    // =========================================================================

    #[test]
    fn failed_stage_first() {
        let stage = FailedStage::new(0, 3);
        assert!(stage.is_first());
        assert!(!stage.is_last());
        assert_eq!(stage.stage_number(), 1);
    }

    #[test]
    fn failed_stage_middle() {
        let stage = FailedStage::new(1, 3);
        assert!(!stage.is_first());
        assert!(!stage.is_last());
        assert_eq!(stage.stage_number(), 2);
    }

    #[test]
    fn failed_stage_last() {
        let stage = FailedStage::new(2, 3);
        assert!(!stage.is_first());
        assert!(stage.is_last());
        assert_eq!(stage.stage_number(), 3);
    }

    #[test]
    fn failed_stage_display() {
        let stage = FailedStage::new(1, 5);
        assert_eq!(stage.to_string(), "stage 2/5");
    }

    // =========================================================================
    // PipelineResult Tests
    // =========================================================================

    #[test]
    fn pipeline_result_completed() {
        let result: PipelineResult<i32, &str> = PipelineResult::completed(42, 3);

        assert!(result.is_completed());
        assert!(!result.is_failed());
        assert!(!result.is_cancelled());
        assert!(!result.is_panicked());
        assert_eq!(result.stages_executed(), 3);
    }

    #[test]
    fn pipeline_result_failed() {
        let result: PipelineResult<i32, &str> =
            PipelineResult::failed("error", FailedStage::new(1, 3));

        assert!(!result.is_completed());
        assert!(result.is_failed());
        assert_eq!(result.stages_executed(), 2); // Stages 0 and 1 were executed
    }

    #[test]
    fn pipeline_result_cancelled() {
        let result: PipelineResult<i32, &str> =
            PipelineResult::cancelled(CancelReason::shutdown(), FailedStage::new(1, 3));

        assert!(!result.is_completed());
        assert!(result.is_cancelled());
        assert_eq!(result.stages_executed(), 1); // Only stage 0 completed before cancel
    }

    #[test]
    fn pipeline_result_panicked() {
        let result: PipelineResult<i32, &str> =
            PipelineResult::panicked(PanicPayload::new("boom"), FailedStage::new(2, 3));

        assert!(!result.is_completed());
        assert!(result.is_panicked());
        assert_eq!(result.stages_executed(), 3); // All stages were attempted
    }

    #[test]
    fn pipeline_result_into_outcome() {
        let completed: PipelineResult<i32, &str> = PipelineResult::completed(42, 3);
        assert!(matches!(completed.into_outcome(), Outcome::Ok(42)));

        let failed: PipelineResult<i32, &str> =
            PipelineResult::failed("error", FailedStage::new(0, 1));
        assert!(matches!(failed.into_outcome(), Outcome::Err("error")));

        let cancelled: PipelineResult<i32, &str> =
            PipelineResult::cancelled(CancelReason::shutdown(), FailedStage::new(0, 1));
        assert!(cancelled.into_outcome().is_cancelled());

        let panicked: PipelineResult<i32, &str> =
            PipelineResult::panicked(PanicPayload::new("oops"), FailedStage::new(0, 1));
        assert!(panicked.into_outcome().is_panicked());
    }

    // =========================================================================
    // stage_outcome_to_result Tests
    // =========================================================================

    #[test]
    fn stage_outcome_ok_returns_none() {
        let result = stage_outcome_to_result::<i32, &str>(Outcome::Ok(42), 0, 3);
        assert!(result.is_none());
    }

    #[test]
    fn stage_outcome_err_returns_failed() {
        let result = stage_outcome_to_result::<i32, &str>(Outcome::Err("error"), 1, 3);
        assert!(result.is_some());
        assert!(result.unwrap().is_failed());
    }

    #[test]
    fn stage_outcome_cancelled_returns_cancelled() {
        let result = stage_outcome_to_result::<i32, &str>(
            Outcome::Cancelled(CancelReason::shutdown()),
            2,
            3,
        );
        assert!(result.is_some());
        assert!(result.unwrap().is_cancelled());
    }

    #[test]
    fn stage_outcome_panicked_returns_panicked() {
        let result = stage_outcome_to_result::<i32, &str>(
            Outcome::Panicked(PanicPayload::new("boom")),
            0,
            3,
        );
        assert!(result.is_some());
        assert!(result.unwrap().is_panicked());
    }

    // =========================================================================
    // pipeline2_outcomes Tests
    // =========================================================================

    #[test]
    fn pipeline2_both_ok() {
        let result = pipeline2_outcomes::<i32, &str>(Outcome::Ok(1), Some(Outcome::Ok(2)));

        assert!(result.is_completed());
        if let PipelineResult::Completed {
            value,
            stages_completed,
        } = result
        {
            assert_eq!(value, 2);
            assert_eq!(stages_completed, 2);
        } else {
            unreachable!("Expected Completed");
        }
    }

    #[test]
    fn pipeline2_first_fails() {
        let result = pipeline2_outcomes::<i32, &str>(Outcome::Err("stage1 error"), None);

        assert!(result.is_failed());
        if let PipelineResult::Failed { error, failed_at } = result {
            assert_eq!(error, "stage1 error");
            assert!(failed_at.is_first());
        } else {
            unreachable!("Expected Failed");
        }
    }

    #[test]
    fn pipeline2_second_fails() {
        let result = pipeline2_outcomes(Outcome::Ok(1), Some(Outcome::Err("stage2 error")));

        assert!(result.is_failed());
        if let PipelineResult::Failed { error, failed_at } = result {
            assert_eq!(error, "stage2 error");
            assert!(failed_at.is_last());
            assert_eq!(failed_at.index, 1);
        } else {
            unreachable!("Expected Failed");
        }
    }

    #[test]
    fn pipeline2_first_cancelled() {
        let result =
            pipeline2_outcomes::<i32, &str>(Outcome::Cancelled(CancelReason::shutdown()), None);

        assert!(result.is_cancelled());
    }

    #[test]
    fn pipeline2_panicked_when_o2_missing() {
        let result = pipeline2_outcomes::<i32, &str>(Outcome::Ok(1), None);
        assert!(result.is_panicked());
        if let PipelineResult::Panicked {
            payload,
            panicked_at,
        } = result
        {
            assert_eq!(payload.message(), "o2 must be provided when o1 succeeds");
            assert_eq!(panicked_at.index, 1);
        } else {
            panic!("Expected Panicked");
        }
    }

    // =========================================================================
    // pipeline3_outcomes Tests
    // =========================================================================

    #[test]
    fn pipeline3_all_ok() {
        let result = pipeline3_outcomes::<i32, &str>(
            Outcome::<i32, &str>::Ok(1),
            Some(Outcome::Ok(2)),
            Some(Outcome::Ok(3)),
        );

        assert!(result.is_completed());
        if let PipelineResult::Completed {
            value,
            stages_completed,
        } = result
        {
            assert_eq!(value, 3);
            assert_eq!(stages_completed, 3);
        } else {
            unreachable!("Expected Completed");
        }
    }

    #[test]
    fn pipeline3_first_fails() {
        let result = pipeline3_outcomes::<i32, &str>(Outcome::Err("s1"), None, None);

        assert!(result.is_failed());
        if let PipelineResult::Failed { failed_at, .. } = result {
            assert_eq!(failed_at.index, 0);
        }
    }

    #[test]
    fn pipeline3_second_fails() {
        let result =
            pipeline3_outcomes::<i32, &str>(Outcome::Ok(1), Some(Outcome::Err("s2")), None);

        assert!(result.is_failed());
        if let PipelineResult::Failed { failed_at, .. } = result {
            assert_eq!(failed_at.index, 1);
        }
    }

    #[test]
    fn pipeline3_third_fails() {
        let result = pipeline3_outcomes(
            Outcome::Ok(1),
            Some(Outcome::Ok(2)),
            Some(Outcome::Err("s3")),
        );

        assert!(result.is_failed());
        if let PipelineResult::Failed { failed_at, .. } = result {
            assert_eq!(failed_at.index, 2);
            assert!(failed_at.is_last());
        }
    }

    #[test]
    fn pipeline3_panicked_when_o2_missing() {
        let result = pipeline3_outcomes::<i32, &str>(Outcome::Ok(1), None, None);
        assert!(result.is_panicked());
        if let PipelineResult::Panicked {
            payload,
            panicked_at,
        } = result
        {
            assert_eq!(payload.message(), "o2 must be provided when o1 succeeds");
            assert_eq!(panicked_at.index, 1);
        } else {
            panic!("Expected Panicked");
        }
    }

    #[test]
    fn pipeline3_panicked_when_o3_missing() {
        let result = pipeline3_outcomes::<i32, &str>(Outcome::Ok(1), Some(Outcome::Ok(2)), None);
        assert!(result.is_panicked());
        if let PipelineResult::Panicked {
            payload,
            panicked_at,
        } = result
        {
            assert_eq!(
                payload.message(),
                "o3 must be provided when o1 and o2 succeed"
            );
            assert_eq!(panicked_at.index, 2);
        } else {
            panic!("Expected Panicked");
        }
    }

    // =========================================================================
    // pipeline_with_final Tests
    // =========================================================================

    #[test]
    fn pipeline_with_final_all_ok() {
        let intermediates: Vec<Outcome<i32, &str>> = vec![Outcome::Ok(1), Outcome::Ok(2)];
        let result = pipeline_with_final(intermediates, Outcome::Ok(42), 3);

        assert!(result.is_completed());
        if let PipelineResult::Completed { value, .. } = result {
            assert_eq!(value, 42);
        }
    }

    #[test]
    fn pipeline_with_final_intermediate_fails() {
        let intermediates: Vec<Outcome<i32, &str>> = vec![Outcome::Ok(1), Outcome::Err("mid fail")];
        let result = pipeline_with_final(intermediates, Outcome::Ok(42), 3);

        assert!(result.is_failed());
        if let PipelineResult::Failed { failed_at, .. } = result {
            assert_eq!(failed_at.index, 1);
        }
    }

    #[test]
    fn pipeline_with_final_final_fails() {
        let intermediates: Vec<Outcome<i32, &str>> = vec![Outcome::Ok(1), Outcome::Ok(2)];
        let result = pipeline_with_final(intermediates, Outcome::Err("final fail"), 3);

        assert!(result.is_failed());
        if let PipelineResult::Failed { failed_at, .. } = result {
            assert_eq!(failed_at.index, 2);
            assert!(failed_at.is_last());
        }
    }

    // =========================================================================
    // pipeline_to_result Tests
    // =========================================================================

    #[test]
    fn pipeline_to_result_completed() {
        let result: PipelineResult<i32, &str> = PipelineResult::completed(42, 3);
        assert_eq!(pipeline_to_result(result).unwrap(), 42);
    }

    #[test]
    fn pipeline_to_result_failed() {
        let result: PipelineResult<i32, &str> =
            PipelineResult::failed("error", FailedStage::new(1, 3));
        let err = pipeline_to_result(result).unwrap_err();
        assert!(matches!(err, PipelineError::StageError { .. }));
    }

    #[test]
    fn pipeline_to_result_cancelled() {
        let result: PipelineResult<i32, &str> =
            PipelineResult::cancelled(CancelReason::shutdown(), FailedStage::new(0, 3));
        let err = pipeline_to_result(result).unwrap_err();
        assert!(matches!(err, PipelineError::Cancelled { .. }));
    }

    #[test]
    fn pipeline_to_result_panicked() {
        let result: PipelineResult<i32, &str> =
            PipelineResult::panicked(PanicPayload::new("boom"), FailedStage::new(2, 3));
        let err = pipeline_to_result(result).unwrap_err();
        assert!(matches!(err, PipelineError::Panicked { .. }));
    }

    // =========================================================================
    // PipelineError Tests
    // =========================================================================

    #[test]
    fn pipeline_error_display_stage_error() {
        let err: PipelineError<&str> = PipelineError::StageError {
            error: "test error",
            stage: FailedStage::new(1, 3),
        };
        let display = err.to_string();
        assert!(display.contains("stage 2/3"));
        assert!(display.contains("test error"));
    }

    #[test]
    fn pipeline_error_display_cancelled() {
        let err: PipelineError<&str> = PipelineError::Cancelled {
            reason: CancelReason::shutdown(),
            stage: FailedStage::new(0, 2),
        };
        let display = err.to_string();
        assert!(display.contains("cancelled"));
        assert!(display.contains("stage 1/2"));
    }

    #[test]
    fn pipeline_error_display_panicked() {
        let err: PipelineError<&str> = PipelineError::Panicked {
            payload: PanicPayload::new("boom"),
            stage: FailedStage::new(2, 3),
        };
        let display = err.to_string();
        assert!(display.contains("panicked"));
        assert!(display.contains("boom"));
    }

    // =========================================================================
    // pipeline_n_outcomes Tests
    // =========================================================================

    #[test]
    fn pipeline_n_all_ok() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Ok(2), Outcome::Ok(3)];
        let result = pipeline_n_outcomes(outcomes, 3);

        assert!(result.is_completed());
        if let PipelineResult::Completed {
            value,
            stages_completed,
        } = result
        {
            assert_eq!(value, 3);
            assert_eq!(stages_completed, 3);
        } else {
            unreachable!("Expected Completed");
        }
    }

    #[test]
    fn pipeline_n_first_error() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![Outcome::Err("fail"), Outcome::Ok(2)];
        let result = pipeline_n_outcomes(outcomes, 3);

        assert!(result.is_failed());
        if let PipelineResult::Failed { error, failed_at } = result {
            assert_eq!(error, "fail");
            assert_eq!(failed_at.index, 0);
            assert_eq!(failed_at.total_stages, 3);
        } else {
            unreachable!("Expected Failed");
        }
    }

    #[test]
    fn pipeline_n_middle_cancel() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Cancelled(CancelReason::shutdown())];
        let result = pipeline_n_outcomes(outcomes, 4);

        assert!(result.is_cancelled());
        if let PipelineResult::Cancelled { cancelled_at, .. } = result {
            assert_eq!(cancelled_at.index, 1);
            assert_eq!(cancelled_at.total_stages, 4);
        } else {
            panic!("Expected Cancelled");
        }
    }

    #[test]
    #[should_panic(expected = "all successful outcomes must cover every pipeline stage")]
    fn pipeline_n_all_ok_partial_run_is_rejected() {
        // Provide fewer outcomes than total_stages, all Ok
        let outcomes: Vec<Outcome<i32, &str>> = vec![Outcome::Ok(10), Outcome::Ok(20)];
        let _ = pipeline_n_outcomes(outcomes, 5);
    }

    #[test]
    fn pipeline_n_single_ok() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![Outcome::Ok(42)];
        let result = pipeline_n_outcomes(outcomes, 1);

        assert!(result.is_completed());
        if let PipelineResult::Completed {
            value,
            stages_completed,
        } = result
        {
            assert_eq!(value, 42);
            assert_eq!(stages_completed, 1);
        } else {
            unreachable!("Expected Completed");
        }
    }

    #[test]
    fn pipeline_n_single_error() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![Outcome::Err("only stage fails")];
        let result = pipeline_n_outcomes(outcomes, 1);

        assert!(result.is_failed());
        if let PipelineResult::Failed { failed_at, .. } = result {
            assert_eq!(failed_at.index, 0);
            assert!(failed_at.is_first());
            assert!(failed_at.is_last());
        } else {
            unreachable!("Expected Failed");
        }
    }

    #[test]
    fn pipeline_n_panic_mid_pipeline() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Ok(1),
            Outcome::Ok(2),
            Outcome::Panicked(PanicPayload::new("stage 3 panicked")),
        ];
        let result = pipeline_n_outcomes(outcomes, 4);

        assert!(result.is_panicked());
        if let PipelineResult::Panicked { panicked_at, .. } = result {
            assert_eq!(panicked_at.index, 2);
            assert_eq!(panicked_at.total_stages, 4);
        } else {
            panic!("Expected Panicked");
        }
    }

    #[test]
    #[should_panic(expected = "outcomes must not be empty")]
    fn pipeline_n_empty_outcomes_panics() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![];
        let _ = pipeline_n_outcomes(outcomes, 3);
    }

    #[test]
    #[should_panic(expected = "more outcomes than stages")]
    fn pipeline_n_too_many_outcomes_panics() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Ok(2), Outcome::Ok(3)];
        let _ = pipeline_n_outcomes(outcomes, 2);
    }

    // =========================================================================
    // pipeline_with_final Validation Tests
    // =========================================================================

    #[test]
    #[should_panic(expected = "total_stages must be positive")]
    fn pipeline_with_final_zero_stages_panics() {
        let intermediates: Vec<Outcome<i32, &str>> = vec![];
        let _ = pipeline_with_final(intermediates, Outcome::Ok(42), 0);
    }

    #[test]
    #[should_panic(expected = "must equal total_stages")]
    fn pipeline_with_final_mismatched_stages_panics() {
        let intermediates: Vec<Outcome<i32, &str>> = vec![Outcome::Ok(1)];
        // 1 intermediate + 1 final = 2, but total_stages = 5
        let _ = pipeline_with_final(intermediates, Outcome::Ok(42), 5);
    }

    #[test]
    fn pipeline_with_final_cancelled_final() {
        let intermediates: Vec<Outcome<i32, &str>> = vec![Outcome::Ok(1), Outcome::Ok(2)];
        let result = pipeline_with_final(
            intermediates,
            Outcome::Cancelled(CancelReason::shutdown()),
            3,
        );

        assert!(result.is_cancelled());
        if let PipelineResult::Cancelled { cancelled_at, .. } = result {
            assert_eq!(cancelled_at.index, 2);
            assert!(cancelled_at.is_last());
        } else {
            panic!("Expected Cancelled");
        }
    }

    #[test]
    fn pipeline_with_final_panicked_final() {
        let intermediates: Vec<Outcome<i32, &str>> = vec![Outcome::Ok(1)];
        let result = pipeline_with_final(
            intermediates,
            Outcome::Panicked(PanicPayload::new("final boom")),
            2,
        );

        assert!(result.is_panicked());
        if let PipelineResult::Panicked { panicked_at, .. } = result {
            assert_eq!(panicked_at.index, 1);
            assert!(panicked_at.is_last());
        } else {
            panic!("Expected Panicked");
        }
    }

    #[test]
    fn pipeline_with_final_single_stage() {
        // 0 intermediates + 1 final = 1 total stage
        let intermediates: Vec<Outcome<i32, &str>> = vec![];
        let result = pipeline_with_final(intermediates, Outcome::Ok(99), 1);

        assert!(result.is_completed());
        if let PipelineResult::Completed { value, .. } = result {
            assert_eq!(value, 99);
        } else {
            unreachable!("Expected Completed");
        }
    }

    // =========================================================================
    // Invariant Tests
    // =========================================================================

    #[test]
    fn error_short_circuits_at_first_failure() {
        // Simulate a 5-stage pipeline where stage 2 (index 2) fails.
        // pipeline_with_final requires intermediates.len() + 1 == total_stages,
        // so provide all 4 intermediates even though short-circuit stops at stage 2.
        let intermediates: Vec<Outcome<i32, &str>> = vec![
            Outcome::Ok(1),
            Outcome::Ok(2),
            Outcome::Err("stage 3 failed"),
            Outcome::Ok(4), // Never reached due to short-circuit
        ];
        let result = pipeline_with_final(intermediates, Outcome::Ok(999), 5);

        assert!(result.is_failed());
        assert_eq!(result.stages_executed(), 3); // Executed stages 0, 1, 2
        if let PipelineResult::Failed { failed_at, .. } = result {
            assert_eq!(failed_at.index, 2);
            assert_eq!(failed_at.total_stages, 5);
        }
    }

    #[test]
    fn cancelled_stops_at_boundary() {
        let intermediates: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Cancelled(CancelReason::shutdown())];
        let result = pipeline_with_final(intermediates, Outcome::Ok(42), 3);

        assert!(result.is_cancelled());
        // Stage 0 succeeded, stage 1 cancelled
        if let PipelineResult::Cancelled { cancelled_at, .. } = result {
            assert_eq!(cancelled_at.index, 1);
        }
    }

    #[test]
    fn stages_executed_reflects_actual_execution() {
        // All stages complete
        let completed: PipelineResult<i32, &str> = PipelineResult::completed(42, 5);
        assert_eq!(completed.stages_executed(), 5);

        // Failed at stage 2 (index 1)
        let failed: PipelineResult<i32, &str> =
            PipelineResult::failed("err", FailedStage::new(1, 5));
        assert_eq!(failed.stages_executed(), 2); // Stages 0 and 1 were executed

        // Cancelled before stage 3 (index 2)
        let cancelled: PipelineResult<i32, &str> =
            PipelineResult::cancelled(CancelReason::shutdown(), FailedStage::new(2, 5));
        assert_eq!(cancelled.stages_executed(), 2); // Stages 0 and 1 completed
    }

    // =========================================================================
    // Wave 54 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn pipeline_config_debug_clone_copy_eq_default() {
        let cfg = PipelineConfig::default();
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("PipelineConfig"), "{dbg}");
        let copied = cfg;
        let cloned = cfg;
        assert_eq!(copied, cloned);
    }

    #[test]
    fn failed_stage_debug_clone_copy_eq() {
        let fs = FailedStage::new(2, 5);
        let dbg = format!("{fs:?}");
        assert!(dbg.contains("FailedStage"), "{dbg}");
        let copied = fs;
        let cloned = fs;
        assert_eq!(copied, cloned);
        assert_ne!(fs, FailedStage::new(3, 5));
    }

    // =========================================================================
    // Composition laws (conformance suite).
    //
    // The four public pipeline constructors —
    //     pipeline2_outcomes, pipeline3_outcomes,
    //     pipeline_n_outcomes, pipeline_with_final
    // — must agree on every input they can all represent. These laws encode
    // that contract so an accidental short-circuit or failed_at mismatch in
    // one constructor does not escape review.
    // =========================================================================

    mod composition_laws {
        use super::super::*;
        use crate::types::Outcome;
        use crate::types::cancel::CancelReason;

        /// Compare two PipelineResults ignoring Panicked payload identity
        /// (PanicPayload does not implement PartialEq on the inner Any).
        #[track_caller]
        fn assert_same_shape<T: std::fmt::Debug + PartialEq, E: std::fmt::Debug + PartialEq>(
            lhs: &PipelineResult<T, E>,
            rhs: &PipelineResult<T, E>,
        ) {
            match (lhs, rhs) {
                (
                    PipelineResult::Completed {
                        value: v1,
                        stages_completed: s1,
                    },
                    PipelineResult::Completed {
                        value: v2,
                        stages_completed: s2,
                    },
                ) => {
                    assert_eq!(v1, v2, "completed values diverge");
                    assert_eq!(s1, s2, "stages_completed diverges");
                }
                (
                    PipelineResult::Failed {
                        error: e1,
                        failed_at: f1,
                    },
                    PipelineResult::Failed {
                        error: e2,
                        failed_at: f2,
                    },
                ) => {
                    assert_eq!(e1, e2, "failed errors diverge");
                    assert_eq!(f1, f2, "failed_at diverges");
                }
                (
                    PipelineResult::Cancelled {
                        reason: r1,
                        cancelled_at: f1,
                    },
                    PipelineResult::Cancelled {
                        reason: r2,
                        cancelled_at: f2,
                    },
                ) => {
                    assert_eq!(r1, r2, "cancel reasons diverge");
                    assert_eq!(f1, f2, "cancelled_at diverges");
                }
                (
                    PipelineResult::Panicked {
                        panicked_at: f1, ..
                    },
                    PipelineResult::Panicked {
                        panicked_at: f2, ..
                    },
                ) => {
                    assert_eq!(f1, f2, "panicked_at diverges");
                }
                (lhs, rhs) => panic!("variant mismatch:\n  lhs={lhs:?}\n  rhs={rhs:?}"),
            }
        }

        /// LAW-1: `pipeline2_outcomes` and `pipeline_n_outcomes` agree on the
        /// full 2-stage input matrix. Every Outcome shape is checked for both
        /// stages.
        #[test]
        fn law_pipeline2_equiv_pipeline_n_across_outcome_matrix() {
            fn outcomes() -> Vec<Outcome<i32, &'static str>> {
                vec![
                    Outcome::Ok(1),
                    Outcome::Err("boom"),
                    Outcome::Cancelled(CancelReason::user("test")),
                ]
            }
            for o1 in outcomes() {
                for o2 in outcomes() {
                    let lhs = pipeline2_outcomes::<i32, &'static str>(o1.clone(), Some(o2.clone()));
                    let rhs =
                        pipeline_n_outcomes::<i32, &'static str>(vec![o1.clone(), o2.clone()], 2);
                    assert_same_shape(&lhs, &rhs);
                }
            }
        }

        /// LAW-2: `pipeline3_outcomes` and `pipeline_n_outcomes` agree on the
        /// 3-stage matrix. Short-circuit means pipeline3 is only called with
        /// None for stages after a non-Ok, so we only compare the complete
        /// [Ok, Ok, X] and [Ok, X] branches.
        #[test]
        fn law_pipeline3_equiv_pipeline_n() {
            let terminal_shapes: Vec<Outcome<i32, &'static str>> = vec![
                Outcome::Ok(3),
                Outcome::Err("boom"),
                Outcome::Cancelled(CancelReason::user("test")),
            ];
            // All-three-stages-executed branch: [Ok, Ok, X]
            for term in terminal_shapes.iter() {
                let lhs = pipeline3_outcomes::<i32, &'static str>(
                    Outcome::Ok(1),
                    Some(Outcome::Ok(2)),
                    Some(term.clone()),
                );
                let rhs = pipeline_n_outcomes::<i32, &'static str>(
                    vec![Outcome::Ok(1), Outcome::Ok(2), term.clone()],
                    3,
                );
                assert_same_shape(&lhs, &rhs);
            }
            // Short-circuit at stage 2: [Ok, X, None]. pipeline_n sees the
            // 2-element vec since the third stage never ran.
            for term in terminal_shapes
                .iter()
                .filter(|o| !matches!(o, Outcome::Ok(_)))
            {
                let lhs = pipeline3_outcomes::<i32, &'static str>(
                    Outcome::Ok(1),
                    Some(term.clone()),
                    None,
                );
                let rhs =
                    pipeline_n_outcomes::<i32, &'static str>(vec![Outcome::Ok(1), term.clone()], 3);
                assert_same_shape(&lhs, &rhs);
            }
        }

        /// LAW-3: `pipeline_with_final` agrees with `pipeline_n_outcomes` when
        /// the caller supplies a full run (intermediates.len() + 1 == total).
        #[test]
        fn law_pipeline_with_final_equiv_pipeline_n_for_complete_runs() {
            let sample: Vec<Outcome<i32, &'static str>> =
                vec![Outcome::Ok(10), Outcome::Ok(20), Outcome::Ok(30)];
            let final_variants: Vec<Outcome<i32, &'static str>> = vec![
                Outcome::Ok(99),
                Outcome::Err("late"),
                Outcome::Cancelled(CancelReason::user("test")),
            ];
            for final_out in final_variants {
                let mut full = sample.clone();
                full.push(final_out.clone());
                let total = full.len();
                let lhs =
                    pipeline_with_final::<i32, &'static str>(sample.clone(), final_out, total);
                let rhs = pipeline_n_outcomes::<i32, &'static str>(full, total);
                assert_same_shape(&lhs, &rhs);
            }
        }

        /// LAW-4: Short-circuit is strict — a non-Ok at index N makes the
        /// result depend only on outcomes[..=N]. Trailing Oks in the vec are
        /// ignored, i.e. passing them vs truncating yields the same result.
        #[test]
        fn law_short_circuit_ignores_trailing_outcomes() {
            let with_trailing: Vec<Outcome<i32, &'static str>> = vec![
                Outcome::Ok(1),
                Outcome::Err("midway"),
                Outcome::Ok(999),    // ignored
                Outcome::Ok(12_345), // ignored
            ];
            let truncated: Vec<Outcome<i32, &'static str>> = with_trailing[..2].to_vec();
            let lhs = pipeline_n_outcomes::<i32, &'static str>(with_trailing, 5);
            let rhs = pipeline_n_outcomes::<i32, &'static str>(truncated, 5);
            assert_same_shape(&lhs, &rhs);
        }

        /// LAW-5: `failed_at.total_stages` is exactly the caller-supplied
        /// total across every failure mode in every constructor, even when
        /// the vec is shorter than total.
        #[test]
        fn law_failed_at_total_stages_is_preserved() {
            for &total in &[1usize, 2, 3, 5, 10] {
                // 2-variant: o1 fails
                let r = pipeline2_outcomes::<i32, &'static str>(Outcome::Err("x"), None);
                if let PipelineResult::Failed { failed_at, .. } = r {
                    assert_eq!(failed_at.total_stages, 2);
                }
                // n-variant: fail at index 0 with various totals
                let r =
                    pipeline_n_outcomes::<i32, &'static str>(vec![Outcome::Err("x")], total.max(1));
                if let PipelineResult::Failed { failed_at, .. } = r {
                    assert_eq!(failed_at.total_stages, total.max(1));
                    assert_eq!(failed_at.index, 0);
                }
            }
        }

        /// LAW-6: Cancel and panic precedence — a Cancelled or Panicked at
        /// index N wins over any later Ok/Err in the vec. Distinct from a
        /// plain Err because the failure category carries different recovery
        /// semantics downstream.
        #[test]
        fn law_cancelled_and_panicked_beat_later_outcomes() {
            let vec_with_late_ok: Vec<Outcome<i32, &'static str>> = vec![
                Outcome::Ok(1),
                Outcome::Cancelled(CancelReason::user("test")),
                Outcome::Ok(2),
            ];
            let r = pipeline_n_outcomes::<i32, &'static str>(vec_with_late_ok, 3);
            match r {
                PipelineResult::Cancelled { cancelled_at, .. } => {
                    assert_eq!(cancelled_at.index, 1);
                    assert_eq!(cancelled_at.total_stages, 3);
                }
                other => panic!("expected Cancelled, got {other:?}"),
            }

            let vec_with_panic: Vec<Outcome<i32, &'static str>> = vec![
                Outcome::Ok(1),
                Outcome::Panicked(PanicPayload::new("boom")),
                Outcome::Err("late"),
            ];
            let r = pipeline_n_outcomes::<i32, &'static str>(vec_with_panic, 3);
            match r {
                PipelineResult::Panicked { panicked_at, .. } => {
                    assert_eq!(panicked_at.index, 1);
                    assert_eq!(panicked_at.total_stages, 3);
                }
                other => panic!("expected Panicked, got {other:?}"),
            }
        }

        /// LAW-7: Single-stage identity — pipeline_n_outcomes of a single Ok
        /// equals Completed(value, 1).
        #[test]
        fn law_single_stage_ok_is_identity() {
            let r = pipeline_n_outcomes::<i32, &'static str>(vec![Outcome::Ok(42)], 1);
            match r {
                PipelineResult::Completed {
                    value,
                    stages_completed,
                } => {
                    assert_eq!(value, 42);
                    assert_eq!(stages_completed, 1);
                }
                other => panic!("expected Completed(42, 1), got {other:?}"),
            }
        }

        /// LAW-8: Completion is total — an all-Ok vec shorter than
        /// total_stages is invalid constructor input, never a Completed
        /// result.
        #[test]
        fn law_all_ok_partial_run_is_rejected() {
            let result = std::panic::catch_unwind(|| {
                pipeline_n_outcomes::<i32, &'static str>(vec![Outcome::Ok(1), Outcome::Ok(2)], 5)
            });
            assert!(
                result.is_err(),
                "an incomplete all-Ok run must not produce a PipelineResult"
            );
        }
    }
}
