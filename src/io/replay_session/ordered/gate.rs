use super::super::RecordedSession;
use super::pending::{PendingInput, PendingIoCaptureLimits, PendingRequest};
use crate::io::replay::IoOperation;
use parking_lot::Mutex;
use std::task::{Context, Poll, Waker};

/// An observable effect category; payloads and random values are never included.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderedEffect {
    /// One duplex I/O operation (a pending attempt in poll-aware sessions).
    Io(IoOperation),
    /// One serial clock observation.
    Clock,
    /// A byte/u64 entropy read on a source ordinal (root is zero).
    Entropy(usize),
    /// A fork on a source ordinal. The child ordinal is retained separately.
    Fork(usize),
}

/// Why a complete cross-provider ordering window cannot be returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum OrderCaptureError {
    /// Too many completed effects for the caller's explicit limit.
    #[error("ordered capture effect limit exceeded")]
    Limit,
    /// Bounded ordering storage could not be reserved.
    #[error("ordered capture allocation failed")]
    Allocation,
    /// Provider calls overlapped or reentered; completion attribution is ambiguous.
    #[error("ordered capture observed overlapping provider calls")]
    Overlap,
    /// A provider call unwound without a completed result.
    #[error("ordered capture contains an interrupted provider call")]
    Interrupted,
    /// A provider call was outstanding at the end of the window.
    #[error("ordered capture has an outstanding provider call")]
    InFlight,
    /// The ordering window was already extracted or refused.
    #[error("ordered capture is already finished")]
    Finished,
    /// The order's component counts/source topology disagree with the tapes.
    #[error("ordered capture does not cover its component windows")]
    InconsistentWindow,
    /// Additional pending-poll/hash/vector admission was exceeded.
    #[error("ordered capture exceeded its pending I/O {0} limit")]
    PendingLimit(&'static str),
}

/// Redacted classification of the first cross-provider replay failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderReplayMismatch {
    /// An extra effect was attempted after the order ended.
    Exhausted,
    /// A synchronous effect or same-direction I/O operation was out of order.
    Effect,
    /// Another admitted effect was still running.
    Overlap,
    /// An admitted effect unwound before returning.
    Interrupted,
    /// An underlying tape diverged or could not satisfy its admitted turn.
    Component,
}

/// Sticky session-wide ordering failure, without captured values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("ordered replay diverged at effect {index}: {reason:?}, expected {expected:?}, actual {actual:?}")]
pub struct OrderReplayError {
    /// Zero-based order index, including pending I/O in poll-aware sessions.
    pub index: usize,
    /// Expected category/source, absent at exhaustion.
    pub expected: Option<OrderedEffect>,
    /// Attempted category/source.
    pub actual: OrderedEffect,
    /// First refusal classification.
    pub reason: OrderReplayMismatch,
}

/// Complete consumption is required even if the consumer returns successfully.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OrderCompletionError {
    /// At least one effect diverged, including ignored errors or caught panics.
    #[error(transparent)]
    Diverged(OrderReplayError),
    /// A prefix was consumed, not the complete ordering window.
    #[error("ordered replay has {remaining} unconsumed effects")]
    Remaining {
        /// Effects not yet consumed.
        remaining: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Entry {
    pub(super) effect: OrderedEffect,
    // Zero except for Fork, where children are allocated in global fork order.
    pub(super) child: usize,
    pub(super) pending: Option<PendingRequest>,
}

pub(super) struct OrderTape {
    pub(super) entries: Vec<Entry>,
    pub(super) poll_aware: bool,
}

impl OrderTape {
    // This checks coverage/topology without reading any provider. Component
    // request values/shape are still checked by their own replayers.
    pub(super) fn covers(&self, components: &RecordedSession) -> bool {
        let (mut io, mut entropy, mut clock, mut sources) = (0usize, 0usize, 0usize, 1usize);
        for entry in &self.entries {
            if !matches!(entry.effect, OrderedEffect::Fork(_)) && entry.child != 0 {
                return false;
            }
            if let Some(request) = &entry.pending {
                let OrderedEffect::Io(operation) = entry.effect else { return false };
                if !self.poll_aware || !request.valid_for(operation) { return false; }
                // Pending attempts have no completed result in the I/O tape.
                continue;
            }
            match entry.effect {
                OrderedEffect::Io(_) => io += 1,
                OrderedEffect::Clock => clock += 1,
                OrderedEffect::Entropy(source) if source < sources => entropy += 1,
                OrderedEffect::Fork(source) if source < sources && entry.child == sources => {
                    entropy += 1;
                    let Some(next) = sources.checked_add(1) else { return false };
                    sources = next;
                }
                OrderedEffect::Entropy(_) | OrderedEffect::Fork(_) => return false,
            }
        }
        io == components.io_operations()
            && entropy == components.entropy_calls()
            && clock == components.clock_observations()
            && sources == components.entropy.streams()
    }
}

struct RecordState {
    pending_limits: Option<PendingIoCaptureLimits>,
    pending_polls: usize,
    pending_bytes: usize,
    entries: Vec<Entry>,
    limit: usize,
    sources: usize,
    active: bool,
    finished: bool,
    failure: Option<OrderCaptureError>,
}

pub(super) struct RecordOrder(Mutex<RecordState>);

impl RecordOrder {
    pub(super) fn new(limit: usize) -> Self {
        Self::with_pending(limit, None)
    }

    pub(super) fn with_pending(limit: usize, pending_limits: Option<PendingIoCaptureLimits>) -> Self {
        Self(Mutex::new(RecordState {
            pending_limits, pending_polls: 0, pending_bytes: 0,
            entries: Vec::new(), limit, sources: 1, active: false,
            finished: false, failure: None,
        }))
    }

    pub(super) fn begin(&self) -> Option<RecordGuard<'_>> {
        let mut state = self.0.lock();
        if state.finished || state.failure.is_some() {
            return None;
        }
        if state.active {
            state.failure = Some(OrderCaptureError::Overlap);
            return None;
        }
        state.active = true;
        Some(RecordGuard { order: self, completed: false })
    }

    pub(super) fn finish(&self) -> Result<OrderTape, OrderCaptureError> {
        let mut state = self.0.lock();
        if state.finished { return Err(OrderCaptureError::Finished); }
        state.finished = true;
        if state.active { state.failure.get_or_insert(OrderCaptureError::InFlight); }
        let tape = OrderTape {
            entries: std::mem::take(&mut state.entries),
            poll_aware: state.pending_limits.is_some(),
        };
        match state.failure {
            Some(error) => Err(error),
            None => Ok(tape),
        }
    }
}

pub(super) struct RecordGuard<'a> {
    order: &'a RecordOrder,
    completed: bool,
}

impl RecordGuard<'_> {
    pub(super) fn finish(self, effect: OrderedEffect, ready: bool) -> usize {
        self.finish_entry(effect, ready, None)
    }

    pub(super) fn finish_io(self, input: PendingInput<'_, '_>, ready: bool) {
        let effect = OrderedEffect::Io(input.operation());
        if ready {
            self.finish(effect, true);
            return;
        }
        let extent = self.admit_pending(input);
        let pending = extent.and_then(|extent| input.snapshot(extent));
        if extent.is_some() && pending.is_none() {
            self.order.0.lock().failure.get_or_insert(OrderCaptureError::InconsistentWindow);
        }
        self.finish_entry(effect, pending.is_some(), pending);
    }

    fn admit_pending(&self, input: PendingInput<'_, '_>) -> Option<usize> {
        let mut state = self.order.0.lock();
        let limits = state.pending_limits?;
        if state.finished || state.failure.is_some() { return None; }
        let failure = if state.entries.len() == state.limit {
            Some(OrderCaptureError::Limit)
        } else if state.pending_polls >= limits.max_polls {
            Some(OrderCaptureError::PendingLimit("polls"))
        } else if input.slices() > limits.max_vectored_slices {
            Some(OrderCaptureError::PendingLimit("vectored slices"))
        } else { None };
        if let Some(error) = failure {
            state.failure = Some(error);
            return None;
        }
        let Some(extent) = input.extent() else {
            state.failure = Some(OrderCaptureError::InconsistentWindow);
            return None;
        };
        let bytes = if input.is_write() { extent } else { 0 };
        if bytes > limits.max_write_bytes - state.pending_bytes {
            state.failure = Some(OrderCaptureError::PendingLimit("write bytes"));
            return None;
        }
        state.pending_polls += 1;
        state.pending_bytes += bytes;
        Some(extent)
    }

    fn finish_entry(mut self, effect: OrderedEffect, ready: bool, pending: Option<PendingRequest>) -> usize {
        let mut state = self.order.0.lock();
        state.active = false;
        self.completed = true;
        if !ready || state.finished || state.failure.is_some() { return 0; }
        if state.entries.len() == state.limit {
            state.failure = Some(OrderCaptureError::Limit);
            return 0;
        }
        if state.entries.len() == state.entries.capacity() {
            let additional = (state.limit - state.entries.len()).min(state.entries.len().max(8));
            if state.entries.try_reserve_exact(additional).is_err() {
                state.failure = Some(OrderCaptureError::Allocation);
                return 0;
            }
        }
        let child = if matches!(effect, OrderedEffect::Fork(_)) {
            let child = state.sources;
            let Some(next) = child.checked_add(1) else {
                state.failure = Some(OrderCaptureError::Limit);
                return 0;
            };
            state.sources = next;
            child
        } else { 0 };
        state.entries.push(Entry { effect, child, pending });
        child
    }
}

impl Drop for RecordGuard<'_> {
    fn drop(&mut self) {
        if !self.completed {
            let mut state = self.order.0.lock();
            state.active = false;
            state.failure.get_or_insert(OrderCaptureError::Interrupted);
        }
    }
}

struct ReplayState {
    tape: OrderTape,
    index: usize,
    active: bool,
    failure: Option<OrderReplayError>,
    waiters: [Option<Waker>; 2],
}

impl ReplayState {
    fn refuse(&mut self, actual: OrderedEffect, reason: OrderReplayMismatch) -> OrderReplayError {
        *self.failure.get_or_insert(OrderReplayError {
            index: self.index,
            expected: self.tape.entries.get(self.index).map(|entry| entry.effect),
            actual, reason,
        })
    }

    fn check(&mut self, actual: OrderedEffect) -> Result<Entry, OrderReplayError> {
        if let Some(error) = self.failure { return Err(error); }
        if self.active { return Err(self.refuse(actual, OrderReplayMismatch::Overlap)); }
        self.tape.entries.get(self.index).cloned()
            .ok_or_else(|| self.refuse(actual, OrderReplayMismatch::Exhausted))
    }
}

pub(super) struct ReplayOrder(Mutex<ReplayState>);

impl ReplayOrder {
    pub(super) fn new(tape: OrderTape) -> Self {
        Self(Mutex::new(ReplayState {
            tape, index: 0, active: false, failure: None, waiters: [None, None],
        }))
    }

    pub(super) fn enter(&self, actual: OrderedEffect) -> Result<ReplayGuard<'_>, OrderReplayError> {
        let result = {
            let mut state = self.0.lock();
            match state.check(actual) {
                Ok(entry) if entry.effect == actual => { state.active = true; Ok(entry) }
                Ok(_) => Err(state.refuse(actual, OrderReplayMismatch::Effect)),
                Err(error) => Err(error),
            }
        };
        if result.is_err() { self.wake_waiters(); }
        result.map(|entry| ReplayGuard { order: self, entry, completed: false })
    }

    pub(super) fn enter_io(
        &self, cx: &mut Context<'_>, operation: IoOperation,
    ) -> Poll<Result<ReplayGuard<'_>, OrderReplayError>> {
        // Clone/drop/wake callbacks MUST stay outside the order mutex. Keep the
        // guard alive before dropping a candidate, so unwinding poisons admission.
        let mut candidate = Some(cx.waker().clone());
        let mut old = None;
        let actual = OrderedEffect::Io(operation);
        let result = {
            let mut state = self.0.lock();
            match state.check(actual) {
                Ok(entry) if entry.effect == actual => {
                    state.active = true;
                    Poll::Ready(Ok(entry))
                }
                Ok(entry) if !state.tape.poll_aware && can_wait(operation, entry.effect) => {
                    let slot = usize::from(operation != IoOperation::Read);
                    old = std::mem::replace(&mut state.waiters[slot], candidate.take());
                    Poll::Pending
                }
                Ok(_) => Poll::Ready(Err(state.refuse(actual, OrderReplayMismatch::Effect))),
                Err(error) => Poll::Ready(Err(error)),
            }
        };
        let result = result.map(|result| result.map(|entry| ReplayGuard {
            order: self, entry, completed: false,
        }));
        drop(old);
        drop(candidate);
        if matches!(&result, Poll::Ready(Err(_))) { self.wake_waiters(); }
        result
    }

    pub(super) fn clear_waiters(&self) {
        let waiters = { std::mem::take(&mut self.0.lock().waiters) };
        // Cleanup can run while another panic is unwinding. Attempt every
        // destructor without holding the mutex or allowing one to skip the rest.
        for waker in waiters.into_iter().flatten() {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(waker)));
        }
    }

    fn wake_waiters(&self) {
        let waiters = { std::mem::take(&mut self.0.lock().waiters) };
        for waker in waiters.into_iter().flatten() {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| waker.wake()));
        }
    }

    pub(super) fn verify(&self) -> Result<(), OrderCompletionError> {
        let state = self.0.lock();
        if let Some(error) = state.failure { return Err(OrderCompletionError::Diverged(error)); }
        let remaining = state.tape.entries.len() - state.index;
        if remaining != 0 { return Err(OrderCompletionError::Remaining { remaining }); }
        Ok(())
    }
}

fn can_wait(actual: IoOperation, expected: OrderedEffect) -> bool {
    match expected {
        OrderedEffect::Io(operation) => (actual == IoOperation::Read) != (operation == IoOperation::Read),
        _ => true,
    }
}

pub(super) struct ReplayGuard<'a> {
    order: &'a ReplayOrder,
    entry: Entry,
    completed: bool,
}

impl ReplayGuard<'_> {
    pub(super) fn child(&self) -> usize { self.entry.child }

    pub(super) fn pending_request(&self) -> Option<&PendingRequest> {
        self.entry.pending.as_ref()
    }

    pub(super) fn finish(mut self, valid: bool) -> Result<(), OrderReplayError> {
        let result = {
            let mut state = self.order.0.lock();
            state.active = false;
            if !valid { state.refuse(self.entry.effect, OrderReplayMismatch::Component); }
            match state.failure {
                Some(error) => Err(error),
                None => { state.index += 1; Ok(()) }
            }
        };
        self.completed = true;
        self.order.wake_waiters();
        result
    }
}

impl Drop for ReplayGuard<'_> {
    fn drop(&mut self) {
        if !self.completed {
            {
                let mut state = self.order.0.lock();
                state.active = false;
                state.refuse(self.entry.effect, OrderReplayMismatch::Interrupted);
            }
            self.order.wake_waiters();
        }
    }
}
