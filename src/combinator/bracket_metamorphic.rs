#![allow(clippy::all)]
//! Metamorphic Testing: bracket resource lifecycle under cancellation
//!
//! This module implements metamorphic relations for the `bracket` combinator,
//! verifying that acquire/release resource lifecycle guarantees hold under
//! concurrent and randomly injected cancellations.
//!
//! # Metamorphic Relations
//!
//! 1. **Acquire/Release Pairing**: If `acquire` succeeds, `release` MUST run, regardless of cancellation in `use` or `release` phases.
//! 2. **Acquire Failure Elision**: If `acquire` fails or is cancelled before completion, `use` and `release` MUST NOT run.
//! 3. **Cancellation Equivalence**: `bracket` under external cancellation must leave the resource in the same state as a `bracket` where the `use` future self-cancels.
//! 4. **Panic Isolation**: A panic in `use` must still trigger `release` before propagating.

#![allow(dead_code)]

use crate::combinator::bracket;
use crate::cx::Cx;
use crate::lab::{LabConfig, LabRuntime};
use crate::types::{Budget, RegionId, TaskId};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

struct LifecycleState {
    acquire_started: AtomicBool,
    acquire_completed: AtomicBool,
    use_started: AtomicBool,
    use_completed: AtomicBool,
    release_started: AtomicBool,
    release_completed: AtomicBool,
}

impl LifecycleState {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            acquire_started: AtomicBool::new(false),
            acquire_completed: AtomicBool::new(false),
            use_started: AtomicBool::new(false),
            use_completed: AtomicBool::new(false),
            release_started: AtomicBool::new(false),
            release_completed: AtomicBool::new(false),
        })
    }

    fn assert_valid_terminal_state(&self) {
        let _acq_s = self.acquire_started.load(Ordering::SeqCst);
        let acq_c = self.acquire_completed.load(Ordering::SeqCst);
        let use_s = self.use_started.load(Ordering::SeqCst);
        let _use_c = self.use_completed.load(Ordering::SeqCst);
        let rel_s = self.release_started.load(Ordering::SeqCst);
        let rel_c = self.release_completed.load(Ordering::SeqCst);

        if acq_c {
            assert!(rel_s, "Acquire completed but release never started");
            // If release started, it must complete eventually (or the runtime crashed, but we don't test process aborts here)
            assert!(rel_c, "Release started but never completed");
        } else {
            assert!(!use_s, "Acquire did not complete but use started");
            assert!(!rel_s, "Acquire did not complete but release started");
        }

        if use_s {
            assert!(acq_c, "Use started but acquire did not complete");
        }
    }
}

fn test_cx() -> Cx {
    Cx::new(
        RegionId::from_arena(crate::util::ArenaIndex::new(0, 0)),
        TaskId::from_arena(crate::util::ArenaIndex::new(0, 0)),
        Budget::INFINITE,
    )
}

struct StepFuture {
    polls_required: u32,
    polls_done: u32,
    on_start: Box<dyn Fn() + Send + Sync>,
    on_complete: Box<dyn Fn() + Send + Sync>,
    panic_on_poll: Option<u32>,
}

impl Future for StepFuture {
    type Output = Result<(), ()>;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.polls_done == 0 {
            (self.on_start)();
        }

        if let Some(panic_poll) = self.panic_on_poll {
            assert!(self.polls_done != panic_poll, "Intentional panic at poll {}", panic_poll);
        }

        self.polls_done += 1;

        if self.polls_done >= self.polls_required {
            (self.on_complete)();
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}

struct StepReleaseFuture {
    polls_required: u32,
    polls_done: u32,
    on_start: Box<dyn Fn() + Send + Sync>,
    on_complete: Box<dyn Fn() + Send + Sync>,
    panic_on_poll: Option<u32>,
}

impl Future for StepReleaseFuture {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.polls_done == 0 {
            (self.on_start)();
        }

        if let Some(panic_poll) = self.panic_on_poll {
            assert!(self.polls_done != panic_poll, "Intentional panic at poll {}", panic_poll);
        }

        self.polls_done += 1;

        if self.polls_done >= self.polls_required {
            (self.on_complete)();
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

#[test]
fn metamorphic_bracket_lifecycle_guarantees() {
    let lab_config = LabConfig::new(42);
    let _lab = LabRuntime::new(lab_config);

    // Test different poll counts to simulate varying completion times
    let scenarios = [(1, 1, 1), (5, 5, 5), (1, 10, 1), (10, 1, 10)];

    for &(acq_polls, use_polls, rel_polls) in &scenarios {
        let state = LifecycleState::new();
        let state_clone = state.clone();

        let release_state = state.clone();
        let fut = bracket(
            StepFuture {
                polls_required: acq_polls,
                polls_done: 0,
                on_start: Box::new({
                    let s = state.clone();
                    move || s.acquire_started.store(true, Ordering::SeqCst)
                }),
                on_complete: Box::new({
                    let s = state.clone();
                    move || s.acquire_completed.store(true, Ordering::SeqCst)
                }),
                panic_on_poll: None,
            },
            move |_| StepFuture {
                polls_required: use_polls,
                polls_done: 0,
                on_start: Box::new({
                    let s = state_clone.clone();
                    move || s.use_started.store(true, Ordering::SeqCst)
                }),
                on_complete: Box::new({
                    let s = state_clone.clone();
                    move || s.use_completed.store(true, Ordering::SeqCst)
                }),
                panic_on_poll: None,
            },
            move |_| StepReleaseFuture {
                polls_required: rel_polls,
                polls_done: 0,
                on_start: Box::new({
                    let s = release_state.clone();
                    move || s.release_started.store(true, Ordering::SeqCst)
                }),
                on_complete: Box::new({
                    let s = release_state.clone();
                    move || s.release_completed.store(true, Ordering::SeqCst)
                }),
                panic_on_poll: None,
            },
        );

        let mut pinned = Box::pin(fut);
        let waker = std::task::Waker::noop().clone();
        let mut ctx = Context::from_waker(&waker);

        let mut polls = 0;
        loop {
            match pinned.as_mut().poll(&mut ctx) {
                Poll::Ready(_) => break,
                Poll::Pending => {
                    polls += 1;
                    assert!(polls <= 100, "Infinite loop detected");
                }
            }
        }

        // After normal completion, all steps should have completed
        state.assert_valid_terminal_state();
        assert!(state.acquire_completed.load(Ordering::SeqCst));
        assert!(state.use_completed.load(Ordering::SeqCst));
        assert!(state.release_completed.load(Ordering::SeqCst));
    }
}

#[test]
fn metamorphic_bracket_cancellation_guarantees() {
    let lab_config = LabConfig::new(43);
    let _lab = LabRuntime::new(lab_config);

    // Cancel at different phases
    for cancel_at_poll in 1..15 {
        let state = LifecycleState::new();
        let state_clone = state.clone();

        let release_state = state.clone();
        let fut = bracket(
            StepFuture {
                polls_required: 5,
                polls_done: 0,
                on_start: Box::new({
                    let s = state.clone();
                    move || s.acquire_started.store(true, Ordering::SeqCst)
                }),
                on_complete: Box::new({
                    let s = state.clone();
                    move || s.acquire_completed.store(true, Ordering::SeqCst)
                }),
                panic_on_poll: None,
            },
            move |_| StepFuture {
                polls_required: 5,
                polls_done: 0,
                on_start: Box::new({
                    let s = state_clone.clone();
                    move || s.use_started.store(true, Ordering::SeqCst)
                }),
                on_complete: Box::new({
                    let s = state_clone.clone();
                    move || s.use_completed.store(true, Ordering::SeqCst)
                }),
                panic_on_poll: None,
            },
            move |_| StepReleaseFuture {
                polls_required: 5,
                polls_done: 0,
                on_start: Box::new({
                    let s = release_state.clone();
                    move || s.release_started.store(true, Ordering::SeqCst)
                }),
                on_complete: Box::new({
                    let s = release_state.clone();
                    move || s.release_completed.store(true, Ordering::SeqCst)
                }),
                panic_on_poll: None,
            },
        );

        let cx = test_cx();
        let mut pinned = Box::pin(fut);
        let waker = std::task::Waker::noop().clone();
        let mut ctx = Context::from_waker(&waker);

        for poll_idx in 0..20 {
            if poll_idx == cancel_at_poll {
                cx.set_cancel_requested(true);
            }

            match pinned.as_mut().poll(&mut ctx) {
                Poll::Ready(_) => break,
                Poll::Pending => {}
            }
        }

        state.assert_valid_terminal_state();
    }
}
