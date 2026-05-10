//! Fuzz oneshot poll-after-await Future contract compliance.
//!
//! Tests arbitrary post-await poll patterns to ensure that after a Future
//! returns Poll::Ready, subsequent polls return Poll::Pending or panic
//! per std::future contract. Validates proper Future state management
//! and PolledAfterCompletion handling.
//!
//! Critical invariants:
//! - Poll after Ready → Pending or panic (never Ready again)
//! - Receiver future properly tracks completion state
//! - Multiple awaits on same receiver handle appropriately
//! - Double-consumption patterns behave consistently

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use asupersync::{Cx, channel::oneshot};
use futures::executor::block_on;
use futures::task::noop_waker;
use libfuzzer_sys::fuzz_target;
use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::task::{Context, Poll};
use std::thread;
use std::time::Duration;

const MAX_AWAIT_ATTEMPTS: usize = 20;
const MAX_EXTRA_POST_COMPLETION_POLLS: usize = 5;
const MAX_RAPID_POLLS: usize = 10;

#[derive(Debug, Clone, Arbitrary)]
struct AwaitConfig {
    /// Value to send through the channel
    sent_value: u32,
    /// Number of await attempts after completion
    post_completion_awaits: u8,
    /// Patterns of await timing
    await_patterns: Vec<AwaitPattern>,
    /// Whether to test concurrent double-await
    test_concurrency: bool,
}

#[derive(Debug, Clone, Arbitrary)]
enum AwaitPattern {
    /// Await immediately after first completion
    Immediate,
    /// Await after small delay
    DelayedAwait { delay_millis: u8 },
    /// Multiple rapid await attempts
    RapidSequence { count: u8 },
    /// Await in separate thread
    ConcurrentAwait,
}

#[derive(Debug, Clone, Arbitrary)]
struct AwaitSequence {
    /// Test configuration
    config: AwaitConfig,
    /// Maximum await attempts to perform
    max_awaits: u8,
}

/// Test execution context tracking await behavior
#[derive(Debug)]
struct AwaitTracker {
    fresh_successes: AtomicUsize,
    post_completion_rejections: AtomicUsize,
    post_completion_panics: AtomicUsize,
    post_completion_pending: AtomicUsize,
    join_failures: AtomicUsize,
}

impl AwaitTracker {
    fn new() -> Self {
        Self {
            fresh_successes: AtomicUsize::new(0),
            post_completion_rejections: AtomicUsize::new(0),
            post_completion_panics: AtomicUsize::new(0),
            post_completion_pending: AtomicUsize::new(0),
            join_failures: AtomicUsize::new(0),
        }
    }

    fn record_fresh_success(&self) {
        self.fresh_successes.fetch_add(1, Ordering::Relaxed);
    }

    fn record_post_completion_rejection(&self) {
        self.post_completion_rejections
            .fetch_add(1, Ordering::Relaxed);
    }

    fn record_post_completion_panic(&self) {
        self.post_completion_panics.fetch_add(1, Ordering::Relaxed);
    }

    fn record_post_completion_pending(&self) {
        self.post_completion_pending.fetch_add(1, Ordering::Relaxed);
    }

    fn record_join_failure(&self) {
        self.join_failures.fetch_add(1, Ordering::Relaxed);
    }

    fn check_future_contract(&self) -> Result<(), String> {
        let fresh_successes = self.fresh_successes.load(Ordering::Relaxed);
        if fresh_successes == 0 {
            return Err("no successful baseline oneshot await was observed".to_string());
        }

        let join_failures = self.join_failures.load(Ordering::Relaxed);
        if join_failures > 0 {
            return Err(format!(
                "concurrent post-completion probes had {join_failures} join failures"
            ));
        }

        Ok(())
    }
}

fn await_fresh_channel_once(
    value: u32,
    tracker: &AwaitTracker,
    label: &str,
) -> Result<u32, String> {
    let cx = Cx::for_testing();
    let (sender, mut receiver) = oneshot::channel::<u32>();
    sender
        .send_blocking(value)
        .map_err(|err| format!("{label}: send_blocking failed: {err:?}"))?;

    match block_on(receiver.recv(&cx)) {
        Ok(received) if received == value => {
            tracker.record_fresh_success();
            Ok(received)
        }
        Ok(received) => Err(format!("{label}: expected {value}, received {received}")),
        Err(err) => Err(format!("{label}: recv failed before completion: {err:?}")),
    }
}

fn poll_completed_recv_future_once(
    value: u32,
    tracker: &AwaitTracker,
    label: &str,
) -> Result<(), String> {
    let cx = Cx::for_testing();
    let (sender, mut receiver) = oneshot::channel::<u32>();
    sender
        .send_blocking(value)
        .map_err(|err| format!("{label}: send_blocking failed: {err:?}"))?;

    let mut recv_future = Box::pin(receiver.recv(&cx));
    let waker = noop_waker();
    let mut task_cx = Context::from_waker(&waker);

    match recv_future.as_mut().poll(&mut task_cx) {
        Poll::Ready(Ok(received)) if received == value => tracker.record_fresh_success(),
        Poll::Ready(Ok(received)) => {
            return Err(format!(
                "{label}: first poll expected {value}, received {received}"
            ));
        }
        Poll::Ready(Err(err)) => {
            return Err(format!("{label}: first poll failed: {err:?}"));
        }
        Poll::Pending => {
            return Err(format!(
                "{label}: first poll was pending despite a pre-sent value"
            ));
        }
    }

    let second_poll = catch_unwind(AssertUnwindSafe(|| recv_future.as_mut().poll(&mut task_cx)));
    match second_poll {
        Ok(Poll::Ready(Ok(second_value))) => Err(format!(
            "{label}: Future contract violation: second poll returned Ok({second_value})"
        )),
        Ok(Poll::Ready(Err(oneshot::RecvError::PolledAfterCompletion))) => {
            tracker.record_post_completion_rejection();
            Ok(())
        }
        Ok(Poll::Ready(Err(_))) => {
            tracker.record_post_completion_rejection();
            Ok(())
        }
        Ok(Poll::Pending) => {
            tracker.record_post_completion_pending();
            Ok(())
        }
        Err(_) => {
            tracker.record_post_completion_panic();
            Ok(())
        }
    }
}

/// Test double-await and post-completion poll behavior.
fn test_double_await_behavior(sequence: &AwaitSequence) -> Result<(), String> {
    let tracker = Arc::new(AwaitTracker::new());

    // First await on a fresh channel should succeed and preserve the value.
    let received_value =
        await_fresh_channel_once(sequence.config.sent_value, &tracker, "baseline")?;

    let extra_polls =
        usize::from(sequence.config.post_completion_awaits).min(MAX_EXTRA_POST_COMPLETION_POLLS);
    for idx in 0..extra_polls {
        let value = received_value.wrapping_add(idx as u32);
        poll_completed_recv_future_once(value, &tracker, "extra post-completion poll")?;
    }

    let max_patterns = usize::from(sequence.max_awaits).clamp(1, MAX_AWAIT_ATTEMPTS);
    for (pattern_idx, pattern) in sequence
        .config
        .await_patterns
        .iter()
        .take(max_patterns)
        .enumerate()
    {
        match pattern {
            AwaitPattern::Immediate => {
                poll_completed_recv_future_once(
                    received_value.wrapping_add(pattern_idx as u32),
                    &tracker,
                    "immediate post-completion poll",
                )?;
            }

            AwaitPattern::DelayedAwait { delay_millis } => {
                thread::sleep(Duration::from_millis(u64::from(*delay_millis).min(2)));
                poll_completed_recv_future_once(
                    received_value.wrapping_add(pattern_idx as u32),
                    &tracker,
                    "delayed post-completion poll",
                )?;
            }

            AwaitPattern::RapidSequence { count } => {
                for rapid_idx in 0..usize::from((*count).min(MAX_RAPID_POLLS as u8)) {
                    let value = received_value
                        .wrapping_add(pattern_idx as u32)
                        .wrapping_add(rapid_idx as u32);
                    poll_completed_recv_future_once(value, &tracker, "rapid post-completion poll")?;
                }
            }

            AwaitPattern::ConcurrentAwait => {
                if !sequence.config.test_concurrency {
                    poll_completed_recv_future_once(
                        received_value.wrapping_add(pattern_idx as u32),
                        &tracker,
                        "concurrency-disabled post-completion poll",
                    )?;
                    continue;
                }

                let handles = (0u32..3)
                    .map(|_| {
                        let tracker = Arc::clone(&tracker);
                        let value = received_value.wrapping_add(pattern_idx as u32);
                        thread::spawn(move || {
                            poll_completed_recv_future_once(
                                value,
                                &tracker,
                                "concurrent post-completion poll",
                            )
                        })
                    })
                    .collect::<Vec<_>>();

                for handle in handles {
                    match handle.join() {
                        Ok(Ok(())) => {}
                        Ok(Err(err)) => return Err(err),
                        Err(_) => {
                            tracker.record_join_failure();
                            return Err(
                                "concurrent post-completion poll thread panicked".to_string()
                            );
                        }
                    }
                }
            }
        }
    }

    // Final contract verification
    tracker.check_future_contract()?;
    Ok(())
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let sequence: AwaitSequence = match unstructured.arbitrary() {
        Ok(seq) => seq,
        Err(_) => return, // Invalid input, skip
    };

    // Validate and limit parameters
    if sequence.config.await_patterns.is_empty() {
        return;
    }

    let result = test_double_await_behavior(&sequence);

    if let Err(msg) = result {
        panic!("Future contract test failed: {msg}");
    }
});
