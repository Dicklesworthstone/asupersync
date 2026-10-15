#!/usr/bin/env python3
"""Apply GH#83's scoped correction, rejecting stale or ambiguous context.

No files are removed and no checkout is reset. Validate the resulting Rust tree
before publishing it. This migration is unnecessary once the fix is applied.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATCHES: dict[str, list[tuple[str, str]]] = {}


def change(path: str, old: str, new: str) -> None:
    PATCHES.setdefault(path, []).append((old, new))


IO = "src/runtime/io_driver.rs"
WORKER = "src/runtime/scheduler/worker.rs"
LANES = "src/runtime/scheduler/three_lane.rs"

change(IO, "impl IoDriverHandle {\n", """impl IoDriverHandle {
    /// Whether a handle currently owns this shared dispatcher's poll turn.
    /// This is a parking hint, not a leadership claim. Only `try_turn_with`'s
    /// CAS grants ownership. Follower parking publishes its waiter before
    /// reading this flag, paired with the coordinator's promotion fence.
    pub(crate) fn is_polling(&self) -> bool {
        self.is_polling.load(Ordering::Acquire)
    }

""")
change(WORKER, """/// A mechanism for parking and unparking a worker.
#[derive(Debug, Clone)]
""", """/// Removes a published waiter even if a conditional-parking predicate panics.
/// On normal exits this is dropped while holding the condvar mutex, so a
/// concurrent `unpark_if_waiting` cannot leave a permit for a departed waiter.
struct ParkerWaitRegistration<'a>(&'a AtomicUsize);

impl Drop for ParkerWaitRegistration<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Release);
    }
}

/// A mechanism for parking and unparking a worker.
#[derive(Debug, Clone)]
""")
change(WORKER, """    pub fn park(&self) {
        if self
""", """    pub fn park(&self) {
        self.park_unless(|| false);
    }

    /// Parks unless `ready` holds after publishing this thread as a waiter.
    /// The predicate runs once, outside the condvar mutex. A publisher that
    /// makes it true, fences SeqCst, then calls `unpark_if_waiting` cannot
    /// miss this waiter: either the predicate sees the publication or the
    /// publisher sees the waiter. See the matching GH#83 promotion fence.
    #[inline]
    pub(crate) fn park_unless(&self, ready: impl FnOnce() -> bool) {
        if self
""")
change(WORKER, """        self.inner.waiting.fetch_add(1, Ordering::Release);
        // br-asupersync-re7cz3: Dekker-style store-load barrier.""", """        self.inner.waiting.fetch_add(1, Ordering::Release);
        let waiter = ParkerWaitRegistration(&self.inner.waiting);
        // br-asupersync-re7cz3: Dekker-style store-load barrier.""")
change(WORKER, """        std::sync::atomic::fence(Ordering::SeqCst);
        let mut guard = self.lock_unpoisoned();
        while self
""", """        std::sync::atomic::fence(Ordering::SeqCst);
        let ready = ready();
        let mut guard = self.lock_unpoisoned();
        if ready {
            drop(waiter);
            return;
        }
        while self
""")
change(WORKER, """        self.inner.waiting.fetch_sub(1, Ordering::Release);
        drop(guard);
    }

    /// Parks the current thread with a timeout.""", """        drop(waiter);
        drop(guard);
    }

    /// Parks the current thread with a timeout.""")
change(WORKER, """    pub fn park_timeout(&self, duration: Duration) {
        if self
""", """    pub fn park_timeout(&self, duration: Duration) {
        self.park_timeout_unless(duration, || false);
    }

    /// Timed counterpart of `park_unless`, with the same publication fence.
    /// Followers with local deadlines need this handshake too: a timeout
    /// alone can otherwise postpone reactor succession until that deadline.
    #[inline]
    pub(crate) fn park_timeout_unless(&self, duration: Duration, ready: impl FnOnce() -> bool) {
        if self
""")
change(WORKER, """        self.inner.waiting.fetch_add(1, Ordering::Release);
        // br-asupersync-re7cz3: see fence comment in park().""", """        self.inner.waiting.fetch_add(1, Ordering::Release);
        let waiter = ParkerWaitRegistration(&self.inner.waiting);
        // br-asupersync-re7cz3: see fence comment in park().""")
change(WORKER, """        std::sync::atomic::fence(Ordering::SeqCst);
        let (guard, _timeout) = self
            .inner
            .cvar
            .wait_timeout_while(self.lock_unpoisoned(), duration, |()| {""", """        std::sync::atomic::fence(Ordering::SeqCst);
        let ready = ready();
        let guard = self.lock_unpoisoned();
        if ready {
            drop(waiter);
            return;
        }
        let (guard, _timeout) = self
            .inner
            .cvar
            .wait_timeout_while(guard, duration, |()| {""")
change(WORKER, """        self.inner.waiting.fetch_sub(1, Ordering::Release);
        drop(guard);
    }

    /// Unparks a parked thread.""", """        drop(waiter);
        drop(guard);
    }

    /// Unparks a parked thread.""")
change(LANES, "const IDLE_IO_POLL_MAX_TIMEOUT: Duration = Duration::from_millis(250);", """const IDLE_IO_POLL_MAX_TIMEOUT: Duration = Duration::from_millis(250);
/// Failed polls have no leader to wake followers. Retry without an indefinite
/// sleep or a free-reactor spin, while retaining nearer future deadlines.
const IO_POLL_ERROR_RETRY_NANOS: u64 = 1_000_000;""")
change(LANES, """    /// No I/O progress from this worker (leader quick miss or no I/O driver).
    NoProgress,
}""", """    /// No I/O progress from this worker (leader quick miss or no I/O driver).
    NoProgress,
    /// Polling failed after acquiring leadership. Retry with bounded backoff,
    /// rather than waiting indefinitely for a nonexistent leader.
    PollError,
}""")
change(LANES, """#[inline]
fn record_backoff_deadline_selection(""", """/// Keep future deadlines during error recovery. An already-due signal was
/// just visited by `next_task`; stale timed-lane entries must not turn a
/// persistently failing reactor into a zero-delay retry loop.
fn io_error_retry_deadline(now: Time, next_deadline: Option<Time>) -> Time {
    let retry = Time::from_nanos(now.as_nanos().saturating_add(IO_POLL_ERROR_RETRY_NANOS));
    next_deadline
        .filter(|deadline| *deadline > now)
        .map_or(retry, |deadline| deadline.min(retry))
}

#[inline]
fn record_backoff_deadline_selection(""")
change(LANES, """    #[inline]
    fn wake_one_parker_prefer_waiter(&self) -> bool {""", """    /// Pass reactor responsibility to one live waiter before running a task.
    /// Unlike a task wake, this neither leaves a permit on a busy worker nor
    /// wakes the reactor itself. A single worker has no follower to promote.
    #[inline]
    pub(crate) fn promote_follower(&self) {
        let count = self.parkers.len();
        if count < 2 {
            return;
        }
        // GH#83: the driver released is_polling before this fence. Paired
        // with conditional parking's waiter-publication fence, either a
        // follower sees that release or this scan sees its waiting count.
        std::sync::atomic::fence(Ordering::SeqCst);
        let start = self.next_wake.fetch_add(1, Ordering::AcqRel);
        for offset in 0..count {
            let index = start.wrapping_add(offset);
            let slot = self.mask.map_or_else(|| index % count, |mask| index & mask);
            if self.parkers[slot].unpark_if_waiting() {
                return;
            }
        }
    }

    #[inline]
    fn wake_one_parker_prefer_waiter(&self) -> bool {""")
change(LANES, """        match turned {
            Ok(Some(n)) => {
                // We successfully polled the reactor (we are the leader for this turn).
                // If n > 0, we woke some tasks.
                // If n == 0 but we had a non-zero timeout, we spent time blocking,
                // so we should continue the loop to check queues again.
                // If n == 0 and timeout was ZERO, we did a quick poll and found nothing.
                if n > 0 || io_timeout != Some(Duration::ZERO) || kept_a_wake {
                    IoPhaseOutcome::Progress
                } else {
                    IoPhaseOutcome::NoProgress
                }
            }
            Ok(None) | Err(_) if kept_a_wake => IoPhaseOutcome::Progress,
            Ok(None) | Err(_) => {
                // Another thread is already polling (we are a follower).
                // Do not busy loop. Proceed to backoff/park logic.
                IoPhaseOutcome::Follower
            }
        }
""", """        classify_io_phase(turned, io_timeout, kept_a_wake)
""")
change(LANES, """thread_local! {
    /// Set while this thread, a worker with nothing else to run, drives its""", """fn classify_io_phase(
    turned: std::io::Result<Option<usize>>,
    timeout: Option<Duration>,
    kept_a_wake: bool,
) -> IoPhaseOutcome {
    match turned {
        Ok(Some(n)) if n > 0 || timeout != Some(Duration::ZERO) || kept_a_wake => {
            IoPhaseOutcome::Progress
        }
        Ok(Some(_)) => IoPhaseOutcome::NoProgress,
        Ok(None) | Err(_) if kept_a_wake => IoPhaseOutcome::Progress,
        Ok(None) => IoPhaseOutcome::Follower,
        // Poll errors release leadership too. The driver records diagnostics;
        // the scheduler retries with backoff instead of inventing a leader.
        Err(_) => IoPhaseOutcome::PollError,
    }
}

thread_local! {
    /// Set while this thread, a worker with nothing else to run, drives its""")
change(LANES, """    #[inline]
    fn reset_empty_backoff(&mut self) {""", """    /// Register as waiting before checking whether the reactor is free.
    /// Timed and untimed followers must re-enter the dispatch loop on return,
    /// even when the promotion brought no runnable task with it.
    fn park_after_io(&self, io_phase: IoPhaseOutcome, timeout: Option<Duration>) {
        let ready = || {
            matches!(io_phase, IoPhaseOutcome::Follower)
                && self.io_driver.as_ref().is_some_and(|io| !io.is_polling())
        };
        match timeout {
            Some(duration) => self.parker.park_timeout_unless(duration, ready),
            None => self.parker.park_unless(ready),
        }
    }

    #[inline]
    fn reset_empty_backoff(&mut self) {""")
change(LANES, """        let lifo_was_enabled = std::mem::replace(&mut self.lifo_enabled, true);

        'dispatch: loop {""", """        let lifo_was_enabled = std::mem::replace(&mut self.lifo_enabled, true);

        // Pass on an acquired reactor turn before the next task poll,
        // including a locally kept I/O wake or an expired shared timer.
        let mut left_reactor = false;
        'dispatch: loop {""")
change(LANES, """            if let Some(task) = self.next_task() {
                self.reset_empty_backoff();
                self.execute(task);""", """            if let Some(task) = self.next_task() {
                if std::mem::take(&mut left_reactor) {
                    self.coordinator.promote_follower();
                }
                self.reset_empty_backoff();
                self.execute(task);""")
change(LANES, """            let io_phase = self.drive_io_phase(return_when_idle);
            if matches!(io_phase, IoPhaseOutcome::Progress) {""", """            let io_phase = self.drive_io_phase(return_when_idle);
            // Quick misses and errors release the flag too. A peer could
            // have become a follower during either brief turn.
            left_reactor = self.io_driver.is_some()
                && !matches!(io_phase, IoPhaseOutcome::Follower);
            if matches!(io_phase, IoPhaseOutcome::Progress) {""")
change(LANES, """                        if let Some(next_deadline) = next_deadline {
                            // Re-fetch now to ensure we don't sleep if deadline passed during logic""", """                        let next_deadline = if matches!(io_phase, IoPhaseOutcome::PollError) {
                            Some(io_error_retry_deadline(self.current_scheduler_time(), next_deadline))
                        } else {
                            next_deadline
                        };

                        if let Some(next_deadline) = next_deadline {
                            // Re-fetch now to ensure we don't sleep if deadline passed during logic""")
change(LANES, """                                    self.parker.park_timeout(Duration::from_nanos(nanos));""", """                                    self.park_after_io(io_phase, Some(Duration::from_nanos(nanos)));""")
change(LANES, """                                    self.parker.park_timeout(Duration::from_nanos(
                                        STALE_DUE_DEADLINE_PARK_NANOS,
                                    ));""", """                                    self.park_after_io(
                                        io_phase,
                                        Some(Duration::from_nanos(STALE_DUE_DEADLINE_PARK_NANOS)),
                                    );""")
change(LANES, """                                    if wheel_due {
                                        self.reset_empty_backoff();
                                        break;
                                    }""", """                                    if wheel_due
                                        || matches!(io_phase, IoPhaseOutcome::Follower | IoPhaseOutcome::PollError)
                                    {
                                        self.reset_empty_backoff();
                                        break;
                                    }""")
change(LANES, """                        } else {
                            // Followers park indefinitely.
                            record_backoff_indefinite_park(&mut self.preemption_metrics, io_phase);
                            self.parker.park();
                        }
                        // After waking, re-check queues by continuing the loop.""", """                        } else {
                            record_backoff_indefinite_park(&mut self.preemption_metrics, io_phase);
                            self.park_after_io(io_phase, None);
                            if matches!(io_phase, IoPhaseOutcome::Follower) {
                                // Promotion is reactor work, not necessarily
                                // a task-queue wake. Return to re-election.
                                self.reset_empty_backoff();
                                break;
                            }
                        }
                        // After waking, re-check queues by continuing the loop.""")
change(LANES, """        self.lifo_enabled = lifo_was_enabled;
        if let Some((task, priority)) = take_lifo_task(&self.coordinator) {""", """        if left_reactor && !self.shutdown.load(Ordering::Acquire) {
            // A bounded/current-thread pump may stop before dispatching.
            self.coordinator.promote_follower();
        }
        self.lifo_enabled = lifo_was_enabled;
        if let Some((task, priority)) = take_lifo_task(&self.coordinator) {""")
change(LANES, """            let _ = io.try_turn_with(Some(Duration::ZERO), |_, _| {});""", """            if !matches!(io.try_turn_with(Some(Duration::ZERO), |_, _| {}), Ok(None)) {
                // A follower can park during this short busy-loop turn too.
                // Hand it on before this worker enters another task poll.
                self.coordinator.promote_follower();
            }""")
change(LANES, """#[cfg(test)]
#[path = "three_lane_tests.rs"]
mod tests;""", """#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "reactor_handoff_tests.rs"]
mod reactor_handoff_tests;

#[cfg(test)]
#[path = "three_lane_tests.rs"]
mod tests;""")


def apply(root: Path) -> None:
    outputs = {}
    for relative, replacements in PATCHES.items():
        path = root / relative
        text = path.read_text()
        for old, new in replacements:
            count = text.count(old)
            if count != 1:
                raise SystemExit(f"Refusing {relative}: expected one exact context, found {count}: {old[:100]!r}")
            text = text.replace(old, new, 1)
        outputs[path] = text
    for path, text in outputs.items():
        path.write_text(text)
        print(f"Patched {path.relative_to(root)}")


if __name__ == "__main__":
    apply(ROOT)
