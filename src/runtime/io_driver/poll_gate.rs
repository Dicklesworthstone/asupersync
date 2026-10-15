//! Wake-interruptible ownership of a shared backend poll.
//!
//! A physical reactor wake may be consumed by another participant. Waiting for
//! that participant's mutex was therefore not a wait for our own wake. Keep the
//! ownership bit behind a short mutex and sleep on a condition variable whose
//! predicate also includes this participant's retained wake. No backend callback
//! executes under the predicate mutex.

use parking_lot::{Condvar, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[derive(Default)]
pub(super) struct PollGate {
    claimed: Mutex<bool>,
    changed: Condvar,
    #[cfg(all(test, not(target_arch = "wasm32")))]
    waiters: std::sync::atomic::AtomicUsize,
}

impl PollGate {
    /// None means this participant was woken, its timeout elapsed, or a
    /// nonblocking/browser turn encountered contention. It does NOT mean that
    /// another worker of this participant is driving its timers.
    pub(super) fn acquire(
        &self,
        woken: &AtomicBool,
        timeout: Option<Duration>,
    ) -> Option<(PollPermit<'_>, Option<Duration>)> {
        #[cfg(target_arch = "wasm32")]
        let mut claimed = self.claimed.try_lock()?;
        #[cfg(not(target_arch = "wasm32"))]
        let mut claimed = if timeout.is_some_and(|duration| duration.is_zero()) {
            self.claimed.try_lock()?
        } else {
            self.claimed.lock()
        };
        if !*claimed {
            *claimed = true;
            return Some((PollPermit(self), timeout));
        }

        #[cfg(target_arch = "wasm32")]
        {
            let _ = woken;
            None
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            // Only contended native turns read the host clock. Recompute the
            // remaining budget from this single start even after notifications
            // intended for a different participant.
            let start = std::time::Instant::now();
            #[cfg(test)]
            struct Waiter<'a>(&'a std::sync::atomic::AtomicUsize);
            #[cfg(test)]
            impl Drop for Waiter<'_> {
                fn drop(&mut self) {
                    self.0.fetch_sub(1, Ordering::Release);
                }
            }
            #[cfg(test)]
            let _waiter = {
                self.waiters.fetch_add(1, Ordering::Release);
                Waiter(&self.waiters)
            };

            loop {
                let remaining = timeout.map(|budget| budget.saturating_sub(start.elapsed()));
                if !*claimed {
                    // Claim a released gate before observing a wake. The
                    // participant will consume it before the backend poll. A
                    // notify_one successor must not leave a free gate behind
                    // while other claimants remain asleep.
                    *claimed = true;
                    return Some((PollPermit(self), remaining));
                }
                // A wake can end our wait while a different participant still
                // owns the backend. Consume only our own retained wake.
                if woken.swap(false, Ordering::AcqRel) {
                    return None;
                }
                match remaining {
                    Some(remaining) if remaining.is_zero() => return None,
                    Some(remaining) => {
                        self.changed.wait_for(&mut claimed, remaining);
                    }
                    None => self.changed.wait(&mut claimed),
                }
            }
        }
    }

    /// The caller publishes its wake bit BEFORE calling this method. Holding
    /// the predicate mutex pairs that publication with the waiter's check and
    /// atomic unlock-and-wait, so a crossing wake cannot be lost. Notify all:
    /// waking only an arbitrary peer could leave the intended participant asleep.
    pub(super) fn interrupt_waiters(&self) {
        let _claimed = self.claimed.lock();
        self.changed.notify_all();
    }

    #[cfg(all(test, unix, not(target_arch = "wasm32")))]
    pub(super) fn lock(&self) -> PollPermit<'_> {
        self.acquire(&AtomicBool::new(false), None)
            .expect("test claim without cancellation or timeout")
            .0
    }

    #[cfg(all(test, unix, not(target_arch = "wasm32")))]
    pub(super) fn waiting_count(&self) -> usize {
        self.waiters.load(Ordering::Acquire)
    }
}

/// Logical poll ownership, not a mutex guard: backend callbacks and mutation
/// wakeups may reenter the gate's notification path without deadlocking.
#[must_use]
pub(super) struct PollPermit<'a>(&'a PollGate);

impl Drop for PollPermit<'_> {
    fn drop(&mut self) {
        let mut claimed = self.0.claimed.lock();
        *claimed = false;
        // Only one next physical poll can run. Wake-specific notifications
        // use notify_all above; an ordinary release needs one successor.
        self.0.changed.notify_one();
    }
}

#[cfg(all(test, unix, not(target_arch = "wasm32")))]
#[path = "poll_gate_tests.rs"]
mod tests;
