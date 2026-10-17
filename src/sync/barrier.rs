//! Barrier for N-way rendezvous with cancel-aware waiting.
//!
//! The barrier trips when `parties` callers have arrived. Exactly one
//! caller observes `is_leader = true` per generation.
//!
//! # Cancel Safety
//!
//! - **Wait**: If a task is cancelled while waiting, it is removed from the
//!   arrival count. The barrier will not trip until a replacement task arrives.
//! - **Trip**: Once the barrier trips, all waiting tasks are woken and will
//!   observe completion, even if cancelled concurrently.

use parking_lot::Mutex;
use smallvec::SmallVec;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

use crate::cx::{CancelWakerToken, Cx};

#[cfg(test)]
std::thread_local! {
    static BEFORE_CANCEL_WAKER_REGISTRATION_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn run_before_cancel_waker_registration_hook() {
    BEFORE_CANCEL_WAKER_REGISTRATION_HOOK.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook();
        }
    });
}

/// Error returned when waiting on a barrier fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BarrierWaitError {
    /// Cancelled while waiting.
    Cancelled,
    /// The wait future was polled after it had already completed.
    PolledAfterCompletion,
}

impl std::fmt::Display for BarrierWaitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => write!(f, "barrier wait cancelled"),
            Self::PolledAfterCompletion => write!(f, "barrier future polled after completion"),
        }
    }
}

impl std::error::Error for BarrierWaitError {}

#[derive(Debug)]
struct BarrierState {
    arrived: usize,
    generation: u64,
    next_waiter_id: u64,
    waiters: SmallVec<[(u64, Waker); 7]>,
    cancellation_count: u64,
}

/// Barrier for N-way rendezvous.
#[derive(Debug)]
pub struct Barrier {
    parties: usize,
    state: Mutex<BarrierState>,
}

impl Barrier {
    /// Creates a new barrier that trips when `parties` have arrived.
    ///
    /// # Panics
    /// Panics if `parties == 0`.
    #[inline]
    #[must_use]
    pub fn new(parties: usize) -> Self {
        assert!(parties > 0, "barrier requires at least 1 party");
        Self {
            parties,
            state: Mutex::new(BarrierState {
                arrived: 0,
                generation: 0,
                next_waiter_id: 0,
                waiters: SmallVec::new(),
                cancellation_count: 0,
            }),
        }
    }

    /// Returns the number of parties required to trip the barrier.
    #[inline]
    #[must_use]
    pub fn parties(&self) -> usize {
        self.parties
    }

    /// Returns a deterministic, redacted snapshot of barrier pressure.
    #[inline]
    #[must_use]
    pub fn telemetry_snapshot(&self, primitive_id: u64) -> crate::sync::SyncTelemetrySnapshot {
        let state = self.state.lock();
        crate::sync::SyncTelemetrySnapshot {
            primitive_id,
            primitive_kind: "barrier",
            capacity: self.parties,
            occupied_units: state.arrived,
            available_units: self.parties.saturating_sub(state.arrived),
            waiter_count: state.waiters.len(),
            generation: state.generation,
            state: if state.waiters.is_empty() && state.arrived == 0 {
                "open"
            } else {
                "waiting"
            },
            cancellation_count: state.cancellation_count,
            closed: false,
        }
    }

    #[cfg(test)]
    pub(crate) fn state_snapshot_for_test(&self) -> (usize, u64, usize) {
        let state = self.state.lock();
        (state.arrived, state.generation, state.waiters.len())
    }

    /// Waits for the barrier to trip.
    ///
    /// If cancelled while waiting, returns `BarrierWaitError::Cancelled` and
    /// decrements the arrival count so the barrier remains consistent for
    /// other waiters.
    #[inline]
    pub fn wait<'a, Caps>(&'a self, cx: &'a Cx<Caps>) -> BarrierWaitFuture<'a, Caps> {
        BarrierWaitFuture {
            barrier: self,
            cx,
            state: WaitState::Init,
            cancel_waker: None,
        }
    }
}

/// Internal state of the wait future.
#[derive(Debug)]
enum WaitState {
    Init,
    /// Waiting for the barrier to trip.
    Waiting {
        generation: u64,
        id: u64,
        slot: usize,
    },
    Done,
}

/// Cancellation-Waker registration owned by one barrier future.
#[derive(Debug)]
struct RegisteredCancelWaker {
    waker: Waker,
    token: CancelWakerToken,
}

/// Future returned by `Barrier::wait`.
#[derive(Debug)]
pub struct BarrierWaitFuture<'a, Caps = crate::cx::cap::All> {
    barrier: &'a Barrier,
    cx: &'a Cx<Caps>,
    state: WaitState,
    /// Task Waker registered with `Cx` for prompt cancellation delivery.
    cancel_waker: Option<RegisteredCancelWaker>,
}

impl<Caps> BarrierWaitFuture<'_, Caps> {
    /// Keep exactly one cancellation-waker registration owned by this future.
    ///
    /// The future retains a clone so replacing or clearing the `Cx` slot can
    /// never destroy the last user-provided waker payload while the `Cx` lock
    /// is held.
    fn refresh_cancel_waker(&mut self, waker: &Waker) {
        let same_local_waker = self
            .cancel_waker
            .as_ref()
            .is_some_and(|registered| registered.waker.will_wake(waker));

        // Retain the current task Waker before entering the Cx so clearing its
        // stored clone can never destroy a safe Wake payload under that lock.
        let incoming_waker = if same_local_waker {
            None
        } else {
            let incoming_waker = waker.clone();
            #[cfg(test)]
            run_before_cancel_waker_registration_hook();
            Some(incoming_waker)
        };
        let previous_token = self
            .cancel_waker
            .as_ref()
            .map(|registered| registered.token);
        let token = self.cx.refresh_cancel_waker(previous_token, waker);
        let retired_waker = if let Some(incoming_waker) = incoming_waker {
            self.cancel_waker.replace(RegisteredCancelWaker {
                waker: incoming_waker,
                token,
            })
        } else {
            self.cancel_waker
                .as_mut()
                .expect("same local Waker requires an existing registration")
                .token = token;
            None
        };
        // A safe Wake payload can run arbitrary destructor code. The Cx lock
        // has been released before the future retires its previous clone.
        drop(retired_waker);
    }

    /// Release this future's cancellation-waker registration, if still current.
    fn clear_cancel_waker(&mut self) {
        let Some(registered) = self.cancel_waker.take() else {
            return;
        };
        self.cx.clear_cancel_waker(registered.token);
        // Keep the payload alive until Cx cleanup releases the lock, then run
        // any final destructor outside that lock.
        drop(registered);
    }

    /// Finish a poll after a cancellation checkpoint reports cancellation.
    fn finish_cancelled(&mut self) -> Poll<Result<BarrierWaitResult, BarrierWaitError>> {
        // If we were waiting, unregister from the barrier generation first.
        if let WaitState::Waiting {
            generation,
            id,
            slot,
        } = self.state
        {
            let mut state = self.barrier.state.lock();

            // Only decrement if the generation hasn't changed (barrier hasn't tripped).
            if state.generation == generation {
                state.cancellation_count = state.cancellation_count.saturating_add(1);
                if state.arrived > 0 {
                    state.arrived -= 1;
                }
                // br-asupersync-abl9h6: remove BY waiter id, not by
                // slot index. Within this generation, prior cancellations
                // may have done swap_remove and moved a different waiter
                // into our `slot` position; the recorded slot is therefore
                // a stale hint, not a guarantee. The waiter set is a
                // SmallVec<[_; 7]>, so the identity scan is bounded by the
                // barrier's own size.
                let _ = slot;
                let retired_waker = state
                    .waiters
                    .iter()
                    .position(|w| w.0 == id)
                    .map(|idx| state.waiters.remove(idx).1);
                drop(state);

                // Mark the future complete before releasing either waker so a
                // panicking destructor cannot make Drop account twice.
                self.state = WaitState::Done;
                self.clear_cancel_waker();
                // Retire the barrier's waker only after both mutexes have been
                // released and the future state transition is committed.
                drop(retired_waker);
                return Poll::Ready(Err(BarrierWaitError::Cancelled));
            }

            // Generation advancement wins a cancellation race: the barrier
            // already released this waiter successfully.
            drop(state);
            self.state = WaitState::Done;
            self.clear_cancel_waker();
            return Poll::Ready(Ok(BarrierWaitResult { is_leader: false }));
        }

        // Cancelled before registering with the barrier itself.
        {
            let mut state = self.barrier.state.lock();
            state.cancellation_count = state.cancellation_count.saturating_add(1);
        }
        self.state = WaitState::Done;
        self.clear_cancel_waker();
        Poll::Ready(Err(BarrierWaitError::Cancelled))
    }
}

impl<Caps> Future for BarrierWaitFuture<'_, Caps> {
    type Output = Result<BarrierWaitResult, BarrierWaitError>;

    #[allow(clippy::too_many_lines)]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if matches!(self.state, WaitState::Done) {
            self.clear_cancel_waker();
            return Poll::Ready(Err(BarrierWaitError::PolledAfterCompletion));
        }

        // Check before registering so already-cancelled calls do not install a
        // stale waker, then register and check again to close the race between
        // the first checkpoint and registration.
        if let Err(_e) = self.cx.checkpoint() {
            return self.finish_cancelled();
        }

        self.refresh_cancel_waker(cx.waker());
        if let Err(_e) = self.cx.checkpoint() {
            return self.finish_cancelled();
        }

        // Clone before taking the barrier mutex. Besides keeping replacement
        // destruction outside the critical section below, this ensures an
        // allocation or custom RawWaker clone cannot unwind through a live
        // BarrierState guard.
        let mut incoming_waker = Some(cx.waker().clone());
        let mut state = self.barrier.state.lock();

        match self.state {
            WaitState::Init => {
                if state.arrived + 1 >= self.barrier.parties {
                    // We are the leader (or the last one to arrive).
                    // Trip the barrier.
                    state.arrived = 0;
                    state.generation = state.generation.wrapping_add(1);

                    // Drain wakers and release lock before waking to
                    // avoid wake-under-lock contention.
                    let wakers: SmallVec<[(u64, Waker); 7]> = state.waiters.drain(..).collect();
                    drop(state);

                    self.state = WaitState::Done;
                    self.clear_cancel_waker();
                    // A user `Waker::wake` may panic. The generation is already
                    // committed and the leader is already `Done`, so contain each
                    // wake panic long enough to notify EVERY detached waiter —
                    // otherwise the loop aborts and the remaining peers park
                    // forever despite the tripped generation — then resume the
                    // first panic to the leader's caller
                    // (br-asupersync-barrier-trip-waker-panic-28i6pa).
                    let mut first_panic: Option<Box<dyn std::any::Any + Send>> = None;
                    for (_, waker) in wakers {
                        if let Err(payload) =
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| waker.wake()))
                        {
                            if first_panic.is_none() {
                                first_panic = Some(payload);
                            }
                        }
                    }
                    if let Some(payload) = first_panic {
                        std::panic::resume_unwind(payload);
                    }

                    Poll::Ready(Ok(BarrierWaitResult { is_leader: true }))
                } else {
                    // Not full yet. Arrive and wait.
                    let waker = incoming_waker
                        .take()
                        .expect("non-cancelled barrier poll must have a waker");
                    let generation = state.generation;
                    let id = state.next_waiter_id;
                    let slot = state.waiters.len();

                    // Do fallible operations first to ensure exception safety
                    state.waiters.push((id, waker));

                    // Now commit infallible state changes
                    state.next_waiter_id = state.next_waiter_id.wrapping_add(1);
                    state.arrived += 1;

                    drop(state);
                    self.state = WaitState::Waiting {
                        generation,
                        id,
                        slot,
                    };
                    Poll::Pending
                }
            }
            WaitState::Waiting {
                generation,
                id,
                slot,
            } => {
                if state.generation == generation {
                    // Still waiting. Update waker if changed.
                    // O(1) fast path: use the remembered slot index.
                    let waker = cx.waker();
                    if slot < state.waiters.len() && state.waiters[slot].0 == id {
                        let retired_waker = if state.waiters[slot].1.will_wake(waker) {
                            None
                        } else {
                            Some(std::mem::replace(
                                &mut state.waiters[slot].1,
                                incoming_waker
                                    .take()
                                    .expect("barrier waker replacement must be available"),
                            ))
                        };
                        drop(state);
                        drop(retired_waker);
                    } else {
                        // Slot invalidated by a concurrent cancellation's
                        // swap_remove.  Fall back to linear scan + push.
                        let mut found_slot = None;
                        let mut retired_waker = None;
                        for (i, w) in state.waiters.iter_mut().enumerate() {
                            if w.0 == id {
                                if !w.1.will_wake(waker) {
                                    retired_waker = Some(std::mem::replace(
                                        &mut w.1,
                                        incoming_waker
                                            .take()
                                            .expect("barrier waker replacement must be available"),
                                    ));
                                }
                                found_slot = Some(i);
                                break;
                            }
                        }
                        let found_slot =
                            found_slot.expect("waiter must be present if generation is unchanged");
                        drop(state);
                        // Update the slot before releasing the retired waker so
                        // a panicking destructor cannot leave stale future state.
                        self.state = WaitState::Waiting {
                            generation,
                            id,
                            slot: found_slot,
                        };
                        drop(retired_waker);
                    }

                    Poll::Pending
                } else {
                    // Generation advanced! We are done.
                    drop(state);
                    self.state = WaitState::Done;
                    self.clear_cancel_waker();
                    Poll::Ready(Ok(BarrierWaitResult { is_leader: false }))
                }
            }
            WaitState::Done => {
                drop(state);
                self.clear_cancel_waker();
                Poll::Ready(Err(BarrierWaitError::PolledAfterCompletion))
            }
        }
    }
}

impl<Caps> Drop for BarrierWaitFuture<'_, Caps> {
    fn drop(&mut self) {
        let retired_waker = if let WaitState::Waiting {
            generation,
            id,
            slot,
        } = self.state
        {
            {
                let mut state = self.barrier.state.lock();

                // Only clean up if the generation hasn't changed (barrier hasn't tripped).
                if state.generation == generation {
                    state.cancellation_count = state.cancellation_count.saturating_add(1);
                    if state.arrived > 0 {
                        state.arrived -= 1;
                    }
                    // br-asupersync-abl9h6: remove BY waiter id (see paired
                    // comment in poll's cancel path). The recorded slot is a
                    // stale hint after any prior swap_remove in the same
                    // generation; identity is the only safe key.
                    let _ = slot;
                    state
                        .waiters
                        .iter()
                        .position(|w| w.0 == id)
                        .map(|idx| state.waiters.swap_remove(idx).1)
                } else {
                    None
                }
            }
        } else {
            None
        };

        // Clear the Cx registration first so the barrier queue's waker remains
        // the final payload owner, then retire it outside both locks.
        self.clear_cancel_waker();
        // Dropping a Waker can destroy a user-provided `Wake` payload.
        // Keep that destructor outside the non-reentrant state mutex.
        drop(retired_waker);
    }
}

/// Result of a barrier wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BarrierWaitResult {
    is_leader: bool,
}

impl BarrierWaitResult {
    /// Returns true for exactly one party (the leader) each generation.
    #[inline]
    #[must_use]
    pub fn is_leader(&self) -> bool {
        self.is_leader
    }
}

#[cfg(test)]
#[path = "barrier_inline_tests.rs"]
mod tests;
