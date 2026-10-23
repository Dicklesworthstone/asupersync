//! Owned auxiliary cancellation wakeups for channel waiters.
//!
//! Channel capacity/data registrations cannot wake a waiter when cancellation
//! is the only event. Keep this registration separate from both those queues
//! and the runtime's cancellation-lane waker. A registration is installed only
//! on the slow path; ready operations do not acquire a cancellation slot.

use crate::cx::{CancelWakerToken, Cx};
use std::task::Waker;

struct Registration {
    // Keep a strong owner outside the Cx registry. Replacing or removing the
    // registry entry must not run the final executor-Waker destructor under
    // its lock. This is the same ownership rule as Cx::cancelled().
    waker: Waker,
    token: CancelWakerToken,
}

struct RegistrationState {
    registration: Option<Registration>,
}

impl RegistrationState {
    const fn new() -> Self {
        Self { registration: None }
    }

    // Callers recheck cancellation after arbitrary Waker callbacks return.
    fn refresh<Caps>(&mut self, cx: &Cx<Caps>, waker: &Waker) {
        let unchanged = self
            .registration
            .as_ref()
            .is_some_and(|registered| registered.waker.will_wake(waker));
        let incoming = if unchanged { None } else { Some(waker.clone()) };
        let previous = self.registration.as_ref().map(|entry| entry.token);
        let token = cx.refresh_cancel_waker(previous, waker);
        let retired = if let Some(waker) = incoming {
            self.registration.replace(Registration { waker, token })
        } else {
            self.registration
                .as_mut()
                .expect("unchanged waker has an owned cancellation registration")
                .token = token;
            None
        };
        drop(retired);
    }

    fn clear<Caps>(&mut self, cx: &Cx<Caps>) {
        if let Some(registered) = self.registration.take() {
            cx.clear_cancel_waker(registered.token);
            drop(registered);
        }
    }
}

pub(super) struct CancelRegistration<'a, Caps = crate::cx::cap::All> {
    cx: &'a Cx<Caps>,
    state: RegistrationState,
}

impl<'a, Caps> CancelRegistration<'a, Caps> {
    pub(super) const fn new(cx: &'a Cx<Caps>) -> Self {
        Self {
            cx,
            state: RegistrationState::new(),
        }
    }

    /// Refresh the wake target without replacing any other waiter's slot.
    ///
    /// Callers must check cancellation after this returns: an executor's
    /// arbitrary Waker clone/retirement callbacks may themselves cancel Cx.
    pub(super) fn refresh(&mut self, waker: &Waker) {
        self.state.refresh(self.cx, waker);
    }

    pub(super) fn clear(&mut self) {
        self.state.clear(self.cx);
    }
}

impl<Caps> Drop for CancelRegistration<'_, Caps> {
    fn drop(&mut self) {
        self.clear();
    }
}

/// A stream owns its Cx, so its cancellation slot must own that same context
/// rather than borrow another field of the stream.
pub(crate) struct OwnedCancelRegistration {
    cx: Cx,
    state: RegistrationState,
}

impl OwnedCancelRegistration {
    pub(crate) fn new(cx: Cx) -> Self {
        Self {
            cx,
            state: RegistrationState::new(),
        }
    }

    pub(crate) fn cx(&self) -> &Cx {
        &self.cx
    }

    pub(crate) fn refresh(&mut self, waker: &Waker) {
        self.state.refresh(&self.cx, waker);
    }

    pub(crate) fn clear(&mut self) {
        self.state.clear(&self.cx);
    }
}

impl std::fmt::Debug for OwnedCancelRegistration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnedCancelRegistration")
            .field("cx", &self.cx)
            .field("registered", &self.state.registration.is_some())
            .finish()
    }
}

impl Drop for OwnedCancelRegistration {
    fn drop(&mut self) {
        self.clear();
    }
}
