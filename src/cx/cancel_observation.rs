//! Private observation of cancellation operations during an enabled Lab poll.
//!
//! Identity is the exact primary CxInner allocation, never a reusable TaskId.
//! Native calls see an empty thread-local slot and do not allocate or lock a
//! recorder. No tracing callback runs while a context lock is held.

use crate::types::CxInner;
use parking_lot::RwLock;
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::{Arc, Weak};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Ordered operations observed on the active primary context.
pub enum CancelObservation {
    MaskEnter,
    MaskExit,
    CheckpointAck,
}

struct Frame {
    owner: Weak<RwLock<CxInner>>,
    events: Rc<RefCell<Vec<CancelObservation>>>,
}

thread_local! {
    static CURRENT: RefCell<Option<Frame>> = const { RefCell::new(None) };
}

/// Restores the previous observer on normal return or unwind, including nested
/// Lab polling. The Rc makes the guard thread-bound without unsafe code.
#[must_use = "keep the observer through poll and cleanup, then drain its events"]
pub struct CancelObservationGuard {
    previous: Option<Frame>,
    events: Rc<RefCell<Vec<CancelObservation>>>,
}

impl std::fmt::Debug for CancelObservationGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CancelObservationGuard").finish_non_exhaustive()
    }
}

impl CancelObservationGuard {
    pub fn enter(owner: &Arc<RwLock<CxInner>>) -> Self {
        let events = Rc::new(RefCell::new(Vec::new()));
        let frame = Frame {
            owner: Arc::downgrade(owner),
            events: Rc::clone(&events),
        };
        let previous = CURRENT.with(|slot| slot.replace(Some(frame)));
        Self { previous, events }
    }

    #[must_use]
    pub fn drain(&self) -> Vec<CancelObservation> {
        std::mem::take(&mut *self.events.borrow_mut())
    }
}

impl Drop for CancelObservationGuard {
    fn drop(&mut self) {
        // During thread-local teardown observation is no longer possible.
        // A frame owns only a weak identity and plain recorder data.
        let _ = CURRENT.try_with(|slot| slot.replace(self.previous.take()));
    }
}

pub fn record(owner: &Arc<RwLock<CxInner>>, event: CancelObservation) {
    let _ = CURRENT.try_with(|slot| {
        let slot = slot.borrow();
        if let Some(frame) = slot.as_ref()
            && std::ptr::eq(frame.owner.as_ptr(), Arc::as_ptr(owner))
        {
            frame.events.borrow_mut().push(event);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cx::Cx;

    #[test]
    fn nested_observers_match_exact_context_and_restore_the_outer_poll() {
        let first = Cx::for_testing();
        let second = Cx::for_testing();
        assert_eq!(first.task_id(), second.task_id());
        let outer = CancelObservationGuard::enter(&first.inner);
        {
            let inner = CancelObservationGuard::enter(&second.inner);
            first.masked(|| {});
            second.masked(|| {});
            assert_eq!(
                inner.drain(),
                vec![CancelObservation::MaskEnter, CancelObservation::MaskExit]
            );
        }
        first.masked(|| {});
        assert_eq!(
            outer.drain(),
            vec![CancelObservation::MaskEnter, CancelObservation::MaskExit]
        );
    }

    #[test]
    fn unwinding_a_nested_observer_restores_the_outer_poll() {
        let first = Cx::for_testing();
        let second = Cx::for_testing();
        let outer = CancelObservationGuard::enter(&first.inner);
        let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _inner = CancelObservationGuard::enter(&second.inner);
            second.masked(|| panic!("nested poll failure"));
        }));
        assert!(failed.is_err());
        first.masked(|| {});
        assert_eq!(
            outer.drain(),
            vec![CancelObservation::MaskEnter, CancelObservation::MaskExit]
        );
    }
}
