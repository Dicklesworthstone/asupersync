//! A single admission/commit point for cross-provider observations.
use super::{
    Arc, CaptureSlot, Context, Entry, GroupEffect, GroupReplayMismatch, GroupSessionCaptureError,
    GroupSessionCaptureLimits, GroupSessionCompletionError, GroupSessionReplayError, IoOperation,
    Mutex, Poll, ReplayIo, Waker,
};

pub(super) struct CaptureState {
    pub(super) slots: Vec<CaptureSlot>,
    pub(super) entries: Vec<Entry>,
    pub(super) live: usize,
    pub(super) active: bool,
    pub(super) finished: bool,
    pub(super) failure: Option<GroupSessionCaptureError>,
    sources: usize,
}
impl Default for CaptureState {
    fn default() -> Self {
        Self { slots: Vec::new(), entries: Vec::new(), live: 0, active: false, finished: false, failure: None, sources: 1 }
    }
}
pub(super) struct CaptureTimeline {
    pub(super) limits: GroupSessionCaptureLimits,
    pub(super) state: Mutex<CaptureState>,
}
impl CaptureTimeline {
    pub(super) fn check_registration(&self, state: &CaptureState, id: u64) -> Result<(), GroupSessionCaptureError> {
        if state.finished { return Err(GroupSessionCaptureError::Finished); }
        if let Some(error) = state.failure { return Err(error); }
        if state.slots.iter().any(|slot| slot.id == id) { return Err(GroupSessionCaptureError::DuplicateStream(id)); }
        if state.slots.len() >= self.limits.max_streams { return Err(GroupSessionCaptureError::Limit("streams")); }
        Ok(())
    }
    pub(super) fn begin(&self) -> Option<CaptureGuard<'_>> {
        let mut state = self.state.lock();
        if state.finished || state.failure.is_some() { return None; }
        if state.active {
            state.failure = Some(GroupSessionCaptureError::Overlap);
            return None;
        }
        state.active = true;
        Some(CaptureGuard { timeline: self, done: false })
    }
}
pub(super) struct CaptureGuard<'a> { timeline: &'a CaptureTimeline, done: bool }
impl CaptureGuard<'_> {
    pub(super) fn finish(mut self, effect: GroupEffect, completed: bool) -> usize {
        let mut state = self.timeline.state.lock();
        state.active = false;
        self.done = true;
        if !completed || state.finished || state.failure.is_some() { return 0; }
        if state.entries.len() >= self.timeline.limits.max_effects {
            state.failure = Some(GroupSessionCaptureError::Limit("effects"));
            return 0;
        }
        if state.entries.len() == state.entries.capacity() {
            let additional = (self.timeline.limits.max_effects - state.entries.len()).min(state.entries.len().max(8));
            if state.entries.try_reserve_exact(additional).is_err() {
                state.failure = Some(GroupSessionCaptureError::Allocation);
                return 0;
            }
        }
        let child = if matches!(effect, GroupEffect::Fork(_)) {
            let child = state.sources;
            let Some(next) = child.checked_add(1) else {
                state.failure = Some(GroupSessionCaptureError::Limit("entropy sources"));
                return 0;
            };
            state.sources = next;
            child
        } else { 0 };
        state.entries.push(Entry { effect, child });
        child
    }
}
impl Drop for CaptureGuard<'_> {
    fn drop(&mut self) {
        if !self.done {
            let mut state = self.timeline.state.lock();
            state.active = false;
            state.failure.get_or_insert(GroupSessionCaptureError::Interrupted);
        }
    }
}

pub(super) struct ReplaySlot {
    pub(super) id: u64,
    pub(super) remaining: usize,
    pub(super) io: Option<ReplayIo>,
    pub(super) waiter: Option<Arc<Waker>>,
}
pub(super) struct ReplayState {
    pub(super) slots: Vec<ReplaySlot>,
    pub(super) entries: Vec<Entry>,
    pub(super) index: usize,
    pub(super) active: bool,
    pub(super) failure: Option<GroupSessionReplayError>,
}
pub(super) struct ReplayTimeline { pub(super) state: Mutex<ReplayState> }

// Arbitrary caller Waker clone/drop/wake never runs under a timeline lock.
// As in the existing replay group, caught panic payloads are deliberately not
// destroyed (their destructors can panic again). This is not a memory bound
// for arbitrarily hostile callbacks or panic hooks.
fn retire(waiter: Option<Arc<Waker>>) {
    if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(waiter))) {
        std::mem::forget(payload);
    }
}
fn wake(waiter: Option<Arc<Waker>>) {
    if let Some(waiter) = waiter {
        if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| waiter.wake_by_ref())) {
            std::mem::forget(payload);
        }
        retire(Some(waiter));
    }
}
impl ReplayState {
    fn fail(&mut self, actual: GroupEffect, reason: GroupReplayMismatch) -> GroupSessionReplayError {
        let error = GroupSessionReplayError {
            index: self.index, expected: self.entries.get(self.index).map(|entry| entry.effect), actual, reason,
        };
        *self.failure.get_or_insert(error)
    }
    fn admit(&mut self, actual: GroupEffect) -> Result<(usize, usize), GroupSessionReplayError> {
        if let Some(error) = self.failure { return Err(error); }
        let Some(entry) = self.entries.get(self.index) else { return Err(self.fail(actual, GroupReplayMismatch::Exhausted)); };
        if self.active { return Err(self.fail(actual, GroupReplayMismatch::Overlap)); }
        if entry.effect != actual { return Err(self.fail(actual, GroupReplayMismatch::Effect)); }
        let child = entry.child;
        self.active = true;
        Ok((self.index, child))
    }
    fn admit_io(&mut self, slot: usize, actual: GroupEffect) -> Result<Option<(usize, usize)>, GroupSessionReplayError> {
        if let Some(error) = self.failure { return Err(error); }
        if self.slots[slot].remaining == 0 { return Err(self.fail(actual, GroupReplayMismatch::Exhausted)); }
        match self.entries.get(self.index).map(|entry| entry.effect) {
            Some(GroupEffect::Io { stream, .. }) if stream == self.slots[slot].id => self.admit(actual).map(Some),
            Some(_) => Ok(None),
            None => Err(self.fail(actual, GroupReplayMismatch::Exhausted)),
        }
    }
}
impl ReplayTimeline {
    fn wake_all(&self) {
        let len = self.state.lock().slots.len();
        for index in 0..len {
            let waiter = self.state.lock().slots[index].waiter.take();
            wake(waiter);
        }
    }
    pub(super) fn enter(&self, actual: GroupEffect) -> Result<ReplayGuard<'_>, GroupSessionReplayError> {
        let result = self.state.lock().admit(actual);
        match result {
            Ok((index, child)) => Ok(ReplayGuard { timeline: self, index, child, actual, slot: None, done: false }),
            Err(error) => { self.wake_all(); Err(error) }
        }
    }
    pub(super) fn enter_io(&self, slot: usize, actual: GroupEffect, cx: &Context<'_>) -> Poll<Result<ReplayGuard<'_>, GroupSessionReplayError>> {
        let result = self.state.lock().admit_io(slot, actual);
        match result {
            Ok(Some((index, child))) => return Poll::Ready(Ok(ReplayGuard { timeline: self, index, child, actual, slot: Some(slot), done: false })),
            Err(error) => { self.wake_all(); return Poll::Ready(Err(error)); }
            Ok(None) => {}
        }
        let mut incoming = Some(Arc::new(cx.waker().clone()));
        let (result, stale) = {
            let mut state = self.state.lock();
            let result = state.admit_io(slot, actual);
            let stale = if matches!(result, Ok(None)) {
                std::mem::replace(&mut state.slots[slot].waiter, incoming.take())
            } else { None };
            (result, stale)
        };
        retire(stale);
        retire(incoming);
        match result {
            Ok(Some((index, child))) => Poll::Ready(Ok(ReplayGuard { timeline: self, index, child, actual, slot: Some(slot), done: false })),
            Ok(None) => Poll::Pending,
            Err(error) => { self.wake_all(); Poll::Ready(Err(error)) }
        }
    }
    pub(super) fn close_stream(&self, slot: usize) {
        let (failed, waiter) = {
            let mut state = self.state.lock();
            let id = state.slots[slot].id;
            let failed = state.slots[slot].remaining != 0;
            if failed {
                let actual = state.entries[state.index..].iter().find_map(|entry| match entry.effect {
                    GroupEffect::Io { stream, .. } if stream == id => Some(entry.effect),
                    _ => None,
                }).unwrap_or(GroupEffect::Io { stream: id, operation: IoOperation::Read });
                state.fail(actual, GroupReplayMismatch::AbandonedStream);
            }
            (failed, state.slots[slot].waiter.take())
        };
        retire(waiter);
        if failed { self.wake_all(); }
    }
    pub(super) fn verify_complete(&self) -> Result<(), GroupSessionCompletionError> {
        let state = self.state.lock();
        if let Some(error) = state.failure { return Err(GroupSessionCompletionError::Diverged(error)); }
        let remaining = state.entries.len() - state.index;
        if remaining != 0 { return Err(GroupSessionCompletionError::Remaining(remaining)); }
        if state.active || state.slots.iter().any(|slot| slot.remaining != 0) { return Err(GroupSessionCompletionError::Components); }
        Ok(())
    }
}

pub(super) struct ReplayGuard<'a> {
    timeline: &'a ReplayTimeline,
    index: usize,
    child: usize,
    actual: GroupEffect,
    slot: Option<usize>,
    done: bool,
}
impl ReplayGuard<'_> {
    pub(super) fn child(&self) -> usize { self.child }
    pub(super) fn finish(mut self, valid: bool) -> Result<(), GroupSessionReplayError> {
        let (result, next, stale) = {
            let mut state = self.timeline.state.lock();
            state.active = false;
            self.done = true;
            let result = if let Some(error) = state.failure {
                Err(error)
            } else if !valid || self.index != state.index {
                Err(state.fail(self.actual, GroupReplayMismatch::Component))
            } else {
                if let Some(slot) = self.slot {
                    // Admission checked nonzero; only this exclusive stream owner
                    // can consume its observation while this guard is active.
                    state.slots[slot].remaining -= 1;
                }
                state.index += 1;
                Ok(())
            };
            let stale = self.slot.and_then(|slot| state.slots[slot].waiter.take());
            let next_id = state.entries.get(state.index).and_then(|entry| match entry.effect {
                GroupEffect::Io { stream, .. } => Some(stream),
                _ => None,
            });
            let next = if result.is_ok() {
                next_id.and_then(|id| state.slots.iter_mut().find(|slot| slot.id == id)).and_then(|slot| slot.waiter.take())
            } else { None };
            (result, next, stale)
        };
        // Every counter and the cross-provider turn commit before any callback.
        retire(stale);
        if result.is_err() { self.timeline.wake_all(); } else { wake(next); }
        result
    }
}
impl Drop for ReplayGuard<'_> {
    fn drop(&mut self) {
        if !self.done {
            {
                let mut state = self.timeline.state.lock();
                state.active = false;
                state.fail(self.actual, GroupReplayMismatch::Interrupted);
            }
            self.timeline.wake_all();
        }
    }
}
