//! Clone-shared admission held through transport-future destruction.

use super::RemoteSymbolError;
use std::future::{Future, poll_fn};
use std::sync::atomic::{AtomicUsize, Ordering};

pub(super) struct Admission {
    active: AtomicUsize,
    limit: usize,
}

impl Admission {
    pub(super) const fn new(limit: usize) -> Self {
        Self { active: AtomicUsize::new(0), limit }
    }

    pub(super) fn active(&self) -> usize { self.active.load(Ordering::Acquire) }
    pub(super) const fn limit(&self) -> usize { self.limit }

    fn acquire(&self) -> Result<Credit<'_>, RemoteSymbolError> {
        let mut active = self.active();
        loop {
            if active >= self.limit { return Err(RemoteSymbolError::Admission); }
            // active < limit <= usize::MAX proves increment cannot overflow.
            match self.active.compare_exchange_weak(active, active + 1, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return Ok(Credit(self)),
                Err(current) => active = current,
            }
        }
    }

    // A factory, not an already-constructed future: eager encoding/network work
    // cannot run before admission. The inner scope destroys even a Ready future
    // before the credit is returned. Drop/unwind retain the same ownership order.
    pub(super) async fn run<T, F, Fut>(&self, make: F) -> Result<T, RemoteSymbolError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, RemoteSymbolError>>,
    {
        let credit = self.acquire()?;
        let result = {
            let mut future = std::pin::pin!(make());
            poll_fn(|task| future.as_mut().poll(task)).await
        };
        drop(credit);
        result
    }
}

struct Credit<'a>(&'a Admission);
impl Drop for Credit<'_> {
    fn drop(&mut self) { self.0.active.fetch_sub(1, Ordering::AcqRel); }
}

#[cfg(test)]
mod tests;
