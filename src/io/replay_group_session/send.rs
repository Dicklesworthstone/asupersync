//! Keep borrowing consumers Send for caller-owned native tasks.
use super::{GroupSessionRunError, ReplayGroupSession};
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::task::Poll;

/// Borrowing consumer future suitable for a caller-owned Send task.
pub type GroupSendConsumerFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

impl ReplayGroupSession {
    /// Execute without erasing the consumer's Send property. This does not spawn
    /// or detach tasks: callers retain their runtime/region ownership. All poll
    /// budget, panic, destructor, completion and external-deadline requirements
    /// match [`Self::run`]. A zero budget refuses before invoking the factory.
    pub async fn run_send<T: Send, F>(self, max_polls: usize, consumer: F) -> Result<T, GroupSessionRunError>
    where
        F: Send + for<'a> FnOnce(&'a ReplayGroupSession) -> GroupSendConsumerFuture<'a, T>,
    {
        if max_polls == 0 { return Err(GroupSessionRunError::PollLimit { limit: 0 }); }
        let result = {
            let mut future = consumer(&self);
            let mut polls = 0;
            poll_fn(|cx| {
                if polls == max_polls { return Poll::Ready(Err(GroupSessionRunError::PollLimit { limit: max_polls })); }
                polls += 1;
                future.as_mut().poll(cx).map(Ok)
            }).await
        };
        let output = result?;
        self.verify_complete()?;
        Ok(output)
    }
}

#[cfg(test)]
#[path = "send_inline_tests.rs"]
mod tests;
