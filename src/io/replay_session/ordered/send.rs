use super::{OrderedReplayInputs, OrderedReplaySession, OrderedRunError};
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::task::Poll;

/// Borrowing consumer future that can run inside a region-owned `Send` task.
pub type OrderedSendConsumerFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

impl OrderedReplaySession {
    /// Execute an ordered replay without erasing the consumer's `Send` property.
    ///
    /// Unlike [`run`](Self::run), this driver can be passed to a native runtime's
    /// owned task API when its factory/output meet those task lifetime bounds.
    /// It does not spawn or detach anything itself. All completion, destructor,
    /// panic, poll-budget and owner-deadline semantics are identical to `run`.
    pub async fn run_send<T: Send, F>(
        mut self,
        max_polls: usize,
        consumer: F,
    ) -> Result<T, OrderedRunError>
    where
        F: Send + for<'a> FnOnce(OrderedReplayInputs<'a>) -> OrderedSendConsumerFuture<'a, T>,
    {
        if max_polls == 0 {
            return Err(OrderedRunError::PollLimit { limit: 0 });
        }
        let result = {
            let mut future = consumer(self.inputs());
            let mut polls = 0;
            poll_fn(|cx| {
                if polls == max_polls {
                    return Poll::Ready(Err(OrderedRunError::PollLimit { limit: max_polls }));
                }
                polls += 1;
                future.as_mut().poll(cx).map(Ok)
            })
            .await
        };
        let output = result?;
        self.verify_complete()?;
        Ok(output)
    }
}

#[cfg(test)]
#[path = "send_inline_tests.rs"]
mod tests;
