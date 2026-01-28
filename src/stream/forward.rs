//! Helpers for forwarding streams to channels.

use crate::channel::mpsc;
use crate::channel::mpsc::SendError;
use crate::cx::Cx;
use crate::runtime::yield_now;
use crate::stream::{Stream, StreamExt};

/// Sink wrapper for mpsc sender.
pub struct SinkStream<T> {
    sender: mpsc::Sender<T>,
}

impl<T> SinkStream<T> {
    /// Create a new SinkStream.
    #[must_use]
    pub fn new(sender: mpsc::Sender<T>) -> Self {
        Self { sender }
    }

    /// Send item through the channel.
    pub async fn send(&self, cx: &Cx, item: T) -> Result<(), SendError<T>> {
        self.sender.send(cx, item).await
    }

    /// Send all items from stream.
    pub async fn send_all<S>(&self, cx: &Cx, stream: S) -> Result<(), SendError<S::Item>>
    where
        S: Stream<Item = T> + Unpin,
    {
        forward(cx, stream, self.sender.clone()).await
    }
}

/// Convert a stream into a channel sender.
#[must_use]
pub fn into_sink<T>(sender: mpsc::Sender<T>) -> SinkStream<T> {
    SinkStream::new(sender)
}

/// Forward stream to channel.
pub async fn forward<S, T>(
    cx: &Cx,
    mut stream: S,
    sender: mpsc::Sender<T>,
) -> Result<(), SendError<T>>
where
    S: Stream<Item = T> + Unpin,
{
    while let Some(item) = stream.next().await {
        // Use try_send + yield_now to avoid blocking the executor
        // In Phase 0/1, we might not have async blocking send that yields to executor properly
        // so we spin with yield_now().
        let mut pending_item = item;
        loop {
            match sender.try_send(pending_item) {
                Ok(()) => break,
                Err(SendError::Full(val)) => {
                    pending_item = val;
                    // Check cancellation before yielding
                    if let Err(_e) = cx.checkpoint() {
                        return Err(SendError::Disconnected(pending_item));
                    }
                    yield_now().await;
                }
                Err(e) => return Err(e),
            }
        }
    }
    Ok(())
}
