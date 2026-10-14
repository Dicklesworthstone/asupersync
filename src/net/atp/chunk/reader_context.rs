//! Explicit context and wake-driven cancellation for borrowing chunk waits.

use std::future::{Future, poll_fn};
use std::io;
use std::pin::pin;
use std::task::Poll;

use crate::cx::Cx;
use crate::cx::cap::CapSetRuntimeMask;
use crate::io::AsyncRead;

use super::{StreamChunk, StreamChunkReader};

fn cancelled() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "stream chunk read cancelled")
}

impl<R: AsyncRead> StreamChunkReader<R> {
    /// Read a chunk under an explicit context, observing cancellation while parked.
    ///
    /// The source is polled with `cx` as its ambient context. Its existing I/O
    /// gates therefore see this context's actual capability mask; this adapter
    /// grants no additional authority and creates no task or timer. Pure memory
    /// sources need no I/O capability merely to assemble a chunk.
    ///
    /// Cancellation is acknowledged only through `checkpoint`, so masking is
    /// respected. A pending wait owns an auxiliary cancellation registration,
    /// which is removed on success, error, panic or abandonment. A cancellation
    /// request can wake this wait independently of the underlying reader.
    ///
    /// Cancelling this borrowing wait does not discard recorded bytes, poison
    /// the reader, abort its source, or reset its chunk index. A later call with
    /// an appropriate non-cancelled context may resume the same partial chunk.
    /// A chunk returned ready by the source poll wins a concurrent cancellation
    /// request: it is delivered, not dropped after committing the read cursor.
    /// No syscall preemption, source retirement or region drain is promised.
    pub async fn next_chunk_with_cx<Caps: CapSetRuntimeMask>(
        &mut self,
        cx: &Cx<Caps>,
    ) -> io::Result<Option<StreamChunk>> {
        cx.with_ambient(async {
            let mut cancellation = pin!(cx.cancelled());
            poll_fn(|task| {
                if cx.checkpoint().is_err() {
                    return Poll::Ready(Err(cancelled()));
                }
                match self.poll_next_chunk(task) {
                    Poll::Ready(result) => Poll::Ready(result),
                    Poll::Pending => {
                        // Register and then recheck the request to close the
                        // checkpoint/register race. A masked observed request
                        // neither aborts the wait nor starts a self-wake loop.
                        if cancellation.as_mut().poll(task).is_ready()
                            && cx.checkpoint().is_err()
                        {
                            return Poll::Ready(Err(cancelled()));
                        }
                        Poll::Pending
                    }
                }
            })
            .await
        })
        .await
    }
}

#[cfg(test)]
#[path = "reader_context_tests.rs"]
mod tests;
