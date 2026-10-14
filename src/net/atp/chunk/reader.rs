//! Incremental payload production for ATP's stream profile.
//!
//! Unlike the size-adaptive, whole-slice profile API, this reader fixes its
//! chunk size before reading and never merges an already emitted tail. It can
//! produce a chunk before EOF or the total input size is known. Fragmentation
//! of the underlying reads does not change chunk boundaries or hashes.
//!
//! Only one chunk is buffered internally. Returned chunks belong to the caller;
//! callers must bound their own queues. Hashes describe payload bytes, not an
//! authenticated producer or permission to consume unverified stream content.

use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use sha2::{Digest, Sha256};

use crate::atp::manifest::{ChunkBoundary, ChunkMetadata, ChunkStrategy};
use crate::io::{AsyncRead, ReadBuf};
use crate::stream::Stream;

use super::profiles::ChunkingProfile as _;
use super::stream::{RollingManifestUpdate, StreamProfile};

const READS_PER_POLL: usize = 16;

/// One owned payload and its canonical ATP chunk descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamChunk {
    /// Descriptor for exactly `bytes`, with contiguous index and byte offset.
    pub boundary: ChunkBoundary,
    /// Payload bytes. A final short chunk contains no padding.
    pub bytes: Vec<u8>,
}

impl StreamChunk {
    /// Build an update using a caller-supplied timestamp, without a host clock.
    ///
    /// The total length is unknown, so completion is not inferred. This is a
    /// provisional description: neither a self-computed hash nor arrival order
    /// establishes authentication or early-consumption safety.
    #[must_use]
    pub fn rolling_update(&self, timestamp_nanos: u64) -> RollingManifestUpdate {
        RollingManifestUpdate {
            chunk_index: self.boundary.index,
            chunk_offset: self.boundary.byte_offset,
            chunk_size: self.boundary.size_bytes,
            chunk_hash: self.boundary.content_hash,
            sequence: sequence(self.boundary.index, self.boundary.byte_offset),
            early_consumption_safe: false,
            completion_ratio: 0.0,
            timestamp_nanos,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadState {
    Open,
    Eof,
    Poisoned,
}

/// A bounded-memory, demand-driven source of fixed-size ATP stream chunks.
///
/// The source is pinned once, so `R` need not be `Unpin`. No task, timer, or
/// background prefetch is created. A chunk is read only when requested.
///
/// # Cancellation and errors
///
/// Dropping a pending [`Self::next_chunk`] wait preserves both the source and
/// its partial chunk in this object. Read errors are returned with the valid
/// prefix retained, and the caller may retry. Invalid replacement storage or
/// a provider panic poisons the reader: it refuses further source polls rather
/// than replaying effects whose progress is unknown. Dropping this object
/// itself inherits the underlying source's cancellation/cleanup limitations.
///
/// This layout is deliberately not a byte-for-byte replacement for the
/// whole-slice profile's size-dependent plan and tail merging. The existing
/// profile APIs and persisted descriptors are unchanged.
#[must_use = "chunk readers do nothing until polled"]
pub struct StreamChunkReader<R> {
    reader: Pin<Box<R>>,
    buffer: Vec<u8>,
    filled: usize,
    chunk_size: usize,
    offset: u64,
    next_index: u64,
    state: ReadState,
}

impl<R> std::fmt::Debug for StreamChunkReader<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamChunkReader")
            .field("chunk_size", &self.chunk_size)
            .field("buffered_bytes", &self.filled)
            .field("emitted_bytes", &self.offset)
            .field("next_index", &self.next_index)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl StreamProfile {
    /// Produce payload chunks incrementally, without knowing the input size.
    ///
    /// `chunk_size` must be between one byte and this profile's 1 MiB maximum.
    /// The source's read fragmentation does not affect the resulting layout.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` for a zero or oversized chunk size, before polling
    /// the source or allocating a payload buffer.
    pub fn chunk_reader<R: AsyncRead>(
        reader: R,
        chunk_size: usize,
    ) -> io::Result<StreamChunkReader<R>> {
        StreamChunkReader::new(reader, chunk_size)
    }
}

impl<R> StreamChunkReader<R> {
    /// Construct a reader with a fixed, explicitly bounded chunk size.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` unless `chunk_size` is in `1..=1_048_576`.
    pub fn new(reader: R, chunk_size: usize) -> io::Result<Self> {
        if chunk_size == 0 || chunk_size as u64 > StreamProfile::max_chunk_size() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "stream chunk size must be between 1 byte and 1 MiB",
            ));
        }
        Ok(Self {
            reader: Box::pin(reader),
            buffer: Vec::new(),
            filled: 0,
            chunk_size,
            offset: 0,
            next_index: 0,
            state: ReadState::Open,
        })
    }

    /// Number of bytes in chunks already returned to the caller.
    #[must_use]
    pub const fn emitted_bytes(&self) -> u64 {
        self.offset
    }

    /// The retained, valid prefix of the chunk currently being assembled.
    #[must_use]
    pub fn buffered_bytes(&self) -> &[u8] {
        &self.buffer[..self.filled]
    }

    /// Inspect the source without mutating its read position.
    #[must_use]
    pub fn get_ref(&self) -> &R {
        self.reader.as_ref().get_ref()
    }

    /// Whether an actual zero-byte successful source read established EOF.
    #[must_use]
    pub fn is_eof(&self) -> bool {
        self.state == ReadState::Eof
    }

    /// Recover the pinned source and all retained, validated payload bytes.
    ///
    /// On an ordinary read error these bytes precede any further source reads.
    /// After a provider-contract failure or panic, source progress is unknown;
    /// recovering these parts does not make that source safe to retry.
    #[must_use]
    pub fn into_parts(mut self) -> (Pin<Box<R>>, Vec<u8>) {
        self.buffer.truncate(self.filled);
        (self.reader, self.buffer)
    }

    fn refuse(&mut self, message: &'static str) -> io::Error {
        self.state = ReadState::Poisoned;
        io::Error::new(io::ErrorKind::InvalidData, message)
    }

    fn emit(&mut self) -> io::Result<Option<StreamChunk>> {
        if self.filled == 0 {
            return Ok(None);
        }
        let index = u32::try_from(self.next_index)
            .map_err(|_| self.refuse("stream chunk index overflow"))?;
        let end = self.offset.checked_add(self.filled as u64)
            .ok_or_else(|| self.refuse("stream chunk offset overflow"))?;
        let boundary = ChunkBoundary {
            index,
            byte_offset: self.offset,
            size_bytes: self.filled as u64,
            content_hash: Sha256::digest(&self.buffer[..self.filled]).into(),
            strategy: ChunkStrategy::FixedSize,
            metadata: Some(ChunkMetadata::Stream {
                sequence: sequence(index, self.offset),
                early_consumption_safe: false,
            }),
        };
        let mut bytes = std::mem::take(&mut self.buffer);
        bytes.truncate(self.filled);
        self.filled = 0;
        self.offset = end;
        self.next_index += 1;
        Ok(Some(StreamChunk { boundary, bytes }))
    }
}

impl<R: AsyncRead> StreamChunkReader<R> {
    /// Wait for one full chunk, a final short chunk, or EOF.
    ///
    /// A cancelled borrowing wait loses no recorded bytes while this reader is
    /// retained. Successful EOF stays terminal and never polls the source again.
    /// A short read alone is not EOF. Read errors retain the partial chunk.
    pub async fn next_chunk(&mut self) -> io::Result<Option<StreamChunk>> {
        poll_fn(|task| self.poll_next_chunk(task)).await
    }

    /// Poll one chunk with bounded work and no read-ahead into the next chunk.
    ///
    /// At most 16 source polls are made in one invocation. Positive progress
    /// reported alongside `Pending` is retained and schedules another poll if
    /// needed; an empty `Pending` does not self-wake. Hash work is bounded by
    /// the configured chunk size. Source syscall/poll duration is not bounded.
    pub fn poll_next_chunk(
        &mut self,
        task: &mut Context<'_>,
    ) -> Poll<io::Result<Option<StreamChunk>>> {
        if self.state == ReadState::Poisoned {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "stream chunk reader has unknown source progress",
            )));
        }
        if self.state == ReadState::Eof || self.filled == self.chunk_size {
            return Poll::Ready(self.emit());
        }
        if self.buffer.is_empty() {
            self.buffer.resize(self.chunk_size, 0);
        }
        for _ in 0..READS_PER_POLL {
            // If a provider unwinds, leave a sticky refusal. No catch_unwind is
            // needed, and the original panic still reaches the caller.
            self.state = ReadState::Poisoned;
            let tail = &mut self.buffer[self.filled..];
            let expected_ptr = tail.as_ptr();
            let capacity = tail.len();
            let mut read_buf = ReadBuf::new(tail);
            let status = self.reader.as_mut().poll_read(task, &mut read_buf);
            let n = read_buf.filled().len();
            if read_buf.filled().as_ptr() != expected_ptr || n > capacity {
                return Poll::Ready(Err(self.refuse("source replaced stream chunk read storage")));
            }
            if n > 0 && self.next_index > u64::from(u32::MAX) {
                return Poll::Ready(Err(self.refuse("stream chunk index overflow")));
            }
            if self.offset.checked_add((self.filled + n) as u64).is_none() {
                return Poll::Ready(Err(self.refuse("stream chunk offset overflow")));
            }
            // Record valid in-place progress before interpreting the status.
            // In particular, an error with bytes must not make a retry skip them.
            self.filled += n;
            self.state = ReadState::Open;
            match status {
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) if n == 0 => {
                    self.state = ReadState::Eof;
                    return Poll::Ready(self.emit());
                }
                Poll::Ready(Ok(())) => {
                    if self.filled == self.chunk_size {
                        return Poll::Ready(self.emit());
                    }
                }
                Poll::Pending => {
                    if self.filled == self.chunk_size {
                        return Poll::Ready(self.emit());
                    }
                    if n > 0 {
                        task.waker().wake_by_ref();
                    }
                    return Poll::Pending;
                }
            }
        }
        task.waker().wake_by_ref();
        Poll::Pending
    }
}

impl<R: AsyncRead> Stream for StreamChunkReader<R> {
    type Item = io::Result<StreamChunk>;

    fn poll_next(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().poll_next_chunk(task).map(Result::transpose)
    }
}

fn sequence(index: u32, offset: u64) -> u64 {
    (u64::from(index) << 32) | (offset & 0xffff_ffff)
}

#[cfg(test)]
#[path = "reader_tests.rs"]
mod tests;
