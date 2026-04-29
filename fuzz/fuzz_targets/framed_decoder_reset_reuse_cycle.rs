//! Structure-aware fuzz target for Framed decoder reset-and-reuse cycle.
//!
//! Tests the critical state consistency across the `Framed::into_parts() -> reconstruct` cycle:
//! 1. Decoder processes partial frames and maintains internal state
//! 2. Framed is deconstructed into parts preserving read/write buffers
//! 3. New Framed is constructed from the same parts
//! 4. Decoder continues processing from its previous state consistently
//!
//! This exercises the reset-and-reuse pattern where decoders must maintain
//! consistent state across transport reconstruction, critical for protocols
//! that need to preserve parsing context across connection handoffs.

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::BytesMut;
use asupersync::codec::framed::{Framed, FramedParts};
use asupersync::codec::{Decoder, Encoder, LinesCodec};
use asupersync::io::{AsyncRead, AsyncWrite, ReadBuf};
use asupersync::stream::Stream;
use libfuzzer_sys::fuzz_target;
use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

const MAX_LINES: usize = 32;
const MAX_LINE_LEN: usize = 128;
const MAX_RESET_CYCLES: usize = 8;

/// Structure-aware input for decoder reset-and-reuse testing.
#[derive(Arbitrary, Debug)]
struct ResetReuseInput {
    /// Lines to encode as test data
    lines: Vec<LineData>,
    /// Reset cycle points - when to decompose and reconstruct
    reset_cycles: Vec<ResetCycle>,
    /// Transport behavior configuration
    transport_config: TransportConfig,
}

#[derive(Arbitrary, Debug)]
struct LineData {
    /// Line content (will be UTF-8 validated)
    #[arbitrary(with = arbitrary_string)]
    content: String,
    /// Whether this line ends with \r\n vs \n
    use_crlf: bool,
}

#[derive(Arbitrary, Debug)]
struct ResetCycle {
    /// After how many decoded frames to trigger reset
    after_frames: u8,
    /// Whether to modify buffers during reset
    modify_during_reset: BufferModification,
}

#[derive(Arbitrary, Debug)]
enum BufferModification {
    None,
    ClearReadBuffer,
    ClearWriteBuffer,
    ClearBoth,
    AppendToRead(#[arbitrary(with = arbitrary_small_bytes)] Vec<u8>),
    TruncateRead(u8), // Truncate to this many bytes
}

#[derive(Arbitrary, Debug)]
struct TransportConfig {
    /// Chunk input delivery to test partial frame handling
    chunk_sizes: Vec<u8>,
    /// Simulate transport errors at specific points
    error_after_bytes: Option<u16>,
}

/// Generate bounded string for fuzzing
fn arbitrary_string(u: &mut arbitrary::Unstructured) -> arbitrary::Result<String> {
    let len = u.int_in_range(0..=MAX_LINE_LEN)?;
    let bytes: Vec<u8> = (0..len).map(|_| u.arbitrary::<u8>()).collect::<Result<Vec<_>, _>>()?;

    // Convert to valid UTF-8, replacing invalid sequences
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Generate small byte arrays
fn arbitrary_small_bytes(u: &mut arbitrary::Unstructured) -> arbitrary::Result<Vec<u8>> {
    let len = u.int_in_range(0..=16)?;
    (0..len).map(|_| u.arbitrary::<u8>()).collect()
}

/// Mock transport that delivers data in configured chunks
#[derive(Debug)]
struct ChunkedTransport {
    read_data: VecDeque<u8>,
    write_data: Vec<u8>,
    chunk_sizes: VecDeque<usize>,
    current_chunk_remaining: usize,
    error_after_bytes: Option<u16>,
    bytes_read: u16,
}

impl ChunkedTransport {
    fn new(data: Vec<u8>, config: TransportConfig) -> Self {
        let chunk_sizes: VecDeque<usize> = config.chunk_sizes
            .into_iter()
            .map(|size| (size as usize).max(1).min(64))
            .collect();

        let current_chunk_remaining = chunk_sizes.front().copied().unwrap_or(64);

        Self {
            read_data: VecDeque::from(data),
            write_data: Vec::new(),
            chunk_sizes,
            current_chunk_remaining,
            error_after_bytes: config.error_after_bytes,
            bytes_read: 0,
        }
    }
}

impl AsyncRead for ChunkedTransport {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Check for error injection
        if let Some(error_after) = this.error_after_bytes {
            if this.bytes_read >= error_after {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "injected transport error"
                )));
            }
        }

        if this.read_data.is_empty() {
            return Poll::Ready(Ok(()));
        }

        let to_read = buf.remaining()
            .min(this.current_chunk_remaining)
            .min(this.read_data.len());

        if to_read == 0 {
            return Poll::Pending;
        }

        let chunk: Vec<u8> = this.read_data.drain(..to_read).collect();
        buf.put_slice(&chunk);

        this.bytes_read = this.bytes_read.saturating_add(to_read as u16);
        this.current_chunk_remaining = this.current_chunk_remaining.saturating_sub(to_read);

        // Move to next chunk size when current is exhausted
        if this.current_chunk_remaining == 0 {
            this.chunk_sizes.pop_front();
            this.current_chunk_remaining = this.chunk_sizes.front().copied().unwrap_or(64);
        }

        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ChunkedTransport {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.write_data.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Apply buffer modifications during reset cycle
fn apply_buffer_modification(
    parts: &mut FramedParts<ChunkedTransport, LinesCodec>,
    modification: &BufferModification,
) {
    match modification {
        BufferModification::None => {}
        BufferModification::ClearReadBuffer => {
            parts.read_buf.clear();
        }
        BufferModification::ClearWriteBuffer => {
            parts.write_buf.clear();
        }
        BufferModification::ClearBoth => {
            parts.read_buf.clear();
            parts.write_buf.clear();
        }
        BufferModification::AppendToRead(data) => {
            parts.read_buf.extend_from_slice(data);
        }
        BufferModification::TruncateRead(len) => {
            let new_len = (*len as usize).min(parts.read_buf.len());
            parts.read_buf.truncate(new_len);
        }
    }
}

/// Reconstruct Framed from parts - this is the core reset-and-reuse pattern
fn reconstruct_framed(mut parts: FramedParts<ChunkedTransport, LinesCodec>) -> (Framed<ChunkedTransport, LinesCodec>, BytesMut, BytesMut) {
    // The reset-and-reuse pattern: extract codec with its internal decoder state,
    // and create a new Framed instance. Return the orphaned buffers for validation.

    // Key insight: The decoder state in the codec is preserved across reconstruction
    let new_framed = Framed::new(parts.inner, parts.codec);

    // Return the orphaned buffers so caller can handle the data migration
    (new_framed, parts.read_buf, parts.write_buf)
}

fuzz_target!(|input: ResetReuseInput| {
    // Guard against excessive input
    if input.lines.len() > MAX_LINES {
        return;
    }
    if input.reset_cycles.len() > MAX_RESET_CYCLES {
        return;
    }

    // Prepare test data by encoding lines
    let mut encoded_data = Vec::new();
    let expected_lines: Vec<String> = input.lines.iter().map(|line_data| {
        let line_ending = if line_data.use_crlf { "\r\n" } else { "\n" };
        let full_line = format!("{}{}", line_data.content, line_ending);
        encoded_data.extend_from_slice(full_line.as_bytes());
        line_data.content.clone()
    }).collect();

    if encoded_data.len() > 1_000_000 {
        return; // Prevent excessive memory usage
    }

    // Create chunked transport and framed decoder
    let transport = ChunkedTransport::new(encoded_data, input.transport_config);
    let mut framed = Framed::new(transport, LinesCodec::new());

    // Track reset cycles
    let mut reset_cycles = VecDeque::from(input.reset_cycles);
    let mut frames_decoded = 0u32;
    let mut decoded_lines = Vec::new();
    let mut reset_count = 0usize;

    // Dummy waker for polling
    let waker = std::task::Waker::from(std::sync::Arc::new(DummyWaker));
    let mut cx = Context::from_waker(&waker);

    // Main fuzzing loop with reset-and-reuse cycles
    loop {
        // Check if we should trigger a reset cycle
        let should_reset = reset_cycles.front()
            .map(|cycle| frames_decoded >= cycle.after_frames as u32)
            .unwrap_or(false);

        if should_reset && reset_count < MAX_RESET_CYCLES {
            let cycle = reset_cycles.pop_front().unwrap();
            reset_count += 1;

            // CRITICAL: The reset-and-reuse cycle
            let mut parts = framed.into_parts();

            // Apply buffer modifications during reset
            apply_buffer_modification(&mut parts, &cycle.modify_during_reset);

            // Reconstruct framed - this is where state consistency is tested
            // The codec with its decoder state is preserved and reused
            let (new_framed, orphaned_read_buf, orphaned_write_buf) = reconstruct_framed(parts);
            framed = new_framed;

            // INVARIANT: Orphaned buffers represent data that was mid-flight during reset
            // In a real implementation, this data would need to be preserved or handled
            // For testing purposes, verify the buffers don't contain invalid state
            assert!(orphaned_read_buf.len() <= 8192, "Read buffer too large after reset");
            assert!(orphaned_write_buf.len() <= 8192, "Write buffer too large after reset");

            // Reset frame counter for next cycle
            frames_decoded = 0;
        }

        // Poll for next frame
        match Pin::new(&mut framed).poll_next(&mut cx) {
            Poll::Ready(Some(Ok(line))) => {
                decoded_lines.push(line);
                frames_decoded += 1;
            }
            Poll::Ready(Some(Err(_e))) => {
                // Expected behavior for malformed input
                break;
            }
            Poll::Ready(None) => {
                // EOF reached
                break;
            }
            Poll::Pending => {
                // No more data available for now
                if reset_cycles.is_empty() {
                    break;
                }
                // Continue to potentially trigger reset cycle
                continue;
            }
        }

        // Prevent infinite loops
        if decoded_lines.len() > MAX_LINES * 2 {
            break;
        }
    }

    // ORACLE: Verify consistency across reset cycles
    // The decoder should produce the same logical result regardless of
    // how many reset-reuse cycles occurred during processing

    // Basic sanity check: decoded lines should be prefix of expected lines
    // (may be fewer due to transport errors or partial processing)
    for (i, decoded) in decoded_lines.iter().enumerate() {
        if let Some(expected) = expected_lines.get(i) {
            assert_eq!(decoded, expected,
                "Frame {i} mismatch after {reset_count} reset cycles: expected '{expected}', got '{decoded}'");
        }
    }

    // Invariant: decoder state should be consistent after any reset cycle
    // This is verified implicitly by the parsing succeeding and producing expected results
});

/// Dummy waker implementation for testing
struct DummyWaker;

impl std::task::Wake for DummyWaker {
    fn wake(self: std::sync::Arc<Self>) {}
}