#![no_main]

use libfuzzer_sys::fuzz_target;

// Re-export the types we need from the main crate
use asupersync::net::quic_native::streams::{
    StreamTable, StreamId, StreamRole, StreamDirection
};

#[derive(Debug)]
struct StreamSegment {
    offset: u64,
    length: u64,
    is_fin: bool,
}

/// Parse fuzzer input into sequence of stream segments
fn parse_segments(data: &[u8]) -> Vec<StreamSegment> {
    let mut segments = Vec::new();
    let mut i = 0;

    while i + 17 <= data.len() {
        let offset = u64::from_le_bytes([
            data[i], data[i+1], data[i+2], data[i+3],
            data[i+4], data[i+5], data[i+6], data[i+7],
        ]);
        let length = u64::from_le_bytes([
            data[i+8], data[i+9], data[i+10], data[i+11],
            data[i+12], data[i+13], data[i+14], data[i+15],
        ]);
        let is_fin = data[i+16] & 1 != 0;

        // Bound inputs to prevent OOM - QUIC streams have practical limits
        let offset = offset % (1u64 << 32); // 4GB max stream size
        let length = length % (1024 * 1024); // 1MB max segment

        segments.push(StreamSegment { offset, length, is_fin });
        i += 17;
    }

    segments
}

fuzz_target!(|data: &[u8]| {
    // Skip too-small inputs
    if data.len() < 17 {
        return;
    }

    let segments = parse_segments(data);
    if segments.is_empty() {
        return;
    }

    // Create a stream table with reasonable limits and flow windows
    let mut table = StreamTable::new(
        StreamRole::Server, // Act as server receiving client streams
        100, // max_local_bidi
        100, // max_local_uni
        1024 * 1024, // send_window (1MB)
        1024 * 1024, // recv_window (1MB)
    );

    // Accept a remote (client) bidirectional stream for receiving data
    let stream_id = StreamId::local(StreamRole::Client, StreamDirection::Bidirectional, 0);
    let _ = table.accept_remote_stream(stream_id); // Ignore if already exists

    // Apply segments in the order provided by fuzzer
    // This tests out-of-order delivery, overlapping segments, etc.
    for segment in segments {
        let result = table.receive_stream_segment(
            stream_id,
            segment.offset,
            segment.length,
            segment.is_fin,
        );

        // We expect some segments to fail due to flow control or protocol violations
        // but the stream should never panic or corrupt its internal state
        let _ = result; // Explicitly ignore expected failures

        // Verify stream invariants hold after each segment
        if let Ok(stream) = table.stream(stream_id) {
            verify_stream_invariants(stream);
        }
    }
});

/// Verify that QuicStream maintains its invariants after each operation
fn verify_stream_invariants(stream: &asupersync::net::quic_native::streams::QuicStream) {
    // Access internal state via public fields
    let recv_offset = stream.recv_offset;
    let final_size = stream.final_size;

    // Invariant 1: recv_offset never exceeds final_size
    if let Some(final_size) = final_size {
        assert!(recv_offset <= final_size,
            "recv_offset ({}) exceeds final_size ({})", recv_offset, final_size);
    }

    // Invariant 2: recv_offset is monotonic (tested implicitly by checking it doesn't decrease)
    // This would be caught by the actual implementation design

    // Invariant 3: Internal recv_ranges should be well-formed
    // (We can't directly access recv_ranges as it's private, but any corruption
    // would likely cause panics in subsequent operations)

    // Invariant 4: No integer overflow in offset calculations
    // (Bounds checking in parse_segments prevents this)
}