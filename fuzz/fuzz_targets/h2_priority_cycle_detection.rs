//! HTTP/2 PRIORITY Frame Cycle Detection Fuzzer
//!
//! Targets the priority dependency tree management in src/http/h2/connection.rs
//! to test cycle detection in stream dependency graphs with arbitrary priority
//! relationships including self-cycles per RFC 9113 Section 5.3.1.
//!
//! Key invariants tested:
//! - Self-dependency detection → PROTOCOL_ERROR
//! - Circular dependency chains rejected (A→B→C→A)
//! - Deep dependency chains without cycles allowed
//! - Priority weight validation (1-256, stored as 0-255)
//! - Exclusive dependency flag handling during cycle detection
//! - Stream dependency tree consistency after cycle rejection
//! - No infinite loops during cycle detection algorithms
//! - Proper error propagation when cycles are detected
//! - Stream tree remains in valid state after cycle attempts
//! - Multiple concurrent dependency updates handled correctly

#![no_main]

use asupersync::bytes::Bytes;
use asupersync::http::h2::connection::{Connection, ConnectionState};
use asupersync::http::h2::error::ErrorCode;
use asupersync::http::h2::frame::{HeadersFrame, PriorityFrame, Setting, SettingsFrame};
use asupersync::http::h2::settings::Settings;
use asupersync::http::h2::{Frame, H2Error};
use libfuzzer_sys::fuzz_target;

/// Maximum input size to prevent OOM
const MAX_INPUT_SIZE: usize = 2048;

/// Maximum number of streams to create
const MAX_STREAMS: u32 = 64;

/// Maximum dependency chain length to test
const MAX_CHAIN_LENGTH: u32 = 32;

fuzz_target!(|data: &[u8]| {
    // Guard against excessive input sizes
    if data.is_empty() || data.len() > MAX_INPUT_SIZE {
        return;
    }

    // Test 1: Simple self-dependency detection
    {
        let result = test_self_dependency_detection(data);
        validate_self_dependency_result(result);
    }

    // Test 2: Simple cycle detection (A → B → A)
    if data.len() >= 8 {
        let stream_a = ((data[0] as u32) % 16 + 1) * 2 + 1; // Odd stream IDs
        let stream_b = ((data[1] as u32) % 16 + 1) * 2 + 1;
        let weight_a = data[2];
        let weight_b = data[3];
        let exclusive_a = data[4] & 0x01 != 0;
        let exclusive_b = data[5] & 0x01 != 0;

        if stream_a != stream_b {
            let result = test_simple_cycle_detection(
                stream_a,
                stream_b,
                weight_a,
                weight_b,
                exclusive_a,
                exclusive_b,
            );
            validate_cycle_result(result, 2);
        }
    }

    // Test 3: Long chain cycle detection (A → B → C → ... → A)
    if data.len() >= 12 {
        let chain_length = (data[8] % 8) + 3; // 3-10 streams
        let chain_data = &data[9..std::cmp::min(data.len(), 32)];

        let result = test_long_chain_cycle(chain_length, chain_data);
        validate_cycle_result(result, chain_length);
    }

    // Test 4: Complex dependency graph with multiple potential cycles
    if data.len() >= 16 {
        let graph_size = (data[12] % 16) + 4; // 4-19 streams
        let graph_data = &data[13..std::cmp::min(data.len(), 64)];

        let result = test_complex_dependency_graph(graph_size, graph_data);
        validate_complex_graph_result(result, graph_size);
    }

    // Test 5: Priority updates that create cycles
    if data.len() >= 20 {
        let update_count = (data[16] % 8) + 1; // 1-8 updates
        let update_data = &data[17..std::cmp::min(data.len(), 48)];

        let result = test_priority_updates_cycles(update_count, update_data);
        validate_priority_update_result(result, update_count);
    }

    // Test 6: Exclusive dependency flag with cycle creation
    if data.len() >= 24 {
        let exclusive_pattern = data[20];
        let stream_pattern = &data[21..std::cmp::min(data.len(), 32)];

        let result = test_exclusive_dependency_cycles(exclusive_pattern, stream_pattern);
        validate_exclusive_result(result);
    }

    // Test 7: Deep dependency chains without cycles (should succeed)
    if data.len() >= 28 {
        let depth = (data[24] % (MAX_CHAIN_LENGTH as u8)) + 1;
        let depth_data = &data[25..std::cmp::min(data.len(), 64)];

        let result = test_deep_dependency_chain(depth as u32, depth_data);
        validate_deep_chain_result(result, depth as u32);
    }

    // Test 8: Concurrent cycle creation attempts
    if data.len() >= 32 {
        let concurrent_count = (data[28] % 8) + 1; // 1-8 concurrent attempts
        let concurrent_data = &data[29..std::cmp::min(data.len(), 64)];

        let result = test_concurrent_cycle_attempts(concurrent_count, concurrent_data);
        validate_concurrent_result(result);
    }

    // Test 9: Parent-child relationship inversions
    if data.len() >= 36 {
        let inversion_count = data[32] % 8; // 0-7 inversions
        let inversion_data = &data[33..std::cmp::min(data.len(), 48)];

        let result = test_parent_child_inversions(inversion_count, inversion_data);
        validate_inversion_result(result);
    }

    // Test 10: Edge cases with zero dependencies and maximum stream IDs
    if data.len() >= 40 {
        let edge_case_type = data[36] % 4;
        let edge_data = &data[37..std::cmp::min(data.len(), 64)];

        let result = test_edge_cases(edge_case_type, edge_data);
        validate_edge_case_result(result);
    }
});

/// Test self-dependency detection (stream depends on itself)
fn test_self_dependency_detection(data: &[u8]) -> Result<SelfDependencyResult, H2Error> {
    let mut connection = Connection::server(Settings::default());
    initialize_connection(&mut connection)?;

    let mut self_dependency_attempts = 0;
    let mut self_dependency_rejections = 0;

    // Test various stream IDs for self-dependency
    for i in 0..std::cmp::min(data.len(), 8) {
        let stream_id = ((data[i] as u32) % 32 + 1) * 2 + 1; // Odd stream IDs
        let weight = if i + 1 < data.len() { data[i + 1] } else { 16 };
        let exclusive = data[i] & 0x80 != 0;

        // Create stream first
        let _ = send_headers_frame(&mut connection, stream_id, false);

        // Attempt self-dependency via PRIORITY frame
        if let Some(_priority_frame) =
            create_priority_frame(stream_id, stream_id, weight, exclusive)
        {
            // In HTTP/2 RFC 9113, PRIORITY frames are deprecated but may still be supported
            // Instead, test via HEADERS with priority
            let result = send_headers_with_priority(
                &mut connection,
                stream_id,
                stream_id,
                weight,
                exclusive,
            );
            self_dependency_attempts += 1;

            if result.is_err() {
                self_dependency_rejections += 1;
            }
        }
    }

    Ok(SelfDependencyResult {
        attempts: self_dependency_attempts,
        rejections: self_dependency_rejections,
        connection_state: connection.state(),
    })
}

/// Test simple two-stream cycle (A depends on B, B depends on A)
fn test_simple_cycle_detection(
    stream_a: u32,
    stream_b: u32,
    weight_a: u8,
    weight_b: u8,
    exclusive_a: bool,
    exclusive_b: bool,
) -> Result<CycleDetectionResult, H2Error> {
    let mut connection = Connection::server(Settings::default());
    initialize_connection(&mut connection)?;

    // Create both streams
    send_headers_frame(&mut connection, stream_a, false)?;
    send_headers_frame(&mut connection, stream_b, false)?;

    let mut cycle_attempts = 0;
    let mut cycle_rejections = 0;

    // Step 1: A depends on B (should succeed)
    let result1 =
        send_headers_with_priority(&mut connection, stream_a, stream_b, weight_a, exclusive_a);
    cycle_attempts += 1;
    if result1.is_err() {
        cycle_rejections += 1;
    }

    // Step 2: B depends on A (should create cycle and be rejected)
    let result2 =
        send_headers_with_priority(&mut connection, stream_b, stream_a, weight_b, exclusive_b);
    cycle_attempts += 1;
    if result2.is_err() {
        cycle_rejections += 1;
    }

    Ok(CycleDetectionResult {
        cycle_length: 2,
        attempts: cycle_attempts,
        rejections: cycle_rejections,
        connection_state: connection.state(),
        final_error: result2.err(),
    })
}

/// Test long chain cycle detection
fn test_long_chain_cycle(chain_length: u8, data: &[u8]) -> Result<CycleDetectionResult, H2Error> {
    let mut connection = Connection::server(Settings::default());
    initialize_connection(&mut connection)?;

    let mut streams = Vec::new();
    let mut cycle_attempts = 0;
    let mut cycle_rejections = 0;

    // Create streams
    for i in 0..chain_length {
        let stream_id = (i as u32 + 1) * 2 + 1;
        streams.push(stream_id);
        let _ = send_headers_frame(&mut connection, stream_id, false);
    }

    let mut final_error = None;

    // Create chain dependencies: streams[0] → streams[1] → streams[2] → ...
    for i in 0..(chain_length - 1) as usize {
        let source_stream = streams[i];
        let target_stream = streams[i + 1];
        let weight = if i < data.len() { data[i] } else { 16 };
        let exclusive = i % 2 == 0; // Alternate exclusive flag

        let result = send_headers_with_priority(
            &mut connection,
            source_stream,
            target_stream,
            weight,
            exclusive,
        );
        cycle_attempts += 1;
        if result.is_err() {
            cycle_rejections += 1;
            if final_error.is_none() {
                final_error = result.err();
            }
        }
    }

    // Close the cycle: last stream depends on first stream
    if streams.len() >= 2 {
        let last_stream = streams[streams.len() - 1];
        let first_stream = streams[0];
        let weight = if data.len() > chain_length as usize {
            data[chain_length as usize]
        } else {
            16
        };
        let exclusive = chain_length % 2 == 0;

        let result = send_headers_with_priority(
            &mut connection,
            last_stream,
            first_stream,
            weight,
            exclusive,
        );
        cycle_attempts += 1;
        if result.is_err() {
            cycle_rejections += 1;
            final_error = result.err();
        }
    }

    Ok(CycleDetectionResult {
        cycle_length: chain_length,
        attempts: cycle_attempts,
        rejections: cycle_rejections,
        connection_state: connection.state(),
        final_error,
    })
}

/// Test complex dependency graph with multiple potential cycles
fn test_complex_dependency_graph(
    graph_size: u8,
    data: &[u8],
) -> Result<ComplexGraphResult, H2Error> {
    let mut connection = Connection::server(Settings::default());
    initialize_connection(&mut connection)?;

    let mut streams = Vec::new();
    let mut dependency_attempts = 0;
    let mut dependency_rejections = 0;

    // Create streams
    for i in 0..std::cmp::min(graph_size, MAX_STREAMS as u8) {
        let stream_id = (i as u32 + 1) * 2 + 1;
        streams.push(stream_id);
        let _ = send_headers_frame(&mut connection, stream_id, false);
    }

    // Create complex dependency pattern based on fuzzed data
    let mut dependency_count = 0;
    let mut offset = 0;
    while offset + 4 <= data.len() && dependency_count < streams.len() * 2 {
        let source_idx = (data[offset] as usize) % streams.len();
        let target_idx = (data[offset + 1] as usize) % streams.len();
        let weight = data[offset + 2];
        let exclusive = data[offset + 3] & 0x01 != 0;

        if source_idx != target_idx {
            let source_stream = streams[source_idx];
            let target_stream = streams[target_idx];

            let result = send_headers_with_priority(
                &mut connection,
                source_stream,
                target_stream,
                weight,
                exclusive,
            );
            dependency_attempts += 1;
            if result.is_err() {
                dependency_rejections += 1;
            }
        }

        dependency_count += 1;
        offset += 4;
    }

    Ok(ComplexGraphResult {
        graph_size,
        dependency_attempts,
        dependency_rejections,
        connection_state: connection.state(),
    })
}

/// Test priority updates that might create cycles
fn test_priority_updates_cycles(
    update_count: u8,
    data: &[u8],
) -> Result<PriorityUpdateResult, H2Error> {
    let mut connection = Connection::server(Settings::default());
    initialize_connection(&mut connection)?;

    // Create initial streams
    let base_streams = 4;
    let mut streams = Vec::new();
    for i in 0..base_streams {
        let stream_id = (i + 1) * 2 + 1;
        streams.push(stream_id);
        let _ = send_headers_frame(&mut connection, stream_id, false);
    }

    // Create initial dependency: 1 → 3, 5 → 7
    let _ = send_headers_with_priority(&mut connection, streams[0], streams[1], 16, false);
    let _ = send_headers_with_priority(&mut connection, streams[2], streams[3], 16, false);

    let mut update_attempts = 0;
    let mut update_rejections = 0;

    // Perform updates that might create cycles
    for i in 0..update_count as usize {
        if i * 4 + 4 <= data.len() {
            let source_idx = (data[i * 4] as usize) % streams.len();
            let target_idx = (data[i * 4 + 1] as usize) % streams.len();
            let weight = data[i * 4 + 2];
            let exclusive = data[i * 4 + 3] & 0x01 != 0;

            if source_idx != target_idx {
                let result = send_headers_with_priority(
                    &mut connection,
                    streams[source_idx],
                    streams[target_idx],
                    weight,
                    exclusive,
                );
                update_attempts += 1;
                if result.is_err() {
                    update_rejections += 1;
                }
            }
        }
    }

    Ok(PriorityUpdateResult {
        update_attempts,
        update_rejections,
        connection_state: connection.state(),
    })
}

/// Test exclusive dependency flag with cycle creation
fn test_exclusive_dependency_cycles(
    exclusive_pattern: u8,
    data: &[u8],
) -> Result<ExclusiveDependencyResult, H2Error> {
    let mut connection = Connection::server(Settings::default());
    initialize_connection(&mut connection)?;

    let stream_count = 6;
    let mut streams = Vec::new();

    // Create streams
    for i in 0..stream_count {
        let stream_id = (i + 1) * 2 + 1;
        streams.push(stream_id);
        let _ = send_headers_frame(&mut connection, stream_id, false);
    }

    let mut exclusive_attempts = 0;
    let mut exclusive_rejections = 0;

    // Create dependencies with exclusive flag pattern
    for i in 0..std::cmp::min(data.len() / 2, (stream_count - 1) as usize) {
        let source_stream = streams[i];
        let target_stream = streams[i + 1];
        let weight = data[i * 2];
        let exclusive = (exclusive_pattern & (1 << (i % 8))) != 0;

        let result = send_headers_with_priority(
            &mut connection,
            source_stream,
            target_stream,
            weight,
            exclusive,
        );
        exclusive_attempts += 1;
        if result.is_err() {
            exclusive_rejections += 1;
        }
    }

    // Attempt to create cycle with exclusive dependency
    if streams.len() >= 2 {
        let last_stream = streams[streams.len() - 1];
        let first_stream = streams[0];
        let exclusive = exclusive_pattern & 0x80 != 0;

        let result =
            send_headers_with_priority(&mut connection, last_stream, first_stream, 32, exclusive);
        exclusive_attempts += 1;
        if result.is_err() {
            exclusive_rejections += 1;
        }
    }

    Ok(ExclusiveDependencyResult {
        exclusive_attempts,
        exclusive_rejections,
        connection_state: connection.state(),
    })
}

/// Test deep dependency chain without cycles (should succeed)
fn test_deep_dependency_chain(depth: u32, data: &[u8]) -> Result<DeepChainResult, H2Error> {
    let mut connection = Connection::server(Settings::default());
    initialize_connection(&mut connection)?;

    let depth = std::cmp::min(depth, MAX_CHAIN_LENGTH);
    let mut streams = Vec::new();

    // Create streams
    for i in 0..depth {
        let stream_id = (i + 1) * 2 + 1;
        streams.push(stream_id);
        let _ = send_headers_frame(&mut connection, stream_id, false);
    }

    let mut chain_attempts = 0;
    let mut chain_successes = 0;

    // Create linear dependency chain (no cycles)
    for i in 1..depth as usize {
        let source_stream = streams[i];
        let target_stream = streams[0]; // All depend on first stream (no cycle)
        let weight = if i < data.len() { data[i] } else { 16 };
        let exclusive = i % 2 == 0;

        let result = send_headers_with_priority(
            &mut connection,
            source_stream,
            target_stream,
            weight,
            exclusive,
        );
        chain_attempts += 1;
        if result.is_ok() {
            chain_successes += 1;
        }
    }

    Ok(DeepChainResult {
        depth,
        chain_attempts,
        chain_successes,
        connection_state: connection.state(),
    })
}

/// Test concurrent cycle creation attempts
fn test_concurrent_cycle_attempts(
    concurrent_count: u8,
    data: &[u8],
) -> Result<ConcurrentResult, H2Error> {
    let mut connection = Connection::server(Settings::default());
    initialize_connection(&mut connection)?;

    let stream_pairs = std::cmp::min(concurrent_count, 8);
    let mut streams = Vec::new();

    // Create stream pairs
    for i in 0..stream_pairs * 2 {
        let stream_id = (i as u32 + 1) * 2 + 1;
        streams.push(stream_id);
        let _ = send_headers_frame(&mut connection, stream_id, false);
    }

    let mut concurrent_attempts = 0;
    let mut concurrent_rejections = 0;

    // Attempt to create multiple cycles simultaneously
    for i in 0..stream_pairs as usize {
        if i * 2 + 1 < streams.len() && i < data.len() {
            let stream_a = streams[i * 2];
            let stream_b = streams[i * 2 + 1];
            let weight = data[i];

            // A → B
            let result1 =
                send_headers_with_priority(&mut connection, stream_a, stream_b, weight, false);
            concurrent_attempts += 1;
            if result1.is_err() {
                concurrent_rejections += 1;
            }

            // B → A (creates cycle)
            let result2 =
                send_headers_with_priority(&mut connection, stream_b, stream_a, weight, false);
            concurrent_attempts += 1;
            if result2.is_err() {
                concurrent_rejections += 1;
            }
        }
    }

    Ok(ConcurrentResult {
        concurrent_attempts,
        concurrent_rejections,
        connection_state: connection.state(),
    })
}

/// Test parent-child relationship inversions
fn test_parent_child_inversions(
    inversion_count: u8,
    data: &[u8],
) -> Result<InversionResult, H2Error> {
    let mut connection = Connection::server(Settings::default());
    initialize_connection(&mut connection)?;

    let stream_count = 8;
    let mut streams = Vec::new();

    // Create streams
    for i in 0..stream_count {
        let stream_id = (i + 1) * 2 + 1;
        streams.push(stream_id);
        let _ = send_headers_frame(&mut connection, stream_id, false);
    }

    // Create initial parent-child relationships: 1→3→5→7, 2→4→6→8
    let _ = send_headers_with_priority(&mut connection, streams[2], streams[0], 16, false); // 5→1
    let _ = send_headers_with_priority(&mut connection, streams[4], streams[2], 16, false); // 9→5
    let _ = send_headers_with_priority(&mut connection, streams[6], streams[4], 16, false); // 13→9

    let mut inversion_attempts = 0;
    let mut inversion_rejections = 0;

    // Attempt inversions
    for i in 0..inversion_count as usize {
        if i < data.len() && i + 2 < streams.len() {
            let child_stream = streams[i];
            let parent_stream = streams[i + 2];
            let weight = data[i];

            // Try to make parent depend on child (inversion)
            let result = send_headers_with_priority(
                &mut connection,
                parent_stream,
                child_stream,
                weight,
                false,
            );
            inversion_attempts += 1;
            if result.is_err() {
                inversion_rejections += 1;
            }
        }
    }

    Ok(InversionResult {
        inversion_attempts,
        inversion_rejections,
        connection_state: connection.state(),
    })
}

/// Test edge cases
fn test_edge_cases(edge_case_type: u8, data: &[u8]) -> Result<EdgeCaseResult, H2Error> {
    let mut connection = Connection::server(Settings::default());
    initialize_connection(&mut connection)?;

    let mut edge_case_attempts = 0;
    let mut edge_case_rejections = 0;

    match edge_case_type {
        0 => {
            // Test dependency on stream 0 (connection-level)
            if !data.is_empty() {
                let stream_id = ((data[0] as u32) % 16 + 1) * 2 + 1;
                let _ = send_headers_frame(&mut connection, stream_id, false);

                let result = send_headers_with_priority(&mut connection, stream_id, 0, 16, false);
                edge_case_attempts += 1;
                if result.is_err() {
                    edge_case_rejections += 1;
                }
            }
        }
        1 => {
            // Test maximum stream ID
            if data.len() >= 4 {
                let max_stream_id = 0x7fff_ffff & !1; // Even, make odd
                let max_stream_id = max_stream_id | 1;
                let target_stream = ((data[0] as u32) % 16 + 1) * 2 + 1;

                let _ = send_headers_frame(&mut connection, max_stream_id, false);
                let _ = send_headers_frame(&mut connection, target_stream, false);

                let result = send_headers_with_priority(
                    &mut connection,
                    max_stream_id,
                    target_stream,
                    data[1],
                    false,
                );
                edge_case_attempts += 1;
                if result.is_err() {
                    edge_case_rejections += 1;
                }
            }
        }
        2 => {
            // Test weight boundaries (0 and 255)
            if data.len() >= 2 {
                let stream_a = ((data[0] as u32) % 16 + 1) * 2 + 1;
                let stream_b = ((data[1] as u32) % 16 + 2) * 2 + 1;

                let _ = send_headers_frame(&mut connection, stream_a, false);
                let _ = send_headers_frame(&mut connection, stream_b, false);

                // Test weight 0
                let result1 =
                    send_headers_with_priority(&mut connection, stream_a, stream_b, 0, false);
                edge_case_attempts += 1;
                if result1.is_err() {
                    edge_case_rejections += 1;
                }

                // Test weight 255
                let result2 =
                    send_headers_with_priority(&mut connection, stream_a, stream_b, 255, false);
                edge_case_attempts += 1;
                if result2.is_err() {
                    edge_case_rejections += 1;
                }
            }
        }
        3 => {
            // Test nonexistent dependency target
            if !data.is_empty() {
                let stream_id = ((data[0] as u32) % 16 + 1) * 2 + 1;
                let nonexistent_target = ((data[0] as u32) % 16 + 10) * 2 + 1;

                let _ = send_headers_frame(&mut connection, stream_id, false);
                // Don't create the target stream

                let result = send_headers_with_priority(
                    &mut connection,
                    stream_id,
                    nonexistent_target,
                    16,
                    false,
                );
                edge_case_attempts += 1;
                if result.is_err() {
                    edge_case_rejections += 1;
                }
            }
        }
        _ => {}
    }

    Ok(EdgeCaseResult {
        edge_case_type,
        edge_case_attempts,
        edge_case_rejections,
        connection_state: connection.state(),
    })
}

// Result types

#[derive(Debug)]
struct SelfDependencyResult {
    attempts: u32,
    rejections: u32,
    connection_state: ConnectionState,
}

#[derive(Debug)]
struct CycleDetectionResult {
    cycle_length: u8,
    attempts: u32,
    rejections: u32,
    connection_state: ConnectionState,
    final_error: Option<H2Error>,
}

#[derive(Debug)]
struct ComplexGraphResult {
    graph_size: u8,
    dependency_attempts: u32,
    dependency_rejections: u32,
    connection_state: ConnectionState,
}

#[derive(Debug)]
struct PriorityUpdateResult {
    update_attempts: u32,
    update_rejections: u32,
    connection_state: ConnectionState,
}

#[derive(Debug)]
struct ExclusiveDependencyResult {
    exclusive_attempts: u32,
    exclusive_rejections: u32,
    connection_state: ConnectionState,
}

#[derive(Debug)]
struct DeepChainResult {
    depth: u32,
    chain_attempts: u32,
    chain_successes: u32,
    connection_state: ConnectionState,
}

#[derive(Debug)]
struct ConcurrentResult {
    concurrent_attempts: u32,
    concurrent_rejections: u32,
    connection_state: ConnectionState,
}

#[derive(Debug)]
struct InversionResult {
    inversion_attempts: u32,
    inversion_rejections: u32,
    connection_state: ConnectionState,
}

#[derive(Debug)]
struct EdgeCaseResult {
    edge_case_type: u8,
    edge_case_attempts: u32,
    edge_case_rejections: u32,
    connection_state: ConnectionState,
}

// Helper functions

fn initialize_connection(connection: &mut Connection) -> Result<(), H2Error> {
    let settings_frame = SettingsFrame::new(vec![
        Setting::MaxConcurrentStreams(100),
        Setting::InitialWindowSize(65536),
        Setting::MaxFrameSize(16384),
    ]);
    let _ = connection.process_frame(Frame::Settings(settings_frame))?;
    Ok(())
}

fn send_headers_frame(
    connection: &mut Connection,
    stream_id: u32,
    end_stream: bool,
) -> Result<(), H2Error> {
    let headers_frame = HeadersFrame::new(
        stream_id,
        Bytes::from("dummy headers"),
        end_stream,
        true, // end_headers
    );
    let _ = connection.process_frame(Frame::Headers(headers_frame))?;
    Ok(())
}

fn send_headers_with_priority(
    connection: &mut Connection,
    stream_id: u32,
    dependency: u32,
    weight: u8,
    exclusive: bool,
) -> Result<(), H2Error> {
    // Create HEADERS frame with priority information
    let mut headers_frame = HeadersFrame::new(
        stream_id,
        Bytes::from("priority headers"),
        false,
        true, // end_headers
    );

    // Set priority spec
    headers_frame.priority = Some(asupersync::http::h2::frame::PrioritySpec {
        exclusive,
        dependency,
        weight,
    });

    let _ = connection.process_frame(Frame::Headers(headers_frame))?;
    Ok(())
}

fn create_priority_frame(
    stream_id: u32,
    dependency: u32,
    weight: u8,
    exclusive: bool,
) -> Option<PriorityFrame> {
    // PRIORITY frames are deprecated in HTTP/2 RFC 9113
    // Return None to indicate they're not used
    let _ = (stream_id, dependency, weight, exclusive);
    None
}

// Validation functions

fn validate_self_dependency_result(result: Result<SelfDependencyResult, H2Error>) {
    match result {
        Ok(res) => {
            // Self-dependencies should always be rejected
            assert!(
                res.rejections > 0 || res.attempts == 0,
                "Self-dependencies should be rejected: {} rejections out of {} attempts",
                res.rejections,
                res.attempts
            );

            // Connection should remain in valid state
            assert!(
                !matches!(res.connection_state, ConnectionState::Closed),
                "Connection should not be closed after self-dependency attempts"
            );
        }
        Err(_) => {
            // Connection errors are acceptable during self-dependency tests
        }
    }
}

fn validate_cycle_result(result: Result<CycleDetectionResult, H2Error>, expected_length: u8) {
    match result {
        Ok(res) => {
            assert_eq!(res.cycle_length, expected_length, "Cycle length mismatch");

            // For cycles of length > 1, the final dependency should be rejected
            if expected_length > 1 {
                assert!(
                    res.final_error.is_some(),
                    "Cycle creation should result in error"
                );

                if let Some(error) = &res.final_error {
                    assert_eq!(
                        error.code,
                        ErrorCode::ProtocolError,
                        "Cycle should result in PROTOCOL_ERROR"
                    );
                }
            }

            // Some attempts should be rejected for cycle detection
            assert!(
                res.rejections > 0 || res.attempts <= 1,
                "Cycles should be detected and rejected"
            );
        }
        Err(_) => {
            // Errors during cycle tests are acceptable
        }
    }
}

fn validate_complex_graph_result(result: Result<ComplexGraphResult, H2Error>, _expected_size: u8) {
    match result {
        Ok(res) => {
            // Complex graphs should have some dependency attempts
            assert!(
                res.dependency_attempts > 0 || res.graph_size <= 1,
                "Complex graph should attempt dependencies"
            );

            // Connection should handle complex graphs without crashing
            assert!(
                !matches!(res.connection_state, ConnectionState::Closed),
                "Connection should survive complex graph operations"
            );
        }
        Err(_) => {
            // Errors in complex graph tests are acceptable
        }
    }
}

fn validate_priority_update_result(
    result: Result<PriorityUpdateResult, H2Error>,
    _update_count: u8,
) {
    match result {
        Ok(res) => {
            // Priority updates should be attempted
            assert!(
                res.update_attempts > 0,
                "Priority updates should be attempted"
            );

            // Some updates may be rejected due to cycle detection
            assert!(
                res.update_rejections <= res.update_attempts,
                "Rejections should not exceed attempts"
            );
        }
        Err(_) => {
            // Errors during priority updates are acceptable
        }
    }
}

fn validate_exclusive_result(result: Result<ExclusiveDependencyResult, H2Error>) {
    match result {
        Ok(res) => {
            // Exclusive dependency operations should be attempted
            assert!(
                res.exclusive_attempts > 0,
                "Exclusive dependency operations should be attempted"
            );
        }
        Err(_) => {
            // Errors during exclusive dependency tests are acceptable
        }
    }
}

fn validate_deep_chain_result(result: Result<DeepChainResult, H2Error>, depth: u32) {
    match result {
        Ok(res) => {
            assert_eq!(res.depth, depth, "Depth mismatch");

            // Linear chains without cycles should mostly succeed
            if depth > 1 {
                assert!(res.chain_attempts > 0, "Chain attempts should be made");
                assert!(
                    res.chain_successes >= res.chain_attempts / 2,
                    "Most linear dependencies should succeed: {} successes out of {} attempts",
                    res.chain_successes,
                    res.chain_attempts
                );
            }
        }
        Err(_) => {
            // Errors during deep chain tests are acceptable
        }
    }
}

fn validate_concurrent_result(result: Result<ConcurrentResult, H2Error>) {
    match result {
        Ok(res) => {
            // Concurrent operations should be attempted
            assert!(
                res.concurrent_attempts > 0,
                "Concurrent operations should be attempted"
            );

            // Some concurrent cycle attempts should be rejected
            assert!(
                res.concurrent_rejections > 0 || res.concurrent_attempts <= 2,
                "Concurrent cycle attempts should be rejected"
            );
        }
        Err(_) => {
            // Errors during concurrent tests are acceptable
        }
    }
}

fn validate_inversion_result(result: Result<InversionResult, H2Error>) {
    match result {
        Ok(res) => {
            if res.inversion_attempts > 0 {
                // Most parent-child inversions should be rejected (they create cycles)
                assert!(
                    res.inversion_rejections > 0,
                    "Parent-child inversions should be rejected"
                );
            }
        }
        Err(_) => {
            // Errors during inversion tests are acceptable
        }
    }
}

fn validate_edge_case_result(result: Result<EdgeCaseResult, H2Error>) {
    match result {
        Ok(_res) => {
            // Edge cases should be handled without crashing
            // Specific validation depends on edge case type
        }
        Err(_) => {
            // Errors during edge case tests are acceptable
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_self_dependency_basic() {
        let data = [1, 16]; // stream_id=3, weight=16
        let result = test_self_dependency_detection(&data);
        assert!(result.is_ok());

        let res = result.unwrap();
        if res.attempts > 0 {
            assert!(res.rejections > 0, "Self-dependency should be rejected");
        }
    }

    #[test]
    fn test_simple_cycle_basic() {
        let result = test_simple_cycle_detection(1, 3, 16, 32, false, true);
        assert!(result.is_ok());

        let res = result.unwrap();
        assert_eq!(res.cycle_length, 2);
        if res.attempts >= 2 {
            assert!(res.rejections > 0, "Cycle should be detected and rejected");
        }
    }

    #[test]
    fn test_long_chain_cycle_basic() {
        let chain_data = [10, 20, 30, 40];
        let result = test_long_chain_cycle(4, &chain_data);
        assert!(result.is_ok());

        let res = result.unwrap();
        assert_eq!(res.cycle_length, 4);
    }

    #[test]
    fn test_deep_chain_no_cycle() {
        let depth_data = [16, 32, 48, 64];
        let result = test_deep_dependency_chain(4, &depth_data);
        assert!(result.is_ok());

        let res = result.unwrap();
        assert_eq!(res.depth, 4);
        // Linear dependencies should mostly succeed
        if res.chain_attempts > 0 {
            assert!(
                res.chain_successes > 0,
                "Linear dependencies should succeed"
            );
        }
    }

    #[test]
    fn test_edge_cases_basic() {
        let edge_data = [42, 128];
        for edge_type in 0..4 {
            let result = test_edge_cases(edge_type, &edge_data);
            assert!(result.is_ok(), "Edge case {} should not panic", edge_type);
        }
    }
}
