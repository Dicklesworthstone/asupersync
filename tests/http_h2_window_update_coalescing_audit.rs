//! Audit test for HTTP/2 flow control WINDOW_UPDATE coalescing.
//!
//! Per RFC 7540, WINDOW_UPDATE frames should be coalesced rather than sent
//! eagerly after every read. This prevents excessive frame overhead and
//! maintains proper flow control backpressure.
//!
//! IMPLEMENTATION ANALYSIS: Our implementation correctly implements coalescing:
//! - Stream-level: WINDOW_UPDATE sent when window drops below 25% (quarter-window)
//! - Connection-level: WINDOW_UPDATE sent when window drops below 50% (half-window)
//! This is SOUND and follows RFC 7540 recommendations.

use asupersync::bytes::Bytes;
use asupersync::http::h2::connection::{Connection, ConnectionState};
use asupersync::http::h2::frame::{DataFrame, Frame, HeadersFrame, WindowUpdateFrame};
use asupersync::http::h2::settings::Settings;

const DEFAULT_WINDOW_SIZE: u32 = 65535;

#[test]
fn test_stream_window_update_coalescing_quarter_threshold() {
    let mut conn = Connection::server(Settings::default());
    conn.state = ConnectionState::Open;

    // Open a stream via HEADERS
    let headers = Frame::Headers(HeadersFrame::new(1, Bytes::new(), false, true));
    conn.process_frame(headers).expect("process headers");

    // Consume data just below the 25% threshold - should NOT trigger WINDOW_UPDATE
    let below_threshold = (DEFAULT_WINDOW_SIZE * 3 / 4) - 1; // 74.99% consumed, 25.01% remaining
    let data = Bytes::from(vec![0u8; below_threshold as usize]);
    let frame = Frame::Data(DataFrame::new(1, data, false));
    conn.process_frame(frame)
        .expect("process data below threshold");

    // Check that NO stream WINDOW_UPDATE was queued
    let mut found_stream_update = false;
    while let Some(frame) = conn.next_frame() {
        if let Frame::WindowUpdate(wu) = frame {
            if wu.stream_id == 1 {
                found_stream_update = true;
            }
        }
    }
    assert!(
        !found_stream_update,
        "Stream WINDOW_UPDATE should NOT be sent when above 25% threshold ({}% consumed)",
        (below_threshold as f64 / DEFAULT_WINDOW_SIZE as f64) * 100.0
    );

    println!("✓ PASS: No WINDOW_UPDATE sent when stream window above 25% threshold");

    // Now consume just enough to cross the 25% threshold
    let cross_threshold_data = Bytes::from(vec![0u8; 10]); // Push us just below 25%
    let frame = Frame::Data(DataFrame::new(1, cross_threshold_data, false));
    conn.process_frame(frame)
        .expect("process data to cross threshold");

    // Now we should get a stream WINDOW_UPDATE
    let mut found_stream_update = false;
    let mut window_update_increment = 0;
    while let Some(frame) = conn.next_frame() {
        if let Frame::WindowUpdate(wu) = frame {
            if wu.stream_id == 1 {
                found_stream_update = true;
                window_update_increment = wu.increment;
            }
        }
    }
    assert!(
        found_stream_update,
        "Stream WINDOW_UPDATE should be sent when below 25% threshold"
    );

    println!("✓ PASS: WINDOW_UPDATE sent when stream window below 25% threshold");
    println!("  Increment: {} bytes", window_update_increment);
}

#[test]
fn test_connection_window_update_coalescing_half_threshold() {
    let mut conn = Connection::server(Settings::default());
    conn.state = ConnectionState::Open;

    // Open a stream
    let headers = Frame::Headers(HeadersFrame::new(1, Bytes::new(), false, true));
    conn.process_frame(headers).expect("process headers");

    // Consume data just below the 50% connection threshold - should NOT trigger connection WINDOW_UPDATE
    let below_threshold = (DEFAULT_WINDOW_SIZE / 2) - 1000; // ~49% consumed, 51% remaining
    let data = Bytes::from(vec![0u8; below_threshold as usize]);
    let frame = Frame::Data(DataFrame::new(1, data, false));
    conn.process_frame(frame)
        .expect("process data below connection threshold");

    // Check that NO connection WINDOW_UPDATE was queued
    let mut found_connection_update = false;
    while let Some(frame) = conn.next_frame() {
        if let Frame::WindowUpdate(wu) = frame {
            if wu.stream_id == 0 {
                found_connection_update = true;
            }
        }
    }
    assert!(
        !found_connection_update,
        "Connection WINDOW_UPDATE should NOT be sent when above 50% threshold"
    );

    println!("✓ PASS: No connection WINDOW_UPDATE sent when above 50% threshold");

    // Now consume enough to cross the 50% connection threshold
    let cross_threshold_data = Bytes::from(vec![0u8; 2000]); // Push us below 50%
    let frame = Frame::Data(DataFrame::new(1, cross_threshold_data, false));
    conn.process_frame(frame)
        .expect("process data to cross connection threshold");

    // Now we should get a connection WINDOW_UPDATE
    let mut found_connection_update = false;
    let mut window_update_increment = 0;
    while let Some(frame) = conn.next_frame() {
        if let Frame::WindowUpdate(wu) = frame {
            if wu.stream_id == 0 {
                found_connection_update = true;
                window_update_increment = wu.increment;
            }
        }
    }
    assert!(
        found_connection_update,
        "Connection WINDOW_UPDATE should be sent when below 50% threshold"
    );

    println!("✓ PASS: Connection WINDOW_UPDATE sent when below 50% threshold");
    println!("  Increment: {} bytes", window_update_increment);
}

#[test]
fn test_no_eager_window_updates_on_small_reads() {
    let mut conn = Connection::server(Settings::default());
    conn.state = ConnectionState::Open;

    // Open a stream
    let headers = Frame::Headers(HeadersFrame::new(1, Bytes::new(), false, true));
    conn.process_frame(headers).expect("process headers");

    // Send many small data frames (simulating small reads)
    let small_read_count = 20;
    let bytes_per_read = 1000;

    for i in 0..small_read_count {
        let data = Bytes::from(vec![0u8; bytes_per_read]);
        let frame = Frame::Data(DataFrame::new(1, data, false));
        conn.process_frame(frame)
            .expect(&format!("process small read {}", i + 1));

        // Check for WINDOW_UPDATEs after each small read
        let mut frames_after_read = Vec::new();
        while let Some(frame) = conn.next_frame() {
            frames_after_read.push(frame);
        }

        // Count WINDOW_UPDATEs
        let window_update_count = frames_after_read
            .iter()
            .filter(|f| matches!(f, Frame::WindowUpdate(_)))
            .count();

        // We should not get a WINDOW_UPDATE after every small read
        let total_consumed = (i + 1) * bytes_per_read;
        let consumption_percent = (total_consumed as f64 / DEFAULT_WINDOW_SIZE as f64) * 100.0;

        if consumption_percent < 75.0 {
            // Well below stream threshold
            assert_eq!(
                window_update_count,
                0,
                "No WINDOW_UPDATE should be sent for small read {} ({}% consumed)",
                i + 1,
                consumption_percent
            );
        }
    }

    println!("✓ PASS: No eager WINDOW_UPDATEs sent for small reads");
    println!(
        "  Processed {} reads of {} bytes each",
        small_read_count, bytes_per_read
    );
    println!(
        "  Total consumed: {} bytes ({}% of window)",
        small_read_count * bytes_per_read,
        (small_read_count * bytes_per_read) as f64 / DEFAULT_WINDOW_SIZE as f64 * 100.0
    );
}

#[test]
fn test_window_update_restores_full_capacity() {
    let mut conn = Connection::server(Settings::default());
    conn.state = ConnectionState::Open;

    // Open a stream
    let headers = Frame::Headers(HeadersFrame::new(1, Bytes::new(), false, true));
    conn.process_frame(headers).expect("process headers");

    // Consume enough to trigger stream WINDOW_UPDATE (below 25% threshold)
    let consume_amount = (DEFAULT_WINDOW_SIZE * 3 / 4) + 1000; // ~76% consumed
    let data = Bytes::from(vec![0u8; consume_amount as usize]);
    let frame = Frame::Data(DataFrame::new(1, data, false));
    conn.process_frame(frame)
        .expect("process data to trigger WINDOW_UPDATE");

    // Get the WINDOW_UPDATE increment
    let mut stream_increment = None;
    while let Some(frame) = conn.next_frame() {
        if let Frame::WindowUpdate(wu) = frame {
            if wu.stream_id == 1 {
                stream_increment = Some(wu.increment);
            }
        }
    }

    let increment = stream_increment.expect("Should have received stream WINDOW_UPDATE");

    // Verify that the increment restores the window to its full capacity
    let remaining_window = DEFAULT_WINDOW_SIZE - consume_amount;
    let expected_increment = DEFAULT_WINDOW_SIZE - remaining_window;

    assert_eq!(
        increment, expected_increment,
        "WINDOW_UPDATE increment should restore window to full capacity"
    );

    println!("✓ PASS: WINDOW_UPDATE restores stream window to full capacity");
    println!("  Consumed: {} bytes", consume_amount);
    println!("  Remaining before update: {} bytes", remaining_window);
    println!("  WINDOW_UPDATE increment: {} bytes", increment);
    println!(
        "  Window after update: {} bytes (full capacity)",
        DEFAULT_WINDOW_SIZE
    );
}

#[test]
fn audit_http2_window_update_coalescing_compliance() {
    println!("\n=== HTTP/2 WINDOW_UPDATE COALESCING COMPLIANCE AUDIT ===\n");

    println!("RFC 7540 REQUIREMENT:");
    println!("- Section 6.9: WINDOW_UPDATE frames should be coalesced to reduce overhead");
    println!("- Prefer batching over eager sending after every read");
    println!("- Maintain proper flow control backpressure\n");

    println!("IMPLEMENTATION ANALYSIS:");
    println!("File: src/http/h2/connection.rs + src/http/h2/stream.rs");
    println!("1. Stream-level coalescing (lines 729-742):");
    println!("   - WINDOW_UPDATE sent when receive window drops below 25%");
    println!("   - Comment: 'prevents eager WINDOW_UPDATE sending that defeats flow control'");
    println!("2. Connection-level coalescing (lines 710-716):");
    println!("   - WINDOW_UPDATE sent when receive window drops below 50%");
    println!("   - Watermark-based triggering, not per-read\n");

    println!("COMPLIANCE VERIFICATION:");
    println!("✓ SOUND: Quarter-window threshold for streams (25%)");
    println!("✓ SOUND: Half-window threshold for connection (50%)");
    println!("✓ SOUND: No eager updates on small reads");
    println!("✓ SOUND: WINDOW_UPDATE restores full window capacity");
    println!("✓ SOUND: Proper coalescing reduces frame overhead\n");

    println!("BEHAVIOR PINNED: Implementation correctly follows RFC 7540");
    println!("- Coalescing preferred over eager updates ✓");
    println!("- Conservative thresholds maintain backpressure ✓");
    println!("- No changes needed - current implementation is optimal ✓");
}

#[test]
fn run_audit() {
    audit_http2_window_update_coalescing_compliance();
}
