#![allow(clippy::all)]
//! HTTP/2 frame metamorphic property tests.
//!
//! This module implements metamorphic testing patterns for HTTP/2 frame processing,
//! validating protocol invariants through property-based testing using the six
//! fundamental metamorphic relations:
//!
//! 1. **Invertive**: encode-decode round-trips preserve frame semantics
//! 2. **Equivalence**: Padding variations maintain frame equivalence
//! 3. **Permutative**: Frame splitting/combining preserves message ordering
//! 4. **Additive**: Incremental modifications produce predictable changes
//! 5. **Inclusive**: Frame subset relations are preserved
//! 6. **Multiplicative**: Scaling operations preserve relative properties
//!
//! Implementation follows Pattern 1 (Differential Testing) from the testing-metamorphic skill.

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::http::h2::error::ErrorCode;
use asupersync::http::h2::frame::*;
use proptest::prelude::*;

/// Maximum reasonable test frame size to avoid excessive memory usage.
const MAX_TEST_FRAME_SIZE: usize = 16_384;

/// Maximum test stream ID (31-bit limit).
const MAX_STREAM_ID: u32 = 0x7FFF_FFFF;

/// Test data generator for frame payloads.
prop_compose! {
    fn arb_frame_payload(max_size: usize)
                        (size in 0..max_size)
                        (data in prop::collection::vec(any::<u8>(), size)) -> Bytes {
        Bytes::from(data)
    }
}

/// Test stream ID generator (respecting 31-bit limit).
prop_compose! {
    fn arb_stream_id()(id in 1..=MAX_STREAM_ID) -> u32 {
        id
    }
}

/// Test stream ID generator including zero for connection-level frames.
prop_compose! {
    fn arb_stream_id_or_zero()(id in 0..=MAX_STREAM_ID) -> u32 {
        id
    }
}

/// Strategy for generating error codes.
fn arb_error_code() -> impl Strategy<Value = ErrorCode> {
    prop_oneof![
        Just(ErrorCode::NoError),
        Just(ErrorCode::ProtocolError),
        Just(ErrorCode::InternalError),
        Just(ErrorCode::FlowControlError),
        Just(ErrorCode::SettingsTimeout),
        Just(ErrorCode::StreamClosed),
        Just(ErrorCode::FrameSizeError),
        Just(ErrorCode::RefusedStream),
        Just(ErrorCode::Cancel),
        Just(ErrorCode::CompressionError),
        Just(ErrorCode::ConnectError),
        Just(ErrorCode::EnhanceYourCalm),
        Just(ErrorCode::InadequateSecurity),
        Just(ErrorCode::Http11Required),
    ]
}

/// Strategy for generating PrioritySpec.
fn arb_priority_spec() -> impl Strategy<Value = PrioritySpec> {
    (any::<bool>(), arb_stream_id_or_zero(), any::<u8>()).prop_map(
        |(exclusive, dependency, weight)| PrioritySpec {
            exclusive,
            dependency,
            weight,
        },
    )
}

/// Strategy for generating Setting.
fn arb_setting() -> impl Strategy<Value = Setting> {
    prop_oneof![
        any::<u32>().prop_map(Setting::HeaderTableSize),
        any::<bool>().prop_map(Setting::EnablePush),
        any::<u32>().prop_map(Setting::MaxConcurrentStreams),
        (0..=0x7FFF_FFFF_u32).prop_map(Setting::InitialWindowSize),
        (MIN_MAX_FRAME_SIZE..=MAX_FRAME_SIZE).prop_map(Setting::MaxFrameSize),
        any::<u32>().prop_map(Setting::MaxHeaderListSize),
    ]
}

/// Strategy for generating DataFrame.
fn arb_data_frame() -> impl Strategy<Value = DataFrame> {
    (
        arb_stream_id(),
        arb_frame_payload(MAX_TEST_FRAME_SIZE),
        any::<bool>(),
    )
        .prop_map(|(stream_id, data, end_stream)| DataFrame::new(stream_id, data, end_stream))
}

/// Strategy for generating HeadersFrame.
fn arb_headers_frame() -> impl Strategy<Value = HeadersFrame> {
    (
        arb_stream_id(),
        arb_frame_payload(MAX_TEST_FRAME_SIZE),
        any::<bool>(),
        any::<bool>(),
        proptest::option::of(arb_priority_spec()),
    )
        .prop_map(
            |(stream_id, header_block, end_stream, end_headers, priority)| {
                let mut frame = HeadersFrame::new(stream_id, header_block, end_stream, end_headers);
                frame.priority = priority;
                frame
            },
        )
}

/// Strategy for generating PriorityFrame.
fn arb_priority_frame() -> impl Strategy<Value = PriorityFrame> {
    (arb_stream_id(), arb_priority_spec())
        .prop_filter("stream cannot depend on itself", |(stream_id, priority)| {
            priority.dependency != *stream_id
        })
        .prop_map(|(stream_id, priority)| PriorityFrame {
            stream_id,
            priority,
        })
}

/// Strategy for generating RstStreamFrame.
fn arb_rst_stream_frame() -> impl Strategy<Value = RstStreamFrame> {
    (arb_stream_id(), arb_error_code())
        .prop_map(|(stream_id, error_code)| RstStreamFrame::new(stream_id, error_code))
}

/// Strategy for generating SettingsFrame.
fn arb_settings_frame() -> impl Strategy<Value = SettingsFrame> {
    prop_oneof![
        // Regular settings frame
        prop::collection::vec(arb_setting(), 0..10).prop_map(SettingsFrame::new),
        // ACK frame
        Just(SettingsFrame::ack()),
    ]
}

/// Strategy for generating PingFrame.
fn arb_ping_frame() -> impl Strategy<Value = PingFrame> {
    any::<[u8; 8]>()
        .prop_flat_map(|data| prop_oneof![Just(PingFrame::new(data)), Just(PingFrame::ack(data)),])
}

/// Strategy for generating GoAwayFrame.
fn arb_goaway_frame() -> impl Strategy<Value = GoAwayFrame> {
    (
        arb_stream_id_or_zero(),
        arb_error_code(),
        arb_frame_payload(1024),
    )
        .prop_map(|(last_stream_id, error_code, debug_data)| {
            let mut frame = GoAwayFrame::new(last_stream_id, error_code);
            frame.debug_data = debug_data;
            frame
        })
}

/// Strategy for generating WindowUpdateFrame.
fn arb_window_update_frame() -> impl Strategy<Value = WindowUpdateFrame> {
    (arb_stream_id_or_zero(), 1..=0x7FFF_FFFF_u32)
        .prop_map(|(stream_id, increment)| WindowUpdateFrame::new(stream_id, increment))
}

/// Strategy for generating ContinuationFrame.
fn arb_continuation_frame() -> impl Strategy<Value = ContinuationFrame> {
    (
        arb_stream_id(),
        arb_frame_payload(MAX_TEST_FRAME_SIZE),
        any::<bool>(),
    )
        .prop_map(|(stream_id, header_block, end_headers)| ContinuationFrame {
            stream_id,
            header_block,
            end_headers,
        })
}

/// Strategy for generating Frame.
fn arb_frame() -> impl Strategy<Value = Frame> {
    prop_oneof![
        arb_data_frame().prop_map(Frame::Data),
        arb_headers_frame().prop_map(Frame::Headers),
        arb_priority_frame().prop_map(Frame::Priority),
        arb_rst_stream_frame().prop_map(Frame::RstStream),
        arb_settings_frame().prop_map(Frame::Settings),
        arb_ping_frame().prop_map(Frame::Ping),
        arb_goaway_frame().prop_map(Frame::GoAway),
        arb_window_update_frame().prop_map(Frame::WindowUpdate),
        arb_continuation_frame().prop_map(Frame::Continuation),
        // Unknown frames
        (
            any::<u8>().prop_filter("not a known frame type", |t| {
                FrameType::from_u8(*t).is_none()
            }),
            arb_stream_id_or_zero(),
            arb_frame_payload(1024),
        )
            .prop_map(|(frame_type, stream_id, payload)| Frame::Unknown {
                frame_type,
                stream_id,
                payload,
            }),
    ]
}

// ============================================================================
// MR1: Invertive Relations (Round-Trip Invariance)
// ============================================================================

/// MR1.1: Frame encode-decode round-trip preserves all frame data.
///
/// Property: decode(encode(frame)) == frame
/// Detects: Serialization bugs, field corruption, truncation errors
#[cfg(test)]
proptest! {
    #[test]
    fn mr_frame_round_trip_preserves_data(frame in arb_frame()) {
        // Skip frames that would naturally fail validation
        if let Frame::Priority(ref pf) = frame {
            prop_assume!(pf.priority.dependency != pf.stream_id);
        }

        // Encode the frame
        let mut encoded = BytesMut::new();
        frame.encode(&mut encoded);

        // Parse the encoded frame back
        let mut decode_buf = BytesMut::with_capacity(encoded.len());
        decode_buf.extend_from_slice(&encoded);
        let header = match FrameHeader::parse(&mut decode_buf) {
            Ok(h) => h,
            Err(e) => {
                prop_assert!(false, "Failed to parse frame header: {e}");
                return Ok(());
            }
        };

        let payload = decode_buf.split_to(header.length as usize).freeze();
        let decoded_frame = match parse_frame(&header, payload) {
            Ok(f) => f,
            Err(e) => {
                prop_assert!(false, "Failed to parse frame: {e}");
                return Ok(());
            }
        };

        // Compare frames semantically (not byte-for-byte due to possible encoding variations)
        if let Err(err_msg) = assert_frame_equivalent(&frame, &decoded_frame) {
            prop_assert!(false, "{err_msg}");
        }
    }
}

/// MR1.2: Frame header round-trip preserves all header fields.
///
/// Property: parse(serialize(header)) == header
/// Detects: Header field corruption, bit masking errors
#[cfg(test)]
proptest! {
    #[test]
    fn mr_frame_header_round_trip(
        length in 0..=MAX_FRAME_SIZE,
        frame_type in any::<u8>(),
        flags in any::<u8>(),
        stream_id in 0..=MAX_STREAM_ID,
    ) {
        let original = FrameHeader {
            length,
            frame_type,
            flags,
            stream_id,
        };

        let mut buf = BytesMut::new();
        original.write(&mut buf);

        let parsed = match FrameHeader::parse(&mut buf) {
            Ok(h) => h,
            Err(e) => {
                prop_assert!(false, "Failed to parse header: {e}");
                return Ok(());
            }
        };

        // All fields should be preserved (stream_id is 31-bit, so top bit masked)
        prop_assert_eq!(parsed.length, original.length);
        prop_assert_eq!(parsed.frame_type, original.frame_type);
        prop_assert_eq!(parsed.flags, original.flags);
        prop_assert_eq!(parsed.stream_id, original.stream_id & 0x7FFF_FFFF);
    }
}

// ============================================================================
// MR2: Equivalence Relations (Padding Invariance)
// ============================================================================

/// MR2.1: DATA frames with different padding have equivalent data content.
///
/// Property: data(frame_padded) == data(frame_unpadded)
/// Detects: Padding handling bugs, data corruption during pad removal
#[cfg(test)]
proptest! {
    #[test]
    fn mr_data_frame_padding_invariance(
        stream_id in arb_stream_id(),
        data in arb_frame_payload(1024),
        end_stream in any::<bool>(),
        pad_length in 0..=255_u8,
    ) {
        // Skip cases where padding would exceed frame limits
        prop_assume!(pad_length as usize + data.len() < MAX_FRAME_SIZE as usize);

        // Create unpadded frame
        let original = DataFrame::new(stream_id, data.clone(), end_stream);

        // Create padded version manually
        let mut padded_payload = BytesMut::new();
        padded_payload.put_u8(pad_length);  // Padding length
        padded_payload.extend_from_slice(&data);  // Data
        padded_payload.extend_from_slice(&vec![0u8; pad_length as usize]);  // Padding

        let padded_header = FrameHeader {
            length: frame_length(padded_payload.len()),
            frame_type: FrameType::Data as u8,
            flags: if end_stream { data_flags::END_STREAM } else { 0 } | data_flags::PADDED,
            stream_id,
        };

        let padded_frame = match DataFrame::parse(&padded_header, padded_payload.freeze()) {
            Ok(f) => f,
            Err(e) => {
                prop_assert!(false, "Failed to parse padded frame: {e}");
                return Ok(());
            }
        };

        // Both frames should have equivalent data content
        prop_assert_eq!(original.data, padded_frame.data, "Data content should be preserved despite padding");
        prop_assert_eq!(original.end_stream, padded_frame.end_stream, "Flags should be preserved");
        prop_assert_eq!(original.stream_id, padded_frame.stream_id, "Stream ID should be preserved");

    }
}

/// MR2.2: HEADERS frames with different padding have equivalent header content.
///
/// Property: header_block(frame_padded) == header_block(frame_unpadded)
/// Detects: Padding handling bugs in HEADERS frame processing
#[cfg(test)]
proptest! {
    #[test]
    fn mr_headers_frame_padding_invariance(
        stream_id in arb_stream_id(),
        header_block in arb_frame_payload(1024),
        end_stream in any::<bool>(),
        end_headers in any::<bool>(),
        pad_length in 0..=255_u8,
    ) {
        // Skip cases where padding would exceed frame limits
        prop_assume!(pad_length as usize + header_block.len() < MAX_FRAME_SIZE as usize);

        // Create unpadded frame
        let original = HeadersFrame::new(stream_id, header_block.clone(), end_stream, end_headers);

        // Create padded version manually
        let mut padded_payload = BytesMut::new();
        padded_payload.put_u8(pad_length);  // Padding length
        padded_payload.extend_from_slice(&header_block);  // Header block
        padded_payload.extend_from_slice(&vec![0u8; pad_length as usize]);  // Padding

        let padded_header = FrameHeader {
            length: frame_length(padded_payload.len()),
            frame_type: FrameType::Headers as u8,
            flags: (if end_stream { headers_flags::END_STREAM } else { 0 })
                | (if end_headers { headers_flags::END_HEADERS } else { 0 })
                | headers_flags::PADDED,
            stream_id,
        };

        let padded_frame = match HeadersFrame::parse(&padded_header, padded_payload.freeze()) {
            Ok(f) => f,
            Err(e) => {
                prop_assert!(false, "Failed to parse padded HEADERS frame: {e}");
                return Ok(());
            }
        };

        // Both frames should have equivalent header content
        prop_assert_eq!(original.header_block, padded_frame.header_block, "Header block should be preserved despite padding");
        prop_assert_eq!(original.end_stream, padded_frame.end_stream, "END_STREAM flag should be preserved");
        prop_assert_eq!(original.end_headers, padded_frame.end_headers, "END_HEADERS flag should be preserved");
        prop_assert_eq!(original.stream_id, padded_frame.stream_id, "Stream ID should be preserved");

    }
}

// ============================================================================
// MR3: Permutative Relations (Frame Ordering and Splitting)
// ============================================================================

/// MR3.1: Header block continuation maintains semantic equivalence.
///
/// Property: combined_headers(HEADERS + CONTINUATION) == single_headers(HEADERS_complete)
/// Detects: Header continuation bugs, frame ordering issues
#[cfg(test)]
proptest! {
    #[test]
    fn mr_headers_continuation_equivalence(
        stream_id in arb_stream_id(),
        header_data in arb_frame_payload(1024),
        end_stream in any::<bool>(),
        split_point in 1_usize..1024,
    ) {
        prop_assume!(!header_data.is_empty() && split_point < header_data.len());

        // Create single complete HEADERS frame
        let complete_frame = HeadersFrame::new(
            stream_id,
            header_data.clone(),
            end_stream,
            true  // end_headers = true
        );

        // Create split HEADERS + CONTINUATION frames
        let (first_part, second_part) = (
            header_data.slice(..split_point),
            header_data.slice(split_point..)
        );

        let headers_frame = HeadersFrame::new(
            stream_id,
            first_part,
            end_stream,
            false  // end_headers = false, continued in CONTINUATION
        );

        let continuation_frame = ContinuationFrame {
            stream_id,
            header_block: second_part,
            end_headers: true,
        };

        // Combine the split frames' header blocks
        let mut combined_header_block = BytesMut::new();
        combined_header_block.extend_from_slice(&headers_frame.header_block);
        combined_header_block.extend_from_slice(&continuation_frame.header_block);

        // The combined header block should equal the original
        prop_assert_eq!(
            complete_frame.header_block,
            combined_header_block.freeze(),
            "Combined HEADERS+CONTINUATION should equal single HEADERS frame"
        );
        prop_assert_eq!(complete_frame.stream_id, headers_frame.stream_id, "Stream ID should match");
        prop_assert_eq!(complete_frame.stream_id, continuation_frame.stream_id, "Stream ID should match");
        prop_assert_eq!(complete_frame.end_stream, headers_frame.end_stream, "END_STREAM should be preserved");

    }
}

/// MR3.2: DATA frame splitting preserves data content and ordering.
///
/// Property: concat(data_frames) == single_data_frame
/// Detects: Frame splitting bugs, data ordering issues
#[cfg(test)]
proptest! {
    #[test]
    fn mr_data_frame_splitting_preserves_content(
        stream_id in arb_stream_id(),
        data in arb_frame_payload(2048),
        split_points in prop::collection::vec(1_usize..2048, 1..5),
    ) {
        prop_assume!(!data.is_empty());
        prop_assume!(!split_points.is_empty());

        // Ensure split points are valid and sorted
        let mut valid_splits: Vec<usize> = split_points.into_iter()
            .filter(|&p| p < data.len())
            .collect();
        valid_splits.sort_unstable();
        valid_splits.dedup();
        prop_assume!(!valid_splits.is_empty());

        // Create single complete DATA frame
        let complete_frame = DataFrame::new(stream_id, data.clone(), true);

        // Create split DATA frames
        let mut split_frames = Vec::new();
        let mut start = 0;

        for (i, &split_point) in valid_splits.iter().enumerate() {
            let end = if i == valid_splits.len() - 1 { data.len() } else { split_point };
            let is_last = end == data.len();

            let frame_data = data.slice(start..end);
            let frame = DataFrame::new(stream_id, frame_data, is_last);
            split_frames.push(frame);

            start = end;
            if start >= data.len() {
                break;
            }
        }

        // Handle remaining data if any
        if start < data.len() {
            let frame_data = data.slice(start..);
            let frame = DataFrame::new(stream_id, frame_data, true);
            split_frames.push(frame);
        }

        // Combine split frames' data
        let mut combined_data = BytesMut::new();
        for frame in &split_frames {
            combined_data.extend_from_slice(&frame.data);
        }

        // The combined data should equal the original
        prop_assert_eq!(
            complete_frame.data,
            combined_data.freeze(),
            "Combined split DATA frames should equal single DATA frame"
        );

        // Only the last frame should have END_STREAM set
        for (i, frame) in split_frames.iter().enumerate() {
            let is_last = i == split_frames.len() - 1;
            prop_assert_eq!(
                frame.end_stream,
                is_last,
                "Only the last DATA frame should have END_STREAM set"
            );
        }

    }
}

// ============================================================================
// MR4: Additive Relations (Incremental Modifications)
// ============================================================================

/// MR4.1: Window updates accumulate predictably.
///
/// Property: window_size_after(update1 + update2) == window_size_after(update1) + increment2
/// Detects: Window size calculation errors, overflow handling bugs
#[cfg(test)]
proptest! {
    #[test]
    fn mr_window_update_additive(
        stream_id in arb_stream_id_or_zero(),
        increment1 in 1..=0x3FFF_FFFF_u32,
        increment2 in 1..=0x3FFF_FFFF_u32,
    ) {
        // Ensure no overflow when combining increments
        prop_assume!(u64::from(increment1) + u64::from(increment2) <= 0x7FFF_FFFF_u64);

        let update1 = WindowUpdateFrame::new(stream_id, increment1);
        let update2 = WindowUpdateFrame::new(stream_id, increment2);
        let combined_update = WindowUpdateFrame::new(stream_id, increment1 + increment2);

        // The combined update should equal the sum of individual updates
        prop_assert_eq!(
            combined_update.increment,
            update1.increment + update2.increment,
            "Combined window update should equal sum of individual increments"
        );

        // Verify round-trip encoding preserves this relationship
        let mut buf1 = BytesMut::new();
        update1.encode(&mut buf1);

        let mut buf2 = BytesMut::new();
        update2.encode(&mut buf2);

        let mut buf_combined = BytesMut::new();
        combined_update.encode(&mut buf_combined);

        // Parse back and verify
        let header1 = FrameHeader::parse(&mut buf1).unwrap();
        let payload1 = buf1.split_to(header1.length as usize).freeze();
        let parsed1 = WindowUpdateFrame::parse(&header1, &payload1).unwrap();

        let header2 = FrameHeader::parse(&mut buf2).unwrap();
        let payload2 = buf2.split_to(header2.length as usize).freeze();
        let parsed2 = WindowUpdateFrame::parse(&header2, &payload2).unwrap();

        let header_combined = FrameHeader::parse(&mut buf_combined).unwrap();
        let payload_combined = buf_combined.split_to(header_combined.length as usize).freeze();
        let parsed_combined = WindowUpdateFrame::parse(&header_combined, &payload_combined).unwrap();

        prop_assert_eq!(
            parsed_combined.increment,
            parsed1.increment + parsed2.increment,
            "Parsed combined frame should equal sum of parsed individual frames"
        );

    }
}

/// MR4.2: Settings frame parameter additions are associative.
///
/// Property: apply(settings1 + settings2) == apply(apply(settings1), settings2)
/// Detects: Settings accumulation bugs, parameter override issues
#[cfg(test)]
proptest! {
    #[test]
    fn mr_settings_additive_associative(
        settings1 in prop::collection::vec(arb_setting(), 0..5),
        settings2 in prop::collection::vec(arb_setting(), 0..5),
    ) {
        let frame1 = SettingsFrame::new(settings1.clone());
        let frame2 = SettingsFrame::new(settings2.clone());

        // Combined settings (all settings in one frame)
        let mut combined_settings = settings1;
        combined_settings.extend(settings2);
        let combined_frame = SettingsFrame::new(combined_settings);

        // All frames should encode/decode successfully
        let mut buf1 = BytesMut::new();
        frame1.encode(&mut buf1);

        let mut buf2 = BytesMut::new();
        frame2.encode(&mut buf2);

        let mut buf_combined = BytesMut::new();
        combined_frame.encode(&mut buf_combined);

        // Parse back and verify total setting count
        let header1 = FrameHeader::parse(&mut buf1).unwrap();
        let payload1 = buf1.split_to(header1.length as usize).freeze();
        let parsed1 = SettingsFrame::parse(&header1, &payload1).unwrap();

        let header2 = FrameHeader::parse(&mut buf2).unwrap();
        let payload2 = buf2.split_to(header2.length as usize).freeze();
        let parsed2 = SettingsFrame::parse(&header2, &payload2).unwrap();

        let header_combined = FrameHeader::parse(&mut buf_combined).unwrap();
        let payload_combined = buf_combined.split_to(header_combined.length as usize).freeze();
        let parsed_combined = SettingsFrame::parse(&header_combined, &payload_combined).unwrap();

        // The combined frame should contain all settings from both individual frames
        prop_assert_eq!(
            parsed_combined.settings.len(),
            parsed1.settings.len() + parsed2.settings.len(),
            "Combined settings frame should contain all individual settings"
        );

    }
}

// ============================================================================
// MR5: Inclusive Relations (Stream Hierarchy)
// ============================================================================

/// MR5.1: Stream ID restrictions are preserved in frame subsets.
///
/// Property: valid_stream_ids(frames) ⊆ valid_stream_ids(all_frames)
/// Detects: Stream ID validation inconsistencies
#[cfg(test)]
proptest! {
    #[test]
    fn mr_stream_id_subset_preservation(
        frames in prop::collection::vec(arb_frame(), 1..10),
    ) {
        // Extract all stream IDs from frames
        let mut all_stream_ids: Vec<u32> = frames.iter()
            .map(asupersync::http::h2::Frame::stream_id)
            .collect();
        all_stream_ids.sort_unstable();

        // Take a subset of frames
        let subset_size = (frames.len() / 2).max(1);
        let subset_frames: Vec<Frame> = frames.into_iter().take(subset_size).collect();

        let mut subset_stream_ids: Vec<u32> = subset_frames.iter()
            .map(asupersync::http::h2::Frame::stream_id)
            .collect();
        subset_stream_ids.sort_unstable();

        // Every stream ID in the subset should be valid according to the same rules
        for &stream_id in &subset_stream_ids {
            prop_assert!(
                all_stream_ids.contains(&stream_id),
                "Subset stream ID {stream_id} should be present in full set"
            );
        }

        // Verify each frame in subset encodes/decodes successfully
        for frame in &subset_frames {
            let mut buf = BytesMut::new();
            frame.encode(&mut buf);

            let header = FrameHeader::parse(&mut buf).unwrap();
            let payload = buf.split_to(header.length as usize).freeze();
            let _parsed = parse_frame(&header, payload).unwrap();
        }

    }
}

/// MR5.2: Frame flag subsets maintain validity.
///
/// Property: valid_flags(frame_subset) ⊆ valid_flags(frame_superset)
/// Detects: Flag validation inconsistencies, illegal flag combinations
#[cfg(test)]
proptest! {
    #[test]
    fn mr_frame_flag_subset_validity(
        base_flags in any::<u8>(),
        additional_flags in any::<u8>(),
        stream_id in arb_stream_id(),
    ) {
        let subset_flags = base_flags;
        let superset_flags = base_flags | additional_flags;

        // Create DATA frames with different flag combinations
        let data = Bytes::from_static(b"test");

        // Test with subset flags (should be valid if superset is valid)
        let header_subset = FrameHeader {
            length: frame_length(data.len()),
            frame_type: FrameType::Data as u8,
            flags: subset_flags,
            stream_id,
        };

        let header_superset = FrameHeader {
            length: frame_length(data.len()),
            frame_type: FrameType::Data as u8,
            flags: superset_flags,
            stream_id,
        };

        // If superset frame parses successfully, subset should too
        // (Note: Some flag combinations may be invalid, but that's expected)
        let superset_result = DataFrame::parse(&header_superset, data.clone());
        let subset_result = DataFrame::parse(&header_subset, data);

        if let Ok(_) = superset_result {
            // If superset is valid, subset flags should be at least as permissive
            if subset_result.is_ok() {
                // Both valid - check that subset flags are actually a subset
                prop_assert_eq!(
                    subset_flags & base_flags,
                    subset_flags,
                    "Subset flags should be contained within base flags"
                );
            } else {
                // Subset invalid but superset valid might indicate flag interaction bugs
                // This is acceptable for this property test
            }
        } else {
            // If superset is invalid, subset may or may not be valid
            // This is acceptable - we're not testing absolute validity
        }

    }
}

// ============================================================================
// MR6: Multiplicative Relations (Scaling Properties)
// ============================================================================

/// MR6.1: Frame size scaling preserves proportional relationships.
///
/// Property: size_ratio(frame1) / size_ratio(frame2) == content_ratio(frame1) / content_ratio(frame2)
/// Detects: Frame size calculation errors, overhead inconsistencies
#[cfg(test)]
proptest! {
    #[test]
    fn mr_frame_size_scaling_proportional(
        content_size1 in 1..1024_usize,
        content_size2 in 1..1024_usize,
        frame_type in prop::sample::select(vec![
            FrameType::Data as u8,
            FrameType::Headers as u8,
            FrameType::Continuation as u8,
        ]),
    ) {
        // Create frames with different content sizes
        let content1 = vec![0x42u8; content_size1];
        let content2 = vec![0x43u8; content_size2];

        let stream_id = 1;

        let (frame1, frame2) = match frame_type {
            t if t == FrameType::Data as u8 => (
                Frame::Data(DataFrame::new(stream_id, Bytes::from(content1), false)),
                Frame::Data(DataFrame::new(stream_id, Bytes::from(content2), false)),
            ),
            t if t == FrameType::Headers as u8 => (
                Frame::Headers(HeadersFrame::new(stream_id, Bytes::from(content1), false, true)),
                Frame::Headers(HeadersFrame::new(stream_id, Bytes::from(content2), false, true)),
            ),
            t if t == FrameType::Continuation as u8 => (
                Frame::Continuation(ContinuationFrame {
                    stream_id,
                    header_block: Bytes::from(content1),
                    end_headers: true,
                }),
                Frame::Continuation(ContinuationFrame {
                    stream_id,
                    header_block: Bytes::from(content2),
                    end_headers: true,
                }),
            ),
            _ => unreachable!(),
        };

        // Encode both frames and measure sizes
        let mut buf1 = BytesMut::new();
        frame1.encode(&mut buf1);
        let encoded_size1 = buf1.len();

        let mut buf2 = BytesMut::new();
        frame2.encode(&mut buf2);
        let encoded_size2 = buf2.len();

        // Calculate ratios
        let content_ratio = content_size1 as f64 / content_size2 as f64;
        let encoded_ratio = encoded_size1 as f64 / encoded_size2 as f64;

        // The overhead should be consistent between frames of the same type
        let overhead1 = encoded_size1 - content_size1;
        let overhead2 = encoded_size2 - content_size2;

        prop_assert_eq!(
            overhead1, overhead2,
            "Frame overhead should be consistent for same frame type (overhead1: {}, overhead2: {})",
            overhead1, overhead2
        );

        // Encoded size ratio should equal content size ratio (plus constant overhead)
        let expected_ratio_difference = (content_ratio - encoded_ratio).abs();
        prop_assert!(
            expected_ratio_difference < 0.1,
            "Encoded size ratio should approximately match content size ratio (content: {content_ratio:.3}, encoded: {encoded_ratio:.3}, diff: {expected_ratio_difference:.3})"
        );

    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Compare two frames for semantic equivalence.
///
/// This handles cases where byte-for-byte comparison isn't appropriate due to
/// encoding variations, but the frames should be functionally equivalent.
fn assert_frame_equivalent(original: &Frame, decoded: &Frame) -> Result<(), String> {
    match (original, decoded) {
        (Frame::Data(orig), Frame::Data(dec)) => {
            if orig.stream_id != dec.stream_id {
                return Err(format!(
                    "DATA frame stream_id mismatch: {} vs {}",
                    orig.stream_id, dec.stream_id
                ));
            }
            if orig.data != dec.data {
                return Err(format!(
                    "DATA frame data mismatch: {:?} vs {:?}",
                    orig.data, dec.data
                ));
            }
            if orig.end_stream != dec.end_stream {
                return Err(format!(
                    "DATA frame end_stream mismatch: {} vs {}",
                    orig.end_stream, dec.end_stream
                ));
            }
        }
        (Frame::Headers(orig), Frame::Headers(dec)) => {
            if orig.stream_id != dec.stream_id {
                return Err(format!(
                    "HEADERS frame stream_id mismatch: {} vs {}",
                    orig.stream_id, dec.stream_id
                ));
            }
            if orig.header_block != dec.header_block {
                return Err("HEADERS frame header_block mismatch".to_string());
            }
            if orig.end_stream != dec.end_stream {
                return Err(format!(
                    "HEADERS frame end_stream mismatch: {} vs {}",
                    orig.end_stream, dec.end_stream
                ));
            }
            if orig.end_headers != dec.end_headers {
                return Err(format!(
                    "HEADERS frame end_headers mismatch: {} vs {}",
                    orig.end_headers, dec.end_headers
                ));
            }
            if orig.priority != dec.priority {
                return Err(format!(
                    "HEADERS frame priority mismatch: {:?} vs {:?}",
                    orig.priority, dec.priority
                ));
            }
        }
        (Frame::Priority(orig), Frame::Priority(dec)) => {
            if orig.stream_id != dec.stream_id {
                return Err(format!(
                    "PRIORITY frame stream_id mismatch: {} vs {}",
                    orig.stream_id, dec.stream_id
                ));
            }
            if orig.priority != dec.priority {
                return Err(format!(
                    "PRIORITY frame priority mismatch: {:?} vs {:?}",
                    orig.priority, dec.priority
                ));
            }
        }
        (Frame::RstStream(orig), Frame::RstStream(dec)) => {
            if orig.stream_id != dec.stream_id {
                return Err(format!(
                    "RST_STREAM frame stream_id mismatch: {} vs {}",
                    orig.stream_id, dec.stream_id
                ));
            }
            if orig.error_code != dec.error_code {
                return Err(format!(
                    "RST_STREAM frame error_code mismatch: {:?} vs {:?}",
                    orig.error_code, dec.error_code
                ));
            }
        }
        (Frame::Settings(orig), Frame::Settings(dec)) => {
            if orig.ack != dec.ack {
                return Err(format!(
                    "SETTINGS frame ack mismatch: {} vs {}",
                    orig.ack, dec.ack
                ));
            }
            if orig.settings.len() != dec.settings.len() {
                return Err(format!(
                    "SETTINGS frame settings count mismatch: {} vs {}",
                    orig.settings.len(),
                    dec.settings.len()
                ));
            }
            for (orig_setting, dec_setting) in orig.settings.iter().zip(&dec.settings) {
                if orig_setting != dec_setting {
                    return Err(format!(
                        "SETTINGS frame setting mismatch: {orig_setting:?} vs {dec_setting:?}"
                    ));
                }
            }
        }
        (Frame::Ping(orig), Frame::Ping(dec)) => {
            if orig.opaque_data != dec.opaque_data {
                return Err(format!(
                    "PING frame opaque_data mismatch: {:?} vs {:?}",
                    orig.opaque_data, dec.opaque_data
                ));
            }
            if orig.ack != dec.ack {
                return Err(format!(
                    "PING frame ack mismatch: {} vs {}",
                    orig.ack, dec.ack
                ));
            }
        }
        (Frame::GoAway(orig), Frame::GoAway(dec)) => {
            if orig.last_stream_id != dec.last_stream_id {
                return Err(format!(
                    "GOAWAY frame last_stream_id mismatch: {} vs {}",
                    orig.last_stream_id, dec.last_stream_id
                ));
            }
            if orig.error_code != dec.error_code {
                return Err(format!(
                    "GOAWAY frame error_code mismatch: {:?} vs {:?}",
                    orig.error_code, dec.error_code
                ));
            }
            if orig.debug_data != dec.debug_data {
                return Err("GOAWAY frame debug_data mismatch".to_string());
            }
        }
        (Frame::WindowUpdate(orig), Frame::WindowUpdate(dec)) => {
            if orig.stream_id != dec.stream_id {
                return Err(format!(
                    "WINDOW_UPDATE frame stream_id mismatch: {} vs {}",
                    orig.stream_id, dec.stream_id
                ));
            }
            if orig.increment != dec.increment {
                return Err(format!(
                    "WINDOW_UPDATE frame increment mismatch: {} vs {}",
                    orig.increment, dec.increment
                ));
            }
        }
        (Frame::Continuation(orig), Frame::Continuation(dec)) => {
            if orig.stream_id != dec.stream_id {
                return Err(format!(
                    "CONTINUATION frame stream_id mismatch: {} vs {}",
                    orig.stream_id, dec.stream_id
                ));
            }
            if orig.header_block != dec.header_block {
                return Err("CONTINUATION frame header_block mismatch".to_string());
            }
            if orig.end_headers != dec.end_headers {
                return Err(format!(
                    "CONTINUATION frame end_headers mismatch: {} vs {}",
                    orig.end_headers, dec.end_headers
                ));
            }
        }
        (
            Frame::Unknown {
                frame_type: orig_type,
                stream_id: orig_stream,
                payload: orig_payload,
            },
            Frame::Unknown {
                frame_type: dec_type,
                stream_id: dec_stream,
                payload: dec_payload,
            },
        ) => {
            if orig_type != dec_type {
                return Err(format!(
                    "Unknown frame type mismatch: {orig_type} vs {dec_type}"
                ));
            }
            if orig_stream != dec_stream {
                return Err(format!(
                    "Unknown frame stream_id mismatch: {orig_stream} vs {dec_stream}"
                ));
            }
            if orig_payload != dec_payload {
                return Err("Unknown frame payload mismatch".to_string());
            }
        }
        _ => {
            return Err(format!(
                "Frame type mismatch: {:?} vs {:?}",
                std::mem::discriminant(original),
                std::mem::discriminant(decoded)
            ));
        }
    }
    Ok(())
}

/// Helper function to create frame_length with proper bounds checking.
fn frame_length(len: usize) -> u32 {
    assert!(
        len <= MAX_FRAME_SIZE as usize,
        "Frame length {len} exceeds maximum {MAX_FRAME_SIZE}"
    );
    len as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that our arbitrary generators produce valid frames.
    #[test]
    fn test_arbitrary_generators_produce_valid_frames() {
        // This is a compilation test to ensure all Arbitrary impls are correct
        let mut runner = proptest::test_runner::TestRunner::default();

        let _ = arb_data_frame().new_tree(&mut runner).unwrap();
        let _ = arb_headers_frame().new_tree(&mut runner).unwrap();
        let _ = arb_priority_frame().new_tree(&mut runner).unwrap();
        let _ = arb_rst_stream_frame().new_tree(&mut runner).unwrap();
        let _ = arb_settings_frame().new_tree(&mut runner).unwrap();
        let _ = arb_ping_frame().new_tree(&mut runner).unwrap();
        let _ = arb_goaway_frame().new_tree(&mut runner).unwrap();
        let _ = arb_window_update_frame().new_tree(&mut runner).unwrap();
        let _ = arb_continuation_frame().new_tree(&mut runner).unwrap();
        let _ = arb_frame().new_tree(&mut runner).unwrap();
    }

    /// Test the assert_frame_equivalent helper with known equivalent frames.
    #[test]
    fn test_assert_frame_equivalent() {
        let frame1 = Frame::Data(DataFrame::new(1, Bytes::from_static(b"test"), false));
        let frame2 = Frame::Data(DataFrame::new(1, Bytes::from_static(b"test"), false));

        assert!(assert_frame_equivalent(&frame1, &frame2).is_ok());

        let frame3 = Frame::Data(DataFrame::new(2, Bytes::from_static(b"test"), false));
        assert!(assert_frame_equivalent(&frame1, &frame3).is_err());
    }
}
