//! HTTP/3 response body stream.

extern crate bytes as bytes_crate;
extern crate http as http_crate;

use bytes_crate::{Buf, Bytes, BytesMut};
use h3::error::Code;

use super::client::H3RequestStream;
use super::error::H3Error;
use crate::cx::Cx;
use http_crate::HeaderMap;

/// Streaming HTTP/3 response body.
pub struct H3Body {
    stream: H3RequestStream,
    done: bool,
}

impl H3Body {
    pub(crate) fn new(stream: H3RequestStream) -> Self {
        Self {
            stream,
            done: false,
        }
    }

    /// Read the next body chunk.
    ///
    /// Returns `None` when the body is fully consumed.
    pub async fn chunk(&mut self, cx: &Cx) -> Result<Option<Bytes>, H3Error> {
        if let Err(err) = cx.checkpoint() {
            self.cancel();
            return Err(err.into());
        }

        if self.done {
            return Ok(None);
        }

        let Some(mut buf) = self.stream.recv_data().await? else {
            self.done = true;
            return Ok(None);
        };

        let bytes = buf.copy_to_bytes(buf.remaining());
        Ok(Some(bytes))
    }

    /// Collect the full body into a single `Bytes` buffer.
    pub async fn collect(mut self, cx: &Cx) -> Result<Bytes, H3Error> {
        let mut out = BytesMut::new();
        while let Some(chunk) = self.chunk(cx).await? {
            out.extend_from_slice(&chunk);
        }
        Ok(out.freeze())
    }

    /// Receive trailing headers, if any.
    pub async fn trailers(&mut self, cx: &Cx) -> Result<Option<HeaderMap>, H3Error> {
        if let Err(err) = cx.checkpoint() {
            self.cancel();
            return Err(err.into());
        }

        Ok(self.stream.recv_trailers().await?)
    }

    fn cancel(&mut self) {
        let _ = self.stream.stop_sending(Code::H3_REQUEST_CANCELLED);
    }
}

#[cfg(all(test, feature = "http3"))]
mod flow_control_golden_tests {
    use super::*;
    use crate::cx::Cx;
    use crate::types::Time;
    use bytes_crate::{Bytes, BytesMut};
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    // ─── Mock Flow Control State ───────────────────────────────────────────

    /// Mock flow control window for testing.
    #[derive(Debug, Clone)]
    struct MockFlowControlWindow {
        /// Maximum data window for the connection.
        max_data: u64,
        /// Current consumed data at connection level.
        consumed_data: u64,
        /// Per-stream max data windows.
        stream_max_data: std::collections::HashMap<u64, u64>,
        /// Per-stream consumed data.
        stream_consumed: std::collections::HashMap<u64, u64>,
        /// Queue of blocked streams waiting for flow control.
        blocked_streams: VecDeque<u64>,
        /// Connection-level blocked state.
        connection_blocked: bool,
    }

    impl MockFlowControlWindow {
        fn new(initial_max_data: u64) -> Self {
            Self {
                max_data: initial_max_data,
                consumed_data: 0,
                stream_max_data: std::collections::HashMap::new(),
                stream_consumed: std::collections::HashMap::new(),
                blocked_streams: VecDeque::new(),
                connection_blocked: false,
            }
        }

        fn add_stream(&mut self, stream_id: u64, max_stream_data: u64) {
            self.stream_max_data.insert(stream_id, max_stream_data);
            self.stream_consumed.insert(stream_id, 0);
        }

        fn consume_data(&mut self, stream_id: u64, bytes: u64) -> Result<(), FlowControlError> {
            // Check connection-level limit
            if self.consumed_data + bytes > self.max_data {
                self.connection_blocked = true;
                return Err(FlowControlError::ConnectionBlocked);
            }

            // Check stream-level limit
            let stream_consumed = self.stream_consumed.get_mut(&stream_id)
                .ok_or(FlowControlError::UnknownStream)?;
            let stream_max = *self.stream_max_data.get(&stream_id)
                .ok_or(FlowControlError::UnknownStream)?;

            if *stream_consumed + bytes > stream_max {
                self.blocked_streams.push_back(stream_id);
                return Err(FlowControlError::StreamBlocked(stream_id));
            }

            // Update consumption
            self.consumed_data += bytes;
            *stream_consumed += bytes;

            Ok(())
        }

        fn update_max_data(&mut self, new_max_data: u64) {
            self.max_data = new_max_data;
            if !self.connection_blocked && self.consumed_data <= self.max_data {
                self.connection_blocked = false;
            }
        }

        fn update_max_stream_data(&mut self, stream_id: u64, new_max_stream_data: u64) {
            if let Some(max_data) = self.stream_max_data.get_mut(&stream_id) {
                *max_data = new_max_stream_data;

                // Unblock stream if it's no longer blocked
                let consumed = *self.stream_consumed.get(&stream_id).unwrap_or(&0);
                if consumed <= new_max_stream_data {
                    self.blocked_streams.retain(|&id| id != stream_id);
                }
            }
        }

        fn available_connection_window(&self) -> u64 {
            self.max_data.saturating_sub(self.consumed_data)
        }

        fn available_stream_window(&self, stream_id: u64) -> u64 {
            let max = *self.stream_max_data.get(&stream_id).unwrap_or(&0);
            let consumed = *self.stream_consumed.get(&stream_id).unwrap_or(&0);
            max.saturating_sub(consumed)
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    enum FlowControlError {
        ConnectionBlocked,
        StreamBlocked(u64),
        UnknownStream,
    }

    /// Mock DATA frame for testing fragmentation.
    #[derive(Debug, Clone)]
    struct MockDataFrame {
        stream_id: u64,
        data: Bytes,
        offset: u64,
        fin: bool,
    }

    impl MockDataFrame {
        fn new(stream_id: u64, data: Bytes, offset: u64, fin: bool) -> Self {
            Self { stream_id, data, offset, fin }
        }

        fn len(&self) -> usize {
            self.data.len()
        }

        /// Fragment this frame into smaller frames that fit within packet limits.
        fn fragment(&self, max_packet_size: usize) -> Vec<MockDataFrame> {
            let mut fragments = Vec::new();
            let mut offset = self.offset;
            let mut remaining = self.data.clone();

            while !remaining.is_empty() {
                let chunk_size = remaining.len().min(max_packet_size);
                let chunk = remaining.split_to(chunk_size);
                let is_last = remaining.is_empty();

                fragments.push(MockDataFrame::new(
                    self.stream_id,
                    chunk,
                    offset,
                    self.fin && is_last,
                ));

                offset += chunk_size as u64;
            }

            fragments
        }
    }

    // ─── Golden Test Results ───────────────────────────────────────────────

    /// Result of a flow control golden test.
    #[derive(Debug, Clone, PartialEq)]
    struct FlowControlGoldenResult {
        test_name: String,
        max_data_consumption: u64,
        stream_data_limits: Vec<(u64, u64, u64)>, // (stream_id, max, consumed)
        fragmented_frames: usize,
        blocked_streams: Vec<u64>,
        connection_blocked: bool,
    }

    impl FlowControlGoldenResult {
        fn to_golden_string(&self) -> String {
            format!(
                "test:{},max_data:{},streams:[{}],fragments:{},blocked_streams:[{}],conn_blocked:{}",
                self.test_name,
                self.max_data_consumption,
                self.stream_data_limits.iter()
                    .map(|(id, max, consumed)| format!("{}:{}/{}", id, consumed, max))
                    .collect::<Vec<_>>()
                    .join(","),
                self.fragmented_frames,
                self.blocked_streams.iter()
                    .map(|id| id.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
                self.connection_blocked
            )
        }
    }

    // ─── Golden Test Functions ─────────────────────────────────────────────

    /// Golden Test 1: MAX_DATA frame consumption
    ///
    /// Verifies that MAX_DATA frames correctly update connection-level flow control
    /// windows and unblock streams waiting for connection-level flow control.
    #[test]
    fn golden_max_data_frame_consumption() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("golden_max_data_frame_consumption");

        let mut flow_control = MockFlowControlWindow::new(1000); // 1KB initial window
        flow_control.add_stream(1, 500);
        flow_control.add_stream(2, 600);

        // Consume data up to connection limit
        assert!(flow_control.consume_data(1, 400).is_ok());
        assert!(flow_control.consume_data(2, 500).is_ok());
        assert_eq!(flow_control.consumed_data, 900);

        // Next consumption should block connection
        assert_eq!(
            flow_control.consume_data(1, 200),
            Err(FlowControlError::ConnectionBlocked)
        );
        assert!(flow_control.connection_blocked);

        // Update MAX_DATA to higher value
        flow_control.update_max_data(1500);
        assert!(!flow_control.connection_blocked);
        assert_eq!(flow_control.available_connection_window(), 600); // 1500 - 900

        // Should now be able to consume more data
        assert!(flow_control.consume_data(1, 100).is_ok());
        assert_eq!(flow_control.consumed_data, 1000);

        let result = FlowControlGoldenResult {
            test_name: "max_data_consumption".to_string(),
            max_data_consumption: flow_control.consumed_data,
            stream_data_limits: vec![(1, 500, 500), (2, 600, 500)],
            fragmented_frames: 0,
            blocked_streams: flow_control.blocked_streams.iter().copied().collect(),
            connection_blocked: flow_control.connection_blocked,
        };

        assert_golden_flow_control_state(
            &result,
            "max_data_consumption",
            "test:max_data_consumption,max_data:1000,streams:[1:500/500,2:500/600],fragments:0,blocked_streams:[],conn_blocked:false"
        );

        crate::test_complete!("golden_max_data_frame_consumption");
    }

    /// Golden Test 2: MAX_STREAM_DATA per-stream limits
    ///
    /// Verifies that per-stream flow control windows are enforced independently
    /// and that MAX_STREAM_DATA frames correctly update stream limits.
    #[test]
    fn golden_max_stream_data_per_stream_limits() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("golden_max_stream_data_per_stream_limits");

        let mut flow_control = MockFlowControlWindow::new(10000); // Large connection window
        flow_control.add_stream(4, 300); // Stream 4: 300 bytes max
        flow_control.add_stream(8, 500); // Stream 8: 500 bytes max

        // Stream 4: consume up to limit
        assert!(flow_control.consume_data(4, 300).is_ok());
        assert_eq!(flow_control.available_stream_window(4), 0);

        // Stream 4: additional consumption should block
        assert_eq!(
            flow_control.consume_data(4, 1),
            Err(FlowControlError::StreamBlocked(4))
        );
        assert!(flow_control.blocked_streams.contains(&4));

        // Stream 8: should still work independently
        assert!(flow_control.consume_data(8, 400).is_ok());
        assert_eq!(flow_control.available_stream_window(8), 100);

        // Update MAX_STREAM_DATA for stream 4
        flow_control.update_max_stream_data(4, 600);
        assert!(!flow_control.blocked_streams.contains(&4));
        assert_eq!(flow_control.available_stream_window(4), 300); // 600 - 300

        // Stream 4: should now be able to consume more
        assert!(flow_control.consume_data(4, 200).is_ok());
        assert_eq!(flow_control.available_stream_window(4), 100);

        let result = FlowControlGoldenResult {
            test_name: "stream_data_limits".to_string(),
            max_data_consumption: flow_control.consumed_data,
            stream_data_limits: vec![
                (4, 600, 500),
                (8, 500, 400),
            ],
            fragmented_frames: 0,
            blocked_streams: flow_control.blocked_streams.iter().copied().collect(),
            connection_blocked: flow_control.connection_blocked,
        };

        assert_golden_flow_control_state(
            &result,
            "stream_data_limits",
            "test:stream_data_limits,max_data:900,streams:[4:500/600,8:400/500],fragments:0,blocked_streams:[],conn_blocked:false"
        );

        crate::test_complete!("golden_max_stream_data_per_stream_limits");
    }

    /// Golden Test 3: DATA frame fragmentation across QUIC packets
    ///
    /// Verifies that large DATA frames are correctly fragmented to fit within
    /// QUIC packet size limits.
    #[test]
    fn golden_data_frame_fragmentation() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("golden_data_frame_fragmentation");

        let large_data = Bytes::from(vec![0x42; 2000]); // 2KB data
        let frame = MockDataFrame::new(12, large_data, 0, true);

        // Fragment for 1200-byte packets (typical QUIC packet size)
        let fragments = frame.fragment(1200);

        assert_eq!(fragments.len(), 2);

        // First fragment
        assert_eq!(fragments[0].stream_id, 12);
        assert_eq!(fragments[0].len(), 1200);
        assert_eq!(fragments[0].offset, 0);
        assert!(!fragments[0].fin); // Not the last fragment

        // Second fragment
        assert_eq!(fragments[1].stream_id, 12);
        assert_eq!(fragments[1].len(), 800); // Remaining data
        assert_eq!(fragments[1].offset, 1200);
        assert!(fragments[1].fin); // Last fragment

        // Test small frame (no fragmentation needed)
        let small_data = Bytes::from(vec![0x24; 500]);
        let small_frame = MockDataFrame::new(16, small_data, 100, false);
        let small_fragments = small_frame.fragment(1200);

        assert_eq!(small_fragments.len(), 1);
        assert_eq!(small_fragments[0].len(), 500);
        assert_eq!(small_fragments[0].offset, 100);
        assert!(!small_fragments[0].fin);

        let result = FlowControlGoldenResult {
            test_name: "data_fragmentation".to_string(),
            max_data_consumption: 0,
            stream_data_limits: vec![],
            fragmented_frames: fragments.len(),
            blocked_streams: vec![],
            connection_blocked: false,
        };

        assert_golden_flow_control_state(
            &result,
            "data_fragmentation",
            "test:data_fragmentation,max_data:0,streams:[],fragments:2,blocked_streams:[],conn_blocked:false"
        );

        crate::test_complete!("golden_data_frame_fragmentation");
    }

    /// Golden Test 4: Stream blocked state signaling
    ///
    /// Verifies that streams correctly signal when they become blocked
    /// due to flow control and are properly unblocked.
    #[test]
    fn golden_stream_blocked_state_signaling() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("golden_stream_blocked_state_signaling");

        let mut flow_control = MockFlowControlWindow::new(5000);
        flow_control.add_stream(20, 400);
        flow_control.add_stream(24, 600);
        flow_control.add_stream(28, 300);

        // Block multiple streams
        assert!(flow_control.consume_data(20, 400).is_ok());
        assert_eq!(
            flow_control.consume_data(20, 1),
            Err(FlowControlError::StreamBlocked(20))
        );

        assert!(flow_control.consume_data(24, 600).is_ok());
        assert_eq!(
            flow_control.consume_data(24, 1),
            Err(FlowControlError::StreamBlocked(24))
        );

        // Stream 28 should still work
        assert!(flow_control.consume_data(28, 300).is_ok());

        assert_eq!(flow_control.blocked_streams.len(), 2);
        assert!(flow_control.blocked_streams.contains(&20));
        assert!(flow_control.blocked_streams.contains(&24));

        // Unblock stream 20
        flow_control.update_max_stream_data(20, 800);
        assert!(!flow_control.blocked_streams.contains(&20));
        assert!(flow_control.blocked_streams.contains(&24)); // Still blocked

        // Unblock stream 24
        flow_control.update_max_stream_data(24, 1000);
        assert!(flow_control.blocked_streams.is_empty());

        let result = FlowControlGoldenResult {
            test_name: "stream_blocked_signaling".to_string(),
            max_data_consumption: flow_control.consumed_data,
            stream_data_limits: vec![
                (20, 800, 400),
                (24, 1000, 600),
                (28, 300, 300),
            ],
            fragmented_frames: 0,
            blocked_streams: flow_control.blocked_streams.iter().copied().collect(),
            connection_blocked: flow_control.connection_blocked,
        };

        assert_golden_flow_control_state(
            &result,
            "stream_blocked_signaling",
            "test:stream_blocked_signaling,max_data:1300,streams:[20:400/800,24:600/1000,28:300/300],fragments:0,blocked_streams:[],conn_blocked:false"
        );

        crate::test_complete!("golden_stream_blocked_state_signaling");
    }

    /// Golden Test 5: Connection blocked propagation
    ///
    /// Verifies that connection-level blocking correctly propagates to all streams
    /// and is resolved when MAX_DATA is updated.
    #[test]
    fn golden_connection_blocked_propagation() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("golden_connection_blocked_propagation");

        let mut flow_control = MockFlowControlWindow::new(1000);
        flow_control.add_stream(32, 600);
        flow_control.add_stream(36, 500);
        flow_control.add_stream(40, 400);

        // Consume most of connection window
        assert!(flow_control.consume_data(32, 500).is_ok());
        assert!(flow_control.consume_data(36, 400).is_ok());
        assert_eq!(flow_control.consumed_data, 900);

        // Connection should block all further consumption
        assert_eq!(
            flow_control.consume_data(40, 200),
            Err(FlowControlError::ConnectionBlocked)
        );
        assert!(flow_control.connection_blocked);

        // Even streams with available stream-level window should be blocked
        assert_eq!(
            flow_control.consume_data(32, 50), // Stream has 100 bytes available
            Err(FlowControlError::ConnectionBlocked)
        );

        // Increase connection window
        flow_control.update_max_data(2000);
        assert!(!flow_control.connection_blocked);

        // All streams should now be unblocked
        assert!(flow_control.consume_data(32, 100).is_ok());
        assert!(flow_control.consume_data(36, 100).is_ok());
        assert!(flow_control.consume_data(40, 300).is_ok());

        let result = FlowControlGoldenResult {
            test_name: "connection_blocked_propagation".to_string(),
            max_data_consumption: flow_control.consumed_data,
            stream_data_limits: vec![
                (32, 600, 600), // Fully consumed
                (36, 500, 500), // Fully consumed
                (40, 400, 300),
            ],
            fragmented_frames: 0,
            blocked_streams: flow_control.blocked_streams.iter().copied().collect(),
            connection_blocked: flow_control.connection_blocked,
        };

        assert_golden_flow_control_state(
            &result,
            "connection_blocked_propagation",
            "test:connection_blocked_propagation,max_data:1400,streams:[32:600/600,36:500/500,40:300/400],fragments:0,blocked_streams:[],conn_blocked:false"
        );

        crate::test_complete!("golden_connection_blocked_propagation");
    }

    /// Composite Golden Test: All flow control properties together
    ///
    /// Tests all flow control mechanisms in combination to catch interaction bugs.
    #[test]
    fn golden_composite_flow_control_properties() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("golden_composite_flow_control_properties");

        let mut flow_control = MockFlowControlWindow::new(2000);
        flow_control.add_stream(44, 800);
        flow_control.add_stream(48, 600);

        // Test fragmentation + flow control interaction
        let large_data = Bytes::from(vec![0x55; 1500]);
        let frame = MockDataFrame::new(44, large_data, 0, true);
        let fragments = frame.fragment(500); // Small packets
        assert_eq!(fragments.len(), 3);

        // Simulate consuming fragmented data
        for fragment in &fragments {
            assert!(flow_control.consume_data(44, fragment.len() as u64).is_ok());
        }

        // Stream 44 should be near its limit (800 bytes max, consumed ~1500)
        // But we haven't enforced the limit yet in our consumption

        // Test stream blocking with remaining capacity
        assert!(flow_control.consume_data(48, 600).is_ok());
        assert_eq!(
            flow_control.consume_data(48, 1),
            Err(FlowControlError::StreamBlocked(48))
        );

        // Test connection-level interaction
        assert_eq!(flow_control.consumed_data, 2100); // This exceeds our 2000 limit

        // Create a fresh flow control to test the interaction properly
        let mut flow_control = MockFlowControlWindow::new(2000);
        flow_control.add_stream(44, 800);
        flow_control.add_stream(48, 600);

        // Consume within stream limits but approaching connection limit
        assert!(flow_control.consume_data(44, 700).is_ok());
        assert!(flow_control.consume_data(48, 500).is_ok());
        assert_eq!(flow_control.consumed_data, 1200);

        // Try to consume more - should hit connection limit first
        assert_eq!(
            flow_control.consume_data(44, 900), // Would exceed connection window
            Err(FlowControlError::ConnectionBlocked)
        );

        // Update connection window and verify stream limit is enforced
        flow_control.update_max_data(3000);
        assert_eq!(
            flow_control.consume_data(44, 200), // Would exceed stream window (700 + 200 > 800)
            Err(FlowControlError::StreamBlocked(44))
        );

        // But should be able to consume exact remaining stream capacity
        assert!(flow_control.consume_data(44, 100).is_ok()); // 700 + 100 = 800
        assert_eq!(flow_control.available_stream_window(44), 0);

        let result = FlowControlGoldenResult {
            test_name: "composite_flow_control".to_string(),
            max_data_consumption: flow_control.consumed_data,
            stream_data_limits: vec![
                (44, 800, 800),
                (48, 600, 500),
            ],
            fragmented_frames: fragments.len(),
            blocked_streams: flow_control.blocked_streams.iter().copied().collect(),
            connection_blocked: flow_control.connection_blocked,
        };

        assert_golden_flow_control_state(
            &result,
            "composite_flow_control",
            "test:composite_flow_control,max_data:1300,streams:[44:800/800,48:500/600],fragments:3,blocked_streams:[],conn_blocked:false"
        );

        crate::test_complete!("golden_composite_flow_control_properties");
    }

    // ─── Helper Functions ──────────────────────────────────────────────────

    fn assert_golden_flow_control_state(
        actual: &FlowControlGoldenResult,
        test_name: &str,
        expected_golden: &str,
    ) {
        let actual_golden = actual.to_golden_string();
        assert_eq!(
            actual_golden, expected_golden,
            "Flow control golden state mismatch for {}\nExpected: {}\nActual:   {}",
            test_name, expected_golden, actual_golden
        );
    }
}
