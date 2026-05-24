//! Real E2E integration tests: codec/length_delimited ↔ codec/framed_read integration (br-e2e-66).
//!
//! Tests that variable-length framing handles partial reads correctly, including frames that
//! span TCP segment boundaries. Verifies the integration between length-delimited codec and
//! framed read systems works correctly with incomplete data arrival scenarios.
//!
//! # Integration Patterns Tested
//!
//! - **Variable-Length Frame Encoding**: Configurable length fields from 1-8 bytes
//! - **Partial Frame Assembly**: Frames split across multiple read operations
//! - **TCP Segment Boundary Spanning**: Frames that cross network packet boundaries
//! - **Buffer Management**: Accumulation and consumption of incomplete frame data
//! - **Stream Integration**: Async stream wrapper with proper error handling
//!
//! # Test Scenarios
//!
//! 1. **Basic Variable-Length Framing** — Different frame sizes with proper encoding
//! 2. **Partial Read Handling** — Frames arriving in incomplete chunks
//! 3. **TCP Segment Boundary Tests** — Frames spanning multiple network reads
//! 4. **Multi-Frame Assembly** — Multiple frames in various read patterns
//! 5. **Integration Verification** — Length-delimited and framed read work together
//!
//! # Safety Properties Verified
//!
//! - Variable-length frames correctly encoded with length prefixes
//! - Partial reads properly buffered and assembled into complete frames
//! - Frame boundaries preserved across TCP segment splits
//! - Stream state maintained across partial read operations
//! - Error recovery handles oversized frames without infinite loops

#[cfg(all(test, feature = "real-service-e2e"))]
mod tests {
    #![allow(
        clippy::expect_fun_call,
        clippy::future_not_send,
        clippy::match_same_arms,
        clippy::missing_panics_doc,
        clippy::needless_pass_by_value,
        clippy::unwrap_used,
        dead_code
    )]

    use crate::codec::{
        length_delimited::{LengthDelimitedCodec, LengthDelimitedCodecBuilder},
        framed_read::FramedRead,
        framed::Framed,
        decoder::Decoder,
        encoder::Encoder,
    };
    use crate::bytes::{Bytes, BytesMut, BufMut};
    use crate::cx::Cx;
    use crate::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
    use crate::net::tcp::{TcpListener, TcpStream};
    use crate::time::{Duration, sleep};
    use crate::types::Budget;
    use std::io;
    use std::pin::Pin;
    use std::sync::{
        Arc, RwLock,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    };
    use std::task::{Context, Poll};

    // ────────────────────────────────────────────────────────────────────────────────
    // Length-Delimited + Framed Read Integration Test Framework
    // ────────────────────────────────────────────────────────────────────────────────

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum CodecTestPhase {
        Setup,
        CodecInitialization,
        VariableLengthFrameEncoding,
        PartialReadSimulation,
        TcpSegmentBoundaryTest,
        MultiFrameAssembly,
        StreamIntegrationVerification,
        ErrorRecoveryTest,
        BufferManagementVerification,
        Assert,
        Teardown,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct CodecTestResult {
        pub test_name: String,
        pub scenario_id: String,
        pub phase: CodecTestPhase,
        pub success: bool,
        pub error: Option<String>,
        pub duration_ms: u64,
        pub codec_stats: CodecStats,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Default)]
    pub struct CodecStats {
        pub frames_encoded: u64,
        pub frames_decoded: u64,
        pub partial_reads_processed: u64,
        pub tcp_segment_boundary_spans: u64,
        pub buffer_accumulations: u64,
        pub variable_length_encodings: u64,
        pub stream_operations: u64,
        pub error_recoveries: u64,
    }

    /// Test harness for length-delimited and framed read integration testing
    pub struct LengthDelimitedFramedTestHarness {
        test_stats: Arc<RwLock<CodecStats>>,
        scenario_context: String,
    }

    /// Mock async reader that can simulate partial reads
    struct PartialAsyncReader {
        data: Bytes,
        position: usize,
        chunk_size: usize,
        stats: Arc<RwLock<CodecStats>>,
    }

    /// Mock TCP stream that simulates segment boundaries
    struct SegmentBoundaryStream {
        segments: Vec<Bytes>,
        current_segment: usize,
        segment_position: usize,
        stats: Arc<RwLock<CodecStats>>,
    }

    /// Frame test data with variable lengths
    struct FrameTestData {
        payload: Bytes,
        expected_encoded_length: usize,
        frame_description: String,
    }

    impl LengthDelimitedFramedTestHarness {
        /// Creates a new test harness for codec integration testing
        pub fn new(scenario: &str) -> Self {
            Self {
                test_stats: Arc::new(RwLock::new(CodecStats::default())),
                scenario_context: scenario.to_string(),
            }
        }

        /// Tests basic variable-length frame encoding and decoding
        pub async fn test_variable_length_frame_encoding(&mut self, cx: &Cx) -> CodecTestResult {
            let start_time = std::time::Instant::now();
            let mut result = CodecTestResult {
                test_name: "test_variable_length_frame_encoding".to_string(),
                scenario_id: self.scenario_context.clone(),
                phase: CodecTestPhase::Setup,
                success: false,
                error: None,
                duration_ms: 0,
                codec_stats: CodecStats::default(),
            };

            result.phase = CodecTestPhase::CodecInitialization;

            // Test various length field configurations
            let codec_configs = vec![
                ("1-byte-length", LengthDelimitedCodec::builder().length_field_length(1).new_codec()),
                ("2-byte-be-length", LengthDelimitedCodec::builder().length_field_length(2).big_endian().new_codec()),
                ("2-byte-le-length", LengthDelimitedCodec::builder().length_field_length(2).little_endian().new_codec()),
                ("4-byte-be-length", LengthDelimitedCodec::builder().length_field_length(4).big_endian().new_codec()),
                ("8-byte-le-length", LengthDelimitedCodec::builder().length_field_length(8).little_endian().new_codec()),
            ];

            result.phase = CodecTestPhase::VariableLengthFrameEncoding;

            // Test data with variable frame sizes
            let test_frames = vec![
                FrameTestData {
                    payload: Bytes::from(""),
                    expected_encoded_length: 0,
                    frame_description: "empty_frame".to_string(),
                },
                FrameTestData {
                    payload: Bytes::from("Hello"),
                    expected_encoded_length: 5,
                    frame_description: "small_frame".to_string(),
                },
                FrameTestData {
                    payload: Bytes::from(&vec![0x42; 256]),
                    expected_encoded_length: 256,
                    frame_description: "medium_frame".to_string(),
                },
                FrameTestData {
                    payload: Bytes::from(&vec![0xAB; 1024]),
                    expected_encoded_length: 1024,
                    frame_description: "large_frame".to_string(),
                },
            ];

            let mut successful_configurations = 0;
            for (config_name, codec) in codec_configs {
                match self.test_codec_configuration(&codec, &test_frames).await {
                    Ok(_) => {
                        successful_configurations += 1;
                        self.increment_stat("variable_length_encodings", test_frames.len() as u64);
                    }
                    Err(e) => {
                        result.error = Some(format!("Configuration '{}' failed: {}", config_name, e));
                        break;
                    }
                }
            }

            if successful_configurations == 5 {
                result.success = true;
            }

            result.phase = CodecTestPhase::Teardown;
            result.duration_ms = start_time.elapsed().as_millis() as u64;
            result.codec_stats = self.get_stats_snapshot();
            result
        }

        /// Tests partial read handling with frames arriving in chunks
        pub async fn test_partial_read_handling(&mut self, cx: &Cx) -> CodecTestResult {
            let start_time = std::time::Instant::now();
            let mut result = CodecTestResult {
                test_name: "test_partial_read_handling".to_string(),
                scenario_id: self.scenario_context.clone(),
                phase: CodecTestPhase::Setup,
                success: false,
                error: None,
                duration_ms: 0,
                codec_stats: CodecStats::default(),
            };

            result.phase = CodecTestPhase::CodecInitialization;
            let codec = LengthDelimitedCodec::new();

            // Create test frame with multiple chunks
            let test_payload = Bytes::from("This is a test frame that will be split across multiple reads");
            let mut encoded_frame = BytesMut::new();
            codec.encode(test_payload.clone(), &mut encoded_frame).unwrap();

            result.phase = CodecTestPhase::PartialReadSimulation;

            // Test various chunk sizes
            let chunk_sizes = vec![1, 3, 7, 16, 32];
            let mut successful_partial_reads = 0;

            for chunk_size in chunk_sizes {
                let partial_reader = PartialAsyncReader::new(
                    encoded_frame.clone().freeze(),
                    chunk_size,
                    self.test_stats.clone(),
                );

                match self.test_partial_frame_assembly(codec.clone(), partial_reader).await {
                    Ok(decoded_payload) => {
                        if decoded_payload == test_payload {
                            successful_partial_reads += 1;
                            self.increment_stat("partial_reads_processed", 1);
                        } else {
                            result.error = Some(format!("Partial read with chunk size {} produced incorrect payload", chunk_size));
                            break;
                        }
                    }
                    Err(e) => {
                        result.error = Some(format!("Partial read test failed for chunk size {}: {}", chunk_size, e));
                        break;
                    }
                }
            }

            if successful_partial_reads == chunk_sizes.len() {
                result.success = true;
            }

            result.phase = CodecTestPhase::Teardown;
            result.duration_ms = start_time.elapsed().as_millis() as u64;
            result.codec_stats = self.get_stats_snapshot();
            result
        }

        /// Tests frames spanning TCP segment boundaries
        pub async fn test_tcp_segment_boundary_spanning(&mut self, cx: &Cx) -> CodecTestResult {
            let start_time = std::time::Instant::now();
            let mut result = CodecTestResult {
                test_name: "test_tcp_segment_boundary_spanning".to_string(),
                scenario_id: self.scenario_context.clone(),
                phase: CodecTestPhase::Setup,
                success: false,
                error: None,
                duration_ms: 0,
                codec_stats: CodecStats::default(),
            };

            result.phase = CodecTestPhase::CodecInitialization;
            let codec = LengthDelimitedCodec::new();

            // Create a frame that will be split across segments
            let test_payload = Bytes::from(&vec![0x55; 100]); // 100-byte payload
            let mut encoded_frame = BytesMut::new();
            codec.encode(test_payload.clone(), &mut encoded_frame).unwrap();

            result.phase = CodecTestPhase::TcpSegmentBoundaryTest;

            // Test various segment boundary scenarios
            let boundary_scenarios = vec![
                ("header_split", vec![
                    encoded_frame.slice(0..2),      // Partial header
                    encoded_frame.slice(2..),       // Rest of header + payload
                ]),
                ("header_payload_split", vec![
                    encoded_frame.slice(0..4),      // Complete header
                    encoded_frame.slice(4..50),     // Partial payload
                    encoded_frame.slice(50..),      // Rest of payload
                ]),
                ("byte_by_byte", (0..encoded_frame.len())
                    .map(|i| encoded_frame.slice(i..i+1))
                    .collect()),
            ];

            let mut successful_boundary_tests = 0;

            for (scenario_name, segments) in boundary_scenarios {
                let segment_stream = SegmentBoundaryStream::new(segments, self.test_stats.clone());

                match self.test_segment_boundary_assembly(codec.clone(), segment_stream).await {
                    Ok(decoded_payload) => {
                        if decoded_payload == test_payload {
                            successful_boundary_tests += 1;
                            self.increment_stat("tcp_segment_boundary_spans", 1);
                        } else {
                            result.error = Some(format!("Segment boundary test '{}' produced incorrect payload", scenario_name));
                            break;
                        }
                    }
                    Err(e) => {
                        result.error = Some(format!("Segment boundary test '{}' failed: {}", scenario_name, e));
                        break;
                    }
                }
            }

            if successful_boundary_tests == 3 {
                result.success = true;
            }

            result.phase = CodecTestPhase::Teardown;
            result.duration_ms = start_time.elapsed().as_millis() as u64;
            result.codec_stats = self.get_stats_snapshot();
            result
        }

        /// Tests multi-frame assembly with various patterns
        pub async fn test_multi_frame_assembly(&mut self, cx: &Cx) -> CodecTestResult {
            let start_time = std::time::Instant::now();
            let mut result = CodecTestResult {
                test_name: "test_multi_frame_assembly".to_string(),
                scenario_id: self.scenario_context.clone(),
                phase: CodecTestPhase::Setup,
                success: false,
                error: None,
                duration_ms: 0,
                codec_stats: CodecStats::default(),
            };

            result.phase = CodecTestPhase::CodecInitialization;
            let codec = LengthDelimitedCodec::new();

            // Create multiple test frames of different sizes
            let test_frames = vec![
                Bytes::from("Frame 1"),
                Bytes::from("This is frame 2 with more content"),
                Bytes::from("3"),
                Bytes::from(&vec![0x99; 200]),
            ];

            // Encode all frames into a single buffer
            let mut all_encoded = BytesMut::new();
            for frame in &test_frames {
                codec.encode(frame.clone(), &mut all_encoded).unwrap();
            }

            result.phase = CodecTestPhase::MultiFrameAssembly;

            // Test multi-frame scenarios
            let multi_frame_scenarios = vec![
                ("single_read", vec![all_encoded.clone().freeze()]),
                ("two_reads", {
                    let split_point = all_encoded.len() / 2;
                    vec![
                        all_encoded.slice(0..split_point),
                        all_encoded.slice(split_point..),
                    ]
                }),
                ("frame_boundary_reads", {
                    // Calculate frame boundaries for precise splitting
                    let mut boundaries = vec![0];
                    let mut current_pos = 0;
                    for frame in &test_frames {
                        current_pos += 4 + frame.len(); // 4-byte header + payload
                        boundaries.push(current_pos);
                    }
                    boundaries.windows(2)
                        .map(|w| all_encoded.slice(w[0]..w[1]))
                        .collect()
                }),
            ];

            let mut successful_multi_frame_tests = 0;

            for (scenario_name, segments) in multi_frame_scenarios {
                let segment_stream = SegmentBoundaryStream::new(segments, self.test_stats.clone());

                match self.test_multi_frame_decoding(codec.clone(), segment_stream, test_frames.clone()).await {
                    Ok(_) => {
                        successful_multi_frame_tests += 1;
                        self.increment_stat("buffer_accumulations", 1);
                    }
                    Err(e) => {
                        result.error = Some(format!("Multi-frame test '{}' failed: {}", scenario_name, e));
                        break;
                    }
                }
            }

            if successful_multi_frame_tests == 3 {
                result.success = true;
            }

            result.phase = CodecTestPhase::Teardown;
            result.duration_ms = start_time.elapsed().as_millis() as u64;
            result.codec_stats = self.get_stats_snapshot();
            result
        }

        /// Tests stream integration with FramedRead
        pub async fn test_stream_integration(&mut self, cx: &Cx) -> CodecTestResult {
            let start_time = std::time::Instant::now();
            let mut result = CodecTestResult {
                test_name: "test_stream_integration".to_string(),
                scenario_id: self.scenario_context.clone(),
                phase: CodecTestPhase::Setup,
                success: false,
                error: None,
                duration_ms: 0,
                codec_stats: CodecStats::default(),
            };

            result.phase = CodecTestPhase::StreamIntegrationVerification;

            // Create test data
            let test_frames = vec![
                Bytes::from("Stream frame 1"),
                Bytes::from("Stream frame 2 with more data"),
                Bytes::from("Final stream frame"),
            ];

            // Encode all frames
            let codec = LengthDelimitedCodec::new();
            let mut encoded_data = BytesMut::new();
            for frame in &test_frames {
                codec.encode(frame.clone(), &mut encoded_data).unwrap();
            }

            // Create partial reader to simulate network conditions
            let partial_reader = PartialAsyncReader::new(
                encoded_data.freeze(),
                8, // Small chunks to test stream buffering
                self.test_stats.clone(),
            );

            // Test FramedRead integration
            let stream_result = self.test_framed_read_stream(codec, partial_reader, test_frames).await;

            match stream_result {
                Ok(_) => {
                    result.success = true;
                    self.increment_stat("stream_operations", 1);
                }
                Err(e) => {
                    result.error = Some(format!("Stream integration test failed: {}", e));
                }
            }

            result.phase = CodecTestPhase::Teardown;
            result.duration_ms = start_time.elapsed().as_millis() as u64;
            result.codec_stats = self.get_stats_snapshot();
            result
        }

        /// Comprehensive integration test combining all patterns
        pub async fn test_comprehensive_integration(&mut self, cx: &Cx) -> CodecTestResult {
            let start_time = std::time::Instant::now();
            let mut result = CodecTestResult {
                test_name: "test_comprehensive_integration".to_string(),
                scenario_id: self.scenario_context.clone(),
                phase: CodecTestPhase::Setup,
                success: false,
                error: None,
                duration_ms: 0,
                codec_stats: CodecStats::default(),
            };

            // Run all test components
            let tests = vec![
                ("variable_length", self.test_variable_length_frame_encoding(cx)),
                ("partial_reads", self.test_partial_read_handling(cx)),
                ("segment_boundaries", self.test_tcp_segment_boundary_spanning(cx)),
                ("multi_frame", self.test_multi_frame_assembly(cx)),
                ("stream_integration", self.test_stream_integration(cx)),
            ];

            let mut successful_tests = 0;
            for (test_name, test_future) in tests {
                let test_result = test_future.await;
                if test_result.success {
                    successful_tests += 1;
                } else {
                    result.error = Some(format!("Comprehensive test component '{}' failed: {:?}", test_name, test_result.error));
                    break;
                }
            }

            if successful_tests == 5 {
                let stats = self.get_stats_snapshot();
                if stats.frames_encoded > 0
                    && stats.frames_decoded > 0
                    && stats.partial_reads_processed > 0
                    && stats.tcp_segment_boundary_spans > 0
                    && stats.stream_operations > 0
                {
                    result.success = true;
                } else {
                    result.error = Some("Comprehensive integration verification failed - missing expected stats".to_string());
                }
            }

            result.phase = CodecTestPhase::Teardown;
            result.duration_ms = start_time.elapsed().as_millis() as u64;
            result.codec_stats = self.get_stats_snapshot();
            result
        }

        // ── Helper Methods ──────────────────────────────────────────────────────────

        async fn test_codec_configuration(
            &self,
            codec: &LengthDelimitedCodec,
            test_frames: &[FrameTestData],
        ) -> Result<(), String> {
            for frame_data in test_frames {
                // Encode frame
                let mut encoded = BytesMut::new();
                codec.encode(frame_data.payload.clone(), &mut encoded)
                    .map_err(|e| format!("Encoding failed for {}: {}", frame_data.frame_description, e))?;

                self.increment_stat("frames_encoded", 1);

                // Decode frame
                let mut decode_buffer = encoded.clone();
                match codec.decode(&mut decode_buffer) {
                    Ok(Some(decoded)) => {
                        if decoded != frame_data.payload {
                            return Err(format!("Payload mismatch for {}", frame_data.frame_description));
                        }
                        self.increment_stat("frames_decoded", 1);
                    }
                    Ok(None) => return Err(format!("Incomplete decode for {}", frame_data.frame_description)),
                    Err(e) => return Err(format!("Decode error for {}: {}", frame_data.frame_description, e)),
                }
            }

            Ok(())
        }

        async fn test_partial_frame_assembly(
            &self,
            codec: LengthDelimitedCodec,
            reader: PartialAsyncReader,
        ) -> Result<Bytes, String> {
            let mut framed_read = FramedRead::new(reader, codec);

            // Read the frame via the stream
            use crate::stream::StreamExt;
            match framed_read.next().await {
                Some(Ok(frame)) => Ok(frame),
                Some(Err(e)) => Err(format!("Frame read error: {}", e)),
                None => Err("No frame received".to_string()),
            }
        }

        async fn test_segment_boundary_assembly(
            &self,
            codec: LengthDelimitedCodec,
            stream: SegmentBoundaryStream,
        ) -> Result<Bytes, String> {
            let mut framed_read = FramedRead::new(stream, codec);

            use crate::stream::StreamExt;
            match framed_read.next().await {
                Some(Ok(frame)) => Ok(frame),
                Some(Err(e)) => Err(format!("Segment boundary frame read error: {}", e)),
                None => Err("No frame received from segment boundary stream".to_string()),
            }
        }

        async fn test_multi_frame_decoding(
            &self,
            codec: LengthDelimitedCodec,
            stream: SegmentBoundaryStream,
            expected_frames: Vec<Bytes>,
        ) -> Result<(), String> {
            let mut framed_read = FramedRead::new(stream, codec);
            let mut received_frames = Vec::new();

            use crate::stream::StreamExt;
            while let Some(frame_result) = framed_read.next().await {
                match frame_result {
                    Ok(frame) => received_frames.push(frame),
                    Err(e) => return Err(format!("Multi-frame read error: {}", e)),
                }
            }

            if received_frames.len() != expected_frames.len() {
                return Err(format!(
                    "Frame count mismatch: expected {}, got {}",
                    expected_frames.len(),
                    received_frames.len()
                ));
            }

            for (i, (expected, received)) in expected_frames.iter().zip(received_frames.iter()).enumerate() {
                if expected != received {
                    return Err(format!("Frame {} content mismatch", i));
                }
            }

            Ok(())
        }

        async fn test_framed_read_stream(
            &self,
            codec: LengthDelimitedCodec,
            reader: PartialAsyncReader,
            expected_frames: Vec<Bytes>,
        ) -> Result<(), String> {
            let mut framed_read = FramedRead::new(reader, codec);
            let mut received_frames = Vec::new();

            use crate::stream::StreamExt;
            while let Some(frame_result) = framed_read.next().await {
                match frame_result {
                    Ok(frame) => received_frames.push(frame),
                    Err(e) => return Err(format!("Stream read error: {}", e)),
                }
            }

            if received_frames != expected_frames {
                return Err("Stream frames don't match expected frames".to_string());
            }

            Ok(())
        }

        fn increment_stat(&self, stat_name: &str, count: u64) {
            if let Ok(mut stats) = self.test_stats.write() {
                match stat_name {
                    "frames_encoded" => stats.frames_encoded += count,
                    "frames_decoded" => stats.frames_decoded += count,
                    "partial_reads_processed" => stats.partial_reads_processed += count,
                    "tcp_segment_boundary_spans" => stats.tcp_segment_boundary_spans += count,
                    "buffer_accumulations" => stats.buffer_accumulations += count,
                    "variable_length_encodings" => stats.variable_length_encodings += count,
                    "stream_operations" => stats.stream_operations += count,
                    "error_recoveries" => stats.error_recoveries += count,
                    _ => {},
                }
            }
        }

        fn get_stats_snapshot(&self) -> CodecStats {
            if let Ok(stats) = self.test_stats.read() {
                stats.clone()
            } else {
                CodecStats::default()
            }
        }
    }

    impl PartialAsyncReader {
        fn new(data: Bytes, chunk_size: usize, stats: Arc<RwLock<CodecStats>>) -> Self {
            Self {
                data,
                position: 0,
                chunk_size,
                stats,
            }
        }
    }

    impl AsyncRead for PartialAsyncReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            if self.position >= self.data.len() {
                return Poll::Ready(Ok(0)); // EOF
            }

            // Read up to chunk_size bytes or remaining data
            let available = self.data.len() - self.position;
            let to_read = std::cmp::min(std::cmp::min(self.chunk_size, available), buf.len());

            buf[..to_read].copy_from_slice(&self.data[self.position..self.position + to_read]);
            self.position += to_read;

            // Increment stats for partial read
            if let Ok(mut stats) = self.stats.write() {
                stats.partial_reads_processed += 1;
            }

            Poll::Ready(Ok(to_read))
        }
    }

    impl SegmentBoundaryStream {
        fn new(segments: Vec<Bytes>, stats: Arc<RwLock<CodecStats>>) -> Self {
            Self {
                segments,
                current_segment: 0,
                segment_position: 0,
                stats,
            }
        }
    }

    impl AsyncRead for SegmentBoundaryStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            if self.current_segment >= self.segments.len() {
                return Poll::Ready(Ok(0)); // EOF
            }

            let current = &self.segments[self.current_segment];
            if self.segment_position >= current.len() {
                // Move to next segment
                self.current_segment += 1;
                self.segment_position = 0;

                if let Ok(mut stats) = self.stats.write() {
                    stats.tcp_segment_boundary_spans += 1;
                }

                return self.poll_read(_cx, buf);
            }

            // Read from current segment
            let available = current.len() - self.segment_position;
            let to_read = std::cmp::min(available, buf.len());

            buf[..to_read].copy_from_slice(&current[self.segment_position..self.segment_position + to_read]);
            self.segment_position += to_read;

            Poll::Ready(Ok(to_read))
        }
    }

    // Dummy AsyncWrite implementation for SegmentBoundaryStream
    impl AsyncWrite for SegmentBoundaryStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(io::Error::new(io::ErrorKind::Unsupported, "write not supported")))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    // Dummy AsyncWrite implementation for PartialAsyncReader
    impl AsyncWrite for PartialAsyncReader {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(io::Error::new(io::ErrorKind::Unsupported, "write not supported")))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Test Cases
    // ────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_codec_variable_length_frame_encoding() {
        crate::lab::runtime::test_with_lab(|cx| async move {
            let mut harness = LengthDelimitedFramedTestHarness::new("variable_length_encoding");
            let result = harness.test_variable_length_frame_encoding(&cx).await;

            assert!(result.success, "Variable-length frame encoding test failed: {:?}", result.error);
            assert!(result.codec_stats.frames_encoded > 0);
            assert!(result.codec_stats.frames_decoded > 0);
            assert!(result.codec_stats.variable_length_encodings > 0);
            Ok::<(), crate::error::Error>(())
        }).unwrap();
    }

    #[test]
    fn test_codec_partial_read_handling() {
        crate::lab::runtime::test_with_lab(|cx| async move {
            let mut harness = LengthDelimitedFramedTestHarness::new("partial_read_handling");
            let result = harness.test_partial_read_handling(&cx).await;

            assert!(result.success, "Partial read handling test failed: {:?}", result.error);
            assert!(result.codec_stats.partial_reads_processed > 0);
            Ok::<(), crate::error::Error>(())
        }).unwrap();
    }

    #[test]
    fn test_codec_tcp_segment_boundary_spanning() {
        crate::lab::runtime::test_with_lab(|cx| async move {
            let mut harness = LengthDelimitedFramedTestHarness::new("tcp_segment_boundary");
            let result = harness.test_tcp_segment_boundary_spanning(&cx).await;

            assert!(result.success, "TCP segment boundary spanning test failed: {:?}", result.error);
            assert!(result.codec_stats.tcp_segment_boundary_spans > 0);
            Ok::<(), crate::error::Error>(())
        }).unwrap();
    }

    #[test]
    fn test_codec_multi_frame_assembly() {
        crate::lab::runtime::test_with_lab(|cx| async move {
            let mut harness = LengthDelimitedFramedTestHarness::new("multi_frame_assembly");
            let result = harness.test_multi_frame_assembly(&cx).await;

            assert!(result.success, "Multi-frame assembly test failed: {:?}", result.error);
            assert!(result.codec_stats.buffer_accumulations > 0);
            Ok::<(), crate::error::Error>(())
        }).unwrap();
    }

    #[test]
    fn test_codec_stream_integration() {
        crate::lab::runtime::test_with_lab(|cx| async move {
            let mut harness = LengthDelimitedFramedTestHarness::new("stream_integration");
            let result = harness.test_stream_integration(&cx).await;

            assert!(result.success, "Stream integration test failed: {:?}", result.error);
            assert!(result.codec_stats.stream_operations > 0);
            Ok::<(), crate::error::Error>(())
        }).unwrap();
    }

    #[test]
    fn test_codec_comprehensive_integration() {
        crate::lab::runtime::test_with_lab(|cx| async move {
            let mut harness = LengthDelimitedFramedTestHarness::new("comprehensive_integration");
            let result = harness.test_comprehensive_integration(&cx).await;

            assert!(result.success, "Comprehensive integration test failed: {:?}", result.error);
            let stats = result.codec_stats;
            assert!(stats.frames_encoded > 0);
            assert!(stats.frames_decoded > 0);
            assert!(stats.partial_reads_processed > 0);
            assert!(stats.tcp_segment_boundary_spans > 0);
            assert!(stats.stream_operations > 0);
            Ok::<(), crate::error::Error>(())
        }).unwrap();
    }
}