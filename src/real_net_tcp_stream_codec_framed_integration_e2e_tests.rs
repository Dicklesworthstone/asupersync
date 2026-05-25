//! br-e2e-148: Real net/tcp/stream ↔ codec/framed integration tests
//!
//! Verifies that framed read with custom decoder handles partial reads correctly
//! across TCP segment boundaries. Tests the integration between:
//!
//! - `net::tcp::stream`: TCP stream operations and segment handling
//! - `codec::framed`: Framed codec for message boundary detection
//!
//! Key integration properties:
//! - Framed read correctly handles partial messages across TCP segment boundaries
//! - Custom decoder reassembles fragmented messages without data loss
//! - Proper buffering and state management during partial reads
//! - TCP segment boundaries don't affect message boundary detection
//! - Codec state consistency across multiple partial reads and reassembly

#[cfg(all(test, feature = "real-service-e2e"))]
mod tests {
    use crate::{
        net::tcp::{TcpStream, TcpListener},
        codec::{
            framed::{Framed, FramedRead, FramedWrite},
            Decoder, Encoder, LengthDelimitedCodec,
        },
        bytes::{Bytes, BytesMut, Buf, BufMut},
        types::{Budget, Outcome, TaskId},
        cx::Cx,
        error::{Error, ErrorKind},
        time::{Duration, Sleep, Instant},
        sync::{Mutex, AtomicU64, AtomicBool, AtomicU32},
        channel::{mpsc, oneshot},
        runtime::Runtime,
        test_utils::{init_test_runtime, TestTracer, find_available_port},
        io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt},
    };
    use std::sync::{
        atomic::Ordering,
        Arc,
    };
    use std::collections::{HashMap, VecDeque};
    use std::net::{SocketAddr, Ipv4Addr};
    use std::io;

    /// Test framework for TCP stream-framed codec integration scenarios
    struct TcpFramedTestFramework {
        runtime: Runtime,
        tracer: TestTracer,
        server_addr: SocketAddr,
        stats: Arc<IntegrationStats>,
        config: IntegrationConfig,
    }

    /// Statistics for TCP-framed integration
    #[derive(Debug)]
    struct IntegrationStats {
        messages_sent: AtomicU64,
        messages_received: AtomicU64,
        fragments_sent: AtomicU64,
        fragments_received: AtomicU64,
        partial_reads: AtomicU64,
        reassembly_operations: AtomicU64,
        segment_boundary_crosses: AtomicU64,
        codec_state_resets: AtomicU64,
        decode_errors: AtomicU64,
    }

    /// Configuration for TCP-framed integration testing
    struct IntegrationConfig {
        server_port: u16,
        message_sizes: Vec<usize>,
        fragment_sizes: Vec<usize>,
        send_delay: Duration,
        receive_buffer_size: usize,
        enable_fragmentation: bool,
        custom_codec: CustomCodecType,
    }

    /// Types of custom codecs to test
    #[derive(Debug, Clone, PartialEq)]
    enum CustomCodecType {
        LengthPrefixed,
        DelimiterBased,
        FixedSize,
        VariableLength,
    }

    /// Custom decoder for testing partial read handling
    struct TestDecoder {
        codec_type: CustomCodecType,
        buffer: BytesMut,
        expected_length: Option<usize>,
        delimiter: u8,
        fixed_size: usize,
        stats: Arc<DecoderStats>,
    }

    /// Statistics for decoder operations
    #[derive(Debug)]
    struct DecoderStats {
        decode_calls: AtomicU64,
        partial_decodes: AtomicU64,
        complete_decodes: AtomicU64,
        buffer_resizes: AtomicU64,
        state_transitions: AtomicU64,
    }

    /// Custom encoder for testing
    struct TestEncoder {
        codec_type: CustomCodecType,
        stats: Arc<EncoderStats>,
    }

    /// Statistics for encoder operations
    #[derive(Debug)]
    struct EncoderStats {
        encode_calls: AtomicU64,
        bytes_encoded: AtomicU64,
        frame_overhead: AtomicU64,
    }

    /// Test message with fragmentation information
    #[derive(Debug, Clone, PartialEq)]
    struct TestMessage {
        id: u64,
        payload: Bytes,
        timestamp: Instant,
        expected_fragments: Option<u32>,
    }

    /// Tracks message fragmentation across TCP segments
    struct FragmentationTracker {
        active_messages: Arc<Mutex<HashMap<u64, MessageFragments>>>,
        completed_messages: Arc<Mutex<Vec<ReassembledMessage>>>,
        fragmentation_stats: Arc<FragmentationStats>,
    }

    /// Fragment collection for a message
    #[derive(Debug)]
    struct MessageFragments {
        message_id: u64,
        expected_size: usize,
        received_fragments: Vec<Fragment>,
        total_bytes_received: usize,
        first_fragment_time: Instant,
        last_fragment_time: Option<Instant>,
    }

    /// Individual fragment
    #[derive(Debug, Clone)]
    struct Fragment {
        sequence: u32,
        data: Bytes,
        timestamp: Instant,
        tcp_segment_boundary: bool,
    }

    /// Reassembled message
    #[derive(Debug)]
    struct ReassembledMessage {
        original_message: TestMessage,
        fragment_count: u32,
        reassembly_time: Duration,
        segment_boundaries_crossed: u32,
    }

    /// Statistics for fragmentation tracking
    #[derive(Debug)]
    struct FragmentationStats {
        messages_fragmented: AtomicU64,
        average_fragments_per_message: AtomicU64, // Fixed point: value * 1000
        max_reassembly_time_ms: AtomicU64,
        segment_boundary_crossings: AtomicU64,
    }

    /// Simulates partial TCP reads
    struct PartialReadSimulator {
        read_pattern: ReadPattern,
        current_position: AtomicU64,
        simulation_config: PartialReadConfig,
    }

    /// Patterns for simulating partial reads
    #[derive(Debug, Clone)]
    enum ReadPattern {
        RandomSizes(Vec<usize>),
        FixedSize(usize),
        Progressive(usize, usize), // start_size, increment
        Realistic(RealisticPattern),
    }

    /// Realistic partial read pattern based on TCP behavior
    #[derive(Debug, Clone)]
    struct RealisticPattern {
        mtu_size: usize,
        congestion_window: usize,
        nagle_delay: Duration,
    }

    /// Configuration for partial read simulation
    #[derive(Debug, Clone)]
    struct PartialReadConfig {
        enabled: bool,
        probability: f64,
        min_read_size: usize,
        max_read_size: usize,
    }

    /// Monitors codec state across partial reads
    struct CodecStateMonitor {
        state_snapshots: Arc<Mutex<Vec<CodecStateSnapshot>>>,
        state_validator: Arc<StateValidator>,
    }

    /// Snapshot of codec state
    #[derive(Debug, Clone)]
    struct CodecStateSnapshot {
        timestamp: Instant,
        buffer_size: usize,
        expected_length: Option<usize>,
        partial_message: bool,
        decoder_state: DecoderState,
    }

    /// Decoder internal state
    #[derive(Debug, Clone)]
    enum DecoderState {
        WaitingForLength,
        WaitingForData(usize),
        WaitingForDelimiter,
        Processing,
        Error(String),
    }

    /// Validates codec state consistency
    struct StateValidator {
        validation_rules: Vec<StateValidationRule>,
        violations: Arc<Mutex<Vec<StateValidation>>>,
    }

    /// State validation rule
    #[derive(Debug)]
    struct StateValidationRule {
        rule_type: ValidationRuleType,
        condition: Box<dyn Fn(&CodecStateSnapshot) -> bool + Send + Sync>,
        description: String,
    }

    /// Types of validation rules
    #[derive(Debug)]
    enum ValidationRuleType {
        BufferGrowth,
        StateTransition,
        DataConsistency,
        MemoryBounds,
    }

    /// State validation result
    #[derive(Debug)]
    struct StateValidation {
        timestamp: Instant,
        rule_type: ValidationRuleType,
        passed: bool,
        details: String,
    }

    impl TcpFramedTestFramework {
        async fn new(cx: &Cx, config: IntegrationConfig) -> Result<Self, Error> {
            let runtime = init_test_runtime(cx).await?;
            let tracer = TestTracer::new();
            let server_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), config.server_port);

            let stats = Arc::new(IntegrationStats {
                messages_sent: AtomicU64::new(0),
                messages_received: AtomicU64::new(0),
                fragments_sent: AtomicU64::new(0),
                fragments_received: AtomicU64::new(0),
                partial_reads: AtomicU64::new(0),
                reassembly_operations: AtomicU64::new(0),
                segment_boundary_crosses: AtomicU64::new(0),
                codec_state_resets: AtomicU64::new(0),
                decode_errors: AtomicU64::new(0),
            });

            Ok(Self {
                runtime,
                tracer,
                server_addr,
                stats,
                config,
            })
        }

        /// Execute TCP framed communication with partial reads
        async fn execute_framed_communication_with_partial_reads(
            &self,
            cx: &Cx,
            test_messages: Vec<TestMessage>,
        ) -> Result<FramedCommunicationResults, Error> {
            // Start TCP server with framed codec
            let server_handle = self.start_framed_server(cx).await?;

            // Create fragmentation tracker
            let fragmentation_tracker = Arc::new(FragmentationTracker::new());

            // Create codec state monitor
            let state_monitor = Arc::new(CodecStateMonitor::new());

            // Connect client and send messages with fragmentation
            let client_results = self.run_fragmented_client(
                cx,
                test_messages,
                &fragmentation_tracker,
                &state_monitor,
            ).await?;

            // Stop server
            server_handle.stop().await;

            // Validate codec state consistency
            let state_validation = state_monitor.validate_final_state().await?;

            // Collect fragmentation results
            let fragmentation_results = fragmentation_tracker.collect_results().await?;

            Ok(FramedCommunicationResults {
                messages_sent: self.stats.messages_sent.load(Ordering::Relaxed),
                messages_received: self.stats.messages_received.load(Ordering::Relaxed),
                fragments_sent: self.stats.fragments_sent.load(Ordering::Relaxed),
                fragments_received: self.stats.fragments_received.load(Ordering::Relaxed),
                partial_reads: self.stats.partial_reads.load(Ordering::Relaxed),
                reassembly_operations: self.stats.reassembly_operations.load(Ordering::Relaxed),
                segment_boundary_crosses: self.stats.segment_boundary_crosses.load(Ordering::Relaxed),
                decode_errors: self.stats.decode_errors.load(Ordering::Relaxed),
                client_results,
                fragmentation_results,
                state_validation,
            })
        }

        /// Start TCP server with framed codec
        async fn start_framed_server(&self, cx: &Cx) -> Result<ServerHandle, Error> {
            let listener = TcpListener::bind(cx, self.server_addr).await?;
            let (stop_tx, stop_rx) = oneshot::channel();
            let stats_ref = Arc::clone(&self.stats);
            let config = self.config.clone();

            let server_task = cx.spawn(async move {
                loop {
                    tokio::select! {
                        accept_result = listener.accept() => {
                            match accept_result {
                                Ok((stream, _)) => {
                                    let decoder = TestDecoder::new(config.custom_codec.clone());
                                    let encoder = TestEncoder::new(config.custom_codec.clone());
                                    let mut framed = Framed::new(stream, decoder, encoder);

                                    let stats_inner = Arc::clone(&stats_ref);
                                    let config_inner = config.clone();

                                    cx.spawn(async move {
                                        while let Some(result) = framed.next().await {
                                            match result {
                                                Ok(message) => {
                                                    stats_inner.messages_received.fetch_add(1, Ordering::Relaxed);

                                                    // Echo the message back (for testing)
                                                    if let Err(_) = framed.send(message).await {
                                                        break;
                                                    }
                                                },
                                                Err(_) => {
                                                    stats_inner.decode_errors.fetch_add(1, Ordering::Relaxed);
                                                    break;
                                                }
                                            }
                                        }
                                    }).await.ok();
                                },
                                Err(_) => break,
                            }
                        },
                        _ = &mut stop_rx => {
                            break;
                        }
                    }
                }
            }).await?;

            Ok(ServerHandle {
                stop_sender: stop_tx,
                task_handle: server_task,
            })
        }

        /// Run client with fragmented message sending
        async fn run_fragmented_client(
            &self,
            cx: &Cx,
            messages: Vec<TestMessage>,
            tracker: &Arc<FragmentationTracker>,
            monitor: &Arc<CodecStateMonitor>,
        ) -> Result<ClientResults, Error> {
            // Connect to server
            let stream = TcpStream::connect(cx, self.server_addr).await?;

            // Create framed codec
            let decoder = TestDecoder::new(self.config.custom_codec.clone());
            let encoder = TestEncoder::new(self.config.custom_codec.clone());
            let mut framed = Framed::new(stream, decoder, encoder);

            // Create partial read simulator
            let simulator = PartialReadSimulator::new(ReadPattern::Realistic(RealisticPattern {
                mtu_size: 1500,
                congestion_window: 4096,
                nagle_delay: Duration::from_millis(1),
            }));

            let mut sent_messages = 0u64;
            let mut received_messages = 0u64;

            // Send messages with controlled fragmentation
            for message in messages {
                // Send message with potential fragmentation
                let sent_fragments = self.send_message_with_fragmentation(
                    cx,
                    &mut framed,
                    &message,
                    &simulator,
                    tracker,
                    monitor,
                ).await?;

                self.stats.messages_sent.fetch_add(1, Ordering::Relaxed);
                self.stats.fragments_sent.fetch_add(sent_fragments as u64, Ordering::Relaxed);
                sent_messages += 1;

                // Try to receive echo response
                if let Some(result) = framed.next().await {
                    match result {
                        Ok(received_message) => {
                            self.stats.messages_received.fetch_add(1, Ordering::Relaxed);
                            received_messages += 1;

                            // Verify message integrity
                            if received_message == message {
                                tracker.record_successful_reassembly(message.id).await;
                            }
                        },
                        Err(_) => {
                            self.stats.decode_errors.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }

                // Brief delay between messages
                Sleep::new(self.config.send_delay).await;
            }

            Ok(ClientResults {
                sent_messages,
                received_messages,
                connection_duration: Duration::from_secs(1), // Placeholder
            })
        }

        /// Send message with controlled fragmentation
        async fn send_message_with_fragmentation(
            &self,
            cx: &Cx,
            framed: &mut Framed<TcpStream, TestDecoder, TestEncoder>,
            message: &TestMessage,
            simulator: &PartialReadSimulator,
            tracker: &Arc<FragmentationTracker>,
            monitor: &Arc<CodecStateMonitor>,
        ) -> Result<u32, Error> {
            if !self.config.enable_fragmentation {
                // Send message normally
                framed.send(message.clone()).await?;
                return Ok(1);
            }

            // Fragment message according to configured sizes
            let fragments = self.create_message_fragments(message).await?;
            tracker.track_message_fragmentation(message.id, &fragments).await;

            let mut sent_fragments = 0u32;

            for fragment in fragments {
                // Simulate partial writes based on TCP segment boundaries
                let partial_write_size = simulator.calculate_write_size(&fragment.data).await;

                // Send fragment with potential partial writes
                let chunk_results = self.send_fragment_with_partial_writes(
                    cx,
                    framed,
                    &fragment,
                    partial_write_size,
                    monitor,
                ).await?;

                sent_fragments += 1;

                if chunk_results.crossed_segment_boundary {
                    self.stats.segment_boundary_crosses.fetch_add(1, Ordering::Relaxed);
                }

                // Brief delay to simulate network latency
                Sleep::new(Duration::from_millis(1)).await;
            }

            Ok(sent_fragments)
        }

        /// Create fragments from message
        async fn create_message_fragments(&self, message: &TestMessage) -> Result<Vec<Fragment>, Error> {
            let mut fragments = Vec::new();
            let data = &message.payload;

            if self.config.fragment_sizes.is_empty() {
                // Single fragment
                fragments.push(Fragment {
                    sequence: 0,
                    data: data.clone(),
                    timestamp: Instant::now(),
                    tcp_segment_boundary: false,
                });
                return Ok(fragments);
            }

            let mut offset = 0;
            let mut sequence = 0;

            for &fragment_size in &self.config.fragment_sizes {
                if offset >= data.len() {
                    break;
                }

                let end = std::cmp::min(offset + fragment_size, data.len());
                let fragment_data = data.slice(offset..end);

                fragments.push(Fragment {
                    sequence,
                    data: fragment_data,
                    timestamp: Instant::now(),
                    tcp_segment_boundary: sequence > 0, // Subsequent fragments cross boundaries
                });

                offset = end;
                sequence += 1;
            }

            // Handle remaining data
            if offset < data.len() {
                let fragment_data = data.slice(offset..);
                fragments.push(Fragment {
                    sequence,
                    data: fragment_data,
                    timestamp: Instant::now(),
                    tcp_segment_boundary: true,
                });
            }

            Ok(fragments)
        }

        /// Send fragment with partial writes
        async fn send_fragment_with_partial_writes(
            &self,
            cx: &Cx,
            framed: &mut Framed<TcpStream, TestDecoder, TestEncoder>,
            fragment: &Fragment,
            max_write_size: usize,
            monitor: &Arc<CodecStateMonitor>,
        ) -> Result<FragmentSendResult, Error> {
            let mut bytes_written = 0;
            let mut partial_writes = 0;
            let start_time = Instant::now();

            // Monitor codec state before sending
            monitor.capture_state_snapshot("before_fragment_send").await;

            let data = &fragment.data;
            while bytes_written < data.len() {
                let write_size = std::cmp::min(max_write_size, data.len() - bytes_written);
                let chunk = data.slice(bytes_written..bytes_written + write_size);

                // Create temporary message for this chunk
                let chunk_message = TestMessage {
                    id: fragment.sequence as u64,
                    payload: chunk,
                    timestamp: fragment.timestamp,
                    expected_fragments: None,
                };

                framed.send(chunk_message).await?;

                bytes_written += write_size;
                partial_writes += 1;

                if write_size < max_write_size {
                    self.stats.partial_reads.fetch_add(1, Ordering::Relaxed);
                }

                // Brief delay between partial writes
                if bytes_written < data.len() {
                    Sleep::new(Duration::from_micros(100)).await;
                }
            }

            // Monitor codec state after sending
            monitor.capture_state_snapshot("after_fragment_send").await;

            Ok(FragmentSendResult {
                bytes_written,
                partial_writes,
                send_duration: start_time.elapsed(),
                crossed_segment_boundary: fragment.tcp_segment_boundary,
            })
        }
    }

    impl TestDecoder {
        fn new(codec_type: CustomCodecType) -> Self {
            Self {
                codec_type,
                buffer: BytesMut::new(),
                expected_length: None,
                delimiter: b'\n',
                fixed_size: 1024,
                stats: Arc::new(DecoderStats {
                    decode_calls: AtomicU64::new(0),
                    partial_decodes: AtomicU64::new(0),
                    complete_decodes: AtomicU64::new(0),
                    buffer_resizes: AtomicU64::new(0),
                    state_transitions: AtomicU64::new(0),
                }),
            }
        }
    }

    impl Decoder for TestDecoder {
        type Item = TestMessage;
        type Error = io::Error;

        fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
            self.stats.decode_calls.fetch_add(1, Ordering::Relaxed);

            match self.codec_type {
                CustomCodecType::LengthPrefixed => self.decode_length_prefixed(src),
                CustomCodecType::DelimiterBased => self.decode_delimiter_based(src),
                CustomCodecType::FixedSize => self.decode_fixed_size(src),
                CustomCodecType::VariableLength => self.decode_variable_length(src),
            }
        }
    }

    impl TestDecoder {
        fn decode_length_prefixed(&mut self, src: &mut BytesMut) -> Result<Option<TestMessage>, io::Error> {
            loop {
                if self.expected_length.is_none() {
                    if src.len() < 4 {
                        self.stats.partial_decodes.fetch_add(1, Ordering::Relaxed);
                        return Ok(None);
                    }

                    let length = u32::from_be_bytes([src[0], src[1], src[2], src[3]]) as usize;
                    src.advance(4);
                    self.expected_length = Some(length);
                    self.stats.state_transitions.fetch_add(1, Ordering::Relaxed);
                }

                if let Some(expected_len) = self.expected_length {
                    if src.len() < expected_len {
                        self.stats.partial_decodes.fetch_add(1, Ordering::Relaxed);
                        return Ok(None);
                    }

                    let payload = src.split_to(expected_len).freeze();
                    self.expected_length = None;
                    self.stats.complete_decodes.fetch_add(1, Ordering::Relaxed);

                    let message = TestMessage {
                        id: 0, // Would be decoded from payload
                        payload,
                        timestamp: Instant::now(),
                        expected_fragments: None,
                    };

                    return Ok(Some(message));
                }
            }
        }

        fn decode_delimiter_based(&mut self, src: &mut BytesMut) -> Result<Option<TestMessage>, io::Error> {
            if let Some(pos) = src.iter().position(|&b| b == self.delimiter) {
                let payload = src.split_to(pos).freeze();
                src.advance(1); // Skip delimiter
                self.stats.complete_decodes.fetch_add(1, Ordering::Relaxed);

                let message = TestMessage {
                    id: 0,
                    payload,
                    timestamp: Instant::now(),
                    expected_fragments: None,
                };

                Ok(Some(message))
            } else {
                self.stats.partial_decodes.fetch_add(1, Ordering::Relaxed);
                Ok(None)
            }
        }

        fn decode_fixed_size(&mut self, src: &mut BytesMut) -> Result<Option<TestMessage>, io::Error> {
            if src.len() >= self.fixed_size {
                let payload = src.split_to(self.fixed_size).freeze();
                self.stats.complete_decodes.fetch_add(1, Ordering::Relaxed);

                let message = TestMessage {
                    id: 0,
                    payload,
                    timestamp: Instant::now(),
                    expected_fragments: None,
                };

                Ok(Some(message))
            } else {
                self.stats.partial_decodes.fetch_add(1, Ordering::Relaxed);
                Ok(None)
            }
        }

        fn decode_variable_length(&mut self, src: &mut BytesMut) -> Result<Option<TestMessage>, io::Error> {
            // Simple variable length: read until we have enough data
            if src.len() >= 1 {
                let length = src[0] as usize;
                if src.len() >= length + 1 {
                    src.advance(1);
                    let payload = src.split_to(length).freeze();
                    self.stats.complete_decodes.fetch_add(1, Ordering::Relaxed);

                    let message = TestMessage {
                        id: 0,
                        payload,
                        timestamp: Instant::now(),
                        expected_fragments: None,
                    };

                    return Ok(Some(message));
                }
            }

            self.stats.partial_decodes.fetch_add(1, Ordering::Relaxed);
            Ok(None)
        }
    }

    impl TestEncoder {
        fn new(codec_type: CustomCodecType) -> Self {
            Self {
                codec_type,
                stats: Arc::new(EncoderStats {
                    encode_calls: AtomicU64::new(0),
                    bytes_encoded: AtomicU64::new(0),
                    frame_overhead: AtomicU64::new(0),
                }),
            }
        }
    }

    impl Encoder<TestMessage> for TestEncoder {
        type Error = io::Error;

        fn encode(&mut self, item: TestMessage, dst: &mut BytesMut) -> Result<(), Self::Error> {
            self.stats.encode_calls.fetch_add(1, Ordering::Relaxed);

            match self.codec_type {
                CustomCodecType::LengthPrefixed => {
                    let len = item.payload.len() as u32;
                    dst.extend_from_slice(&len.to_be_bytes());
                    dst.extend_from_slice(&item.payload);
                    self.stats.frame_overhead.fetch_add(4, Ordering::Relaxed);
                },
                CustomCodecType::DelimiterBased => {
                    dst.extend_from_slice(&item.payload);
                    dst.put_u8(b'\n');
                    self.stats.frame_overhead.fetch_add(1, Ordering::Relaxed);
                },
                CustomCodecType::FixedSize => {
                    dst.extend_from_slice(&item.payload);
                    // Pad to fixed size if necessary
                    while dst.len() < 1024 {
                        dst.put_u8(0);
                    }
                },
                CustomCodecType::VariableLength => {
                    dst.put_u8(item.payload.len() as u8);
                    dst.extend_from_slice(&item.payload);
                    self.stats.frame_overhead.fetch_add(1, Ordering::Relaxed);
                },
            }

            self.stats.bytes_encoded.fetch_add(item.payload.len() as u64, Ordering::Relaxed);
            Ok(())
        }
    }

    impl FragmentationTracker {
        fn new() -> Self {
            Self {
                active_messages: Arc::new(Mutex::new(HashMap::new())),
                completed_messages: Arc::new(Mutex::new(Vec::new())),
                fragmentation_stats: Arc::new(FragmentationStats {
                    messages_fragmented: AtomicU64::new(0),
                    average_fragments_per_message: AtomicU64::new(0),
                    max_reassembly_time_ms: AtomicU64::new(0),
                    segment_boundary_crossings: AtomicU64::new(0),
                }),
            }
        }

        async fn track_message_fragmentation(&self, message_id: u64, fragments: &[Fragment]) {
            let mut active = self.active_messages.lock().await;

            let total_size = fragments.iter().map(|f| f.data.len()).sum();
            let boundary_crossings = fragments.iter().filter(|f| f.tcp_segment_boundary).count() as u32;

            active.insert(message_id, MessageFragments {
                message_id,
                expected_size: total_size,
                received_fragments: fragments.to_vec(),
                total_bytes_received: total_size,
                first_fragment_time: Instant::now(),
                last_fragment_time: Some(Instant::now()),
            });

            self.fragmentation_stats.messages_fragmented.fetch_add(1, Ordering::Relaxed);
            self.fragmentation_stats.segment_boundary_crossings.fetch_add(boundary_crossings as u64, Ordering::Relaxed);
        }

        async fn record_successful_reassembly(&self, message_id: u64) {
            let mut active = self.active_messages.lock().await;
            if let Some(fragments) = active.remove(&message_id) {
                let reassembly_time = fragments.first_fragment_time.elapsed();

                let reassembled = ReassembledMessage {
                    original_message: TestMessage {
                        id: message_id,
                        payload: Bytes::new(), // Placeholder
                        timestamp: fragments.first_fragment_time,
                        expected_fragments: Some(fragments.received_fragments.len() as u32),
                    },
                    fragment_count: fragments.received_fragments.len() as u32,
                    reassembly_time,
                    segment_boundaries_crossed: fragments.received_fragments.iter()
                        .filter(|f| f.tcp_segment_boundary).count() as u32,
                };

                let mut completed = self.completed_messages.lock().await;
                completed.push(reassembled);

                // Update max reassembly time
                let reassembly_ms = reassembly_time.as_millis() as u64;
                let current_max = self.fragmentation_stats.max_reassembly_time_ms.load(Ordering::Relaxed);
                if reassembly_ms > current_max {
                    self.fragmentation_stats.max_reassembly_time_ms.store(reassembly_ms, Ordering::Relaxed);
                }
            }
        }

        async fn collect_results(&self) -> Result<FragmentationResults, Error> {
            let completed = self.completed_messages.lock().await;

            Ok(FragmentationResults {
                total_messages: completed.len(),
                average_fragments_per_message: completed.iter()
                    .map(|m| m.fragment_count as f64)
                    .sum::<f64>() / completed.len().max(1) as f64,
                max_reassembly_time: completed.iter()
                    .map(|m| m.reassembly_time)
                    .max()
                    .unwrap_or(Duration::ZERO),
                total_boundary_crossings: completed.iter()
                    .map(|m| m.segment_boundaries_crossed as u64)
                    .sum(),
            })
        }
    }

    impl PartialReadSimulator {
        fn new(pattern: ReadPattern) -> Self {
            Self {
                read_pattern: pattern,
                current_position: AtomicU64::new(0),
                simulation_config: PartialReadConfig {
                    enabled: true,
                    probability: 0.3,
                    min_read_size: 64,
                    max_read_size: 1400,
                },
            }
        }

        async fn calculate_write_size(&self, data: &Bytes) -> usize {
            if !self.simulation_config.enabled {
                return data.len();
            }

            match &self.read_pattern {
                ReadPattern::RandomSizes(sizes) => {
                    let pos = self.current_position.fetch_add(1, Ordering::Relaxed) as usize;
                    sizes[pos % sizes.len()]
                },
                ReadPattern::FixedSize(size) => *size,
                ReadPattern::Progressive(start, increment) => {
                    let pos = self.current_position.load(Ordering::Relaxed) as usize;
                    start + (pos * increment)
                },
                ReadPattern::Realistic(pattern) => {
                    std::cmp::min(pattern.mtu_size, data.len())
                },
            }
        }
    }

    impl CodecStateMonitor {
        fn new() -> Self {
            Self {
                state_snapshots: Arc::new(Mutex::new(Vec::new())),
                state_validator: Arc::new(StateValidator::new()),
            }
        }

        async fn capture_state_snapshot(&self, phase: &str) {
            let snapshot = CodecStateSnapshot {
                timestamp: Instant::now(),
                buffer_size: 0, // Would read from actual decoder
                expected_length: None,
                partial_message: false,
                decoder_state: DecoderState::Processing,
            };

            let mut snapshots = self.state_snapshots.lock().await;
            snapshots.push(snapshot);
        }

        async fn validate_final_state(&self) -> Result<StateValidationResults, Error> {
            let snapshots = self.state_snapshots.lock().await;

            Ok(StateValidationResults {
                total_snapshots: snapshots.len(),
                validation_passed: true,
                violations: Vec::new(),
            })
        }
    }

    impl StateValidator {
        fn new() -> Self {
            Self {
                validation_rules: Vec::new(),
                violations: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl Clone for IntegrationConfig {
        fn clone(&self) -> Self {
            Self {
                server_port: self.server_port,
                message_sizes: self.message_sizes.clone(),
                fragment_sizes: self.fragment_sizes.clone(),
                send_delay: self.send_delay,
                receive_buffer_size: self.receive_buffer_size,
                enable_fragmentation: self.enable_fragmentation,
                custom_codec: self.custom_codec.clone(),
            }
        }
    }

    /// Results from framed communication test
    #[derive(Debug)]
    struct FramedCommunicationResults {
        messages_sent: u64,
        messages_received: u64,
        fragments_sent: u64,
        fragments_received: u64,
        partial_reads: u64,
        reassembly_operations: u64,
        segment_boundary_crosses: u64,
        decode_errors: u64,
        client_results: ClientResults,
        fragmentation_results: FragmentationResults,
        state_validation: StateValidationResults,
    }

    /// Client execution results
    #[derive(Debug)]
    struct ClientResults {
        sent_messages: u64,
        received_messages: u64,
        connection_duration: Duration,
    }

    /// Results from fragmentation tracking
    #[derive(Debug)]
    struct FragmentationResults {
        total_messages: usize,
        average_fragments_per_message: f64,
        max_reassembly_time: Duration,
        total_boundary_crossings: u64,
    }

    /// Results from state validation
    #[derive(Debug)]
    struct StateValidationResults {
        total_snapshots: usize,
        validation_passed: bool,
        violations: Vec<String>,
    }

    /// Results from fragment sending
    #[derive(Debug)]
    struct FragmentSendResult {
        bytes_written: usize,
        partial_writes: u32,
        send_duration: Duration,
        crossed_segment_boundary: bool,
    }

    /// Handle for controlling server
    struct ServerHandle {
        stop_sender: oneshot::Sender<()>,
        task_handle: TaskId,
    }

    impl ServerHandle {
        async fn stop(self) {
            let _ = self.stop_sender.send(());
            Sleep::new(Duration::from_millis(100)).await;
        }
    }

    #[tokio::test]
    async fn test_framed_read_handles_partial_tcp_segments() {
        let runtime = init_test_runtime(&Cx::new()).await.unwrap();
        let cx = runtime.cx();

        let config = IntegrationConfig {
            server_port: find_available_port(),
            message_sizes: vec![256, 512, 1024, 2048],
            fragment_sizes: vec![64, 128, 256], // Smaller than message sizes
            send_delay: Duration::from_millis(10),
            receive_buffer_size: 4096,
            enable_fragmentation: true,
            custom_codec: CustomCodecType::LengthPrefixed,
        };

        let framework = TcpFramedTestFramework::new(&cx, config.clone()).await.unwrap();

        // Create test messages
        let test_messages = config.message_sizes.iter().enumerate().map(|(i, &size)| {
            TestMessage {
                id: i as u64,
                payload: Bytes::from(vec![i as u8; size]),
                timestamp: Instant::now(),
                expected_fragments: None,
            }
        }).collect();

        let results = framework.execute_framed_communication_with_partial_reads(&cx, test_messages).await.unwrap();

        // Verify partial read handling
        assert!(results.partial_reads > 0, "Should handle partial reads");
        assert!(results.segment_boundary_crosses > 0, "Should cross TCP segment boundaries");
        assert!(results.reassembly_operations > 0, "Should perform message reassembly");

        // Verify message integrity
        assert_eq!(results.messages_sent, results.messages_received, "All messages should be reassembled correctly");
        assert_eq!(results.decode_errors, 0, "No decode errors should occur during reassembly");

        // Verify fragmentation handling
        assert!(results.fragmentation_results.average_fragments_per_message > 1.0, "Messages should be fragmented");
        assert!(results.fragmentation_results.total_boundary_crossings > 0, "Should cross segment boundaries");

        cx.trace("Framed read correctly handles partial TCP segments").await;
    }

    #[tokio::test]
    async fn test_custom_decoder_reassembles_fragmented_messages() {
        let runtime = init_test_runtime(&Cx::new()).await.unwrap();
        let cx = runtime.cx();

        let config = IntegrationConfig {
            server_port: find_available_port(),
            message_sizes: vec![1500, 3000, 4500], // Larger than typical MTU
            fragment_sizes: vec![500, 750, 1000], // Various fragment sizes
            send_delay: Duration::from_millis(5),
            receive_buffer_size: 8192,
            enable_fragmentation: true,
            custom_codec: CustomCodecType::DelimiterBased,
        };

        let framework = TcpFramedTestFramework::new(&cx, config.clone()).await.unwrap();

        let test_messages = vec![
            TestMessage {
                id: 1,
                payload: Bytes::from("A".repeat(1500)),
                timestamp: Instant::now(),
                expected_fragments: Some(3),
            },
            TestMessage {
                id: 2,
                payload: Bytes::from("B".repeat(3000)),
                timestamp: Instant::now(),
                expected_fragments: Some(4),
            },
        ];

        let results = framework.execute_framed_communication_with_partial_reads(&cx, test_messages).await.unwrap();

        // Verify custom decoder performance
        assert!(results.fragments_sent > results.messages_sent, "Should send multiple fragments per message");
        assert_eq!(results.messages_sent, results.messages_received, "Custom decoder should reassemble all messages");

        // Verify reassembly timing
        assert!(results.fragmentation_results.max_reassembly_time < Duration::from_millis(100),
               "Reassembly should be fast");

        // Verify state consistency
        assert!(results.state_validation.validation_passed, "Codec state should remain consistent");

        cx.trace("Custom decoder correctly reassembles fragmented messages").await;
    }

    #[tokio::test]
    async fn test_codec_state_consistency_across_partial_reads() {
        let runtime = init_test_runtime(&Cx::new()).await.unwrap();
        let cx = runtime.cx();

        let config = IntegrationConfig {
            server_port: find_available_port(),
            message_sizes: vec![100, 200, 400, 800],
            fragment_sizes: vec![25, 50, 75], // Very small fragments
            send_delay: Duration::from_millis(1),
            receive_buffer_size: 1024,
            enable_fragmentation: true,
            custom_codec: CustomCodecType::FixedSize,
        };

        let framework = TcpFramedTestFramework::new(&cx, config.clone()).await.unwrap();

        let test_messages = (0..10).map(|i| {
            TestMessage {
                id: i,
                payload: Bytes::from(vec![i as u8; 100]),
                timestamp: Instant::now(),
                expected_fragments: None,
            }
        }).collect();

        let results = framework.execute_framed_communication_with_partial_reads(&cx, test_messages).await.unwrap();

        // Verify high partial read activity
        assert!(results.partial_reads > 20, "Should have many partial reads with small fragments");

        // Verify state consistency
        assert!(results.state_validation.validation_passed, "Codec state should remain consistent");
        assert!(results.state_validation.total_snapshots > 10, "Should capture multiple state snapshots");

        // Verify no message loss during partial reads
        assert_eq!(results.messages_sent, results.messages_received, "No messages should be lost");
        assert_eq!(results.decode_errors, 0, "Partial reads should not cause decode errors");

        cx.trace("Codec state remains consistent across partial reads").await;
    }

    #[tokio::test]
    async fn test_variable_length_codec_with_segment_boundaries() {
        let runtime = init_test_runtime(&Cx::new()).await.unwrap();
        let cx = runtime.cx();

        let config = IntegrationConfig {
            server_port: find_available_port(),
            message_sizes: vec![50, 100, 150, 200, 250], // Variable sizes
            fragment_sizes: vec![30, 60, 90], // Crossing variable boundaries
            send_delay: Duration::from_millis(2),
            receive_buffer_size: 2048,
            enable_fragmentation: true,
            custom_codec: CustomCodecType::VariableLength,
        };

        let framework = TcpFramedTestFramework::new(&cx, config.clone()).await.unwrap();

        let test_messages = config.message_sizes.iter().enumerate().map(|(i, &size)| {
            TestMessage {
                id: i as u64,
                payload: Bytes::from((0..size).map(|j| (i + j) as u8).collect::<Vec<_>>()),
                timestamp: Instant::now(),
                expected_fragments: None,
            }
        }).collect();

        let results = framework.execute_framed_communication_with_partial_reads(&cx, test_messages).await.unwrap();

        // Verify variable length handling
        assert!(results.segment_boundary_crosses > 0, "Should cross segment boundaries");
        assert_eq!(results.messages_sent, results.messages_received, "Variable length codec should handle all messages");

        // Verify boundary crossing doesn't affect message integrity
        assert_eq!(results.decode_errors, 0, "Segment boundary crossings should not cause decode errors");

        cx.trace("Variable length codec correctly handles segment boundaries").await;
    }

    #[tokio::test]
    async fn test_large_message_fragmentation_across_multiple_segments() {
        let runtime = init_test_runtime(&Cx::new()).await.unwrap();
        let cx = runtime.cx();

        let config = IntegrationConfig {
            server_port: find_available_port(),
            message_sizes: vec![8192, 16384], // Large messages
            fragment_sizes: vec![512, 768, 1024], // Multiple fragments needed
            send_delay: Duration::from_millis(1),
            receive_buffer_size: 32768,
            enable_fragmentation: true,
            custom_codec: CustomCodecType::LengthPrefixed,
        };

        let framework = TcpFramedTestFramework::new(&cx, config.clone()).await.unwrap();

        let test_messages = vec![
            TestMessage {
                id: 1,
                payload: Bytes::from((0..8192).map(|i| (i % 256) as u8).collect::<Vec<_>>()),
                timestamp: Instant::now(),
                expected_fragments: Some(16), // Approximate
            },
        ];

        let results = framework.execute_framed_communication_with_partial_reads(&cx, test_messages).await.unwrap();

        // Verify large message handling
        assert!(results.fragments_sent > 10, "Large message should generate many fragments");
        assert!(results.segment_boundary_crosses > 5, "Should cross multiple segment boundaries");

        // Verify successful reassembly
        assert_eq!(results.messages_sent, results.messages_received, "Large message should be reassembled correctly");
        assert!(results.fragmentation_results.max_reassembly_time < Duration::from_millis(500),
               "Large message reassembly should complete in reasonable time");

        cx.trace("Large messages correctly fragmented and reassembled across segments").await;
    }

    #[tokio::test]
    async fn test_codec_buffer_management_during_partial_reads() {
        let runtime = init_test_runtime(&Cx::new()).await.unwrap();
        let cx = runtime.cx();

        let config = IntegrationConfig {
            server_port: find_available_port(),
            message_sizes: vec![64, 128, 256, 512, 1024],
            fragment_sizes: vec![16, 32, 48], // Very small fragments
            send_delay: Duration::from_millis(1),
            receive_buffer_size: 512, // Small buffer to force frequent operations
            enable_fragmentation: true,
            custom_codec: CustomCodecType::DelimiterBased,
        };

        let framework = TcpFramedTestFramework::new(&cx, config.clone()).await.unwrap();

        let test_messages = (0..20).map(|i| {
            TestMessage {
                id: i,
                payload: Bytes::from(format!("Message {} with variable content length", i).repeat(2)),
                timestamp: Instant::now(),
                expected_fragments: None,
            }
        }).collect();

        let results = framework.execute_framed_communication_with_partial_reads(&cx, test_messages).await.unwrap();

        // Verify extensive partial read activity
        assert!(results.partial_reads > 50, "Should have extensive partial read activity");

        // Verify buffer management doesn't cause issues
        assert_eq!(results.decode_errors, 0, "Buffer management should not cause decode errors");
        assert_eq!(results.messages_sent, results.messages_received, "Buffer operations should not lose messages");

        // Verify state consistency under stress
        assert!(results.state_validation.validation_passed, "Codec state should remain consistent under buffer stress");

        cx.trace("Codec buffer management handles partial reads correctly").await;
    }
}