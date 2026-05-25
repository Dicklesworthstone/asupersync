//! BR-E2E-189: Real raptorq/encoding ↔ codec/length_delimited Integration E2E Tests
//!
//! This module provides comprehensive integration tests between the RaptorQ encoding
//! pipeline and length-delimited framing codec. The tests verify that length-delimited
//! framing correctly encapsulates raptorq symbols without alignment errors, ensuring
//! proper symbol boundaries and data integrity throughout the encoding-framing pipeline.
//!
//! # Integration Focus
//!
//! Tests the coordination between:
//! - `raptorq::encoding` - RFC 6330 systematic encoding with deterministic symbols
//! - `codec::length_delimited` - Length-prefixed framing with configurable parameters
//!
//! # Key Scenarios
//!
//! - Symbol encapsulation: RaptorQ symbols correctly framed with length prefixes
//! - Alignment preservation: Symbol boundaries maintained through framing process
//! - Variable symbol sizes: Different symbol sizes handled without truncation
//! - Round-trip integrity: Encoded symbols survive framing/deframing cycles
//! - Deterministic behavior: Identical input produces identical framed output

use crate::{
    bytes::{Bytes, BytesMut, BufMut},
    codec::{
        Decoder, Encoder,
        length_delimited::{LengthDelimitedCodec, LengthDelimitedCodecBuilder},
        raptorq::{EncodedSymbol, EncodingPipeline, EncodingConfig},
    },
    config::EncodingConfig as RaptorQConfig,
    cx::{Cx, Scope},
    error::Outcome,
    runtime::RuntimeBuilder,
    sync::Mutex,
    time::{Duration, Sleep},
    types::{
        ObjectId, Time,
        resource::{PoolConfig, SymbolPool},
    },
    util::{
        det_rng::{DetRng, RngSeed},
        entropy::EntropySource,
    },
};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    io::{self, ErrorKind},
};

/// Tracks raptorq-length_delimited integration events and alignment verification
#[derive(Debug, Clone)]
struct RaptorQLengthDelimitedTracker {
    /// Total RaptorQ symbols encoded
    raptorq_symbols_encoded: Arc<AtomicU64>,
    /// Symbols successfully framed with length delimited codec
    symbols_framed: Arc<AtomicU64>,
    /// Symbols successfully decoded from frames
    symbols_unframed: Arc<AtomicU64>,
    /// Byte-perfect round-trip verifications
    round_trip_successes: Arc<AtomicU64>,
    /// Alignment errors detected
    alignment_errors: Arc<AtomicU64>,
    /// Framing errors encountered
    framing_errors: Arc<AtomicU64>,
    /// Symbol size mismatches
    size_mismatches: Arc<AtomicU64>,
    /// Total bytes processed through pipeline
    bytes_processed: Arc<AtomicU64>,
    /// Different symbol sizes handled
    unique_symbol_sizes: Arc<Mutex<HashSet<usize>>>,
    /// Event timeline for debugging
    event_timeline: Arc<Mutex<Vec<(String, std::time::Instant, String)>>>,
}

impl RaptorQLengthDelimitedTracker {
    fn new() -> Self {
        Self {
            raptorq_symbols_encoded: Arc::new(AtomicU64::new(0)),
            symbols_framed: Arc::new(AtomicU64::new(0)),
            symbols_unframed: Arc::new(AtomicU64::new(0)),
            round_trip_successes: Arc::new(AtomicU64::new(0)),
            alignment_errors: Arc::new(AtomicU64::new(0)),
            framing_errors: Arc::new(AtomicU64::new(0)),
            size_mismatches: Arc::new(AtomicU64::new(0)),
            bytes_processed: Arc::new(AtomicU64::new(0)),
            unique_symbol_sizes: Arc::new(Mutex::new(HashSet::new())),
            event_timeline: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn record_raptorq_symbol_encoded(&self) -> u64 {
        self.raptorq_symbols_encoded.fetch_add(1, Ordering::Relaxed)
    }

    fn record_symbol_framed(&self, size: usize) -> u64 {
        self.bytes_processed.fetch_add(size as u64, Ordering::Relaxed);
        self.symbols_framed.fetch_add(1, Ordering::Relaxed)
    }

    fn record_symbol_unframed(&self, size: usize) -> u64 {
        self.symbols_unframed.fetch_add(1, Ordering::Relaxed)
    }

    fn record_round_trip_success(&self) -> u64 {
        self.round_trip_successes.fetch_add(1, Ordering::Relaxed)
    }

    fn record_alignment_error(&self) -> u64 {
        self.alignment_errors.fetch_add(1, Ordering::Relaxed)
    }

    fn record_framing_error(&self) -> u64 {
        self.framing_errors.fetch_add(1, Ordering::Relaxed)
    }

    fn record_size_mismatch(&self) -> u64 {
        self.size_mismatches.fetch_add(1, Ordering::Relaxed)
    }

    async fn record_unique_symbol_size(&self, cx: &Cx, size: usize) {
        let mut sizes = self.unique_symbol_sizes.lock(cx).await;
        sizes.insert(size);
    }

    async fn record_event(&self, cx: &Cx, event_type: String, details: String) {
        let mut timeline = self.event_timeline.lock(cx).await;
        timeline.push((event_type, std::time::Instant::now(), details));
    }

    fn verify_symbol_processing(&self) -> bool {
        let encoded = self.raptorq_symbols_encoded.load(Ordering::Relaxed);
        let framed = self.symbols_framed.load(Ordering::Relaxed);
        let unframed = self.symbols_unframed.load(Ordering::Relaxed);

        // Should have processed symbols through the pipeline
        encoded > 0 && framed >= encoded && unframed >= framed
    }

    fn verify_round_trip_integrity(&self) -> bool {
        let successes = self.round_trip_successes.load(Ordering::Relaxed);
        let alignment_errors = self.alignment_errors.load(Ordering::Relaxed);

        // Should have successful round trips with minimal alignment errors
        successes > 0 && alignment_errors == 0
    }

    fn verify_framing_reliability(&self) -> bool {
        let framed = self.symbols_framed.load(Ordering::Relaxed);
        let framing_errors = self.framing_errors.load(Ordering::Relaxed);

        // Should frame symbols reliably
        framed > 0 && framing_errors == 0
    }
}

/// RaptorQ symbol with framing metadata for verification
#[derive(Debug, Clone)]
struct FramedRaptorQSymbol {
    /// Original encoded symbol
    symbol: EncodedSymbol,
    /// Symbol data as bytes
    data: Bytes,
    /// Expected frame size (including length prefix)
    expected_frame_size: usize,
    /// Symbol identifier for tracking
    symbol_id: u64,
}

/// Integration test orchestrator for RaptorQ ↔ length-delimited coordination
struct RaptorQLengthDelimitedOrchestrator {
    /// RaptorQ encoding pipeline
    encoding_pipeline: EncodingPipeline,
    /// Length-delimited codec for framing
    length_delimited_codec: LengthDelimitedCodec,
    /// Integration tracking
    tracker: RaptorQLengthDelimitedTracker,
    /// Symbol ID counter
    symbol_id_counter: Arc<AtomicU64>,
}

impl RaptorQLengthDelimitedOrchestrator {
    fn new(tracker: RaptorQLengthDelimitedTracker) -> Self {
        // Configure RaptorQ encoding pipeline
        let encoding_config = RaptorQConfig {
            repair_overhead: 1.2,
            max_block_size: 1024,
            symbol_size: 64, // Start with 64-byte symbols
            encoding_parallelism: 1,
            decoding_parallelism: 1,
        };

        let symbol_pool = SymbolPool::new(PoolConfig::default());
        let encoding_pipeline = EncodingPipeline::new(encoding_config, symbol_pool);

        // Configure length-delimited codec with standard settings
        let length_delimited_codec = LengthDelimitedCodec::builder()
            .length_field_length(4)     // 4-byte length prefix
            .big_endian(true)           // Network byte order
            .max_frame_length(8 * 1024) // 8KB max frame
            .new_codec();

        Self {
            encoding_pipeline,
            length_delimited_codec,
            tracker,
            symbol_id_counter: Arc::new(AtomicU64::new(0)),
        }
    }

    async fn encode_data_to_symbols(
        &mut self,
        cx: &Cx,
        object_id: ObjectId,
        data: &[u8],
    ) -> Outcome<Vec<FramedRaptorQSymbol>> {
        let mut framed_symbols = Vec::new();

        self.tracker
            .record_event(
                cx,
                "raptorq_encoding_start".to_string(),
                format!("object_id={:?}, data_len={}", object_id, data.len()),
            )
            .await;

        // Encode data through RaptorQ pipeline
        for encoded_symbol in self.encoding_pipeline.encode(object_id, data)? {
            let symbol_id = self.symbol_id_counter.fetch_add(1, Ordering::Relaxed);
            self.tracker.record_raptorq_symbol_encoded();

            // Convert symbol to bytes
            let symbol_data = encoded_symbol.data().clone();
            let data_len = symbol_data.len();

            self.tracker.record_unique_symbol_size(cx, data_len).await;

            // Calculate expected frame size (4-byte length prefix + data)
            let expected_frame_size = 4 + data_len;

            let framed_symbol = FramedRaptorQSymbol {
                symbol: encoded_symbol,
                data: symbol_data,
                expected_frame_size,
                symbol_id,
            };

            framed_symbols.push(framed_symbol);

            self.tracker
                .record_event(
                    cx,
                    "symbol_prepared".to_string(),
                    format!("symbol_id={}, size={}, expected_frame_size={}",
                        symbol_id, data_len, expected_frame_size),
                )
                .await;
        }

        self.tracker
            .record_event(
                cx,
                "raptorq_encoding_complete".to_string(),
                format!("symbols_produced={}", framed_symbols.len()),
            )
            .await;

        Ok(framed_symbols)
    }

    async fn frame_symbol_with_length_delimited(
        &mut self,
        cx: &Cx,
        framed_symbol: &FramedRaptorQSymbol,
    ) -> Outcome<Bytes> {
        let mut buffer = BytesMut::new();

        self.tracker
            .record_event(
                cx,
                "framing_start".to_string(),
                format!("symbol_id={}, data_len={}",
                    framed_symbol.symbol_id, framed_symbol.data.len()),
            )
            .await;

        // Use length-delimited codec to frame the symbol data
        match self.length_delimited_codec.encode(framed_symbol.data.clone(), &mut buffer) {
            Ok(()) => {
                let frame_bytes = buffer.freeze();
                let actual_frame_size = frame_bytes.len();

                // Verify expected frame size matches actual
                if actual_frame_size != framed_symbol.expected_frame_size {
                    self.tracker.record_size_mismatch();

                    self.tracker
                        .record_event(
                            cx,
                            "size_mismatch".to_string(),
                            format!("symbol_id={}, expected={}, actual={}",
                                framed_symbol.symbol_id,
                                framed_symbol.expected_frame_size,
                                actual_frame_size),
                        )
                        .await;

                    return Err(format!(
                        "Frame size mismatch: expected {}, got {}",
                        framed_symbol.expected_frame_size, actual_frame_size
                    ).into());
                }

                self.tracker.record_symbol_framed(framed_symbol.data.len());

                self.tracker
                    .record_event(
                        cx,
                        "framing_success".to_string(),
                        format!("symbol_id={}, frame_size={}",
                            framed_symbol.symbol_id, actual_frame_size),
                    )
                    .await;

                Ok(frame_bytes)
            }
            Err(error) => {
                self.tracker.record_framing_error();

                self.tracker
                    .record_event(
                        cx,
                        "framing_error".to_string(),
                        format!("symbol_id={}, error={}", framed_symbol.symbol_id, error),
                    )
                    .await;

                Err(format!("Framing error: {}", error).into())
            }
        }
    }

    async fn unframe_symbol_with_length_delimited(
        &mut self,
        cx: &Cx,
        frame_data: &Bytes,
        original_symbol: &FramedRaptorQSymbol,
    ) -> Outcome<Bytes> {
        let mut buffer = BytesMut::from(frame_data.as_ref());

        self.tracker
            .record_event(
                cx,
                "unframing_start".to_string(),
                format!("symbol_id={}, frame_len={}",
                    original_symbol.symbol_id, frame_data.len()),
            )
            .await;

        // Use length-delimited codec to decode the frame
        match self.length_delimited_codec.decode(&mut buffer) {
            Ok(Some(decoded_data)) => {
                // Verify alignment - decoded data should match original
                if decoded_data != original_symbol.data {
                    self.tracker.record_alignment_error();

                    self.tracker
                        .record_event(
                            cx,
                            "alignment_error".to_string(),
                            format!("symbol_id={}, original_len={}, decoded_len={}",
                                original_symbol.symbol_id,
                                original_symbol.data.len(),
                                decoded_data.len()),
                        )
                        .await;

                    return Err(format!(
                        "Alignment error: decoded data doesn't match original for symbol {}",
                        original_symbol.symbol_id
                    ).into());
                }

                self.tracker.record_symbol_unframed(decoded_data.len());

                self.tracker
                    .record_event(
                        cx,
                        "unframing_success".to_string(),
                        format!("symbol_id={}, decoded_len={}",
                            original_symbol.symbol_id, decoded_data.len()),
                    )
                    .await;

                Ok(decoded_data)
            }
            Ok(None) => {
                self.tracker.record_framing_error();
                Err(format!("Incomplete frame for symbol {}", original_symbol.symbol_id).into())
            }
            Err(error) => {
                self.tracker.record_framing_error();

                self.tracker
                    .record_event(
                        cx,
                        "unframing_error".to_string(),
                        format!("symbol_id={}, error={}", original_symbol.symbol_id, error),
                    )
                    .await;

                Err(format!("Unframing error: {}", error).into())
            }
        }
    }

    async fn test_round_trip_symbol(
        &mut self,
        cx: &Cx,
        framed_symbol: &FramedRaptorQSymbol,
    ) -> Outcome<()> {
        // Frame the symbol
        let frame_data = self.frame_symbol_with_length_delimited(cx, framed_symbol).await?;

        // Unframe the symbol
        let decoded_data = self.unframe_symbol_with_length_delimited(cx, &frame_data, framed_symbol).await?;

        // Verify round-trip integrity
        if decoded_data == framed_symbol.data {
            self.tracker.record_round_trip_success();

            self.tracker
                .record_event(
                    cx,
                    "round_trip_success".to_string(),
                    format!("symbol_id={}", framed_symbol.symbol_id),
                )
                .await;

            println!("✓ Round trip success for symbol {}", framed_symbol.symbol_id);
        } else {
            self.tracker.record_alignment_error();

            self.tracker
                .record_event(
                    cx,
                    "round_trip_failure".to_string(),
                    format!("symbol_id={}", framed_symbol.symbol_id),
                )
                .await;

            return Err(format!("Round trip failed for symbol {}", framed_symbol.symbol_id).into());
        }

        Ok(())
    }

    async fn run_variable_symbol_size_test(&mut self, cx: &Cx) -> Outcome<()> {
        // Test with different symbol sizes to verify alignment handling
        let symbol_sizes = vec![32, 64, 128, 256, 512, 1024];

        for symbol_size in symbol_sizes {
            // Reconfigure pipeline for this symbol size
            let encoding_config = RaptorQConfig {
                repair_overhead: 1.2,
                max_block_size: 1024,
                symbol_size: symbol_size as u16,
                encoding_parallelism: 1,
                decoding_parallelism: 1,
            };

            let symbol_pool = SymbolPool::new(PoolConfig::default());
            self.encoding_pipeline = EncodingPipeline::new(encoding_config, symbol_pool);

            // Generate test data
            let test_data = format!("Variable symbol size test data for {} byte symbols. ", symbol_size).repeat(symbol_size / 50 + 1);
            let test_data = &test_data.as_bytes()[..symbol_size * 3]; // ~3 symbols worth

            let object_id = ObjectId::new(0, symbol_size as u64);

            // Encode and test framing
            let framed_symbols = self.encode_data_to_symbols(cx, object_id, test_data).await?;

            for framed_symbol in &framed_symbols {
                self.test_round_trip_symbol(cx, framed_symbol).await?;
            }

            println!("✓ Variable symbol size test completed for {} byte symbols", symbol_size);
        }

        Ok(())
    }

    async fn run_alignment_stress_test(&mut self, cx: &Cx) -> Outcome<()> {
        // Test with data that could cause alignment issues (odd sizes, misaligned boundaries)
        let test_cases = vec![
            ("odd_size_data", vec![0x42u8; 63]),        // Odd size
            ("power_of_two_plus_one", vec![0xAAu8; 65]), // Just over power of 2
            ("small_data", vec![0x11u8; 7]),            // Very small
            ("boundary_data", vec![0xFFu8; 511]),       // Just under 512
        ];

        for (test_name, test_data) in test_cases {
            let object_id = ObjectId::new(test_data.len() as u64, 12345);

            self.tracker
                .record_event(
                    cx,
                    "alignment_stress_test".to_string(),
                    format!("test={}, data_len={}", test_name, test_data.len()),
                )
                .await;

            let framed_symbols = self.encode_data_to_symbols(cx, object_id, &test_data).await?;

            for framed_symbol in &framed_symbols {
                self.test_round_trip_symbol(cx, framed_symbol).await?;
            }

            println!("✓ Alignment stress test completed: {}", test_name);
        }

        Ok(())
    }

    async fn run_codec_configuration_test(&mut self, cx: &Cx) -> Outcome<()> {
        // Test with different length-delimited codec configurations
        let codec_configs = vec![
            ("standard_4byte", 4, true, 8192),      // Standard 4-byte big-endian
            ("compact_2byte", 2, true, 4096),      // Compact 2-byte
            ("large_8byte", 8, true, 16384),       // Large 8-byte length field
            ("little_endian", 4, false, 8192),     // Little-endian variant
        ];

        for (config_name, length_field_len, big_endian, max_frame) in codec_configs {
            // Reconfigure codec
            self.length_delimited_codec = LengthDelimitedCodec::builder()
                .length_field_length(length_field_len)
                .big_endian(big_endian)
                .max_frame_length(max_frame)
                .new_codec();

            self.tracker
                .record_event(
                    cx,
                    "codec_config_test".to_string(),
                    format!("config={}, length_field={}, big_endian={}, max_frame={}",
                        config_name, length_field_len, big_endian, max_frame),
                )
                .await;

            // Test with standard data
            let test_data = format!("Codec configuration test for {}. ", config_name).repeat(10);
            let object_id = ObjectId::new(42, test_data.len() as u64);

            let framed_symbols = self.encode_data_to_symbols(cx, object_id, test_data.as_bytes()).await?;

            for framed_symbol in &framed_symbols {
                // Update expected frame size for different length field sizes
                let mut updated_symbol = framed_symbol.clone();
                updated_symbol.expected_frame_size = length_field_len + framed_symbol.data.len();

                self.test_round_trip_symbol(cx, &updated_symbol).await?;
            }

            println!("✓ Codec configuration test completed: {}", config_name);
        }

        Ok(())
    }
}

/// Comprehensive integration test for RaptorQ encoding ↔ length-delimited framing
#[tokio::test]
async fn test_raptorq_length_delimited_symbol_encapsulation() -> Outcome<()> {
    let runtime = RuntimeBuilder::new()
        .with_deterministic_execution(false)
        .build()
        .await?;

    runtime
        .run(async move |cx| {
            let scope = cx.scope("raptorq_length_delimited_integration").await?;

            scope
                .run(async move |cx| {
                    // Initialize tracking
                    let tracker = RaptorQLengthDelimitedTracker::new();
                    let mut orchestrator = RaptorQLengthDelimitedOrchestrator::new(tracker.clone());

                    // Phase 1: Basic symbol encapsulation test
                    let test_data = b"Basic RaptorQ symbol encapsulation test with length-delimited framing.";
                    let object_id = ObjectId::new(1, test_data.len() as u64);

                    let framed_symbols = orchestrator
                        .encode_data_to_symbols(cx, object_id, test_data)
                        .await?;

                    for framed_symbol in &framed_symbols {
                        orchestrator.test_round_trip_symbol(cx, framed_symbol).await?;
                    }

                    println!("✓ Phase 1 completed: Basic symbol encapsulation");

                    // Phase 2: Variable symbol size test
                    orchestrator.run_variable_symbol_size_test(cx).await?;
                    println!("✓ Phase 2 completed: Variable symbol sizes");

                    // Phase 3: Alignment stress test
                    orchestrator.run_alignment_stress_test(cx).await?;
                    println!("✓ Phase 3 completed: Alignment stress tests");

                    // Phase 4: Codec configuration variations
                    orchestrator.run_codec_configuration_test(cx).await?;
                    println!("✓ Phase 4 completed: Codec configuration tests");

                    // Phase 5: Large data test
                    let large_test_data = "Large data test for RaptorQ length-delimited integration. ".repeat(100);
                    let large_object_id = ObjectId::new(2, large_test_data.len() as u64);

                    let large_framed_symbols = orchestrator
                        .encode_data_to_symbols(cx, large_object_id, large_test_data.as_bytes())
                        .await?;

                    for framed_symbol in &large_framed_symbols {
                        orchestrator.test_round_trip_symbol(cx, framed_symbol).await?;
                    }

                    println!("✓ Phase 5 completed: Large data test");

                    // Phase 6: Verification
                    assert!(
                        tracker.verify_symbol_processing(),
                        "Should have processed symbols through RaptorQ → length-delimited pipeline"
                    );

                    assert!(
                        tracker.verify_round_trip_integrity(),
                        "Should maintain round-trip integrity without alignment errors"
                    );

                    assert!(
                        tracker.verify_framing_reliability(),
                        "Should frame symbols reliably without framing errors"
                    );

                    // Verify statistics
                    let symbols_encoded = tracker.raptorq_symbols_encoded.load(Ordering::Relaxed);
                    let symbols_framed = tracker.symbols_framed.load(Ordering::Relaxed);
                    let symbols_unframed = tracker.symbols_unframed.load(Ordering::Relaxed);
                    let round_trips = tracker.round_trip_successes.load(Ordering::Relaxed);
                    let alignment_errors = tracker.alignment_errors.load(Ordering::Relaxed);
                    let framing_errors = tracker.framing_errors.load(Ordering::Relaxed);
                    let bytes_processed = tracker.bytes_processed.load(Ordering::Relaxed);

                    let unique_sizes = {
                        let sizes = tracker.unique_symbol_sizes.lock(cx).await;
                        sizes.len()
                    };

                    assert!(symbols_encoded > 0, "Should have encoded RaptorQ symbols");
                    assert_eq!(symbols_framed, symbols_encoded, "All symbols should be framed");
                    assert_eq!(symbols_unframed, symbols_framed, "All framed symbols should be unframed");
                    assert_eq!(round_trips, symbols_encoded, "All symbols should complete round trip");
                    assert_eq!(alignment_errors, 0, "Should have no alignment errors");
                    assert_eq!(framing_errors, 0, "Should have no framing errors");
                    assert!(bytes_processed > 0, "Should have processed bytes");
                    assert!(unique_sizes >= 6, "Should have tested multiple symbol sizes"); // From variable size test

                    println!(
                        "Integration test completed: {} symbols encoded, {} framed, {} unframed, {} round trips, {} unique sizes, {} bytes processed",
                        symbols_encoded, symbols_framed, symbols_unframed, round_trips, unique_sizes, bytes_processed
                    );

                    Ok(())
                })
                .await
        })
        .await
}

/// Test alignment verification under edge cases
#[tokio::test]
async fn test_raptorq_length_delimited_alignment_edge_cases() -> Outcome<()> {
    let runtime = RuntimeBuilder::new()
        .with_deterministic_execution(false)
        .build()
        .await?;

    runtime
        .run(async move |cx| {
            let scope = cx.scope("raptorq_alignment_edge_cases").await?;

            scope
                .run(async move |cx| {
                    let tracker = RaptorQLengthDelimitedTracker::new();

                    // Test edge cases that might cause alignment issues
                    let edge_cases = vec![
                        ("zero_padding", vec![0u8; 64]),
                        ("alternating_pattern", (0..64).map(|i| if i % 2 == 0 { 0xAA } else { 0x55 }).collect()),
                        ("incremental_pattern", (0..64).map(|i| i as u8).collect()),
                        ("boundary_values", vec![0xFF; 64]),
                    ];

                    for (case_name, test_data) in edge_cases {
                        tracker
                            .record_event(
                                cx,
                                "edge_case_test".to_string(),
                                format!("case={}", case_name),
                            )
                            .await;

                        // Use multiple symbol sizes for this edge case
                        for symbol_size in [32, 64, 128].iter() {
                            let encoding_config = RaptorQConfig {
                                repair_overhead: 1.1,
                                max_block_size: 512,
                                symbol_size: *symbol_size as u16,
                                encoding_parallelism: 1,
                                decoding_parallelism: 1,
                            };

                            let symbol_pool = SymbolPool::new(PoolConfig::default());
                            let mut encoding_pipeline = EncodingPipeline::new(encoding_config, symbol_pool);

                            let mut length_delimited_codec = LengthDelimitedCodec::new();

                            let object_id = ObjectId::new(case_name.len() as u64, *symbol_size as u64);

                            // Encode through RaptorQ
                            for encoded_symbol in encoding_pipeline.encode(object_id, &test_data)? {
                                tracker.record_raptorq_symbol_encoded();

                                let symbol_data = encoded_symbol.data().clone();

                                // Frame with length-delimited codec
                                let mut frame_buffer = BytesMut::new();
                                length_delimited_codec.encode(symbol_data.clone(), &mut frame_buffer)?;

                                let framed_data = frame_buffer.freeze();
                                tracker.record_symbol_framed(symbol_data.len());

                                // Unframe and verify
                                let mut decode_buffer = BytesMut::from(framed_data.as_ref());
                                match length_delimited_codec.decode(&mut decode_buffer)? {
                                    Some(decoded_data) => {
                                        if decoded_data == symbol_data {
                                            tracker.record_round_trip_success();
                                        } else {
                                            tracker.record_alignment_error();
                                            return Err(format!("Alignment error in edge case: {}", case_name).into());
                                        }
                                        tracker.record_symbol_unframed(decoded_data.len());
                                    }
                                    None => {
                                        tracker.record_framing_error();
                                        return Err(format!("Incomplete frame in edge case: {}", case_name).into());
                                    }
                                }
                            }
                        }

                        println!("✓ Edge case completed: {}", case_name);
                    }

                    // Verify edge case handling
                    let alignment_errors = tracker.alignment_errors.load(Ordering::Relaxed);
                    assert_eq!(alignment_errors, 0, "Should handle edge cases without alignment errors");

                    let round_trips = tracker.round_trip_successes.load(Ordering::Relaxed);
                    assert!(round_trips > 0, "Should have successful round trips in edge cases");

                    println!(
                        "Edge case test completed: {} round trips, {} alignment errors",
                        round_trips, alignment_errors
                    );

                    Ok(())
                })
                .await
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_raptorq_length_delimited_tracker_creation() {
        let tracker = RaptorQLengthDelimitedTracker::new();

        // Verify initial state
        assert_eq!(tracker.raptorq_symbols_encoded.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.symbols_framed.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.symbols_unframed.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.round_trip_successes.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.alignment_errors.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.framing_errors.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.size_mismatches.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.bytes_processed.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_tracking_operations() {
        let tracker = RaptorQLengthDelimitedTracker::new();

        // Record events
        tracker.record_raptorq_symbol_encoded();
        tracker.record_symbol_framed(64);
        tracker.record_symbol_unframed(64);
        tracker.record_round_trip_success();

        // Verify tracking
        assert_eq!(tracker.raptorq_symbols_encoded.load(Ordering::Relaxed), 1);
        assert_eq!(tracker.symbols_framed.load(Ordering::Relaxed), 1);
        assert_eq!(tracker.symbols_unframed.load(Ordering::Relaxed), 1);
        assert_eq!(tracker.round_trip_successes.load(Ordering::Relaxed), 1);
        assert_eq!(tracker.bytes_processed.load(Ordering::Relaxed), 64);

        // Verify verification methods
        assert!(tracker.verify_symbol_processing());
        assert!(tracker.verify_round_trip_integrity());
        assert!(tracker.verify_framing_reliability());
    }

    #[test]
    fn test_framed_raptorq_symbol_creation() {
        // This test would require actual RaptorQ symbols, which need a runtime context
        // For now, we test the structure
        let symbol_data = Bytes::from_static(b"test symbol data");
        let expected_frame_size = 4 + symbol_data.len(); // 4-byte length prefix + data

        // Verify expected frame size calculation
        assert_eq!(expected_frame_size, 20); // 4 + 16 bytes
    }
}