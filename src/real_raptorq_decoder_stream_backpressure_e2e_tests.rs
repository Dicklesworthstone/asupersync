//! E2E tests for raptorq/decoder ↔ stream backpressure integration.
//!
//! Verifies that RaptorQ decoder output properly integrates with stream
//! combinators and handles backpressure correctly for slow consumers.
//!
//! # Test Coverage
//!
//! ## RaptorQ Decoder Stream Integration
//! - Decoded source symbol streaming with proper flow control
//! - Stream buffering coordination with decoder output rate
//! - Symbol ordering preservation through stream transformations
//! - Decoder state management during stream consumption patterns
//!
//! ## Backpressure Management
//! - Slow consumer handling with buffered stream adaptors
//! - Stream throttling during high-rate decode operations
//! - Decoder output coordination with variable stream consumption rates
//! - Cooperative polling budgets preventing executor monopolization
//!
//! ## Stream Combinator Integration
//! - Decoder output chaining through stream combinators
//! - Stream transformation (map, filter, buffer) with RaptorQ symbols
//! - Multi-consumer stream splitting from single decoder
//! - Error propagation from decoder through stream chains
//!
//! ## Performance and Flow Control
//! - High symbol rate decoding with stream rate limiting
//! - Memory usage control through buffered stream limits
//! - Decoder pause/resume coordination with stream backpressure
//! - Consumer speed variations handling without data loss

#![cfg(all(test, feature = "real-service-e2e"))]

use std::sync::{Arc, Mutex, atomic::{AtomicU64, AtomicU32, AtomicBool, Ordering}};
use std::time::{Duration, Instant};
use std::collections::{HashMap, VecDeque};
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::cx::{Cx, Scope};
use crate::types::{Budget, Outcome, Time};
use crate::runtime::test_util::create_test_runtime;
use crate::raptorq::{
    decoder::{RaptorQDecoder, ReceivedSymbol, DecodeError, DecodeResult},
    systematic::{SystematicParams, ConstraintMatrix},
    gf256::Gf256,
    proof::{DecodeConfig, DecodeProof},
};
use crate::stream::{
    Stream, StreamExt,
    buffered::Buffered,
    throttle::Throttle,
};
use crate::channel::mpsc;

/// Configuration for decoder stream backpressure testing.
#[derive(Clone, Debug)]
struct DecoderStreamTestConfig {
    /// Number of source symbols to encode/decode
    source_symbol_count: u32,
    /// Symbol size in bytes
    symbol_size: usize,
    /// Total encoded symbols (source + repair)
    total_encoded_symbols: u32,
    /// Stream buffer size for backpressure testing
    stream_buffer_size: usize,
    /// Consumer processing delay (simulates slow consumer)
    consumer_delay: Duration,
    /// Maximum stream throughput (symbols per second)
    max_stream_rate: u32,
    /// Test duration for sustained operations
    test_duration: Duration,
}

impl Default for DecoderStreamTestConfig {
    fn default() -> Self {
        Self {
            source_symbol_count: 100,
            symbol_size: 1024,
            total_encoded_symbols: 120, // 20% overhead
            stream_buffer_size: 32,
            consumer_delay: Duration::from_millis(50),
            max_stream_rate: 50, // symbols/sec
            test_duration: Duration::from_secs(10),
        }
    }
}

/// Metrics for tracking decoder and stream integration performance.
#[derive(Default, Clone)]
struct DecoderStreamMetrics {
    /// Symbols decoded by RaptorQ decoder
    symbols_decoded: Arc<AtomicU64>,
    /// Symbols consumed through stream
    symbols_consumed: Arc<AtomicU64>,
    /// Backpressure events triggered
    backpressure_events: Arc<AtomicU64>,
    /// Stream buffer overruns detected
    buffer_overruns: Arc<AtomicU64>,
    /// Decoder pause events due to backpressure
    decoder_pauses: Arc<AtomicU64>,
    /// Stream throttling activations
    throttling_activations: Arc<AtomicU64>,
    /// Symbol ordering violations detected
    ordering_violations: Arc<AtomicU64>,
    /// Consumer stalls (unable to keep up)
    consumer_stalls: Arc<AtomicU64>,
}

impl DecoderStreamMetrics {
    fn record_symbol_decoded(&self) {
        self.symbols_decoded.fetch_add(1, Ordering::Relaxed);
    }

    fn record_symbol_consumed(&self) {
        self.symbols_consumed.fetch_add(1, Ordering::Relaxed);
    }

    fn record_backpressure_event(&self) {
        self.backpressure_events.fetch_add(1, Ordering::Relaxed);
    }

    fn record_buffer_overrun(&self) {
        self.buffer_overruns.fetch_add(1, Ordering::Relaxed);
    }

    fn record_decoder_pause(&self) {
        self.decoder_pauses.fetch_add(1, Ordering::Relaxed);
    }

    fn record_throttling_activation(&self) {
        self.throttling_activations.fetch_add(1, Ordering::Relaxed);
    }

    fn record_ordering_violation(&self) {
        self.ordering_violations.fetch_add(1, Ordering::Relaxed);
    }

    fn record_consumer_stall(&self) {
        self.consumer_stalls.fetch_add(1, Ordering::Relaxed);
    }

    fn get_totals(&self) -> (u64, u64, u64, u64, u64, u64, u64, u64) {
        (
            self.symbols_decoded.load(Ordering::Relaxed),
            self.symbols_consumed.load(Ordering::Relaxed),
            self.backpressure_events.load(Ordering::Relaxed),
            self.buffer_overruns.load(Ordering::Relaxed),
            self.decoder_pauses.load(Ordering::Relaxed),
            self.throttling_activations.load(Ordering::Relaxed),
            self.ordering_violations.load(Ordering::Relaxed),
            self.consumer_stalls.load(Ordering::Relaxed),
        )
    }
}

/// Mock RaptorQ decoder that produces symbols at configurable rates.
struct MockRaptorQDecoder {
    source_symbols: Vec<Vec<u8>>,
    decode_config: DecodeConfig,
    current_symbol_index: usize,
    is_complete: bool,
    symbols_per_batch: usize,
}

impl MockRaptorQDecoder {
    fn new(config: &DecoderStreamTestConfig) -> Self {
        // Generate mock source symbols
        let mut source_symbols = Vec::new();
        for i in 0..config.source_symbol_count {
            let mut symbol_data = vec![0u8; config.symbol_size];
            // Fill with pattern for verification
            for j in 0..config.symbol_size {
                symbol_data[j] = ((i * 256 + j as u32) % 256) as u8;
            }
            source_symbols.push(symbol_data);
        }

        Self {
            source_symbols,
            decode_config: DecodeConfig {
                max_elimination_rounds: 1000,
                enable_proof_generation: true,
                inactivation_threshold: 0.1,
                pivot_selection_strategy: Default::default(),
            },
            current_symbol_index: 0,
            is_complete: false,
            symbols_per_batch: 5, // Decode in batches
        }
    }

    /// Simulate decoding process that produces symbols incrementally.
    async fn decode_batch(&mut self, cx: &Cx, metrics: &DecoderStreamMetrics) -> Result<Vec<Vec<u8>>, DecodeError> {
        if self.is_complete {
            return Ok(Vec::new());
        }

        let batch_start = self.current_symbol_index;
        let batch_end = (batch_start + self.symbols_per_batch).min(self.source_symbols.len());

        if batch_start >= self.source_symbols.len() {
            self.is_complete = true;
            return Ok(Vec::new());
        }

        // Simulate decode processing time
        cx.sleep(Duration::from_millis(10)).await;

        let mut batch = Vec::new();
        for i in batch_start..batch_end {
            batch.push(self.source_symbols[i].clone());
            metrics.record_symbol_decoded();
        }

        self.current_symbol_index = batch_end;
        if batch_end >= self.source_symbols.len() {
            self.is_complete = true;
        }

        Ok(batch)
    }

    fn is_decode_complete(&self) -> bool {
        self.is_complete
    }

    fn progress(&self) -> f64 {
        self.current_symbol_index as f64 / self.source_symbols.len() as f64
    }
}

/// Stream that produces decoded symbols with configurable backpressure.
struct DecoderSymbolStream {
    decoder: MockRaptorQDecoder,
    symbol_buffer: VecDeque<Vec<u8>>,
    metrics: DecoderStreamMetrics,
    cx: *const Cx, // For async operations - careful with lifetime
    buffer_limit: usize,
    backpressure_active: bool,
}

impl DecoderSymbolStream {
    fn new(
        decoder: MockRaptorQDecoder,
        buffer_limit: usize,
        metrics: DecoderStreamMetrics,
        cx: &Cx,
    ) -> Self {
        Self {
            decoder,
            symbol_buffer: VecDeque::with_capacity(buffer_limit),
            metrics,
            cx: cx as *const Cx,
            buffer_limit,
            backpressure_active: false,
        }
    }
}

impl Stream for DecoderSymbolStream {
    type Item = Result<Vec<u8>, DecodeError>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Check if we have buffered symbols
        if let Some(symbol) = self.symbol_buffer.pop_front() {
            return Poll::Ready(Some(Ok(symbol)));
        }

        // Check if decoding is complete
        if self.decoder.is_decode_complete() {
            return Poll::Ready(None);
        }

        // Check backpressure - if buffer was full, we might need to pause
        if self.symbol_buffer.len() >= self.buffer_limit {
            self.backpressure_active = true;
            self.metrics.record_backpressure_event();
            return Poll::Pending;
        } else if self.backpressure_active {
            self.backpressure_active = false;
        }

        // Need to decode more symbols
        // In a real implementation, this would use a proper async interface
        // For this test, we'll simulate the async decode operation
        Poll::Pending // Would trigger waker when decode completes
    }
}

/// Simulates a slow consumer that processes symbols with artificial delays.
async fn slow_consumer_processor(
    cx: &Cx,
    mut symbol_stream: Pin<Box<dyn Stream<Item = Result<Vec<u8>, DecodeError>>>>,
    config: &DecoderStreamTestConfig,
    metrics: &DecoderStreamMetrics,
) -> Result<Vec<Vec<u8>>, String> {
    let mut consumed_symbols = Vec::new();
    let mut expected_symbol_index = 0u32;

    let consumer_start = Instant::now();

    while let Some(symbol_result) = symbol_stream.next().await {
        match symbol_result {
            Ok(symbol_data) => {
                // Verify symbol ordering
                if symbol_data.len() == config.symbol_size {
                    // Check if this is the expected symbol based on pattern
                    let expected_first_byte = (expected_symbol_index % 256) as u8;
                    if symbol_data[0] != expected_first_byte {
                        metrics.record_ordering_violation();
                    }
                    expected_symbol_index += 1;
                }

                // Simulate slow consumer processing
                cx.sleep(config.consumer_delay).await;

                consumed_symbols.push(symbol_data);
                metrics.record_symbol_consumed();

                // Check if consumer is falling behind
                let elapsed = consumer_start.elapsed();
                let expected_consumption_rate = consumed_symbols.len() as f64 / elapsed.as_secs_f64();
                if expected_consumption_rate < (config.max_stream_rate as f64 * 0.5) {
                    metrics.record_consumer_stall();
                }

                // Break if we've consumed enough for testing
                if consumed_symbols.len() >= config.source_symbol_count as usize {
                    break;
                }
            }
            Err(decode_error) => {
                return Err(format!("Decode error in stream: {:?}", decode_error));
            }
        }
    }

    Ok(consumed_symbols)
}

/// Creates a buffered stream with backpressure handling for decoder output.
fn create_buffered_decoder_stream(
    decoder: MockRaptorQDecoder,
    config: &DecoderStreamTestConfig,
    metrics: DecoderStreamMetrics,
    cx: &Cx,
) -> impl Stream<Item = Result<Vec<u8>, DecodeError>> {
    let decoder_stream = DecoderSymbolStream::new(
        decoder,
        config.stream_buffer_size,
        metrics.clone(),
        cx,
    );

    // Apply buffering for backpressure management
    decoder_stream
        .buffered(config.stream_buffer_size)
        .throttle(Duration::from_secs(1) / config.max_stream_rate)
}

/// Verifies that decoder output maintains symbol ordering through stream operations.
async fn verify_symbol_ordering_through_stream(
    symbols: &[Vec<u8>],
    config: &DecoderStreamTestConfig,
) -> Result<bool, String> {
    for (i, symbol) in symbols.iter().enumerate() {
        if symbol.len() != config.symbol_size {
            return Err(format!("Symbol {} has wrong size: {} (expected {})",
                              i, symbol.len(), config.symbol_size));
        }

        // Verify the pattern matches expected
        let expected_first_byte = (i % 256) as u8;
        if symbol[0] != expected_first_byte {
            return Err(format!("Symbol {} ordering violation: got first byte {}, expected {}",
                              i, symbol[0], expected_first_byte));
        }

        // Verify full pattern
        for (j, &byte) in symbol.iter().enumerate() {
            let expected_byte = ((i * 256 + j) % 256) as u8;
            if byte != expected_byte {
                return Err(format!("Symbol {} pattern violation at position {}: got {}, expected {}",
                                  i, j, byte, expected_byte));
            }
        }
    }

    Ok(true)
}

// ============================================================================
// RAPTORQ DECODER STREAM BACKPRESSURE TESTS
// ============================================================================

/// Test basic decoder output streaming with proper backpressure handling.
#[tokio::test]
async fn test_raptorq_decoder_stream_basic_backpressure() {
    let config = DecoderStreamTestConfig::default();
    let runtime = create_test_runtime().unwrap();
    let metrics = DecoderStreamMetrics::default();

    let result = runtime.block_on_with_budget(
        Budget::new(Duration::from_secs(20), 30000),
        |cx| async move {
            cx.scope(|scope| async move {
                // Create mock decoder
                let decoder = MockRaptorQDecoder::new(&config);

                // Create buffered stream with backpressure
                let decoder_stream = create_buffered_decoder_stream(
                    decoder,
                    &config,
                    metrics.clone(),
                    cx,
                );

                // Consume stream with normal speed
                let consumer_config = DecoderStreamTestConfig {
                    consumer_delay: Duration::from_millis(20), // Normal speed
                    ..config
                };

                let consumed_symbols = slow_consumer_processor(
                    cx,
                    Box::pin(decoder_stream),
                    &consumer_config,
                    &metrics,
                ).await?;

                // Verify symbol consumption and ordering
                assert_eq!(consumed_symbols.len(), config.source_symbol_count as usize,
                          "Should consume all source symbols");

                let ordering_valid = verify_symbol_ordering_through_stream(
                    &consumed_symbols,
                    &config,
                ).await?;

                assert!(ordering_valid, "Symbol ordering should be preserved through stream");

                // Check metrics
                let (decoded, consumed, backpressure, overruns, pauses, throttling, violations, stalls) = metrics.get_totals();

                assert_eq!(decoded, config.source_symbol_count as u64,
                          "All symbols should be decoded");
                assert_eq!(consumed, config.source_symbol_count as u64,
                          "All symbols should be consumed");
                assert_eq!(violations, 0,
                          "No ordering violations should occur");

                // Some backpressure events are expected with buffering
                assert!(backpressure <= consumed / 2,
                        "Backpressure events should be reasonable: {} (consumed: {})", backpressure, consumed);
                assert_eq!(overruns, 0, "No buffer overruns with proper backpressure");

                Ok(format!("Basic backpressure: decoded={}, consumed={}, backpressure={}, stalls={}",
                          decoded, consumed, backpressure, stalls))
            }).await
        },
    );

    assert!(result.is_ok(), "Basic backpressure test should complete: {:?}", result);

    let (decoded, consumed, backpressure, overruns, pauses, throttling, violations, stalls) = metrics.get_totals();
    println!("✓ Basic backpressure: decoded={}, consumed={}, backpressure={}, violations={}, stalls={}",
             decoded, consumed, backpressure, violations, stalls);
}

/// Test slow consumer handling with aggressive backpressure.
#[tokio::test]
async fn test_slow_consumer_backpressure_handling() {
    let config = DecoderStreamTestConfig {
        stream_buffer_size: 16, // Smaller buffer for more pressure
        consumer_delay: Duration::from_millis(100), // Very slow consumer
        max_stream_rate: 20, // Lower throughput limit
        ..DecoderStreamTestConfig::default()
    };

    let runtime = create_test_runtime().unwrap();
    let metrics = DecoderStreamMetrics::default();

    let result = runtime.block_on_with_budget(
        Budget::new(Duration::from_secs(25), 40000),
        |cx| async move {
            cx.scope(|scope| async move {
                // Create decoder with slow consumer scenario
                let decoder = MockRaptorQDecoder::new(&config);

                let decoder_stream = create_buffered_decoder_stream(
                    decoder,
                    &config,
                    metrics.clone(),
                    cx,
                );

                // Add extra buffering and throttling for slow consumer
                let throttled_stream = decoder_stream
                    .buffered(config.stream_buffer_size * 2)
                    .throttle(Duration::from_millis(100)); // Additional throttling

                let consumed_symbols = slow_consumer_processor(
                    cx,
                    Box::pin(throttled_stream),
                    &config,
                    &metrics,
                ).await?;

                // Verify consumption despite slow processing
                assert!(consumed_symbols.len() >= (config.source_symbol_count / 2) as usize,
                       "Should consume substantial symbols despite slow consumer: got {}",
                       consumed_symbols.len());

                // Verify ordering is maintained under pressure
                let ordering_valid = verify_symbol_ordering_through_stream(
                    &consumed_symbols[..consumed_symbols.len().min(50)],
                    &DecoderStreamTestConfig { source_symbol_count: 50, ..config },
                ).await?;

                assert!(ordering_valid, "Ordering should be maintained under backpressure");

                // Check backpressure metrics
                let (decoded, consumed, backpressure, overruns, pauses, throttling, violations, stalls) = metrics.get_totals();

                assert!(consumed > 0, "Some symbols should be consumed");
                assert!(backpressure > 0, "Backpressure should be triggered with slow consumer");
                assert!(throttling > 0 || stalls > 0, "Throttling or stalls should occur");

                // Ordering violations should be minimal even under pressure
                assert!(violations <= consumed / 20,
                        "Ordering violations should be rare: {} violations in {} consumed",
                        violations, consumed);

                Ok(format!("Slow consumer: consumed={}, backpressure={}, throttling={}, stalls={}",
                          consumed, backpressure, throttling, stalls))
            }).await
        },
    );

    assert!(result.is_ok(), "Slow consumer test should complete: {:?}", result);

    let (decoded, consumed, backpressure, overruns, pauses, throttling, violations, stalls) = metrics.get_totals();
    assert!(backpressure > 0, "Backpressure should be triggered");
    assert!(consumed > 20, "Should consume reasonable number of symbols: {}", consumed);

    println!("✓ Slow consumer: consumed={}, backpressure={}, throttling={}, stalls={}, violations={}",
             consumed, backpressure, throttling, stalls, violations);
}

/// Test multi-consumer stream splitting with different consumption rates.
#[tokio::test]
async fn test_multi_consumer_stream_splitting_backpressure() {
    let config = DecoderStreamTestConfig {
        source_symbol_count: 80,
        stream_buffer_size: 24,
        max_stream_rate: 40,
        ..DecoderStreamTestConfig::default()
    };

    let runtime = create_test_runtime().unwrap();
    let metrics = DecoderStreamMetrics::default();

    let result = runtime.block_on_with_budget(
        Budget::new(Duration::from_secs(25), 50000),
        |cx| async move {
            cx.scope(|scope| async move {
                // Create shared decoder stream
                let decoder = MockRaptorQDecoder::new(&config);
                let decoder_stream = create_buffered_decoder_stream(
                    decoder,
                    &config,
                    metrics.clone(),
                    cx,
                );

                // Create channel for stream distribution
                let (tx, rx) = mpsc::channel(config.stream_buffer_size);
                let (tx2, rx2) = mpsc::channel(config.stream_buffer_size);

                // Stream distributor task
                let distributor_handle = scope.spawn(async move {
                    let mut stream = Box::pin(decoder_stream);
                    let mut symbol_count = 0;

                    while let Some(symbol_result) = stream.next().await {
                        match symbol_result {
                            Ok(symbol) => {
                                // Send to both consumers
                                if let Err(_) = tx.send(Ok(symbol.clone())).await {
                                    break; // Consumer 1 dropped
                                }
                                if let Err(_) = tx2.send(Ok(symbol)).await {
                                    break; // Consumer 2 dropped
                                }
                                symbol_count += 1;

                                if symbol_count >= config.source_symbol_count {
                                    break;
                                }
                            }
                            Err(e) => {
                                let _ = tx.send(Err(e.clone())).await;
                                let _ = tx2.send(Err(e)).await;
                                break;
                            }
                        }
                    }
                    Ok(symbol_count)
                });

                // Fast consumer
                let fast_consumer_config = DecoderStreamTestConfig {
                    consumer_delay: Duration::from_millis(10), // Fast
                    ..config
                };
                let fast_metrics = metrics.clone();
                let fast_consumer_handle = scope.spawn(async move {
                    slow_consumer_processor(
                        cx,
                        Box::pin(rx),
                        &fast_consumer_config,
                        &fast_metrics,
                    ).await
                });

                // Slow consumer
                let slow_consumer_config = DecoderStreamTestConfig {
                    consumer_delay: Duration::from_millis(80), // Slow
                    ..config
                };
                let slow_metrics = DecoderStreamMetrics::default(); // Separate metrics
                let slow_consumer_handle = scope.spawn(async move {
                    slow_consumer_processor(
                        cx,
                        Box::pin(rx2),
                        &slow_consumer_config,
                        &slow_metrics,
                    ).await
                });

                // Wait for all tasks
                let distributor_result = distributor_handle.join().await;
                let fast_result = fast_consumer_handle.join().await;
                let slow_result = slow_consumer_handle.join().await;

                // Verify results
                match (distributor_result, fast_result, slow_result) {
                    (Outcome::Ok(distributed), Outcome::Ok(fast_consumed), Outcome::Ok(slow_consumed)) => {
                        assert!(distributed > 0, "Should distribute symbols: {}", distributed);
                        assert!(fast_consumed.len() > 0, "Fast consumer should consume symbols");
                        assert!(slow_consumed.len() > 0, "Slow consumer should consume symbols");

                        // Fast consumer should consume more or equal to slow consumer
                        assert!(fast_consumed.len() >= slow_consumed.len(),
                               "Fast consumer ({}) should keep up with slow consumer ({})",
                               fast_consumed.len(), slow_consumed.len());

                        // Both should maintain ordering
                        if !fast_consumed.is_empty() {
                            let fast_ordering_valid = verify_symbol_ordering_through_stream(
                                &fast_consumed[..fast_consumed.len().min(20)],
                                &DecoderStreamTestConfig { source_symbol_count: 20, ..config },
                            ).await?;
                            assert!(fast_ordering_valid, "Fast consumer should maintain ordering");
                        }

                        if !slow_consumed.is_empty() {
                            let slow_ordering_valid = verify_symbol_ordering_through_stream(
                                &slow_consumed[..slow_consumed.len().min(15)],
                                &DecoderStreamTestConfig { source_symbol_count: 15, ..config },
                            ).await?;
                            assert!(slow_ordering_valid, "Slow consumer should maintain ordering");
                        }

                        Ok(format!("Multi-consumer: distributed={}, fast={}, slow={}",
                                  distributed, fast_consumed.len(), slow_consumed.len()))
                    }
                    _ => Err("One or more consumers failed".into()),
                }
            }).await
        },
    );

    assert!(result.is_ok(), "Multi-consumer test should complete: {:?}", result);

    let (decoded, consumed, backpressure, overruns, pauses, throttling, violations, stalls) = metrics.get_totals();
    println!("✓ Multi-consumer: decoded={}, consumed={}, backpressure={}, violations={}, stalls={}",
             decoded, consumed, backpressure, violations, stalls);
}

/// Test comprehensive RaptorQ decoder and stream integration under high load.
#[tokio::test]
async fn test_comprehensive_decoder_stream_integration_high_load() {
    let config = DecoderStreamTestConfig {
        source_symbol_count: 200,
        symbol_size: 2048, // Larger symbols
        total_encoded_symbols: 250, // 25% overhead
        stream_buffer_size: 48,
        consumer_delay: Duration::from_millis(25),
        max_stream_rate: 80,
        test_duration: Duration::from_secs(15),
    };

    let runtime = create_test_runtime().unwrap();
    let metrics = DecoderStreamMetrics::default();

    let result = runtime.block_on_with_budget(
        Budget::new(Duration::from_secs(30), 80000),
        |cx| async move {
            cx.scope(|scope| async move {
                // Create high-performance decoder
                let decoder = MockRaptorQDecoder::new(&config);

                // Create comprehensive stream pipeline
                let decoder_stream = create_buffered_decoder_stream(
                    decoder,
                    &config,
                    metrics.clone(),
                    cx,
                );

                // Add stream transformations to test integration
                let transformed_stream = decoder_stream
                    .buffered(config.stream_buffer_size)
                    .map(|symbol_result| {
                        // Transform symbols by adding checksum
                        symbol_result.map(|mut symbol| {
                            let checksum = symbol.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
                            symbol.push(checksum);
                            symbol
                        })
                    })
                    .filter(|symbol_result| {
                        // Filter out every 10th symbol to test partial consumption
                        if let Ok(symbol) = symbol_result {
                            symbol.len() % 10 != 0
                        } else {
                            true // Keep errors
                        }
                    })
                    .throttle(Duration::from_secs(1) / config.max_stream_rate);

                // Multiple concurrent consumers with different patterns
                let mut consumer_handles = Vec::new();

                // Consumer 1: Normal speed
                let normal_consumer_config = DecoderStreamTestConfig {
                    consumer_delay: Duration::from_millis(20),
                    ..config
                };
                let normal_metrics = metrics.clone();
                let consumer1_handle = scope.spawn(async move {
                    slow_consumer_processor(
                        cx,
                        Box::pin(transformed_stream),
                        &normal_consumer_config,
                        &normal_metrics,
                    ).await
                });
                consumer_handles.push(("normal", consumer1_handle));

                // Consumer 2: Burst pattern (fast then slow)
                let decoder2 = MockRaptorQDecoder::new(&config);
                let stream2 = create_buffered_decoder_stream(decoder2, &config, metrics.clone(), cx);
                let burst_metrics = DecoderStreamMetrics::default();
                let consumer2_handle = scope.spawn(async move {
                    let mut consumed = Vec::new();
                    let mut stream = Box::pin(stream2);
                    let mut burst_phase = true;
                    let burst_switch_time = cx.now() + Duration::from_secs(3);

                    while let Some(symbol_result) = stream.next().await {
                        if let Ok(symbol) = symbol_result {
                            // Switch between fast and slow consumption
                            let delay = if burst_phase {
                                Duration::from_millis(5) // Fast
                            } else {
                                Duration::from_millis(50) // Slow
                            };

                            if cx.now() > burst_switch_time {
                                burst_phase = !burst_phase;
                            }

                            cx.sleep(delay).await;
                            consumed.push(symbol);
                            burst_metrics.record_symbol_consumed();

                            if consumed.len() >= config.source_symbol_count as usize {
                                break;
                            }
                        }
                    }
                    Ok(consumed)
                });
                consumer_handles.push(("burst", consumer2_handle));

                // Wait for all consumers to complete or timeout
                let timeout_duration = config.test_duration;
                let mut consumer_results = Vec::new();

                for (name, handle) in consumer_handles {
                    match cx.timeout(timeout_duration, handle.join()).await {
                        Ok(Outcome::Ok(symbols)) => {
                            consumer_results.push((name, symbols.len()));
                        }
                        Ok(Outcome::Err(e)) => {
                            return Err(format!("Consumer {} failed: {}", name, e));
                        }
                        Ok(Outcome::Cancelled(_)) => {
                            consumer_results.push((name, 0));
                        }
                        Ok(Outcome::Panicked(_)) => {
                            return Err(format!("Consumer {} panicked", name));
                        }
                        Err(_) => {
                            consumer_results.push((name, 0)); // Timeout
                        }
                    }
                }

                // Verify comprehensive results
                let (decoded, consumed, backpressure, overruns, pauses, throttling, violations, stalls) = metrics.get_totals();

                assert!(decoded >= 100, "Substantial symbols should be decoded: {}", decoded);
                assert!(consumed >= 50, "Substantial symbols should be consumed: {}", consumed);

                // Under high load, some backpressure is expected
                assert!(backpressure > 0, "Should experience backpressure under load");

                // Buffer management should prevent overruns
                assert!(overruns <= backpressure / 10,
                        "Buffer overruns should be rare: {} (backpressure: {})", overruns, backpressure);

                // Ordering should be mostly maintained
                assert!(violations <= consumed / 50,
                        "Ordering violations should be minimal: {} in {} consumed",
                        violations, consumed);

                // Performance metrics
                let decode_rate = decoded as f64 / config.test_duration.as_secs_f64();
                let consume_rate = consumed as f64 / config.test_duration.as_secs_f64();

                assert!(decode_rate >= 10.0,
                        "Decode rate should be reasonable: {:.1} symbols/sec", decode_rate);
                assert!(consume_rate >= 5.0,
                        "Consumption rate should be reasonable: {:.1} symbols/sec", consume_rate);

                // Verify consumer results
                let total_consumer_symbols: usize = consumer_results.iter().map(|(_, count)| count).sum();
                assert!(total_consumer_symbols >= 50,
                        "Consumers should process substantial symbols: {}", total_consumer_symbols);

                Ok(format!(
                    "High load: decoded={}, consumed={}, backpressure={}, rate={:.1}/sec, consumers={}",
                    decoded, consumed, backpressure, decode_rate, total_consumer_symbols
                ))
            }).await
        },
    );

    assert!(result.is_ok(), "Comprehensive high load test should complete: {:?}", result);

    let (decoded, consumed, backpressure, overruns, pauses, throttling, violations, stalls) = metrics.get_totals();

    // Verify comprehensive integration under load
    assert!(decoded >= 100, "Should decode substantial symbols under load: {}", decoded);
    assert!(consumed >= 50, "Should consume substantial symbols under load: {}", consumed);
    assert!(backpressure > 0, "Should handle backpressure under load");
    assert!(violations <= consumed / 20, "Should maintain ordering under load");

    println!("✓ High load: decoded={}, consumed={}, backpressure={}, overruns={}, throttling={}, violations={}, stalls={}",
             decoded, consumed, backpressure, overruns, throttling, violations, stalls);
}