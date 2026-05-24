//! BR-E2E-85: Real RaptorQ Encoding ↔ RaptorQ Decoding Integration E2E Tests
//!
//! This module provides comprehensive integration tests between the RaptorQ encoding
//! and decoding subsystems. The tests verify that large objects encoded with systematic
//! blocks decode correctly when receivers get repair symbols out-of-order and with
//! synthetic packet loss.
//!
//! # Integration Focus
//!
//! Tests the coordination between:
//! - `raptorq::encoding` - RaptorQ encoding with systematic block generation
//! - `raptorq::decoding` - RaptorQ decoding with out-of-order symbol recovery
//!
//! # Key Scenarios
//!
//! - Large object encoding with systematic blocks
//! - Out-of-order repair symbol delivery and recovery
//! - Synthetic packet loss simulation and recovery
//! - Decoder state management under lossy conditions
//! - Symbol reordering and reconstruction validation

use crate::{
    cx::{Cx, Scope},
    error::Outcome,
    raptorq::{
        decoding::{
            Decoder, DecoderConfig, DecoderStats, DecodingEvent, SymbolReceiver,
        },
        encoding::{
            Encoder, EncoderConfig, EncodingEvent, EncodingParams, SymbolGenerator,
        },
        gf256::Gf256,
        rfc6330::{ObjectTransmissionInformation, SourceBlockNumber, Symbol, SymbolId},
        systematic::SystematicIndex,
        ObjectId, PayloadId, RepairSymbol, SourceSymbol,
    },
    runtime::RuntimeBuilder,
    sync::{Barrier, Mutex},
    time::{Duration, Sleep},
    types::{Budget, TaskId},
    util::{
        det_rng::{DetRng, RngSeed},
        entropy::EntropySource,
    },
};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
};

/// Tracks symbol delivery and reconstruction events during lossy transmission
#[derive(Debug, Clone)]
struct SymbolDeliveryTracker {
    /// Source symbols delivered in-order
    source_symbols_delivered: Arc<AtomicU64>,
    /// Repair symbols delivered out-of-order
    repair_symbols_delivered: Arc<AtomicU64>,
    /// Symbols lost due to synthetic loss
    symbols_lost: Arc<AtomicU64>,
    /// Symbols received out-of-order
    symbols_reordered: Arc<AtomicU64>,
    /// Successful object reconstructions
    objects_reconstructed: Arc<AtomicU64>,
    /// Reconstruction failures
    reconstruction_failures: Arc<AtomicU64>,
    /// Symbol delivery timeline for verification
    delivery_timeline: Arc<Mutex<Vec<(SymbolId, std::time::Instant, bool)>>>,
}

impl SymbolDeliveryTracker {
    fn new() -> Self {
        Self {
            source_symbols_delivered: Arc::new(AtomicU64::new(0)),
            repair_symbols_delivered: Arc::new(AtomicU64::new(0)),
            symbols_lost: Arc::new(AtomicU64::new(0)),
            symbols_reordered: Arc::new(AtomicU64::new(0)),
            objects_reconstructed: Arc::new(AtomicU64::new(0)),
            reconstruction_failures: Arc::new(AtomicU64::new(0)),
            delivery_timeline: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn record_source_symbol_delivered(&self) {
        self.source_symbols_delivered.fetch_add(1, Ordering::Relaxed);
    }

    fn record_repair_symbol_delivered(&self) {
        self.repair_symbols_delivered.fetch_add(1, Ordering::Relaxed);
    }

    fn record_symbol_lost(&self) {
        self.symbols_lost.fetch_add(1, Ordering::Relaxed);
    }

    fn record_symbol_reordered(&self) {
        self.symbols_reordered.fetch_add(1, Ordering::Relaxed);
    }

    fn record_object_reconstructed(&self) {
        self.objects_reconstructed.fetch_add(1, Ordering::Relaxed);
    }

    fn record_reconstruction_failure(&self) {
        self.reconstruction_failures.fetch_add(1, Ordering::Relaxed);
    }

    async fn record_symbol_delivery(
        &self,
        cx: &Cx,
        symbol_id: SymbolId,
        is_repair: bool,
    ) {
        let mut timeline = self.delivery_timeline.lock(cx).await;
        timeline.push((symbol_id, std::time::Instant::now(), is_repair));
    }

    fn verify_lossy_recovery(&self) -> bool {
        let lost = self.symbols_lost.load(Ordering::Relaxed);
        let reconstructed = self.objects_reconstructed.load(Ordering::Relaxed);
        let failures = self.reconstruction_failures.load(Ordering::Relaxed);

        // Should have recovered despite losses
        lost > 0 && reconstructed > 0 && failures == 0
    }

    fn verify_out_of_order_handling(&self) -> bool {
        let reordered = self.symbols_reordered.load(Ordering::Relaxed);
        let repair_delivered = self.repair_symbols_delivered.load(Ordering::Relaxed);

        // Should have handled out-of-order symbols
        reordered > 0 && repair_delivered > 0
    }
}

/// Simulates lossy, out-of-order network delivery of RaptorQ symbols
struct LossySymbolChannel {
    /// Loss probability (0.0 = no loss, 1.0 = total loss)
    loss_rate: f64,
    /// Out-of-order delivery probability
    reorder_rate: f64,
    /// Maximum reorder delay in symbol positions
    max_reorder_delay: usize,
    /// Symbol buffer for reordering
    reorder_buffer: Arc<Mutex<VecDeque<(SymbolId, Vec<u8>, bool)>>>,
    /// Random number generator for loss simulation
    rng: Arc<Mutex<DetRng>>,
    /// Delivery tracking
    delivery_tracker: SymbolDeliveryTracker,
}

impl LossySymbolChannel {
    fn new(
        loss_rate: f64,
        reorder_rate: f64,
        max_reorder_delay: usize,
        seed: RngSeed,
        delivery_tracker: SymbolDeliveryTracker,
    ) -> Self {
        Self {
            loss_rate,
            reorder_rate,
            max_reorder_delay,
            reorder_buffer: Arc::new(Mutex::new(VecDeque::new())),
            rng: Arc::new(Mutex::new(DetRng::from_seed(seed))),
            delivery_tracker,
        }
    }

    async fn transmit_symbol(
        &self,
        cx: &Cx,
        symbol_id: SymbolId,
        symbol_data: Vec<u8>,
        is_repair: bool,
    ) -> Option<(SymbolId, Vec<u8>)> {
        let mut rng = self.rng.lock(cx).await;

        // Simulate loss
        if rng.gen_range(0.0..1.0) < self.loss_rate {
            self.delivery_tracker.record_symbol_lost();
            return None;
        }

        // Simulate reordering
        if rng.gen_range(0.0..1.0) < self.reorder_rate {
            self.delivery_tracker.record_symbol_reordered();

            let mut buffer = self.reorder_buffer.lock(cx).await;
            buffer.push_back((symbol_id, symbol_data, is_repair));

            // Limit buffer size
            if buffer.len() > self.max_reorder_delay {
                if let Some((id, data, is_repair_buffered)) = buffer.pop_front() {
                    self.delivery_tracker
                        .record_symbol_delivery(cx, id, is_repair_buffered)
                        .await;

                    if is_repair_buffered {
                        self.delivery_tracker.record_repair_symbol_delivered();
                    } else {
                        self.delivery_tracker.record_source_symbol_delivered();
                    }

                    return Some((id, data));
                }
            }

            return None; // Symbol buffered for reordering
        }

        // Deliver symbol immediately
        self.delivery_tracker
            .record_symbol_delivery(cx, symbol_id, is_repair)
            .await;

        if is_repair {
            self.delivery_tracker.record_repair_symbol_delivered();
        } else {
            self.delivery_tracker.record_source_symbol_delivered();
        }

        Some((symbol_id, symbol_data))
    }

    async fn flush_reorder_buffer(
        &self,
        cx: &Cx,
    ) -> Vec<(SymbolId, Vec<u8>)> {
        let mut buffer = self.reorder_buffer.lock(cx).await;
        let mut flushed = Vec::new();

        while let Some((symbol_id, symbol_data, is_repair)) = buffer.pop_front() {
            self.delivery_tracker
                .record_symbol_delivery(cx, symbol_id, is_repair)
                .await;

            if is_repair {
                self.delivery_tracker.record_repair_symbol_delivered();
            } else {
                self.delivery_tracker.record_source_symbol_delivered();
            }

            flushed.push((symbol_id, symbol_data));
        }

        flushed
    }
}

/// Large object generator for RaptorQ encoding tests
struct LargeObjectGenerator {
    /// Object size in bytes
    size: usize,
    /// Content pattern for verification
    pattern: Vec<u8>,
    /// Object identifier
    object_id: ObjectId,
}

impl LargeObjectGenerator {
    fn new(size: usize, object_id: ObjectId) -> Self {
        // Generate deterministic pattern for verification
        let pattern: Vec<u8> = (0..256).map(|i| i as u8).collect();

        Self {
            size,
            pattern,
            object_id,
        }
    }

    fn generate_object(&self) -> Vec<u8> {
        let mut object_data = Vec::with_capacity(self.size);

        for i in 0..self.size {
            object_data.push(self.pattern[i % self.pattern.len()]);
        }

        object_data
    }

    fn verify_object(&self, decoded_data: &[u8]) -> bool {
        if decoded_data.len() != self.size {
            return false;
        }

        for (i, &byte) in decoded_data.iter().enumerate() {
            if byte != self.pattern[i % self.pattern.len()] {
                return false;
            }
        }

        true
    }
}

/// Comprehensive integration test for RaptorQ encoding and decoding under lossy conditions
#[tokio::test]
async fn test_raptorq_encoding_decoding_lossy_out_of_order() -> Outcome<()> {
    let runtime = RuntimeBuilder::new()
        .with_deterministic_execution(false)
        .build()
        .await?;

    runtime
        .run(async move |cx| {
            let scope = cx.scope("raptorq_encoding_decoding_integration").await?;

            scope
                .run(async move |cx| {
                    // Initialize tracking
                    let delivery_tracker = SymbolDeliveryTracker::new();

                    // Generate large test object (1MB)
                    let object_size = 1024 * 1024; // 1MB
                    let object_id = ObjectId::new(42);
                    let object_generator = LargeObjectGenerator::new(object_size, object_id);
                    let original_data = object_generator.generate_object();

                    // Configure encoding parameters for systematic blocks
                    let encoding_params = EncodingParams {
                        symbol_size: 1400, // MTU-friendly symbol size
                        systematic_threshold: 0.8, // 80% systematic symbols
                        repair_overhead: 0.3, // 30% repair overhead
                    };

                    let encoder_config = EncoderConfig {
                        params: encoding_params,
                        max_source_symbols: 8192,
                        max_repair_symbols: 2048,
                        enable_systematic_index: true,
                    };

                    // Configure decoder
                    let decoder_config = DecoderConfig {
                        max_source_symbols: 8192,
                        max_repair_symbols: 2048,
                        symbol_timeout: Duration::from_secs(10),
                        enable_early_reconstruction: true,
                    };

                    // Create encoder and decoder
                    let encoder = Encoder::new(encoder_config);
                    let mut decoder = Decoder::new(decoder_config);

                    // Set up lossy channel with out-of-order delivery
                    let lossy_channel = LossySymbolChannel::new(
                        0.15, // 15% loss rate
                        0.4,  // 40% out-of-order rate
                        20,   // Max 20 symbol reorder delay
                        RngSeed::new(12345),
                        delivery_tracker.clone(),
                    );

                    // Phase 1: Encode the large object
                    let encoding_result = encoder.encode(cx, object_id, &original_data).await?;

                    let transmission_info = encoding_result.transmission_info();
                    let source_symbols = encoding_result.source_symbols();
                    let repair_symbols = encoding_result.repair_symbols();

                    assert!(
                        source_symbols.len() > 0,
                        "Encoder should generate source symbols"
                    );
                    assert!(
                        repair_symbols.len() > 0,
                        "Encoder should generate repair symbols"
                    );

                    // Verify systematic index is properly set
                    let systematic_symbols = source_symbols
                        .iter()
                        .filter(|symbol| symbol.is_systematic())
                        .count();

                    assert!(
                        systematic_symbols as f64 / source_symbols.len() as f64 >= 0.7,
                        "Should have high proportion of systematic symbols"
                    );

                    // Phase 2: Initialize decoder with transmission info
                    decoder.initialize(cx, transmission_info).await?;

                    // Phase 3: Transmit source symbols through lossy channel
                    let mut delivered_symbols = 0;
                    let total_source_symbols = source_symbols.len();

                    for (i, source_symbol) in source_symbols.iter().enumerate() {
                        let symbol_data = source_symbol.data().to_vec();
                        let symbol_id = source_symbol.id();

                        if let Some((delivered_id, delivered_data)) = lossy_channel
                            .transmit_symbol(cx, symbol_id, symbol_data, false)
                            .await
                        {
                            match decoder
                                .receive_source_symbol(cx, delivered_id, delivered_data)
                                .await
                            {
                                Ok(_) => delivered_symbols += 1,
                                Err(e) => {
                                    eprintln!("Failed to receive source symbol {}: {}", i, e);
                                }
                            }
                        }

                        // Add small delay to simulate network timing
                        if i % 10 == 0 {
                            Sleep::new(Duration::from_micros(100)).await;
                        }
                    }

                    // Phase 4: Check if reconstruction is possible with source symbols only
                    let initial_stats = decoder.stats().await;
                    let needs_repair = initial_stats.missing_symbols > 0;

                    println!(
                        "After source symbols: delivered={}, missing={}",
                        delivered_symbols, initial_stats.missing_symbols
                    );

                    // Phase 5: Transmit repair symbols if needed (out-of-order)
                    if needs_repair {
                        // Shuffle repair symbol order to simulate out-of-order delivery
                        let mut repair_order: Vec<usize> = (0..repair_symbols.len()).collect();
                        let mut rng_seed = RngSeed::new(54321);
                        let mut rng = DetRng::from_seed(rng_seed);

                        // Fisher-Yates shuffle
                        for i in (1..repair_order.len()).rev() {
                            let j = rng.gen_range(0..=i);
                            repair_order.swap(i, j);
                        }

                        for &repair_idx in &repair_order {
                            let repair_symbol = &repair_symbols[repair_idx];
                            let symbol_data = repair_symbol.data().to_vec();
                            let symbol_id = repair_symbol.id();

                            if let Some((delivered_id, delivered_data)) = lossy_channel
                                .transmit_symbol(cx, symbol_id, symbol_data, true)
                                .await
                            {
                                match decoder
                                    .receive_repair_symbol(cx, delivered_id, delivered_data)
                                    .await
                                {
                                    Ok(DecodingEvent::ObjectReconstructed) => {
                                        delivery_tracker.record_object_reconstructed();
                                        break;
                                    }
                                    Ok(DecodingEvent::SymbolReceived) => {
                                        // Continue receiving symbols
                                    }
                                    Err(e) => {
                                        eprintln!(
                                            "Failed to receive repair symbol {}: {}",
                                            repair_idx, e
                                        );
                                    }
                                }
                            }

                            // Check reconstruction status periodically
                            if repair_idx % 10 == 0 {
                                let current_stats = decoder.stats().await;
                                if current_stats.is_complete {
                                    delivery_tracker.record_object_reconstructed();
                                    break;
                                }

                                Sleep::new(Duration::from_micros(50)).await;
                            }
                        }
                    }

                    // Phase 6: Flush any remaining symbols from reorder buffer
                    let flushed_symbols = lossy_channel.flush_reorder_buffer(cx).await;
                    for (symbol_id, symbol_data) in flushed_symbols {
                        let _ = decoder
                            .receive_repair_symbol(cx, symbol_id, symbol_data)
                            .await;
                    }

                    // Phase 7: Attempt object reconstruction
                    let final_stats = decoder.stats().await;
                    if !final_stats.is_complete {
                        delivery_tracker.record_reconstruction_failure();
                        return Err("Decoder failed to reconstruct object".into());
                    }

                    let reconstructed_data = decoder.reconstruct_object(cx).await?;

                    // Phase 8: Verification
                    assert!(
                        object_generator.verify_object(&reconstructed_data),
                        "Reconstructed object does not match original"
                    );

                    assert_eq!(
                        reconstructed_data.len(),
                        original_data.len(),
                        "Reconstructed object size mismatch"
                    );

                    assert_eq!(
                        reconstructed_data,
                        original_data,
                        "Reconstructed object content mismatch"
                    );

                    // Verify integration behavior
                    assert!(
                        delivery_tracker.verify_lossy_recovery(),
                        "Should have recovered despite packet loss"
                    );

                    assert!(
                        delivery_tracker.verify_out_of_order_handling(),
                        "Should have handled out-of-order symbol delivery"
                    );

                    // Verify stats
                    assert!(
                        final_stats.symbols_received > 0,
                        "Decoder should have received symbols"
                    );

                    assert!(
                        final_stats.repair_symbols_used > 0 || !needs_repair,
                        "Should use repair symbols if source symbols were insufficient"
                    );

                    println!(
                        "Integration test completed successfully: {} symbols received, {} repair symbols used",
                        final_stats.symbols_received, final_stats.repair_symbols_used
                    );

                    Ok(())
                })
                .await
        })
        .await
}

/// Test RaptorQ encoding/decoding with extreme loss conditions
#[tokio::test]
async fn test_raptorq_extreme_loss_recovery() -> Outcome<()> {
    let runtime = RuntimeBuilder::new()
        .with_deterministic_execution(false)
        .build()
        .await?;

    runtime
        .run(async move |cx| {
            let scope = cx.scope("raptorq_extreme_loss_recovery").await?;

            scope
                .run(async move |cx| {
                    let delivery_tracker = SymbolDeliveryTracker::new();

                    // Smaller object for extreme loss test
                    let object_size = 64 * 1024; // 64KB
                    let object_id = ObjectId::new(123);
                    let object_generator = LargeObjectGenerator::new(object_size, object_id);
                    let original_data = object_generator.generate_object();

                    // Configure for high repair overhead
                    let encoding_params = EncodingParams {
                        symbol_size: 1024,
                        systematic_threshold: 0.6, // Lower systematic ratio
                        repair_overhead: 0.8, // High repair overhead for extreme loss
                    };

                    let encoder_config = EncoderConfig {
                        params: encoding_params,
                        max_source_symbols: 1024,
                        max_repair_symbols: 1024,
                        enable_systematic_index: true,
                    };

                    let decoder_config = DecoderConfig {
                        max_source_symbols: 1024,
                        max_repair_symbols: 1024,
                        symbol_timeout: Duration::from_secs(5),
                        enable_early_reconstruction: true,
                    };

                    let encoder = Encoder::new(encoder_config);
                    let mut decoder = Decoder::new(decoder_config);

                    // Extreme loss channel (50% loss, high reorder)
                    let lossy_channel = LossySymbolChannel::new(
                        0.5,  // 50% loss rate
                        0.7,  // 70% out-of-order rate
                        50,   // High reorder delay
                        RngSeed::new(99999),
                        delivery_tracker.clone(),
                    );

                    // Encode object
                    let encoding_result = encoder.encode(cx, object_id, &original_data).await?;

                    decoder
                        .initialize(cx, encoding_result.transmission_info())
                        .await?;

                    // Transmit all symbols through extreme loss channel
                    let mut total_transmitted = 0;
                    let mut reconstruction_achieved = false;

                    // Source symbols first
                    for source_symbol in encoding_result.source_symbols() {
                        if let Some((symbol_id, symbol_data)) = lossy_channel
                            .transmit_symbol(cx, source_symbol.id(), source_symbol.data().to_vec(), false)
                            .await
                        {
                            total_transmitted += 1;
                            let _ = decoder.receive_source_symbol(cx, symbol_id, symbol_data).await;

                            let stats = decoder.stats().await;
                            if stats.is_complete {
                                reconstruction_achieved = true;
                                delivery_tracker.record_object_reconstructed();
                                break;
                            }
                        }
                    }

                    // Repair symbols if still needed
                    if !reconstruction_achieved {
                        for repair_symbol in encoding_result.repair_symbols() {
                            if let Some((symbol_id, symbol_data)) = lossy_channel
                                .transmit_symbol(cx, repair_symbol.id(), repair_symbol.data().to_vec(), true)
                                .await
                            {
                                total_transmitted += 1;
                                match decoder.receive_repair_symbol(cx, symbol_id, symbol_data).await {
                                    Ok(DecodingEvent::ObjectReconstructed) => {
                                        reconstruction_achieved = true;
                                        delivery_tracker.record_object_reconstructed();
                                        break;
                                    }
                                    Ok(DecodingEvent::SymbolReceived) => {
                                        // Continue
                                    }
                                    Err(_) => {
                                        // Symbol rejected or decoder error
                                    }
                                }

                                let stats = decoder.stats().await;
                                if stats.is_complete {
                                    reconstruction_achieved = true;
                                    delivery_tracker.record_object_reconstructed();
                                    break;
                                }
                            }
                        }
                    }

                    // Flush buffer
                    let flushed_symbols = lossy_channel.flush_reorder_buffer(cx).await;
                    for (symbol_id, symbol_data) in flushed_symbols {
                        total_transmitted += 1;
                        let _ = decoder.receive_repair_symbol(cx, symbol_id, symbol_data).await;

                        let stats = decoder.stats().await;
                        if stats.is_complete {
                            reconstruction_achieved = true;
                            delivery_tracker.record_object_reconstructed();
                            break;
                        }
                    }

                    if !reconstruction_achieved {
                        delivery_tracker.record_reconstruction_failure();
                        return Err("Failed to reconstruct object under extreme loss conditions".into());
                    }

                    // Verify reconstruction
                    let reconstructed_data = decoder.reconstruct_object(cx).await?;
                    assert!(object_generator.verify_object(&reconstructed_data));

                    // Verify extreme loss recovery
                    assert!(delivery_tracker.verify_lossy_recovery());

                    println!(
                        "Extreme loss recovery successful: {} symbols transmitted, object reconstructed",
                        total_transmitted
                    );

                    Ok(())
                })
                .await
        })
        .await
}

/// Test encoding/decoding with systematic index optimization
#[tokio::test]
async fn test_raptorq_systematic_index_optimization() -> Outcome<()> {
    let runtime = RuntimeBuilder::new()
        .with_deterministic_execution(false)
        .build()
        .await?;

    runtime
        .run(async move |cx| {
            let scope = cx.scope("raptorq_systematic_optimization").await?;

            scope
                .run(async move |cx| {
                    let delivery_tracker = SymbolDeliveryTracker::new();

                    // Medium sized object
                    let object_size = 256 * 1024; // 256KB
                    let object_id = ObjectId::new(456);
                    let object_generator = LargeObjectGenerator::new(object_size, object_id);
                    let original_data = object_generator.generate_object();

                    // Configure for maximum systematic optimization
                    let encoding_params = EncodingParams {
                        symbol_size: 1200,
                        systematic_threshold: 0.95, // Very high systematic ratio
                        repair_overhead: 0.2, // Low repair overhead
                    };

                    let encoder_config = EncoderConfig {
                        params: encoding_params,
                        max_source_symbols: 2048,
                        max_repair_symbols: 512,
                        enable_systematic_index: true,
                    };

                    let decoder_config = DecoderConfig {
                        max_source_symbols: 2048,
                        max_repair_symbols: 512,
                        symbol_timeout: Duration::from_secs(3),
                        enable_early_reconstruction: true,
                    };

                    let encoder = Encoder::new(encoder_config);
                    let mut decoder = Decoder::new(decoder_config);

                    // Low loss channel to test systematic optimization
                    let lossy_channel = LossySymbolChannel::new(
                        0.05, // 5% loss rate
                        0.2,  // 20% out-of-order rate
                        10,   // Low reorder delay
                        RngSeed::new(11111),
                        delivery_tracker.clone(),
                    );

                    // Encode with systematic optimization
                    let encoding_result = encoder.encode(cx, object_id, &original_data).await?;

                    // Verify high systematic ratio
                    let source_symbols = encoding_result.source_symbols();
                    let systematic_count = source_symbols
                        .iter()
                        .filter(|symbol| symbol.is_systematic())
                        .count();

                    let systematic_ratio = systematic_count as f64 / source_symbols.len() as f64;
                    assert!(
                        systematic_ratio >= 0.9,
                        "Should achieve high systematic ratio: {}",
                        systematic_ratio
                    );

                    decoder
                        .initialize(cx, encoding_result.transmission_info())
                        .await?;

                    // Transmit systematic symbols preferentially
                    let mut reconstruction_achieved = false;

                    // Send systematic symbols first
                    for source_symbol in source_symbols.iter().filter(|s| s.is_systematic()) {
                        if let Some((symbol_id, symbol_data)) = lossy_channel
                            .transmit_symbol(cx, source_symbol.id(), source_symbol.data().to_vec(), false)
                            .await
                        {
                            let _ = decoder.receive_source_symbol(cx, symbol_id, symbol_data).await;

                            let stats = decoder.stats().await;
                            if stats.is_complete {
                                reconstruction_achieved = true;
                                delivery_tracker.record_object_reconstructed();
                                break;
                            }
                        }
                    }

                    // Send non-systematic symbols if needed
                    if !reconstruction_achieved {
                        for source_symbol in source_symbols.iter().filter(|s| !s.is_systematic()) {
                            if let Some((symbol_id, symbol_data)) = lossy_channel
                                .transmit_symbol(cx, source_symbol.id(), source_symbol.data().to_vec(), false)
                                .await
                            {
                                let _ = decoder.receive_source_symbol(cx, symbol_id, symbol_data).await;

                                let stats = decoder.stats().await;
                                if stats.is_complete {
                                    reconstruction_achieved = true;
                                    delivery_tracker.record_object_reconstructed();
                                    break;
                                }
                            }
                        }
                    }

                    if !reconstruction_achieved {
                        delivery_tracker.record_reconstruction_failure();
                        return Err("Failed to reconstruct with systematic symbols".into());
                    }

                    // Verify reconstruction
                    let reconstructed_data = decoder.reconstruct_object(cx).await?;
                    assert!(object_generator.verify_object(&reconstructed_data));

                    let final_stats = decoder.stats().await;

                    // With high systematic ratio and low loss, should need minimal repair symbols
                    assert!(
                        final_stats.repair_symbols_used <= 5,
                        "Should use minimal repair symbols with high systematic ratio"
                    );

                    println!(
                        "Systematic optimization successful: {}% systematic symbols, {} repair symbols used",
                        systematic_ratio * 100.0,
                        final_stats.repair_symbols_used
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
    fn test_symbol_delivery_tracker_creation() {
        let tracker = SymbolDeliveryTracker::new();

        // Verify initial state
        assert_eq!(tracker.source_symbols_delivered.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.repair_symbols_delivered.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.symbols_lost.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.symbols_reordered.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.objects_reconstructed.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.reconstruction_failures.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_symbol_delivery_tracking() {
        let tracker = SymbolDeliveryTracker::new();

        // Record events
        tracker.record_source_symbol_delivered();
        tracker.record_repair_symbol_delivered();
        tracker.record_symbol_lost();
        tracker.record_symbol_reordered();
        tracker.record_object_reconstructed();

        // Verify tracking
        assert_eq!(tracker.source_symbols_delivered.load(Ordering::Relaxed), 1);
        assert_eq!(tracker.repair_symbols_delivered.load(Ordering::Relaxed), 1);
        assert_eq!(tracker.symbols_lost.load(Ordering::Relaxed), 1);
        assert_eq!(tracker.symbols_reordered.load(Ordering::Relaxed), 1);
        assert_eq!(tracker.objects_reconstructed.load(Ordering::Relaxed), 1);

        // Verify verification methods
        assert!(tracker.verify_lossy_recovery());
        assert!(tracker.verify_out_of_order_handling());
    }

    #[test]
    fn test_large_object_generator() {
        let object_id = ObjectId::new(42);
        let generator = LargeObjectGenerator::new(1000, object_id);

        let object_data = generator.generate_object();
        assert_eq!(object_data.len(), 1000);

        // Verify pattern
        for (i, &byte) in object_data.iter().enumerate() {
            assert_eq!(byte, (i % 256) as u8);
        }

        // Verify verification
        assert!(generator.verify_object(&object_data));

        // Test with modified data
        let mut modified_data = object_data.clone();
        modified_data[500] = 255;
        assert!(!generator.verify_object(&modified_data));
    }

    #[test]
    fn test_lossy_recovery_verification_edge_cases() {
        let tracker = SymbolDeliveryTracker::new();

        // No losses
        tracker.record_object_reconstructed();
        assert!(!tracker.verify_lossy_recovery()); // No losses recorded

        // Losses but no reconstruction
        let tracker2 = SymbolDeliveryTracker::new();
        tracker2.record_symbol_lost();
        assert!(!tracker2.verify_lossy_recovery()); // No reconstruction

        // Proper lossy recovery
        let tracker3 = SymbolDeliveryTracker::new();
        tracker3.record_symbol_lost();
        tracker3.record_object_reconstructed();
        assert!(tracker3.verify_lossy_recovery()); // Both conditions met
    }

    #[test]
    fn test_out_of_order_handling_verification() {
        let tracker = SymbolDeliveryTracker::new();

        // No reordering
        tracker.record_repair_symbol_delivered();
        assert!(!tracker.verify_out_of_order_handling()); // No reordering

        // Reordering without repair symbols
        let tracker2 = SymbolDeliveryTracker::new();
        tracker2.record_symbol_reordered();
        assert!(!tracker2.verify_out_of_order_handling()); // No repair symbols

        // Proper out-of-order handling
        let tracker3 = SymbolDeliveryTracker::new();
        tracker3.record_symbol_reordered();
        tracker3.record_repair_symbol_delivered();
        assert!(tracker3.verify_out_of_order_handling()); // Both conditions met
    }
}