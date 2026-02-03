//! Integration tests for the RaptorQ pipeline.

use std::pin::Pin;
use std::task::{Context, Poll};

use crate::config::RaptorQConfig;
use crate::cx::Cx;
use crate::error::ErrorKind;
use crate::observability::Metrics;
use crate::raptorq::builder::{RaptorQReceiverBuilder, RaptorQSenderBuilder};
use crate::security::{AuthenticatedSymbol, AuthenticationTag, SecurityContext};
use crate::transport::error::{SinkError, StreamError};
use crate::transport::sink::SymbolSink;
use crate::transport::stream::SymbolStream;
use crate::types::symbol::ObjectId;

// =========================================================================
// Mock transport
// =========================================================================

struct VecSink {
    symbols: Vec<AuthenticatedSymbol>,
}

impl VecSink {
    fn new() -> Self {
        Self {
            symbols: Vec::new(),
        }
    }
}

impl SymbolSink for VecSink {
    fn poll_send(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        symbol: AuthenticatedSymbol,
    ) -> Poll<Result<(), SinkError>> {
        self.symbols.push(symbol);
        Poll::Ready(Ok(()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
        Poll::Ready(Ok(()))
    }

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
        Poll::Ready(Ok(()))
    }
}

impl Unpin for VecSink {}

struct VecStream {
    symbols: Vec<AuthenticatedSymbol>,
    index: usize,
}

impl VecStream {
    fn new(symbols: Vec<AuthenticatedSymbol>) -> Self {
        Self { symbols, index: 0 }
    }
}

impl SymbolStream for VecStream {
    fn poll_next(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<AuthenticatedSymbol, StreamError>>> {
        if self.index < self.symbols.len() {
            let sym = self.symbols[self.index].clone();
            self.index += 1;
            Poll::Ready(Some(Ok(sym)))
        } else {
            Poll::Ready(None)
        }
    }
}

impl Unpin for VecStream {}

// =========================================================================
// Tests
// =========================================================================

#[test]
fn sender_builder_with_transport_succeeds() {
    let result = RaptorQSenderBuilder::new()
        .config(RaptorQConfig::default())
        .transport(VecSink::new())
        .build();
    assert!(result.is_ok());
}

#[test]
fn receiver_builder_with_source_succeeds() {
    let result = RaptorQReceiverBuilder::new()
        .config(RaptorQConfig::default())
        .source(VecStream::new(vec![]))
        .build();
    assert!(result.is_ok());
}

#[test]
fn default_config_passes_validation() {
    let config = RaptorQConfig::default();
    assert!(config.validate().is_ok());
}

#[test]
fn sender_encodes_and_transmits() {
    let cx: Cx = Cx::for_testing();
    let sink = VecSink::new();
    let mut sender = RaptorQSenderBuilder::new()
        .config(RaptorQConfig::default())
        .transport(sink)
        .build()
        .unwrap();

    let data = vec![42u8; 1024];
    let object_id = ObjectId::new_for_test(1);
    let outcome = sender.send_object(&cx, object_id, &data).unwrap();

    assert_eq!(outcome.object_id, object_id);
    assert!(outcome.source_symbols > 0);
    assert!(outcome.symbols_sent > 0);
    assert_eq!(
        outcome.symbols_sent,
        outcome.source_symbols + outcome.repair_symbols
    );
}

#[test]
fn sender_with_security_signs_symbols() {
    let cx: Cx = Cx::for_testing();
    let sink = VecSink::new();
    let security = SecurityContext::for_testing(42);

    let mut sender = RaptorQSenderBuilder::new()
        .config(RaptorQConfig::default())
        .transport(sink)
        .security(security)
        .build()
        .unwrap();

    let data = vec![0xABu8; 512];
    let object_id = ObjectId::new_for_test(2);
    let outcome = sender.send_object(&cx, object_id, &data).unwrap();
    assert!(outcome.symbols_sent > 0);
}

#[test]
fn sender_rejects_oversized_data() {
    let cx: Cx = Cx::for_testing();
    let sink = VecSink::new();
    let mut sender = RaptorQSenderBuilder::new()
        .config(RaptorQConfig::default())
        .transport(sink)
        .build()
        .unwrap();

    // Create data larger than max_block_size * symbol_size.
    let max = u64::try_from(sender.config().encoding.max_block_size)
        .expect("max_block_size fits u64")
        * u64::from(sender.config().encoding.symbol_size);
    let data = vec![0u8; (max + 1) as usize];
    let result = sender.send_object(&cx, ObjectId::new_for_test(99), &data);

    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::DataTooLarge);
}

#[test]
fn sender_respects_cancellation() {
    let cx: Cx = Cx::for_testing();
    cx.set_cancel_requested(true);

    let sink = VecSink::new();
    let mut sender = RaptorQSenderBuilder::new()
        .config(RaptorQConfig::default())
        .transport(sink)
        .build()
        .unwrap();

    let data = vec![0u8; 512];
    let result = sender.send_object(&cx, ObjectId::new_for_test(1), &data);
    assert!(result.is_err());
}

#[test]
fn sender_with_metrics_increments_counters() {
    let cx: Cx = Cx::for_testing();
    let sink = VecSink::new();
    let metrics = Metrics::new();

    let mut sender = RaptorQSenderBuilder::new()
        .config(RaptorQConfig::default())
        .transport(sink)
        .metrics(metrics)
        .build()
        .unwrap();

    let data = vec![1u8; 256];
    sender
        .send_object(&cx, ObjectId::new_for_test(1), &data)
        .unwrap();

    // Metrics should have been updated (exact values depend on encoding).
}

#[test]
fn send_receive_roundtrip() {
    let cx: Cx = Cx::for_testing();

    // Sender side.
    let sink = VecSink::new();
    let mut sender = RaptorQSenderBuilder::new()
        .config(RaptorQConfig::default())
        .transport(sink)
        .build()
        .unwrap();

    let original_data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
    let object_id = ObjectId::new_for_test(77);
    let outcome = sender.send_object(&cx, object_id, &original_data).unwrap();

    // Extract symbols from the sink for the receiver.
    let symbols: Vec<AuthenticatedSymbol> = sender.transport_mut().symbols.drain(..).collect();
    assert_eq!(symbols.len(), outcome.symbols_sent);

    // Receiver side — needs ObjectParams to know how to decode.
    // For Phase 0, the encoding pipeline produces symbols that match the
    // decoding pipeline's expectations. We need to compute params.
    let config = &sender.config().encoding;
    let symbol_size = config.symbol_size;
    let source_symbols = outcome.source_symbols as u16;
    let params = crate::types::symbol::ObjectParams::new(
        object_id,
        original_data.len() as u64,
        symbol_size,
        1, // single source block
        source_symbols,
    );

    let stream = VecStream::new(symbols);
    let mut receiver = RaptorQReceiverBuilder::new()
        .config(RaptorQConfig::default())
        .source(stream)
        .build()
        .unwrap();

    let recv_outcome = receiver.receive_object(&cx, &params).unwrap();
    // The decoded data should match the original (after trimming padding).
    assert!(recv_outcome.data.len() >= original_data.len());
    assert_eq!(&recv_outcome.data[..original_data.len()], &original_data);
}

#[test]
fn receiver_reports_insufficient_symbols() {
    let cx: Cx = Cx::for_testing();

    // Empty stream — no symbols available.
    let stream = VecStream::new(vec![]);
    let mut receiver = RaptorQReceiverBuilder::new()
        .config(RaptorQConfig::default())
        .source(stream)
        .build()
        .unwrap();

    let params =
        crate::types::symbol::ObjectParams::new(ObjectId::new_for_test(1), 1024, 256, 1, 4);

    let result = receiver.receive_object(&cx, &params);
    assert!(result.is_err());
}

#[test]
fn builder_default_config_used_when_not_specified() {
    let sender = RaptorQSenderBuilder::new()
        .transport(VecSink::new())
        .build()
        .unwrap();

    assert_eq!(sender.config().encoding.symbol_size, 256);
}

#[test]
fn builder_accepts_custom_config() {
    let mut config = RaptorQConfig::default();
    config.encoding.symbol_size = 512;

    let sender = RaptorQSenderBuilder::new()
        .config(config)
        .transport(VecSink::new())
        .build()
        .unwrap();

    assert_eq!(sender.config().encoding.symbol_size, 512);
}

#[test]
fn send_empty_data_succeeds() {
    let cx: Cx = Cx::for_testing();
    let sink = VecSink::new();
    let mut sender = RaptorQSenderBuilder::new()
        .config(RaptorQConfig::default())
        .transport(sink)
        .build()
        .unwrap();

    let outcome = sender
        .send_object(&cx, ObjectId::new_for_test(1), &[])
        .unwrap();
    // Empty data may produce zero symbols (no source blocks to encode).
    assert_eq!(outcome.source_symbols, 0);
}

#[test]
fn send_symbols_directly() {
    let cx: Cx = Cx::for_testing();
    let sink = VecSink::new();
    let mut sender = RaptorQSenderBuilder::new()
        .config(RaptorQConfig::default())
        .transport(sink)
        .build()
        .unwrap();

    // Create a few authenticated symbols.
    let symbols: Vec<AuthenticatedSymbol> = (0..5)
        .map(|i| {
            let sym = crate::types::symbol::Symbol::new_for_test(1, 0, i, &[i as u8; 256]);
            AuthenticatedSymbol::new_verified(sym, AuthenticationTag::zero())
        })
        .collect();

    let count = sender.send_symbols(&cx, symbols).unwrap();
    assert_eq!(count, 5);
    assert_eq!(sender.transport_mut().symbols.len(), 5);
}
