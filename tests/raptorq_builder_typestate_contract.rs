//! Runnable contract for the RaptorQ sender/receiver builder typestate (bead bd-3uox5).
//!
//! `src/raptorq/builder.rs` carries inline `#[cfg(test)]` coverage of the builder
//! error paths, but those assertions live in the lib-unittest binary, which is
//! currently un-runnable tree-wide (peer `cfg(test)` churn in the scheduler breaks
//! `cargo test --lib`). This integration crate links the library in non-test mode, so
//! the builder contract is actually executable via RCH, and it widens coverage past
//! what the inline tests assert:
//!
//!   * the **receiver** default-config and idempotence paths (inline only proves the
//!     sender side), and
//!   * **typestate-transition field preservation**: a `config` set *before* the
//!     `transport::<U>` / `source::<U>` retyping survives the type transition, and the
//!     result is independent of whether `config` is supplied before or after the
//!     transport/source — the move inside `transport<U>`/`source<U>` must carry every
//!     already-staged field into the freshly-typed builder.
//!
//! The compile-time half of the typestate (you cannot call `build()` until the
//! transport/source type implements `SymbolSink`/`SymbolStream`) is enforced by the
//! `impl<T: SymbolSink + Unpin>` / `impl<S: SymbolStream + Unpin>` bounds and belongs
//! in the trybuild compile-fail suite, not here; this file pins the *runtime* contract
//! the type bounds leave open (the `Option` is still `None` when constructed via
//! `default()` with an explicit type parameter).
//!
//! Every assertion is verifiable by construction — no external fixture needed.
//!
//! # Repro
//!
//! ```text
//! rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_asupersync_test \
//!   cargo test --test raptorq_builder_typestate_contract --features test-internals -- --nocapture
//! ```

#![allow(missing_docs)]

use asupersync::config::RaptorQConfig;
use asupersync::error::{Error, ErrorKind};
use asupersync::raptorq::{RaptorQReceiverBuilder, RaptorQSenderBuilder};
use asupersync::security::AuthenticatedSymbol;
use asupersync::transport::error::{SinkError, StreamError};
use asupersync::transport::sink::SymbolSink;
use asupersync::transport::stream::SymbolStream;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Default RaptorQ symbol size (`EncodingConfig::default`).
const DEFAULT_SYMBOL_SIZE: u16 = 256;
/// A non-default, still-valid (`>= 8`) symbol size used to make typestate field
/// preservation observable through `config()`.
const ALT_SYMBOL_SIZE: u16 = 512;

/// A `SymbolSink` that accepts and discards every symbol. Used purely as the
/// transport *type* so `RaptorQSenderBuilder::build()` is callable.
struct NoopSink;

impl SymbolSink for NoopSink {
    fn poll_send(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _symbol: AuthenticatedSymbol,
    ) -> Poll<Result<(), SinkError>> {
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

impl Unpin for NoopSink {}

/// A `SymbolStream` that immediately reports end-of-stream. Used purely as the
/// source *type* so `RaptorQReceiverBuilder::build()` is callable.
struct NoopStream;

impl SymbolStream for NoopStream {
    fn poll_next(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<AuthenticatedSymbol, StreamError>>> {
        Poll::Ready(None)
    }
}

impl Unpin for NoopStream {}

/// Asserts `result` is the builder's `InvalidEncodingParams` failure without
/// requiring the `Ok` payload to be `Debug` (the pipelines are not).
fn assert_invalid_params<T>(result: Result<T, Error>, ctx: &str) {
    let err = result
        .err()
        .unwrap_or_else(|| panic!("{ctx}: expected an error, got Ok"));
    assert_eq!(
        err.kind(),
        ErrorKind::InvalidEncodingParams,
        "{ctx}: wrong error kind"
    );
}

/// A config whose `symbol_size` is set to `size`, leaving every other field default.
fn config_with_symbol_size(size: u16) -> RaptorQConfig {
    let mut config = RaptorQConfig::default();
    config.encoding.symbol_size = size;
    config
}

#[test]
fn sender_build_without_transport_fails_closed() {
    // `default::<NoopSink>()` satisfies the `T: SymbolSink` build bound while leaving
    // `transport == None`, exercising the runtime "transport is required" guard the
    // type bound cannot catch.
    let result = RaptorQSenderBuilder::<NoopSink>::default()
        .config(RaptorQConfig::default())
        .build();
    assert_invalid_params(result, "sender missing transport");
}

#[test]
fn receiver_build_without_source_fails_closed() {
    let result = RaptorQReceiverBuilder::<NoopStream>::default()
        .config(RaptorQConfig::default())
        .build();
    assert_invalid_params(result, "receiver missing source");
}

#[test]
fn sender_build_rejects_invalid_config() {
    // symbol_size 0 is below the `>= 8` floor in RaptorQConfig::validate.
    let result = RaptorQSenderBuilder::new()
        .config(config_with_symbol_size(0))
        .transport(NoopSink)
        .build();
    assert_invalid_params(result, "sender invalid config");
}

#[test]
fn receiver_build_rejects_invalid_config() {
    let result = RaptorQReceiverBuilder::new()
        .config(config_with_symbol_size(0))
        .source(NoopStream)
        .build();
    assert_invalid_params(result, "receiver invalid config");
}

#[test]
fn sender_uses_default_config_when_unset() {
    let sender = RaptorQSenderBuilder::new()
        .transport(NoopSink)
        .build()
        .expect("default sender build");
    assert_eq!(
        sender.config().encoding.symbol_size,
        DEFAULT_SYMBOL_SIZE,
        "an unset config must fall back to RaptorQConfig::default"
    );
}

#[test]
fn receiver_uses_default_config_when_unset() {
    // Gap vs the inline suite: only the sender default-config path is covered there.
    let receiver = RaptorQReceiverBuilder::new()
        .source(NoopStream)
        .build()
        .expect("default receiver build");
    assert_eq!(
        receiver.config().encoding.symbol_size,
        DEFAULT_SYMBOL_SIZE,
        "receiver must also default its config when unset"
    );
}

#[test]
fn sender_config_survives_transport_typestate_transition_in_any_order() {
    let config = config_with_symbol_size(ALT_SYMBOL_SIZE);

    // config staged on the `<()>` builder, then carried through `transport::<NoopSink>`.
    let config_first = RaptorQSenderBuilder::new()
        .config(config.clone())
        .transport(NoopSink)
        .build()
        .expect("config-before-transport build");

    // config applied after the type already transitioned to `<NoopSink>`.
    let transport_first = RaptorQSenderBuilder::new()
        .transport(NoopSink)
        .config(config)
        .build()
        .expect("transport-before-config build");

    assert_eq!(config_first.config().encoding.symbol_size, ALT_SYMBOL_SIZE);
    assert_eq!(
        transport_first.config().encoding.symbol_size,
        ALT_SYMBOL_SIZE
    );
    assert_eq!(
        format!("{:?}", config_first.config()),
        format!("{:?}", transport_first.config()),
        "transport<U> must preserve every staged field; order must not matter"
    );
}

#[test]
fn receiver_config_survives_source_typestate_transition_in_any_order() {
    let config = config_with_symbol_size(ALT_SYMBOL_SIZE);

    let config_first = RaptorQReceiverBuilder::new()
        .config(config.clone())
        .source(NoopStream)
        .build()
        .expect("config-before-source build");

    let source_first = RaptorQReceiverBuilder::new()
        .source(NoopStream)
        .config(config)
        .build()
        .expect("source-before-config build");

    assert_eq!(config_first.config().encoding.symbol_size, ALT_SYMBOL_SIZE);
    assert_eq!(source_first.config().encoding.symbol_size, ALT_SYMBOL_SIZE);
    assert_eq!(
        format!("{:?}", config_first.config()),
        format!("{:?}", source_first.config()),
        "source<U> must preserve every staged field; order must not matter"
    );
}

#[test]
fn receiver_builds_are_idempotent_for_equal_inputs() {
    // Gap vs the inline suite: only sender idempotence is covered there.
    let config = config_with_symbol_size(ALT_SYMBOL_SIZE);

    let first = RaptorQReceiverBuilder::new()
        .config(config.clone())
        .source(NoopStream)
        .build()
        .expect("first receiver build");
    let second = RaptorQReceiverBuilder::new()
        .config(config)
        .source(NoopStream)
        .build()
        .expect("second receiver build");

    assert_eq!(
        format!("{:?}", first.config()),
        format!("{:?}", second.config()),
        "equal inputs must yield byte-identical receiver config"
    );
}
