#![cfg(all(feature = "quic", not(target_arch = "wasm32")))]
//! Native QUIC public-surface integration checks.
//!
//! The old Tokio/Quinn compat archive was permanently disabled. These tests now
//! exercise the native, runtime-agnostic QUIC state-machine types exposed by
//! the core crate's `quic` feature.

use asupersync::cx::Cx;
use asupersync::net::{
    QuicConfig, QuicConnection, QuicConnectionState, QuicError, StreamDirection, StreamId,
    StreamRole,
};

#[test]
fn native_quic_public_surface_starts_idle_and_rejects_early_app_streams() {
    let cx = Cx::for_testing();
    let config = QuicConfig {
        role: StreamRole::Client,
        max_local_bidi: 2,
        max_local_uni: 1,
        send_window: 1024,
        recv_window: 2048,
        connection_send_limit: 4096,
        connection_recv_limit: 8192,
        drain_timeout_micros: 10_000,
    };
    let mut connection = QuicConnection::new(config);

    assert_eq!(connection.state(), QuicConnectionState::Idle);
    assert!(!connection.can_send_1rtt());

    let err = connection
        .open_local_bidi(&cx)
        .expect_err("application streams require 1-RTT or 0-RTT keys");
    assert!(matches!(
        err,
        QuicError::InvalidState("1-RTT traffic not yet enabled")
    ));
}

#[test]
fn native_quic_public_surface_closes_without_socket_io_or_tokio_runtime() {
    let cx = Cx::for_testing();
    let mut connection = QuicConnection::new(QuicConfig::default());

    connection
        .close_immediately(&cx, 42)
        .expect("immediate close is a pure state-machine transition");

    assert_eq!(connection.state(), QuicConnectionState::Closed);
    let err = connection
        .open_local_bidi(&cx)
        .expect_err("closed connection must reject new streams");
    assert!(matches!(
        err,
        QuicError::InvalidState("connection is closed")
    ));
}

#[test]
fn native_quic_stream_ids_preserve_rfc_low_bit_semantics() {
    let client_bidi = StreamId::local(StreamRole::Client, StreamDirection::Bidirectional, 0);
    let server_bidi = StreamId::local(StreamRole::Server, StreamDirection::Bidirectional, 0);
    let client_uni = StreamId::local(StreamRole::Client, StreamDirection::Unidirectional, 7);
    let server_uni = StreamId::local(StreamRole::Server, StreamDirection::Unidirectional, 7);

    assert_eq!(client_bidi.0, 0);
    assert_eq!(server_bidi.0, 1);
    assert_eq!(client_uni.0, (7 << 2) | 0b10);
    assert_eq!(server_uni.0, (7 << 2) | 0b11);

    assert!(client_bidi.is_local_for(StreamRole::Client));
    assert!(!client_bidi.is_local_for(StreamRole::Server));
    assert_eq!(client_bidi.direction(), StreamDirection::Bidirectional);
    assert_eq!(server_uni.direction(), StreamDirection::Unidirectional);
}
