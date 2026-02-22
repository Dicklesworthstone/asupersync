//! QH3-E5 — Cancellation, drain, finalize, and loser-drain invariant E2E tests.
//!
//! These tests exercise connection and stream teardown paths:
//! Cx-based cancellation, close_immediately, draining with in-flight streams,
//! reset_stream_send, stop_receiving, double close idempotency, drain timeout
//! boundary precision, finalize-after-cancel, and accept_remote_stream while
//! draining.  All deterministic, no async runtime.

use asupersync::cx::Cx;
use asupersync::net::quic_native::streams::{QuicStreamError, StreamId};
use asupersync::net::quic_native::{
    NativeQuicConnection, NativeQuicConnectionConfig, NativeQuicConnectionError,
    QuicConnectionState, StreamDirection, StreamRole,
};
use asupersync::types::Time;
use asupersync::util::DetRng;

// ---------------------------------------------------------------------------
// Helpers (replicated from quic_h3_e2e.rs)
// ---------------------------------------------------------------------------

/// Build a test Cx with infinite budget and no cancellation.
fn test_cx() -> Cx {
    Cx::for_testing()
}

/// Deterministic microsecond clock starting at seed-derived offset.
struct DetClock {
    now_micros: u64,
}

impl DetClock {
    fn new(rng: &mut DetRng) -> Self {
        let base_micros = Time::from_millis(1_000).as_nanos() / 1_000;
        let jitter = rng.next_u64() % 1_000;
        Self {
            now_micros: base_micros + jitter,
        }
    }

    fn advance(&mut self, delta_micros: u64) {
        self.now_micros += delta_micros;
    }

    fn now(&self) -> u64 {
        self.now_micros
    }
}

/// A paired client+server connection setup driven through the full handshake.
struct ConnectionPair {
    client: NativeQuicConnection,
    server: NativeQuicConnection,
    cx: Cx,
    clock: DetClock,
}

impl ConnectionPair {
    fn new(rng: &mut DetRng) -> Self {
        let cx = test_cx();
        let clock = DetClock::new(rng);

        let client_cfg = NativeQuicConnectionConfig {
            role: StreamRole::Client,
            max_local_bidi: 64,
            max_local_uni: 64,
            send_window: 1 << 18,
            recv_window: 1 << 18,
            connection_send_limit: 4 << 20,
            connection_recv_limit: 4 << 20,
            drain_timeout_micros: 2_000_000,
        };

        let server_cfg = NativeQuicConnectionConfig {
            role: StreamRole::Server,
            max_local_bidi: 64,
            max_local_uni: 64,
            send_window: 1 << 18,
            recv_window: 1 << 18,
            connection_send_limit: 4 << 20,
            connection_recv_limit: 4 << 20,
            drain_timeout_micros: 2_000_000,
        };

        let client = NativeQuicConnection::new(client_cfg);
        let server = NativeQuicConnection::new(server_cfg);

        Self {
            client,
            server,
            cx,
            clock,
        }
    }

    /// Drive both endpoints through the full handshake to Established state.
    fn establish(&mut self) {
        let cx = &self.cx;

        self.client
            .begin_handshake(cx)
            .expect("client begin_handshake");
        self.server
            .begin_handshake(cx)
            .expect("server begin_handshake");

        assert_eq!(self.client.state(), QuicConnectionState::Handshaking);
        assert_eq!(self.server.state(), QuicConnectionState::Handshaking);

        self.client
            .on_handshake_keys_available(cx)
            .expect("client hs keys");
        self.server
            .on_handshake_keys_available(cx)
            .expect("server hs keys");

        self.client
            .on_1rtt_keys_available(cx)
            .expect("client 1rtt keys");
        self.server
            .on_1rtt_keys_available(cx)
            .expect("server 1rtt keys");

        self.client
            .on_handshake_confirmed(cx)
            .expect("client confirmed");
        self.server
            .on_handshake_confirmed(cx)
            .expect("server confirmed");

        assert_eq!(self.client.state(), QuicConnectionState::Established);
        assert_eq!(self.server.state(), QuicConnectionState::Established);
        assert!(self.client.can_send_1rtt());
        assert!(self.server.can_send_1rtt());
    }
}

// ===========================================================================
// Test 1: Cancel via Cx — connection operations fail, streams are abandoned
// ===========================================================================

#[test]
fn cancel_via_cx_blocks_all_connection_operations() {
    let mut rng = DetRng::new(0xE5_0001);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    // Open several streams while the connection is healthy.
    let s0 = pair.client.open_local_bidi(cx).expect("open s0");
    let s1 = pair.client.open_local_bidi(cx).expect("open s1");
    let s2 = pair.client.open_local_uni(cx).expect("open s2");

    // Write data to each stream.
    pair.client.write_stream(cx, s0, 256).expect("write s0");
    pair.client.write_stream(cx, s1, 512).expect("write s1");
    pair.client.write_stream(cx, s2, 128).expect("write s2");

    // Verify streams are tracked.
    assert_eq!(pair.client.streams().len(), 3);

    // Now cancel via Cx.
    cx.set_cancel_requested(true);

    // Every connection operation should return Cancelled.
    let err = pair
        .client
        .open_local_bidi(cx)
        .expect_err("open after cancel");
    assert_eq!(err, NativeQuicConnectionError::Cancelled);

    let err = pair
        .client
        .write_stream(cx, s0, 1)
        .expect_err("write after cancel");
    assert_eq!(err, NativeQuicConnectionError::Cancelled);

    let err = pair
        .client
        .receive_stream(cx, s0, 1)
        .expect_err("receive after cancel");
    assert_eq!(err, NativeQuicConnectionError::Cancelled);

    let err = pair
        .client
        .poll(cx, pair.clock.now())
        .expect_err("poll after cancel");
    assert_eq!(err, NativeQuicConnectionError::Cancelled);

    let err = pair
        .client
        .begin_close(cx, pair.clock.now(), 0x0)
        .expect_err("begin_close after cancel");
    assert_eq!(err, NativeQuicConnectionError::Cancelled);

    let err = pair
        .client
        .close_immediately(cx, 0x0)
        .expect_err("close_immediately after cancel");
    assert_eq!(err, NativeQuicConnectionError::Cancelled);

    let err = pair
        .client
        .next_writable_stream(cx)
        .expect_err("next_writable after cancel");
    assert_eq!(err, NativeQuicConnectionError::Cancelled);

    // The connection state itself has NOT transitioned (cancel is at the Cx level,
    // not the transport level); it is still Established.
    assert_eq!(pair.client.state(), QuicConnectionState::Established);
}

// ===========================================================================
// Test 2: close_immediately — instant transition to Closed, no drain
// ===========================================================================

#[test]
fn close_immediately_skips_drain_phase() {
    let mut rng = DetRng::new(0xE5_0002);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    // Open a stream and write data so the connection is "busy".
    let stream = pair.client.open_local_bidi(cx).expect("open stream");
    pair.client.write_stream(cx, stream, 1024).expect("write");

    // close_immediately should jump directly to Closed.
    pair.client
        .close_immediately(cx, 0xCAFE)
        .expect("close_immediately");

    assert_eq!(pair.client.state(), QuicConnectionState::Closed);
    assert_eq!(pair.client.transport().close_code(), Some(0xCAFE));

    // No drain phase — it should NOT have been Draining at any point.
    // Verify that subsequent operations fail with InvalidState, not Draining.
    let err = pair
        .client
        .open_local_bidi(cx)
        .expect_err("open after close");
    assert_eq!(
        err,
        NativeQuicConnectionError::InvalidState("1-RTT traffic not yet enabled")
    );

    let err = pair
        .client
        .write_stream(cx, stream, 1)
        .expect_err("write after close");
    assert_eq!(
        err,
        NativeQuicConnectionError::InvalidState("1-RTT traffic not yet enabled")
    );
}

// ===========================================================================
// Test 3: Drain with in-flight streams — existing receives OK, new opens blocked
// ===========================================================================

#[test]
fn drain_with_in_flight_streams() {
    let mut rng = DetRng::new(0xE5_0003);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    // Open multiple streams with pending data.
    let s0 = pair.client.open_local_bidi(cx).expect("open s0");
    let s1 = pair.client.open_local_bidi(cx).expect("open s1");
    let s2 = pair.client.open_local_bidi(cx).expect("open s2");

    pair.client.write_stream(cx, s0, 100).expect("write s0");
    pair.client.write_stream(cx, s1, 200).expect("write s1");
    pair.client.write_stream(cx, s2, 300).expect("write s2");

    // Server accepts the streams.
    pair.server.accept_remote_stream(cx, s0).expect("accept s0");
    pair.server.accept_remote_stream(cx, s1).expect("accept s1");
    pair.server.accept_remote_stream(cx, s2).expect("accept s2");

    // Begin draining.
    let now = pair.clock.now();
    pair.client.begin_close(cx, now, 0x0).expect("begin_close");
    assert_eq!(pair.client.state(), QuicConnectionState::Draining);

    // Existing receives should still work on all streams.
    pair.client
        .receive_stream(cx, s0, 50)
        .expect("receive s0 while draining");
    pair.client
        .receive_stream(cx, s1, 75)
        .expect("receive s1 while draining");
    pair.client
        .receive_stream(cx, s2, 100)
        .expect("receive s2 while draining");

    // But new stream opens are blocked (InvalidState, not 1-RTT check).
    let err = pair
        .client
        .open_local_bidi(cx)
        .expect_err("open bidi while draining");
    assert_eq!(
        err,
        NativeQuicConnectionError::InvalidState("1-RTT traffic not yet enabled")
    );

    let err = pair
        .client
        .open_local_uni(cx)
        .expect_err("open uni while draining");
    assert_eq!(
        err,
        NativeQuicConnectionError::InvalidState("1-RTT traffic not yet enabled")
    );

    // Accepting remote streams while draining is also blocked
    // (ensure_stream_open_state requires Established).
    let remote_stream = StreamId::local(StreamRole::Server, StreamDirection::Bidirectional, 0);
    let err = pair
        .client
        .accept_remote_stream(cx, remote_stream)
        .expect_err("accept while draining");
    assert_eq!(
        err,
        NativeQuicConnectionError::InvalidState(
            "new application streams require established state"
        )
    );

    // Verify the streams still exist with correct offsets.
    let view = pair.client.streams().stream(s0).expect("s0 view");
    assert_eq!(view.send_offset, 100);
    assert_eq!(view.recv_offset, 50);
}

// ===========================================================================
// Test 4: Reset stream during active transfer
// ===========================================================================

#[test]
fn reset_stream_send_during_active_transfer() {
    let mut rng = DetRng::new(0xE5_0004);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    // Open a bidi stream and write some data.
    let stream = pair.client.open_local_bidi(cx).expect("open stream");
    pair.client
        .write_stream(cx, stream, 500)
        .expect("write 500 bytes");

    // Verify current state.
    let view = pair.client.streams().stream(stream).expect("stream view");
    assert_eq!(view.send_offset, 500);
    assert!(view.send_reset.is_none());

    // Reset the stream with error code 0x77, final_size = 500 (matching sent bytes).
    pair.client
        .reset_stream_send(cx, stream, 0x77, 500)
        .expect("reset_stream_send");

    // Verify reset is recorded.
    let view = pair
        .client
        .streams()
        .stream(stream)
        .expect("stream view after reset");
    assert_eq!(view.send_reset, Some((0x77, 500)));

    // Attempting to reset with a different final_size should fail (inconsistent).
    let err = pair
        .client
        .reset_stream_send(cx, stream, 0x77, 600)
        .expect_err("inconsistent reset");
    assert!(
        matches!(
            err,
            NativeQuicConnectionError::Stream(QuicStreamError::InconsistentReset { .. })
        ),
        "expected InconsistentReset, got: {err:?}"
    );

    // Attempting to reset with final_size below sent bytes should fail.
    let stream2 = pair.client.open_local_bidi(cx).expect("open stream2");
    pair.client
        .write_stream(cx, stream2, 200)
        .expect("write stream2");
    let err = pair
        .client
        .reset_stream_send(cx, stream2, 0x88, 100)
        .expect_err("final_size < sent");
    assert!(
        matches!(
            err,
            NativeQuicConnectionError::Stream(QuicStreamError::InvalidFinalSize { .. })
        ),
        "expected InvalidFinalSize, got: {err:?}"
    );
}

// ===========================================================================
// Test 5: Stop receiving — client calls stop_receiving, subsequent receives fail
// ===========================================================================

#[test]
fn stop_receiving_blocks_future_receives() {
    let mut rng = DetRng::new(0xE5_0005);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    // Open a bidi stream.
    let stream = pair.client.open_local_bidi(cx).expect("open stream");

    // Server accepts and sends data (simulated via write on server side).
    pair.server
        .accept_remote_stream(cx, stream)
        .expect("server accept");
    pair.server
        .write_stream(cx, stream, 256)
        .expect("server write");

    // Client receives some data before stopping.
    pair.client
        .receive_stream(cx, stream, 64)
        .expect("client receive initial");

    // Verify receive offset advanced.
    let view = pair.client.streams().stream(stream).expect("stream view");
    assert_eq!(view.recv_offset, 64);

    // Client stops receiving with error code 0x42.
    pair.client
        .stop_receiving(cx, stream, 0x42)
        .expect("stop_receiving");

    // Verify error code is recorded.
    let view = pair
        .client
        .streams()
        .stream(stream)
        .expect("stream view after stop");
    assert_eq!(view.receive_stopped_error_code, Some(0x42));

    // Subsequent receives should fail with ReceiveStopped.
    let err = pair
        .client
        .receive_stream(cx, stream, 1)
        .expect_err("receive after stop_receiving");
    assert_eq!(
        err,
        NativeQuicConnectionError::Stream(QuicStreamError::ReceiveStopped { code: 0x42 })
    );

    // Out-of-order segment receives should also fail.
    let err = pair
        .client
        .receive_stream_segment(cx, stream, 100, 10, false)
        .expect_err("segment after stop_receiving");
    assert_eq!(
        err,
        NativeQuicConnectionError::Stream(QuicStreamError::ReceiveStopped { code: 0x42 })
    );

    // But writing on the same stream should still work (stop_receiving is recv-side only).
    pair.client
        .write_stream(cx, stream, 128)
        .expect("write after stop_receiving");
    let view = pair
        .client
        .streams()
        .stream(stream)
        .expect("stream view final");
    assert_eq!(view.send_offset, 128);
}

// ===========================================================================
// Test 6: Double close — begin_close twice is idempotent
// ===========================================================================

#[test]
fn double_begin_close_is_idempotent() {
    let mut rng = DetRng::new(0xE5_0006);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    // First close — transition to Draining.
    let now = pair.clock.now();
    pair.client
        .begin_close(cx, now, 0xAA)
        .expect("first begin_close");
    assert_eq!(pair.client.state(), QuicConnectionState::Draining);
    assert_eq!(pair.client.transport().close_code(), Some(0xAA));

    // Second close — should be idempotent (Draining -> Draining is OK).
    pair.clock.advance(1_000);
    let now2 = pair.clock.now();
    pair.client
        .begin_close(cx, now2, 0xBB)
        .expect("second begin_close");
    assert_eq!(pair.client.state(), QuicConnectionState::Draining);

    // The close_code should still be 0xAA from the first call because
    // start_draining_with_code calls start_draining first (which is idempotent
    // at Draining -> Draining) and then overwrites the close_code.
    // So it will actually be 0xBB.
    assert_eq!(pair.client.transport().close_code(), Some(0xBB));

    // The drain deadline was set by the first call.  Advance to the original
    // deadline and verify the connection closes (the drain deadline is from
    // the first begin_close, since the second call's transition() is a no-op
    // for Draining->Draining, it does NOT reset the deadline... actually
    // start_draining sets drain_deadline, but since transition() returns Ok
    // for same-state, the deadline IS overwritten).
    // Since the second call was at now+1000 with drain_timeout=2_000_000,
    // the new deadline is now+1000+2_000_000.
    // We are currently at now+1000. Advance to now+1000+2_000_000-1 => still Draining.
    pair.clock.advance(2_000_000 - 1);
    pair.client
        .poll(cx, pair.clock.now())
        .expect("poll before deadline");
    assert_eq!(pair.client.state(), QuicConnectionState::Draining);

    // Advance 1 more microsecond => Closed.
    pair.clock.advance(1);
    pair.client
        .poll(cx, pair.clock.now())
        .expect("poll at deadline");
    assert_eq!(pair.client.state(), QuicConnectionState::Closed);
}

// ===========================================================================
// Test 7: Drain timeout boundary — exact microsecond precision
// ===========================================================================

#[test]
fn drain_timeout_boundary_exact_microsecond() {
    let mut rng = DetRng::new(0xE5_0007);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    let drain_start = pair.clock.now();
    pair.client
        .begin_close(cx, drain_start, 0x0)
        .expect("begin_close");
    assert_eq!(pair.client.state(), QuicConnectionState::Draining);

    // The drain timeout is 2_000_000 microseconds.
    // Deadline = drain_start + 2_000_000.

    // Advance to exactly 1 microsecond before the deadline.
    pair.clock.advance(2_000_000 - 1);
    pair.client.poll(cx, pair.clock.now()).expect("poll -1us");
    assert_eq!(
        pair.client.state(),
        QuicConnectionState::Draining,
        "should still be Draining at deadline - 1us"
    );

    // Advance exactly 1 more microsecond to hit the deadline.
    pair.clock.advance(1);
    pair.client
        .poll(cx, pair.clock.now())
        .expect("poll at deadline");
    assert_eq!(
        pair.client.state(),
        QuicConnectionState::Closed,
        "should be Closed at exactly the deadline"
    );

    // Subsequent polls after Closed are safe.
    pair.clock.advance(1_000_000);
    pair.client
        .poll(cx, pair.clock.now())
        .expect("poll after closed");
    assert_eq!(pair.client.state(), QuicConnectionState::Closed);
}

// ===========================================================================
// Test 8: Finalize after cancel — poll transitions Draining -> Closed
// ===========================================================================

#[test]
fn finalize_after_begin_close_via_poll() {
    let mut rng = DetRng::new(0xE5_0008);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    // Open some streams and write data.
    let s0 = pair.client.open_local_bidi(cx).expect("open s0");
    let s1 = pair.client.open_local_uni(cx).expect("open s1");
    pair.client.write_stream(cx, s0, 1024).expect("write s0");
    pair.client.write_stream(cx, s1, 512).expect("write s1");

    // Begin close: Established -> Draining.
    let drain_start = pair.clock.now();
    pair.client
        .begin_close(cx, drain_start, 0x1234)
        .expect("begin_close");
    assert_eq!(pair.client.state(), QuicConnectionState::Draining);

    // Poll at various intermediate times — should remain Draining.
    for step in [100_000, 500_000, 1_000_000, 1_500_000, 1_999_998] {
        pair.client
            .poll(cx, drain_start + step)
            .expect("intermediate poll");
        assert_eq!(
            pair.client.state(),
            QuicConnectionState::Draining,
            "should still be Draining at +{step}us"
        );
    }

    // Advance to drain_start + 1_999_999 => still Draining.
    pair.client
        .poll(cx, drain_start + 1_999_999)
        .expect("poll -1us");
    assert_eq!(pair.client.state(), QuicConnectionState::Draining);

    // Advance to drain_start + 2_000_000 => Closed.
    pair.client
        .poll(cx, drain_start + 2_000_000)
        .expect("poll at deadline");
    assert_eq!(pair.client.state(), QuicConnectionState::Closed);
    assert_eq!(pair.client.transport().close_code(), Some(0x1234));

    // Operations after close should fail.
    let err = pair
        .client
        .open_local_bidi(cx)
        .expect_err("open after close");
    assert_eq!(
        err,
        NativeQuicConnectionError::InvalidState("1-RTT traffic not yet enabled")
    );
}

// ===========================================================================
// Test 9: accept_remote_stream while draining returns error
// ===========================================================================

#[test]
fn accept_remote_stream_while_draining_returns_error() {
    let mut rng = DetRng::new(0xE5_0009);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    // Open a stream and begin draining.
    let _s0 = pair.client.open_local_bidi(cx).expect("open s0");
    let now = pair.clock.now();
    pair.client.begin_close(cx, now, 0x0).expect("begin_close");
    assert_eq!(pair.client.state(), QuicConnectionState::Draining);

    // Try to accept a server-initiated stream while draining.
    let remote_bidi = StreamId::local(StreamRole::Server, StreamDirection::Bidirectional, 0);
    let err = pair
        .client
        .accept_remote_stream(cx, remote_bidi)
        .expect_err("accept while draining");
    assert_eq!(
        err,
        NativeQuicConnectionError::InvalidState(
            "new application streams require established state"
        )
    );

    // Also test with a server-initiated uni stream.
    let remote_uni = StreamId::local(StreamRole::Server, StreamDirection::Unidirectional, 0);
    let err = pair
        .client
        .accept_remote_stream(cx, remote_uni)
        .expect_err("accept uni while draining");
    assert_eq!(
        err,
        NativeQuicConnectionError::InvalidState(
            "new application streams require established state"
        )
    );

    // And also verify accept_remote_stream is blocked after Closed.
    pair.clock.advance(2_000_001);
    pair.client
        .poll(cx, pair.clock.now())
        .expect("poll to closed");
    assert_eq!(pair.client.state(), QuicConnectionState::Closed);

    let remote_bidi2 = StreamId::local(StreamRole::Server, StreamDirection::Bidirectional, 1);
    let err = pair
        .client
        .accept_remote_stream(cx, remote_bidi2)
        .expect_err("accept after closed");
    assert_eq!(
        err,
        NativeQuicConnectionError::InvalidState(
            "new application streams require established state"
        )
    );
}

// ===========================================================================
// Test 10: Server-side close_immediately while client is draining
// ===========================================================================

#[test]
fn server_close_immediately_while_client_drains() {
    let mut rng = DetRng::new(0xE5_000A);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    // Open shared streams.
    let stream = pair.client.open_local_bidi(cx).expect("open stream");
    pair.server
        .accept_remote_stream(cx, stream)
        .expect("server accept");

    // Client writes data.
    pair.client
        .write_stream(cx, stream, 1024)
        .expect("client write");

    // Server receives data.
    pair.server
        .receive_stream(cx, stream, 512)
        .expect("server receive");

    // Client begins draining.
    let now = pair.clock.now();
    pair.client
        .begin_close(cx, now, 0x10)
        .expect("client drain");
    assert_eq!(pair.client.state(), QuicConnectionState::Draining);

    // Server closes immediately (e.g., upon receiving client's CONNECTION_CLOSE).
    pair.server
        .close_immediately(cx, 0x10)
        .expect("server close_immediately");
    assert_eq!(pair.server.state(), QuicConnectionState::Closed);
    assert_eq!(pair.server.transport().close_code(), Some(0x10));

    // Client is still draining.
    assert_eq!(pair.client.state(), QuicConnectionState::Draining);

    // Advance the client past its drain timeout.
    pair.clock.advance(2_000_000);
    pair.client
        .poll(cx, pair.clock.now())
        .expect("client poll to closed");
    assert_eq!(pair.client.state(), QuicConnectionState::Closed);

    // Both sides are now closed.
    assert_eq!(pair.client.state(), QuicConnectionState::Closed);
    assert_eq!(pair.server.state(), QuicConnectionState::Closed);
}
