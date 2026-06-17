//! High-level QUIC connection API (`arq-quic-epic-b0k8qo.1.6`, "A6").
//!
//! The lower `quic_native` modules expose the raw data-plane machinery: the
//! [`NativeQuicConnection`] state machine ([`connection`](super::connection)),
//! the stream reassembly + flow-control table ([`streams`](super::streams)), the
//! 1-RTT packet-protection boundary
//! ([`crate::net::atp::quic::packet_protection`]), the real UDP endpoint
//! ([`endpoint`](super::endpoint)), and the integrated event loop
//! ([`managed_endpoint`](super::managed_endpoint)). What was missing was a
//! *usable application surface* on top of those pieces — the "thin adapter
//! target" that Phase B (`transport_quic`) needs so it can issue ~5-7
//! high-level calls instead of hand-driving packet/crypto/ACK loops.
//!
//! This module provides that surface as [`QuicConnection`]: a role-aware handle
//! that drives the handshake, sends/receives RFC 9221 DATAGRAMs (A1/A2), opens
//! a bidirectional control stream as ordered reliable bytes (A3), exposes path
//! statistics (RTT / cwnd / loss) for the Phase C controller, and closes
//! gracefully.
//!
//! # Transport model (no-claim boundary)
//!
//! [`QuicConnection`] is the *production* handle: every method here is the same
//! call shape `transport_quic` and the eventual real-UDP path will use. What is
//! deliberately *deterministic / lab-only* is the in-memory transport that
//! carries bytes between two handles — [`establish_loopback`] and
//! [`pump_app_data`]. They stand in for:
//!
//! * the production [`ManagedQuicEndpoint`](super::managed_endpoint) event loop
//!   that pumps real UDP packets and timers, and
//! * the real wire-CRYPTO handshake driver + AEAD protect/unprotect that
//!   `b0k8qo.1.1` ("→ protect → UDP" remainder), the `b0k8qo.1.5` handshake
//!   driver remainder, and `b0k8qo.1.7` (real-UDP loopback e2e) still owe.
//!
//! Today receiving a `CRYPTO` frame only nudges `Idle → Handshaking`; the
//! handshake keys are advanced by explicit transition calls, so the loopback
//! helpers drive those transitions directly (matching the deterministic
//! `tests/quic_h3_e2e.rs` harness). This is honest deterministic behavior, not a
//! mock: the DATAGRAM and STREAM bytes really flow through
//! [`NativeQuicConnection::generate_frames`] →
//! [`NativeQuicConnection::process_packet_payload`]. The protect/UDP wire layer
//! is simply not interposed yet.
//!
//! # Fail-closed
//!
//! The client identity gate is preserved end to end: a client
//! [`QuicConnection`] cannot reach [`QuicConnectionState::Established`] unless
//! the application has recorded a verified server identity via
//! [`QuicConnection::record_verified_server_identity`] (which, on the production
//! path, must follow a genuine in-handshake X.509 verification — there is no
//! insecure skip-verify default, per `asupersync-7pwwwe` / `b0k8qo.1.5`).
//! [`establish_loopback`] does not bypass this: it propagates the
//! [`QuicTlsError::ServerCertificateUnverified`](super::tls::QuicTlsError)
//! fail-closed error if the client identity was not recorded first.

use crate::bytes::{Bytes, BytesMut};
use crate::cx::Cx;
use crate::net::atp::protocol::quic_frames::QuicFrame;
use std::task::{Context as TaskContext, Poll};

use super::connection::{
    NativeQuicConnection, NativeQuicConnectionConfig, NativeQuicConnectionError,
};
use super::streams::{StreamId, StreamRole};
use super::transport::{PacketNumberSpace, QuicConnectionState};

/// Opt-in stderr tracing for the high-level QUIC API, gated by `ATP_QUIC_TRACE`
/// so the production path stays silent (mirrors `connection.rs`'s `quictrace!`).
macro_rules! apitrace {
    ($($arg:tt)*) => {
        if std::env::var_os("ATP_QUIC_TRACE").is_some() {
            eprintln!("[atp-quic-api] {}", format!($($arg)*));
        }
    };
}

/// Default maximum 1-RTT packet payload budget used by the deterministic
/// loopback transport when a caller does not specify one.
///
/// A datagram frame is bounded to 1200 bytes by the connection, so this
/// comfortably carries a full datagram plus framing while still exercising the
/// multi-packet path for large stream transfers.
pub const DEFAULT_MAX_PACKET_BYTES: usize = 1350;

/// Safety cap on [`pump_until_idle`] iterations so a misbehaving queue can never
/// spin forever; far above any realistic per-direction flight.
const PUMP_ITERATION_CAP: usize = 16_384;

/// Point-in-time path statistics for the Phase C adaptive controller.
///
/// All values are read from the connection's loss-recovery / congestion-control
/// state machine; they are advisory signals, not guarantees.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct QuicPathStats {
    /// Smoothed RTT estimate in microseconds, once at least one RTT sample has
    /// been observed.
    pub smoothed_rtt_micros: Option<u64>,
    /// Most recent RTT sample in microseconds.
    pub latest_rtt_micros: Option<u64>,
    /// RTT variation in microseconds.
    pub rttvar_micros: Option<u64>,
    /// Current congestion window in bytes.
    pub congestion_window_bytes: u64,
    /// Bytes currently in flight (sent, not yet acknowledged or declared lost).
    pub bytes_in_flight: u64,
    /// Probe-timeout backoff count (a rough loss / tail-latency signal).
    pub pto_count: u32,
    /// Cumulative packets acknowledged by the recovery state.
    pub packets_acked: u64,
    /// Cumulative packets declared lost by the recovery state.
    pub packets_lost: u64,
    /// Cumulative packet loss rate over packets that reached an acked/lost
    /// recovery outcome.
    pub loss_rate: f64,
}

/// A high-level, role-aware handle over a single native QUIC connection.
///
/// This is the application-facing surface for the QUIC data plane: drive the
/// handshake, then send/receive datagrams and reliable control-stream bytes
/// without touching frames, packets, or crypto directly. See the [module
/// docs](self) for the transport model and fail-closed semantics.
#[derive(Debug)]
pub struct QuicConnection {
    inner: NativeQuicConnection,
    role: StreamRole,
    /// Monotonic 1-RTT packet number used by the deterministic loopback
    /// transport. The production path assigns packet numbers in the protect
    /// layer instead.
    next_app_pn: u64,
}

impl QuicConnection {
    fn from_config(mut config: NativeQuicConnectionConfig, role: StreamRole) -> Self {
        config.role = role;
        Self {
            inner: NativeQuicConnection::new(config),
            role,
            next_app_pn: 0,
        }
    }

    /// Construct a client-role connection handle.
    ///
    /// The `role` field of `config` is forced to [`StreamRole::Client`].
    #[must_use]
    pub fn client(config: NativeQuicConnectionConfig) -> Self {
        apitrace!("event=conn_new role=client");
        Self::from_config(config, StreamRole::Client)
    }

    /// Construct a server-role connection handle.
    ///
    /// The `role` field of `config` is forced to [`StreamRole::Server`].
    #[must_use]
    pub fn server(config: NativeQuicConnectionConfig) -> Self {
        apitrace!("event=conn_new role=server");
        Self::from_config(config, StreamRole::Server)
    }

    /// This connection's role.
    #[must_use]
    pub fn role(&self) -> StreamRole {
        self.role
    }

    /// Current transport state.
    #[must_use]
    pub fn state(&self) -> QuicConnectionState {
        self.inner.state()
    }

    /// Whether application (1-RTT) data may be sent right now (handshake is
    /// confirmed and 1-RTT keys are installed).
    #[must_use]
    pub fn can_send_app_data(&self) -> bool {
        self.inner.can_send_1rtt()
    }

    /// Borrow the underlying state machine for advanced/diagnostic use.
    #[must_use]
    pub fn inner(&self) -> &NativeQuicConnection {
        &self.inner
    }

    // -- handshake -----------------------------------------------------------

    /// Begin the handshake (`Idle → Handshaking`).
    ///
    /// # Errors
    /// Returns a [`NativeQuicConnectionError`] if `cx` is cancelled or the
    /// transport rejects the transition from its current state.
    pub fn begin_handshake(&mut self, cx: &Cx) -> Result<(), NativeQuicConnectionError> {
        apitrace!("event=begin_handshake role={:?}", self.role);
        self.inner.begin_handshake(cx)
    }

    /// Mark handshake-level keys installed.
    ///
    /// # Errors
    /// Returns a [`NativeQuicConnectionError`] if `cx` is cancelled or the TLS
    /// machine rejects installing handshake keys in its current level.
    pub fn mark_handshake_keys_available(
        &mut self,
        cx: &Cx,
    ) -> Result<(), NativeQuicConnectionError> {
        self.inner.on_handshake_keys_available(cx)
    }

    /// Mark 1-RTT application keys installed.
    ///
    /// # Errors
    /// Returns a [`NativeQuicConnectionError`] if `cx` is cancelled or the TLS
    /// machine rejects installing 1-RTT keys in its current level.
    pub fn mark_app_keys_available(&mut self, cx: &Cx) -> Result<(), NativeQuicConnectionError> {
        self.inner.on_1rtt_keys_available(cx)
    }

    /// Record that the application has verified the server's identity.
    ///
    /// This is the only way to clear the fail-closed server-identity gate on a
    /// **client** connection. On the production path it must be called only
    /// after a genuine certificate verification (chain + hostname + signature)
    /// has succeeded; there is deliberately no insecure skip-verify toggle
    /// (`asupersync-7pwwwe`). On a server connection it has no effect on the
    /// handshake — the identity gate is only consulted on the client path.
    pub fn record_verified_server_identity(&mut self) {
        apitrace!("event=server_identity_recorded role={:?}", self.role);
        self.inner.record_verified_server_identity();
    }

    /// Confirm the handshake (`Handshaking → Established`).
    ///
    /// # Errors
    /// For a client connection this fails closed with
    /// [`QuicTlsError::ServerCertificateUnverified`](super::tls::QuicTlsError)
    /// (wrapped in [`NativeQuicConnectionError::Tls`]) unless
    /// [`Self::record_verified_server_identity`] was called first. It also
    /// returns a [`NativeQuicConnectionError`] if `cx` is cancelled or the
    /// transport/TLS state is not ready to confirm.
    pub fn confirm_handshake(&mut self, cx: &Cx) -> Result<(), NativeQuicConnectionError> {
        let result = self.inner.on_handshake_confirmed(cx);
        match &result {
            Ok(()) => apitrace!("event=handshake_confirmed role={:?}", self.role),
            Err(err) => apitrace!(
                "event=handshake_confirm_failed role={:?} err={err:?}",
                self.role
            ),
        }
        result
    }

    // -- datagrams (A1 / A2) -------------------------------------------------

    /// Queue an unreliable application datagram (RFC 9221) for transmission.
    ///
    /// The handle enforces that application data may only be sent once the
    /// connection is established (1-RTT). The payload is bounded by the
    /// connection's `max_datagram_frame_size`; an oversize payload is rejected
    /// fail-closed.
    ///
    /// # Errors
    /// * [`NativeQuicConnectionError::InvalidState`] if the connection is not
    ///   yet established.
    /// * [`NativeQuicConnectionError::DatagramTooLarge`] if the encoded frame
    ///   would exceed the maximum datagram frame size.
    /// * [`NativeQuicConnectionError::Cancelled`] if `cx` is cancelled.
    pub fn send_datagram(
        &mut self,
        cx: &Cx,
        payload: Bytes,
    ) -> Result<(), NativeQuicConnectionError> {
        if !self.inner.can_send_1rtt() {
            apitrace!(
                "event=datagram_send_reject reason=not_established role={:?}",
                self.role
            );
            return Err(NativeQuicConnectionError::InvalidState(
                "send_datagram requires an established 1-RTT connection",
            ));
        }
        let len = payload.len();
        let result = self.inner.send_datagram(cx, payload);
        if result.is_ok() {
            apitrace!("event=datagram_queued role={:?} len={len}", self.role);
        }
        result
    }

    /// Pop the next received datagram payload, if any (non-blocking).
    #[must_use]
    pub fn recv_datagram(&mut self) -> Option<Bytes> {
        self.inner.recv_datagram()
    }

    /// Cx-aware poll for the next received datagram payload (no busy-poll).
    ///
    /// Returns [`Poll::Ready`] with the payload when one is buffered, observes
    /// cancellation through `cx` (returning [`Poll::Ready`] with
    /// [`NativeQuicConnectionError::Cancelled`]), and otherwise registers
    /// `task_cx`'s waker for the next datagram arrival and returns
    /// [`Poll::Pending`].
    pub fn poll_recv_datagram(
        &mut self,
        cx: &Cx,
        task_cx: &mut TaskContext<'_>,
    ) -> Poll<Result<Bytes, NativeQuicConnectionError>> {
        self.inner.poll_recv_datagram(cx, task_cx)
    }

    /// Number of received datagram payloads currently buffered.
    #[must_use]
    pub fn pending_datagram_count(&self) -> usize {
        self.inner.pending_datagram_count()
    }

    /// Total datagrams emitted onto the (loopback) wire.
    #[must_use]
    pub fn datagrams_sent(&self) -> u64 {
        self.inner.datagrams_sent()
    }

    /// Total datagrams accepted on receive (counted before any drop-oldest).
    #[must_use]
    pub fn datagrams_received(&self) -> u64 {
        self.inner.datagrams_received()
    }

    // -- control stream (A3) -------------------------------------------------

    /// Open a bidirectional control stream and return its id.
    ///
    /// # Errors
    /// Returns a [`NativeQuicConnectionError`] if `cx` is cancelled, the
    /// connection is not in a data-transfer state, or the local stream limit is
    /// exhausted.
    pub fn open_control_stream(&mut self, cx: &Cx) -> Result<StreamId, NativeQuicConnectionError> {
        let id = self.inner.open_local_bidi(cx)?;
        apitrace!(
            "event=control_stream_open role={:?} stream={}",
            self.role,
            id.0
        );
        Ok(id)
    }

    /// Queue reliable, ordered bytes (and an optional FIN) on a control stream.
    ///
    /// # Errors
    /// Returns a [`NativeQuicConnectionError`] if `cx` is cancelled, the
    /// connection is not in a data-transfer state, the stream is unknown, or the
    /// flow-control window is exhausted (a `STREAM_DATA_BLOCKED` is queued).
    pub fn write_control(
        &mut self,
        cx: &Cx,
        stream: StreamId,
        data: Bytes,
        fin: bool,
    ) -> Result<(), NativeQuicConnectionError> {
        self.inner.write_stream_bytes(cx, stream, data, fin)
    }

    /// Read contiguous reassembled bytes from a control stream (up to `max`).
    ///
    /// Returns an empty buffer when no further contiguous bytes are available
    /// yet; check [`Self::is_control_eof`] to distinguish "more later" from EOF.
    ///
    /// # Errors
    /// Returns a [`NativeQuicConnectionError`] if `cx` is cancelled, the
    /// connection is not in a stream-active state, or the stream is unknown.
    pub fn read_control(
        &mut self,
        cx: &Cx,
        stream: StreamId,
        max: usize,
    ) -> Result<Bytes, NativeQuicConnectionError> {
        self.inner.read_stream_bytes(cx, stream, max)
    }

    /// Whether the application has consumed a control stream through its FIN.
    ///
    /// # Errors
    /// Returns a [`NativeQuicConnectionError`] if the stream is unknown.
    pub fn is_control_eof(&self, stream: StreamId) -> Result<bool, NativeQuicConnectionError> {
        self.inner.is_stream_read_eof(stream)
    }

    // -- path stats (Phase C) ------------------------------------------------

    /// Snapshot of path statistics for adaptive control.
    #[must_use]
    pub fn path_stats(&self) -> QuicPathStats {
        let transport = self.inner.transport();
        let rtt = transport.rtt();
        QuicPathStats {
            smoothed_rtt_micros: rtt.smoothed_rtt_micros(),
            latest_rtt_micros: rtt.latest_rtt_micros(),
            rttvar_micros: rtt.rttvar_micros(),
            congestion_window_bytes: transport.congestion_window_bytes(),
            bytes_in_flight: transport.bytes_in_flight(),
            pto_count: transport.pto_count(),
            packets_acked: transport.packets_acked_total(),
            packets_lost: transport.packets_lost_total(),
            loss_rate: transport.packet_loss_rate(),
        }
    }

    // -- close ---------------------------------------------------------------

    /// Begin a graceful close (enter draining with an application error code).
    ///
    /// # Errors
    /// Returns a [`NativeQuicConnectionError`] if `cx` is cancelled or the
    /// transport rejects the transition.
    pub fn begin_close(
        &mut self,
        cx: &Cx,
        now_micros: u64,
        app_error_code: u64,
    ) -> Result<(), NativeQuicConnectionError> {
        apitrace!(
            "event=begin_close role={:?} code={app_error_code}",
            self.role
        );
        self.inner.begin_close(cx, now_micros, app_error_code)
    }
}

/// Drive a client + server [`QuicConnection`] pair through the handshake to
/// [`QuicConnectionState::Established`] using the deterministic in-memory
/// transport.
///
/// This is the lab/test substitute for the production event loop + real
/// wire-CRYPTO handshake driver (see the [module docs](self)). It drives the
/// key-availability transitions directly (matching `tests/quic_h3_e2e.rs`); the
/// real driver will instead advance them from exchanged CRYPTO bytes.
///
/// The fail-closed client-identity gate is preserved: the `client` must have
/// recorded a verified server identity via
/// [`QuicConnection::record_verified_server_identity`] before this call, or it
/// returns the wrapped
/// [`QuicTlsError::ServerCertificateUnverified`](super::tls::QuicTlsError).
///
/// # Errors
/// Propagates any [`NativeQuicConnectionError`] from the underlying transitions,
/// including the fail-closed identity gate.
pub fn establish_loopback(
    cx: &Cx,
    client: &mut QuicConnection,
    server: &mut QuicConnection,
) -> Result<(), NativeQuicConnectionError> {
    client.begin_handshake(cx)?;
    server.begin_handshake(cx)?;
    client.mark_handshake_keys_available(cx)?;
    server.mark_handshake_keys_available(cx)?;
    client.mark_app_keys_available(cx)?;
    server.mark_app_keys_available(cx)?;
    // Server confirms freely; client must have a recorded verified identity or
    // it fails closed here.
    server.confirm_handshake(cx)?;
    client.confirm_handshake(cx)?;
    apitrace!("event=loopback_established");
    Ok(())
}

/// Deterministic in-memory transport: drain one 1-RTT packet's worth of pending
/// application frames (control STREAM + DATAGRAM) from `from` and deliver them
/// to `to`, returning the number of frames moved.
///
/// This stands in for the production UDP send + AEAD protect/unprotect path; the
/// bytes themselves really flow through
/// [`NativeQuicConnection::generate_frames`] →
/// [`NativeQuicConnection::process_packet_payload`].
///
/// It deliberately does not record sent packets through the loss-recovery
/// machine (`on_packet_sent` / `on_ack_received`), so RTT and bytes-in-flight
/// reported by [`QuicConnection::path_stats`] stay at their initial defaults
/// under the loopback; the production event-loop path populates those signals.
///
/// # Errors
/// Returns a [`NativeQuicConnectionError`] if frame generation, encoding, or
/// payload processing fails (including `cx` cancellation).
pub fn pump_app_data(
    cx: &Cx,
    from: &mut QuicConnection,
    to: &mut QuicConnection,
    max_packet_bytes: usize,
    now_micros: u64,
) -> Result<usize, NativeQuicConnectionError> {
    let frames: Vec<QuicFrame> =
        from.inner
            .generate_frames(cx, PacketNumberSpace::ApplicationData, max_packet_bytes)?;
    if frames.is_empty() {
        return Ok(0);
    }
    let mut payload = BytesMut::new();
    for frame in &frames {
        frame.encode(&mut payload)?;
    }
    let packet_number = from.next_app_pn;
    from.next_app_pn = from.next_app_pn.saturating_add(1);
    to.inner.process_packet_payload(
        cx,
        PacketNumberSpace::ApplicationData,
        packet_number,
        &payload,
        now_micros,
    )?;
    apitrace!(
        "event=pump frames={} bytes={} pn={packet_number}",
        frames.len(),
        payload.len()
    );
    Ok(frames.len())
}

/// Repeatedly [`pump_app_data`] from `from` to `to` until `from` has no further
/// pending application frames, returning the total number of frames moved.
///
/// Bounded by [`PUMP_ITERATION_CAP`] so a stuck queue can never spin forever.
///
/// # Errors
/// Returns a [`NativeQuicConnectionError`] on the first failing pump round, or
/// [`NativeQuicConnectionError::InvalidState`] if the iteration cap is hit
/// (which would indicate a non-draining queue).
pub fn pump_until_idle(
    cx: &Cx,
    from: &mut QuicConnection,
    to: &mut QuicConnection,
    max_packet_bytes: usize,
    now_micros: u64,
) -> Result<usize, NativeQuicConnectionError> {
    let mut total = 0;
    for _ in 0..PUMP_ITERATION_CAP {
        let moved = pump_app_data(cx, from, to, max_packet_bytes, now_micros)?;
        if moved == 0 {
            return Ok(total);
        }
        total += moved;
    }
    Err(NativeQuicConnectionError::InvalidState(
        "pump_until_idle exceeded its iteration cap without draining",
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::cast_possible_truncation)]
    use super::*;

    fn test_cx() -> Cx<crate::cx::cap::All> {
        Cx::for_testing()
    }

    fn pair() -> (QuicConnection, QuicConnection) {
        // `NativeQuicConnectionConfig` is `Copy`, so each constructor copies it.
        let cfg = NativeQuicConnectionConfig::default();
        (QuicConnection::client(cfg), QuicConnection::server(cfg))
    }

    fn established_pair(cx: &Cx) -> (QuicConnection, QuicConnection) {
        let (mut client, mut server) = pair();
        client.record_verified_server_identity();
        establish_loopback(cx, &mut client, &mut server).expect("loopback establishes");
        (client, server)
    }

    #[test]
    fn loopback_reaches_established_on_both_sides() {
        let cx = test_cx();
        let (client, server) = established_pair(&cx);
        assert_eq!(client.state(), QuicConnectionState::Established);
        assert_eq!(server.state(), QuicConnectionState::Established);
        assert!(client.can_send_app_data());
        assert!(server.can_send_app_data());
        assert_eq!(client.role(), StreamRole::Client);
        assert_eq!(server.role(), StreamRole::Server);
    }

    #[test]
    fn client_handshake_fails_closed_without_verified_identity() {
        let cx = test_cx();
        let (mut client, mut server) = pair();
        // No record_verified_server_identity() -> client confirm must fail closed.
        let err = establish_loopback(&cx, &mut client, &mut server)
            .expect_err("client must fail closed without verified identity");
        assert!(
            matches!(err, NativeQuicConnectionError::Tls(_)),
            "expected a TLS fail-closed error, got {err:?}"
        );
        assert_ne!(client.state(), QuicConnectionState::Established);
    }

    #[test]
    fn datagram_roundtrip_exact_and_fifo() {
        let cx = test_cx();
        let (mut client, mut server) = established_pair(&cx);

        let payloads: [&[u8]; 3] = [b"first-symbol", b"second", b"third-datagram-payload"];
        for p in payloads {
            client
                .send_datagram(&cx, Bytes::copy_from_slice(p))
                .expect("queue datagram");
        }
        let moved = pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            1000,
        )
        .expect("pump");
        assert!(
            moved >= payloads.len(),
            "expected >= {} frames",
            payloads.len()
        );

        for expected in payloads {
            let got = server.recv_datagram().expect("a datagram arrived");
            assert_eq!(got.as_ref(), expected, "exact payload, FIFO order");
        }
        assert!(server.recv_datagram().is_none(), "no extra datagrams");
        assert_eq!(client.datagrams_sent(), payloads.len() as u64);
        assert_eq!(server.datagrams_received(), payloads.len() as u64);
    }

    #[test]
    fn datagram_send_before_established_is_rejected() {
        let cx = test_cx();
        let (mut client, _server) = pair();
        let err = client
            .send_datagram(&cx, Bytes::from_static(b"too early"))
            .expect_err("must reject before established");
        assert!(matches!(err, NativeQuicConnectionError::InvalidState(_)));
    }

    #[test]
    fn oversize_datagram_is_rejected_fail_closed() {
        let cx = test_cx();
        let (mut client, _server) = established_pair(&cx);
        let huge = Bytes::from(vec![0xABu8; 4096]);
        let err = client
            .send_datagram(&cx, huge)
            .expect_err("oversize datagram must be rejected");
        assert!(matches!(
            err,
            NativeQuicConnectionError::DatagramTooLarge { .. }
        ));
    }

    #[test]
    fn control_stream_roundtrip_multi_packet_reassembly() {
        let cx = test_cx();
        let (mut client, mut server) = established_pair(&cx);

        let stream = client
            .open_control_stream(&cx)
            .expect("open control stream");
        // A payload large enough to span several small packets.
        let body: Vec<u8> = (0..2048u32).map(|i| (i % 251) as u8).collect();
        client
            .write_control(&cx, stream, Bytes::copy_from_slice(&body), true)
            .expect("write control bytes + FIN");

        // Tiny budget forces multi-packet fragmentation across the pump.
        let moved = pump_until_idle(&cx, &mut client, &mut server, 256, 2000).expect("pump");
        assert!(
            moved > 1,
            "large payload should span multiple packets, moved {moved}"
        );

        let mut received = Vec::new();
        loop {
            let chunk = server
                .read_control(&cx, stream, 4096)
                .expect("read control");
            if chunk.is_empty() {
                break;
            }
            received.extend_from_slice(&chunk);
        }
        assert_eq!(received, body, "stream bytes reassembled in order");
        assert!(
            server.is_control_eof(stream).expect("eof query"),
            "FIN should be observed after consuming all bytes"
        );
    }

    #[test]
    fn poll_recv_datagram_pending_then_ready() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::task::Wake;

        struct CountingWaker(AtomicUsize);
        impl Wake for CountingWaker {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
            fn wake_by_ref(self: &Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let cx = test_cx();
        let (mut client, mut server) = established_pair(&cx);

        let counter = Arc::new(CountingWaker(AtomicUsize::new(0)));
        let waker = counter.clone().into();
        let mut task_cx = TaskContext::from_waker(&waker);

        // Empty queue: registers the waker, returns Pending (no busy-poll).
        assert!(matches!(
            server.poll_recv_datagram(&cx, &mut task_cx),
            Poll::Pending
        ));

        // Deliver a datagram; the registered waker must fire.
        client
            .send_datagram(&cx, Bytes::from_static(b"wakeup"))
            .expect("queue datagram");
        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            3000,
        )
        .expect("pump");
        assert!(
            counter.0.load(Ordering::SeqCst) >= 1,
            "arrival must wake the registered task"
        );

        // Now the poll resolves with the exact payload.
        match server.poll_recv_datagram(&cx, &mut task_cx) {
            Poll::Ready(Ok(got)) => assert_eq!(got.as_ref(), b"wakeup"),
            other => panic!("expected Ready(Ok), got {other:?}"),
        }
    }

    #[test]
    fn path_stats_are_exposed() {
        let cx = test_cx();
        let (client, _server) = established_pair(&cx);
        let stats = client.path_stats();
        // Congestion window has a nonzero initial value; in-flight starts at 0.
        assert!(stats.congestion_window_bytes > 0);
        assert_eq!(stats.bytes_in_flight, 0);
        assert_eq!(stats.pto_count, 0);
        assert_eq!(stats.packets_acked, 0);
        assert_eq!(stats.packets_lost, 0);
        assert_eq!(stats.loss_rate, 0.0);
    }

    #[test]
    fn graceful_close_transitions_out_of_established() {
        let cx = test_cx();
        let (mut client, _server) = established_pair(&cx);
        client.begin_close(&cx, 5000, 0).expect("begin close");
        assert_ne!(client.state(), QuicConnectionState::Established);
    }
}
