//! Cx-integrated native QUIC connection orchestration.
//!
//! This type composes:
//! - TLS/key-phase progression (`QuicTlsMachine`)
//! - transport/loss-recovery lifecycle (`QuicTransportMachine`)
//! - stream/flow-control state (`StreamTable`)
//!
//! It intentionally stays runtime-agnostic and does not perform socket I/O.

use crate::cx::Cx;
use std::fmt;

use super::streams::{QuicStreamError, StreamId, StreamRole, StreamTable, StreamTableError};
use super::tls::{CryptoLevel, KeyUpdateEvent, QuicTlsError, QuicTlsMachine};
use super::transport::{
    AckEvent, AckRange, PacketNumberSpace, QuicConnectionState, QuicTransportMachine,
    SentPacketMeta, TransportError,
};

/// Native-connection errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeQuicConnectionError {
    /// Operation was cancelled via `Cx`.
    Cancelled,
    /// TLS/key-phase state error.
    Tls(QuicTlsError),
    /// Transport lifecycle or recovery state error.
    Transport(TransportError),
    /// Stream-table error.
    StreamTable(StreamTableError),
    /// Stream-state error.
    Stream(QuicStreamError),
    /// Congestion-control window would be exceeded.
    CongestionLimited {
        /// Requested in-flight bytes for the packet.
        requested: u64,
        /// Current bytes in flight.
        bytes_in_flight: u64,
        /// Current congestion window.
        congestion_window: u64,
    },
    /// Invalid operation for current connection state.
    InvalidState(&'static str),
}

impl fmt::Display for NativeQuicConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => write!(f, "operation cancelled"),
            Self::Tls(err) => write!(f, "{err}"),
            Self::Transport(err) => write!(f, "{err}"),
            Self::StreamTable(err) => write!(f, "{err}"),
            Self::Stream(err) => write!(f, "{err}"),
            Self::CongestionLimited {
                requested,
                bytes_in_flight,
                congestion_window,
            } => write!(
                f,
                "congestion window exceeded: requested={requested}, in_flight={bytes_in_flight}, cwnd={congestion_window}"
            ),
            Self::InvalidState(msg) => write!(f, "invalid native quic connection state: {msg}"),
        }
    }
}

impl std::error::Error for NativeQuicConnectionError {}

impl From<QuicTlsError> for NativeQuicConnectionError {
    fn from(value: QuicTlsError) -> Self {
        Self::Tls(value)
    }
}

impl From<TransportError> for NativeQuicConnectionError {
    fn from(value: TransportError) -> Self {
        Self::Transport(value)
    }
}

impl From<StreamTableError> for NativeQuicConnectionError {
    fn from(value: StreamTableError) -> Self {
        Self::StreamTable(value)
    }
}

impl From<QuicStreamError> for NativeQuicConnectionError {
    fn from(value: QuicStreamError) -> Self {
        Self::Stream(value)
    }
}

/// Configuration for a native QUIC connection state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeQuicConnectionConfig {
    /// Endpoint role for stream-ID ownership.
    pub role: StreamRole,
    /// Local bidirectional stream limit.
    pub max_local_bidi: u64,
    /// Local unidirectional stream limit.
    pub max_local_uni: u64,
    /// Per-stream send window.
    pub send_window: u64,
    /// Per-stream receive window.
    pub recv_window: u64,
    /// Connection-level send-data limit.
    pub connection_send_limit: u64,
    /// Connection-level receive-data limit.
    pub connection_recv_limit: u64,
    /// Drain timeout used by graceful close.
    pub drain_timeout_micros: u64,
}

impl Default for NativeQuicConnectionConfig {
    fn default() -> Self {
        Self {
            role: StreamRole::Client,
            max_local_bidi: 128,
            max_local_uni: 128,
            send_window: 1 << 20,
            recv_window: 1 << 20,
            connection_send_limit: 16 << 20,
            connection_recv_limit: 16 << 20,
            drain_timeout_micros: 3_000_000,
        }
    }
}

/// Cx-integrated native QUIC connection machine.
#[derive(Debug, Clone)]
pub struct NativeQuicConnection {
    tls: QuicTlsMachine,
    transport: QuicTransportMachine,
    streams: StreamTable,
    next_packet_numbers: [u64; 3],
    migration_disabled: bool,
    active_path_id: u64,
    migration_events: u64,
    drain_timeout_micros: u64,
}

impl NativeQuicConnection {
    /// Construct a new connection machine.
    #[must_use]
    pub fn new(config: NativeQuicConnectionConfig) -> Self {
        Self {
            tls: QuicTlsMachine::new(),
            transport: QuicTransportMachine::new(),
            streams: StreamTable::new_with_connection_limits(
                config.role,
                config.max_local_bidi,
                config.max_local_uni,
                config.send_window,
                config.recv_window,
                config.connection_send_limit,
                config.connection_recv_limit,
            ),
            next_packet_numbers: [0, 0, 0],
            migration_disabled: false,
            active_path_id: 0,
            migration_events: 0,
            drain_timeout_micros: config.drain_timeout_micros,
        }
    }

    /// Current transport state.
    #[must_use]
    pub fn state(&self) -> QuicConnectionState {
        self.transport.state()
    }

    /// Whether application (1-RTT) data can be sent.
    #[must_use]
    pub fn can_send_1rtt(&self) -> bool {
        self.tls.can_send_1rtt() && self.transport.state() == QuicConnectionState::Established
    }

    /// Whether 0-RTT application-data packets may be sent in current state.
    #[must_use]
    pub fn can_send_0rtt(&self) -> bool {
        self.tls.can_send_0rtt() && self.transport.state() == QuicConnectionState::Handshaking
    }

    /// Access TLS machine snapshot.
    #[must_use]
    pub fn tls(&self) -> &QuicTlsMachine {
        &self.tls
    }

    /// Access transport machine snapshot.
    #[must_use]
    pub fn transport(&self) -> &QuicTransportMachine {
        &self.transport
    }

    /// Access stream table snapshot.
    #[must_use]
    pub fn streams(&self) -> &StreamTable {
        &self.streams
    }

    /// Start handshake.
    pub fn begin_handshake(&mut self, cx: &Cx) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.transport.begin_handshake()?;
        Ok(())
    }

    /// Mark handshake keys installed.
    pub fn on_handshake_keys_available(
        &mut self,
        cx: &Cx,
    ) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.tls.on_handshake_keys_available()?;
        Ok(())
    }

    /// Mark 1-RTT keys installed.
    pub fn on_1rtt_keys_available(&mut self, cx: &Cx) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.tls.on_1rtt_keys_available()?;
        Ok(())
    }

    /// Confirm handshake and transition transport to `Established`.
    pub fn on_handshake_confirmed(&mut self, cx: &Cx) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        if self.tls.level() != CryptoLevel::OneRtt {
            return Err(NativeQuicConnectionError::Tls(
                QuicTlsError::HandshakeNotConfirmed,
            ));
        }
        self.transport.on_established()?;
        self.tls.on_handshake_confirmed()?;
        Ok(())
    }

    /// Open a local bidirectional stream.
    pub fn open_local_bidi(&mut self, cx: &Cx) -> Result<StreamId, NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.ensure_data_state()?;
        let id = self.streams.open_local_bidi()?;
        Ok(id)
    }

    /// Open a local unidirectional stream.
    pub fn open_local_uni(&mut self, cx: &Cx) -> Result<StreamId, NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.ensure_data_state()?;
        let id = self.streams.open_local_uni()?;
        Ok(id)
    }

    /// Accept a remote stream ID.
    pub fn accept_remote_stream(
        &mut self,
        cx: &Cx,
        id: StreamId,
    ) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.ensure_stream_open_state()?;
        self.streams.accept_remote_stream(id)?;
        Ok(())
    }

    /// Account bytes written to a stream.
    pub fn write_stream(
        &mut self,
        cx: &Cx,
        id: StreamId,
        len: u64,
    ) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.ensure_data_state()?;
        self.streams
            .write_stream(id, len)
            .map_err(map_stream_table_error)?;
        Ok(())
    }

    /// Account bytes received on a stream.
    pub fn receive_stream(
        &mut self,
        cx: &Cx,
        id: StreamId,
        len: u64,
    ) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.ensure_stream_active_state()?;
        self.streams
            .receive_stream(id, len)
            .map_err(map_stream_table_error)?;
        Ok(())
    }

    /// Account bytes received on a stream at an explicit offset.
    pub fn receive_stream_segment(
        &mut self,
        cx: &Cx,
        id: StreamId,
        offset: u64,
        len: u64,
        is_fin: bool,
    ) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.ensure_stream_active_state()?;
        self.streams
            .receive_stream_segment(id, offset, len, is_fin)
            .map_err(map_stream_table_error)?;
        Ok(())
    }

    /// Set stream final size.
    pub fn set_stream_final_size(
        &mut self,
        cx: &Cx,
        id: StreamId,
        final_size: u64,
    ) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.ensure_stream_active_state()?;
        self.streams
            .set_stream_final_size(id, final_size)
            .map_err(map_stream_table_error)?;
        Ok(())
    }

    /// Process peer STOP_SENDING for a local stream.
    pub fn on_stop_sending(
        &mut self,
        cx: &Cx,
        id: StreamId,
        error_code: u64,
    ) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.ensure_stream_active_state()?;
        self.streams
            .stream_mut(id)
            .map_err(map_stream_table_error)?
            .on_stop_sending(error_code);
        Ok(())
    }

    /// Locally stop receiving on a stream.
    pub fn stop_receiving(
        &mut self,
        cx: &Cx,
        id: StreamId,
        error_code: u64,
    ) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.ensure_stream_active_state()?;
        self.streams
            .stream_mut(id)
            .map_err(map_stream_table_error)?
            .stop_receiving(error_code);
        Ok(())
    }

    /// Locally reset stream send-side (`RESET_STREAM`).
    pub fn reset_stream_send(
        &mut self,
        cx: &Cx,
        id: StreamId,
        error_code: u64,
        final_size: u64,
    ) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.ensure_stream_active_state()?;
        self.streams
            .stream_mut(id)?
            .reset_send(error_code, final_size)?;
        Ok(())
    }

    /// Graceful close (enters draining).
    pub fn begin_close(
        &mut self,
        cx: &Cx,
        now_micros: u64,
        app_error_code: u64,
    ) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.transport.start_draining_with_code(
            now_micros,
            self.drain_timeout_micros,
            app_error_code,
        )?;
        Ok(())
    }

    /// Immediate terminal close.
    pub fn close_immediately(
        &mut self,
        cx: &Cx,
        app_error_code: u64,
    ) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.transport.close_immediately(app_error_code);
        Ok(())
    }

    /// Poll transport timers (drain deadline).
    pub fn poll(&mut self, cx: &Cx, now_micros: u64) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.transport.poll(now_micros);
        Ok(())
    }

    /// Enable session resumption/0-RTT mode for current handshake.
    pub fn enable_resumption_0rtt(&mut self, cx: &Cx) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.tls.enable_resumption();
        Ok(())
    }

    /// Disable session resumption/0-RTT mode.
    pub fn disable_resumption_0rtt(&mut self, cx: &Cx) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.tls.disable_resumption();
        Ok(())
    }

    /// Set active-migration policy (typically sourced from peer transport params).
    pub fn set_active_migration_disabled(
        &mut self,
        cx: &Cx,
        disabled: bool,
    ) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.migration_disabled = disabled;
        Ok(())
    }

    /// Current active path identifier.
    #[must_use]
    pub fn active_path_id(&self) -> u64 {
        self.active_path_id
    }

    /// Number of successful path migrations observed.
    #[must_use]
    pub fn migration_events(&self) -> u64 {
        self.migration_events
    }

    /// Request migration to a new path identifier.
    pub fn request_path_migration(
        &mut self,
        cx: &Cx,
        new_path_id: u64,
    ) -> Result<u64, NativeQuicConnectionError> {
        checkpoint(cx)?;
        if self.migration_disabled {
            return Err(NativeQuicConnectionError::InvalidState(
                "active migration disabled by transport parameters",
            ));
        }
        if self.transport.state() != QuicConnectionState::Established {
            return Err(NativeQuicConnectionError::InvalidState(
                "path migration requires established state",
            ));
        }
        if new_path_id == self.active_path_id {
            return Ok(self.migration_events);
        }
        self.active_path_id = new_path_id;
        self.migration_events = self.migration_events.saturating_add(1);
        Ok(self.migration_events)
    }

    /// Track a sent packet and return assigned packet number.
    pub fn on_packet_sent(
        &mut self,
        cx: &Cx,
        space: PacketNumberSpace,
        bytes: u64,
        ack_eliciting: bool,
        in_flight: bool,
        time_sent_micros: u64,
    ) -> Result<u64, NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.ensure_packet_send_state(space)?;
        if in_flight && !self.transport.can_send(bytes) {
            return Err(NativeQuicConnectionError::CongestionLimited {
                requested: bytes,
                bytes_in_flight: self.transport.bytes_in_flight(),
                congestion_window: self.transport.congestion_window_bytes(),
            });
        }
        let pn = self.next_packet_number(space)?;
        self.transport.on_packet_sent(SentPacketMeta {
            space,
            packet_number: pn,
            bytes,
            ack_eliciting,
            in_flight,
            time_sent_micros,
        });
        Ok(pn)
    }

    /// Process ACK.
    pub fn on_ack_received(
        &mut self,
        cx: &Cx,
        space: PacketNumberSpace,
        acked_packet_numbers: &[u64],
        ack_delay_micros: u64,
        now_micros: u64,
    ) -> Result<AckEvent, NativeQuicConnectionError> {
        checkpoint(cx)?;
        let event = self.transport.on_ack_received(
            space,
            acked_packet_numbers,
            ack_delay_micros,
            now_micros,
        );
        Ok(event)
    }

    /// Process ACK via explicit ranges.
    pub fn on_ack_ranges(
        &mut self,
        cx: &Cx,
        space: PacketNumberSpace,
        ack_ranges: &[AckRange],
        ack_delay_micros: u64,
        now_micros: u64,
    ) -> Result<AckEvent, NativeQuicConnectionError> {
        checkpoint(cx)?;
        Ok(self
            .transport
            .on_ack_ranges(space, ack_ranges, ack_delay_micros, now_micros))
    }

    /// Compute PTO deadline.
    pub fn pto_deadline_micros(
        &self,
        cx: &Cx,
        now_micros: u64,
    ) -> Result<Option<u64>, NativeQuicConnectionError> {
        checkpoint(cx)?;
        Ok(self.transport.pto_deadline_micros(now_micros))
    }

    /// Record PTO timeout firing (backoff).
    pub fn on_pto_expired(&mut self, cx: &Cx) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.transport.on_pto_expired();
        Ok(())
    }

    /// Request local key update.
    pub fn request_local_key_update(
        &mut self,
        cx: &Cx,
    ) -> Result<KeyUpdateEvent, NativeQuicConnectionError> {
        checkpoint(cx)?;
        let evt = self.tls.request_local_key_update()?;
        Ok(evt)
    }

    /// Commit local key update once keys are installed.
    pub fn commit_local_key_update(
        &mut self,
        cx: &Cx,
    ) -> Result<KeyUpdateEvent, NativeQuicConnectionError> {
        checkpoint(cx)?;
        let evt = self.tls.commit_local_key_update()?;
        Ok(evt)
    }

    /// Process peer key phase.
    pub fn on_peer_key_phase(
        &mut self,
        cx: &Cx,
        phase: bool,
    ) -> Result<KeyUpdateEvent, NativeQuicConnectionError> {
        checkpoint(cx)?;
        let evt = self.tls.on_peer_key_phase(phase)?;
        Ok(evt)
    }

    /// Next locally initiated stream eligible for write scheduling.
    pub fn next_writable_stream(
        &mut self,
        cx: &Cx,
    ) -> Result<Option<StreamId>, NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.ensure_data_state()?;
        Ok(self.streams.next_writable_stream())
    }

    fn ensure_data_state(&self) -> Result<(), NativeQuicConnectionError> {
        if self.transport.state() == QuicConnectionState::Closed {
            return Err(NativeQuicConnectionError::InvalidState(
                "connection is closed",
            ));
        }
        if !self.can_send_1rtt() {
            return Err(NativeQuicConnectionError::InvalidState(
                "1-RTT traffic not yet enabled",
            ));
        }
        Ok(())
    }

    fn ensure_stream_open_state(&self) -> Result<(), NativeQuicConnectionError> {
        if self.transport.state() != QuicConnectionState::Established {
            return Err(NativeQuicConnectionError::InvalidState(
                "new application streams require established state",
            ));
        }
        Ok(())
    }

    fn ensure_stream_active_state(&self) -> Result<(), NativeQuicConnectionError> {
        if matches!(
            self.transport.state(),
            QuicConnectionState::Established | QuicConnectionState::Draining
        ) {
            return Ok(());
        }
        Err(NativeQuicConnectionError::InvalidState(
            "stream operation requires established or draining state",
        ))
    }

    fn ensure_packet_send_state(
        &self,
        space: PacketNumberSpace,
    ) -> Result<(), NativeQuicConnectionError> {
        if self.transport.state() == QuicConnectionState::Closed {
            return Err(NativeQuicConnectionError::InvalidState(
                "packet send requires non-closed connection state",
            ));
        }
        if matches!(space, PacketNumberSpace::ApplicationData)
            && !self.can_send_1rtt()
            && !self.can_send_0rtt()
        {
            return Err(NativeQuicConnectionError::InvalidState(
                "application-data packets require established 1-RTT state",
            ));
        }
        Ok(())
    }

    fn next_packet_number(
        &mut self,
        space: PacketNumberSpace,
    ) -> Result<u64, NativeQuicConnectionError> {
        let idx = match space {
            PacketNumberSpace::Initial => 0,
            PacketNumberSpace::Handshake => 1,
            PacketNumberSpace::ApplicationData => 2,
        };
        let out = self.next_packet_numbers[idx];
        if out >= (1 << 62) - 1 {
            return Err(NativeQuicConnectionError::InvalidState(
                "packet number limit reached; connection must be closed",
            ));
        }
        self.next_packet_numbers[idx] = out + 1;
        Ok(out)
    }
}

fn checkpoint(cx: &Cx) -> Result<(), NativeQuicConnectionError> {
    cx.checkpoint()
        .map_err(|_| NativeQuicConnectionError::Cancelled)
}

fn map_stream_table_error(err: StreamTableError) -> NativeQuicConnectionError {
    match err {
        StreamTableError::Stream(stream_err) => NativeQuicConnectionError::Stream(stream_err),
        other => NativeQuicConnectionError::StreamTable(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Budget;
    use crate::util::ArenaIndex;
    use crate::{RegionId, TaskId};

    fn test_cx() -> Cx {
        Cx::new(
            RegionId::from_arena(ArenaIndex::new(0, 0)),
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            Budget::INFINITE,
        )
    }

    fn established_conn() -> NativeQuicConnection {
        let cx = test_cx();
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
        conn.begin_handshake(&cx).expect("begin");
        conn.on_handshake_keys_available(&cx).expect("hs keys");
        conn.on_1rtt_keys_available(&cx).expect("1rtt keys");
        conn.on_handshake_confirmed(&cx).expect("confirmed");
        conn
    }

    #[test]
    fn cannot_open_data_stream_before_1rtt_enabled() {
        let cx = test_cx();
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
        conn.begin_handshake(&cx).expect("begin");
        let err = conn.open_local_bidi(&cx).expect_err("must fail");
        assert_eq!(
            err,
            NativeQuicConnectionError::InvalidState("1-RTT traffic not yet enabled")
        );
    }

    #[test]
    fn cannot_accept_remote_stream_before_established() {
        let cx = test_cx();
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
        conn.begin_handshake(&cx).expect("begin");
        let remote = StreamId::local(
            StreamRole::Server,
            crate::net::quic_native::streams::StreamDirection::Bidirectional,
            0,
        );
        let err = conn
            .accept_remote_stream(&cx, remote)
            .expect_err("must fail before established");
        assert_eq!(
            err,
            NativeQuicConnectionError::InvalidState(
                "new application streams require established state"
            )
        );
    }

    #[test]
    fn established_connection_can_open_and_write_stream() {
        let cx = test_cx();
        let mut conn = established_conn();
        let stream = conn.open_local_bidi(&cx).expect("open");
        conn.write_stream(&cx, stream, 12).expect("write");
        conn.receive_stream(&cx, stream, 4).expect("receive");
        conn.set_stream_final_size(&cx, stream, 3)
            .expect_err("final size must not regress");
    }

    #[test]
    fn packet_numbers_increase_per_space() {
        let cx = test_cx();
        let mut conn = established_conn();
        let pn0 = conn
            .on_packet_sent(&cx, PacketNumberSpace::Initial, 1200, true, true, 10_000)
            .expect("pn0");
        let pn1 = conn
            .on_packet_sent(&cx, PacketNumberSpace::Initial, 1200, true, true, 10_100)
            .expect("pn1");
        let pn2 = conn
            .on_packet_sent(
                &cx,
                PacketNumberSpace::ApplicationData,
                1200,
                true,
                true,
                10_200,
            )
            .expect("pn2");
        assert_eq!(pn0, 0);
        assert_eq!(pn1, 1);
        assert_eq!(pn2, 0);
    }

    #[test]
    fn application_data_packets_require_established_1rtt() {
        let cx = test_cx();
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
        conn.begin_handshake(&cx).expect("begin");
        let err = conn
            .on_packet_sent(
                &cx,
                PacketNumberSpace::ApplicationData,
                1200,
                true,
                true,
                10_000,
            )
            .expect_err("appdata before 1-rtt must fail");
        assert_eq!(
            err,
            NativeQuicConnectionError::InvalidState(
                "application-data packets require established 1-RTT state"
            )
        );
    }

    #[test]
    fn packet_send_is_rejected_after_close() {
        let cx = test_cx();
        let mut conn = established_conn();
        conn.close_immediately(&cx, 0x77).expect("close");
        let err = conn
            .on_packet_sent(&cx, PacketNumberSpace::Initial, 1200, true, true, 10_000)
            .expect_err("send after close must fail");
        assert_eq!(
            err,
            NativeQuicConnectionError::InvalidState(
                "packet send requires non-closed connection state"
            )
        );
    }

    #[test]
    fn stop_sending_is_enforced_via_connection_api() {
        let cx = test_cx();
        let mut conn = established_conn();
        let stream = conn.open_local_uni(&cx).expect("open");
        conn.write_stream(&cx, stream, 4).expect("write");
        conn.on_stop_sending(&cx, stream, 77).expect("stop_sending");
        let err = conn.write_stream(&cx, stream, 1).expect_err("must fail");
        assert_eq!(
            err,
            NativeQuicConnectionError::Stream(QuicStreamError::SendStopped { code: 77 })
        );
    }

    #[test]
    fn out_of_order_receive_segment_reassembles_via_connection_api() {
        let cx = test_cx();
        let mut conn = established_conn();
        let stream = conn.open_local_bidi(&cx).expect("open");
        conn.receive_stream_segment(&cx, stream, 5, 5, false)
            .expect("out-of-order");
        assert_eq!(
            conn.streams().stream(stream).expect("stream").recv_offset,
            0
        );
        conn.receive_stream_segment(&cx, stream, 0, 5, false)
            .expect("fill gap");
        assert_eq!(
            conn.streams().stream(stream).expect("stream").recv_offset,
            10
        );
    }

    #[test]
    fn on_ack_ranges_via_connection_api() {
        let cx = test_cx();
        let mut conn = established_conn();
        conn.on_packet_sent(
            &cx,
            PacketNumberSpace::ApplicationData,
            1200,
            true,
            true,
            10_000,
        )
        .expect("sent");
        conn.on_packet_sent(
            &cx,
            PacketNumberSpace::ApplicationData,
            1200,
            true,
            true,
            10_050,
        )
        .expect("sent");
        let ranges = [AckRange::new(1, 0).expect("range")];
        let ack = conn
            .on_ack_ranges(&cx, PacketNumberSpace::ApplicationData, &ranges, 0, 20_000)
            .expect("ack");
        assert_eq!(ack.acked_packets, 2);
    }

    #[test]
    fn begin_close_records_application_error_code() {
        let cx = test_cx();
        let mut conn = established_conn();
        conn.begin_close(&cx, 50_000, 0xdead).expect("close");
        assert_eq!(conn.transport().close_code(), Some(0xdead));
    }

    #[test]
    fn receive_stream_allowed_while_draining() {
        let cx = test_cx();
        let mut conn = established_conn();
        let stream = conn.open_local_bidi(&cx).expect("open");
        conn.begin_close(&cx, 50_000, 0xdead).expect("close");
        conn.receive_stream(&cx, stream, 1)
            .expect("receive while draining");
    }

    #[test]
    fn write_is_blocked_when_congestion_window_is_full() {
        let cx = test_cx();
        let mut conn = established_conn();
        for _ in 0..20 {
            let send = conn.on_packet_sent(
                &cx,
                PacketNumberSpace::ApplicationData,
                1_200,
                true,
                true,
                10_000,
            );
            if matches!(
                send,
                Err(NativeQuicConnectionError::CongestionLimited { .. })
            ) {
                return;
            }
        }
        panic!("expected congestion to limit packet sends");
    }

    #[test]
    fn handshake_confirm_does_not_mutate_tls_if_transport_is_not_handshaking() {
        let cx = test_cx();
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
        conn.on_1rtt_keys_available(&cx).expect("1rtt keys");
        let err = conn.on_handshake_confirmed(&cx).expect_err("must fail");
        assert!(matches!(
            err,
            NativeQuicConnectionError::Transport(TransportError::InvalidStateTransition {
                from: QuicConnectionState::Idle,
                to: QuicConnectionState::Established
            })
        ));
        assert!(!conn.tls().can_send_1rtt());
    }

    // --- Gap 1: Cancellation path via Cx (Cancelled error variant) ---

    #[test]
    fn cancelled_cx_returns_cancelled_error() {
        let cx = test_cx();
        cx.set_cancel_requested(true);
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
        let err = conn.begin_handshake(&cx).expect_err("must fail");
        assert_eq!(err, NativeQuicConnectionError::Cancelled);
    }

    #[test]
    fn cancelled_cx_blocks_open_local_bidi() {
        let cx = test_cx();
        let mut conn = established_conn();
        cx.set_cancel_requested(true);
        let err = conn.open_local_bidi(&cx).expect_err("must fail");
        assert_eq!(err, NativeQuicConnectionError::Cancelled);
    }

    #[test]
    fn cancelled_cx_blocks_poll() {
        let cx = test_cx();
        let mut conn = established_conn();
        cx.set_cancel_requested(true);
        let err = conn.poll(&cx, 1_000_000).expect_err("must fail");
        assert_eq!(err, NativeQuicConnectionError::Cancelled);
    }

    // --- Gap 2: close_immediately via NativeQuicConnection wrapper ---

    #[test]
    fn close_immediately_transitions_to_closed_with_code() {
        let cx = test_cx();
        let mut conn = established_conn();
        conn.close_immediately(&cx, 0xbeef).expect("close");
        assert_eq!(conn.state(), QuicConnectionState::Closed);
        assert_eq!(conn.transport().close_code(), Some(0xbeef));
    }

    #[test]
    fn close_immediately_from_handshaking() {
        let cx = test_cx();
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
        conn.begin_handshake(&cx).expect("begin");
        conn.close_immediately(&cx, 42).expect("close");
        assert_eq!(conn.state(), QuicConnectionState::Closed);
        assert_eq!(conn.transport().close_code(), Some(42));
    }

    // --- Gap 3: poll drives drain-to-closed transition ---

    #[test]
    fn poll_drives_drain_to_closed_when_deadline_reached() {
        let cx = test_cx();
        let mut conn = established_conn();
        let drain_timeout = conn.drain_timeout_micros;
        let now = 100_000u64;
        conn.begin_close(&cx, now, 0x1234).expect("drain");
        assert_eq!(conn.state(), QuicConnectionState::Draining);

        conn.poll(&cx, now + drain_timeout - 1)
            .expect("poll before deadline");
        assert_eq!(conn.state(), QuicConnectionState::Draining);

        conn.poll(&cx, now + drain_timeout)
            .expect("poll at deadline");
        assert_eq!(conn.state(), QuicConnectionState::Closed);
    }

    #[test]
    fn poll_noop_when_not_draining() {
        let cx = test_cx();
        let mut conn = established_conn();
        conn.poll(&cx, 999_999).expect("poll");
        assert_eq!(conn.state(), QuicConnectionState::Established);
    }

    // --- Gap 4: reset_stream_send via connection API ---

    #[test]
    fn reset_stream_send_records_reset_on_stream() {
        let cx = test_cx();
        let mut conn = established_conn();
        let stream = conn.open_local_bidi(&cx).expect("open");
        conn.write_stream(&cx, stream, 10).expect("write");
        conn.reset_stream_send(&cx, stream, 0x77, 10)
            .expect("reset");
        let s = conn.streams().stream(stream).expect("stream");
        assert_eq!(s.send_reset, Some((0x77, 10)));
    }

    #[test]
    fn reset_stream_send_rejects_final_size_below_sent() {
        let cx = test_cx();
        let mut conn = established_conn();
        let stream = conn.open_local_bidi(&cx).expect("open");
        conn.write_stream(&cx, stream, 20).expect("write");
        let err = conn
            .reset_stream_send(&cx, stream, 0x01, 5)
            .expect_err("must fail");
        assert!(matches!(
            err,
            NativeQuicConnectionError::Stream(QuicStreamError::InvalidFinalSize { .. })
        ));
    }

    // --- Gap 5: stop_receiving via connection API ---

    #[test]
    fn stop_receiving_blocks_subsequent_receives() {
        let cx = test_cx();
        let mut conn = established_conn();
        let stream = conn.open_local_bidi(&cx).expect("open");
        conn.stop_receiving(&cx, stream, 0x42)
            .expect("stop_receiving");
        let err = conn
            .receive_stream(&cx, stream, 1)
            .expect_err("must fail after stop_receiving");
        assert_eq!(
            err,
            NativeQuicConnectionError::Stream(QuicStreamError::ReceiveStopped { code: 0x42 })
        );
    }

    #[test]
    fn stop_receiving_records_error_code() {
        let cx = test_cx();
        let mut conn = established_conn();
        let stream = conn.open_local_bidi(&cx).expect("open");
        conn.stop_receiving(&cx, stream, 99).expect("stop");
        let s = conn.streams().stream(stream).expect("stream");
        assert_eq!(s.receive_stopped_error_code, Some(99));
    }

    // --- Gap 6: Key update methods via connection API ---

    #[test]
    fn request_and_commit_local_key_update() {
        let cx = test_cx();
        let mut conn = established_conn();
        let scheduled = conn.request_local_key_update(&cx).expect("request");
        assert_eq!(
            scheduled,
            KeyUpdateEvent::LocalUpdateScheduled {
                next_phase: true,
                generation: 1,
            }
        );
        let committed = conn.commit_local_key_update(&cx).expect("commit");
        assert_eq!(
            committed,
            KeyUpdateEvent::LocalUpdateScheduled {
                next_phase: true,
                generation: 1,
            }
        );
        assert!(conn.tls().local_key_phase());
    }

    #[test]
    fn on_peer_key_phase_via_connection_api() {
        let cx = test_cx();
        let mut conn = established_conn();
        assert!(!conn.tls().remote_key_phase());
        let evt = conn.on_peer_key_phase(&cx, true).expect("peer update");
        assert_eq!(
            evt,
            KeyUpdateEvent::RemoteUpdateAccepted {
                new_phase: true,
                generation: 1,
            }
        );
        assert!(conn.tls().remote_key_phase());
    }

    #[test]
    fn duplicate_peer_key_phase_returns_no_change() {
        let cx = test_cx();
        let mut conn = established_conn();
        conn.on_peer_key_phase(&cx, true).expect("first");
        let evt = conn.on_peer_key_phase(&cx, true).expect("second same");
        assert_eq!(evt, KeyUpdateEvent::NoChange);
    }

    #[test]
    fn appdata_packets_allowed_with_0rtt_resumption() {
        let cx = test_cx();
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
        conn.begin_handshake(&cx).expect("begin");
        conn.on_handshake_keys_available(&cx)
            .expect("handshake keys");
        conn.enable_resumption_0rtt(&cx).expect("enable 0-rtt");

        assert!(conn.can_send_0rtt());
        let pn = conn
            .on_packet_sent(
                &cx,
                PacketNumberSpace::ApplicationData,
                1200,
                true,
                true,
                10_000,
            )
            .expect("0-rtt appdata send");
        assert_eq!(pn, 0);
    }

    #[test]
    fn path_migration_requires_established_state() {
        let cx = test_cx();
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
        conn.begin_handshake(&cx).expect("begin");
        let err = conn
            .request_path_migration(&cx, 7)
            .expect_err("must fail while handshaking");
        assert_eq!(
            err,
            NativeQuicConnectionError::InvalidState("path migration requires established state")
        );
    }

    #[test]
    fn path_migration_is_blocked_when_disabled() {
        let cx = test_cx();
        let mut conn = established_conn();
        conn.set_active_migration_disabled(&cx, true)
            .expect("set policy");
        let err = conn
            .request_path_migration(&cx, 9)
            .expect_err("must fail when migration disabled");
        assert_eq!(
            err,
            NativeQuicConnectionError::InvalidState(
                "active migration disabled by transport parameters"
            )
        );
    }

    #[test]
    fn path_migration_updates_active_path_and_counter() {
        let cx = test_cx();
        let mut conn = established_conn();
        assert_eq!(conn.active_path_id(), 0);
        assert_eq!(conn.migration_events(), 0);

        let n = conn
            .request_path_migration(&cx, 3)
            .expect("first migration");
        assert_eq!(n, 1);
        assert_eq!(conn.active_path_id(), 3);
        assert_eq!(conn.migration_events(), 1);

        let n = conn
            .request_path_migration(&cx, 3)
            .expect("same path is idempotent");
        assert_eq!(n, 1);
        assert_eq!(conn.migration_events(), 1);

        let n = conn
            .request_path_migration(&cx, 11)
            .expect("second migration");
        assert_eq!(n, 2);
        assert_eq!(conn.active_path_id(), 11);
        assert_eq!(conn.migration_events(), 2);
    }

    // --- Gap 7: next_writable_stream via connection API ---

    #[test]
    fn next_writable_stream_returns_open_stream() {
        let cx = test_cx();
        let mut conn = established_conn();
        let stream = conn.open_local_bidi(&cx).expect("open");
        let writable = conn.next_writable_stream(&cx).expect("next_writable");
        assert_eq!(writable, Some(stream));
    }

    #[test]
    fn next_writable_stream_returns_none_when_no_streams() {
        let cx = test_cx();
        let mut conn = established_conn();
        let writable = conn.next_writable_stream(&cx).expect("next_writable");
        assert_eq!(writable, None);
    }

    #[test]
    fn next_writable_stream_skips_stopped_stream() {
        let cx = test_cx();
        let mut conn = established_conn();
        let s1 = conn.open_local_bidi(&cx).expect("open1");
        let s2 = conn.open_local_bidi(&cx).expect("open2");
        conn.on_stop_sending(&cx, s1, 99).expect("stop s1");
        let writable = conn.next_writable_stream(&cx).expect("next_writable");
        assert_eq!(writable, Some(s2));
    }

    // --- Gap 8: Write operations after Close -> InvalidState ---

    #[test]
    fn write_stream_after_close_returns_invalid_state() {
        let cx = test_cx();
        let mut conn = established_conn();
        let stream = conn.open_local_bidi(&cx).expect("open");
        conn.close_immediately(&cx, 0xff).expect("close");
        let err = conn
            .write_stream(&cx, stream, 1)
            .expect_err("must fail after close");
        assert_eq!(
            err,
            NativeQuicConnectionError::InvalidState("connection is closed")
        );
    }

    #[test]
    fn open_local_bidi_after_close_returns_invalid_state() {
        let cx = test_cx();
        let mut conn = established_conn();
        conn.close_immediately(&cx, 0xff).expect("close");
        let err = conn.open_local_bidi(&cx).expect_err("must fail");
        assert_eq!(
            err,
            NativeQuicConnectionError::InvalidState("connection is closed")
        );
    }

    #[test]
    fn next_writable_stream_after_close_returns_invalid_state() {
        let cx = test_cx();
        let mut conn = established_conn();
        conn.open_local_bidi(&cx).expect("open");
        conn.close_immediately(&cx, 0xff).expect("close");
        let err = conn
            .next_writable_stream(&cx)
            .expect_err("must fail after close");
        assert_eq!(
            err,
            NativeQuicConnectionError::InvalidState("connection is closed")
        );
    }

    // --- Gap 9: accept_remote_stream while draining -> InvalidState ---

    #[test]
    fn accept_remote_stream_while_draining_returns_invalid_state() {
        let cx = test_cx();
        let mut conn = established_conn();
        conn.begin_close(&cx, 50_000, 0xdead).expect("drain");
        assert_eq!(conn.state(), QuicConnectionState::Draining);
        let remote = StreamId::local(
            StreamRole::Server,
            crate::net::quic_native::streams::StreamDirection::Bidirectional,
            0,
        );
        let err = conn
            .accept_remote_stream(&cx, remote)
            .expect_err("must fail while draining");
        assert_eq!(
            err,
            NativeQuicConnectionError::InvalidState(
                "new application streams require established state"
            )
        );
    }

    // --- Gap 10: NativeQuicConnectionError Display/From impls ---

    #[test]
    fn display_cancelled() {
        let err = NativeQuicConnectionError::Cancelled;
        assert_eq!(format!("{err}"), "operation cancelled");
    }

    #[test]
    fn display_congestion_limited() {
        let err = NativeQuicConnectionError::CongestionLimited {
            requested: 1500,
            bytes_in_flight: 12000,
            congestion_window: 12000,
        };
        assert_eq!(
            format!("{err}"),
            "congestion window exceeded: requested=1500, in_flight=12000, cwnd=12000"
        );
    }

    #[test]
    fn display_invalid_state() {
        let err = NativeQuicConnectionError::InvalidState("test message");
        assert_eq!(
            format!("{err}"),
            "invalid native quic connection state: test message"
        );
    }

    #[test]
    fn from_quic_tls_error() {
        let tls_err = QuicTlsError::HandshakeNotConfirmed;
        let conn_err: NativeQuicConnectionError = tls_err.clone().into();
        assert_eq!(conn_err, NativeQuicConnectionError::Tls(tls_err));
    }

    #[test]
    fn from_transport_error() {
        let transport_err = TransportError::InvalidStateTransition {
            from: QuicConnectionState::Idle,
            to: QuicConnectionState::Established,
        };
        let conn_err: NativeQuicConnectionError = transport_err.clone().into();
        assert_eq!(
            conn_err,
            NativeQuicConnectionError::Transport(transport_err)
        );
    }

    #[test]
    fn from_stream_table_error() {
        let st_err = StreamTableError::UnknownStream(StreamId(99));
        let conn_err: NativeQuicConnectionError = st_err.clone().into();
        assert_eq!(conn_err, NativeQuicConnectionError::StreamTable(st_err));
    }

    #[test]
    fn from_quic_stream_error() {
        let stream_err = QuicStreamError::SendStopped { code: 42 };
        let conn_err: NativeQuicConnectionError = stream_err.clone().into();
        assert_eq!(conn_err, NativeQuicConnectionError::Stream(stream_err));
    }

    #[test]
    fn display_tls_error_passthrough() {
        let inner = QuicTlsError::HandshakeNotConfirmed;
        let err = NativeQuicConnectionError::Tls(inner.clone());
        assert_eq!(format!("{err}"), format!("{inner}"));
    }

    #[test]
    fn display_transport_error_passthrough() {
        let inner = TransportError::InvalidStateTransition {
            from: QuicConnectionState::Idle,
            to: QuicConnectionState::Closed,
        };
        let err = NativeQuicConnectionError::Transport(inner.clone());
        assert_eq!(format!("{err}"), format!("{inner}"));
    }

    #[test]
    fn display_stream_table_error_passthrough() {
        let inner = StreamTableError::UnknownStream(StreamId(7));
        let err = NativeQuicConnectionError::StreamTable(inner.clone());
        assert_eq!(format!("{err}"), format!("{inner}"));
    }

    #[test]
    fn display_stream_error_passthrough() {
        let inner = QuicStreamError::SendStopped { code: 100 };
        let err = NativeQuicConnectionError::Stream(inner.clone());
        assert_eq!(format!("{err}"), format!("{inner}"));
    }
}
