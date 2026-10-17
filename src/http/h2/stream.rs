//! HTTP/2 stream state management.
//!
//! Implements stream state machine as defined in RFC 7540 Section 5.1.

use std::collections::VecDeque;

use crate::bytes::Bytes;
// br-asupersync-tlv3gp: StreamStore now uses a flat Vec<Option<Stream>>
// indexed by stream id offset from a sliding base, replacing the prior
// DetHashMap<u32, Stream>. The hot-path lookup is one bounds check and
// one pointer indirection rather than a hash + bucket scan.

use super::error::{ErrorCode, H2Error};
use super::frame::PrioritySpec;
#[cfg(test)]
use super::hpack::Header;
#[cfg(test)]
use super::settings::DEFAULT_INITIAL_WINDOW_SIZE;

/// Maximum accumulated header fragment size multiplier.
/// Provides protection against DoS via unbounded CONTINUATION frames.
const HEADER_FRAGMENT_MULTIPLIER: usize = 4;

/// Validate that a trailer block contains no HTTP/2 pseudo-headers.
///
/// br-asupersync-of0l5f: RFC 9113 §8.1 says trailers must not
/// include pseudo-header fields. The pre-fix path accepted trailing
/// HEADERS containing embedded `:status` / `:method` / `:path`
/// etc., letting a malicious peer rewrite the request line after
/// the initial HEADERS already committed it.
///
/// br-asupersync-90n3nh: this helper is now `pub(crate)`. Production
/// trailer validation is performed by
/// [`super::connection::validate_h2_pseudo_headers`] with
/// `is_trailers=true` (introduced in br-asupersync-0eyf7t), which
/// is the canonical validator and additionally enforces RFC 8.2.1
/// lowercase + RFC 8.2.2 connection-specific-header bans on the
/// trailer block. This module-local helper is retained as the
/// minimal name-only fast path for use by Stream-internal call
/// sites and the of0l5f regression tests; it is not part of the
/// public API surface because dual-implementation validators for a
/// security-sensitive check could drift across maintenance.
///
/// Pseudo-headers are HPACK fields whose name begins with `':'`.
/// This validator is name-only — it does not inspect values, since
/// the value is irrelevant once a `':'` prefix is observed.
///
/// Returns `Ok(())` if no pseudo-header is present, or
/// `Err(&'static str)` with a stable error reason on first match.
/// Callers should map the `Err` to a connection-level
/// `H2Error::protocol(...)` (PROTOCOL_ERROR) and trigger GOAWAY.
#[cfg(test)]
pub(crate) fn reject_pseudo_headers_in_trailers(headers: &[Header]) -> Result<(), &'static str> {
    for h in headers {
        if h.name.starts_with(':') {
            return Err("trailer block must not contain pseudo-header fields (RFC 9113 §8.1)");
        }
    }
    Ok(())
}

/// Absolute maximum header fragment size (256 KB).
/// caps the size even if max_header_list_size is very large (e.g. u32::MAX).
const MAX_HEADER_FRAGMENT_SIZE: usize = 256 * 1024;

/// Maximum number of HEADERS/CONTINUATION fragments accumulated for a single
/// header block before the stream is rejected with `ENHANCE_YOUR_CALM`.
///
/// The byte cap ([`MAX_HEADER_FRAGMENT_SIZE`] / `max_header_fragment_size`)
/// alone does NOT bound the fragment *count*: a peer can send an unbounded
/// stream of zero-length CONTINUATION frames, each adding 0 bytes (so the byte
/// cap never trips) while still pushing an entry onto `header_fragments`. That
/// is the CONTINUATION-flood DoS (CVE-2024-27316 class) — unbounded `Vec<Bytes>`
/// growth, bounded only by the connection-level CONTINUATION timeout, which
/// bounds duration but not the memory accumulated within it. This count cap
/// closes that bypass. 1024 is far above any legitimate fragmentation (a 256 KiB
/// header block at the 16 KiB default frame size is ~16 frames) while keeping
/// the retained `Bytes` entries trivially bounded.
const MAX_HEADER_CONTINUATION_FRAGMENTS: usize = 1024;

/// Maximum valid HTTP/2 stream ID (31-bit, MSB must be 0).
const MAX_STREAM_ID: u32 = 0x7FFF_FFFF;

/// Stream state as defined in RFC 7540 Section 5.1.
///
/// ```text
///                              +--------+
///                      send PP |        | recv PP
///                     ,--------|  idle  |--------.
///                    /         |        |         \
///                   v          +--------+          v
///            +----------+          |           +----------+
///            |          |          | send H /  |          |
///     ,------| reserved |          | recv H    | reserved |------.
///     |      | (local)  |          |           | (remote) |      |
///     |      +----------+          v           +----------+      |
///     |          |             +--------+             |          |
///     |          |     recv ES |        | send ES     |          |
///     |   send H |     ,-------|  open  |-------.     | recv H   |
///     |          |    /        |        |        \    |          |
///     |          v   v         +--------+         v   v          |
///     |      +----------+          |           +----------+      |
///     |      |   half   |          |           |   half   |      |
///     |      |  closed  |          | send R /  |  closed  |      |
///     |      | (remote) |          | recv R    | (local)  |      |
///     |      +----------+          |           +----------+      |
///     |           |                |                 |           |
///     |           | send ES /      |       recv ES / |           |
///     |           | send R /       v        send R / |           |
///     |           | recv R     +--------+   recv R   |           |
///     | send R /  `----------->|        |<-----------'  send R / |
///     | recv R                 | closed |               recv R   |
///     `----------------------->|        |<-----------------------'
///                              +--------+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    /// Idle state (initial state for new streams).
    Idle,
    /// Reserved (local) - server has sent PUSH_PROMISE.
    ReservedLocal,
    /// Reserved (remote) - server has received PUSH_PROMISE.
    ReservedRemote,
    /// Open - both sides can send data.
    Open,
    /// Half-closed (local) - local side has sent END_STREAM.
    HalfClosedLocal,
    /// Half-closed (remote) - remote side has sent END_STREAM.
    HalfClosedRemote,
    /// Closed - stream has been terminated.
    Closed,
}

impl StreamState {
    /// Check if data can be sent in this state.
    #[must_use]
    pub fn can_send(&self) -> bool {
        matches!(
            self,
            Self::Open | Self::HalfClosedRemote | Self::ReservedLocal
        )
    }

    /// Check if data can be received in this state.
    #[must_use]
    pub fn can_recv(&self) -> bool {
        matches!(
            self,
            Self::Open | Self::HalfClosedLocal | Self::ReservedRemote
        )
    }

    /// Check if the stream is in a terminal state.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        matches!(self, Self::Closed)
    }

    /// Check if the stream counts toward the max concurrent streams limit (RFC 7540 §5.1.2).
    /// "open", "half-closed", and "reserved" states all count toward the limit.
    /// Per RFC 7540 §5.1.2: "Streams in the 'reserved' state count toward the
    /// maximum, unless they have been reset."
    #[must_use]
    pub fn is_active(&self) -> bool {
        matches!(
            self,
            Self::Open
                | Self::HalfClosedLocal
                | Self::HalfClosedRemote
                | Self::ReservedLocal
                | Self::ReservedRemote
        )
    }

    /// Check if headers can be sent in this state.
    #[must_use]
    pub fn can_send_headers(&self) -> bool {
        matches!(
            self,
            Self::Idle | Self::ReservedLocal | Self::Open | Self::HalfClosedRemote
        )
    }

    /// Check if headers can be received in this state.
    #[must_use]
    pub fn can_recv_headers(&self) -> bool {
        matches!(
            self,
            Self::Idle | Self::ReservedRemote | Self::Open | Self::HalfClosedLocal
        )
    }
}

/// HTTP/2 stream.
#[derive(Debug)]
pub struct Stream {
    /// Stream identifier.
    id: u32,
    /// Current state.
    state: StreamState,
    /// Send window size.
    send_window: i32,
    /// Receive window size.
    recv_window: i32,
    /// Initial window size (for window update calculations).
    initial_send_window: i32,
    /// Initial receive window size (for auto WINDOW_UPDATE threshold).
    initial_recv_window: i32,
    /// Received DATA cannot be retroactively moved to consumption accounting.
    #[cfg(feature = "http2-streaming")]
    recv_data_started: bool,
    /// Outstanding receive bytes when the application owns stream credit.
    /// Includes padding until the connection discards it after frame validation.
    #[cfg(feature = "http2-streaming")]
    deferred_recv_bytes: Option<u64>,
    /// Priority specification.
    priority: PrioritySpec,
    /// Pending data to send (buffered due to flow control).
    pending_data: VecDeque<PendingData>,
    /// The API has accepted END_STREAM but the connection has not emitted it.
    queued_end_stream: bool,
    /// Temporarily retain an over-limit field block only to synchronize HPACK.
    refused_headers: bool,
    /// Error code if stream was reset.
    error_code: Option<ErrorCode>,
    /// This endpoint sent RST_STREAM, so frames the peer sent before the
    /// reset reached it are ignored rather than treated as errors.
    reset_sent: bool,
    /// Whether we've received END_HEADERS.
    headers_complete: bool,
    /// br-asupersync-0eyf7t — Set to `true` AFTER the initial
    /// HEADERS block for this stream has been successfully decoded
    /// in `decode_headers`. Used to discriminate the trailers
    /// section (any subsequent HEADERS-with-END_HEADERS for the
    /// same stream) from the initial header block. Per RFC 9113
    /// §8.1, trailers MUST NOT contain pseudo-header fields, so
    /// the connection layer needs to surface this signal to the
    /// pseudo-header validator.
    initial_headers_decoded: bool,
    /// Accumulated header block fragments.
    header_fragments: Vec<Bytes>,
    /// Running total byte length of `header_fragments`, maintained O(1) on every
    /// push so the accumulation cap can be enforced without re-summing the whole
    /// vector each frame (the re-sum was O(N) per CONTINUATION frame = O(N^2)
    /// over a fragmented header block — a CPU DoS amplifier). Invariant:
    /// `header_fragments_bytes == header_fragments.iter().map(Bytes::len).sum()`.
    header_fragments_bytes: usize,
    /// Max header list size (used to bound fragment accumulation).
    max_header_list_size: u32,
}

/// Pending data waiting for flow control window.
#[derive(Debug)]
struct PendingData {
    data: Bytes,
    end_stream: bool,
}

impl Stream {
    /// Create a new stream in idle state.
    #[must_use]
    pub fn new(id: u32, initial_window_size: u32, max_header_list_size: u32) -> Self {
        Self::new_with_recv_window(
            id,
            initial_window_size,
            initial_window_size,
            max_header_list_size,
        )
    }

    /// Create a new stream with separate peer-send and local-receive windows.
    #[must_use]
    pub fn new_with_recv_window(
        id: u32,
        initial_send_window_size: u32,
        initial_recv_window_size: u32,
        max_header_list_size: u32,
    ) -> Self {
        let initial_send_window =
            i32::try_from(initial_send_window_size).expect("initial send window size exceeds i32");
        let initial_recv_window = i32::try_from(initial_recv_window_size)
            .expect("initial receive window size exceeds i32");
        Self {
            id,
            state: StreamState::Idle,
            send_window: initial_send_window,
            recv_window: initial_recv_window,
            initial_send_window,
            initial_recv_window,
            #[cfg(feature = "http2-streaming")]
            recv_data_started: false,
            #[cfg(feature = "http2-streaming")]
            deferred_recv_bytes: None,
            priority: PrioritySpec {
                exclusive: false,
                dependency: 0,
                weight: 16,
            },
            pending_data: VecDeque::new(),
            queued_end_stream: false,
            refused_headers: false,
            error_code: None,
            reset_sent: false,
            headers_complete: true,
            initial_headers_decoded: false,
            header_fragments: Vec::new(),
            header_fragments_bytes: 0,
            max_header_list_size,
        }
    }

    /// br-asupersync-0eyf7t — Returns `true` if the initial HEADERS
    /// block for this stream has already been fully decoded. Used by
    /// the connection layer to detect that a subsequent HEADERS
    /// frame is the trailers section (which must not contain
    /// pseudo-header fields per RFC 9113 §8.1).
    #[must_use]
    pub fn initial_headers_decoded(&self) -> bool {
        self.initial_headers_decoded
    }

    /// br-asupersync-0eyf7t — Mark the initial HEADERS block as
    /// fully decoded. Called from the connection layer's
    /// `decode_headers` after a successful first-headers
    /// validation. Idempotent.
    pub fn mark_initial_headers_decoded(&mut self) {
        self.initial_headers_decoded = true;
    }

    /// Create a new reserved (remote) stream.
    #[must_use]
    pub fn new_reserved_remote(
        id: u32,
        initial_window_size: u32,
        max_header_list_size: u32,
    ) -> Self {
        let mut stream = Self::new(id, initial_window_size, max_header_list_size);
        stream.state = StreamState::ReservedRemote;
        stream
    }

    /// Create a new reserved (remote) stream with a local receive window.
    #[must_use]
    pub fn new_reserved_remote_with_recv_window(
        id: u32,
        initial_send_window_size: u32,
        initial_recv_window_size: u32,
        max_header_list_size: u32,
    ) -> Self {
        let mut stream = Self::new_with_recv_window(
            id,
            initial_send_window_size,
            initial_recv_window_size,
            max_header_list_size,
        );
        stream.state = StreamState::ReservedRemote;
        stream
    }

    /// Create a new reserved (local) stream.
    #[must_use]
    pub fn new_reserved_local(
        id: u32,
        initial_window_size: u32,
        max_header_list_size: u32,
    ) -> Self {
        let mut stream = Self::new(id, initial_window_size, max_header_list_size);
        stream.state = StreamState::ReservedLocal;
        stream
    }

    /// Create a new reserved (local) stream with a local receive window.
    #[must_use]
    pub fn new_reserved_local_with_recv_window(
        id: u32,
        initial_send_window_size: u32,
        initial_recv_window_size: u32,
        max_header_list_size: u32,
    ) -> Self {
        let mut stream = Self::new_with_recv_window(
            id,
            initial_send_window_size,
            initial_recv_window_size,
            max_header_list_size,
        );
        stream.state = StreamState::ReservedLocal;
        stream
    }

    /// Compute maximum accumulated header fragment size for a given limit.
    pub(crate) fn max_header_fragment_size_for(max_header_list_size: u32) -> usize {
        let max_list_size = usize::try_from(max_header_list_size).unwrap_or(usize::MAX);
        let calculated = max_list_size.saturating_mul(HEADER_FRAGMENT_MULTIPLIER);
        calculated.min(MAX_HEADER_FRAGMENT_SIZE)
    }

    fn max_header_fragment_size(&self) -> usize {
        Self::max_header_fragment_size_for(self.max_header_list_size)
    }

    /// Get the stream ID.
    #[must_use]
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Get the current state.
    #[must_use]
    pub fn state(&self) -> StreamState {
        self.state
    }

    /// Get the send window size.
    #[must_use]
    pub fn send_window(&self) -> i32 {
        self.send_window
    }

    /// Get the receive window size.
    #[must_use]
    pub fn recv_window(&self) -> i32 {
        self.recv_window
    }

    #[cfg(feature = "http2-streaming")]
    pub(crate) fn defer_recv_window_updates(&mut self) -> Result<(), H2Error> {
        if self.error_code.is_some() {
            return Err(H2Error::stream(
                self.id,
                ErrorCode::StreamClosed,
                "cannot defer receive credit on a reset stream",
            ));
        }
        if self.deferred_recv_bytes.is_some() {
            return Ok(());
        }
        if !self.initial_headers_decoded || !self.headers_complete || self.recv_data_started {
            return Err(H2Error::stream(
                self.id,
                ErrorCode::ProtocolError,
                "receive credit must be deferred after initial HEADERS and before DATA",
            ));
        }
        self.deferred_recv_bytes = Some(0);
        Ok(())
    }

    #[cfg(feature = "http2-streaming")]
    pub(crate) fn deferred_recv_bytes(&self) -> Option<u64> {
        self.deferred_recv_bytes
    }

    /// Retire consumed bytes, returning only credit still useful to the peer.
    #[cfg(feature = "http2-streaming")]
    pub(crate) fn release_deferred_recv_capacity(&mut self, amount: u32) -> Result<u32, H2Error> {
        if self.error_code.is_some() {
            return Ok(0);
        }
        let pending = self.deferred_recv_bytes.ok_or_else(|| {
            H2Error::stream(
                self.id,
                ErrorCode::ProtocolError,
                "stream receive credit is not deferred",
            )
        })?;
        let remaining = pending.checked_sub(u64::from(amount)).ok_or_else(|| {
            H2Error::stream(
                self.id,
                ErrorCode::FlowControlError,
                "released receive capacity exceeds unconsumed DATA",
            )
        })?;
        let increment = if self.state.can_recv() { amount } else { 0 };
        if increment != 0 {
            let delta = i32::try_from(increment).map_err(|_| {
                H2Error::stream(
                    self.id,
                    ErrorCode::FlowControlError,
                    "window increment too large",
                )
            })?;
            self.update_recv_window(delta)?;
        }
        self.deferred_recv_bytes = Some(remaining);
        Ok(increment)
    }

    /// Get the priority specification.
    #[must_use]
    pub fn priority(&self) -> &PrioritySpec {
        &self.priority
    }

    /// Get the error code if stream was reset.
    #[must_use]
    pub fn error_code(&self) -> Option<ErrorCode> {
        self.error_code
    }

    /// Check if headers are being received (CONTINUATION expected).
    #[must_use]
    pub fn is_receiving_headers(&self) -> bool {
        !self.headers_complete
    }

    /// Check if there is pending data.
    #[must_use]
    pub fn has_pending_data(&self) -> bool {
        !self.pending_data.is_empty()
    }

    pub(crate) fn queue_end_stream(&mut self, end_stream: bool) {
        self.queued_end_stream |= end_stream;
    }

    pub(crate) fn emit_end_stream(&mut self) {
        self.queued_end_stream = false;
    }

    pub(crate) fn headers_refused(&self) -> bool {
        self.refused_headers
    }

    /// Record that this endpoint sent RST_STREAM for the stream.
    pub(crate) fn mark_reset_sent(&mut self) {
        self.reset_sent = true;
    }

    /// RFC 9113 §5.1: after sending RST_STREAM, frames the peer had already
    /// sent on the stream are ignored. Their field blocks are still decoded
    /// so the HPACK dynamic tables stay in step.
    pub(crate) fn reset_sent(&self) -> bool {
        self.reset_sent
    }

    pub(crate) fn wire_closed(&self) -> bool {
        self.state.is_closed() && !self.queued_end_stream
    }

    fn wire_active(&self) -> bool {
        self.state.is_active() || self.queued_end_stream
    }

    /// Update send window size.
    pub fn update_send_window(&mut self, delta: i32) -> Result<(), H2Error> {
        // Check for overflow using wider arithmetic
        let new_window = i64::from(self.send_window) + i64::from(delta);
        let new_window = i32::try_from(new_window).map_err(|_| {
            H2Error::stream(self.id, ErrorCode::FlowControlError, "window size overflow")
        })?;
        self.send_window = new_window;
        Ok(())
    }

    /// Update receive window size.
    pub fn update_recv_window(&mut self, delta: i32) -> Result<(), H2Error> {
        // Check for overflow using wider arithmetic
        let new_window = i64::from(self.recv_window) + i64::from(delta);
        let new_window = i32::try_from(new_window).map_err(|_| {
            H2Error::stream(self.id, ErrorCode::FlowControlError, "window size overflow")
        })?;
        self.recv_window = new_window;
        Ok(())
    }

    /// Consume from send window (for sending data).
    pub fn consume_send_window(&mut self, amount: u32) {
        let amount_i64 = i64::from(amount);
        let new_window = i64::from(self.send_window) - amount_i64;
        // Clamp to i32 range — window can legitimately go negative per RFC 9113 §6.9.2
        self.send_window =
            i32::try_from(new_window.clamp(i64::from(i32::MIN), i64::from(i32::MAX)))
                .unwrap_or(i32::MIN);
    }

    /// Consume from receive window (for receiving data).
    ///
    /// br-asupersync-kaqld3: pre-fix the body did `clamp(MIN..MAX)`
    /// and left the window stuck at `i32::MIN` whenever the peer
    /// overshot the window total. Subsequent WINDOW_UPDATEs added to
    /// a deeply-negative baseline and the window never recovered to
    /// a positive value, **deadlocking the stream**. RFC 9113 §6.9.1
    /// is unambiguous: "A receiver MUST treat the receipt of a
    /// flow-controlled frame with length that would cause the
    /// flow-control window to exceed the maximum size as a
    /// connection error of type FLOW_CONTROL_ERROR."
    ///
    /// The fix returns `Result<(), H2Error>` so the caller (the
    /// data-frame ingestion path at `process_data` ~line 590) can
    /// propagate the error upward. Underflow below `i32::MIN` is
    /// the surfaceable event because `recv_window` legitimately may
    /// go negative after a `SETTINGS_INITIAL_WINDOW_SIZE` shrink
    /// (RFC 9113 §6.9.2) — but only down to the representable bound,
    /// not stuck-on-MIN. Anything that would underflow past `i32::MIN`
    /// is a connection-level FLOW_CONTROL_ERROR.
    pub fn consume_recv_window(&mut self, amount: u32) -> Result<(), H2Error> {
        let amount_i64 = i64::from(amount);
        let new_window = i64::from(self.recv_window) - amount_i64;
        if new_window < i64::from(i32::MIN) {
            return Err(H2Error::connection(
                ErrorCode::FlowControlError,
                "receive flow-control window underflow \
                 (peer overshot stream window total — RFC 9113 §6.9.1)",
            ));
        }
        // Safe cast: bounds-checked above against i32::MIN, and
        // amount is u32 so new_window cannot exceed i32::MAX.
        #[allow(clippy::cast_possible_truncation)]
        {
            self.recv_window = new_window as i32;
        }
        Ok(())
    }

    /// Check if the receive window is low enough to warrant an automatic WINDOW_UPDATE.
    ///
    /// Returns `Some(increment)` when the recv window has dropped below 25% of
    /// its initial value. The increment replenishes the window back to its initial size.
    ///
    /// This conservative threshold (25% instead of 50%) prevents eager WINDOW_UPDATE
    /// sending that defeats flow control backpressure and reduces risk of unbounded
    /// memory buffering.
    #[must_use]
    pub fn auto_window_update_increment(&self) -> Option<u32> {
        #[cfg(feature = "http2-streaming")]
        if self.deferred_recv_bytes.is_some() {
            return None;
        }
        // Use 25% threshold instead of 50% to be more conservative about flow control.
        // At least 1, so a window of 1-3 bytes is refilled once it is used up.
        let low_watermark = (self.initial_recv_window / 4).max(1);
        if self.recv_window < low_watermark {
            let increment = i64::from(self.initial_recv_window) - i64::from(self.recv_window);
            u32::try_from(increment).ok().filter(|&inc| inc > 0)
        } else {
            None
        }
    }

    /// Set the priority.
    pub fn set_priority(&mut self, priority: PrioritySpec) {
        self.priority = priority;
    }

    /// Update initial window size (affects send window).
    pub fn update_initial_window_size(&mut self, new_size: u32) -> Result<(), H2Error> {
        let new_size = i32::try_from(new_size)
            .map_err(|_| H2Error::flow_control("initial window size too large"))?;
        let delta = new_size - self.initial_send_window;
        self.initial_send_window = new_size;
        self.update_send_window(delta)
    }

    /// Transition to Open state (send headers).
    pub fn send_headers(&mut self, end_stream: bool) -> Result<(), H2Error> {
        match self.state {
            StreamState::Idle => {
                self.state = if end_stream {
                    StreamState::HalfClosedLocal
                } else {
                    StreamState::Open
                };
                Ok(())
            }
            StreamState::ReservedLocal => {
                self.state = if end_stream {
                    StreamState::Closed
                } else {
                    StreamState::HalfClosedRemote
                };
                Ok(())
            }
            StreamState::Open if end_stream => {
                self.state = StreamState::HalfClosedLocal;
                Ok(())
            }
            StreamState::HalfClosedRemote if end_stream => {
                self.state = StreamState::Closed;
                Ok(())
            }
            // Sending headers without END_STREAM on an already-open stream
            // (e.g. server response headers before DATA frames) is valid per
            // RFC 7540 §8.1 — state stays unchanged.
            StreamState::Open | StreamState::HalfClosedRemote => Ok(()),
            _ => Err(H2Error::stream(
                self.id,
                ErrorCode::StreamClosed,
                "cannot send headers in current state",
            )),
        }
    }

    /// Transition state on receiving headers.
    pub fn recv_headers(
        &mut self,
        end_stream: bool,
        end_headers: bool,
        is_client: bool,
    ) -> Result<(), H2Error> {
        // Validate the state transition BEFORE modifying any fields.
        // Setting headers_complete before validation would allow
        // recv_continuation to accumulate fragments on a closed stream.
        //
        // br-asupersync-pyhaov: track whether the initial header block
        // for this stream has already been fully received. Receiving
        // a SECOND HEADERS frame after the first one's END_HEADERS
        // signals trailers (RFC 9113 §8.1). RFC 9113 §8.1 mandates
        // 'Trailers MUST be sent as a HEADERS frame with both
        // END_HEADERS and END_STREAM set'. The state machine pre-fix
        // accepted trailing HEADERS without END_STREAM on Open /
        // HalfClosedLocal as if it were 1xx informational, masking
        // the malformed-trailer case on the server-receives-request
        // direction (where 1xx informational is impossible — only
        // SERVERS send 1xx, never clients).
        let is_trailer_attempt = self.headers_complete
            && matches!(self.state, StreamState::Open | StreamState::HalfClosedLocal);
        if is_trailer_attempt && !end_stream {
            // Server side (is_client=false): the only legitimate HEADERS-
            // after-headers-complete is request trailers, which MUST have
            // END_STREAM. No END_STREAM ⇒ malformed.
            //
            // Client side (is_client=true): the server may legitimately
            // send 1xx informational HEADERS without END_STREAM before
            // the final response. We CANNOT distinguish 1xx-informational
            // from 'malformed trailers without END_STREAM' at this layer
            // because we don't have the decoded :status here yet. The
            // pseudo-header validator in connection.rs::decode_headers
            // is the right place for the client-side discrimination
            // (1xx :status passes, no-pseudo-headers + no-END_STREAM
            // fails). For SERVER-side, we can fail closed here because
            // 1xx-style intermediate headers are not part of the
            // request message grammar.
            if !is_client {
                return Err(H2Error::stream(
                    self.id,
                    ErrorCode::ProtocolError,
                    "trailers MUST have END_STREAM (RFC 9113 §8.1) — \
                     server received second HEADERS without END_STREAM",
                ));
            }
        }

        match self.state {
            StreamState::Idle => {
                self.state = if end_stream {
                    StreamState::HalfClosedRemote
                } else {
                    StreamState::Open
                };
            }
            StreamState::ReservedRemote => {
                self.state = if end_stream {
                    StreamState::Closed
                } else {
                    StreamState::HalfClosedLocal
                };
            }
            StreamState::Open if end_stream => {
                self.state = StreamState::HalfClosedRemote;
            }
            StreamState::HalfClosedLocal if end_stream => {
                self.state = StreamState::Closed;
            }
            // Receiving headers without END_STREAM on an already-open stream
            // is valid per RFC 9113 §8.1 ONLY for client-side reception of
            // 1xx informational responses; the server-side variant is
            // rejected above. State stays unchanged.
            StreamState::Open | StreamState::HalfClosedLocal => {}
            _ => {
                return Err(H2Error::stream(
                    self.id,
                    ErrorCode::StreamClosed,
                    "cannot receive headers in current state",
                ));
            }
        }

        // Only update headers_complete after the state transition succeeds.
        self.headers_complete = end_headers;
        Ok(())
    }

    /// br-asupersync-of0l5f: returns `true` if the next HEADERS
    /// frame on this stream would be a TRAILER block per RFC 9113
    /// §8.1 — i.e. the initial header block has already been fully
    /// received (`headers_complete == true`) and the stream is in a
    /// state that still admits HEADERS (Open / HalfClosedLocal).
    ///
    /// Callers (e.g. the `connection.rs` HEADERS dispatch) should
    /// query this BEFORE invoking [`Self::recv_headers`] so the
    /// decoded header block can be passed through
    /// `connection::validate_h2_pseudo_headers(headers, is_trailers=true)`
    /// (the canonical trailer validator, br-asupersync-0eyf7t) —
    /// RFC 9113 §8.1 requires that "Trailers MUST NOT include
    /// pseudo-header fields". The pre-fix code path accepted
    /// trailing HEADERS without rejecting embedded `:status` /
    /// `:method` / `:path` pseudo-headers, letting an attacker
    /// rewrite the request line AFTER the initial HEADERS already
    /// committed it.
    #[must_use]
    pub fn would_be_trailer_block(&self) -> bool {
        self.headers_complete
            && matches!(self.state, StreamState::Open | StreamState::HalfClosedLocal)
    }

    /// Process CONTINUATION frame.
    pub fn recv_continuation(
        &mut self,
        header_block: Bytes,
        end_headers: bool,
    ) -> Result<(), H2Error> {
        // Reject CONTINUATION on closed streams as defense-in-depth. A
        // HEADERS frame with END_STREAM but not END_HEADERS closes a
        // half-closed (local) stream while its field block is still
        // arriving; the CONTINUATION frames that finish the block are part
        // of that HEADERS frame (RFC 9113 §6.2), so they are taken. A reset
        // stream still refuses them.
        if self.state.is_closed() && (self.headers_complete || self.error_code.is_some()) {
            return Err(H2Error::stream(
                self.id,
                ErrorCode::StreamClosed,
                "CONTINUATION on closed stream",
            ));
        }

        if self.headers_complete {
            return Err(H2Error::stream(
                self.id,
                ErrorCode::ProtocolError,
                "unexpected CONTINUATION frame",
            ));
        }

        // Bound both the accumulated byte size AND the fragment count to prevent
        // the CONTINUATION-flood DoS. The byte cap uses the O(1) running counter
        // (re-summing the vector here was O(N^2) over a fragmented block); the
        // count cap closes the zero-length-fragment bypass where empty frames
        // add 0 bytes yet still grow the vector unbounded.
        if self.header_fragments.len() >= MAX_HEADER_CONTINUATION_FRAGMENTS {
            return Err(H2Error::stream(
                self.id,
                ErrorCode::EnhanceYourCalm,
                "too many header block fragments",
            ));
        }
        if self
            .header_fragments_bytes
            .saturating_add(header_block.len())
            > self.max_header_fragment_size()
        {
            return Err(H2Error::stream(
                self.id,
                ErrorCode::EnhanceYourCalm,
                "accumulated header fragments too large",
            ));
        }

        self.header_fragments_bytes = self
            .header_fragments_bytes
            .saturating_add(header_block.len());
        self.header_fragments.push(header_block);
        self.headers_complete = end_headers;
        Ok(())
    }

    /// Take accumulated header fragments.
    pub fn take_header_fragments(&mut self) -> Vec<Bytes> {
        self.header_fragments_bytes = 0;
        std::mem::take(&mut self.header_fragments)
    }

    /// Add header fragment for accumulation.
    ///
    /// Returns an error if the accumulated size or fragment count would exceed
    /// the limit (see [`Stream::recv_continuation`] for the rationale).
    pub fn add_header_fragment(&mut self, fragment: Bytes) -> Result<(), H2Error> {
        if self.header_fragments.len() >= MAX_HEADER_CONTINUATION_FRAGMENTS {
            return Err(H2Error::stream(
                self.id,
                ErrorCode::EnhanceYourCalm,
                "too many header block fragments",
            ));
        }
        if self.header_fragments_bytes.saturating_add(fragment.len())
            > self.max_header_fragment_size()
        {
            return Err(H2Error::stream(
                self.id,
                ErrorCode::EnhanceYourCalm,
                "accumulated header fragments too large",
            ));
        }
        self.header_fragments_bytes = self.header_fragments_bytes.saturating_add(fragment.len());
        self.header_fragments.push(fragment);
        Ok(())
    }

    /// Transition state on sending data.
    pub fn send_data(&mut self, end_stream: bool) -> Result<(), H2Error> {
        // RFC 7540 §5.1: reserved(local) only permits HEADERS, RST_STREAM,
        // and PRIORITY — DATA frames are not allowed before the stream is
        // activated via send_headers.
        if !self.state.can_send() || self.state == StreamState::ReservedLocal {
            return Err(H2Error::stream(
                self.id,
                ErrorCode::StreamClosed,
                "cannot send data in current state",
            ));
        }

        if end_stream {
            match self.state {
                StreamState::Open => self.state = StreamState::HalfClosedLocal,
                StreamState::HalfClosedRemote => self.state = StreamState::Closed,
                _ => {}
            }
        }

        Ok(())
    }

    /// Transition state on receiving data.
    pub fn recv_data(&mut self, len: u32, end_stream: bool) -> Result<(), H2Error> {
        // RFC 7540 §5.1: reserved(remote) only permits HEADERS, RST_STREAM,
        // and PRIORITY — DATA frames must not arrive before the server sends
        // HEADERS to activate the promised stream.
        if !self.state.can_recv() || self.state == StreamState::ReservedRemote {
            return Err(H2Error::stream(
                self.id,
                ErrorCode::StreamClosed,
                "cannot receive data in current state",
            ));
        }

        let len_i32 = i32::try_from(len).map_err(|_| {
            H2Error::stream(
                self.id,
                ErrorCode::FlowControlError,
                "data length too large",
            )
        })?;

        // Check flow control
        if len_i32 > self.recv_window {
            return Err(H2Error::stream(
                self.id,
                ErrorCode::FlowControlError,
                "data exceeds flow control window",
            ));
        }

        #[cfg(feature = "http2-streaming")]
        let deferred_recv_bytes = self
            .deferred_recv_bytes
            .map(|pending| {
                pending.checked_add(u64::from(len)).ok_or_else(|| {
                    H2Error::stream(
                        self.id,
                        ErrorCode::FlowControlError,
                        "unconsumed receive capacity overflow",
                    )
                })
            })
            .transpose()?;

        // br-asupersync-kaqld3: propagate FLOW_CONTROL_ERROR if the
        // window underflows below i32::MIN. The check at line 582
        // guards against the common overshoot, but a SETTINGS shrink
        // mid-flight could still drive the window very negative; the
        // arithmetic-bound check inside consume_recv_window is the
        // last line of defence.
        self.consume_recv_window(len)?;
        #[cfg(feature = "http2-streaming")]
        {
            self.recv_data_started = true;
            self.deferred_recv_bytes = deferred_recv_bytes;
        }

        if end_stream {
            match self.state {
                StreamState::Open => self.state = StreamState::HalfClosedRemote,
                StreamState::HalfClosedLocal => self.state = StreamState::Closed,
                _ => {}
            }
        }

        Ok(())
    }

    /// Reset the stream.
    pub fn reset(&mut self, error_code: ErrorCode) {
        self.state = StreamState::Closed;
        self.error_code = Some(error_code);
        self.queued_end_stream = false;
        // Release buffered data to avoid holding memory until prune.
        self.header_fragments.clear();
        self.header_fragments_bytes = 0;
        self.pending_data.clear();
        #[cfg(feature = "http2-streaming")]
        if let Some(pending) = &mut self.deferred_recv_bytes {
            *pending = 0;
        }
    }

    /// Queue data for sending (when flow control blocks).
    pub fn queue_data(&mut self, data: Bytes, end_stream: bool) {
        self.pending_data
            .push_back(PendingData { data, end_stream });
    }

    /// Take pending data that fits in the window.
    pub fn take_pending_data(&mut self, max_len: usize) -> Option<(Bytes, bool)> {
        if max_len == 0 {
            return None;
        }
        if let Some(front) = self.pending_data.front() {
            if front.data.len() <= max_len {
                // Take entire chunk
                let pending = self.pending_data.pop_front()?;
                return Some((pending.data, pending.end_stream));
            }
        }

        if let Some(front) = self.pending_data.front_mut() {
            // Take partial chunk
            let data = front.data.slice(..max_len);
            front.data = front.data.slice(max_len..);
            return Some((data, false));
        }

        None
    }
}

/// Stream store for managing multiple streams.
///
/// br-asupersync-tlv3gp: backed by a flat `Vec<Option<Stream>>` indexed
/// by the offset `(stream_id - base_id)` rather than a `DetHashMap<u32,
/// Stream>`. The H2 frame-dispatch hot path (`get` / `get_mut` per
/// incoming frame) becomes a single bounds check and one pointer
/// indirection — no hash computation, no bucket scan, no tombstone
/// fix-up. Memory is bounded by `(highest_id - base_id) / 1`
/// `Option<Stream>` slots; `prune_closed` advances `base_id` past any
/// contiguous `None` prefix so completed-stream slots are reclaimed.
///
/// Correctness invariants preserved from the prior `DetHashMap` impl:
///
///   - HTTP/2 forbids reusing a stream id (RFC 9113 §5.1.1), so we
///     never insert into a slot that previously held a different
///     stream — `insert_stream` panics-via-assert if violated, but
///     callers above this layer enforce monotonic-id allocation so
///     the assert is a defence-in-depth check, not a runtime case.
///   - `len()` counts all *currently-stored* streams (active +
///     closed-but-not-yet-pruned), matching the old `HashMap::len`.
///   - `prune_closed` keeps reserved/idle slots and only drops
///     closed ones.
///   - `set_initial_window_size` skips closed streams (their windows
///     are irrelevant and applying a delta could trigger a spurious
///     overflow blocking the SETTINGS update).
///
/// Concurrent dispatch: `StreamStore` continues to require `&mut self`
/// for mutating operations; outer-layer locks (the H2 connection
/// mutex) provide the synchronisation, same as before.
#[derive(Debug)]
pub struct StreamStore {
    /// Sparse storage indexed by `(id - base_id) as usize`.
    /// `None` slots represent (a) ids that fall in a gap between
    /// strictly-monotonic allocations of the same parity, or (b)
    /// streams that were closed and pruned but whose slot has not yet
    /// been compacted away from the front.
    streams: Vec<Option<Stream>>,
    /// Lowest stream id that `streams[0]` represents. Advances during
    /// `prune_closed` when the leading run of `None` slots can be
    /// dropped.
    base_id: u32,
    /// Cached count of `Some(_)` slots so `len()` stays O(1).
    occupied: usize,
    /// Next client-initiated stream ID (odd).
    next_client_stream_id: u32,
    /// Next server-initiated stream ID (even).
    next_server_stream_id: u32,
    /// Maximum concurrent streams.
    max_concurrent_streams: u32,
    /// Our advertised limit when negotiated independently. None preserves the
    /// public store API's legacy aggregate limit across both directions.
    local_max_concurrent_streams: Option<u32>,
    /// Initial window size for new streams.
    initial_window_size: u32,
    /// Initial receive window size advertised by our local SETTINGS.
    initial_recv_window_size: u32,
    /// Maximum header list size for new streams.
    max_header_list_size: u32,
    /// Whether this is a client (for stream ID assignment).
    is_client: bool,
}

impl StreamStore {
    /// Create a new stream store.
    #[must_use]
    pub fn new(is_client: bool, initial_window_size: u32, max_header_list_size: u32) -> Self {
        Self::new_with_local_recv_window(
            is_client,
            initial_window_size,
            initial_window_size,
            max_header_list_size,
        )
    }

    /// Create a new stream store with separate peer-send and local-receive windows.
    #[must_use]
    pub fn new_with_local_recv_window(
        is_client: bool,
        initial_window_size: u32,
        initial_recv_window_size: u32,
        max_header_list_size: u32,
    ) -> Self {
        Self {
            streams: Vec::new(),
            base_id: 1,
            occupied: 0,
            next_client_stream_id: 1,
            next_server_stream_id: 2,
            max_concurrent_streams: u32::MAX,
            local_max_concurrent_streams: None,
            initial_window_size,
            initial_recv_window_size,
            max_header_list_size,
            is_client,
        }
    }

    // ----- internal flat-Vec primitives (br-asupersync-tlv3gp) ---------

    /// Compute the slot index for `id` if the slot is in range.
    /// Returns `None` if `id < base_id` (already pruned) or
    /// `id - base_id` exceeds the current Vec length.
    #[inline]
    fn slot_index(&self, id: u32) -> Option<usize> {
        if id < self.base_id {
            return None;
        }
        let off = (id - self.base_id) as usize;
        if off >= self.streams.len() {
            return None;
        }
        Some(off)
    }

    /// Hard ceiling on the `(id - base_id)` gap that
    /// [`ensure_slot`] is willing to materialise. RFC 9113 stream
    /// ids range up to `0x7FFF_FFFF` (~2.1B), and a peer that opens
    /// `id=1` followed by `id=0x7FFF_FFFD` would otherwise force
    /// `resize_with` to allocate ~2.1B `Option<Stream>` slots
    /// (tens of GB) — memory-DoS. The `max_concurrent_streams`
    /// gate counts only OCCUPIED slots, not Vec capacity, so it does
    /// not bound the gap.
    ///
    /// Chosen so the worst-case *eager* allocation stays ~16 MiB
    /// regardless of `Stream`'s in-memory width. A single peer HEADERS
    /// frame on a high stream id makes [`ensure_slot`] call
    /// `resize_with(gap + 1, …)`, so the ceiling has to be measured in
    /// bytes, not slots. `Stream` is ~100+ bytes (it embeds a
    /// `VecDeque`, a `Vec`, four window `i32`s, a `PrioritySpec`, …), so
    /// the old hand-estimate of "16 B/slot" made a literal `1 << 20`
    /// really a ~100 MB single-frame amplifier. Deriving the cap from
    /// `size_of::<Option<Stream>>()` keeps the 16 MiB bound honest if the
    /// struct grows, while staying far above any realistic
    /// `max_concurrent_streams` (typically ≤1024) and still rejecting the
    /// pathological ~2.1B-id-gap attack (RFC 9113 ids reach
    /// `0x7FFF_FFFF`).
    //
    // Truncation in the `as u32` casts is impossible: `TARGET_ALLOC_BYTES`
    // is 16 Mi, and `size_of::<Option<Stream>>() >= 1`, so `gap <= 16 Mi`
    // — three orders of magnitude below `u32::MAX`.
    #[allow(clippy::cast_possible_truncation)]
    const MAX_STREAM_GAP_FROM_BASE: u32 = {
        const TARGET_ALLOC_BYTES: usize = 16 * 1024 * 1024;
        // Never drop the ceiling below a working set that comfortably
        // exceeds any realistic `max_concurrent_streams`.
        const FLOOR_SLOTS: usize = 1 << 16;
        let gap = TARGET_ALLOC_BYTES / core::mem::size_of::<Option<Stream>>();
        if gap < FLOOR_SLOTS {
            FLOOR_SLOTS as u32
        } else {
            gap as u32
        }
    };

    /// Ensure the Vec has a slot for `id`, growing if needed.
    /// `id` MUST be `>= base_id`; callers ensure this because
    /// stream-id allocation is strictly monotonic per parity and ids
    /// below `base_id` have already been validated as "already-used"
    /// by the caller before reaching this method.
    ///
    /// br-asupersync-jq82r4: returns Err on stream-id gaps that
    /// would grow the flat Vec beyond [`MAX_STREAM_GAP_FROM_BASE`].
    /// As a last-chance, attempts [`prune_closed`] first so a long
    /// run of finished streams can advance `base_id` and reclaim
    /// the cap.
    #[inline]
    fn ensure_slot(&mut self, id: u32) -> Result<usize, H2Error> {
        debug_assert!(
            id >= self.base_id,
            "id < base_id should be rejected upstream"
        );
        if id.saturating_sub(self.base_id) > Self::MAX_STREAM_GAP_FROM_BASE {
            // Last-chance compaction: prune the leading closed run so
            // base_id advances and the gap may fit. After this
            // base_id may have moved; recheck.
            self.prune_closed();
            if id < self.base_id || id.saturating_sub(self.base_id) > Self::MAX_STREAM_GAP_FROM_BASE
            {
                return Err(H2Error::stream(
                    id,
                    ErrorCode::RefusedStream,
                    "stream id gap exceeds implementation ceiling \
                     (br-asupersync-jq82r4): would grow flat Vec by \
                     >1M slots; reject to prevent memory DoS",
                ));
            }
        }
        let off = (id - self.base_id) as usize;
        if off >= self.streams.len() {
            self.streams.resize_with(off + 1, || None);
        }
        Ok(off)
    }

    /// Non-mutating gap pre-check for callers that update
    /// `next_*_stream_id` BEFORE calling `insert_stream`. Returns
    /// the same `RefusedStream` error that `ensure_slot` would, but
    /// without mutating any field — so the caller can reject without
    /// rolling back the monotonic-id counter.
    ///
    /// Intentionally STRICTER than `ensure_slot` (no prune-and-retry):
    /// if the gap is genuinely recoverable via `prune_closed`, the
    /// caller's eventual path through `insert_stream → ensure_slot`
    /// will retry there. The pre-check just short-circuits the
    /// obvious DoS pattern before any state mutation.
    #[inline]
    fn precheck_stream_gap(&self, id: u32) -> Result<(), H2Error> {
        if id >= self.base_id && id - self.base_id > Self::MAX_STREAM_GAP_FROM_BASE {
            return Err(H2Error::stream(
                id,
                ErrorCode::RefusedStream,
                "stream id gap exceeds implementation ceiling \
                 (br-asupersync-jq82r4)",
            ));
        }
        Ok(())
    }

    /// Insert a new stream at `id`. Returns `Err` only if `id <
    /// base_id` (already pruned past) or if `ensure_slot` rejects the
    /// id-gap (br-asupersync-jq82r4). Updates `occupied`. The caller
    /// is responsible for stream-id-uniqueness — this method asserts
    /// that the slot was previously empty (defence in depth against
    /// the RFC 9113 §5.1.1 reuse prohibition).
    fn insert_stream(&mut self, id: u32, stream: Stream) -> Result<(), H2Error> {
        if id < self.base_id {
            return Err(H2Error::protocol("stream id below pruned base"));
        }
        let idx = self.ensure_slot(id)?;
        debug_assert!(
            self.streams[idx].is_none(),
            "stream id reuse violates RFC 9113 §5.1.1 — caller should reject before insert"
        );
        if self.streams[idx].is_none() {
            self.occupied += 1;
        }
        self.streams[idx] = Some(stream);
        Ok(())
    }

    /// Iterate over `Some` streams (ignores gaps).
    #[inline]
    fn iter_streams(&self) -> impl Iterator<Item = &Stream> + '_ {
        self.streams.iter().filter_map(|s| s.as_ref())
    }

    /// Iterate over `Some` streams mutably (ignores gaps).
    #[inline]
    fn iter_streams_mut(&mut self) -> impl Iterator<Item = &mut Stream> + '_ {
        self.streams.iter_mut().filter_map(|s| s.as_mut())
    }

    /// Drop slots that fail the predicate; mirrors `HashMap::retain`.
    /// Snapshots `base_id` first so the closure can see the id even
    /// while we hold a mutable borrow on `self.streams`.
    fn retain_streams<F>(&mut self, mut pred: F)
    where
        F: FnMut(u32, &mut Stream) -> bool,
    {
        let base = self.base_id;
        let mut removed = 0;
        for (i, slot) in self.streams.iter_mut().enumerate() {
            if let Some(stream) = slot.as_mut() {
                let id = base.saturating_add(i as u32);
                if !pred(id, stream) {
                    *slot = None;
                    removed += 1;
                }
            }
        }
        self.occupied = self.occupied.saturating_sub(removed);
        self.compact_base();
    }

    /// Trim leading `None` entries by advancing `base_id`.
    ///
    /// HTTP/2 client-initiated and server-initiated stream-id spaces advance
    /// independently. A gap at the front can only be compacted when that id is
    /// already below the next legal id for its parity; otherwise the empty slot
    /// may still represent a future remote stream.
    fn compact_base(&mut self) {
        let base = self.base_id;
        let next_client = self.next_client_stream_id;
        let next_server = self.next_server_stream_id;
        let leading_none = self
            .streams
            .iter()
            .enumerate()
            .take_while(|(index, slot)| {
                if slot.is_some() {
                    return false;
                }
                let id = base.saturating_add(*index as u32);
                if id % 2 == 1 {
                    id < next_client
                } else {
                    id < next_server
                }
            })
            .count();
        if leading_none > 0 {
            self.streams.drain(..leading_none);
            self.base_id = self.base_id.saturating_add(leading_none as u32);
        }
    }

    // ----- public API --------------------------------------------------

    /// Set the maximum concurrent streams.
    pub fn set_max_concurrent_streams(&mut self, max: u32) {
        self.max_concurrent_streams = max;
        self.local_max_concurrent_streams = None;
    }

    pub(crate) fn set_local_max_concurrent_streams(&mut self, max: u32) {
        self.local_max_concurrent_streams = Some(max);
    }

    pub(crate) fn set_remote_max_concurrent_streams(&mut self, max: u32) {
        self.max_concurrent_streams = max;
    }

    /// Set the initial window size for new streams.
    pub fn set_initial_window_size(&mut self, size: u32) -> Result<(), H2Error> {
        // First check if any stream would overflow to prevent partial mutations
        self.check_initial_window_size(size)?;

        // Update existing streams.  Closed streams are excluded: their
        // windows are irrelevant and applying a large delta could trigger
        // a spurious overflow error that blocks the entire SETTINGS update.
        for stream in self.iter_streams_mut() {
            if !stream.wire_closed() {
                stream.update_initial_window_size(size)?;
            }
        }
        self.initial_window_size = size;
        Ok(())
    }

    /// Check if setting the initial window size would overflow any stream's window.
    pub fn check_initial_window_size(&self, size: u32) -> Result<(), H2Error> {
        let delta = i64::from(size) - i64::from(self.initial_window_size);
        for stream in self.iter_streams() {
            if !stream.wire_closed() {
                let new_window = i64::from(stream.send_window()) + delta;
                if new_window > i64::from(i32::MAX) || new_window < i64::from(i32::MIN) {
                    return Err(H2Error::flow_control("flow-control window overflow"));
                }
            }
        }
        Ok(())
    }

    /// Get the initial window size.
    #[must_use]
    pub fn initial_window_size(&self) -> u32 {
        self.initial_window_size
    }

    /// Get the local initial receive window size.
    #[must_use]
    pub fn initial_recv_window_size(&self) -> u32 {
        self.initial_recv_window_size
    }

    /// Get a stream by ID. O(1) — single bounds check + indirection.
    #[must_use]
    pub fn get(&self, id: u32) -> Option<&Stream> {
        self.slot_index(id).and_then(|i| self.streams[i].as_ref())
    }

    /// Get a mutable stream by ID. O(1).
    #[must_use]
    pub fn get_mut(&mut self, id: u32) -> Option<&mut Stream> {
        match self.slot_index(id) {
            Some(i) => self.streams[i].as_mut(),
            None => None,
        }
    }

    /// Returns true when `id` is currently in the idle state.
    ///
    /// This covers stream IDs that are not present in the store yet but are
    /// still in the not-yet-opened range for their initiator parity.
    #[must_use]
    pub fn is_idle_stream_id(&self, id: u32) -> bool {
        if id == 0 || id > MAX_STREAM_ID {
            return false;
        }

        if let Some(stream) = self.get(id) {
            return stream.state() == StreamState::Idle;
        }

        if id % 2 == 1 {
            id >= self.next_client_stream_id
        } else {
            id >= self.next_server_stream_id
        }
    }

    /// Get or create a stream.
    pub fn get_or_create(&mut self, id: u32) -> Result<&mut Stream, H2Error> {
        self.get_or_create_inner(id, false)
    }

    /// The connection must decode even a refused stream's field block before
    /// resetting it. At most one incomplete field block is legal at a time.
    pub(crate) fn get_or_create_for_headers(&mut self, id: u32) -> Result<&mut Stream, H2Error> {
        self.get_or_create_inner(id, true)
    }

    fn get_or_create_inner(
        &mut self,
        id: u32,
        retain_refused: bool,
    ) -> Result<&mut Stream, H2Error> {
        if self.get(id).is_none() {
            let mut refused_headers = false;
            // Validate stream ID
            if id == 0 {
                return Err(H2Error::protocol("stream ID 0 is reserved"));
            }
            if id > MAX_STREAM_ID {
                return Err(H2Error::protocol("stream ID exceeds maximum"));
            }
            // br-asupersync-jq82r4: pre-validate the stream-id gap
            // from base_id BEFORE any state advance
            // (next_*_stream_id update, max-concurrent-streams
            // check) so a rejection leaves no half-mutated state
            // that would corrupt subsequent legitimate streams. The
            // gap check inside ensure_slot remains as the ultimate
            // guarantee — we just check first so we can fail fast
            // and cheaply.
            self.precheck_stream_gap(id)?;

            let is_client_stream = id % 2 == 1;
            if self.is_client && is_client_stream {
                return Err(H2Error::protocol("invalid stream ID parity"));
            }
            if !self.is_client && !is_client_stream {
                return Err(H2Error::protocol("invalid stream ID parity"));
            }

            // RFC 7540 Section 5.1.2: reject incoming streams that exceed our
            // advertised max_concurrent_streams.  We amortize the O(N) active
            // count by first checking the total tracked stream count (which
            // includes closed streams kept for GOAWAY bookkeeping).
            let local_limit = self
                .local_max_concurrent_streams
                .unwrap_or(self.max_concurrent_streams);
            if self.occupied >= local_limit as usize {
                let active = self
                    .iter_streams()
                    .filter(|s| {
                        s.wire_active()
                            && (self.local_max_concurrent_streams.is_none()
                                || (s.id % 2 == 1) != self.is_client)
                    })
                    .count();
                // Prune closed streams while we're scanning.
                self.retain_streams(|_, s| !s.wire_closed());
                if active >= local_limit as usize {
                    if !retain_refused {
                        return Err(H2Error::stream(
                            id,
                            ErrorCode::RefusedStream,
                            "max concurrent streams exceeded",
                        ));
                    }
                    refused_headers = true;
                }
            }

            if self.is_client && !is_client_stream {
                // Server-initiated stream received by client
                if id < self.next_server_stream_id {
                    return Err(H2Error::protocol("stream ID already used"));
                }
                self.next_server_stream_id = id.saturating_add(2);
            } else if !self.is_client && is_client_stream {
                // Client-initiated stream received by server
                if id < self.next_client_stream_id {
                    return Err(H2Error::protocol("stream ID already used"));
                }
                self.next_client_stream_id = id.saturating_add(2);
            }

            let mut stream = Stream::new_with_recv_window(
                id,
                self.initial_window_size,
                self.initial_recv_window_size,
                self.max_header_list_size,
            );
            stream.refused_headers = refused_headers;
            self.insert_stream(id, stream)?;
        }
        self.get_mut(id).ok_or_else(|| {
            H2Error::connection(ErrorCode::InternalError, "stream missing after insert")
        })
    }

    /// Reserve a remote-initiated stream (e.g., PUSH_PROMISE).
    pub fn reserve_remote_stream(&mut self, id: u32) -> Result<&mut Stream, H2Error> {
        if id == 0 {
            return Err(H2Error::protocol("stream ID 0 is reserved"));
        }
        if id > MAX_STREAM_ID {
            return Err(H2Error::protocol("stream ID exceeds maximum"));
        }
        if self.get(id).is_some() {
            return Err(H2Error::protocol("stream ID already used"));
        }
        // br-asupersync-jq82r4: refuse PUSH_PROMISE that would
        // explode the flat Vec before mutating next_*_stream_id.
        self.precheck_stream_gap(id)?;

        let is_client_stream = id % 2 == 1;
        if self.is_client {
            if is_client_stream {
                return Err(H2Error::protocol("invalid promised stream ID"));
            }
            if id < self.next_server_stream_id {
                return Err(H2Error::protocol("stream ID already used"));
            }
            self.next_server_stream_id = id.saturating_add(2);
        } else {
            if !is_client_stream {
                return Err(H2Error::protocol("invalid promised stream ID"));
            }
            if id < self.next_client_stream_id {
                return Err(H2Error::protocol("stream ID already used"));
            }
            self.next_client_stream_id = id.saturating_add(2);
        }

        let stream = Stream::new_reserved_remote_with_recv_window(
            id,
            self.initial_window_size,
            self.initial_recv_window_size,
            self.max_header_list_size,
        );
        self.insert_stream(id, stream)?;
        self.get_mut(id).ok_or_else(|| {
            H2Error::connection(
                ErrorCode::InternalError,
                "reserved stream missing after insert",
            )
        })
    }

    /// Reserve a locally-initiated stream (e.g., outbound PUSH_PROMISE).
    pub fn reserve_local_stream(&mut self) -> Result<u32, H2Error> {
        let id = self.allocate_stream_id()?;
        let initial_window_size = self.initial_window_size;
        let initial_recv_window_size = self.initial_recv_window_size;
        let max_header_list_size = self.max_header_list_size;
        let stream = self.get_mut(id).ok_or_else(|| {
            H2Error::connection(
                ErrorCode::InternalError,
                "allocated stream missing from store",
            )
        })?;
        *stream = Stream::new_reserved_local_with_recv_window(
            id,
            initial_window_size,
            initial_recv_window_size,
            max_header_list_size,
        );
        Ok(id)
    }

    /// Allocate a new stream ID.
    pub fn allocate_stream_id(&mut self) -> Result<u32, H2Error> {
        // Amortize the O(N) active stream count and prune operations.
        // We only perform the O(N) scan when the total number of tracked
        // streams reaches the max_concurrent_streams limit.
        if self.occupied >= self.max_concurrent_streams as usize {
            let mut active_count = 0_u32;
            let is_client = self.is_client;
            let directional = self.local_max_concurrent_streams.is_some();
            self.retain_streams(|_, s| {
                if s.wire_active() && (!directional || (s.id % 2 == 1) == is_client) {
                    active_count = active_count.saturating_add(1);
                }
                !s.wire_closed()
            });

            if active_count >= self.max_concurrent_streams {
                return Err(H2Error::protocol("max concurrent streams exceeded"));
            }
        }

        // br-asupersync-jq82r4: refuse self-allocation when the next
        // id would explode the flat Vec, BEFORE incrementing
        // next_*_stream_id (so a refused allocation doesn't burn an
        // id and desynchronise the parity counter).
        let next_self_id = if self.is_client {
            self.next_client_stream_id
        } else {
            self.next_server_stream_id
        };
        if next_self_id <= MAX_STREAM_ID {
            self.precheck_stream_gap(next_self_id)?;
        }

        let id = if self.is_client {
            if self.next_client_stream_id > MAX_STREAM_ID {
                return Err(H2Error::protocol("stream ID exhausted"));
            }
            let id = self.next_client_stream_id;
            self.next_client_stream_id = id.saturating_add(2);
            id
        } else {
            if self.next_server_stream_id > MAX_STREAM_ID {
                return Err(H2Error::protocol("stream ID exhausted"));
            }
            let id = self.next_server_stream_id;
            self.next_server_stream_id = id.saturating_add(2);
            id
        };

        let stream = Stream::new_with_recv_window(
            id,
            self.initial_window_size,
            self.initial_recv_window_size,
            self.max_header_list_size,
        );
        self.insert_stream(id, stream)?;
        Ok(id)
    }

    /// Get the total number of streams (including closed).
    #[must_use]
    pub fn len(&self) -> usize {
        self.occupied
    }

    /// Return whether the store has zero streams.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.occupied == 0
    }

    /// Remove closed streams.
    pub fn prune_closed(&mut self) {
        self.retain_streams(|_, stream| !stream.wire_closed());
    }

    /// Remove closed streams unless the caller still needs their stream id
    /// for queued connection-layer work.
    pub fn prune_closed_except<F>(&mut self, mut keep_closed: F)
    where
        F: FnMut(u32) -> bool,
    {
        self.retain_streams(|id, stream| !stream.wire_closed() || keep_closed(id));
    }

    /// Get all active stream IDs.
    ///
    /// Uses the same `is_active()` predicate as [`Self::active_count`] so
    /// `active_stream_ids().len() == active_count()` always holds.
    #[must_use]
    pub fn active_stream_ids(&self) -> Vec<u32> {
        let base = self.base_id;
        self.streams
            .iter()
            .enumerate()
            .filter_map(|(i, slot)| {
                slot.as_ref().and_then(|s| {
                    if s.wire_active() {
                        Some(base.saturating_add(i as u32))
                    } else {
                        None
                    }
                })
            })
            .collect()
    }

    /// Get count of active streams.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.iter_streams().filter(|s| s.wire_active()).count()
    }
}

#[cfg(test)]
#[path = "stream_inline_tests.rs"]
mod tests;
