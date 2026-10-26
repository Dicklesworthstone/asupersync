//! WebSocket close handshake protocol (RFC 6455 Section 7).
//!
//! The close handshake ensures clean connection termination with proper
//! status code propagation. The protocol is:
//!
//! 1. Initiator sends Close frame with optional status code and reason
//! 2. Receiver replies with a Close frame, typically echoing the peer's
//!    status code when it is valid for transmission
//! 3. Both sides enter closed state
//!
//! # Cancel-Safety
//!
//! Close operations are designed to be cancel-safe:
//! - Bounded timeout prevents hanging on unresponsive peers
//! - Cancellation closes with `CloseConfig::cancellation_code` (GoingAway, 1001, by default)
//! - Partial close is handled gracefully
//!
//! # Example
//!
//! ```ignore
//! use asupersync::net::websocket::{CloseReason, CloseCode};
//!
//! // Parse close frame payload
//! let reason = CloseReason::parse(&payload)?;
//! println!("Close code: {:?}, reason: {:?}", reason.code, reason.text);
//!
//! // Create close response
//! let response = CloseReason::new(CloseCode::Normal, None);
//! ```

use super::{CloseCode, Frame, Opcode, WsError};
use crate::bytes::Bytes;
use crate::cx::Cx;
use crate::time::{Sleep, TimerDriverHandle};
use crate::types::Time;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

const CLOSE_CODE_BYTES: usize = 2;
const MAX_CLOSE_PAYLOAD_BYTES: usize = 125;

/// Parsed close frame payload.
///
/// A close frame may contain:
/// - No payload (empty)
/// - 2 bytes: status code only
/// - 2+ bytes: status code followed by UTF-8 reason text
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CloseReason {
    /// Close status code (if present).
    pub code: Option<CloseCode>,
    /// Raw close status code from wire payload, including custom codes.
    pub raw_code: Option<u16>,
    /// Close reason text (if present).
    pub text: Option<String>,
}

impl CloseReason {
    /// Create a new close reason.
    #[must_use]
    pub fn new(code: CloseCode, text: Option<&str>) -> Self {
        let raw = u16::from(code);
        Self {
            code: Some(code),
            raw_code: Some(raw),
            text: text.map(String::from),
        }
    }

    /// Create an empty close reason (no code or text).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            code: None,
            raw_code: None,
            text: None,
        }
    }

    /// Create a close reason for normal closure.
    #[must_use]
    pub fn normal() -> Self {
        Self::new(CloseCode::Normal, None)
    }

    /// Create a close reason for going away (cancellation).
    #[must_use]
    pub fn going_away() -> Self {
        Self::new(CloseCode::GoingAway, None)
    }

    /// Create a close reason with text.
    #[must_use]
    pub fn with_text(code: CloseCode, text: &str) -> Self {
        Self::new(code, Some(text))
    }

    /// Parse a close frame payload.
    ///
    /// # Payload Format
    ///
    /// - Empty: No code or reason
    /// - 2 bytes: Big-endian status code
    /// - 2+ bytes: Status code + UTF-8 reason text
    ///
    /// # Errors
    ///
    /// Returns `WsError::InvalidClosePayload` if:
    /// - Payload exceeds the close-frame payload limit
    /// - Payload is exactly 1 byte (invalid)
    /// - Status code is invalid/reserved for wire use
    /// - Reason text is not valid UTF-8
    pub fn parse(payload: &[u8]) -> Result<Self, WsError> {
        if payload.len() > MAX_CLOSE_PAYLOAD_BYTES {
            return Err(WsError::InvalidClosePayload);
        }

        match payload.len() {
            0 => Ok(Self::empty()),
            1 => Err(WsError::InvalidClosePayload),
            _ => {
                let code_raw = u16::from_be_bytes([payload[0], payload[1]]);
                if !CloseCode::is_valid_received_code(code_raw) {
                    return Err(WsError::InvalidClosePayload);
                }
                let code = CloseCode::from_u16(code_raw);

                let text = if payload.len() > 2 {
                    let text_bytes = &payload[2..];
                    let text_str = std::str::from_utf8(text_bytes)
                        .map_err(|_| WsError::InvalidClosePayload)?;
                    Some(text_str.to_string())
                } else {
                    None
                };

                Ok(Self {
                    code,
                    raw_code: Some(code_raw),
                    text,
                })
            }
        }
    }

    /// Encode this close reason into a frame payload.
    #[must_use]
    pub fn encode(&self) -> Bytes {
        match self.outbound_payload_parts() {
            (DropReasonText::No, code, text) => Self::encode_parts(code, text),
            (DropReasonText::Yes, code, _) => Self::encode_parts(code, None),
        }
    }

    fn encode_parts(code: Option<u16>, text: Option<&str>) -> Bytes {
        match (code, text) {
            (None, None) => Bytes::new(),
            (None, Some(_text)) => Bytes::new(),
            (Some(code_val), None) => Bytes::copy_from_slice(&code_val.to_be_bytes()),
            (Some(code_val), Some(text)) => {
                let mut buf = Vec::with_capacity(2 + text.len());
                buf.extend_from_slice(&code_val.to_be_bytes());
                buf.extend_from_slice(text.as_bytes());
                Bytes::from(buf)
            }
        }
    }

    /// Convert to a close frame.
    #[must_use]
    pub fn to_frame(&self) -> Frame {
        match self.outbound_payload_parts() {
            (DropReasonText::No, code, text) => Frame::close(code, text),
            (DropReasonText::Yes, code, _) => Frame::close(code, None),
        }
    }

    /// Returns the outbound wire close code when this reason can be sent
    /// without violating RFC 6455's send-side close-code rules.
    #[must_use]
    fn outbound_wire_code(&self) -> Option<u16> {
        match self.raw_code {
            Some(code) if CloseCode::is_valid_code(code) => Some(code),
            Some(_) => None,
            None => self
                .code
                .map(u16::from)
                .filter(|code| CloseCode::is_valid_code(*code)),
        }
    }

    /// Returns the code/text pair to place on the wire.
    ///
    /// A parsed peer code may be valid to receive but forbidden to send
    /// (for example 1016-2999). In that case we downgrade to an empty close
    /// frame instead of inventing a different status code. Overlong reason text
    /// is dropped while preserving a sendable code, keeping this path panic-free.
    #[must_use]
    fn outbound_payload_parts(&self) -> (DropReasonText, Option<u16>, Option<&str>) {
        let code = self.outbound_wire_code();
        let raw_text = self.text.as_deref();
        let text = match (code, raw_text) {
            (Some(_), Some(text)) if CLOSE_CODE_BYTES + text.len() <= MAX_CLOSE_PAYLOAD_BYTES => {
                Some(text)
            }
            _ => None,
        };
        let drop_text = raw_text.is_some() && text.is_none();
        (
            if drop_text {
                DropReasonText::Yes
            } else {
                DropReasonText::No
            },
            code,
            text,
        )
    }

    /// Check if this represents a normal closure.
    #[must_use]
    pub fn is_normal(&self) -> bool {
        self.wire_code() == Some(u16::from(CloseCode::Normal))
    }

    /// Check if this represents a protocol error.
    #[must_use]
    pub fn is_error(&self) -> bool {
        matches!(
            self.code,
            Some(
                CloseCode::ProtocolError
                    | CloseCode::InvalidPayload
                    | CloseCode::PolicyViolation
                    | CloseCode::InternalError
            )
        )
    }

    /// Returns the wire close code (including custom codes).
    #[must_use]
    pub const fn wire_code(&self) -> Option<u16> {
        match (self.raw_code, self.code) {
            (Some(code), _) => Some(code),
            (None, Some(code)) => Some(code as u16),
            (None, None) => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DropReasonText {
    No,
    Yes,
}

/// State of the close handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CloseState {
    /// Connection is open (normal operation).
    #[default]
    Open,
    /// We sent a close frame, waiting for peer's close frame.
    CloseSent,
    /// We received a close frame, need to send response.
    CloseReceived,
    /// Close handshake complete, connection can be terminated.
    Closed,
}

impl CloseState {
    /// Check if the connection is still open for data.
    #[must_use]
    pub const fn is_open(self) -> bool {
        matches!(self, Self::Open)
    }

    /// Check if the close handshake is complete.
    #[must_use]
    pub const fn is_closed(self) -> bool {
        matches!(self, Self::Closed)
    }

    /// Check if we're in the process of closing.
    #[must_use]
    pub const fn is_closing(self) -> bool {
        matches!(self, Self::CloseSent | Self::CloseReceived)
    }
}

/// Configuration for close handshake behavior.
#[derive(Debug, Clone)]
pub struct CloseConfig {
    /// Timeout for waiting for close response from peer.
    pub close_timeout: Duration,
    /// Whether to send close frame on drop if still open.
    pub close_on_drop: bool,
    /// Default close code for cancellation.
    pub cancellation_code: CloseCode,
}

impl Default for CloseConfig {
    fn default() -> Self {
        Self {
            close_timeout: Duration::from_secs(5),
            close_on_drop: true,
            cancellation_code: CloseCode::GoingAway,
        }
    }
}

impl CloseConfig {
    /// Create a new close configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the close timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.close_timeout = timeout;
        self
    }

    /// Set whether to send close on drop.
    #[must_use]
    pub fn with_close_on_drop(mut self, enabled: bool) -> Self {
        self.close_on_drop = enabled;
        self
    }

    /// Set the cancellation close code.
    #[must_use]
    pub fn with_cancellation_code(mut self, code: CloseCode) -> Self {
        self.cancellation_code = code;
        self
    }
}

/// One absolute close budget, retained across cancelled waits and split/reunite.
/// The captured clock is never replaced by a later caller's ambient context.
#[derive(Debug, Clone)]
pub(super) struct CloseDeadline {
    at: Time,
    clock: Option<TimerDriverHandle>,
    timed_out: Arc<AtomicBool>,
}

impl CloseDeadline {
    pub(super) fn new(cx: Option<&Cx>, timeout: Duration) -> Self {
        let ambient = cx.is_none().then(Cx::current).flatten();
        let clock = cx.or(ambient.as_ref()).and_then(Cx::timer_driver);
        let now = clock.as_ref().map_or_else(
            || {
                let _ambient = Cx::set_current(None);
                crate::time::wall_now()
            },
            TimerDriverHandle::now,
        );
        Self {
            at: now.saturating_add_nanos(u64::try_from(timeout.as_nanos()).unwrap_or(u64::MAX)),
            clock,
            timed_out: Arc::new(AtomicBool::new(false)),
        }
    }

    pub(super) fn timed_out(&self) -> bool {
        self.timed_out.load(Ordering::Acquire)
    }

    /// This may invoke an injected clock, so call it outside connection locks.
    pub(super) fn elapsed(&self) -> bool {
        self.timed_out()
            || self.clock.as_ref().map_or_else(
                || {
                    let _ambient = Cx::set_current(None);
                    crate::time::wall_now()
                },
                TimerDriverHandle::now,
            ) >= self.at
    }

    pub(super) fn expire(&self) {
        self.timed_out.store(true, Ordering::Release);
    }

    pub(super) fn sleep(&self) -> Sleep {
        match &self.clock {
            Some(clock) => Sleep::with_timer_driver(self.at, clock.clone()),
            None => {
                let _ambient = Cx::set_current(None);
                Sleep::new(self.at)
            }
        }
    }

    pub(super) fn poll(&self, sleep: &mut Sleep, task: &mut Context<'_>) -> Poll<()> {
        if self.timed_out() {
            return Poll::Ready(());
        }
        let _ambient = self.clock.is_none().then(|| Cx::set_current(None));
        Pin::new(sleep).poll_deadline(task)
    }

    /// Wait with a retained deadline. Explicit operation cancellation wins
    /// over expiry; timer cancellation itself must not look like elapsed time.
    pub(super) async fn wait<T>(
        &self,
        cx: Option<&Cx>,
        future: impl Future<Output = Result<T, WsError>>,
    ) -> Result<Option<T>, WsError> {
        let mut future = std::pin::pin!(future);
        let mut sleep = self.sleep();
        let mut cancel = cx.map(super::client::WsCancelWakerGuard::new);
        poll_fn(|task| {
            if let Some(cancel) = &mut cancel {
                cancel.refresh(task.waker());
            }
            if cx.is_some_and(|cx| cx.checkpoint().is_err()) {
                return Poll::Ready(Err(WsError::Io(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "cancelled",
                ))));
            }
            if self.poll(&mut sleep, task).is_ready() {
                self.expire();
                return Poll::Ready(Ok(None));
            }
            future.as_mut().poll(task).map(|result| result.map(Some))
        })
        .await
    }
}

pub(super) fn close_timeout_error() -> WsError {
    WsError::Io(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "WebSocket close handshake timed out",
    ))
}

/// Close handshake state machine.
///
/// Tracks the state of the WebSocket close handshake and provides
/// methods for transitioning through the handshake phases.
#[derive(Debug)]
pub struct CloseHandshake {
    /// Current state of the handshake.
    state: CloseState,
    /// Configuration.
    config: CloseConfig,
    /// Our close reason (if we initiated).
    our_reason: Option<CloseReason>,
    /// Peer's close reason (if they initiated).
    peer_reason: Option<CloseReason>,
    /// Captured by the first actual close operation, not by each waiter.
    deadline: Option<CloseDeadline>,
}

impl CloseHandshake {
    /// The close reason for a connection closed because its task was
    /// cancelled: the configured [`CloseConfig::cancellation_code`]
    /// (`GoingAway` by default), or `GoingAway` if the configured code may not
    /// be sent on the wire.
    #[must_use]
    pub(crate) fn cancellation_reason(&self) -> CloseReason {
        let code = self.config.cancellation_code;
        CloseReason::new(
            if code.is_sendable() {
                code
            } else {
                CloseCode::GoingAway
            },
            None,
        )
    }

    /// Create a new close handshake tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(CloseConfig::default())
    }

    /// Create with custom configuration.
    #[must_use]
    pub fn with_config(config: CloseConfig) -> Self {
        Self {
            state: CloseState::Open,
            config,
            our_reason: None,
            peer_reason: None,
            deadline: None,
        }
    }

    /// Get the current state.
    #[must_use]
    pub const fn state(&self) -> CloseState {
        self.state
    }

    /// Check if the connection is open.
    #[must_use]
    pub const fn is_open(&self) -> bool {
        self.state.is_open()
    }

    /// Check if the close handshake is complete.
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.state.is_closed()
    }

    /// Get our close reason (if we initiated).
    #[must_use]
    pub fn our_reason(&self) -> Option<&CloseReason> {
        self.our_reason.as_ref()
    }

    /// Get peer's close reason (if they initiated).
    #[must_use]
    pub fn peer_reason(&self) -> Option<&CloseReason> {
        self.peer_reason.as_ref()
    }

    /// Get the close timeout.
    #[must_use]
    pub const fn close_timeout(&self) -> Duration {
        self.config.close_timeout
    }

    pub(super) fn deadline(&self) -> Option<CloseDeadline> {
        self.deadline.clone()
    }

    pub(super) fn start_deadline(&mut self, candidate: CloseDeadline) {
        if self.deadline.is_none() {
            self.deadline = Some(candidate);
        }
    }

    pub(super) fn timed_out(&self) -> bool {
        self.deadline.as_ref().is_some_and(CloseDeadline::timed_out)
    }

    /// Initiate a close handshake.
    ///
    /// Returns the close frame to send, or `None` if already closing/closed.
    ///
    /// # State Transitions
    ///
    /// - `Open` → `CloseSent`: Returns close frame
    /// - `CloseReceived` → `CloseReceived`: Returns close frame (response)
    ///   and waits for [`mark_response_sent`](Self::mark_response_sent)
    ///   before completing the handshake
    /// - `CloseSent` | `Closed`: Returns `None`
    pub fn initiate(&mut self, reason: CloseReason) -> Option<Frame> {
        match self.state {
            CloseState::Open => {
                self.state = CloseState::CloseSent;
                let frame = reason.to_frame();
                self.our_reason = Some(reason);
                Some(frame)
            }
            CloseState::CloseReceived => {
                // We're responding to their close. The handshake is not
                // complete until the response frame is actually sent.
                let frame = reason.to_frame();
                self.our_reason = Some(reason);
                Some(frame)
            }
            CloseState::CloseSent | CloseState::Closed => None,
        }
    }

    /// Handle a received close frame.
    ///
    /// Returns the close frame to send in response, or `None` if no response needed.
    ///
    /// # State Transitions
    ///
    /// - `Open` → `CloseReceived`: Stores peer reason, returns response frame
    /// - `CloseSent` → `Closed`: Stores peer reason, returns `None` (handshake complete)
    /// - `CloseReceived` | `Closed`: Returns `None` (duplicate/unexpected)
    pub fn receive_close(&mut self, frame: &Frame) -> Result<Option<Frame>, WsError> {
        if frame.opcode != Opcode::Close {
            return Err(WsError::InvalidOpcode(frame.opcode as u8));
        }

        let reason = CloseReason::parse(&frame.payload)?;

        match self.state {
            CloseState::Open => {
                // Peer initiated close - we need to respond
                self.state = CloseState::CloseReceived;

                // Echo the peer's status code only when it is valid for
                // transmission. Receive-only reserved codes (1016-2999) must
                // be accepted during parsing but must not be sent back.
                let response_code = reason.outbound_wire_code();
                self.peer_reason = Some(reason);
                let response = if let Some(response_code) = response_code {
                    Frame::close(Some(response_code), None)
                } else {
                    Frame::close(None, None)
                };
                Ok(Some(response))
            }
            CloseState::CloseSent => {
                // We sent close, peer is responding - handshake complete
                self.state = CloseState::Closed;
                self.peer_reason = Some(reason);
                Ok(None)
            }
            CloseState::CloseReceived | CloseState::Closed => {
                // Duplicate or unexpected close frame - ignore
                Ok(None)
            }
        }
    }

    /// Mark that the close response frame has been successfully sent.
    ///
    /// Transitions `CloseReceived` -> `Closed`. In all other states this is a no-op.
    pub fn mark_response_sent(&mut self) {
        if self.state == CloseState::CloseReceived {
            self.state = CloseState::Closed;
        }
    }

    /// Force transition to closed state.
    ///
    /// Use this when the connection is terminated without proper handshake
    /// (timeout, error, etc.).
    pub fn force_close(&mut self, reason: CloseReason) {
        self.state = CloseState::Closed;
        if self.our_reason.is_none() {
            self.our_reason = Some(reason);
        }
    }

    /// Reset to open state.
    ///
    /// This should only be used for testing or connection reuse.
    #[cfg(test)]
    pub fn reset(&mut self) {
        self.state = CloseState::Open;
        self.our_reason = None;
        self.peer_reason = None;
        self.deadline = None;
    }
}

impl Default for CloseHandshake {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "close_inline_tests.rs"]
mod tests;
