//! WebSocket close handshake protocol (RFC 6455 Section 7).
//!
//! The close handshake ensures clean connection termination with proper
//! status code propagation. The protocol is:
//!
//! 1. Initiator sends Close frame with optional status code and reason
//! 2. Receiver echoes Close frame back
//! 3. Both sides enter closed state
//!
//! # Cancel-Safety
//!
//! Close operations are designed to be cancel-safe:
//! - Bounded timeout prevents hanging on unresponsive peers
//! - Cancellation uses GoingAway (1001) status code
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
use std::time::Duration;

/// Parsed close frame payload.
///
/// A close frame may contain:
/// - No payload (empty)
/// - 2 bytes: status code only
/// - 2+ bytes: status code followed by UTF-8 reason text
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// - Payload is exactly 1 byte (invalid)
    /// - Status code is invalid/reserved for wire use
    /// - Reason text is not valid UTF-8
    pub fn parse(payload: &[u8]) -> Result<Self, WsError> {
        match payload.len() {
            0 => Ok(Self::empty()),
            1 => Err(WsError::InvalidClosePayload),
            _ => {
                let code_raw = u16::from_be_bytes([payload[0], payload[1]]);
                if !CloseCode::is_valid_code(code_raw) {
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
        let code = self.raw_code.or_else(|| self.code.map(u16::from));
        match (code, &self.text) {
            (None, _) => Bytes::new(),
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
        let code = self.raw_code.or_else(|| self.code.map(u16::from));
        Frame::close(code, self.text.as_deref())
    }

    /// Check if this represents a normal closure.
    #[must_use]
    pub fn is_normal(&self) -> bool {
        self.raw_code == Some(u16::from(CloseCode::Normal))
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
        self.raw_code
    }
}

impl Default for CloseReason {
    fn default() -> Self {
        Self::empty()
    }
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
}

impl CloseHandshake {
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

    /// Initiate a close handshake.
    ///
    /// Returns the close frame to send, or `None` if already closing/closed.
    ///
    /// # State Transitions
    ///
    /// - `Open` → `CloseSent`: Returns close frame
    /// - `CloseReceived` → `Closed`: Returns close frame (response)
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
                // We're responding to their close
                self.state = CloseState::Closed;
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
                self.peer_reason = Some(reason);

                // Echo peer code as-is when present, including custom valid
                // application codes in 3000..=4999.
                let response_code = if frame.payload.len() >= 2 {
                    u16::from_be_bytes([frame.payload[0], frame.payload[1]])
                } else {
                    u16::from(CloseCode::Normal)
                };
                Ok(Some(Frame::close(Some(response_code), None)))
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
    }
}

impl Default for CloseHandshake {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn close_reason_parse_empty() {
        let reason = CloseReason::parse(&[]).unwrap();
        assert_eq!(reason.code, None);
        assert_eq!(reason.raw_code, None);
        assert_eq!(reason.text, None);
    }

    #[test]
    fn close_reason_parse_code_only() {
        let payload = 1000u16.to_be_bytes();
        let reason = CloseReason::parse(&payload).unwrap();
        assert_eq!(reason.code, Some(CloseCode::Normal));
        assert_eq!(reason.raw_code, Some(1000));
        assert_eq!(reason.text, None);
    }

    #[test]
    fn close_reason_parse_code_and_text() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&1001u16.to_be_bytes());
        payload.extend_from_slice(b"Going away");

        let reason = CloseReason::parse(&payload).unwrap();
        assert_eq!(reason.code, Some(CloseCode::GoingAway));
        assert_eq!(reason.raw_code, Some(1001));
        assert_eq!(reason.text.as_deref(), Some("Going away"));
    }

    #[test]
    fn close_reason_parse_custom_code_preserves_raw_code() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&3001u16.to_be_bytes());
        payload.extend_from_slice(b"custom");

        let reason = CloseReason::parse(&payload).unwrap();
        assert_eq!(reason.code, None);
        assert_eq!(reason.raw_code, Some(3001));
        assert_eq!(reason.wire_code(), Some(3001));
        assert_eq!(reason.text.as_deref(), Some("custom"));
    }

    #[test]
    fn close_reason_parse_invalid_single_byte() {
        let result = CloseReason::parse(&[0x00]);
        assert!(result.is_err());
    }

    #[test]
    fn close_reason_parse_invalid_utf8() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&1000u16.to_be_bytes());
        payload.extend_from_slice(&[0xFF, 0xFE]); // Invalid UTF-8

        let result = CloseReason::parse(&payload);
        assert!(result.is_err());
    }

    #[test]
    fn close_reason_parse_invalid_reserved_code() {
        let payload = 1004u16.to_be_bytes();
        let result = CloseReason::parse(&payload);
        assert!(matches!(result, Err(WsError::InvalidClosePayload)));
    }

    #[test]
    fn close_reason_parse_invalid_unassigned_code() {
        let payload = 1012u16.to_be_bytes();
        let result = CloseReason::parse(&payload);
        assert!(matches!(result, Err(WsError::InvalidClosePayload)));
    }

    #[test]
    fn close_reason_encode_empty() {
        let reason = CloseReason::empty();
        let encoded = reason.encode();
        assert!(encoded.is_empty());
    }

    #[test]
    fn close_reason_encode_code_only() {
        let reason = CloseReason::new(CloseCode::Normal, None);
        let encoded = reason.encode();
        assert_eq!(encoded.as_ref(), &1000u16.to_be_bytes());
    }

    #[test]
    fn close_reason_encode_code_and_text() {
        let reason = CloseReason::with_text(CloseCode::GoingAway, "bye");
        let encoded = reason.encode();

        let mut expected = Vec::new();
        expected.extend_from_slice(&1001u16.to_be_bytes());
        expected.extend_from_slice(b"bye");

        assert_eq!(encoded.as_ref(), expected.as_slice());
    }

    #[test]
    fn close_reason_roundtrip() {
        let original = CloseReason::with_text(CloseCode::Normal, "goodbye");
        let encoded = original.encode();
        let parsed = CloseReason::parse(&encoded).unwrap();

        assert_eq!(original.code, parsed.code);
        assert_eq!(original.raw_code, parsed.raw_code);
        assert_eq!(original.text, parsed.text);
    }

    #[test]
    fn close_code_valid_ranges() {
        assert!(CloseCode::is_valid_code(1000));
        assert!(CloseCode::is_valid_code(1003));
        assert!(CloseCode::is_valid_code(1007));
        assert!(CloseCode::is_valid_code(1011));
        assert!(CloseCode::is_valid_code(3000));
        assert!(CloseCode::is_valid_code(4999));

        assert!(!CloseCode::is_valid_code(1004)); // Reserved
        assert!(!CloseCode::is_valid_code(1005)); // NoStatusReceived
        assert!(!CloseCode::is_valid_code(1006)); // Abnormal
        assert!(!CloseCode::is_valid_code(999)); // Below valid range
        assert!(!CloseCode::is_valid_code(5000)); // Above valid range
    }

    #[test]
    fn close_state_transitions() {
        assert!(CloseState::Open.is_open());
        assert!(!CloseState::Open.is_closed());
        assert!(!CloseState::Open.is_closing());

        assert!(!CloseState::CloseSent.is_open());
        assert!(!CloseState::CloseSent.is_closed());
        assert!(CloseState::CloseSent.is_closing());

        assert!(!CloseState::Closed.is_open());
        assert!(CloseState::Closed.is_closed());
        assert!(!CloseState::Closed.is_closing());
    }

    #[test]
    fn handshake_initiate_from_open() {
        let mut handshake = CloseHandshake::new();
        let frame = handshake.initiate(CloseReason::normal());

        assert!(frame.is_some());
        assert_eq!(handshake.state(), CloseState::CloseSent);
        assert!(handshake.our_reason().is_some());
    }

    #[test]
    fn handshake_initiate_when_already_closing() {
        let mut handshake = CloseHandshake::new();
        handshake.initiate(CloseReason::normal());

        // Second initiate should return None
        let frame = handshake.initiate(CloseReason::normal());
        assert!(frame.is_none());
    }

    #[test]
    fn handshake_receive_close_from_open() {
        let mut handshake = CloseHandshake::new();
        let close_frame = Frame::close(Some(1000), Some("bye"));

        let response = handshake.receive_close(&close_frame).unwrap();

        assert!(response.is_some());
        assert_eq!(handshake.state(), CloseState::CloseReceived);
        assert!(handshake.peer_reason().is_some());
    }

    #[test]
    fn handshake_receive_close_echoes_custom_code() {
        let mut handshake = CloseHandshake::new();
        let close_frame = Frame::close(Some(3001), Some("custom"));

        let response = handshake.receive_close(&close_frame).unwrap().unwrap();
        assert_eq!(response.opcode, Opcode::Close);
        assert_eq!(&response.payload[..2], &3001u16.to_be_bytes());
        assert_eq!(handshake.peer_reason().unwrap().wire_code(), Some(3001));
        assert_eq!(handshake.state(), CloseState::CloseReceived);
    }

    #[test]
    fn handshake_receive_close_after_sent() {
        let mut handshake = CloseHandshake::new();
        handshake.initiate(CloseReason::normal());

        let close_frame = Frame::close(Some(1000), None);
        let response = handshake.receive_close(&close_frame).unwrap();

        assert!(response.is_none()); // No response needed
        assert_eq!(handshake.state(), CloseState::Closed);
    }

    #[test]
    fn handshake_complete_flow_initiator() {
        let mut handshake = CloseHandshake::new();

        // 1. We initiate close
        let frame = handshake.initiate(CloseReason::normal());
        assert!(frame.is_some());
        assert_eq!(handshake.state(), CloseState::CloseSent);

        // 2. We receive peer's close response
        let peer_close = Frame::close(Some(1000), None);
        let response = handshake.receive_close(&peer_close).unwrap();
        assert!(response.is_none()); // Handshake complete, no response
        assert_eq!(handshake.state(), CloseState::Closed);
    }

    #[test]
    fn handshake_complete_flow_receiver() {
        let mut handshake = CloseHandshake::new();

        // 1. We receive peer's close
        let peer_close = Frame::close(Some(1000), Some("goodbye"));
        let response = handshake.receive_close(&peer_close).unwrap();
        assert!(response.is_some());
        assert_eq!(handshake.state(), CloseState::CloseReceived);

        // 2. We send our close response
        let frame = handshake.initiate(CloseReason::normal());
        assert!(frame.is_some());
        assert_eq!(handshake.state(), CloseState::Closed);
    }

    #[test]
    fn handshake_force_close() {
        let mut handshake = CloseHandshake::new();
        handshake.force_close(CloseReason::new(CloseCode::Abnormal, None));

        assert_eq!(handshake.state(), CloseState::Closed);
        assert!(handshake.our_reason().is_some());
    }

    #[test]
    fn close_config_builder() {
        let config = CloseConfig::new()
            .with_timeout(Duration::from_secs(10))
            .with_close_on_drop(false)
            .with_cancellation_code(CloseCode::InternalError);

        assert_eq!(config.close_timeout, Duration::from_secs(10));
        assert!(!config.close_on_drop);
        assert_eq!(config.cancellation_code, CloseCode::InternalError);
    }

    // =========================================================================
    // Wave 56 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn close_reason_debug_clone_eq() {
        let r = CloseReason::normal();
        let dbg = format!("{r:?}");
        assert!(dbg.contains("CloseReason"), "{dbg}");
        let cloned = r.clone();
        assert_eq!(r, cloned);
    }

    #[test]
    fn close_state_debug_clone_copy_eq_default() {
        let s = CloseState::default();
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Open"), "{dbg}");
        let copied = s;
        let cloned = s;
        assert_eq!(copied, cloned);
        assert_ne!(s, CloseState::CloseSent);
    }

    #[test]
    fn close_config_debug_clone() {
        let cfg = CloseConfig::new();
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("CloseConfig"), "{dbg}");
        let cloned = cfg.clone();
        assert_eq!(cfg.close_timeout, cloned.close_timeout);
    }
}
