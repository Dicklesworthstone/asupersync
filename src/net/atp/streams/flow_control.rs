//! Stream Flow Control
//!
//! Implements QUIC stream-level and connection-level flow control with
//! credit-based windows and backpressure handling.

use super::{StreamError, StreamId};
use crate::types::outcome::Outcome;
use std::collections::HashMap;

/// Flow control window for a stream
#[derive(Debug, Clone)]
pub struct FlowControlWindow {
    /// Current send window (bytes we can send)
    send_window: u64,
    /// Maximum send window
    max_send_window: u64,
    /// Current receive window (bytes we can receive)
    receive_window: u64,
    /// Maximum receive window
    max_receive_window: u64,
    /// Bytes sent so far
    bytes_sent: u64,
    /// Bytes received so far
    bytes_received: u64,
    /// Bytes acknowledged by peer
    bytes_acked: u64,
    /// Whether the stream is blocked on flow control
    send_blocked: bool,
    /// Whether we've sent MAX_STREAM_DATA
    max_data_sent: bool,
}

impl FlowControlWindow {
    /// Create a new flow control window
    pub fn new(initial_send_window: u64, initial_receive_window: u64) -> Self {
        Self {
            send_window: initial_send_window,
            max_send_window: initial_send_window,
            receive_window: initial_receive_window,
            max_receive_window: initial_receive_window,
            bytes_sent: 0,
            bytes_received: 0,
            bytes_acked: 0,
            send_blocked: false,
            max_data_sent: false,
        }
    }

    /// Check if we can send the given number of bytes
    pub fn can_send(&self, bytes: u64) -> bool {
        self.bytes_sent + bytes <= self.send_window && !self.send_blocked
    }

    /// Reserve bytes for sending (call before actually sending)
    pub fn reserve_send(&mut self, bytes: u64) -> Outcome<(), StreamError> {
        if !self.can_send(bytes) {
            self.send_blocked = true;
            return Outcome::err(StreamError::FlowControlViolation {
                stream_id: StreamId::new(0), // Will be filled in by caller
                limit: self.send_window,
                attempted: self.bytes_sent + bytes,
            });
        }

        self.bytes_sent += bytes;
        Outcome::ok(())
    }

    /// Check if we can receive the given number of bytes
    pub fn can_receive(&self, bytes: u64) -> bool {
        self.bytes_received + bytes <= self.receive_window
    }

    /// Record bytes received
    pub fn record_received(&mut self, bytes: u64) -> Outcome<(), StreamError> {
        if !self.can_receive(bytes) {
            return Outcome::err(StreamError::FlowControlViolation {
                stream_id: StreamId::new(0), // Will be filled in by caller
                limit: self.receive_window,
                attempted: self.bytes_received + bytes,
            });
        }

        self.bytes_received += bytes;
        Outcome::ok(())
    }

    /// Update send window based on MAX_STREAM_DATA from peer
    pub fn update_send_window(&mut self, new_limit: u64) {
        if new_limit > self.send_window {
            self.send_window = new_limit;
            self.max_send_window = new_limit;
            self.send_blocked = false;
        }
    }

    /// Update receive window (increase our limit)
    pub fn update_receive_window(&mut self, new_limit: u64) {
        if new_limit > self.receive_window {
            self.receive_window = new_limit;
            self.max_receive_window = new_limit;
            self.max_data_sent = false; // Need to send new MAX_STREAM_DATA
        }
    }

    /// Record bytes acknowledged by peer
    pub fn record_acked(&mut self, bytes: u64) {
        self.bytes_acked += bytes;
    }

    /// Check if we need to send MAX_STREAM_DATA to peer
    pub fn should_send_max_data(&self) -> bool {
        !self.max_data_sent && self.receive_window > self.bytes_received
    }

    /// Mark that we sent MAX_STREAM_DATA
    pub fn mark_max_data_sent(&mut self) {
        self.max_data_sent = true;
    }

    /// Get current flow control statistics
    pub fn statistics(&self) -> FlowControlStats {
        FlowControlStats {
            send_window: self.send_window,
            receive_window: self.receive_window,
            bytes_sent: self.bytes_sent,
            bytes_received: self.bytes_received,
            bytes_acked: self.bytes_acked,
            send_blocked: self.send_blocked,
        }
    }

    /// Check if stream is blocked on send
    pub fn is_send_blocked(&self) -> bool {
        self.send_blocked
    }

    /// Get available send capacity
    pub fn send_capacity(&self) -> u64 {
        self.send_window.saturating_sub(self.bytes_sent)
    }

    /// Get remaining receive capacity (window - received)
    pub fn receive_capacity(&self) -> u64 {
        self.receive_window.saturating_sub(self.bytes_received)
    }
}

/// Connection-level flow control manager
#[derive(Debug)]
pub struct ConnectionFlowControl {
    /// Per-stream flow control windows
    stream_windows: HashMap<StreamId, FlowControlWindow>,
    /// Connection-level send window
    connection_send_window: u64,
    /// Connection-level receive window
    connection_receive_window: u64,
    /// Total bytes sent on connection
    connection_bytes_sent: u64,
    /// Total bytes received on connection
    connection_bytes_received: u64,
    /// Connection blocked on flow control
    connection_send_blocked: bool,
    /// Default initial stream window
    default_stream_window: u64,
}

impl ConnectionFlowControl {
    /// Create a new connection flow control manager
    pub fn new(initial_connection_window: u64, initial_stream_window: u64) -> Self {
        Self {
            stream_windows: HashMap::new(),
            connection_send_window: initial_connection_window,
            connection_receive_window: initial_connection_window,
            connection_bytes_sent: 0,
            connection_bytes_received: 0,
            connection_send_blocked: false,
            default_stream_window: initial_stream_window,
        }
    }

    /// Initialize flow control for a new stream
    pub fn init_stream(&mut self, stream_id: StreamId) {
        let window = FlowControlWindow::new(self.default_stream_window, self.default_stream_window);
        self.stream_windows.insert(stream_id, window);
    }

    /// Check if we can send bytes on a stream
    pub fn can_send(&self, stream_id: StreamId, bytes: u64) -> bool {
        if self.connection_send_blocked {
            return false;
        }

        if self.connection_bytes_sent + bytes > self.connection_send_window {
            return false;
        }

        if let Some(window) = self.stream_windows.get(&stream_id) {
            window.can_send(bytes)
        } else {
            false
        }
    }

    /// Reserve bytes for sending (both stream and connection level)
    pub fn reserve_send(&mut self, stream_id: StreamId, bytes: u64) -> Outcome<(), StreamError> {
        // Check connection-level limit first
        if self.connection_bytes_sent + bytes > self.connection_send_window {
            self.connection_send_blocked = true;
            return Outcome::err(StreamError::FlowControlViolation {
                stream_id,
                limit: self.connection_send_window,
                attempted: self.connection_bytes_sent + bytes,
            });
        }

        // Check stream-level limit
        if let Some(window) = self.stream_windows.get_mut(&stream_id) {
            match window.reserve_send(bytes) {
                Outcome::Ok(()) => {
                    self.connection_bytes_sent += bytes;
                    Outcome::ok(())
                }
                Outcome::Err(mut error) => {
                    // Fill in the stream ID
                    if let StreamError::FlowControlViolation {
                        stream_id: ref mut sid,
                        ..
                    } = error
                    {
                        *sid = stream_id;
                    }
                    Outcome::err(error)
                }
                Outcome::Cancelled(reason) => Outcome::cancelled(reason),
                Outcome::Panicked(payload) => Outcome::panicked(payload),
            }
        } else {
            Outcome::err(StreamError::StreamNotFound { stream_id })
        }
    }

    /// Record bytes received on a stream
    pub fn record_received(&mut self, stream_id: StreamId, bytes: u64) -> Outcome<(), StreamError> {
        // Check connection-level limit
        if self.connection_bytes_received + bytes > self.connection_receive_window {
            return Outcome::err(StreamError::FlowControlViolation {
                stream_id,
                limit: self.connection_receive_window,
                attempted: self.connection_bytes_received + bytes,
            });
        }

        // Check stream-level limit
        if let Some(window) = self.stream_windows.get_mut(&stream_id) {
            match window.record_received(bytes) {
                Outcome::Ok(()) => {
                    self.connection_bytes_received += bytes;
                    Outcome::ok(())
                }
                Outcome::Err(mut error) => {
                    // Fill in the stream ID
                    if let StreamError::FlowControlViolation {
                        stream_id: ref mut sid,
                        ..
                    } = error
                    {
                        *sid = stream_id;
                    }
                    Outcome::err(error)
                }
                Outcome::Cancelled(reason) => Outcome::cancelled(reason),
                Outcome::Panicked(payload) => Outcome::panicked(payload),
            }
        } else {
            Outcome::err(StreamError::StreamNotFound { stream_id })
        }
    }

    /// Update connection send window
    pub fn update_connection_send_window(&mut self, new_limit: u64) {
        if new_limit > self.connection_send_window {
            self.connection_send_window = new_limit;
            self.connection_send_blocked = false;
        }
    }

    /// Update stream send window
    pub fn update_stream_send_window(&mut self, stream_id: StreamId, new_limit: u64) {
        if let Some(window) = self.stream_windows.get_mut(&stream_id) {
            window.update_send_window(new_limit);
        }
    }

    /// Get streams that need MAX_STREAM_DATA updates
    pub fn streams_needing_max_data(&self) -> Vec<StreamId> {
        self.stream_windows
            .iter()
            .filter(|(_, window)| window.should_send_max_data())
            .map(|(&stream_id, _)| stream_id)
            .collect()
    }

    /// Get flow control window for a stream
    pub fn get_stream_window(&self, stream_id: StreamId) -> Option<&FlowControlWindow> {
        self.stream_windows.get(&stream_id)
    }

    /// Get mutable flow control window for a stream
    pub fn get_stream_window_mut(&mut self, stream_id: StreamId) -> Option<&mut FlowControlWindow> {
        self.stream_windows.get_mut(&stream_id)
    }

    /// Remove flow control for a closed stream
    pub fn remove_stream(&mut self, stream_id: StreamId) {
        self.stream_windows.remove(&stream_id);
    }

    /// Get connection flow control statistics
    pub fn connection_statistics(&self) -> ConnectionFlowStats {
        ConnectionFlowStats {
            connection_send_window: self.connection_send_window,
            connection_receive_window: self.connection_receive_window,
            connection_bytes_sent: self.connection_bytes_sent,
            connection_bytes_received: self.connection_bytes_received,
            connection_send_blocked: self.connection_send_blocked,
            active_streams: self.stream_windows.len(),
        }
    }
}

/// Flow control statistics for a stream
#[derive(Debug, Clone)]
pub struct FlowControlStats {
    pub send_window: u64,
    pub receive_window: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub bytes_acked: u64,
    pub send_blocked: bool,
}

/// Connection flow control statistics
#[derive(Debug, Clone)]
pub struct ConnectionFlowStats {
    pub connection_send_window: u64,
    pub connection_receive_window: u64,
    pub connection_bytes_sent: u64,
    pub connection_bytes_received: u64,
    pub connection_send_blocked: bool,
    pub active_streams: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flow_control_window_basic() {
        let mut window = FlowControlWindow::new(1000, 1000);

        assert!(window.can_send(500));
        assert!(window.reserve_send(500).is_ok());
        assert_eq!(window.send_capacity(), 500);

        assert!(window.can_receive(300));
        assert!(window.record_received(300).is_ok());
        assert_eq!(window.receive_capacity(), 700);
    }

    #[test]
    fn test_flow_control_window_violation() {
        let mut window = FlowControlWindow::new(100, 100);

        // Should fail to send more than window allows
        let result = window.reserve_send(150);
        assert!(result.is_err());
        assert!(window.is_send_blocked());
    }

    #[test]
    fn test_connection_flow_control() {
        let mut flow_control = ConnectionFlowControl::new(10000, 1000);
        let stream_id = StreamId::new(0);

        flow_control.init_stream(stream_id);

        assert!(flow_control.can_send(stream_id, 500));
        assert!(flow_control.reserve_send(stream_id, 500).is_ok());

        // Should fail if stream doesn't exist
        let nonexistent_stream = StreamId::new(100);
        assert!(!flow_control.can_send(nonexistent_stream, 100));
    }
}
