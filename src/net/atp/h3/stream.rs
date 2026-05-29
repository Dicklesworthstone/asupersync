//! ATP-over-H3 stream management.

use super::{AtpH3Error, AtpH3Result};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Stream direction for ATP-over-H3.
#[derive(Debug, Clone, PartialEq)]
pub enum StreamDirection {
    /// Bidirectional stream (can send and receive).
    Bidirectional,
    /// Outbound-only stream (send only).
    Outbound,
    /// Inbound-only stream (receive only).
    Inbound,
}

/// Stream state for lifecycle management.
#[derive(Debug, Clone, PartialEq)]
pub enum StreamState {
    /// Stream is open and ready for data.
    Open,
    /// Stream is half-closed (local close sent).
    HalfClosedLocal,
    /// Stream is half-closed (remote close received).
    HalfClosedRemote,
    /// Stream is fully closed.
    Closed,
    /// Stream encountered an error.
    Error(String),
    /// Stream is being reset.
    Reset,
}

/// ATP-over-H3 stream.
#[derive(Debug)]
pub struct AtpH3Stream {
    /// Stream ID.
    stream_id: u64,
    /// Stream direction.
    direction: StreamDirection,
    /// Current stream state.
    state: StreamState,
    /// Outbound data queue.
    send_queue: VecDeque<Vec<u8>>,
    /// Inbound data buffer.
    recv_buffer: Vec<u8>,
    /// Maximum buffer size.
    max_buffer_size: usize,
    /// Stream creation time.
    created_at: Instant,
    /// Last activity timestamp.
    last_activity: Instant,
    /// Total bytes sent.
    bytes_sent: u64,
    /// Total bytes received.
    bytes_received: u64,
    /// Send queue high water mark.
    send_queue_high_water: usize,
}

impl AtpH3Stream {
    /// Create a new ATP-over-H3 stream.
    pub fn new(stream_id: u64, direction: StreamDirection) -> Self {
        let now = Instant::now();

        Self {
            stream_id,
            direction,
            state: StreamState::Open,
            send_queue: VecDeque::new(),
            recv_buffer: Vec::new(),
            max_buffer_size: 64 * 1024, // 64KB default
            created_at: now,
            last_activity: now,
            bytes_sent: 0,
            bytes_received: 0,
            send_queue_high_water: 16, // Maximum queued send operations
        }
    }

    /// Get the stream ID.
    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }

    /// Get the stream direction.
    pub fn direction(&self) -> &StreamDirection {
        &self.direction
    }

    /// Get the current stream state.
    pub fn state(&self) -> &StreamState {
        &self.state
    }

    /// Check if the stream can send data.
    pub fn can_send(&self) -> bool {
        match &self.direction {
            StreamDirection::Bidirectional | StreamDirection::Outbound => {
                matches!(
                    self.state,
                    StreamState::Open | StreamState::HalfClosedRemote
                )
            }
            StreamDirection::Inbound => false,
        }
    }

    /// Check if the stream can receive data.
    pub fn can_receive(&self) -> bool {
        match &self.direction {
            StreamDirection::Bidirectional | StreamDirection::Inbound => {
                matches!(self.state, StreamState::Open | StreamState::HalfClosedLocal)
            }
            StreamDirection::Outbound => false,
        }
    }

    /// Check if the stream is closed.
    pub fn is_closed(&self) -> bool {
        matches!(
            self.state,
            StreamState::Closed | StreamState::Error(_) | StreamState::Reset
        )
    }

    /// Send data on the stream.
    pub fn send(&mut self, data: &[u8]) -> AtpH3Result<()> {
        if !self.can_send() {
            return Err(AtpH3Error::Stream(format!(
                "Cannot send on stream {} in state {:?}",
                self.stream_id, self.state
            )));
        }

        if self.send_queue.len() >= self.send_queue_high_water {
            return Err(AtpH3Error::Stream(
                "Send queue full - apply backpressure".to_string(),
            ));
        }

        if data.len() > self.max_buffer_size {
            return Err(AtpH3Error::Stream(format!(
                "Data size {} exceeds maximum buffer size {}",
                data.len(),
                self.max_buffer_size
            )));
        }

        self.send_queue.push_back(data.to_vec());
        self.update_activity();
        Ok(())
    }

    /// Get the next chunk of data to send.
    pub fn next_send_data(&mut self) -> Option<Vec<u8>> {
        let data = self.send_queue.pop_front();
        if data.is_some() {
            self.update_activity();
        }
        data
    }

    /// Check if there is data pending to send.
    pub fn has_pending_send(&self) -> bool {
        !self.send_queue.is_empty()
    }

    /// Get the number of queued send operations.
    pub fn send_queue_len(&self) -> usize {
        self.send_queue.len()
    }

    /// Receive data on the stream.
    pub fn receive(&mut self, data: &[u8]) -> AtpH3Result<()> {
        if !self.can_receive() {
            return Err(AtpH3Error::Stream(format!(
                "Cannot receive on stream {} in state {:?}",
                self.stream_id, self.state
            )));
        }

        if self.recv_buffer.len() + data.len() > self.max_buffer_size {
            return Err(AtpH3Error::Stream(
                "Receive buffer full - apply backpressure".to_string(),
            ));
        }

        self.recv_buffer.extend_from_slice(data);
        self.bytes_received += data.len() as u64;
        self.update_activity();
        Ok(())
    }

    /// Read received data from the stream.
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let to_copy = buf.len().min(self.recv_buffer.len());
        if to_copy > 0 {
            buf[..to_copy].copy_from_slice(&self.recv_buffer[..to_copy]);
            self.recv_buffer.drain(..to_copy);
            self.update_activity();
        }
        to_copy
    }

    /// Get the amount of data available to read.
    pub fn available(&self) -> usize {
        self.recv_buffer.len()
    }

    /// Close the stream for sending.
    pub fn close_send(&mut self) -> AtpH3Result<()> {
        match self.state {
            StreamState::Open => {
                if self.direction == StreamDirection::Inbound {
                    return Err(AtpH3Error::Stream(
                        "Cannot close send on inbound-only stream".to_string(),
                    ));
                }
                self.state = StreamState::HalfClosedLocal;
                self.update_activity();
                Ok(())
            }
            StreamState::HalfClosedRemote => {
                self.state = StreamState::Closed;
                self.update_activity();
                Ok(())
            }
            _ => Err(AtpH3Error::Stream(format!(
                "Cannot close send in state {:?}",
                self.state
            ))),
        }
    }

    /// Handle remote close (peer closed their send side).
    pub fn handle_remote_close(&mut self) -> AtpH3Result<()> {
        match self.state {
            StreamState::Open => {
                self.state = StreamState::HalfClosedRemote;
                self.update_activity();
                Ok(())
            }
            StreamState::HalfClosedLocal => {
                self.state = StreamState::Closed;
                self.update_activity();
                Ok(())
            }
            _ => Ok(()), // Already closed or closing
        }
    }

    /// Close the stream immediately.
    pub fn close(&mut self) -> AtpH3Result<()> {
        self.state = StreamState::Closed;
        self.send_queue.clear();
        self.recv_buffer.clear();
        self.update_activity();
        Ok(())
    }

    /// Reset the stream due to an error.
    pub fn reset(&mut self, reason: String) -> AtpH3Result<()> {
        self.state = StreamState::Error(reason);
        self.send_queue.clear();
        self.recv_buffer.clear();
        self.update_activity();
        Ok(())
    }

    /// Handle stream reset from peer.
    pub fn handle_peer_reset(&mut self) {
        self.state = StreamState::Reset;
        self.send_queue.clear();
        self.recv_buffer.clear();
        self.update_activity();
    }

    /// Get stream statistics.
    pub fn stats(&self) -> StreamStats {
        StreamStats {
            stream_id: self.stream_id,
            direction: self.direction.clone(),
            state: self.state.clone(),
            bytes_sent: self.bytes_sent,
            bytes_received: self.bytes_received,
            send_queue_len: self.send_queue.len(),
            recv_buffer_len: self.recv_buffer.len(),
            max_buffer_size: self.max_buffer_size,
            uptime_ms: elapsed_millis_floor_one(self.created_at.elapsed()),
            idle_time_ms: elapsed_millis_floor_one(self.last_activity.elapsed()),
        }
    }

    /// Set the maximum buffer size.
    pub fn set_max_buffer_size(&mut self, size: usize) {
        self.max_buffer_size = size;
    }

    /// Set the send queue high water mark.
    pub fn set_send_queue_high_water(&mut self, count: usize) {
        self.send_queue_high_water = count;
    }

    /// Update last activity timestamp.
    fn update_activity(&mut self) {
        self.last_activity = Instant::now();
    }
}

fn elapsed_millis_floor_one(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis().max(1)).unwrap_or(u64::MAX)
}

/// Stream statistics.
#[derive(Debug, Clone)]
pub struct StreamStats {
    /// Stream ID.
    pub stream_id: u64,
    /// Stream direction.
    pub direction: StreamDirection,
    /// Current stream state.
    pub state: StreamState,
    /// Total bytes sent.
    pub bytes_sent: u64,
    /// Total bytes received.
    pub bytes_received: u64,
    /// Current send queue length.
    pub send_queue_len: usize,
    /// Current receive buffer length.
    pub recv_buffer_len: usize,
    /// Maximum buffer size.
    pub max_buffer_size: usize,
    /// Stream uptime in milliseconds.
    pub uptime_ms: u64,
    /// Idle time in milliseconds.
    pub idle_time_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_creation() {
        let stream = AtpH3Stream::new(42, StreamDirection::Bidirectional);

        assert_eq!(stream.stream_id(), 42);
        assert_eq!(stream.direction(), &StreamDirection::Bidirectional);
        assert_eq!(stream.state(), &StreamState::Open);
        assert!(stream.can_send());
        assert!(stream.can_receive());
        assert!(!stream.is_closed());
    }

    #[test]
    fn test_stream_direction_capabilities() {
        let mut bi_stream = AtpH3Stream::new(0, StreamDirection::Bidirectional);
        let mut out_stream = AtpH3Stream::new(4, StreamDirection::Outbound);
        let mut in_stream = AtpH3Stream::new(8, StreamDirection::Inbound);

        // Bidirectional can send and receive
        assert!(bi_stream.can_send());
        assert!(bi_stream.can_receive());

        // Outbound can only send
        assert!(out_stream.can_send());
        assert!(!out_stream.can_receive());

        // Inbound can only receive
        assert!(!in_stream.can_send());
        assert!(in_stream.can_receive());

        // Test actual operations
        assert!(bi_stream.send(b"test").is_ok());
        assert!(bi_stream.receive(b"response").is_ok());

        assert!(out_stream.send(b"test").is_ok());
        assert!(out_stream.receive(b"response").is_err());

        assert!(in_stream.send(b"test").is_err());
        assert!(in_stream.receive(b"response").is_ok());
    }

    #[test]
    fn test_stream_send_receive() {
        let mut stream = AtpH3Stream::new(0, StreamDirection::Bidirectional);

        // Send data
        assert!(stream.send(b"hello").is_ok());
        assert!(stream.has_pending_send());
        assert_eq!(stream.send_queue_len(), 1);

        // Get data to send
        let data = stream.next_send_data().unwrap();
        assert_eq!(data, b"hello");
        assert!(!stream.has_pending_send());

        // Receive data
        assert!(stream.receive(b"world").is_ok());
        assert_eq!(stream.available(), 5);

        // Read received data
        let mut buf = [0u8; 10];
        let read = stream.read(&mut buf);
        assert_eq!(read, 5);
        assert_eq!(&buf[..read], b"world");
        assert_eq!(stream.available(), 0);
    }

    #[test]
    fn test_stream_buffer_limits() {
        let mut stream = AtpH3Stream::new(0, StreamDirection::Bidirectional);
        stream.set_max_buffer_size(100);
        stream.set_send_queue_high_water(2);

        // Fill send queue
        assert!(stream.send(b"data1").is_ok());
        assert!(stream.send(b"data2").is_ok());
        assert!(stream.send(b"data3").is_err()); // Queue full

        // Fill receive buffer
        let large_data = vec![0u8; 150];
        assert!(stream.receive(&large_data).is_err()); // Buffer too small
    }

    #[test]
    fn test_stream_close_lifecycle() {
        let mut stream = AtpH3Stream::new(0, StreamDirection::Bidirectional);

        // Close sending side
        assert!(stream.close_send().is_ok());
        assert_eq!(stream.state(), &StreamState::HalfClosedLocal);
        assert!(!stream.can_send());
        assert!(stream.can_receive());

        // Remote closes their side
        assert!(stream.handle_remote_close().is_ok());
        assert_eq!(stream.state(), &StreamState::Closed);
        assert!(!stream.can_send());
        assert!(!stream.can_receive());
        assert!(stream.is_closed());
    }

    #[test]
    fn test_stream_reset() {
        let mut stream = AtpH3Stream::new(0, StreamDirection::Bidirectional);

        // Add some data
        assert!(stream.send(b"test").is_ok());
        assert!(stream.receive(b"data").is_ok());

        // Reset stream
        assert!(stream.reset("Test reset".to_string()).is_ok());
        assert!(matches!(stream.state(), StreamState::Error(_)));
        assert!(stream.is_closed());
        assert_eq!(stream.send_queue_len(), 0);
        assert_eq!(stream.available(), 0);

        // Cannot send/receive after reset
        assert!(stream.send(b"more").is_err());
        assert!(stream.receive(b"more").is_err());
    }

    #[test]
    fn test_peer_reset() {
        let mut stream = AtpH3Stream::new(0, StreamDirection::Bidirectional);

        assert!(stream.send(b"test").is_ok());
        assert!(stream.receive(b"data").is_ok());

        stream.handle_peer_reset();
        assert_eq!(stream.state(), &StreamState::Reset);
        assert!(stream.is_closed());
        assert_eq!(stream.send_queue_len(), 0);
        assert_eq!(stream.available(), 0);
    }

    #[test]
    fn test_stream_stats() {
        let mut stream = AtpH3Stream::new(42, StreamDirection::Bidirectional);

        assert!(stream.send(b"hello").is_ok());
        assert!(stream.receive(b"world").is_ok());

        let stats = stream.stats();
        assert_eq!(stats.stream_id, 42);
        assert_eq!(stats.direction, StreamDirection::Bidirectional);
        assert_eq!(stats.state, StreamState::Open);
        assert_eq!(stats.bytes_received, 5);
        assert_eq!(stats.send_queue_len, 1);
        assert_eq!(stats.recv_buffer_len, 5);
        assert!(stats.uptime_ms > 0);
    }

    #[test]
    fn test_inbound_stream_close_restrictions() {
        let mut stream = AtpH3Stream::new(0, StreamDirection::Inbound);

        // Cannot close send on inbound-only stream
        assert!(stream.close_send().is_err());

        // But can handle remote close
        assert!(stream.handle_remote_close().is_ok());
        assert_eq!(stream.state(), &StreamState::HalfClosedRemote);
    }
}
