//! HTTP/2 stream state management.
//!
//! Implements stream state machine as defined in RFC 7540 Section 5.1.

use std::collections::VecDeque;

use crate::bytes::Bytes;

use super::error::{ErrorCode, H2Error};
use super::frame::PrioritySpec;
use super::settings::DEFAULT_INITIAL_WINDOW_SIZE;

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
    /// Priority specification.
    priority: PrioritySpec,
    /// Pending data to send (buffered due to flow control).
    pending_data: VecDeque<PendingData>,
    /// Error code if stream was reset.
    error_code: Option<ErrorCode>,
    /// Whether we've received END_HEADERS.
    headers_complete: bool,
    /// Accumulated header block fragments.
    header_fragments: Vec<Bytes>,
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
    pub fn new(id: u32, initial_window_size: u32) -> Self {
        let initial_send_window =
            i32::try_from(initial_window_size).expect("initial window size exceeds i32");
        let default_recv_window =
            i32::try_from(DEFAULT_INITIAL_WINDOW_SIZE).expect("default window size exceeds i32");
        Self {
            id,
            state: StreamState::Idle,
            send_window: initial_send_window,
            recv_window: default_recv_window,
            initial_send_window,
            initial_recv_window: default_recv_window,
            priority: PrioritySpec {
                exclusive: false,
                dependency: 0,
                weight: 16,
            },
            pending_data: VecDeque::new(),
            error_code: None,
            headers_complete: true,
            header_fragments: Vec::new(),
        }
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

    /// Update send window size.
    pub fn update_send_window(&mut self, delta: i32) -> Result<(), H2Error> {
        // Check for overflow using wider arithmetic
        let new_window = i64::from(self.send_window) + i64::from(delta);
        let new_window =
            i32::try_from(new_window).map_err(|_| H2Error::flow_control("window size overflow"))?;
        self.send_window = new_window;
        Ok(())
    }

    /// Update receive window size.
    pub fn update_recv_window(&mut self, delta: i32) -> Result<(), H2Error> {
        // Check for overflow using wider arithmetic
        let new_window = i64::from(self.recv_window) + i64::from(delta);
        let new_window =
            i32::try_from(new_window).map_err(|_| H2Error::flow_control("window size overflow"))?;
        self.recv_window = new_window;
        Ok(())
    }

    /// Consume from send window (for sending data).
    pub fn consume_send_window(&mut self, amount: u32) {
        let amount = i32::try_from(amount).expect("window size exceeds i32");
        self.send_window -= amount;
    }

    /// Consume from receive window (for receiving data).
    pub fn consume_recv_window(&mut self, amount: u32) {
        let amount = i32::try_from(amount).expect("window size exceeds i32");
        self.recv_window -= amount;
    }

    /// Check if the receive window is low enough to warrant an automatic WINDOW_UPDATE.
    ///
    /// Returns `Some(increment)` when the recv window has dropped below 50% of
    /// its initial value. The increment replenishes the window back to its initial size.
    #[must_use]
    pub fn auto_window_update_increment(&self) -> Option<u32> {
        let low_watermark = self.initial_recv_window / 2;
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
            _ => Err(H2Error::stream(
                self.id,
                ErrorCode::StreamClosed,
                "cannot send headers in current state",
            )),
        }
    }

    /// Transition state on receiving headers.
    pub fn recv_headers(&mut self, end_stream: bool, end_headers: bool) -> Result<(), H2Error> {
        self.headers_complete = end_headers;

        match self.state {
            StreamState::Idle => {
                self.state = if end_stream {
                    StreamState::HalfClosedRemote
                } else {
                    StreamState::Open
                };
                Ok(())
            }
            StreamState::ReservedRemote => {
                self.state = if end_stream {
                    StreamState::Closed
                } else {
                    StreamState::HalfClosedLocal
                };
                Ok(())
            }
            StreamState::Open if end_stream => {
                self.state = StreamState::HalfClosedRemote;
                Ok(())
            }
            StreamState::HalfClosedLocal if end_stream => {
                self.state = StreamState::Closed;
                Ok(())
            }
            _ => Err(H2Error::stream(
                self.id,
                ErrorCode::StreamClosed,
                "cannot receive headers in current state",
            )),
        }
    }

    /// Process CONTINUATION frame.
    pub fn recv_continuation(
        &mut self,
        header_block: Bytes,
        end_headers: bool,
    ) -> Result<(), H2Error> {
        if self.headers_complete {
            return Err(H2Error::stream(
                self.id,
                ErrorCode::ProtocolError,
                "unexpected CONTINUATION frame",
            ));
        }

        self.header_fragments.push(header_block);
        self.headers_complete = end_headers;
        Ok(())
    }

    /// Take accumulated header fragments.
    pub fn take_header_fragments(&mut self) -> Vec<Bytes> {
        std::mem::take(&mut self.header_fragments)
    }

    /// Add header fragment for accumulation.
    pub fn add_header_fragment(&mut self, fragment: Bytes) {
        self.header_fragments.push(fragment);
    }

    /// Transition state on sending data.
    pub fn send_data(&mut self, end_stream: bool) -> Result<(), H2Error> {
        if !self.state.can_send() {
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
        if !self.state.can_recv() {
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

        self.consume_recv_window(len);

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
    }

    /// Queue data for sending (when flow control blocks).
    pub fn queue_data(&mut self, data: Bytes, end_stream: bool) {
        self.pending_data
            .push_back(PendingData { data, end_stream });
    }

    /// Take pending data that fits in the window.
    pub fn take_pending_data(&mut self, max_len: usize) -> Option<(Bytes, bool)> {
        if let Some(front) = self.pending_data.front_mut() {
            if front.data.len() <= max_len {
                // Take entire chunk
                let pending = self.pending_data.pop_front().unwrap();
                Some((pending.data, pending.end_stream))
            } else {
                // Take partial chunk
                let data = front.data.slice(..max_len);
                front.data = front.data.slice(max_len..);
                Some((data, false))
            }
        } else {
            None
        }
    }
}

/// Stream store for managing multiple streams.
#[derive(Debug)]
pub struct StreamStore {
    streams: std::collections::HashMap<u32, Stream>,
    /// Next client-initiated stream ID (odd).
    next_client_stream_id: u32,
    /// Next server-initiated stream ID (even).
    next_server_stream_id: u32,
    /// Maximum concurrent streams.
    max_concurrent_streams: u32,
    /// Initial window size for new streams.
    initial_window_size: u32,
    /// Whether this is a client (for stream ID assignment).
    is_client: bool,
}

impl StreamStore {
    /// Create a new stream store.
    #[must_use]
    pub fn new(is_client: bool, initial_window_size: u32) -> Self {
        Self {
            streams: std::collections::HashMap::new(),
            next_client_stream_id: 1,
            next_server_stream_id: 2,
            max_concurrent_streams: u32::MAX,
            initial_window_size,
            is_client,
        }
    }

    /// Set the maximum concurrent streams.
    pub fn set_max_concurrent_streams(&mut self, max: u32) {
        self.max_concurrent_streams = max;
    }

    /// Set the initial window size for new streams.
    pub fn set_initial_window_size(&mut self, size: u32) -> Result<(), H2Error> {
        // Update existing streams
        for stream in self.streams.values_mut() {
            stream.update_initial_window_size(size)?;
        }
        self.initial_window_size = size;
        Ok(())
    }

    /// Get the initial window size.
    #[must_use]
    pub fn initial_window_size(&self) -> u32 {
        self.initial_window_size
    }

    /// Get a stream by ID.
    #[must_use]
    pub fn get(&self, id: u32) -> Option<&Stream> {
        self.streams.get(&id)
    }

    /// Get a mutable stream by ID.
    #[must_use]
    pub fn get_mut(&mut self, id: u32) -> Option<&mut Stream> {
        self.streams.get_mut(&id)
    }

    /// Get or create a stream.
    pub fn get_or_create(&mut self, id: u32) -> Result<&mut Stream, H2Error> {
        if !self.streams.contains_key(&id) {
            // Validate stream ID
            if id == 0 {
                return Err(H2Error::protocol("stream ID 0 is reserved"));
            }

            let is_client_stream = id % 2 == 1;
            if self.is_client && !is_client_stream {
                // Server-initiated stream received by client
                if id < self.next_server_stream_id {
                    return Err(H2Error::protocol("stream ID already used"));
                }
                self.next_server_stream_id = id + 2;
            } else if !self.is_client && is_client_stream {
                // Client-initiated stream received by server
                if id < self.next_client_stream_id {
                    return Err(H2Error::protocol("stream ID already used"));
                }
                self.next_client_stream_id = id + 2;
            }

            let stream = Stream::new(id, self.initial_window_size);
            self.streams.insert(id, stream);
        }
        Ok(self.streams.get_mut(&id).unwrap())
    }

    /// Allocate a new stream ID.
    pub fn allocate_stream_id(&mut self) -> Result<u32, H2Error> {
        let active_count = self
            .streams
            .values()
            .filter(|s| !s.state.is_closed())
            .count() as u32;
        if active_count >= self.max_concurrent_streams {
            return Err(H2Error::protocol("max concurrent streams exceeded"));
        }

        let id = if self.is_client {
            let id = self.next_client_stream_id;
            self.next_client_stream_id += 2;
            id
        } else {
            let id = self.next_server_stream_id;
            self.next_server_stream_id += 2;
            id
        };

        let stream = Stream::new(id, self.initial_window_size);
        self.streams.insert(id, stream);
        Ok(id)
    }

    /// Remove closed streams.
    pub fn prune_closed(&mut self) {
        self.streams.retain(|_, stream| !stream.state.is_closed());
    }

    /// Get all active stream IDs.
    #[must_use]
    pub fn active_stream_ids(&self) -> Vec<u32> {
        self.streams
            .iter()
            .filter(|(_, s)| !s.state.is_closed())
            .map(|(&id, _)| id)
            .collect()
    }

    /// Get count of active streams.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.streams
            .values()
            .filter(|s| !s.state.is_closed())
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_state_transitions() {
        let mut stream = Stream::new(1, 65535);
        assert_eq!(stream.state(), StreamState::Idle);

        // Send headers (no end_stream)
        stream.send_headers(false).unwrap();
        assert_eq!(stream.state(), StreamState::Open);

        // Receive data with end_stream
        stream.recv_data(100, true).unwrap();
        assert_eq!(stream.state(), StreamState::HalfClosedRemote);

        // Send data with end_stream
        stream.send_data(true).unwrap();
        assert_eq!(stream.state(), StreamState::Closed);
    }

    #[test]
    fn test_stream_flow_control() {
        let mut stream = Stream::new(1, 65535);
        assert_eq!(stream.send_window(), 65535);

        stream.consume_send_window(1000);
        assert_eq!(stream.send_window(), 64535);

        stream.update_send_window(500).unwrap();
        assert_eq!(stream.send_window(), 65035);
    }

    #[test]
    fn test_stream_store_allocation() {
        let mut store = StreamStore::new(true, 65535);

        let id1 = store.allocate_stream_id().unwrap();
        assert_eq!(id1, 1);

        let id2 = store.allocate_stream_id().unwrap();
        assert_eq!(id2, 3);

        let id3 = store.allocate_stream_id().unwrap();
        assert_eq!(id3, 5);
    }

    #[test]
    fn test_stream_store_max_concurrent() {
        let mut store = StreamStore::new(true, 65535);
        store.set_max_concurrent_streams(2);

        store.allocate_stream_id().unwrap();
        store.allocate_stream_id().unwrap();

        // Third should fail
        assert!(store.allocate_stream_id().is_err());

        // Close one stream
        store.get_mut(1).unwrap().reset(ErrorCode::NoError);
        store.prune_closed();

        // Now we can allocate again
        assert!(store.allocate_stream_id().is_ok());
    }
}
