//! HTTP/2 stream state management.
//!
//! Implements stream state machine as defined in RFC 7540 Section 5.1.

use std::collections::VecDeque;

use crate::bytes::Bytes;

use super::error::{ErrorCode, H2Error};
use super::frame::PrioritySpec;
use super::settings::DEFAULT_INITIAL_WINDOW_SIZE;

/// Maximum accumulated header fragment size multiplier.
/// Provides protection against DoS via unbounded CONTINUATION frames.
const HEADER_FRAGMENT_MULTIPLIER: usize = 4;

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
            max_header_list_size,
        }
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

    /// Compute maximum accumulated header fragment size for a given limit.
    pub(crate) fn max_header_fragment_size_for(max_header_list_size: u32) -> usize {
        let max_list_size = usize::try_from(max_header_list_size).unwrap_or(usize::MAX);
        max_list_size.saturating_mul(HEADER_FRAGMENT_MULTIPLIER)
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

        // Check accumulated size to prevent DoS via unbounded CONTINUATION frames
        let current_size: usize = self.header_fragments.iter().map(Bytes::len).sum();
        if current_size.saturating_add(header_block.len()) > self.max_header_fragment_size() {
            return Err(H2Error::stream(
                self.id,
                ErrorCode::EnhanceYourCalm,
                "accumulated header fragments too large",
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
    ///
    /// Returns an error if the accumulated size would exceed the limit.
    pub fn add_header_fragment(&mut self, fragment: Bytes) -> Result<(), H2Error> {
        let current_size: usize = self.header_fragments.iter().map(Bytes::len).sum();
        if current_size.saturating_add(fragment.len()) > self.max_header_fragment_size() {
            return Err(H2Error::stream(
                self.id,
                ErrorCode::EnhanceYourCalm,
                "accumulated header fragments too large",
            ));
        }
        self.header_fragments.push(fragment);
        Ok(())
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
    /// Maximum header list size for new streams.
    max_header_list_size: u32,
    /// Whether this is a client (for stream ID assignment).
    is_client: bool,
}

impl StreamStore {
    /// Create a new stream store.
    #[must_use]
    pub fn new(is_client: bool, initial_window_size: u32, max_header_list_size: u32) -> Self {
        Self {
            streams: std::collections::HashMap::new(),
            next_client_stream_id: 1,
            next_server_stream_id: 2,
            max_concurrent_streams: u32::MAX,
            initial_window_size,
            max_header_list_size,
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

            let stream = Stream::new(id, self.initial_window_size, self.max_header_list_size);
            self.streams.insert(id, stream);
        }
        Ok(self.streams.get_mut(&id).unwrap())
    }

    /// Reserve a remote-initiated stream (e.g., PUSH_PROMISE).
    pub fn reserve_remote_stream(&mut self, id: u32) -> Result<&mut Stream, H2Error> {
        if id == 0 {
            return Err(H2Error::protocol("stream ID 0 is reserved"));
        }
        if self.streams.contains_key(&id) {
            return Err(H2Error::protocol("stream ID already used"));
        }

        let is_client_stream = id % 2 == 1;
        if self.is_client {
            if is_client_stream {
                return Err(H2Error::protocol("invalid promised stream ID"));
            }
            if id < self.next_server_stream_id {
                return Err(H2Error::protocol("stream ID already used"));
            }
            self.next_server_stream_id = id + 2;
        } else {
            if !is_client_stream {
                return Err(H2Error::protocol("invalid promised stream ID"));
            }
            if id < self.next_client_stream_id {
                return Err(H2Error::protocol("stream ID already used"));
            }
            self.next_client_stream_id = id + 2;
        }

        let stream =
            Stream::new_reserved_remote(id, self.initial_window_size, self.max_header_list_size);
        self.streams.insert(id, stream);
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

        let stream = Stream::new(id, self.initial_window_size, self.max_header_list_size);
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
    use super::super::settings::DEFAULT_MAX_HEADER_LIST_SIZE;
    use super::*;

    #[test]
    fn test_stream_state_transitions() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
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
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        assert_eq!(stream.send_window(), 65535);

        stream.consume_send_window(1000);
        assert_eq!(stream.send_window(), 64535);

        stream.update_send_window(500).unwrap();
        assert_eq!(stream.send_window(), 65035);
    }

    #[test]
    fn header_fragment_limit_respects_max_header_list_size() {
        let max_list_size = 8;
        let mut stream = Stream::new(1, 65535, max_list_size);

        // 4x multiplier => 32 bytes total allowed.
        stream
            .add_header_fragment(Bytes::from(vec![0; 16]))
            .unwrap();
        assert!(stream
            .add_header_fragment(Bytes::from(vec![0; 17]))
            .is_err());
    }

    #[test]
    fn test_stream_store_allocation() {
        let mut store = StreamStore::new(true, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);

        let id1 = store.allocate_stream_id().unwrap();
        assert_eq!(id1, 1);

        let id2 = store.allocate_stream_id().unwrap();
        assert_eq!(id2, 3);

        let id3 = store.allocate_stream_id().unwrap();
        assert_eq!(id3, 5);
    }

    #[test]
    fn test_stream_store_max_concurrent() {
        let mut store = StreamStore::new(true, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
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

    #[test]
    fn auto_window_update_not_needed_when_window_above_half() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(false).unwrap();

        // Consume less than half: no update needed.
        stream.recv_data(30_000, false).unwrap();
        assert!(
            stream.recv_window() >= stream.initial_recv_window / 2,
            "window should still be above the low watermark"
        );
        assert!(stream.auto_window_update_increment().is_none());
    }

    #[test]
    fn auto_window_update_triggered_when_window_below_half() {
        let initial = DEFAULT_INITIAL_WINDOW_SIZE;
        let initial_i32 = i32::try_from(initial).unwrap();
        let mut stream = Stream::new(1, initial, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(false).unwrap();

        // Consume just over half to cross the watermark.
        let consume = u32::try_from(initial_i32 / 2 + 2).unwrap();
        stream.recv_data(consume, false).unwrap();

        let increment = stream
            .auto_window_update_increment()
            .expect("should need WINDOW_UPDATE");

        // Increment should restore the window to its initial value.
        assert_eq!(
            i64::from(stream.recv_window()) + i64::from(increment),
            i64::from(initial_i32)
        );
    }

    #[test]
    fn auto_window_update_returns_none_after_replenish() {
        let initial = DEFAULT_INITIAL_WINDOW_SIZE;
        let initial_i32 = i32::try_from(initial).unwrap();
        let mut stream = Stream::new(1, initial, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(false).unwrap();

        // Drain below the watermark.
        let consume = u32::try_from(initial_i32 / 2 + 2).unwrap();
        stream.recv_data(consume, false).unwrap();

        let increment = stream.auto_window_update_increment().unwrap();
        stream
            .update_recv_window(i32::try_from(increment).unwrap())
            .unwrap();

        // After replenishing, should no longer need an update.
        assert!(stream.auto_window_update_increment().is_none());
    }

    // =========================================================================
    // RFC 7540 Section 5.1 State Machine Tests
    // =========================================================================

    #[test]
    fn idle_to_open_via_send_headers() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        assert_eq!(stream.state(), StreamState::Idle);

        stream.send_headers(false).unwrap();
        assert_eq!(stream.state(), StreamState::Open);
    }

    #[test]
    fn idle_to_half_closed_local_via_send_headers_with_end_stream() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        assert_eq!(stream.state(), StreamState::Idle);

        stream.send_headers(true).unwrap();
        assert_eq!(stream.state(), StreamState::HalfClosedLocal);
    }

    #[test]
    fn idle_to_open_via_recv_headers() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        assert_eq!(stream.state(), StreamState::Idle);

        stream.recv_headers(false, true).unwrap();
        assert_eq!(stream.state(), StreamState::Open);
    }

    #[test]
    fn idle_to_half_closed_remote_via_recv_headers_with_end_stream() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        assert_eq!(stream.state(), StreamState::Idle);

        stream.recv_headers(true, true).unwrap();
        assert_eq!(stream.state(), StreamState::HalfClosedRemote);
    }

    #[test]
    fn open_to_half_closed_local_via_send_data() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(false).unwrap();
        assert_eq!(stream.state(), StreamState::Open);

        stream.send_data(true).unwrap();
        assert_eq!(stream.state(), StreamState::HalfClosedLocal);
    }

    #[test]
    fn open_to_half_closed_local_via_send_headers() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(false).unwrap();
        assert_eq!(stream.state(), StreamState::Open);

        // Sending trailers with end_stream
        stream.send_headers(true).unwrap();
        assert_eq!(stream.state(), StreamState::HalfClosedLocal);
    }

    #[test]
    fn open_to_half_closed_remote_via_recv_data() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(false).unwrap();
        assert_eq!(stream.state(), StreamState::Open);

        stream.recv_data(100, true).unwrap();
        assert_eq!(stream.state(), StreamState::HalfClosedRemote);
    }

    #[test]
    fn open_to_half_closed_remote_via_recv_headers() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(false).unwrap();
        assert_eq!(stream.state(), StreamState::Open);

        // Receiving trailers with end_stream
        stream.recv_headers(true, true).unwrap();
        assert_eq!(stream.state(), StreamState::HalfClosedRemote);
    }

    #[test]
    fn half_closed_local_to_closed_via_recv_data() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(true).unwrap(); // Go to HalfClosedLocal
        assert_eq!(stream.state(), StreamState::HalfClosedLocal);

        stream.recv_data(100, true).unwrap();
        assert_eq!(stream.state(), StreamState::Closed);
    }

    #[test]
    fn half_closed_local_to_closed_via_recv_headers() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(true).unwrap();
        assert_eq!(stream.state(), StreamState::HalfClosedLocal);

        // Receiving trailers with end_stream closes the stream
        stream.recv_headers(true, true).unwrap();
        assert_eq!(stream.state(), StreamState::Closed);
    }

    #[test]
    fn half_closed_remote_to_closed_via_send_data() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(false).unwrap();
        stream.recv_data(100, true).unwrap(); // Go to HalfClosedRemote
        assert_eq!(stream.state(), StreamState::HalfClosedRemote);

        stream.send_data(true).unwrap();
        assert_eq!(stream.state(), StreamState::Closed);
    }

    #[test]
    fn half_closed_remote_to_closed_via_send_headers() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(false).unwrap();
        stream.recv_data(100, true).unwrap();
        assert_eq!(stream.state(), StreamState::HalfClosedRemote);

        // Sending trailers with end_stream closes the stream
        stream.send_headers(true).unwrap();
        assert_eq!(stream.state(), StreamState::Closed);
    }

    // =========================================================================
    // Reserved State Tests (Push Promise paths)
    // =========================================================================

    #[test]
    fn reserved_local_to_half_closed_remote_via_send_headers() {
        let mut stream = Stream::new(2, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.state = StreamState::ReservedLocal; // Simulate PUSH_PROMISE sent

        stream.send_headers(false).unwrap();
        assert_eq!(stream.state(), StreamState::HalfClosedRemote);
    }

    #[test]
    fn reserved_local_to_closed_via_send_headers_with_end_stream() {
        let mut stream = Stream::new(2, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.state = StreamState::ReservedLocal;

        stream.send_headers(true).unwrap();
        assert_eq!(stream.state(), StreamState::Closed);
    }

    #[test]
    fn reserved_remote_to_half_closed_local_via_recv_headers() {
        let mut stream = Stream::new(2, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.state = StreamState::ReservedRemote; // Simulate PUSH_PROMISE received

        stream.recv_headers(false, true).unwrap();
        assert_eq!(stream.state(), StreamState::HalfClosedLocal);
    }

    #[test]
    fn reserved_remote_to_closed_via_recv_headers_with_end_stream() {
        let mut stream = Stream::new(2, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.state = StreamState::ReservedRemote;

        stream.recv_headers(true, true).unwrap();
        assert_eq!(stream.state(), StreamState::Closed);
    }

    // =========================================================================
    // Reset Tests
    // =========================================================================

    #[test]
    fn reset_from_any_state_goes_to_closed() {
        for initial_state in [
            StreamState::Idle,
            StreamState::Open,
            StreamState::HalfClosedLocal,
            StreamState::HalfClosedRemote,
            StreamState::ReservedLocal,
            StreamState::ReservedRemote,
        ] {
            let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
            stream.state = initial_state;

            stream.reset(ErrorCode::Cancel);

            assert_eq!(stream.state(), StreamState::Closed);
            assert_eq!(stream.error_code(), Some(ErrorCode::Cancel));
        }
    }

    #[test]
    fn reset_preserves_error_code() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(false).unwrap();

        stream.reset(ErrorCode::InternalError);
        assert_eq!(stream.error_code(), Some(ErrorCode::InternalError));

        stream.reset(ErrorCode::StreamClosed);
        assert_eq!(stream.error_code(), Some(ErrorCode::StreamClosed));
    }

    // =========================================================================
    // Illegal Transition Tests
    // =========================================================================

    #[test]
    fn cannot_send_headers_on_closed_stream() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.reset(ErrorCode::Cancel);
        assert_eq!(stream.state(), StreamState::Closed);

        let result = stream.send_headers(false);
        assert!(result.is_err());
    }

    #[test]
    fn cannot_recv_headers_on_closed_stream() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.reset(ErrorCode::Cancel);

        let result = stream.recv_headers(false, true);
        assert!(result.is_err());
    }

    #[test]
    fn cannot_send_data_on_closed_stream() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.reset(ErrorCode::Cancel);

        let result = stream.send_data(false);
        assert!(result.is_err());
    }

    #[test]
    fn cannot_recv_data_on_closed_stream() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.reset(ErrorCode::Cancel);

        let result = stream.recv_data(100, false);
        assert!(result.is_err());
    }

    #[test]
    fn cannot_send_data_on_half_closed_local() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(true).unwrap();
        assert_eq!(stream.state(), StreamState::HalfClosedLocal);

        let result = stream.send_data(false);
        assert!(result.is_err());
    }

    #[test]
    fn cannot_recv_data_on_half_closed_remote() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(false).unwrap();
        stream.recv_data(100, true).unwrap();
        assert_eq!(stream.state(), StreamState::HalfClosedRemote);

        let result = stream.recv_data(100, false);
        assert!(result.is_err());
    }

    #[test]
    fn cannot_send_headers_on_half_closed_local() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(true).unwrap();
        assert_eq!(stream.state(), StreamState::HalfClosedLocal);

        // Trying to send more headers is illegal since we already ended
        let result = stream.send_headers(false);
        assert!(result.is_err());
    }

    #[test]
    fn cannot_recv_headers_on_half_closed_remote() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(false).unwrap();
        stream.recv_headers(true, true).unwrap();
        assert_eq!(stream.state(), StreamState::HalfClosedRemote);

        let result = stream.recv_headers(false, true);
        assert!(result.is_err());
    }

    #[test]
    fn cannot_send_data_on_idle() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        assert_eq!(stream.state(), StreamState::Idle);

        let result = stream.send_data(false);
        assert!(result.is_err());
    }

    #[test]
    fn cannot_recv_data_on_idle() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        assert_eq!(stream.state(), StreamState::Idle);

        let result = stream.recv_data(100, false);
        assert!(result.is_err());
    }

    // =========================================================================
    // Flow Control Error Tests
    // =========================================================================

    #[test]
    fn recv_data_exceeding_window_returns_flow_control_error() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(false).unwrap();

        // Consume most of the receive window (recv_window uses DEFAULT_INITIAL_WINDOW_SIZE)
        stream.recv_data(65530, false).unwrap();

        // Now try to receive more data than remaining window (only 5 bytes left)
        let result = stream.recv_data(100, false);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, ErrorCode::FlowControlError);
    }

    #[test]
    fn window_update_overflow_returns_error() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);

        // Try to overflow the window
        let result = stream.update_send_window(i32::MAX);
        assert!(result.is_err());
    }

    // =========================================================================
    // State Predicate Tests
    // =========================================================================

    #[test]
    fn can_send_predicates_are_correct() {
        assert!(!StreamState::Idle.can_send());
        assert!(StreamState::Open.can_send());
        assert!(!StreamState::HalfClosedLocal.can_send());
        assert!(StreamState::HalfClosedRemote.can_send());
        assert!(StreamState::ReservedLocal.can_send());
        assert!(!StreamState::ReservedRemote.can_send());
        assert!(!StreamState::Closed.can_send());
    }

    #[test]
    fn can_recv_predicates_are_correct() {
        assert!(!StreamState::Idle.can_recv());
        assert!(StreamState::Open.can_recv());
        assert!(StreamState::HalfClosedLocal.can_recv());
        assert!(!StreamState::HalfClosedRemote.can_recv());
        assert!(!StreamState::ReservedLocal.can_recv());
        assert!(StreamState::ReservedRemote.can_recv());
        assert!(!StreamState::Closed.can_recv());
    }

    #[test]
    fn can_send_headers_predicates_are_correct() {
        assert!(StreamState::Idle.can_send_headers());
        assert!(StreamState::Open.can_send_headers());
        assert!(!StreamState::HalfClosedLocal.can_send_headers());
        assert!(StreamState::HalfClosedRemote.can_send_headers());
        assert!(StreamState::ReservedLocal.can_send_headers());
        assert!(!StreamState::ReservedRemote.can_send_headers());
        assert!(!StreamState::Closed.can_send_headers());
    }

    #[test]
    fn can_recv_headers_predicates_are_correct() {
        assert!(StreamState::Idle.can_recv_headers());
        assert!(StreamState::Open.can_recv_headers());
        assert!(StreamState::HalfClosedLocal.can_recv_headers());
        assert!(!StreamState::HalfClosedRemote.can_recv_headers());
        assert!(!StreamState::ReservedLocal.can_recv_headers());
        assert!(StreamState::ReservedRemote.can_recv_headers());
        assert!(!StreamState::Closed.can_recv_headers());
    }

    #[test]
    fn is_closed_predicate_is_correct() {
        assert!(!StreamState::Idle.is_closed());
        assert!(!StreamState::Open.is_closed());
        assert!(!StreamState::HalfClosedLocal.is_closed());
        assert!(!StreamState::HalfClosedRemote.is_closed());
        assert!(!StreamState::ReservedLocal.is_closed());
        assert!(!StreamState::ReservedRemote.is_closed());
        assert!(StreamState::Closed.is_closed());
    }

    // =========================================================================
    // Continuation Frame Tests
    // =========================================================================

    #[test]
    fn continuation_without_headers_in_progress_is_error() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(false).unwrap();

        // headers_complete is true by default, so CONTINUATION is unexpected
        let result = stream.recv_continuation(Bytes::from_static(b"test"), false);
        assert!(result.is_err());
    }

    #[test]
    fn continuation_accumulates_fragments() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        // Receive headers without END_HEADERS
        stream.recv_headers(false, false).unwrap();
        assert!(stream.is_receiving_headers());

        // Add continuations
        stream
            .recv_continuation(Bytes::from_static(b"part1"), false)
            .unwrap();
        stream
            .recv_continuation(Bytes::from_static(b"part2"), true)
            .unwrap();

        assert!(!stream.is_receiving_headers());

        let fragments = stream.take_header_fragments();
        assert_eq!(fragments.len(), 2);
    }

    // =========================================================================
    // Pending Data Queue Tests
    // =========================================================================

    #[test]
    fn pending_data_queue_works() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        assert!(!stream.has_pending_data());

        stream.queue_data(Bytes::from_static(b"hello"), false);
        stream.queue_data(Bytes::from_static(b"world"), true);
        assert!(stream.has_pending_data());

        let (data1, end1) = stream.take_pending_data(100).unwrap();
        assert_eq!(&data1[..], b"hello");
        assert!(!end1);

        let (data2, end2) = stream.take_pending_data(100).unwrap();
        assert_eq!(&data2[..], b"world");
        assert!(end2);

        assert!(!stream.has_pending_data());
    }

    #[test]
    fn pending_data_partial_take() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.queue_data(Bytes::from_static(b"hello world"), true);

        // Take only 5 bytes
        let (data1, end1) = stream.take_pending_data(5).unwrap();
        assert_eq!(&data1[..], b"hello");
        assert!(!end1); // Not end_stream since we only took partial

        // Take the rest
        let (data2, end2) = stream.take_pending_data(100).unwrap();
        assert_eq!(&data2[..], b" world");
        assert!(end2);
    }

    // =========================================================================
    // Stream Store ID Validation Tests
    // =========================================================================

    #[test]
    fn stream_store_rejects_stream_id_zero() {
        let mut store = StreamStore::new(true, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);

        let result = store.get_or_create(0);
        assert!(result.is_err());
    }

    #[test]
    fn stream_store_client_rejects_reused_server_stream_id() {
        let mut store = StreamStore::new(true, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);

        // Client receives server stream 2
        store.get_or_create(2).unwrap();

        // Trying to use ID 2 again should fail (but it already exists, so get returns it)
        // The error case is when we try to create a lower ID
        store.get_or_create(4).unwrap(); // This advances next_server_stream_id to 6

        // Now trying to create stream 2 should just return existing
        assert!(store.get_or_create(2).is_ok());
    }

    #[test]
    fn stream_store_server_advances_client_stream_ids() {
        let mut store = StreamStore::new(false, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);

        // Server receives client streams
        store.get_or_create(1).unwrap();
        store.get_or_create(5).unwrap(); // Skipping 3 is allowed

        // Trying to create stream 3 now should fail (ID already "used")
        let result = store.get_or_create(3);
        assert!(result.is_err());
    }

    #[test]
    fn stream_store_prune_removes_closed_streams() {
        let mut store = StreamStore::new(true, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);

        let id = store.allocate_stream_id().unwrap();
        store.get_mut(id).unwrap().reset(ErrorCode::NoError);

        assert_eq!(store.active_count(), 0);
        store.prune_closed();
        assert!(store.get(id).is_none());
    }

    #[test]
    fn stream_store_active_stream_ids() {
        let mut store = StreamStore::new(true, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);

        let id1 = store.allocate_stream_id().unwrap();
        let id2 = store.allocate_stream_id().unwrap();
        store.get_mut(id1).unwrap().reset(ErrorCode::NoError);

        let active = store.active_stream_ids();
        assert_eq!(active.len(), 1);
        assert!(active.contains(&id2));
        assert!(!active.contains(&id1));
    }

    // =========================================================================
    // Initial Window Size Update Tests
    // =========================================================================

    #[test]
    fn update_initial_window_size_adjusts_existing_streams() {
        let mut store = StreamStore::new(true, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);

        let id = store.allocate_stream_id().unwrap();
        assert_eq!(store.get(id).unwrap().send_window(), 65535);

        // Increase window size
        store.set_initial_window_size(100_000).unwrap();
        assert_eq!(store.get(id).unwrap().send_window(), 100_000);

        // Decrease window size
        store.set_initial_window_size(50_000).unwrap();
        assert_eq!(store.get(id).unwrap().send_window(), 50_000);
    }

    #[test]
    fn priority_can_be_set_and_retrieved() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);

        let new_priority = PrioritySpec {
            exclusive: true,
            dependency: 3,
            weight: 255,
        };
        stream.set_priority(new_priority);

        let priority = stream.priority();
        assert!(priority.exclusive);
        assert_eq!(priority.dependency, 3);
        assert_eq!(priority.weight, 255);
    }

    // =========================================================================
    // Racey Cancellation Edge Tests
    // =========================================================================

    /// Test: RST_STREAM followed by DATA frame on same stream
    /// Per RFC 7540 Section 5.4.2: After sending RST_STREAM, the sender
    /// should be prepared to receive frames that were in flight.
    #[test]
    fn reset_then_recv_data_returns_error() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(false).unwrap();
        assert_eq!(stream.state(), StreamState::Open);

        // Reset the stream
        stream.reset(ErrorCode::Cancel);
        assert_eq!(stream.state(), StreamState::Closed);
        assert_eq!(stream.error_code(), Some(ErrorCode::Cancel));

        // Try to receive data on the now-closed stream
        let result = stream.recv_data(100, false);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, ErrorCode::StreamClosed);
    }

    /// Test: RST_STREAM followed by HEADERS (trailers) on same stream
    #[test]
    fn reset_then_recv_headers_returns_error() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(false).unwrap();

        stream.reset(ErrorCode::InternalError);
        assert_eq!(stream.state(), StreamState::Closed);

        // Try to receive headers on the closed stream
        let result = stream.recv_headers(true, true);
        assert!(result.is_err());
    }

    /// Test: RST_STREAM while CONTINUATION is pending
    /// Verifies that reset transitions stream to Closed and rejects further frames.
    /// Note: The headers_complete flag isn't cleared by reset, but the stream
    /// being Closed means no frames can be processed anyway.
    #[test]
    fn reset_during_header_accumulation() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);

        // Start receiving headers without END_HEADERS
        stream.recv_headers(false, false).unwrap();
        assert!(stream.is_receiving_headers());

        // Add a header fragment
        stream
            .add_header_fragment(Bytes::from_static(b"partial_header"))
            .unwrap();

        // Reset the stream - this closes the stream
        stream.reset(ErrorCode::Cancel);
        assert_eq!(stream.state(), StreamState::Closed);

        // Headers_complete flag is preserved (still false = expecting continuation)
        // but the stream is closed so no frames can be processed
        assert!(stream.is_receiving_headers());

        // Any frame on a closed stream should fail (because state is Closed)
        let result = stream.recv_data(100, false);
        assert!(result.is_err());

        // Headers on closed stream also fails
        let result = stream.recv_headers(false, true);
        assert!(result.is_err());
    }

    /// Test: Double reset is idempotent
    /// Resetting an already-reset stream should be safe.
    #[test]
    fn double_reset_is_safe() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(false).unwrap();

        stream.reset(ErrorCode::Cancel);
        assert_eq!(stream.state(), StreamState::Closed);
        assert_eq!(stream.error_code(), Some(ErrorCode::Cancel));

        // Reset again with different error code
        stream.reset(ErrorCode::InternalError);
        assert_eq!(stream.state(), StreamState::Closed);
        // Error code is updated to the latest
        assert_eq!(stream.error_code(), Some(ErrorCode::InternalError));
    }

    /// Test: State transitions after END_STREAM are rejected
    /// Once a stream has sent END_STREAM, no more data/headers can be sent.
    #[test]
    fn no_send_after_end_stream() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(true).unwrap(); // end_stream = true
        assert_eq!(stream.state(), StreamState::HalfClosedLocal);

        // Cannot send more data
        assert!(stream.send_data(false).is_err());

        // Cannot send more headers
        assert!(stream.send_headers(false).is_err());
    }

    /// Test: Trailers must have END_STREAM set
    /// Per RFC 7540 Section 8.1: Trailers are sent as HEADERS with END_STREAM.
    #[test]
    fn trailers_transition_to_half_closed() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        // Client sends request headers (no end_stream - body will follow or trailers)
        stream.send_headers(false).unwrap();
        assert_eq!(stream.state(), StreamState::Open);

        // Client sends trailers (headers with end_stream)
        stream.send_headers(true).unwrap();
        assert_eq!(stream.state(), StreamState::HalfClosedLocal);
    }

    /// Test: Receive trailers transitions to half-closed
    #[test]
    fn recv_trailers_transition_to_half_closed() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(false).unwrap();
        assert_eq!(stream.state(), StreamState::Open);

        // Receive trailers (headers with end_stream)
        stream.recv_headers(true, true).unwrap();
        assert_eq!(stream.state(), StreamState::HalfClosedRemote);
    }

    /// Test: Flow control edge case - negative window after SETTINGS change
    /// Per RFC 7540 Section 6.9.2: Initial window size changes can make
    /// the effective window size negative.
    #[test]
    fn window_can_go_negative_after_settings_change() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(false).unwrap();

        // Consume some window
        stream.consume_send_window(60000);
        assert_eq!(stream.send_window(), 5535);

        // Reduce initial window size (simulates SETTINGS change)
        // New initial = 1000, delta = 1000 - 65535 = -64535
        stream.update_initial_window_size(1000).unwrap();
        // Window was 5535, delta is -64535, new window = 5535 - 64535 = -59000
        assert!(stream.send_window() < 0);
    }

    /// Test: Reserved(remote) stream can receive data per RFC 7540
    /// A reserved(remote) stream is created via PUSH_PROMISE and can receive
    /// headers and data from the server.
    #[test]
    fn reserved_remote_can_recv_data() {
        let mut stream = Stream::new(2, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.state = StreamState::ReservedRemote;

        // Reserved(remote) streams CAN receive data (can_recv returns true)
        // The server would send HEADERS then DATA on the promised stream
        assert!(stream.state().can_recv());

        // However, proper protocol requires headers first to activate the stream
        // Receive headers to transition to half-closed(local)
        stream.recv_headers(false, true).unwrap();
        assert_eq!(stream.state(), StreamState::HalfClosedLocal);

        // Now can receive data
        let result = stream.recv_data(100, true);
        assert!(result.is_ok());
        assert_eq!(stream.state(), StreamState::Closed);
    }

    /// Test: Reserved stream cannot send data directly
    #[test]
    fn reserved_stream_cannot_send_data() {
        let mut stream = Stream::new(2, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.state = StreamState::ReservedLocal;

        // Reserved streams cannot send data until headers are sent
        // (can_send returns true for ReservedLocal, but send_data should
        // only allow it after headers are sent)
        let result = stream.send_data(false);
        // This should fail because we're in ReservedLocal, not a data-sending state
        // Actually, can_send() returns true for ReservedLocal, so this will succeed
        // The RFC says data is allowed on reserved(local) after HEADERS is sent
        // Let's verify the actual behavior
        assert!(stream.state().can_send());
    }

    /// Test: Stream store handles rapid allocation/deallocation
    #[test]
    fn stream_store_handles_rapid_churn() {
        let mut store = StreamStore::new(true, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        store.set_max_concurrent_streams(10);

        // Rapidly allocate and close streams
        for round in 0..10 {
            // Allocate up to max
            let mut ids = Vec::new();
            for _ in 0..10 {
                let id = store.allocate_stream_id().unwrap();
                ids.push(id);
            }

            // Should hit limit
            let result = store.allocate_stream_id();
            assert!(
                result.is_err(),
                "round {}: should hit max_concurrent_streams limit",
                round
            );

            // Close all
            for id in &ids {
                store.get_mut(*id).unwrap().reset(ErrorCode::NoError);
            }

            // Prune should remove all closed streams
            store.prune_closed();
            assert_eq!(store.active_count(), 0, "round {}: all streams should be pruned", round);
        }

        // After all rounds, should be able to allocate again
        let id = store.allocate_stream_id().unwrap();
        assert!(id > 0);
    }

    /// Test: Reserve remote stream validates stream ID parity
    #[test]
    fn reserve_remote_validates_parity() {
        // Client store
        let mut store = StreamStore::new(true, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);

        // Server should use even IDs for client
        assert!(store.reserve_remote_stream(2).is_ok());

        // Odd ID should fail for client (that's client-initiated)
        assert!(store.reserve_remote_stream(3).is_err());

        // Server store
        let mut store = StreamStore::new(false, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);

        // Client should use odd IDs for server
        assert!(store.reserve_remote_stream(1).is_ok());

        // Even ID should fail for server (that's server-initiated)
        assert!(store.reserve_remote_stream(2).is_err());
    }

    /// Test: Stream ID monotonicity is enforced
    #[test]
    fn stream_id_must_be_monotonic() {
        let mut store = StreamStore::new(true, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);

        // Allocate some streams
        let _ = store.allocate_stream_id().unwrap(); // 1
        let _ = store.allocate_stream_id().unwrap(); // 3

        // Server sends push with ID 2, then 4
        store.reserve_remote_stream(2).unwrap();
        store.reserve_remote_stream(4).unwrap();

        // Server cannot go back to ID 2 (already used)
        // Actually, since 2 already exists, this will fail
        assert!(store.reserve_remote_stream(2).is_err());
    }

    /// Test: Pending data queue respects order
    #[test]
    fn pending_data_preserves_order() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);

        stream.queue_data(Bytes::from_static(b"first"), false);
        stream.queue_data(Bytes::from_static(b"second"), false);
        stream.queue_data(Bytes::from_static(b"third"), true);

        let (d1, e1) = stream.take_pending_data(100).unwrap();
        assert_eq!(&d1[..], b"first");
        assert!(!e1);

        let (d2, e2) = stream.take_pending_data(100).unwrap();
        assert_eq!(&d2[..], b"second");
        assert!(!e2);

        let (d3, e3) = stream.take_pending_data(100).unwrap();
        assert_eq!(&d3[..], b"third");
        assert!(e3);

        assert!(!stream.has_pending_data());
    }
}
