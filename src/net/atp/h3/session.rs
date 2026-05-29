//! H3 session management for ATP-over-WebTransport.

use super::{AdapterConfig, AtpH3Error, AtpH3Result, AtpH3Stream, H3FrameCodec, StreamDirection};
use std::collections::HashMap;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// H3 session state.
#[derive(Debug, Clone, PartialEq)]
pub enum SessionState {
    /// Session is being established.
    Connecting,
    /// Session is active and ready for frame exchange.
    Active,
    /// Session is draining (closing gracefully).
    Draining,
    /// Session is closed.
    Closed,
    /// Session encountered an error.
    Error(String),
}

/// ATP-over-H3 session.
#[derive(Debug)]
pub struct H3Session {
    /// Session identifier.
    session_id: String,
    /// Current session state.
    state: SessionState,
    /// Session configuration.
    config: AdapterConfig,
    /// Frame codec.
    codec: H3FrameCodec,
    /// Active streams.
    streams: HashMap<u64, AtpH3Stream>,
    /// Outbound WebTransport datagrams awaiting backend transmission.
    datagram_send_queue: VecDeque<Vec<u8>>,
    /// Maximum queued datagrams before backpressure.
    datagram_queue_high_water: usize,
    /// Next stream ID for outbound streams.
    next_stream_id: u64,
    /// Session creation time.
    created_at: Instant,
    /// Last activity timestamp.
    last_activity: Instant,
    /// Connection timeout duration.
    timeout: Duration,
}

impl H3Session {
    /// Create a new H3 session.
    pub fn new(session_id: String, config: &AdapterConfig) -> AtpH3Result<Self> {
        let now = Instant::now();
        let timeout = Duration::from_millis(config.connection_timeout_ms);

        Ok(Self {
            session_id,
            state: SessionState::Connecting,
            config: config.clone(),
            codec: H3FrameCodec::new(),
            streams: HashMap::new(),
            datagram_send_queue: VecDeque::new(),
            datagram_queue_high_water: 64,
            next_stream_id: 0, // Client streams start at 0, 4, 8, ...
            created_at: now,
            last_activity: now,
            timeout,
        })
    }

    /// Get the session ID.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Get the current session state.
    pub fn state(&self) -> &SessionState {
        &self.state
    }

    /// Get the frame codec bound to this session.
    pub fn codec(&self) -> &H3FrameCodec {
        &self.codec
    }

    /// Check if the session is active.
    pub fn is_active(&self) -> bool {
        matches!(self.state, SessionState::Active)
    }

    /// Check if the session is closed.
    pub fn is_closed(&self) -> bool {
        matches!(self.state, SessionState::Closed | SessionState::Error(_))
    }

    /// Activate the session (transition from Connecting to Active).
    pub fn activate(&mut self) -> AtpH3Result<()> {
        match self.state {
            SessionState::Connecting => {
                self.state = SessionState::Active;
                self.update_activity();
                Ok(())
            }
            _ => Err(AtpH3Error::Session(format!(
                "Cannot activate session in state {:?}",
                self.state
            ))),
        }
    }

    /// Create a new outbound stream.
    pub fn create_stream(&mut self, direction: StreamDirection) -> AtpH3Result<u64> {
        if !self.is_active() {
            return Err(AtpH3Error::Session("Session is not active".to_string()));
        }

        if self.streams.len() >= self.config.max_streams as usize {
            return Err(AtpH3Error::Session("Maximum streams exceeded".to_string()));
        }

        let stream_id = self.next_stream_id;
        self.next_stream_id += 4; // WebTransport bidirectional streams use every 4th ID

        let stream = AtpH3Stream::new(stream_id, direction);
        self.streams.insert(stream_id, stream);
        self.update_activity();

        Ok(stream_id)
    }

    /// Get a stream by ID.
    pub fn get_stream(&self, stream_id: u64) -> Option<&AtpH3Stream> {
        self.streams.get(&stream_id)
    }

    /// Get a mutable reference to a stream by ID.
    pub fn get_stream_mut(&mut self, stream_id: u64) -> Option<&mut AtpH3Stream> {
        self.update_activity();
        self.streams.get_mut(&stream_id)
    }

    /// Close a stream.
    pub fn close_stream(&mut self, stream_id: u64) -> AtpH3Result<()> {
        if let Some(mut stream) = self.streams.remove(&stream_id) {
            stream.close()?;
        }
        self.update_activity();
        Ok(())
    }

    /// Get the number of active streams.
    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }

    /// Get all active stream IDs.
    pub fn stream_ids(&self) -> Vec<u64> {
        self.streams.keys().copied().collect()
    }

    /// Send data on a stream.
    pub fn send_on_stream(&mut self, stream_id: u64, data: &[u8]) -> AtpH3Result<()> {
        if !self.is_active() {
            return Err(AtpH3Error::Session("Session is not active".to_string()));
        }

        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or_else(|| AtpH3Error::Stream(format!("Stream {} not found", stream_id)))?;

        stream.send(data)?;
        self.update_activity();
        Ok(())
    }

    /// Queue datagram data for WebTransport backend transmission.
    pub fn send_datagram(&mut self, data: &[u8]) -> AtpH3Result<()> {
        if !self.is_active() {
            return Err(AtpH3Error::Session("Session is not active".to_string()));
        }

        if self.datagram_send_queue.len() >= self.datagram_queue_high_water {
            return Err(AtpH3Error::Session(
                "Datagram send queue full - apply backpressure".to_string(),
            ));
        }

        if data.len() > self.config.max_datagram_size {
            return Err(AtpH3Error::Session(format!(
                "Datagram size {} exceeds maximum {}",
                data.len(),
                self.config.max_datagram_size
            )));
        }

        self.datagram_send_queue.push_back(data.to_vec());
        self.update_activity();
        Ok(())
    }

    /// Pop the next queued datagram for the concrete WebTransport backend.
    pub fn next_datagram(&mut self) -> Option<Vec<u8>> {
        let datagram = self.datagram_send_queue.pop_front();
        if datagram.is_some() {
            self.update_activity();
        }
        datagram
    }

    /// Returns true if a datagram is queued for backend transmission.
    pub fn has_pending_datagram(&self) -> bool {
        !self.datagram_send_queue.is_empty()
    }

    /// Number of datagrams queued for backend transmission.
    pub fn datagram_queue_len(&self) -> usize {
        self.datagram_send_queue.len()
    }

    /// Check if the session has timed out.
    pub fn is_timed_out(&self) -> bool {
        self.last_activity.elapsed() > self.timeout
    }

    /// Get session uptime.
    pub fn uptime(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Get time since last activity.
    pub fn idle_time(&self) -> Duration {
        self.last_activity.elapsed()
    }

    /// Start graceful session closure.
    pub fn start_close(&mut self) -> AtpH3Result<()> {
        match self.state {
            SessionState::Active => {
                self.state = SessionState::Draining;
                self.update_activity();
                Ok(())
            }
            SessionState::Draining => Ok(()), // Already draining
            SessionState::Closed | SessionState::Error(_) => Ok(()), // Already closed
            SessionState::Connecting => {
                // Can close while connecting
                self.state = SessionState::Closed;
                Ok(())
            }
        }
    }

    /// Close the session immediately.
    pub fn close(mut self) -> AtpH3Result<()> {
        // Close all streams
        let stream_ids: Vec<u64> = self.streams.keys().copied().collect();
        for stream_id in stream_ids {
            self.close_stream(stream_id)?;
        }

        self.state = SessionState::Closed;
        Ok(())
    }

    /// Handle session error.
    pub fn handle_error(&mut self, error: String) {
        self.state = SessionState::Error(error);
        self.update_activity();
    }

    /// Get session statistics.
    pub fn stats(&self) -> SessionStats {
        SessionStats {
            session_id: self.session_id.clone(),
            state: self.state.clone(),
            stream_count: self.streams.len(),
            datagram_queue_len: self.datagram_send_queue.len(),
            max_streams: self.config.max_streams as usize,
            uptime_ms: elapsed_millis_floor_one(self.uptime()),
            idle_time_ms: elapsed_millis_floor_one(self.idle_time()),
            timeout_ms: duration_millis(self.timeout),
        }
    }

    /// Update last activity timestamp.
    fn update_activity(&mut self) {
        self.last_activity = Instant::now();
    }
}

fn elapsed_millis_floor_one(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis().max(1)).unwrap_or(u64::MAX)
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// Session statistics.
#[derive(Debug, Clone)]
pub struct SessionStats {
    /// Session ID.
    pub session_id: String,
    /// Current session state.
    pub state: SessionState,
    /// Number of active streams.
    pub stream_count: usize,
    /// Number of queued outbound datagrams.
    pub datagram_queue_len: usize,
    /// Maximum allowed streams.
    pub max_streams: usize,
    /// Session uptime in milliseconds.
    pub uptime_ms: u64,
    /// Idle time in milliseconds.
    pub idle_time_ms: u64,
    /// Configured timeout in milliseconds.
    pub timeout_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> AdapterConfig {
        AdapterConfig {
            max_streams: 10,
            max_datagram_size: 1350,
            enable_unreliable_repair: true,
            connection_timeout_ms: 30000,
        }
    }

    #[test]
    fn test_session_creation() {
        let config = test_config();
        let session = H3Session::new("test-session".to_string(), &config).unwrap();

        assert_eq!(session.session_id(), "test-session");
        assert_eq!(session.state(), &SessionState::Connecting);
        assert!(!session.is_active());
        assert!(!session.is_closed());
        assert_eq!(session.stream_count(), 0);
    }

    #[test]
    fn test_session_activation() {
        let config = test_config();
        let mut session = H3Session::new("test-session".to_string(), &config).unwrap();

        assert!(session.activate().is_ok());
        assert_eq!(session.state(), &SessionState::Active);
        assert!(session.is_active());

        // Cannot activate again
        assert!(session.activate().is_err());
    }

    #[test]
    fn test_stream_management() {
        let config = test_config();
        let mut session = H3Session::new("test-session".to_string(), &config).unwrap();
        session.activate().unwrap();

        // Create streams
        let stream_id1 = session
            .create_stream(StreamDirection::Bidirectional)
            .unwrap();
        assert_eq!(stream_id1, 0);

        let stream_id2 = session.create_stream(StreamDirection::Outbound).unwrap();
        assert_eq!(stream_id2, 4);

        assert_eq!(session.stream_count(), 2);

        // Get stream
        assert!(session.get_stream(stream_id1).is_some());
        assert!(session.get_stream(999).is_none());

        // Close stream
        assert!(session.close_stream(stream_id1).is_ok());
        assert_eq!(session.stream_count(), 1);
        assert!(session.get_stream(stream_id1).is_none());
    }

    #[test]
    fn test_stream_limits() {
        let mut config = test_config();
        config.max_streams = 2;

        let mut session = H3Session::new("test-session".to_string(), &config).unwrap();
        session.activate().unwrap();

        // Create maximum streams
        assert!(
            session
                .create_stream(StreamDirection::Bidirectional)
                .is_ok()
        );
        assert!(
            session
                .create_stream(StreamDirection::Bidirectional)
                .is_ok()
        );

        // Exceed limit
        assert!(
            session
                .create_stream(StreamDirection::Bidirectional)
                .is_err()
        );
    }

    #[test]
    fn test_session_closure() {
        let config = test_config();
        let mut session = H3Session::new("test-session".to_string(), &config).unwrap();
        session.activate().unwrap();

        // Create stream
        let _stream_id = session
            .create_stream(StreamDirection::Bidirectional)
            .unwrap();

        // Start close
        assert!(session.start_close().is_ok());
        assert_eq!(session.state(), &SessionState::Draining);

        // Complete close
        assert!(session.close().is_ok());
    }

    #[test]
    fn test_datagram_send() {
        let config = test_config();
        let mut session = H3Session::new("test-session".to_string(), &config).unwrap();
        session.activate().unwrap();

        // Queue normal datagram
        let data = vec![0u8; 100];
        assert!(session.send_datagram(&data).is_ok());
        assert!(session.has_pending_datagram());
        assert_eq!(session.datagram_queue_len(), 1);
        assert_eq!(session.next_datagram(), Some(data));
        assert!(!session.has_pending_datagram());

        // Exceed size limit
        let large_data = vec![0u8; 2000];
        assert!(session.send_datagram(&large_data).is_err());
    }

    #[test]
    fn test_datagram_send_applies_backpressure() {
        let config = test_config();
        let mut session = H3Session::new("test-session".to_string(), &config).unwrap();
        session.activate().unwrap();

        for _ in 0..64 {
            session.send_datagram(&[1, 2, 3]).unwrap();
        }

        let err = session
            .send_datagram(&[1, 2, 3])
            .expect_err("queue high water should apply backpressure");
        assert!(err.to_string().contains("Datagram send queue full"));
    }

    #[test]
    fn test_session_stats() {
        let config = test_config();
        let mut session = H3Session::new("test-session".to_string(), &config).unwrap();
        session.activate().unwrap();

        let _stream_id = session
            .create_stream(StreamDirection::Bidirectional)
            .unwrap();

        let stats = session.stats();
        assert_eq!(stats.session_id, "test-session");
        assert_eq!(stats.state, SessionState::Active);
        assert_eq!(stats.stream_count, 1);
        assert_eq!(stats.datagram_queue_len, 0);
        assert_eq!(stats.max_streams, 10);
        assert!(stats.uptime_ms > 0);
    }

    #[test]
    fn test_timeout_detection() {
        let mut config = test_config();
        config.connection_timeout_ms = 1; // Very short timeout

        let session = H3Session::new("test-session".to_string(), &config).unwrap();

        // Sleep briefly to trigger timeout
        std::thread::sleep(Duration::from_millis(10));
        assert!(session.is_timed_out());
    }
}
