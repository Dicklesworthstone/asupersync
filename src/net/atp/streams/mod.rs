//! ATP Stream Management and Scheduling
//!
//! Implements reliable QUIC streams with flow control, reassembly, reset handling,
//! and ATP-specific priority classes for control, data, repair, proof, and diagnostics.

pub mod flow_control;
pub mod reassembly;
pub mod scheduler;
pub mod stream;

pub use flow_control::*;
pub use reassembly::*;
pub use scheduler::*;
pub use stream::*;

use crate::cx::Cx;
use crate::types::outcome::Outcome;
use std::collections::HashMap;

/// Stream priority classes for ATP traffic
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum StreamPriority {
    /// ATP control frames (highest priority)
    Control = 0,
    /// Proof bundles and verification data
    Proof = 1,
    /// Primary data transfer
    Data = 2,
    /// Repair symbols and recovery data
    Repair = 3,
    /// Diagnostics and logging (lowest priority)
    Diagnostics = 4,
}

impl Default for StreamPriority {
    fn default() -> Self {
        StreamPriority::Data
    }
}

/// Stream identifier with direction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamId {
    pub id: u64,
}

impl StreamId {
    /// Create a new stream ID
    pub fn new(id: u64) -> Self {
        Self { id }
    }

    /// Check if this is a bidirectional stream
    pub fn is_bidirectional(&self) -> bool {
        (self.id & 0x02) == 0
    }

    /// Check if this is a client-initiated stream
    pub fn is_client_initiated(&self) -> bool {
        (self.id & 0x01) == 0
    }

    /// Check if this is a unidirectional stream
    pub fn is_unidirectional(&self) -> bool {
        !self.is_bidirectional()
    }

    /// Check if this is a server-initiated stream
    pub fn is_server_initiated(&self) -> bool {
        !self.is_client_initiated()
    }
}

/// Stream reset codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamResetCode {
    /// Application requested close
    ApplicationClose = 0,
    /// Internal error
    InternalError = 1,
    /// Flow control violation
    FlowControlViolation = 2,
    /// Final size mismatch
    FinalSizeMismatch = 3,
    /// Connection close
    ConnectionClose = 4,
}

/// Stop sending codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopSendingCode {
    /// Application requested stop
    ApplicationStop = 0,
    /// Internal error
    InternalError = 1,
    /// Flow control violation
    FlowControlViolation = 2,
    /// Connection close
    ConnectionClose = 3,
}

/// Stream errors
#[derive(Debug, Clone)]
pub enum StreamError {
    /// Stream not found
    StreamNotFound { stream_id: StreamId },
    /// Stream already exists
    StreamAlreadyExists { stream_id: StreamId },
    /// Stream is closed
    StreamClosed {
        stream_id: StreamId,
        reset_code: Option<StreamResetCode>,
    },
    /// Flow control violation
    FlowControlViolation {
        stream_id: StreamId,
        limit: u64,
        attempted: u64,
    },
    /// Final size mismatch
    FinalSizeMismatch {
        stream_id: StreamId,
        expected: u64,
        actual: u64,
    },
    /// Invalid stream state
    InvalidState { stream_id: StreamId, state: String },
    /// Connection error
    ConnectionError { reason: String },
}

/// Stream manager coordinates all streams for a connection
pub struct StreamManager {
    streams: HashMap<StreamId, AtpStream>,
    scheduler: StreamScheduler,
    next_client_bidi: u64,
    next_client_uni: u64,
    next_server_bidi: u64,
    next_server_uni: u64,
    is_server: bool,
}

impl StreamManager {
    /// Create a new stream manager
    pub fn new(is_server: bool) -> Self {
        Self {
            streams: HashMap::new(),
            scheduler: StreamScheduler::new(),
            next_client_bidi: 0,
            next_client_uni: 2,
            next_server_bidi: 1,
            next_server_uni: 3,
            is_server,
        }
    }

    /// Open a new outgoing stream
    pub fn open_stream(
        &mut self,
        cx: &Cx,
        is_bidirectional: bool,
        priority: StreamPriority,
    ) -> Outcome<StreamId, StreamError> {
        let stream_id = if self.is_server {
            if is_bidirectional {
                let id = StreamId::new(self.next_server_bidi);
                self.next_server_bidi += 4;
                id
            } else {
                let id = StreamId::new(self.next_server_uni);
                self.next_server_uni += 4;
                id
            }
        } else {
            if is_bidirectional {
                let id = StreamId::new(self.next_client_bidi);
                self.next_client_bidi += 4;
                id
            } else {
                let id = StreamId::new(self.next_client_uni);
                self.next_client_uni += 4;
                id
            }
        };

        if self.streams.contains_key(&stream_id) {
            return Outcome::err(StreamError::StreamAlreadyExists { stream_id });
        }

        let stream = AtpStream::new(stream_id, is_bidirectional, priority, true);
        self.streams.insert(stream_id, stream);
        self.scheduler.register_stream(stream_id, priority);

        cx.trace(&format!(
            "stream_opened stream_id={:?} priority={:?}",
            stream_id, priority
        ));

        Outcome::ok(stream_id)
    }

    /// Accept an incoming stream
    pub fn accept_stream(
        &mut self,
        cx: &Cx,
        stream_id: StreamId,
        priority: StreamPriority,
    ) -> Outcome<(), StreamError> {
        if self.streams.contains_key(&stream_id) {
            return Outcome::err(StreamError::StreamAlreadyExists { stream_id });
        }

        let is_bidirectional = stream_id.is_bidirectional();
        let stream = AtpStream::new(stream_id, is_bidirectional, priority, false);
        self.streams.insert(stream_id, stream);
        self.scheduler.register_stream(stream_id, priority);

        cx.trace(&format!(
            "stream_accepted stream_id={:?} priority={:?}",
            stream_id, priority
        ));

        Outcome::ok(())
    }

    /// Get a mutable reference to a stream
    pub fn get_stream_mut(&mut self, stream_id: StreamId) -> Option<&mut AtpStream> {
        self.streams.get_mut(&stream_id)
    }

    /// Get a reference to a stream
    pub fn get_stream(&self, stream_id: StreamId) -> Option<&AtpStream> {
        self.streams.get(&stream_id)
    }

    /// Close a stream gracefully
    pub fn close_stream(&mut self, cx: &Cx, stream_id: StreamId) -> Outcome<(), StreamError> {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.close();
            self.scheduler.unregister_stream(stream_id);
            cx.trace(&format!("stream_closed stream_id={:?}", stream_id));
            Outcome::ok(())
        } else {
            Outcome::err(StreamError::StreamNotFound { stream_id })
        }
    }

    /// Reset a stream with error code
    pub fn reset_stream(
        &mut self,
        cx: &Cx,
        stream_id: StreamId,
        reset_code: StreamResetCode,
    ) -> Outcome<(), StreamError> {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.reset(reset_code);
            self.scheduler.unregister_stream(stream_id);
            cx.trace(&format!(
                "stream_reset stream_id={:?} code={:?}",
                stream_id, reset_code
            ));
            Outcome::ok(())
        } else {
            Outcome::err(StreamError::StreamNotFound { stream_id })
        }
    }

    /// Send stop_sending to peer
    pub fn stop_sending(
        &mut self,
        cx: &Cx,
        stream_id: StreamId,
        stop_code: StopSendingCode,
    ) -> Outcome<(), StreamError> {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.stop_sending(stop_code);
            cx.trace(&format!(
                "stop_sending stream_id={:?} code={:?}",
                stream_id, stop_code
            ));
            Outcome::ok(())
        } else {
            Outcome::err(StreamError::StreamNotFound { stream_id })
        }
    }

    /// Get the next stream to schedule for sending
    pub fn next_scheduled_stream(&mut self) -> Option<StreamId> {
        self.scheduler.next_stream()
    }

    /// Mark a stream eligible for scheduling after flow-control or drain progress.
    pub fn mark_stream_ready(&mut self, stream_id: StreamId) -> Outcome<(), StreamError> {
        if self.streams.contains_key(&stream_id) {
            self.scheduler.mark_ready(stream_id);
            Outcome::ok(())
        } else {
            Outcome::err(StreamError::StreamNotFound { stream_id })
        }
    }

    /// Mark a stream ineligible for scheduling while blocked by flow control or drain state.
    pub fn mark_stream_blocked(&mut self, stream_id: StreamId) -> Outcome<(), StreamError> {
        if self.streams.contains_key(&stream_id) {
            self.scheduler.mark_blocked(stream_id);
            Outcome::ok(())
        } else {
            Outcome::err(StreamError::StreamNotFound { stream_id })
        }
    }

    /// Remove closed streams
    pub fn cleanup_closed_streams(&mut self) {
        self.streams.retain(|stream_id, stream| {
            if stream.is_closed() {
                self.scheduler.unregister_stream(*stream_id);
                false
            } else {
                true
            }
        });
    }

    /// Check if all streams are closed (for connection drain)
    pub fn all_streams_closed(&self) -> bool {
        self.streams.values().all(|stream| stream.is_closed())
    }
}
