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

use crate::bytes::Bytes;
use crate::cx::Cx;
use crate::net::atp::protocol::quic_frames::QuicFrame;
use crate::net::atp::protocol::varint::VarInt;
use crate::types::outcome::Outcome;
use std::collections::HashMap;

/// Stream priority classes for ATP traffic
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum StreamPriority {
    /// ATP control frames (highest priority)
    Control = 0,
    /// Proof bundles and verification data
    Proof = 1,
    /// Primary data transfer
    #[default]
    Data = 2,
    /// Repair symbols and recovery data
    Repair = 3,
    /// Diagnostics and logging (lowest priority)
    Diagnostics = 4,
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

    /// Queue outbound bytes on a managed stream and update scheduler readiness.
    pub fn queue_stream_data(
        &mut self,
        cx: &Cx,
        stream_id: StreamId,
        data: Bytes,
        fin: bool,
    ) -> Outcome<(), StreamError> {
        let has_send_data = {
            let Some(stream) = self.streams.get_mut(&stream_id) else {
                return Outcome::err(StreamError::StreamNotFound { stream_id });
            };

            match stream.queue_send(cx, data, fin) {
                Outcome::Ok(()) => stream.has_send_data(),
                Outcome::Err(error) => return Outcome::err(error),
                Outcome::Cancelled(reason) => return Outcome::cancelled(reason),
                Outcome::Panicked(payload) => return Outcome::panicked(payload),
            }
        };

        if has_send_data {
            self.scheduler.mark_ready(stream_id);
        } else {
            self.scheduler.mark_blocked(stream_id);
        }

        Outcome::ok(())
    }

    /// Drain schedulable stream payload into QUIC STREAM frames.
    pub fn drain_quic_stream_frames(
        &mut self,
        max_frames: usize,
        max_frame_payload: usize,
    ) -> Outcome<Vec<QuicFrame>, StreamError> {
        let mut frames = Vec::new();
        if max_frames == 0 || max_frame_payload == 0 {
            return Outcome::ok(frames);
        }

        while frames.len() < max_frames {
            let Some(stream_id) = self.scheduler.next_stream() else {
                break;
            };

            let Some((offset, data, fin, has_more_send_data)) =
                self.streams.get_mut(&stream_id).and_then(|stream| {
                    stream
                        .get_send_data(max_frame_payload as u64)
                        .map(|(offset, data, fin)| (offset, data, fin, stream.has_send_data()))
                })
            else {
                self.scheduler.mark_blocked(stream_id);
                continue;
            };

            if data.is_empty() && !fin {
                if has_more_send_data {
                    self.scheduler.mark_ready(stream_id);
                } else {
                    self.scheduler.mark_blocked(stream_id);
                }
                continue;
            }

            let frame = match quic_stream_frame(stream_id, offset, data, fin) {
                Outcome::Ok(frame) => frame,
                Outcome::Err(error) => return Outcome::err(error),
                Outcome::Cancelled(reason) => return Outcome::cancelled(reason),
                Outcome::Panicked(payload) => return Outcome::panicked(payload),
            };
            frames.push(frame);

            if has_more_send_data {
                self.scheduler.mark_ready(stream_id);
            } else {
                self.scheduler.mark_blocked(stream_id);
            }
        }

        Outcome::ok(frames)
    }

    /// Close a stream gracefully
    pub fn close_stream(&mut self, cx: &Cx, stream_id: StreamId) -> Outcome<(), StreamError> {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.close();
            if stream.has_send_data() {
                self.scheduler.mark_ready(stream_id);
            } else if stream.is_closed() {
                self.scheduler.unregister_stream(stream_id);
            } else {
                self.scheduler.mark_blocked(stream_id);
            }
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

fn quic_stream_frame(
    stream_id: StreamId,
    offset: u64,
    data: Bytes,
    fin: bool,
) -> Outcome<QuicFrame, StreamError> {
    let stream_id_varint = match VarInt::try_from(stream_id.id) {
        Ok(stream_id) => stream_id,
        Err(error) => {
            return Outcome::err(StreamError::InvalidState {
                stream_id,
                state: format!("stream id cannot be encoded as QUIC varint: {error}"),
            });
        }
    };
    let offset = if offset == 0 {
        None
    } else {
        match VarInt::try_from(offset) {
            Ok(offset) => Some(offset),
            Err(error) => {
                return Outcome::err(StreamError::InvalidState {
                    stream_id,
                    state: format!("stream offset cannot be encoded as QUIC varint: {error}"),
                });
            }
        }
    };

    Outcome::ok(QuicFrame::Stream {
        stream_id: stream_id_varint,
        offset,
        data,
        fin,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cx::cap;
    use crate::net::atp::protocol::packet_assembly::{
        PacketAssembler, PacketConstraints, PacketNumberSpace,
    };

    fn test_cx() -> Cx<cap::All> {
        Cx::for_testing()
    }

    fn assert_stream_id(outcome: Outcome<StreamId, StreamError>, context: &str) -> StreamId {
        match outcome {
            Outcome::Ok(stream_id) => stream_id,
            other => panic!("{context}: expected stream id, got {other:?}"),
        }
    }

    #[test]
    fn close_stream_keeps_fin_schedulable_when_previously_blocked() {
        let cx = test_cx();
        let mut manager = StreamManager::new(false);
        let stream_id = assert_stream_id(
            manager.open_stream(&cx, true, StreamPriority::Data),
            "open client bidirectional stream",
        );

        assert!(manager.mark_stream_blocked(stream_id).is_ok());
        assert!(manager.next_scheduled_stream().is_none());

        assert!(manager.close_stream(&cx, stream_id).is_ok());
        assert_eq!(manager.next_scheduled_stream(), Some(stream_id));
    }

    #[test]
    fn close_stream_does_not_reschedule_after_fin_is_drained() {
        let cx = test_cx();
        let mut manager = StreamManager::new(false);
        let stream_id = assert_stream_id(
            manager.open_stream(&cx, true, StreamPriority::Data),
            "open client bidirectional stream",
        );

        assert!(manager.close_stream(&cx, stream_id).is_ok());
        assert_eq!(manager.next_scheduled_stream(), Some(stream_id));

        let Some(stream) = manager.get_stream_mut(stream_id) else {
            panic!("test stream should remain registered until both halves close");
        };
        let Some((offset, data, fin)) = stream.get_send_data(1024) else {
            panic!("close should produce a FIN-only frame");
        };
        assert_eq!(offset, 0);
        assert!(data.is_empty());
        assert!(fin);

        assert!(manager.close_stream(&cx, stream_id).is_ok());
        assert!(manager.next_scheduled_stream().is_none());
    }

    #[test]
    fn queued_stream_bytes_drain_into_quic_frames_and_packet_bytes() {
        let cx = test_cx();
        let mut manager = StreamManager::new(false);
        let data_stream = assert_stream_id(
            manager.open_stream(&cx, true, StreamPriority::Data),
            "open data stream",
        );
        let control_stream = assert_stream_id(
            manager.open_stream(&cx, true, StreamPriority::Control),
            "open control stream",
        );

        assert!(
            manager
                .queue_stream_data(&cx, data_stream, Bytes::from_static(b"abcdef"), true)
                .is_ok()
        );
        assert!(
            manager
                .queue_stream_data(&cx, control_stream, Bytes::from_static(b"go"), false)
                .is_ok()
        );

        let frames = match manager.drain_quic_stream_frames(3, 3) {
            Outcome::Ok(frames) => frames,
            other => panic!("stream frames should drain cleanly, got {other:?}"),
        };

        assert_eq!(frames.len(), 3);
        assert!(matches!(
            &frames[0],
            QuicFrame::Stream {
                stream_id,
                offset: None,
                data,
                fin: false
            } if stream_id.value() == control_stream.id && data.as_ref() == b"go"
        ));
        assert!(matches!(
            &frames[1],
            QuicFrame::Stream {
                stream_id,
                offset: None,
                data,
                fin: false
            } if stream_id.value() == data_stream.id && data.as_ref() == b"abc"
        ));
        assert!(matches!(
            &frames[2],
            QuicFrame::Stream {
                stream_id,
                offset: Some(offset),
                data,
                fin: true
            } if stream_id.value() == data_stream.id
                && offset.value() == 3
                && data.as_ref() == b"def"
        ));
        assert!(manager.next_scheduled_stream().is_none());

        let mut assembler = PacketAssembler::new(
            PacketConstraints::new()
                .with_packet_number_space(PacketNumberSpace::ApplicationData)
                .without_anti_amplification(),
        );
        for frame in frames {
            assembler.add_quic_frame(frame);
        }

        let packet = assembler
            .assemble_packet()
            .expect("packet assembly should not fail")
            .expect("queued stream frames should produce one packet");
        assert_eq!(packet.frames.len(), 3);
        assert!(packet.ack_eliciting);
        assert!(packet.retransmittable);

        let encoded = packet.encode_frames().expect("encode assembled frames");
        assert!(
            encoded.len() > b"abcdefgo".len(),
            "encoded packet payload should include QUIC frame metadata"
        );
    }

    #[test]
    fn empty_non_fin_send_does_not_emit_stream_frame() {
        let cx = test_cx();
        let mut manager = StreamManager::new(false);
        let stream_id = assert_stream_id(
            manager.open_stream(&cx, true, StreamPriority::Data),
            "open stream",
        );

        assert!(
            manager
                .queue_stream_data(&cx, stream_id, Bytes::new(), false)
                .is_ok()
        );

        let frames = match manager.drain_quic_stream_frames(2, 16) {
            Outcome::Ok(frames) => frames,
            other => panic!("empty non-FIN drain should not fail, got {other:?}"),
        };

        assert!(frames.is_empty());
        assert!(manager.next_scheduled_stream().is_none());
    }
}
