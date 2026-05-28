//! ATP Stream Implementation
//!
//! Implements individual QUIC streams with send/receive capabilities,
//! flow control integration, and proper state management.

use super::{
    DataSegment, FlowControlWindow, ReassemblyBuffer, StopSendingCode, StreamError, StreamId,
    StreamPriority, StreamResetCode,
};
use crate::bytes::Bytes;
use crate::cx::Cx;
use crate::types::outcome::Outcome;
use std::collections::VecDeque;

/// Stream state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamState {
    /// Stream is open and can send/receive
    Open,
    /// Local end closed (FIN sent)
    LocalClosed,
    /// Remote end closed (FIN received)
    RemoteClosed,
    /// Both ends closed gracefully
    Closed,
    /// Stream reset by local
    ResetLocal { code: StreamResetCode },
    /// Stream reset by remote
    ResetRemote { code: StreamResetCode },
    /// Stream reset by both
    ResetBoth {
        local_code: StreamResetCode,
        remote_code: StreamResetCode,
    },
}

/// Send state for stream
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendState {
    /// Ready to send data
    Ready,
    /// Sending data
    Send,
    /// Data sent, waiting for ACK
    DataSent,
    /// Reset sent
    ResetSent { code: StreamResetCode },
    /// Reset confirmed
    ResetRecvd,
}

/// Receive state for stream
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiveState {
    /// Ready to receive data
    Recv,
    /// Receiving data
    SizeKnown,
    /// Data complete
    DataRecvd,
    /// Reset received
    ResetRecvd { code: StreamResetCode },
    /// Reset read
    ResetRead,
}

/// An ATP stream with send/receive capabilities
#[derive(Debug)]
pub struct AtpStream {
    /// Stream identifier
    id: StreamId,
    /// Stream priority class
    priority: StreamPriority,
    /// Whether this is a bidirectional stream
    is_bidirectional: bool,
    /// Whether this is an outgoing stream (we initiated it)
    is_outgoing: bool,
    /// Overall stream state
    state: StreamState,
    /// Send state
    send_state: SendState,
    /// Receive state
    receive_state: ReceiveState,
    /// Flow control window
    flow_control: FlowControlWindow,
    /// Reassembly buffer for incoming data
    reassembly: ReassemblyBuffer,
    /// Send buffer for outgoing data
    send_buffer: VecDeque<Bytes>,
    /// Next offset to send
    next_send_offset: u64,
    /// Bytes sent but not yet acknowledged
    bytes_in_flight: u64,
    /// Whether STOP_SENDING was sent
    stop_sending_sent: Option<StopSendingCode>,
    /// Whether STOP_SENDING was received
    stop_sending_received: Option<StopSendingCode>,
    /// Final send size if FIN sent
    final_send_size: Option<u64>,
    /// Whether this stream has data ready to send
    ready_to_send: bool,
    /// Whether this stream is blocked on flow control
    send_blocked: bool,
}

impl AtpStream {
    /// Create a new ATP stream
    pub fn new(
        id: StreamId,
        is_bidirectional: bool,
        priority: StreamPriority,
        is_outgoing: bool,
    ) -> Self {
        Self {
            id,
            priority,
            is_bidirectional,
            is_outgoing,
            state: StreamState::Open,
            send_state: SendState::Ready,
            receive_state: ReceiveState::Recv,
            flow_control: FlowControlWindow::new(65536, 65536), // Default 64KB windows
            reassembly: ReassemblyBuffer::new(1048576),         // 1MB reassembly buffer
            send_buffer: VecDeque::new(),
            next_send_offset: 0,
            bytes_in_flight: 0,
            stop_sending_sent: None,
            stop_sending_received: None,
            final_send_size: None,
            ready_to_send: false,
            send_blocked: false,
        }
    }

    /// Get stream ID
    pub fn id(&self) -> StreamId {
        self.id
    }

    /// Get stream priority
    pub fn priority(&self) -> StreamPriority {
        self.priority
    }

    /// Check if stream is bidirectional
    pub fn is_bidirectional(&self) -> bool {
        self.is_bidirectional
    }

    /// Check if stream is outgoing (we initiated it)
    pub fn is_outgoing(&self) -> bool {
        self.is_outgoing
    }

    /// Get current stream state
    pub fn state(&self) -> &StreamState {
        &self.state
    }

    /// Check if stream is closed
    pub fn is_closed(&self) -> bool {
        matches!(
            self.state,
            StreamState::Closed
                | StreamState::ResetLocal { .. }
                | StreamState::ResetRemote { .. }
                | StreamState::ResetBoth { .. }
        )
    }

    /// Check if stream can send data
    pub fn can_send(&self) -> bool {
        matches!(
            self.send_state,
            SendState::Ready | SendState::Send | SendState::DataSent
        ) && !matches!(
            self.state,
            StreamState::ResetLocal { .. } | StreamState::ResetBoth { .. }
        )
    }

    /// Check if stream can receive data
    pub fn can_receive(&self) -> bool {
        matches!(
            self.receive_state,
            ReceiveState::Recv | ReceiveState::SizeKnown
        ) && !matches!(
            self.state,
            StreamState::ResetRemote { .. } | StreamState::ResetBoth { .. }
        )
    }

    /// Queue data for sending
    pub fn queue_send(&mut self, cx: &Cx, data: Bytes, fin: bool) -> Outcome<(), StreamError> {
        if !self.can_send() {
            return Outcome::err(StreamError::InvalidState {
                stream_id: self.id,
                state: format!("Cannot send in state {:?}", self.send_state),
            });
        }

        if self.final_send_size.is_some() {
            return Outcome::err(StreamError::InvalidState {
                stream_id: self.id,
                state: "Cannot queue send data after stream final size is known".to_string(),
            });
        }

        self.send_buffer.push_back(data.clone());
        self.ready_to_send = true;

        if fin {
            self.final_send_size = Some(self.next_send_offset + self.pending_send_bytes());
            self.send_state = SendState::DataSent;
        }

        cx.trace(&format!(
            "stream_send_queued stream_id={:?} bytes={} fin={} ready={}",
            self.id,
            data.len(),
            fin,
            self.ready_to_send
        ));

        Outcome::ok(())
    }

    /// Get data ready to send (respecting flow control)
    pub fn get_send_data(&mut self, max_bytes: u64) -> Option<(u64, Bytes, bool)> {
        if !self.ready_to_send || self.send_blocked {
            return None;
        }

        if max_bytes == 0
            && self
                .send_buffer
                .front()
                .is_some_and(|data| !data.is_empty())
        {
            return None;
        }

        if let Some(data) = self.send_buffer.pop_front() {
            let offset = self.next_send_offset;
            let bytes_to_send = std::cmp::min(data.len() as u64, max_bytes);
            let data_to_send = data.slice(0..bytes_to_send as usize);

            // If we didn't send all the data, put the rest back
            if bytes_to_send < data.len() as u64 {
                let remaining = data.slice(bytes_to_send as usize..);
                self.send_buffer.push_front(remaining);
            } else {
                // Check if this is the last data and we should send FIN
                if self.send_buffer.is_empty() && self.final_send_size.is_some() {
                    self.ready_to_send = false;
                }
            }

            self.next_send_offset += bytes_to_send;
            self.bytes_in_flight += bytes_to_send;

            let is_fin = self.final_send_size == Some(self.next_send_offset);
            if is_fin {
                self.update_stream_state_on_send_complete();
            }

            Some((offset, data_to_send, is_fin))
        } else if self.final_send_size == Some(self.next_send_offset) {
            self.ready_to_send = false;
            self.update_stream_state_on_send_complete();
            Some((self.next_send_offset, Bytes::new(), true))
        } else {
            None
        }
    }

    /// Receive data segment
    pub fn receive_data(
        &mut self,
        cx: &Cx,
        offset: u64,
        data: Bytes,
        fin: bool,
    ) -> Outcome<Vec<Bytes>, StreamError> {
        if !self.can_receive() {
            return Outcome::err(StreamError::InvalidState {
                stream_id: self.id,
                state: format!("Cannot receive in state {:?}", self.receive_state),
            });
        }

        let segment = DataSegment::new(offset, data.clone(), fin);

        cx.trace(&format!(
            "stream_data_received stream_id={:?} offset={} bytes={} fin={}",
            self.id,
            offset,
            data.len(),
            fin
        ));

        match self.reassembly.insert_segment(segment) {
            Outcome::Ok(deliverable) => {
                if fin {
                    if self.reassembly.is_complete() {
                        self.receive_state = ReceiveState::DataRecvd;
                        self.update_stream_state_on_receive_complete();
                    } else {
                        self.receive_state = ReceiveState::SizeKnown;
                    }
                }

                Outcome::ok(deliverable)
            }
            Outcome::Err(mut error) => {
                // Fill in stream ID for errors from reassembly
                match &mut error {
                    StreamError::FinalSizeMismatch { stream_id, .. } => {
                        *stream_id = self.id;
                    }
                    StreamError::InvalidState { stream_id, .. } => {
                        *stream_id = self.id;
                    }
                    _ => {}
                }
                Outcome::err(error)
            }
            Outcome::Cancelled(reason) => Outcome::cancelled(reason),
            Outcome::Panicked(payload) => Outcome::panicked(payload),
        }
    }

    /// Reset the stream
    pub fn reset(&mut self, code: StreamResetCode) {
        match &self.state {
            StreamState::Open => {
                self.state = StreamState::ResetLocal { code };
                self.send_state = SendState::ResetSent { code };
            }
            StreamState::RemoteClosed => {
                self.state = StreamState::ResetLocal { code };
                self.send_state = SendState::ResetSent { code };
            }
            StreamState::ResetRemote { code: remote_code } => {
                self.state = StreamState::ResetBoth {
                    local_code: code,
                    remote_code: *remote_code,
                };
                self.send_state = SendState::ResetSent { code };
            }
            _ => {
                // Already reset or closed
            }
        }

        self.clear_send_buffer();
        self.ready_to_send = false;
    }

    /// Handle remote reset
    pub fn handle_remote_reset(&mut self, code: StreamResetCode) {
        match &self.state {
            StreamState::Open => {
                self.state = StreamState::ResetRemote { code };
                self.receive_state = ReceiveState::ResetRecvd { code };
            }
            StreamState::LocalClosed => {
                self.state = StreamState::ResetRemote { code };
                self.receive_state = ReceiveState::ResetRecvd { code };
            }
            StreamState::ResetLocal { code: local_code } => {
                self.state = StreamState::ResetBoth {
                    local_code: *local_code,
                    remote_code: code,
                };
                self.receive_state = ReceiveState::ResetRecvd { code };
            }
            _ => {
                // Already reset or closed
            }
        }

        self.reassembly.reset();
    }

    /// Send STOP_SENDING to peer
    pub fn stop_sending(&mut self, code: StopSendingCode) {
        self.stop_sending_sent = Some(code);
    }

    /// Handle STOP_SENDING from peer
    pub fn handle_stop_sending(&mut self, code: StopSendingCode) {
        self.stop_sending_received = Some(code);
        self.clear_send_buffer();
        self.ready_to_send = false;
    }

    /// Close the stream gracefully (send FIN)
    pub fn close(&mut self) {
        if self.can_send() && self.final_send_size.is_none() {
            self.final_send_size = Some(self.next_send_offset + self.pending_send_bytes());
            self.send_state = SendState::DataSent;
            self.ready_to_send = true;
        }
    }

    /// Update stream priority
    pub fn set_priority(&mut self, priority: StreamPriority) {
        self.priority = priority;
    }

    /// Check if stream has data ready to send
    pub fn has_send_data(&self) -> bool {
        self.ready_to_send && !self.send_blocked
    }

    /// Mark stream as flow control blocked
    pub fn mark_send_blocked(&mut self) {
        self.send_blocked = true;
    }

    /// Mark stream as flow control unblocked
    pub fn mark_send_unblocked(&mut self) {
        self.send_blocked = false;
    }

    /// Acknowledge sent data
    pub fn ack_data(&mut self, bytes: u64) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes);
        self.flow_control.record_acked(bytes);
    }

    /// Get flow control statistics
    pub fn flow_control_stats(&self) -> &FlowControlWindow {
        &self.flow_control
    }

    /// Get mutable flow control window
    pub fn flow_control_mut(&mut self) -> &mut FlowControlWindow {
        &mut self.flow_control
    }

    /// Get stream statistics
    pub fn statistics(&self) -> StreamStats {
        StreamStats {
            id: self.id,
            priority: self.priority,
            state: self.state.clone(),
            send_state: self.send_state.clone(),
            receive_state: self.receive_state.clone(),
            send_buffer_size: self.send_buffer.len(),
            next_send_offset: self.next_send_offset,
            bytes_in_flight: self.bytes_in_flight,
            reassembly_stats: self.reassembly.statistics(),
            flow_control_stats: self.flow_control.statistics(),
        }
    }

    /// Clear the send buffer
    fn clear_send_buffer(&mut self) {
        self.send_buffer.clear();
    }

    /// Count queued but unsent payload bytes.
    fn pending_send_bytes(&self) -> u64 {
        self.send_buffer
            .iter()
            .map(|segment| segment.len() as u64)
            .sum()
    }

    /// Update stream state when local send is complete.
    fn update_stream_state_on_send_complete(&mut self) {
        match &self.state {
            StreamState::Open => {
                self.state = StreamState::LocalClosed;
            }
            StreamState::RemoteClosed => {
                self.state = StreamState::Closed;
            }
            _ => {
                // Already closed or reset.
            }
        }
    }

    /// Update stream state when receive is complete
    fn update_stream_state_on_receive_complete(&mut self) {
        match &self.state {
            StreamState::Open => {
                self.state = StreamState::RemoteClosed;
            }
            StreamState::LocalClosed => {
                self.state = StreamState::Closed;
            }
            _ => {
                // Already closed or reset
            }
        }
    }
}

/// Stream statistics
#[derive(Debug, Clone)]
pub struct StreamStats {
    pub id: StreamId,
    pub priority: StreamPriority,
    pub state: StreamState,
    pub send_state: SendState,
    pub receive_state: ReceiveState,
    pub send_buffer_size: usize,
    pub next_send_offset: u64,
    pub bytes_in_flight: u64,
    pub reassembly_stats: super::ReassemblyStats,
    pub flow_control_stats: super::FlowControlStats,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cx::{Cx, cap};

    fn test_cx() -> Cx<cap::All> {
        Cx::for_testing()
    }

    fn assert_receive_ok(outcome: Outcome<Vec<Bytes>, StreamError>, context: &str) -> Vec<Bytes> {
        match outcome {
            Outcome::Ok(received) => received,
            other => panic!("{context}: expected receive_data to succeed, got {other:?}"),
        }
    }

    #[test]
    fn test_stream_send_receive() {
        let cx = test_cx();
        let mut stream = AtpStream::new(StreamId::new(0), true, StreamPriority::Data, true);

        // Queue some data for sending
        let data = Bytes::from("hello world");
        assert!(stream.queue_send(&cx, data.clone(), false).is_ok());
        assert!(stream.has_send_data());

        // Get data to send
        if let Some((offset, send_data, fin)) = stream.get_send_data(1000) {
            assert_eq!(offset, 0);
            assert_eq!(send_data, data);
            assert!(!fin);
        } else {
            panic!("Should have data to send");
        }

        // Receive the same data
        let received =
            assert_receive_ok(stream.receive_data(&cx, 0, data, false), "in-order receive");
        assert_eq!(received.len(), 1);
        assert_eq!(received[0], Bytes::from("hello world"));
    }

    #[test]
    fn test_stream_reset() {
        let mut stream = AtpStream::new(StreamId::new(4), true, StreamPriority::Control, false);

        assert!(!stream.is_closed());

        stream.reset(StreamResetCode::ApplicationClose);
        assert!(stream.is_closed());
        assert!(matches!(stream.state, StreamState::ResetLocal { .. }));
    }

    #[test]
    fn test_stream_out_of_order_receive() {
        let cx = test_cx();
        let mut stream = AtpStream::new(StreamId::new(8), true, StreamPriority::Data, false);

        // Receive data out of order
        let data1 = assert_receive_ok(
            stream.receive_data(&cx, 5, Bytes::from("world"), false),
            "out-of-order suffix receive",
        );
        assert_eq!(data1.len(), 0); // Buffered, not delivered

        let data2 = assert_receive_ok(
            stream.receive_data(&cx, 0, Bytes::from("hello"), false),
            "out-of-order prefix receive",
        );
        assert_eq!(data2.len(), 2); // Both segments delivered
        assert_eq!(data2[0], Bytes::from("hello"));
        assert_eq!(data2[1], Bytes::from("world"));
    }

    #[test]
    fn test_stream_fin_handling() {
        let cx = test_cx();
        let mut stream = AtpStream::new(StreamId::new(12), true, StreamPriority::Data, true);

        // Send with FIN
        let data = Bytes::from("final data");
        assert!(stream.queue_send(&cx, data.clone(), true).is_ok());

        // Get data should include FIN
        if let Some((offset, send_data, fin)) = stream.get_send_data(1000) {
            assert_eq!(offset, 0);
            assert_eq!(send_data, data);
            assert!(fin);
        }

        // Receive with FIN should complete the stream
        let received = assert_receive_ok(
            stream.receive_data(&cx, 0, data, true),
            "receive with final size",
        );
        assert_eq!(received.len(), 1);
        assert!(matches!(stream.receive_state, ReceiveState::DataRecvd));
    }

    #[test]
    fn test_stream_close_emits_fin_only_frame() {
        let mut stream = AtpStream::new(StreamId::new(16), true, StreamPriority::Data, true);

        stream.close();

        if let Some((offset, data, fin)) = stream.get_send_data(1000) {
            assert_eq!(offset, 0);
            assert!(data.is_empty());
            assert!(fin);
        } else {
            panic!("close without buffered data should emit a FIN-only frame");
        }

        assert!(!stream.has_send_data());
        assert!(matches!(stream.state, StreamState::LocalClosed));
    }

    #[test]
    fn test_stream_close_fin_covers_buffered_unsent_data() {
        let cx = test_cx();
        let mut stream = AtpStream::new(StreamId::new(20), true, StreamPriority::Data, true);

        assert!(stream.queue_send(&cx, Bytes::from("hello"), false).is_ok());
        assert!(stream.queue_send(&cx, Bytes::from("world"), false).is_ok());

        stream.close();

        if let Some((offset, data, fin)) = stream.get_send_data(5) {
            assert_eq!(offset, 0);
            assert_eq!(data, Bytes::from("hello"));
            assert!(!fin);
        } else {
            panic!("first buffered segment should be sendable after close");
        }

        if let Some((offset, data, fin)) = stream.get_send_data(5) {
            assert_eq!(offset, 5);
            assert_eq!(data, Bytes::from("world"));
            assert!(fin);
        } else {
            panic!("final buffered segment should carry FIN after close");
        }

        assert!(!stream.has_send_data());
        assert!(matches!(stream.state, StreamState::LocalClosed));
    }

    #[test]
    fn test_stream_queue_fin_accounts_for_prior_buffered_data() {
        let cx = test_cx();
        let mut stream = AtpStream::new(StreamId::new(24), true, StreamPriority::Data, true);

        assert!(stream.queue_send(&cx, Bytes::from("hello"), false).is_ok());
        assert!(stream.queue_send(&cx, Bytes::from("world"), true).is_ok());

        if let Some((offset, data, fin)) = stream.get_send_data(5) {
            assert_eq!(offset, 0);
            assert_eq!(data, Bytes::from("hello"));
            assert!(!fin);
        } else {
            panic!("previously queued data should be sent before FIN");
        }

        if let Some((offset, data, fin)) = stream.get_send_data(5) {
            assert_eq!(offset, 5);
            assert_eq!(data, Bytes::from("world"));
            assert!(fin);
        } else {
            panic!("segment queued with FIN should carry FIN at combined final size");
        }

        assert!(!stream.has_send_data());
        assert!(matches!(stream.state, StreamState::LocalClosed));
    }

    #[test]
    fn test_stream_get_send_data_zero_budget_does_not_emit_payload_frame() {
        let cx = test_cx();
        let mut stream = AtpStream::new(StreamId::new(28), true, StreamPriority::Data, true);

        assert!(stream.queue_send(&cx, Bytes::from("hello"), false).is_ok());

        assert!(stream.get_send_data(0).is_none());
        assert!(stream.has_send_data());

        if let Some((offset, data, fin)) = stream.get_send_data(5) {
            assert_eq!(offset, 0);
            assert_eq!(data, Bytes::from("hello"));
            assert!(!fin);
        } else {
            panic!("payload should still be sendable after zero-budget poll");
        }
    }

    #[test]
    fn test_stream_rejects_queue_send_after_final_size_is_known() {
        let cx = test_cx();
        let mut stream = AtpStream::new(StreamId::new(32), true, StreamPriority::Data, true);

        assert!(stream.queue_send(&cx, Bytes::from("final"), true).is_ok());

        match stream.queue_send(&cx, Bytes::from("late"), false) {
            Outcome::Err(StreamError::InvalidState { stream_id, state }) => {
                assert_eq!(stream_id, StreamId::new(32));
                assert!(state.contains("final size"));
            }
            other => panic!("late send after FIN should be rejected, got {other:?}"),
        }
    }
}
