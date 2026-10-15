//! Reference implementation showing how ATP streams should implement two-phase effects.
//!
//! This module provides a corrected ATP stream implementation that follows the
//! two-phase reserve/commit pattern required by the asupersync runtime invariant.

use std::collections::VecDeque;
use std::sync::Arc;

use parking_lot::Mutex;

/// Example ATP stream error type.
#[derive(Debug, Clone)]
pub enum AtpStreamError {
    /// Stream is in invalid state for operation.
    InvalidState(String),
    /// Send queue is full.
    QueueFull,
    /// Data size exceeds limits.
    DataTooLarge { size: usize, max: usize },
}

/// Stream state for the example implementation.
#[derive(Debug, Clone, PartialEq)]
pub enum StreamState {
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
    Error(String),
}

/// Stream direction.
#[derive(Debug, Clone, PartialEq)]
pub enum StreamDirection {
    Bidirectional,
    Outbound,
    Inbound,
}

#[derive(Debug)]
struct SendState {
    send_queue: VecDeque<Vec<u8>>,
    send_queue_high_water: usize,
    reserved_sends: usize,
    max_buffer_size: usize,
}

/// Reference ATP stream using two-phase effects.
pub struct TwoPhasedAtpStream {
    stream_id: u64,
    direction: StreamDirection,
    state: StreamState,
    send: Arc<Mutex<SendState>>,

    // Receive state
    recv_buffer: Vec<u8>,
}

impl TwoPhasedAtpStream {
    /// Create a new ATP stream with two-phase effect support.
    pub fn new(stream_id: u64, direction: StreamDirection) -> Self {
        Self {
            stream_id,
            direction,
            state: StreamState::Open,
            send: Arc::new(Mutex::new(SendState {
                send_queue: VecDeque::new(),
                send_queue_high_water: 16,
                reserved_sends: 0,
                max_buffer_size: 1024 * 1024, // 1MB
            })),
            recv_buffer: Vec::new(),
        }
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

    /// Reserve space for a send operation (Phase 1 of two-phase pattern).
    pub async fn reserve_send(&mut self) -> Result<TwoPhaseStreamPermit, AtpStreamError> {
        // Validate stream state
        if !self.can_send() {
            return Err(AtpStreamError::InvalidState(format!(
                "Cannot send on stream {} in state {:?}",
                self.stream_id, self.state
            )));
        }

        // Check available capacity (including reserved slots)
        let mut send = self.send.lock();
        let total_pending = send.send_queue.len().saturating_add(send.reserved_sends);
        if total_pending >= send.send_queue_high_water {
            return Err(AtpStreamError::QueueFull);
        }

        send.reserved_sends += 1;

        Ok(TwoPhaseStreamPermit::new(
            self.stream_id,
            Arc::clone(&self.send),
        ))
    }

    /// Get the next chunk of data to send.
    pub fn next_send_data(&mut self) -> Option<Vec<u8>> {
        self.send.lock().send_queue.pop_front()
    }

    /// Check if there is data pending to send.
    pub fn has_pending_send(&self) -> bool {
        !self.send.lock().send_queue.is_empty()
    }

    /// Get the current send queue length.
    pub fn send_queue_len(&self) -> usize {
        self.send.lock().send_queue.len()
    }

    /// Get the number of reserved send slots.
    pub fn reserved_sends(&self) -> usize {
        self.send.lock().reserved_sends
    }

    /// Receive data into the stream's buffer.
    pub fn receive(&mut self, data: &[u8]) -> Result<(), AtpStreamError> {
        let max_buffer_size = self.send.lock().max_buffer_size;
        let buffered_size =
            self.recv_buffer
                .len()
                .checked_add(data.len())
                .ok_or(AtpStreamError::DataTooLarge {
                    size: usize::MAX,
                    max: max_buffer_size,
                })?;
        if buffered_size > max_buffer_size {
            return Err(AtpStreamError::DataTooLarge {
                size: buffered_size,
                max: max_buffer_size,
            });
        }

        self.recv_buffer.extend_from_slice(data);
        Ok(())
    }

    /// Read data from the receive buffer.
    pub fn read_data(&mut self, buf: &mut [u8]) -> usize {
        let to_read = buf.len().min(self.recv_buffer.len());
        buf[..to_read].copy_from_slice(&self.recv_buffer[..to_read]);
        self.recv_buffer.drain(..to_read);
        to_read
    }

    /// Get stream statistics.
    pub fn stats(&self) -> StreamStats {
        StreamStats {
            stream_id: self.stream_id,
            direction: self.direction.clone(),
            state: self.state.clone(),
            send_queue_len: self.send_queue_len(),
            reserved_sends: self.reserved_sends(),
            recv_buffer_len: self.recv_buffer.len(),
        }
    }
}

fn commit_reserved_send(
    stream_id: u64,
    send: &Arc<Mutex<SendState>>,
    data: &[u8],
) -> Result<(), AtpStreamError> {
    let mut send = send.lock();
    if send.reserved_sends == 0 {
        return Err(AtpStreamError::InvalidState(format!(
            "No reserved send slot for stream {stream_id}"
        )));
    }

    if data.len() > send.max_buffer_size {
        send.reserved_sends -= 1;
        return Err(AtpStreamError::DataTooLarge {
            size: data.len(),
            max: send.max_buffer_size,
        });
    }

    send.send_queue.push_back(data.to_vec());
    send.reserved_sends -= 1;
    Ok(())
}

fn abort_reserved_send(send: &Arc<Mutex<SendState>>) {
    let mut send = send.lock();
    if send.reserved_sends > 0 {
        send.reserved_sends -= 1;
    }
}

/// Permit for two-phase stream sends.
pub struct TwoPhaseStreamPermit {
    stream_id: u64,
    send: Arc<Mutex<SendState>>,
    committed: bool,
}

impl TwoPhaseStreamPermit {
    fn new(stream_id: u64, send: Arc<Mutex<SendState>>) -> Self {
        Self {
            stream_id,
            send,
            committed: false,
        }
    }

    /// Commit the send operation with the given data.
    pub fn commit(mut self, data: &[u8]) -> Result<(), AtpStreamError> {
        assert!(!self.committed, "Permit already used"); // ubs:ignore - test oracle

        let result = commit_reserved_send(self.stream_id, &self.send, data);
        self.committed = true;
        result
    }

    /// Abort the send operation.
    pub fn abort(mut self) {
        abort_reserved_send(&self.send);
        self.committed = true;
    }
}

impl Drop for TwoPhaseStreamPermit {
    fn drop(&mut self) {
        if !self.committed {
            abort_reserved_send(&self.send);
        }
    }
}

/// Statistics for an ATP stream.
#[derive(Debug, Clone)]
pub struct StreamStats {
    pub stream_id: u64,
    pub direction: StreamDirection,
    pub state: StreamState,
    pub send_queue_len: usize,
    pub reserved_sends: usize,
    pub recv_buffer_len: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_lite::future;

    #[test]
    fn test_two_phase_send_success() {
        future::block_on(async {
            let mut stream = TwoPhasedAtpStream::new(42, StreamDirection::Bidirectional);

            // Reserve
            let permit = stream.reserve_send().await.unwrap(); // ubs:ignore - test oracle
            assert_eq!(stream.reserved_sends(), 1);
            assert_eq!(stream.send_queue_len(), 0);

            permit.commit(b"test data").unwrap(); // ubs:ignore - test oracle
            assert_eq!(stream.reserved_sends(), 0);
            assert_eq!(stream.send_queue_len(), 1);

            // Verify data can be retrieved
            let data = stream.next_send_data().unwrap(); // ubs:ignore - test oracle
            assert_eq!(data, b"test data");
        });
    }

    #[test]
    fn test_two_phase_send_abort() {
        future::block_on(async {
            let mut stream = TwoPhasedAtpStream::new(42, StreamDirection::Bidirectional);

            // Reserve
            let permit = stream.reserve_send().await.unwrap(); // ubs:ignore - test oracle
            assert_eq!(stream.reserved_sends(), 1);

            permit.abort();
            assert_eq!(stream.reserved_sends(), 0);
            assert_eq!(stream.send_queue_len(), 0);
        });
    }

    #[test]
    fn test_dropped_permit_releases_reservation() {
        future::block_on(async {
            let mut stream = TwoPhasedAtpStream::new(42, StreamDirection::Bidirectional);

            let permit = stream.reserve_send().await.unwrap(); // ubs:ignore - test oracle
            assert_eq!(stream.reserved_sends(), 1);

            drop(permit);
            assert_eq!(stream.reserved_sends(), 0);
            assert_eq!(stream.send_queue_len(), 0);
        });
    }

    #[test]
    fn test_queue_full_prevents_reservation() {
        future::block_on(async {
            let mut stream = TwoPhasedAtpStream::new(42, StreamDirection::Bidirectional);
            stream.send.lock().send_queue_high_water = 2;

            // Fill queue to high water mark
            let permit1 = stream.reserve_send().await.unwrap(); // ubs:ignore - test oracle
            let permit2 = stream.reserve_send().await.unwrap(); // ubs:ignore - test oracle

            // Third reservation should fail
            assert!(matches!(
                stream.reserve_send().await,
                Err(AtpStreamError::QueueFull)
            ));

            // Clean up by aborting reservations
            permit1.abort();
            permit2.abort();
        });
    }

    #[test]
    fn test_data_too_large() {
        future::block_on(async {
            let mut stream = TwoPhasedAtpStream::new(42, StreamDirection::Bidirectional);
            stream.send.lock().max_buffer_size = 10;

            let permit = stream.reserve_send().await.unwrap(); // ubs:ignore - test oracle

            let result = permit.commit(b"this is too long");
            assert!(matches!(result, Err(AtpStreamError::DataTooLarge { .. })));
            assert_eq!(stream.reserved_sends(), 0); // Reservation cleaned up
        });
    }

    #[test]
    fn test_reservations_are_independent() {
        future::block_on(async {
            let mut stream = TwoPhasedAtpStream::new(42, StreamDirection::Bidirectional);

            let first = stream.reserve_send().await.unwrap(); // ubs:ignore - test oracle
            let second = stream.reserve_send().await.unwrap(); // ubs:ignore - test oracle
            assert_eq!(stream.reserved_sends(), 2);

            first.abort();
            assert_eq!(stream.reserved_sends(), 1);

            second.commit(b"still reserved").unwrap(); // ubs:ignore - test oracle
            assert_eq!(stream.reserved_sends(), 0);
            assert_eq!(stream.next_send_data().unwrap(), b"still reserved");
        });
    }

    #[test]
    fn test_receive_rejects_over_limit_without_mutating_buffer() {
        let mut stream = TwoPhasedAtpStream::new(42, StreamDirection::Bidirectional);
        stream.send.lock().max_buffer_size = 5;

        stream.receive(b"abc").unwrap(); // ubs:ignore - test oracle

        let result = stream.receive(b"def");
        assert!(matches!(
            result,
            Err(AtpStreamError::DataTooLarge { size: 6, max: 5 })
        ));
        assert_eq!(stream.stats().recv_buffer_len, 3);

        let mut buffer = [0; 5];
        assert_eq!(stream.read_data(&mut buffer), 3);
        assert_eq!(&buffer[..3], b"abc");
    }

    #[test]
    fn test_cannot_send_on_inbound_stream() {
        future::block_on(async {
            let mut stream = TwoPhasedAtpStream::new(42, StreamDirection::Inbound);

            assert!(matches!(
                stream.reserve_send().await,
                Err(AtpStreamError::InvalidState(_))
            ));
        });
    }
}
