//! Stream Data Reassembly
//!
//! Handles out-of-order stream data reception and reassembly for QUIC streams.
//! Maintains proper ordering and detects final size violations.

use super::{StreamError, StreamId};
use crate::bytes::Bytes;
use crate::types::outcome::Outcome;
use std::collections::BTreeMap;

/// A segment of stream data with offset
#[derive(Debug, Clone)]
pub struct DataSegment {
    /// Offset in the stream
    pub offset: u64,
    /// The actual data bytes
    pub data: Bytes,
    /// Whether this segment contains the final byte of the stream
    pub is_final: bool,
}

impl DataSegment {
    /// Create a new data segment
    pub fn new(offset: u64, data: Bytes, is_final: bool) -> Self {
        Self {
            offset,
            data,
            is_final,
        }
    }

    /// Get the end offset of this segment (exclusive)
    pub fn end_offset(&self) -> u64 {
        self.offset + self.data.len() as u64
    }

    /// Check if this segment overlaps with another
    pub fn overlaps_with(&self, other: &DataSegment) -> bool {
        self.offset < other.end_offset() && other.offset < self.end_offset()
    }

    /// Check if this segment is adjacent to another
    pub fn is_adjacent_to(&self, other: &DataSegment) -> bool {
        self.end_offset() == other.offset || other.end_offset() == self.offset
    }
}

/// Stream data reassembly buffer
#[derive(Debug)]
pub struct ReassemblyBuffer {
    /// Buffered data segments, keyed by offset
    segments: BTreeMap<u64, DataSegment>,
    /// Next expected offset for delivery
    next_offset: u64,
    /// Final size of the stream if known
    final_size: Option<u64>,
    /// Whether we've received the final segment
    received_final: bool,
    /// Maximum buffered data to prevent memory exhaustion
    max_buffered_data: u64,
    /// Current amount of buffered data
    buffered_data_size: u64,
}

impl ReassemblyBuffer {
    /// Create a new reassembly buffer
    pub fn new(max_buffered_data: u64) -> Self {
        Self {
            segments: BTreeMap::new(),
            next_offset: 0,
            final_size: None,
            received_final: false,
            max_buffered_data,
            buffered_data_size: 0,
        }
    }

    /// Insert a data segment into the buffer
    pub fn insert_segment(&mut self, mut segment: DataSegment) -> Outcome<Vec<Bytes>, StreamError> {
        // Handle overlap with already delivered data
        if segment.offset < self.next_offset {
            if segment.end_offset() <= self.next_offset {
                // Completely duplicate (already delivered), ignore it
                return Outcome::ok(Vec::new());
            }
            // Partially duplicate, truncate the already-delivered portion
            let duplicate_len = (self.next_offset - segment.offset) as usize;
            segment.data = segment.data.slice(duplicate_len..);
            segment.offset = self.next_offset;
        }

        // Check for final size consistency
        if segment.is_final {
            let segment_final_size = segment.end_offset();
            if let Some(existing_final_size) = self.final_size {
                if segment_final_size != existing_final_size {
                    return Outcome::err(StreamError::FinalSizeMismatch {
                        stream_id: StreamId::new(0), // Will be filled by caller
                        expected: existing_final_size,
                        actual: segment_final_size,
                    });
                }
            } else {
                self.final_size = Some(segment_final_size);
            }
            self.received_final = true;
        }

        // Check if this would exceed our buffering limit
        let new_data_size = segment.data.len() as u64;
        if self.buffered_data_size + new_data_size > self.max_buffered_data {
            return Outcome::err(StreamError::ConnectionError {
                reason: "Reassembly buffer limit exceeded".to_string(),
            });
        }

        // Check for overlaps with existing segments
        for existing_segment in self.segments.values() {
            if segment.overlaps_with(existing_segment) {
                // For now, we reject overlapping segments
                // A more sophisticated implementation could merge them
                return Outcome::err(StreamError::InvalidState {
                    stream_id: StreamId::new(0), // Will be filled by caller
                    state: format!("Overlapping segment at offset {}", segment.offset), // ubs:ignore - error path only
                });
            }
        }

        // Insert the segment
        let offset = segment.offset;
        self.buffered_data_size += new_data_size;
        self.segments.insert(offset, segment);

        // Try to deliver consecutive data starting from next_offset
        let deliverable = self.extract_deliverable_data();

        Outcome::ok(deliverable)
    }

    /// Extract data that can be delivered in order
    fn extract_deliverable_data(&mut self) -> Vec<Bytes> {
        let mut deliverable = Vec::new();

        while let Some((&offset, _)) = self.segments.iter().next() {
            if offset != self.next_offset {
                // Gap in the stream, can't deliver yet
                break;
            }

            // Remove and deliver this segment
            if let Some(segment) = self.segments.remove(&offset) {
                self.next_offset = segment.end_offset();
                self.buffered_data_size -= segment.data.len() as u64;
                deliverable.push(segment.data);
            }
        }

        deliverable
    }

    /// Check if the stream is complete (all data received and delivered)
    pub fn is_complete(&self) -> bool {
        self.received_final
            && self.segments.is_empty()
            && self.final_size.is_some_and(|size| self.next_offset >= size)
    }

    /// Get the current next expected offset
    pub fn next_expected_offset(&self) -> u64 {
        self.next_offset
    }

    /// Get the final size if known
    pub fn final_size(&self) -> Option<u64> {
        self.final_size
    }

    /// Check if we've received the final segment
    pub fn received_final_segment(&self) -> bool {
        self.received_final
    }

    /// Get the number of buffered segments
    pub fn buffered_segments(&self) -> usize {
        self.segments.len()
    }

    /// Get the amount of buffered data
    pub fn buffered_data_size(&self) -> u64 {
        self.buffered_data_size
    }

    /// Get statistics about the reassembly buffer
    pub fn statistics(&self) -> ReassemblyStats {
        let gaps = self.count_gaps();

        ReassemblyStats {
            next_offset: self.next_offset,
            final_size: self.final_size,
            buffered_segments: self.segments.len(),
            buffered_data_size: self.buffered_data_size,
            max_buffered_data: self.max_buffered_data,
            gaps: gaps,
            is_complete: self.is_complete(),
        }
    }

    /// Count the number of gaps in the buffered data
    fn count_gaps(&self) -> usize {
        let mut gaps = 0;
        let mut expected_offset = self.next_offset;

        for (&offset, segment) in &self.segments {
            if offset > expected_offset {
                gaps += 1;
            }
            expected_offset = segment.end_offset();
        }

        gaps
    }

    /// Reset the buffer (for stream reset)
    pub fn reset(&mut self) {
        self.segments.clear();
        self.next_offset = 0;
        self.final_size = None;
        self.received_final = false;
        self.buffered_data_size = 0;
    }

    /// Check if buffer has any gaps
    pub fn has_gaps(&self) -> bool {
        self.count_gaps() > 0
    }

    /// Get the earliest gap offset
    pub fn earliest_gap_offset(&self) -> Option<u64> {
        if self.segments.is_empty() {
            return None;
        }

        let mut expected_offset = self.next_offset;
        for (&offset, segment) in &self.segments {
            if offset > expected_offset {
                return Some(expected_offset);
            }
            expected_offset = segment.end_offset();
        }

        None
    }
}

/// Reassembly statistics
#[derive(Debug, Clone)]
pub struct ReassemblyStats {
    pub next_offset: u64,
    pub final_size: Option<u64>,
    pub buffered_segments: usize,
    pub buffered_data_size: u64,
    pub max_buffered_data: u64,
    pub gaps: usize,
    pub is_complete: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::Bytes;

    #[test]
    fn test_reassembly_in_order() {
        let mut buffer = ReassemblyBuffer::new(10000);

        let segment1 = DataSegment::new(0, Bytes::from("hello"), false);
        let segment2 = DataSegment::new(5, Bytes::from("world"), true);

        let result1 = buffer.insert_segment(segment1).unwrap(); // ubs:ignore - test oracle
        assert_eq!(result1.len(), 1);
        assert_eq!(&result1[0][..], b"hello");

        let result2 = buffer.insert_segment(segment2).unwrap(); // ubs:ignore - test oracle
        assert_eq!(result2.len(), 1);
        assert_eq!(&result2[0][..], b"world");

        assert!(buffer.is_complete());
        assert_eq!(buffer.final_size(), Some(10));
    }

    #[test]
    fn test_reassembly_out_of_order() {
        let mut buffer = ReassemblyBuffer::new(10000);

        // Insert segments out of order
        let segment2 = DataSegment::new(5, Bytes::from("world"), true);
        let segment1 = DataSegment::new(0, Bytes::from("hello"), false);

        // Second segment first - should be buffered
        let result1 = buffer.insert_segment(segment2).unwrap(); // ubs:ignore - test oracle
        assert_eq!(result1.len(), 0); // Nothing deliverable yet

        // First segment - should deliver both
        let result2 = buffer.insert_segment(segment1).unwrap(); // ubs:ignore - test oracle
        assert_eq!(result2.len(), 2);
        assert_eq!(&result2[0][..], b"hello");
        assert_eq!(&result2[1][..], b"world");

        assert!(buffer.is_complete());
    }

    #[test]
    fn test_final_size_mismatch() {
        let mut buffer = ReassemblyBuffer::new(10000);

        let segment1 = DataSegment::new(0, Bytes::from("hello"), true);
        let segment2 = DataSegment::new(5, Bytes::from("world"), true);

        buffer.insert_segment(segment1).unwrap(); // ubs:ignore - test oracle

        // This should fail due to final size mismatch
        let result = buffer.insert_segment(segment2);
        assert!(result.is_err());
    }

    #[test]
    fn test_overlapping_segments() {
        let mut buffer = ReassemblyBuffer::new(10000);

        let segment1 = DataSegment::new(0, Bytes::from("hello"), false);
        let segment2 = DataSegment::new(2, Bytes::from("llo"), false);

        buffer.insert_segment(segment1).unwrap(); // ubs:ignore - test oracle

        // This should fail due to overlap
        let result = buffer.insert_segment(segment2);
        assert!(result.is_err());
    }

    #[test]
    fn test_buffer_limit() {
        let mut buffer = ReassemblyBuffer::new(10); // Very small limit

        let large_segment = DataSegment::new(0, Bytes::from("this is too large"), false);

        let result = buffer.insert_segment(large_segment);
        assert!(result.is_err());
    }
}
