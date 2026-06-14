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
        self.checked_end_offset().unwrap_or(u64::MAX)
    }

    fn checked_end_offset(&self) -> Option<u64> {
        self.offset.checked_add(self.data.len() as u64)
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
        let mut segment_end = match segment.checked_end_offset() {
            Some(end) => end,
            None => {
                return Outcome::err(StreamError::InvalidState {
                    stream_id: StreamId::new(0),
                    state: "Stream segment offset overflow".to_string(),
                });
            }
        };

        // Handle overlap with already delivered data
        if segment.offset < self.next_offset {
            if segment_end <= self.next_offset {
                // Completely duplicate (already delivered), ignore it
                return Outcome::ok(Vec::new());
            }
            // Partially duplicate, truncate the already-delivered portion
            let duplicate_len = (self.next_offset - segment.offset) as usize;
            segment.data = segment.data.slice(duplicate_len..);
            segment.offset = self.next_offset;
            segment_end = match segment.checked_end_offset() {
                Some(end) => end,
                None => {
                    return Outcome::err(StreamError::InvalidState {
                        stream_id: StreamId::new(0),
                        state: "Stream segment offset overflow".to_string(),
                    });
                }
            };
        }

        // Check for final size consistency
        let pending_final_size = if segment.is_final {
            let segment_final_size = segment_end;
            if let Some(existing_final_size) = self.final_size {
                if segment_final_size != existing_final_size {
                    return Outcome::err(StreamError::FinalSizeMismatch {
                        stream_id: StreamId::new(0), // Will be filled by caller
                        expected: existing_final_size,
                        actual: segment_final_size,
                    });
                }
            }
            Some(segment_final_size)
        } else {
            None
        };

        let uncovered_segments = match self.uncovered_segments(segment) {
            Ok(segments) => segments,
            Err(err) => return Outcome::err(err),
        };

        // Check if this would exceed our buffering limit
        let new_data_size = uncovered_segments.iter().try_fold(0_u64, |sum, segment| {
            sum.checked_add(segment.data.len() as u64)
        });
        let Some(new_data_size) = new_data_size else {
            return Outcome::err(StreamError::ConnectionError {
                reason: "Reassembly buffer size overflow".to_string(),
            });
        };
        let Some(buffered_after_insert) = self.buffered_data_size.checked_add(new_data_size) else {
            return Outcome::err(StreamError::ConnectionError {
                reason: "Reassembly buffer size overflow".to_string(),
            });
        };
        if buffered_after_insert > self.max_buffered_data {
            return Outcome::err(StreamError::ConnectionError {
                reason: "Reassembly buffer limit exceeded".to_string(),
            });
        }

        if let Some(final_size) = pending_final_size {
            self.final_size = Some(final_size);
            self.received_final = true;
        }

        for uncovered in uncovered_segments {
            let offset = uncovered.offset;
            self.buffered_data_size += uncovered.data.len() as u64;
            self.segments.insert(offset, uncovered);
        }

        // Try to deliver consecutive data starting from next_offset
        let deliverable = self.extract_deliverable_data();

        Outcome::ok(deliverable)
    }

    fn uncovered_segments(&self, segment: DataSegment) -> Result<Vec<DataSegment>, StreamError> {
        let mut ranges = vec![(0usize, segment.data.len())];

        for existing in self.segments.values() {
            if !segment.overlaps_with(existing) {
                continue;
            }

            let overlap_start = segment.offset.max(existing.offset);
            let overlap_end = segment.end_offset().min(existing.end_offset());
            let segment_start = (overlap_start - segment.offset) as usize;
            let segment_end = (overlap_end - segment.offset) as usize;
            let existing_start = (overlap_start - existing.offset) as usize;
            let existing_end = (overlap_end - existing.offset) as usize;

            if segment.data.slice(segment_start..segment_end)
                != existing.data.slice(existing_start..existing_end)
            {
                return Err(StreamError::InvalidState {
                    stream_id: StreamId::new(0),
                    state: format!(
                        "Conflicting overlapping segment at offset {}",
                        segment.offset
                    ),
                });
            }

            let mut next_ranges = Vec::with_capacity(ranges.len() + 1);
            for (start, end) in ranges {
                if segment_end <= start || segment_start >= end {
                    next_ranges.push((start, end));
                    continue;
                }
                if start < segment_start {
                    next_ranges.push((start, segment_start));
                }
                if segment_end < end {
                    next_ranges.push((segment_end, end));
                }
            }
            ranges = next_ranges;
            if ranges.is_empty() {
                break;
            }
        }

        Ok(ranges
            .into_iter()
            .map(|(start, end)| DataSegment {
                offset: segment.offset + start as u64,
                data: segment.data.slice(start..end),
                is_final: segment.is_final && end == segment.data.len(),
            })
            .collect())
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

        let segment1 = DataSegment::new(5, Bytes::from("world"), false);
        let duplicate_overlap = DataSegment::new(7, Bytes::from("rld"), false);
        let conflicting_overlap = DataSegment::new(6, Bytes::from("XX"), false);

        buffer.insert_segment(segment1).unwrap(); // ubs:ignore - test oracle

        // Duplicate overlapping bytes are harmless retransmissions.
        let duplicate = buffer.insert_segment(duplicate_overlap).unwrap(); // ubs:ignore - test oracle
        assert!(duplicate.is_empty());

        // Conflicting buffered bytes must fail closed.
        let result = buffer.insert_segment(conflicting_overlap);
        assert!(result.is_err());
    }

    #[test]
    fn test_buffer_limit() {
        let mut buffer = ReassemblyBuffer::new(10); // Very small limit

        let large_segment = DataSegment::new(0, Bytes::from("this is too large"), false);

        let result = buffer.insert_segment(large_segment);
        assert!(result.is_err());
    }

    #[test]
    fn rejected_final_segment_does_not_poison_final_size() {
        let mut buffer = ReassemblyBuffer::new(4);

        let rejected_final = DataSegment::new(5, Bytes::from("final"), true);
        let rejected = buffer.insert_segment(rejected_final);
        assert!(rejected.is_err());
        assert_eq!(buffer.final_size(), None);
        assert!(!buffer.received_final_segment());

        let accepted_final = DataSegment::new(0, Bytes::from("ok"), true);
        let delivered = buffer.insert_segment(accepted_final).unwrap(); // ubs:ignore - test oracle
        assert_eq!(delivered.len(), 1);
        assert_eq!(&delivered[0][..], b"ok");
        assert_eq!(buffer.final_size(), Some(2));
        assert!(buffer.received_final_segment());
        assert!(buffer.is_complete());
    }

    #[test]
    fn conflicting_final_overlap_does_not_poison_final_size() {
        let mut buffer = ReassemblyBuffer::new(10000);

        let buffered = DataSegment::new(5, Bytes::from("world"), false);
        buffer.insert_segment(buffered).unwrap(); // ubs:ignore - test oracle

        let conflicting_final = DataSegment::new(5, Bytes::from("WORLD"), true);
        let rejected = buffer.insert_segment(conflicting_final);
        assert!(rejected.is_err());
        assert_eq!(buffer.final_size(), None);
        assert!(!buffer.received_final_segment());

        let matching_final = DataSegment::new(5, Bytes::from("world"), true);
        let duplicate = buffer.insert_segment(matching_final).unwrap(); // ubs:ignore - test oracle
        assert!(duplicate.is_empty());
        assert_eq!(buffer.final_size(), Some(10));
        assert!(buffer.received_final_segment());

        let prefix = DataSegment::new(0, Bytes::from("hello"), false);
        let delivered = buffer.insert_segment(prefix).unwrap(); // ubs:ignore - test oracle
        assert_eq!(delivered.len(), 2);
        assert_eq!(&delivered[0][..], b"hello");
        assert_eq!(&delivered[1][..], b"world");
        assert!(buffer.is_complete());
    }

    #[test]
    fn segment_offset_overflow_is_rejected() {
        let mut buffer = ReassemblyBuffer::new(10000);

        let overflowing = DataSegment::new(u64::MAX - 1, Bytes::from_static(b"abcd"), false);
        let result = buffer.insert_segment(overflowing);

        assert!(result.is_err());
        assert_eq!(buffer.next_expected_offset(), 0);
        assert_eq!(buffer.buffered_segments(), 0);
        assert_eq!(buffer.buffered_data_size(), 0);
        assert_eq!(buffer.final_size(), None);
        assert!(!buffer.received_final_segment());
    }
}
