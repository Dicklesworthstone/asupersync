//! Range Tracking for Sparse File Operations

use std::collections::BTreeMap;
use std::fmt;

/// A contiguous range of bytes
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SparseRange {
    /// Start offset (inclusive)
    pub start: u64,
    /// End offset (exclusive)
    pub end: u64,
}

impl SparseRange {
    /// Create a new range
    pub fn new(start: u64, end: u64) -> Self {
        assert!(start <= end, "Invalid range: start {} > end {}", start, end);
        Self { start, end }
    }

    /// Create a range from offset and size
    pub fn from_offset_size(offset: u64, size: u64) -> Self {
        Self::try_from_offset_size(offset, size).unwrap_or_else(|| {
            panic!("range offset overflow: offset {offset} + size {size} exceeds u64::MAX")
        })
    }

    /// Try to create a range from offset and size.
    ///
    /// Returns `None` if `offset + size` would overflow.
    #[must_use]
    pub fn try_from_offset_size(offset: u64, size: u64) -> Option<Self> {
        Some(Self::new(offset, offset.checked_add(size)?))
    }

    /// Get the size of this range
    pub fn size(&self) -> u64 {
        self.end - self.start
    }

    /// Check if this range is empty
    pub fn is_empty(&self) -> bool {
        self.start >= self.end
    }

    /// Check if this range contains the given offset
    pub fn contains(&self, offset: u64) -> bool {
        offset >= self.start && offset < self.end
    }

    /// Check if this range overlaps with another range
    pub fn overlaps(&self, other: &SparseRange) -> bool {
        self.start < other.end && self.end > other.start
    }

    /// Check if this range is adjacent to another range
    pub fn adjacent_to(&self, other: &SparseRange) -> bool {
        self.end == other.start || other.end == self.start
    }

    /// Check if this range can be merged with another range
    pub fn can_merge(&self, other: &SparseRange) -> bool {
        self.overlaps(other) || self.adjacent_to(other)
    }

    /// Merge this range with another range if possible
    pub fn merge(&self, other: &SparseRange) -> Option<SparseRange> {
        if self.can_merge(other) {
            Some(SparseRange::new(
                self.start.min(other.start),
                self.end.max(other.end),
            ))
        } else {
            None
        }
    }

    /// Split this range at the given offset
    pub fn split_at(&self, offset: u64) -> Option<(SparseRange, SparseRange)> {
        if offset > self.start && offset < self.end {
            Some((
                SparseRange::new(self.start, offset),
                SparseRange::new(offset, self.end),
            ))
        } else {
            None
        }
    }

    /// Get the intersection of this range with another range
    pub fn intersection(&self, other: &SparseRange) -> Option<SparseRange> {
        let start = self.start.max(other.start);
        let end = self.end.min(other.end);
        if start < end {
            Some(SparseRange::new(start, end))
        } else {
            None
        }
    }
}

impl fmt::Display for SparseRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            write!(f, "[empty]")
        } else {
            write!(f, "[{}-{})", self.start, self.end)
        }
    }
}

/// A specific chunk range with metadata
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkRange {
    /// Byte offset in the file
    pub offset: u64,
    /// Size of the chunk in bytes
    pub size: u64,
}

impl ChunkRange {
    /// Create a new chunk range
    pub fn new(offset: u64, size: u64) -> Self {
        Self::try_new(offset, size).unwrap_or_else(|| {
            panic!("chunk range overflow: offset {offset} + size {size} exceeds u64::MAX")
        })
    }

    /// Try to create a new chunk range.
    ///
    /// Returns `None` if `offset + size` would overflow.
    #[must_use]
    pub fn try_new(offset: u64, size: u64) -> Option<Self> {
        offset.checked_add(size)?;
        Some(Self { offset, size })
    }

    /// Convert to a SparseRange
    pub fn to_sparse_range(&self) -> SparseRange {
        SparseRange::from_offset_size(self.offset, self.size)
    }

    /// Try to convert to a SparseRange.
    ///
    /// Returns `None` if `offset + size` would overflow.
    #[must_use]
    pub fn try_to_sparse_range(&self) -> Option<SparseRange> {
        SparseRange::try_from_offset_size(self.offset, self.size)
    }

    /// Get the end offset (exclusive)
    pub fn end_offset(&self) -> u64 {
        self.try_end_offset().unwrap_or_else(|| {
            panic!(
                "chunk range end overflow: offset {} + size {} exceeds u64::MAX",
                self.offset, self.size
            )
        })
    }

    /// Try to get the end offset (exclusive).
    ///
    /// Returns `None` if `offset + size` would overflow.
    #[must_use]
    pub fn try_end_offset(&self) -> Option<u64> {
        self.offset.checked_add(self.size)
    }

    /// Check if this chunk overlaps with another chunk
    pub fn overlaps(&self, other: &ChunkRange) -> bool {
        match (self.try_to_sparse_range(), other.try_to_sparse_range()) {
            (Some(left), Some(right)) => left.overlaps(&right),
            _ => false,
        }
    }

    /// Check if this chunk contains the given offset
    pub fn contains_offset(&self, offset: u64) -> bool {
        self.try_end_offset()
            .is_some_and(|end| offset >= self.offset && offset < end)
    }
}

impl fmt::Display for ChunkRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "chunk@{}+{}", self.offset, self.size)
    }
}

/// Tracks written ranges in a sparse file and provides completeness analysis
pub struct RangeTracker {
    /// Written ranges, stored as (start_offset -> range)
    ranges: BTreeMap<u64, SparseRange>,
    /// Total number of bytes covered by all ranges
    total_bytes: u64,
    /// Largest end offset seen
    max_end_offset: u64,
}

impl RangeTracker {
    /// Create a new empty range tracker
    pub fn new() -> Self {
        Self {
            ranges: BTreeMap::new(),
            total_bytes: 0,
            max_end_offset: 0,
        }
    }

    /// Add a new range to the tracker
    pub fn add_range(&mut self, range: SparseRange) {
        if range.is_empty() {
            return;
        }

        // Update max end offset
        self.max_end_offset = self.max_end_offset.max(range.end);

        // Check for overlaps and merging opportunities
        let overlapping_ranges = self.find_overlapping_ranges(&range);

        if overlapping_ranges.is_empty() {
            // No overlaps, just insert the new range
            self.ranges.insert(range.start, range);
            self.total_bytes += range.size();
        } else {
            // Merge with overlapping ranges
            let mut merged_range = range;

            // Remove overlapping ranges and expand the merged range
            for overlapping_range in &overlapping_ranges {
                self.total_bytes -= overlapping_range.size();
                merged_range = merged_range.merge(overlapping_range).unwrap();
                self.ranges.remove(&overlapping_range.start);
            }

            // Insert the merged range
            self.ranges.insert(merged_range.start, merged_range);
            self.total_bytes += merged_range.size();
        }

        // Try to merge with adjacent ranges
        self.merge_adjacent_ranges();
    }

    /// Check if a range overlaps with any existing ranges
    pub fn overlaps(&self, range: &SparseRange) -> bool {
        !self.find_overlapping_ranges(range).is_empty()
    }

    /// Check if all bytes from 0 to the given size are covered
    pub fn is_contiguous_to(&self, size: u64) -> bool {
        if size == 0 {
            return true;
        }

        // Should have exactly one range from 0 to size
        if self.ranges.len() != 1 {
            return false;
        }

        if let Some(first_range) = self.ranges.values().next() {
            first_range.start == 0 && first_range.end >= size
        } else {
            false
        }
    }

    /// Get the total number of bytes covered
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Get the number of separate ranges
    pub fn range_count(&self) -> usize {
        self.ranges.len()
    }

    /// Get all ranges as a vector
    pub fn get_ranges(&self) -> Vec<SparseRange> {
        self.ranges.values().copied().collect()
    }

    /// Find gaps in coverage up to the given size
    pub fn find_gaps(&self, total_size: u64) -> Vec<SparseRange> {
        let mut gaps = Vec::new();
        let mut current_offset = 0;

        for range in self.ranges.values() {
            if range.start > current_offset {
                // Gap found
                gaps.push(SparseRange::new(current_offset, range.start));
            }
            current_offset = current_offset.max(range.end);
        }

        // Check for trailing gap
        if current_offset < total_size {
            gaps.push(SparseRange::new(current_offset, total_size));
        }

        gaps
    }

    /// Get coverage ratio (0.0 to 1.0) for the given total size
    pub fn coverage_ratio(&self, total_size: u64) -> f64 {
        if total_size == 0 {
            return 1.0;
        }

        let covered_bytes = self.calculate_covered_bytes(total_size);
        covered_bytes as f64 / total_size as f64
    }

    /// Check if a specific offset is covered
    pub fn is_offset_covered(&self, offset: u64) -> bool {
        self.ranges.values().any(|range| range.contains(offset))
    }

    /// Get the range that covers the given offset, if any
    pub fn get_covering_range(&self, offset: u64) -> Option<SparseRange> {
        self.ranges
            .values()
            .find(|range| range.contains(offset))
            .copied()
    }

    /// Remove a range from tracking
    pub fn remove_range(&mut self, range: &SparseRange) -> bool {
        let overlapping_ranges = self.find_overlapping_ranges(range);

        if overlapping_ranges.is_empty() {
            return false;
        }

        // Remove overlapping ranges
        for overlapping_range in &overlapping_ranges {
            self.ranges.remove(&overlapping_range.start);
            self.total_bytes -= overlapping_range.size();
        }

        // Add back the non-overlapping parts
        for overlapping_range in &overlapping_ranges {
            // Parts before the removed range
            if overlapping_range.start < range.start {
                let before_range = SparseRange::new(
                    overlapping_range.start,
                    range.start.min(overlapping_range.end),
                );
                if !before_range.is_empty() {
                    self.ranges.insert(before_range.start, before_range);
                    self.total_bytes += before_range.size();
                }
            }

            // Parts after the removed range
            if overlapping_range.end > range.end {
                let after_range = SparseRange::new(
                    range.end.max(overlapping_range.start),
                    overlapping_range.end,
                );
                if !after_range.is_empty() {
                    self.ranges.insert(after_range.start, after_range);
                    self.total_bytes += after_range.size();
                }
            }
        }

        true
    }

    /// Clear all ranges
    pub fn clear(&mut self) {
        self.ranges.clear();
        self.total_bytes = 0;
        self.max_end_offset = 0;
    }

    /// Get statistics about the range tracker
    pub fn get_stats(&self) -> RangeStats {
        let gaps = self.find_gaps(self.max_end_offset);
        let largest_gap = gaps.iter().map(|gap| gap.size()).max().unwrap_or(0);

        let smallest_range = self
            .ranges
            .values()
            .map(|range| range.size())
            .min()
            .unwrap_or(0);

        let largest_range = self
            .ranges
            .values()
            .map(|range| range.size())
            .max()
            .unwrap_or(0);

        RangeStats {
            total_ranges: self.ranges.len(),
            total_bytes_covered: self.total_bytes,
            max_end_offset: self.max_end_offset,
            gap_count: gaps.len(),
            largest_gap_size: largest_gap,
            smallest_range_size: smallest_range,
            largest_range_size: largest_range,
            fragmentation_ratio: if self.max_end_offset > 0 {
                gaps.len() as f64 / (gaps.len() + self.ranges.len()) as f64
            } else {
                0.0
            },
        }
    }

    // Private helper methods

    fn find_overlapping_ranges(&self, range: &SparseRange) -> Vec<SparseRange> {
        self.ranges
            .values()
            .filter(|existing_range| existing_range.overlaps(range))
            .copied()
            .collect()
    }

    fn merge_adjacent_ranges(&mut self) {
        if self.ranges.len() <= 1 {
            return;
        }

        let mut sorted_ranges = std::mem::take(&mut self.ranges).into_values();
        let mut new_ranges = std::collections::BTreeMap::new();
        let mut total_bytes = 0;

        // Safe to unwrap because len > 1
        let mut current_range = sorted_ranges.next().unwrap();

        for next_range in sorted_ranges {
            if current_range.can_merge(&next_range) {
                // Merge these two ranges
                current_range = current_range.merge(&next_range).unwrap();
            } else {
                // Add the settled range
                total_bytes += current_range.size();
                new_ranges.insert(current_range.start, current_range);
                current_range = next_range;
            }
        }

        // Add the final range
        total_bytes += current_range.size();
        new_ranges.insert(current_range.start, current_range);

        self.ranges = new_ranges;
        self.total_bytes = total_bytes;
    }

    fn calculate_covered_bytes(&self, total_size: u64) -> u64 {
        self.ranges
            .values()
            .map(|range| {
                let start = range.start;
                let end = range.end.min(total_size);
                end.saturating_sub(start)
            })
            .sum()
    }
}

impl Default for RangeTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for RangeTracker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RangeTracker {{ ranges: {:?}, total_bytes: {}, max_end_offset: {} }}",
            self.ranges.values().collect::<Vec<_>>(),
            self.total_bytes,
            self.max_end_offset
        )
    }
}

/// Statistics about range tracker state
#[derive(Debug, Clone)]
pub struct RangeStats {
    /// Total number of ranges
    pub total_ranges: usize,
    /// Total bytes covered by all ranges
    pub total_bytes_covered: u64,
    /// Maximum end offset seen
    pub max_end_offset: u64,
    /// Number of gaps in coverage
    pub gap_count: usize,
    /// Size of the largest gap
    pub largest_gap_size: u64,
    /// Size of the smallest range
    pub smallest_range_size: u64,
    /// Size of the largest range
    pub largest_range_size: u64,
    /// Fragmentation ratio (0.0 = no fragmentation, 1.0 = maximum fragmentation)
    pub fragmentation_ratio: f64,
}

impl fmt::Display for RangeStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RangeStats {{ ranges: {}, bytes: {}, gaps: {}, fragmentation: {:.2} }}",
            self.total_ranges, self.total_bytes_covered, self.gap_count, self.fragmentation_ratio
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sparse_range_operations() {
        let range1 = SparseRange::new(10, 20);
        let range2 = SparseRange::new(15, 25);
        let range3 = SparseRange::new(30, 40);

        assert_eq!(range1.size(), 10);
        assert!(range1.contains(15));
        assert!(!range1.contains(25));

        assert!(range1.overlaps(&range2));
        assert!(!range1.overlaps(&range3));

        let merged = range1.merge(&range2).unwrap();
        assert_eq!(merged, SparseRange::new(10, 25));

        assert!(range1.can_merge(&range2));
        assert!(!range1.can_merge(&range3));
    }

    #[test]
    fn test_range_tracker_basic() {
        let mut tracker = RangeTracker::new();

        // Add some ranges
        tracker.add_range(SparseRange::new(0, 10));
        tracker.add_range(SparseRange::new(20, 30));

        assert_eq!(tracker.total_bytes(), 20);
        assert_eq!(tracker.range_count(), 2);

        assert!(tracker.is_offset_covered(5));
        assert!(!tracker.is_offset_covered(15));
        assert!(tracker.is_offset_covered(25));

        // Check coverage
        assert_eq!(tracker.coverage_ratio(40), 0.5);
        assert!(!tracker.is_contiguous_to(40));
    }

    #[test]
    fn test_range_merging() {
        let mut tracker = RangeTracker::new();

        // Add overlapping ranges that should be merged
        tracker.add_range(SparseRange::new(0, 10));
        tracker.add_range(SparseRange::new(5, 15));
        tracker.add_range(SparseRange::new(10, 20));

        // Should result in one range from 0 to 20
        assert_eq!(tracker.range_count(), 1);
        assert_eq!(tracker.total_bytes(), 20);

        let ranges = tracker.get_ranges();
        assert_eq!(ranges[0], SparseRange::new(0, 20));
    }

    #[test]
    fn test_gap_detection() {
        let mut tracker = RangeTracker::new();

        tracker.add_range(SparseRange::new(0, 10));
        tracker.add_range(SparseRange::new(20, 30));
        tracker.add_range(SparseRange::new(40, 50));

        let gaps = tracker.find_gaps(60);
        assert_eq!(gaps.len(), 3);

        assert_eq!(gaps[0], SparseRange::new(10, 20));
        assert_eq!(gaps[1], SparseRange::new(30, 40));
        assert_eq!(gaps[2], SparseRange::new(50, 60));
    }

    #[test]
    fn test_contiguous_detection() {
        let mut tracker = RangeTracker::new();

        // Not contiguous - has gaps
        tracker.add_range(SparseRange::new(0, 10));
        tracker.add_range(SparseRange::new(20, 30));
        assert!(!tracker.is_contiguous_to(30));

        // Fill the gap
        tracker.add_range(SparseRange::new(10, 20));
        assert!(tracker.is_contiguous_to(30));
        assert!(tracker.is_contiguous_to(25)); // Partial coverage
    }

    #[test]
    fn test_range_removal() {
        let mut tracker = RangeTracker::new();

        tracker.add_range(SparseRange::new(0, 30));
        assert_eq!(tracker.total_bytes(), 30);

        // Remove middle part
        let removed = tracker.remove_range(&SparseRange::new(10, 20));
        assert!(removed);
        assert_eq!(tracker.total_bytes(), 20);
        assert_eq!(tracker.range_count(), 2);

        // Should have ranges [0-10) and [20-30)
        let ranges = tracker.get_ranges();
        assert!(ranges.contains(&SparseRange::new(0, 10)));
        assert!(ranges.contains(&SparseRange::new(20, 30)));
    }

    #[test]
    fn test_chunk_range_operations() {
        let chunk1 = ChunkRange::new(100, 50);
        let chunk2 = ChunkRange::new(125, 25);

        assert_eq!(chunk1.end_offset(), 150);
        assert!(chunk1.contains_offset(125));
        assert!(!chunk1.contains_offset(200));

        assert!(chunk1.overlaps(&chunk2));

        let sparse_range = chunk1.to_sparse_range();
        assert_eq!(sparse_range, SparseRange::new(100, 150));
    }

    #[test]
    fn test_offset_size_overflow_rejected_explicitly() {
        assert!(SparseRange::try_from_offset_size(u64::MAX, 1).is_none());
        assert!(ChunkRange::try_new(u64::MAX, 1).is_none());

        let sparse_panic = std::panic::catch_unwind(|| SparseRange::from_offset_size(u64::MAX, 1));
        assert!(sparse_panic.is_err());

        let chunk_panic = std::panic::catch_unwind(|| ChunkRange::new(u64::MAX, 1));
        assert!(chunk_panic.is_err());

        let invalid_chunk = ChunkRange {
            offset: u64::MAX,
            size: 1,
        };
        assert!(invalid_chunk.try_end_offset().is_none());
        assert!(invalid_chunk.try_to_sparse_range().is_none());
        assert!(!invalid_chunk.contains_offset(0));
        assert!(!invalid_chunk.overlaps(&ChunkRange::new(0, 1)));
    }

    #[test]
    fn test_range_statistics() {
        let mut tracker = RangeTracker::new();

        tracker.add_range(SparseRange::new(0, 10));
        tracker.add_range(SparseRange::new(20, 30));
        tracker.add_range(SparseRange::new(50, 100));

        let stats = tracker.get_stats();
        assert_eq!(stats.total_ranges, 3);
        assert_eq!(stats.total_bytes_covered, 70);
        assert_eq!(stats.gap_count, 2); // gaps within observed extent: 10-20, 30-50
        assert_eq!(stats.largest_range_size, 50);
        assert_eq!(stats.smallest_range_size, 10);
    }

    #[test]
    fn test_range_edge_cases() {
        let mut tracker = RangeTracker::new();

        // Empty range should be ignored
        tracker.add_range(SparseRange::new(10, 10));
        assert_eq!(tracker.range_count(), 0);

        // Zero-sized coverage
        assert_eq!(tracker.coverage_ratio(0), 1.0);
        assert!(tracker.is_contiguous_to(0));

        // Remove non-existent range
        let removed = tracker.remove_range(&SparseRange::new(100, 200));
        assert!(!removed);
    }

    #[test]
    fn test_sparse_range_split() {
        let range = SparseRange::new(10, 30);

        let split = range.split_at(20);
        assert!(split.is_some());

        let (left, right) = split.unwrap();
        assert_eq!(left, SparseRange::new(10, 20));
        assert_eq!(right, SparseRange::new(20, 30));

        // Split at boundary should return None
        assert!(range.split_at(10).is_none());
        assert!(range.split_at(30).is_none());
        assert!(range.split_at(5).is_none());
    }

    #[test]
    fn test_range_intersection() {
        let range1 = SparseRange::new(10, 30);
        let range2 = SparseRange::new(20, 40);
        let range3 = SparseRange::new(50, 60);

        let intersection = range1.intersection(&range2);
        assert!(intersection.is_some());
        assert_eq!(intersection.unwrap(), SparseRange::new(20, 30));

        let no_intersection = range1.intersection(&range3);
        assert!(no_intersection.is_none());
    }
}
