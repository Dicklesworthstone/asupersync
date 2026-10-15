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
        !self.is_empty() && !other.is_empty() && self.start < other.end && self.end > other.start
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

    /// Add a range, coalescing only its overlapping or adjacent neighbors.
    ///
    /// With `n` retained ranges and `k` neighbors absorbed, this performs
    /// O((k + 1) log(n + 1)) tree work and uses constant auxiliary space.
    /// In particular, a disjoint write does not scan or rebuild the whole map.
    pub fn add_range(&mut self, mut range: SparseRange) {
        if range.is_empty() {
            return;
        }

        // Update max end offset
        self.max_end_offset = self.max_end_offset.max(range.end);

        // Coalesced ranges are disjoint: at most one predecessor can touch
        // the new start. Copy its endpoints before mutating the tree.
        if let Some(previous) = self.ranges.range(..=range.start).next_back()
            .map(|(_, previous)| *previous)
            .filter(|previous| previous.end >= range.start)
        {
            self.ranges.remove(&previous.start);
            self.total_bytes -= previous.size();
            range.start = previous.start;
            range.end = range.end.max(previous.end);
        }

        // Include a successor starting exactly at the end (adjacency), without
        // computing end + 1, which would overflow for the last u64 interval.
        while let Some(next) = self.ranges.range(range.start..=range.end).next()
            .map(|(_, next)| *next)
        {
            self.ranges.remove(&next.start);
            self.total_bytes -= next.size();
            range.end = range.end.max(next.end);
        }

        self.ranges.insert(range.start, range);
        self.total_bytes += range.size();
    }

    /// Check for overlap with one predecessor lookup and no temporary allocation.
    pub fn overlaps(&self, range: &SparseRange) -> bool {
        if range.is_empty() {
            return false;
        }
        self.ranges.range(..range.end).next_back()
            .is_some_and(|(_, previous)| previous.end > range.start)
    }

    /// Check if all bytes from 0 to the given size are covered
    pub fn is_contiguous_to(&self, size: u64) -> bool {
        if size == 0 {
            return true;
        }

        // Stored ranges are coalesced. Later disjoint ranges do not affect
        // completeness of a prefix covered by the first range.
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
            if current_offset >= total_size || range.start >= total_size {
                break;
            }
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
        self.get_covering_range(offset).is_some()
    }

    /// Get the range that covers the given offset, if any
    pub fn get_covering_range(&self, offset: u64) -> Option<SparseRange> {
        self.ranges.range(..=offset).next_back()
            .map(|(_, range)| *range)
            .filter(|range| range.contains(offset))
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
        let mut overlaps = Vec::new();
        if range.is_empty() {
            return overlaps;
        }
        // Only the predecessor can begin before the query and still overlap.
        // Excluding range.start here prevents duplicating the first range below.
        if let Some(previous) = self.ranges.range(..range.start).next_back()
            .map(|(_, previous)| *previous)
            .filter(|previous| previous.end > range.start)
        {
            overlaps.push(previous);
        }
        overlaps.extend(self.ranges.range(range.start..range.end).map(|(_, value)| *value));
        overlaps
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

    #[test]
    fn empty_range_removal_preserves_contiguous_coverage() {
        let whole = SparseRange::new(0, 10);
        let mut tracker = RangeTracker::new();
        tracker.add_range(whole);
        for empty in [
            SparseRange::new(0, 0),
            SparseRange::new(5, 5),
            SparseRange::new(10, 10),
            SparseRange { start: 7, end: 3 },
        ] {
            assert!(!whole.overlaps(&empty));
            assert!(!empty.overlaps(&whole));
            assert!(!tracker.overlaps(&empty));
            assert!(!tracker.remove_range(&empty));
            assert_eq!(tracker.get_ranges(), vec![whole]);
            assert_eq!(tracker.total_bytes(), 10);
            assert!(tracker.is_contiguous_to(10));
        }
        assert!(!ChunkRange::new(5, 0).overlaps(&ChunkRange::new(0, 10)));
        assert!(tracker.remove_range(&SparseRange::new(4, 6)));
        assert_eq!(tracker.total_bytes(), 8);
        assert_eq!(tracker.find_gaps(10), vec![SparseRange::new(4, 6)]);
        assert!(!tracker.is_contiguous_to(10));
    }

    #[test]
    fn prefix_queries_ignore_later_ranges_at_u64_boundary() {
        let mut tracker = RangeTracker::new();
        tracker.add_range(SparseRange::new(0, 10));
        tracker.add_range(SparseRange::new(u64::MAX - 1, u64::MAX));
        assert!(tracker.is_contiguous_to(10));
        assert!(!tracker.is_contiguous_to(11));
        assert!(tracker.find_gaps(0).is_empty());
        assert!(tracker.find_gaps(10).is_empty());
        assert_eq!(tracker.find_gaps(11), vec![SparseRange::new(10, 11)]);
        assert_eq!(
            tracker.find_gaps(u64::MAX),
            vec![SparseRange::new(10, u64::MAX - 1)]
        );
    }

    #[test]
    fn bounded_range_queries_match_byte_set_oracle() {
        for mask in 0_u16..256 {
            let mut tracker = RangeTracker::new();
            for offset in (0..8).rev() {
                if mask & (1 << offset) != 0 {
                    tracker.add_range(SparseRange::new(offset, offset + 1));
                }
            }
            for size in 0..=10 {
                let missing: Vec<u64> = (0..size)
                    .filter(|offset| *offset >= 8 || mask & (1 << offset) == 0)
                    .collect();
                let gaps = tracker.find_gaps(size);
                assert!(
                    gaps.iter()
                        .all(|gap| gap.start < gap.end && gap.end <= size)
                );
                let reported: Vec<u64> = gaps.iter().flat_map(|gap| gap.start..gap.end).collect();
                assert_eq!(reported, missing, "mask={mask} size={size}");
                assert_eq!(
                    tracker.is_contiguous_to(size),
                    missing.is_empty(),
                    "mask={mask} size={size}"
                );
            }
        }
    }
}

#[cfg(test)]
mod neighbor_tests {
    use super::*;

    fn from_mask(mask: u8) -> RangeTracker {
        let mut tracker = RangeTracker::new();
        for offset in (0..6).rev() {
            if mask & (1 << offset) != 0 {
                tracker.add_range(SparseRange::new(offset, offset + 1));
            }
        }
        tracker
    }

    fn assert_oracle(tracker: &RangeTracker, expected: &[bool; 6]) {
        let ranges = tracker.get_ranges();
        assert!(ranges.iter().all(|range| range.start < range.end));
        assert!(ranges.windows(2).all(|pair| pair[0].end < pair[1].start));
        assert_eq!(tracker.total_bytes(), expected.iter().filter(|value| **value).count() as u64);
        assert_eq!(tracker.total_bytes(), ranges.iter().map(SparseRange::size).sum::<u64>());
        for offset in 0..=6 {
            let covered = offset < 6 && expected[offset];
            assert_eq!(tracker.is_offset_covered(offset as u64), covered);
            assert_eq!(tracker.get_covering_range(offset as u64),
                ranges.iter().find(|range| range.contains(offset as u64)).copied());
        }
        for start in 0..=6 {
            for end in 0..=6 {
                let query = SparseRange { start: start as u64, end: end as u64 };
                let overlaps = start < end && expected[start..end].iter().any(|covered| *covered);
                assert_eq!(tracker.overlaps(&query), overlaps);
                let old_scan: Vec<_> = ranges.iter().filter(|range| range.overlaps(&query)).copied().collect();
                assert_eq!(tracker.find_overlapping_ranges(&query), old_scan);
            }
        }
    }

    #[test]
    fn every_small_union_and_subtraction_preserves_coalesced_byte_coverage() {
        for mask in 0_u8..64 {
            for start in 0..=6 {
                for end in 0..=6 {
                    for adding in [false, true] {
                        let mut tracker = from_mask(mask);
                        let mut expected = std::array::from_fn(|offset| mask & (1 << offset) != 0);
                        let range = SparseRange { start: start as u64, end: end as u64 };
                        let overlap = start < end && expected[start..end].iter().any(|covered| *covered);
                        if adding {
                            tracker.add_range(range);
                        } else {
                            assert_eq!(tracker.remove_range(&range), overlap);
                        }
                        if start < end {
                            expected[start..end].fill(adding);
                        }
                        assert_oracle(&tracker, &expected);
                        // Reinsert a removed window or remove the newly added
                        // window to exercise split-then-merge and merge-then-split.
                        if adding {
                            tracker.remove_range(&range);
                        } else {
                            tracker.add_range(range);
                        }
                        if start < end {
                            expected[start..end].fill(!adding);
                        }
                        assert_oracle(&tracker, &expected);
                    }
                }
            }
        }
    }

    #[test]
    fn fragmented_out_of_order_ingress_and_gap_filling_keep_exact_union() {
        const COUNT: u64 = 16_384;
        let mut tracker = RangeTracker::new();
        // An odd multiplier permutes this power-of-two domain. Each first-pass
        // insert is disjoint, the historically expensive sparse-writer case.
        for index in 0..COUNT {
            let offset = 2 * ((index * 8191) % COUNT);
            assert!(!tracker.overlaps(&SparseRange::new(offset, offset + 1)));
            tracker.add_range(SparseRange::new(offset, offset + 1));
        }
        assert_eq!(tracker.range_count(), COUNT as usize);
        assert_eq!(tracker.total_bytes(), COUNT);
        for index in 0..COUNT {
            assert!(tracker.is_offset_covered(2 * index));
            assert!(!tracker.is_offset_covered(2 * index + 1));
            assert!(!tracker.overlaps(&SparseRange::new(2 * index + 1, 2 * index + 2)));
        }
        for index in (0..COUNT).rev() {
            tracker.add_range(SparseRange::new(2 * index + 1, 2 * index + 2));
        }
        assert_eq!(tracker.get_ranges(), vec![SparseRange::new(0, 2 * COUNT)]);
        assert_eq!(tracker.total_bytes(), 2 * COUNT);
        assert!(tracker.find_gaps(2 * COUNT).is_empty());
    }

    #[test]
    fn endpoint_unions_and_removal_preserve_full_u64_extent_and_historical_maximum() {
        let mut tracker = RangeTracker::new();
        tracker.add_range(SparseRange::new(u64::MAX - 2, u64::MAX));
        tracker.add_range(SparseRange::new(0, 2));
        tracker.add_range(SparseRange::new(2, u64::MAX - 2));
        assert_eq!(tracker.total_bytes(), u64::MAX);
        assert_eq!(tracker.get_ranges(), vec![SparseRange::new(0, u64::MAX)]);
        tracker.add_range(SparseRange::new(1, u64::MAX - 1));
        assert_eq!(tracker.total_bytes(), u64::MAX);
        assert!(tracker.get_covering_range(u64::MAX).is_none());
        assert!(tracker.is_offset_covered(u64::MAX - 1));
        assert!(!tracker.overlaps(&SparseRange::new(u64::MAX, u64::MAX)));
        assert!(tracker.remove_range(&SparseRange::new(2, u64::MAX - 3)));
        assert_eq!(tracker.total_bytes(), 5);
        assert_eq!(tracker.get_ranges(), vec![SparseRange::new(0, 2), SparseRange::new(u64::MAX - 3, u64::MAX)]);
        assert!(tracker.remove_range(&SparseRange::new(u64::MAX - 3, u64::MAX)));
        assert_eq!(tracker.get_stats().max_end_offset, u64::MAX);
        assert_eq!(tracker.find_gaps(u64::MAX), vec![SparseRange::new(2, u64::MAX)]);
        tracker.clear();
        assert_eq!(tracker.total_bytes(), 0);
        assert_eq!(tracker.get_stats().max_end_offset, 0);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn native_sparse_writer_completes_fragmented_file_with_each_publication_policy() {
        use crate::atp::journal::{CommitPolicy, FsyncPolicy, SparseWriterConfig, WriteOptions};
        use crate::atp::journal::sparse_writer::ScopedSparseWriter;
        use crate::atp::manifest::Manifest;
        use crate::atp::object::{MetadataPolicy, Object, ObjectGraph};
        use crate::cx::Cx;
        use crate::runtime::{RootDrainOutcome, RuntimeBuilder};
        use std::sync::Arc;
        use std::time::Duration;

        for workers in [1, 2] {
            let directory = tempfile::tempdir().unwrap();
            let builder = if workers == 1 { RuntimeBuilder::current_thread() }
                else { RuntimeBuilder::new().worker_threads(workers).with_sharded_state(true) };
            let runtime = builder.blocking_threads(1, 2).build().unwrap();
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let content: Vec<u8> = (0..1024).map(|value| (value % 251) as u8).collect();
                let object = Object::file(content.clone());
                let object_id = object.id.clone();
                let mut graph = ObjectGraph::new();
                graph.add_root(object).unwrap();
                let manifest = Arc::new(Manifest::from_graph(&graph, MetadataPolicy::portable()).unwrap());
                for policy in [CommitPolicy::AtomicRename, CommitPolicy::CopyAndVerify, CommitPolicy::LinkAndUnlink] {
                    let path = directory.path().join(format!("fragmented-{policy:?}"));
                    let writer = ScopedSparseWriter::new(&cx, object_id.clone(), path.clone(), SparseWriterConfig {
                        enable_preallocation: false, fsync_policy: FsyncPolicy::BeforeCommit,
                        commit_policy: policy, ..SparseWriterConfig::default()
                    }).await.unwrap().unwrap();
                    writer.set_expected_size(&cx, content.len() as u64).await.unwrap().unwrap();
                    for parity in [1, 0] {
                        for index in (0..256).rev().filter(|index| index % 2 == parity) {
                            let offset = index * 4;
                            writer.write_chunk(&cx, offset as u64, content[offset..offset + 4].to_vec(), WriteOptions::default())
                                .await.unwrap().unwrap();
                        }
                        assert_eq!(writer.is_complete(&cx).await.unwrap().unwrap(), parity == 0);
                        assert_eq!(writer.get_stats(&cx).await.unwrap().unwrap().total_bytes_written,
                            if parity == 1 { 512 } else { 1024 });
                    }
                    assert_eq!(writer.verify_and_commit(&cx, Arc::clone(&manifest)).await.unwrap().unwrap(), path);
                    assert_eq!(cx.scoped_fs().read(path).await.unwrap(), content);
                }
            });
            let report = runtime.shutdown_drained(Duration::from_secs(5));
            assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
            assert_eq!(report.live_tasks, 0);
            assert_eq!(report.pending_spawns, 0);
            assert_eq!(report.pending_obligations, 0);
        }
    }
}
