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
#[path = "range_tracker_inline_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "range_tracker_neighbor_tests_inline_tests.rs"]
mod neighbor_tests;
