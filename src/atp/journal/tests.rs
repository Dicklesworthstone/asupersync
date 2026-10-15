//! Basic tests for sparse writer components

type ChunkRange = super::ChunkRange;
type CommitPolicy = super::CommitPolicy;
type FsyncPolicy = super::FsyncPolicy;
type QuarantineReason = super::QuarantineReason;
type RangeTracker = super::RangeTracker;
type SparseRange = super::SparseRange;
type SparseWriterConfig = super::SparseWriterConfig;
type TempManagementConfig = super::temp_management::TempManagementConfig;
type WriteOptions = super::WriteOptions;
type WritePriority = super::sparse_writer::WritePriority;

#[cfg(test)]
mod tests {
    use std::time::Duration;

    #[test]
    fn test_sparse_range_operations() {
        let range1 = super::SparseRange::new(10, 20);
        let range2 = super::SparseRange::new(15, 25);
        let range3 = super::SparseRange::new(30, 40);

        assert_eq!(range1.size(), 10);
        assert!(range1.contains(15));
        assert!(!range1.contains(25));

        assert!(range1.overlaps(&range2));
        assert!(!range1.overlaps(&range3));

        let merged = range1.merge(&range2).unwrap();
        assert_eq!(merged, super::SparseRange::new(10, 25));

        assert!(range1.can_merge(&range2));
        assert!(!range1.can_merge(&range3));
    }

    #[test]
    fn test_range_tracker_basic() {
        let mut tracker = super::RangeTracker::new();

        // Add some ranges
        tracker.add_range(super::SparseRange::new(0, 10));
        tracker.add_range(super::SparseRange::new(20, 30));

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
        let mut tracker = super::RangeTracker::new();

        // Add overlapping ranges that should be merged
        tracker.add_range(super::SparseRange::new(0, 10));
        tracker.add_range(super::SparseRange::new(5, 15));
        tracker.add_range(super::SparseRange::new(10, 20));

        // Should result in one range from 0 to 20
        assert_eq!(tracker.range_count(), 1);
        assert_eq!(tracker.total_bytes(), 20);

        let ranges = tracker.get_ranges();
        assert_eq!(ranges[0], super::SparseRange::new(0, 20));
    }

    #[test]
    fn test_gap_detection() {
        let mut tracker = super::RangeTracker::new();

        tracker.add_range(super::SparseRange::new(0, 10));
        tracker.add_range(super::SparseRange::new(20, 30));
        tracker.add_range(super::SparseRange::new(40, 50));

        let gaps = tracker.find_gaps(60);
        assert_eq!(gaps.len(), 3);

        assert_eq!(gaps[0], super::SparseRange::new(10, 20));
        assert_eq!(gaps[1], super::SparseRange::new(30, 40));
        assert_eq!(gaps[2], super::SparseRange::new(50, 60));
    }

    #[test]
    fn test_contiguous_detection() {
        let mut tracker = super::RangeTracker::new();

        // Not contiguous - has gaps
        tracker.add_range(super::SparseRange::new(0, 10));
        tracker.add_range(super::SparseRange::new(20, 30));
        assert!(!tracker.is_contiguous_to(30));

        // Fill the gap
        tracker.add_range(super::SparseRange::new(10, 20));
        assert!(tracker.is_contiguous_to(30));
        assert!(tracker.is_contiguous_to(25)); // Partial coverage
    }

    #[test]
    fn test_range_removal() {
        let mut tracker = super::RangeTracker::new();

        tracker.add_range(super::SparseRange::new(0, 30));
        assert_eq!(tracker.total_bytes(), 30);

        // Remove middle part
        let removed = tracker.remove_range(&super::SparseRange::new(10, 20));
        assert!(removed);
        assert_eq!(tracker.total_bytes(), 20);
        assert_eq!(tracker.range_count(), 2);

        // Should have ranges [0-10) and [20-30)
        let ranges = tracker.get_ranges();
        assert!(ranges.contains(&super::SparseRange::new(0, 10)));
        assert!(ranges.contains(&super::SparseRange::new(20, 30)));
    }

    #[test]
    fn test_chunk_range_operations() {
        let chunk1 = super::ChunkRange::new(100, 50);
        let chunk2 = super::ChunkRange::new(125, 25);

        assert_eq!(chunk1.end_offset(), 150);
        assert!(chunk1.contains_offset(125));
        assert!(!chunk1.contains_offset(200));

        assert!(chunk1.overlaps(&chunk2));

        let sparse_range = chunk1.to_sparse_range();
        assert_eq!(sparse_range, super::SparseRange::new(100, 150));
    }

    #[test]
    fn test_range_statistics() {
        let mut tracker = super::RangeTracker::new();

        tracker.add_range(super::SparseRange::new(0, 10));
        tracker.add_range(super::SparseRange::new(20, 30));
        tracker.add_range(super::SparseRange::new(50, 100));

        let stats = tracker.get_stats();
        assert_eq!(stats.total_ranges, 3);
        assert_eq!(stats.total_bytes_covered, 70);
        assert_eq!(stats.gap_count, 2); // gaps within observed extent: 10-20, 30-50
        assert_eq!(stats.largest_range_size, 50);
        assert_eq!(stats.smallest_range_size, 10);
    }

    #[test]
    fn test_range_edge_cases() {
        let mut tracker = super::RangeTracker::new();

        // Empty range should be ignored
        tracker.add_range(super::SparseRange::new(10, 10));
        assert_eq!(tracker.range_count(), 0);

        // Zero-sized coverage
        assert_eq!(tracker.coverage_ratio(0), 1.0);
        assert!(tracker.is_contiguous_to(0));

        // Remove non-existent range
        let removed = tracker.remove_range(&super::SparseRange::new(100, 200));
        assert!(!removed);
    }

    #[test]
    fn test_sparse_range_split() {
        let range = super::SparseRange::new(10, 30);

        let split = range.split_at(20);
        assert!(split.is_some());

        let (left, right) = split.unwrap();
        assert_eq!(left, super::SparseRange::new(10, 20));
        assert_eq!(right, super::SparseRange::new(20, 30));

        // Split at boundary should return None
        assert!(range.split_at(10).is_none());
        assert!(range.split_at(30).is_none());
        assert!(range.split_at(5).is_none());
    }

    #[test]
    fn test_range_intersection() {
        let range1 = super::SparseRange::new(10, 30);
        let range2 = super::SparseRange::new(20, 40);
        let range3 = super::SparseRange::new(50, 60);

        let intersection = range1.intersection(&range2);
        assert!(intersection.is_some());
        assert_eq!(intersection.unwrap(), super::SparseRange::new(20, 30));

        let no_intersection = range1.intersection(&range3);
        assert!(no_intersection.is_none());
    }

    #[test]
    fn test_temp_management_config() {
        use super::TempManagementConfig;

        let config = TempManagementConfig::default();
        assert_eq!(config.temp_prefix, "atp_sparse");
        assert_eq!(config.max_temp_age, Duration::from_secs(24 * 60 * 60));
        assert!(config.include_pid_in_name);
        assert!(config.auto_create_quarantine);
    }

    #[test]
    fn test_fsync_policy_properties() {
        use super::FsyncPolicy;

        let never = FsyncPolicy::Never;
        assert_eq!(never.performance_impact(), 0);
        assert_eq!(never.durability_level(), 0);

        let every_write = FsyncPolicy::EveryWrite;
        assert_eq!(every_write.performance_impact(), 100);
        assert_eq!(every_write.durability_level(), 100);
    }

    #[test]
    fn test_commit_policy_properties() {
        use super::CommitPolicy;

        let atomic = CommitPolicy::AtomicRename;
        assert!(!atomic.supports_cross_filesystem());
        assert_eq!(atomic.performance_level(), 100);

        let copy = CommitPolicy::CopyAndVerify;
        assert!(copy.supports_cross_filesystem());
        assert_eq!(copy.safety_level(), 100);
    }

    #[test]
    fn test_quarantine_reason_properties() {
        use super::QuarantineReason;

        let cancelled = QuarantineReason::Cancelled;
        assert_eq!(cancelled.severity(), 20);
        assert!(cancelled.description().contains("cancelled"));

        let corruption = QuarantineReason::CorruptionDetected;
        assert_eq!(corruption.severity(), 100);
        assert!(corruption.description().contains("corruption"));
    }

    #[test]
    fn test_sparse_writer_config_defaults() {
        use super::SparseWriterConfig;

        let config = SparseWriterConfig::default();
        assert!(config.enable_preallocation);
        assert_eq!(config.chunk_size_hint, 1024 * 1024);
        assert!(config.enable_quarantine);
    }

    #[test]
    fn test_write_options_defaults() {
        use super::{WriteOptions, WritePriority};

        let options = WriteOptions::default();
        assert_eq!(options.priority, WritePriority::Normal);
        assert!(!options.force_sync);
        assert!(options.size_hint.is_none());
    }

    #[test]
    fn test_priority_ordering() {
        use super::WritePriority;

        assert!(WritePriority::Critical > WritePriority::High);
        assert!(WritePriority::High > WritePriority::Normal);
        assert!(WritePriority::Normal > WritePriority::Low);
    }
}
