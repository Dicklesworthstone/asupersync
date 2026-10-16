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
