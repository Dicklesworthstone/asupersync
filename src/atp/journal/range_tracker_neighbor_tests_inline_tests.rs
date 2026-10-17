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
