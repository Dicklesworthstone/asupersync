    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::record::RegionRecord;
    use crate::types::Budget;
    use crate::util::ArenaIndex;

    fn test_region_id() -> RegionId {
        RegionId::from_arena(ArenaIndex::new(0, 1))
    }

    #[test]
    fn rref_is_copy_and_clone() {
        let region_id = test_region_id();
        let record = RegionRecord::new(region_id, None, Budget::INFINITE);
        let index = record.heap_alloc(42u32).expect("heap alloc");
        let rref = RRef::<u32>::new(region_id, index);

        // Test Copy
        let rref2 = rref;
        assert_eq!(rref.region_id(), rref2.region_id());

        // Clone is implied by Copy, assert the trait bound explicitly.
        assert_clone::<RRef<u32>>();
    }

    #[test]
    fn rref_equality() {
        let region_id = test_region_id();
        let record = RegionRecord::new(region_id, None, Budget::INFINITE);

        let index1 = record.heap_alloc(1u32).expect("heap alloc");
        let index2 = record.heap_alloc(2u32).expect("heap alloc");

        let rref1a = RRef::<u32>::new(region_id, index1);
        let rref1_clone = RRef::<u32>::new(region_id, index1);
        let rref2 = RRef::<u32>::new(region_id, index2);

        assert_eq!(rref1a, rref1_clone);
        assert_ne!(rref1a, rref2);
    }

    #[test]
    fn rref_accessors() {
        let region_id = test_region_id();
        let record = RegionRecord::new(region_id, None, Budget::INFINITE);
        let index = record.heap_alloc("hello".to_string()).expect("heap alloc");
        let rref = RRef::<String>::new(region_id, index);

        assert_eq!(rref.region_id(), region_id);
        assert_eq!(rref.heap_index(), index);
    }

    #[test]
    fn rref_debug_format() {
        let region_id = test_region_id();
        let record = RegionRecord::new(region_id, None, Budget::INFINITE);
        let index = record.heap_alloc(42u32).expect("heap alloc");
        let rref = RRef::<u32>::new(region_id, index);

        let debug_str = format!("{rref:?}");
        assert!(debug_str.contains("RRef"));
        assert!(debug_str.contains("region_id"));
        assert!(debug_str.contains("index"));
    }

    #[test]
    fn rref_access_through_region_record() {
        let region_id = test_region_id();
        let record = RegionRecord::new(region_id, None, Budget::INFINITE);
        let index = record.heap_alloc("hello".to_string()).expect("heap alloc");
        let rref = RRef::<String>::new(region_id, index);

        let value = record.rref_get(&rref).expect("rref_get");
        assert_eq!(value, "hello");

        let len = record.rref_with(&rref, String::len).expect("rref_with");
        assert_eq!(len, 5);
    }

    #[test]
    fn rref_region_mismatch_is_error() {
        let region_a = test_region_id();
        let region_b = RegionId::from_arena(ArenaIndex::new(1, 0));
        let record_a = RegionRecord::new(region_a, None, Budget::INFINITE);
        let record_b = RegionRecord::new(region_b, None, Budget::INFINITE);

        let index = record_a.heap_alloc(7u32).expect("heap alloc");
        let rref = RRef::<u32>::new(region_a, index);

        let err = record_b.rref_get(&rref).expect_err("region mismatch");
        assert_eq!(
            err,
            RRefError::RegionMismatch {
                expected: region_a,
                actual: region_b,
            }
        );
    }

    // Compile-time test for Send/Sync bounds
    fn assert_clone<T: Clone>() {}
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}

    #[test]
    fn rref_send_sync_bounds() {
        // RRef<T> is Send when T: Send
        assert_send::<RRef<u32>>();
        assert_send::<RRef<String>>();
        assert_send::<RRef<Vec<i32>>>();

        // RRef<T> is Sync when T: Sync
        assert_sync::<RRef<u32>>();
        assert_sync::<RRef<String>>();
        assert_sync::<RRef<Vec<i32>>>();
    }

    // ================================================================
    // Witness validation tests (bd-27c7l)
    // ================================================================

    #[test]
    fn validate_witness_matching_region_succeeds() {
        let rid = test_region_id();
        let record = RegionRecord::new(rid, None, Budget::INFINITE);
        let index = record.heap_alloc(42u32).expect("heap alloc");
        let rref = RRef::<u32>::new(rid, index);

        let witness = RRefAccessWitness::new(rid);
        assert!(rref.validate_witness(&witness).is_ok());
    }

    #[test]
    fn validate_witness_wrong_region_fails() {
        let rid_a = test_region_id();
        let rid_b = RegionId::from_arena(ArenaIndex::new(77, 0));
        let record = RegionRecord::new(rid_a, None, Budget::INFINITE);
        let index = record.heap_alloc(42u32).expect("heap alloc");
        let rref = RRef::<u32>::new(rid_a, index);

        let wrong_witness = RRefAccessWitness::new(rid_b);
        let err = rref.validate_witness(&wrong_witness);
        assert_eq!(err.unwrap_err(), RRefError::WrongRegion);
    }

    #[test]
    fn access_witness_is_copy_and_eq() {
        let rid = test_region_id();
        let w1 = RRefAccessWitness::new(rid);
        let w2 = w1; // Copy
        assert_eq!(w1, w2);
        assert_eq!(w1.region(), rid);
    }

    #[test]
    fn rref_error_display_coverage() {
        let rid = test_region_id();
        let cases: Vec<(RRefError, &str)> = vec![
            (RRefError::RegionNotFound(rid), "region not found"),
            (RRefError::AllocationInvalid, "heap allocation is invalid"),
            (
                RRefError::RegionMismatch {
                    expected: rid,
                    actual: rid,
                },
                "region mismatch",
            ),
            (RRefError::RegionClosed, "region is closed"),
            (
                RRefError::WrongRegion,
                "access witness references wrong region",
            ),
        ];

        for (err, expected_substring) in cases {
            let msg = format!("{err}");
            assert!(
                msg.contains(expected_substring),
                "expected '{expected_substring}' in '{msg}'"
            );
        }
    }
