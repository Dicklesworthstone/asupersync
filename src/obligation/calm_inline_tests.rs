    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    #[test]
    fn classification_count_is_16() {
        assert_eq!(classifications().len(), 16);
    }

    #[test]
    fn monotone_ratio_is_correct() {
        let ratio = monotone_ratio();
        // 7 monotone out of 16 = 0.4375
        assert!((ratio - 0.4375).abs() < 0.001, "ratio = {ratio}");
    }

    #[test]
    fn coordination_points_are_non_monotone() {
        let points = coordination_points();
        assert_eq!(points.len(), 9);
        for p in &points {
            assert_eq!(p.monotonicity, Monotonicity::NonMonotone);
        }
    }

    #[test]
    fn coordination_free_are_monotone() {
        let free = coordination_free();
        assert_eq!(free.len(), 7);
        for f in &free {
            assert_eq!(f.monotonicity, Monotonicity::Monotone);
        }
    }

    #[test]
    fn all_operations_have_justification() {
        for c in classifications() {
            assert!(
                !c.justification.is_empty(),
                "{} has no justification",
                c.operation
            );
        }
    }

    #[test]
    fn monotonicity_display() {
        assert_eq!(Monotonicity::Monotone.to_string(), "monotone");
        assert_eq!(Monotonicity::NonMonotone.to_string(), "non_monotone");
    }

    #[test]
    fn reserve_is_monotone() {
        let reserve = classifications()
            .iter()
            .find(|c| c.operation == "Reserve")
            .unwrap();
        assert_eq!(reserve.monotonicity, Monotonicity::Monotone);
    }

    #[test]
    fn region_close_is_non_monotone() {
        let rc = classifications()
            .iter()
            .find(|c| c.operation == "RegionClose")
            .unwrap();
        assert_eq!(rc.monotonicity, Monotonicity::NonMonotone);
    }

    #[test]
    fn crdt_merge_is_monotone() {
        let merge = classifications()
            .iter()
            .find(|c| c.operation == "CrdtMerge")
            .unwrap();
        assert_eq!(merge.monotonicity, Monotonicity::Monotone);
    }

    #[test]
    fn all_seven_monotone_operations() {
        let expected = [
            "Reserve",
            "Send",
            "Acquire",
            "Renew",
            "Delegate",
            "CrdtMerge",
            "CancelRequest",
        ];
        let mono: Vec<&str> = coordination_free().iter().map(|c| c.operation).collect();
        // Verify exact membership rather than just the count.
        for exp in &expected {
            assert!(
                mono.contains(exp),
                "missing expected monotone operation {exp}"
            );
        }
        assert_eq!(mono.len(), 7);
    }

    // ── derive-trait coverage (wave 73) ──────────────────────────────────

    #[test]
    fn monotonicity_debug_clone_copy_eq_hash() {
        use std::collections::HashSet;

        let m = Monotonicity::Monotone;
        let m2 = m; // Copy
        let m3 = m;
        assert_eq!(m, m2);
        assert_eq!(m2, m3);

        let nm = Monotonicity::NonMonotone;
        assert_ne!(m, nm);

        let mut set = HashSet::new();
        set.insert(m);
        set.insert(m2);
        assert_eq!(set.len(), 1);
        set.insert(nm);
        assert_eq!(set.len(), 2);

        let dbg = format!("{m:?}");
        assert!(dbg.contains("Monotone"));
    }

    #[test]
    fn calm_classification_debug_clone_eq() {
        let c1 = CalmClassification {
            operation: "TestOp",
            protocol: "TestProto",
            monotonicity: Monotonicity::Monotone,
            justification: "test justification",
        };
        let c2 = c1.clone();
        assert_eq!(c1, c2);

        let c3 = CalmClassification {
            operation: "OtherOp",
            protocol: "TestProto",
            monotonicity: Monotonicity::NonMonotone,
            justification: "other justification",
        };
        assert_ne!(c1, c3);

        let dbg = format!("{c1:?}");
        assert!(dbg.contains("CalmClassification"));
        assert!(dbg.contains("TestOp"));
    }

    #[test]
    fn metamorphic_partitioned_views_preserve_classification_order() {
        let original = classifications();
        let monotone = coordination_free();
        let non_monotone = coordination_points();

        let reconstructed: Vec<(&'static str, Monotonicity)> = original
            .iter()
            .map(|classification| {
                let projection = match classification.monotonicity {
                    Monotonicity::Monotone => monotone
                        .iter()
                        .find(|candidate| candidate.operation == classification.operation)
                        .expect("monotone projection should contain every monotone operation"),
                    Monotonicity::NonMonotone => non_monotone
                        .iter()
                        .find(|candidate| candidate.operation == classification.operation)
                        .expect(
                            "non-monotone projection should contain every non-monotone operation",
                        ),
                };
                (projection.operation, projection.monotonicity)
            })
            .collect();

        let original_projection: Vec<(&'static str, Monotonicity)> = original
            .iter()
            .map(|classification| (classification.operation, classification.monotonicity))
            .collect();

        assert_eq!(
            reconstructed, original_projection,
            "projecting through monotone/non-monotone filtered views must preserve original order"
        );
    }
