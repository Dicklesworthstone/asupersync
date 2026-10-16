    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::util::ArenaIndex;
    use insta::assert_snapshot;
    use std::collections::HashMap;

    fn region(n: u32) -> RegionId {
        RegionId::from_arena(ArenaIndex::new(n, 0))
    }

    fn t(nanos: u64) -> Time {
        Time::from_nanos(nanos)
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn dump_region_tree_scrubbed(name: &str, oracle: &RegionTreeOracle) -> String {
        let ids = oracle.sorted_region_ids();
        let aliases: HashMap<RegionId, String> = ids
            .iter()
            .enumerate()
            .map(|(index, region_id)| (*region_id, format!("[REGION_{index}]")))
            .collect();

        let root = oracle.root().map_or_else(
            || "none".to_owned(),
            |region_id| aliases[&region_id].clone(),
        );

        let mut lines = vec![
            format!("scenario: {name}"),
            format!("root: {root}"),
            format!("region_count: {}", oracle.region_count()),
            "regions:".to_owned(),
        ];

        for region_id in ids {
            let entry = oracle
                .regions
                .get(&region_id)
                .expect("snapshot region should exist");
            let parent = entry.parent.map_or_else(
                || "none".to_owned(),
                |parent_id| aliases[&parent_id].clone(),
            );
            let depth = oracle
                .depth(region_id)
                .map_or_else(|| "cycle".to_owned(), |depth| depth.to_string());
            let mut children: Vec<String> = entry
                .subregions
                .iter()
                .copied()
                .map(|child_id| aliases[&child_id].clone())
                .collect();
            children.sort();

            lines.push(format!("- id: {}", aliases[&region_id]));
            lines.push(format!("  parent: {parent}"));
            lines.push(format!("  depth: {depth}"));
            lines.push(format!("  created_at: {:?}", entry.created_at));
            lines.push(format!("  children: [{}]", children.join(", ")));
        }

        lines.join("\n")
    }

    // === Valid Tree Tests ===

    #[test]
    fn empty_tree_passes() {
        init_test("empty_tree_passes");
        let oracle = RegionTreeOracle::new();
        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        crate::test_complete!("empty_tree_passes");
    }

    #[test]
    fn single_root_passes() {
        init_test("single_root_passes");
        let mut oracle = RegionTreeOracle::new();
        oracle.on_region_create(region(0), None, t(10));
        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        let root = oracle.root();
        crate::assert_with_log!(root == Some(region(0)), "root", Some(region(0)), root);
        crate::test_complete!("single_root_passes");
    }

    #[test]
    fn linear_chain_passes() {
        init_test("linear_chain_passes");
        let mut oracle = RegionTreeOracle::new();

        // r0 -> r1 -> r2
        oracle.on_region_create(region(0), None, t(10));
        oracle.on_region_create(region(1), Some(region(0)), t(20));
        oracle.on_region_create(region(2), Some(region(1)), t(30));

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        let count = oracle.region_count();
        crate::assert_with_log!(count == 3, "region_count", 3, count);
        crate::test_complete!("linear_chain_passes");
    }

    #[test]
    fn branching_tree_passes() {
        init_test("branching_tree_passes");
        let mut oracle = RegionTreeOracle::new();

        //       r0
        //      /  \
        //    r1    r2
        //   / \
        //  r3  r4
        oracle.on_region_create(region(0), None, t(10));
        oracle.on_region_create(region(1), Some(region(0)), t(20));
        oracle.on_region_create(region(2), Some(region(0)), t(30));
        oracle.on_region_create(region(3), Some(region(1)), t(40));
        oracle.on_region_create(region(4), Some(region(1)), t(50));

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        let count = oracle.region_count();
        crate::assert_with_log!(count == 5, "region_count", 5, count);
        crate::test_complete!("branching_tree_passes");
    }

    #[test]
    fn deeply_nested_tree_passes() {
        init_test("deeply_nested_tree_passes");
        let mut oracle = RegionTreeOracle::new();

        // Create a chain of 10 nested regions
        oracle.on_region_create(region(0), None, t(0));
        for i in 1..10 {
            oracle.on_region_create(region(i), Some(region(i - 1)), t(u64::from(i) * 10));
        }

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        let depth9 = oracle.depth(region(9));
        crate::assert_with_log!(depth9 == Some(9), "depth 9", Some(9), depth9);
        let depth0 = oracle.depth(region(0));
        crate::assert_with_log!(depth0 == Some(0), "depth 0", Some(0), depth0);
        crate::test_complete!("deeply_nested_tree_passes");
    }

    // === Multiple Roots Violation ===

    #[test]
    fn multiple_roots_fails() {
        init_test("multiple_roots_fails");
        let mut oracle = RegionTreeOracle::new();

        oracle.on_region_create(region(0), None, t(10));
        oracle.on_region_create(region(1), None, t(20)); // Second root!

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "err", true, err);

        match result.unwrap_err() {
            RegionTreeViolation::MultipleRoots { roots } => {
                let len = roots.len();
                crate::assert_with_log!(len == 2, "roots len", 2, len);
                let has0 = roots.contains(&region(0));
                crate::assert_with_log!(has0, "contains r0", true, has0);
                let has1 = roots.contains(&region(1));
                crate::assert_with_log!(has1, "contains r1", true, has1);
            }
            other => panic!("Expected MultipleRoots, got {other:?}"),
        }
        crate::test_complete!("multiple_roots_fails");
    }

    #[test]
    fn multiple_roots_with_children_fails() {
        init_test("multiple_roots_with_children_fails");
        let mut oracle = RegionTreeOracle::new();

        // Two separate trees
        oracle.on_region_create(region(0), None, t(10));
        oracle.on_region_create(region(1), Some(region(0)), t(20));
        oracle.on_region_create(region(2), None, t(30)); // Second root!
        oracle.on_region_create(region(3), Some(region(2)), t(40));

        let result = oracle.check();
        let is_multiple = matches!(
            result.unwrap_err(),
            RegionTreeViolation::MultipleRoots { .. }
        );
        crate::assert_with_log!(is_multiple, "multiple roots", true, is_multiple);
        crate::test_complete!("multiple_roots_with_children_fails");
    }

    // === No Root Violation ===

    #[test]
    fn no_root_fails() {
        init_test("no_root_fails");
        let mut oracle = RegionTreeOracle::new();

        // Manually create regions where all have parents (forming a cycle)
        // which results in NoRoot being detected first
        oracle.regions.insert(
            region(0),
            RegionTreeEntry {
                parent: Some(region(1)),
                subregions: HashSet::from([region(1)]),
                created_at: t(10),
            },
        );
        oracle.regions.insert(
            region(1),
            RegionTreeEntry {
                parent: Some(region(0)),
                subregions: HashSet::from([region(0)]),
                created_at: t(20),
            },
        );

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "err", true, err);

        // First we'll get NoRoot since all have parents
        match result.unwrap_err() {
            RegionTreeViolation::NoRoot => {
                // Expected - there's no root when all regions have parents
            }
            other => panic!("Expected NoRoot, got {other:?}"),
        }
        crate::test_complete!("no_root_fails");
    }

    // === Invalid Parent Violation ===

    #[test]
    fn invalid_parent_fails() {
        init_test("invalid_parent_fails");
        let mut oracle = RegionTreeOracle::new();

        oracle.on_region_create(region(0), None, t(10));
        // region(1) claims region(99) as parent, but region(99) doesn't exist
        oracle.on_region_create(region(1), Some(region(99)), t(20));

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "err", true, err);

        match result.unwrap_err() {
            RegionTreeViolation::InvalidParent {
                region: r,
                claimed_parent,
            } => {
                crate::assert_with_log!(r == region(1), "region", region(1), r);
                crate::assert_with_log!(
                    claimed_parent == region(99),
                    "parent",
                    region(99),
                    claimed_parent
                );
            }
            other => panic!("Expected InvalidParent, got {other:?}"), // ubs:ignore - test helper
        }
        crate::test_complete!("invalid_parent_fails");
    }

    // === Parent-Child Mismatch Violation ===

    #[test]
    fn parent_child_mismatch_fails() {
        init_test("parent_child_mismatch_fails");
        let mut oracle = RegionTreeOracle::new();

        // Create root
        oracle.on_region_create(region(0), None, t(10));

        // Manually insert a region that claims region(0) as parent
        // but don't add it to region(0)'s subregions
        oracle.regions.insert(
            region(1),
            RegionTreeEntry {
                parent: Some(region(0)),
                subregions: HashSet::new(),
                created_at: t(20),
            },
        );
        // Note: we did NOT add region(1) to region(0)'s subregions

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "err", true, err);

        match result.unwrap_err() {
            RegionTreeViolation::ParentChildMismatch { region: r, parent } => {
                crate::assert_with_log!(r == region(1), "region", region(1), r);
                crate::assert_with_log!(parent == region(0), "parent", region(0), parent);
            }
            other => panic!("Expected ParentChildMismatch, got {other:?}"),
        }
        crate::test_complete!("parent_child_mismatch_fails");
    }

    #[test]
    fn stale_parent_subregion_edge_fails() {
        init_test("stale_parent_subregion_edge_fails");
        let mut oracle = RegionTreeOracle::new();

        oracle.on_region_create(region(0), None, t(10));
        oracle.on_region_create(region(2), Some(region(0)), t(20));
        oracle.on_region_create(region(1), Some(region(0)), t(30));

        // Simulate a reparent where old parent->child edge was not cleaned.
        if let Some(entry) = oracle.regions.get_mut(&region(1)) {
            entry.parent = Some(region(2));
        }
        oracle.on_subregion_add(region(2), region(1));

        let result = oracle.check();
        assert!(result.is_err());
        match result.unwrap_err() {
            RegionTreeViolation::ParentChildMismatch { region: r, parent } => {
                assert_eq!(r, region(1));
                assert_eq!(parent, region(0));
            }
            other => panic!("Expected ParentChildMismatch, got {other:?}"),
        }
        crate::test_complete!("stale_parent_subregion_edge_fails");
    }

    // === Cycle Detection ===

    #[test]
    fn simple_cycle_fails() {
        init_test("simple_cycle_fails");
        let mut oracle = RegionTreeOracle::new();

        // Create a cycle: r0 -> r1 -> r2 -> r0
        // We need to manually create this since on_region_create prevents it

        oracle.regions.insert(
            region(0),
            RegionTreeEntry {
                parent: Some(region(2)),
                subregions: HashSet::from([region(1)]),
                created_at: t(10),
            },
        );
        oracle.regions.insert(
            region(1),
            RegionTreeEntry {
                parent: Some(region(0)),
                subregions: HashSet::from([region(2)]),
                created_at: t(20),
            },
        );
        oracle.regions.insert(
            region(2),
            RegionTreeEntry {
                parent: Some(region(1)),
                subregions: HashSet::from([region(0)]),
                created_at: t(30),
            },
        );

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "err", true, err);

        // First we'll get NoRoot since all have parents
        match result.unwrap_err() {
            RegionTreeViolation::NoRoot => {
                // Expected - there's no root in a cycle
            }
            RegionTreeViolation::CycleDetected { cycle } => {
                let empty = cycle.is_empty();
                crate::assert_with_log!(!empty, "cycle not empty", false, empty);
            }
            other => panic!("Expected NoRoot or CycleDetected, got {other:?}"),
        }
        crate::test_complete!("simple_cycle_fails");
    }

    #[test]
    fn self_loop_fails() {
        init_test("self_loop_fails");
        let mut oracle = RegionTreeOracle::new();

        // Region is its own parent
        oracle.regions.insert(
            region(0),
            RegionTreeEntry {
                parent: Some(region(0)),
                subregions: HashSet::from([region(0)]),
                created_at: t(10),
            },
        );

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "err", true, err);
        crate::test_complete!("self_loop_fails");
    }

    // === Helper Method Tests ===

    #[test]
    fn depth_calculation() {
        init_test("depth_calculation");
        let mut oracle = RegionTreeOracle::new();

        oracle.on_region_create(region(0), None, t(10));
        oracle.on_region_create(region(1), Some(region(0)), t(20));
        oracle.on_region_create(region(2), Some(region(1)), t(30));

        let depth0 = oracle.depth(region(0));
        crate::assert_with_log!(depth0 == Some(0), "depth 0", Some(0), depth0);
        let depth1 = oracle.depth(region(1));
        crate::assert_with_log!(depth1 == Some(1), "depth 1", Some(1), depth1);
        let depth2 = oracle.depth(region(2));
        crate::assert_with_log!(depth2 == Some(2), "depth 2", Some(2), depth2);
        let depth_missing = oracle.depth(region(99));
        crate::assert_with_log!(
            depth_missing.is_none(),
            "depth missing",
            None::<usize>,
            depth_missing
        ); // Not found
        crate::test_complete!("depth_calculation");
    }

    #[test]
    fn root_returns_none_for_multiple_roots() {
        init_test("root_returns_none_for_multiple_roots");
        let mut oracle = RegionTreeOracle::new();

        oracle.on_region_create(region(0), None, t(10));
        oracle.on_region_create(region(1), None, t(20));

        let root = oracle.root();
        crate::assert_with_log!(root.is_none(), "root none", None::<RegionId>, root);
        crate::test_complete!("root_returns_none_for_multiple_roots");
    }

    #[test]
    fn region_tree_structured_dump_scrubbed_snapshot() {
        init_test("region_tree_structured_dump_scrubbed_snapshot");

        let mut branching = RegionTreeOracle::new();
        branching.on_region_create(region(10), None, t(10));
        branching.on_region_create(region(20), Some(region(10)), t(20));
        branching.on_region_create(region(30), Some(region(10)), t(30));
        branching.on_region_create(region(40), Some(region(20)), t(40));
        branching.on_region_create(region(50), Some(region(20)), t(50));

        let mut nested = RegionTreeOracle::new();
        nested.on_region_create(region(100), None, t(100));
        nested.on_region_create(region(110), Some(region(100)), t(110));
        nested.on_region_create(region(120), Some(region(110)), t(120));
        nested.on_region_create(region(130), Some(region(120)), t(130));
        nested.on_region_create(region(140), Some(region(130)), t(140));

        let mut reparented = RegionTreeOracle::new();
        reparented.on_region_create(region(200), None, t(200));
        reparented.on_region_create(region(210), Some(region(200)), t(210));
        reparented.on_region_create(region(220), Some(region(200)), t(220));
        reparented.on_region_create(region(230), Some(region(210)), t(230));
        reparented.on_region_create(region(240), Some(region(230)), t(240));
        reparented.on_region_create(region(230), Some(region(220)), t(250));

        let snapshot = [
            dump_region_tree_scrubbed("branching", &branching),
            dump_region_tree_scrubbed("nested_chain", &nested),
            dump_region_tree_scrubbed("reparented_subtree", &reparented),
        ]
        .join("\n\n");

        assert_snapshot!("region_tree_structured_dump_scrubbed", snapshot);
        crate::test_complete!("region_tree_structured_dump_scrubbed_snapshot");
    }

    #[test]
    fn reset_clears_state() {
        init_test("reset_clears_state");
        let mut oracle = RegionTreeOracle::new();

        oracle.on_region_create(region(0), None, t(10));
        oracle.on_region_create(region(1), Some(region(0)), t(20));

        let count = oracle.region_count();
        crate::assert_with_log!(count == 2, "region_count", 2, count);

        oracle.reset();

        let count = oracle.region_count();
        crate::assert_with_log!(count == 0, "region_count", 0, count);
        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        crate::test_complete!("reset_clears_state");
    }

    #[test]
    fn on_subregion_add_updates_parent() {
        init_test("on_subregion_add_updates_parent");
        let mut oracle = RegionTreeOracle::new();

        oracle.on_region_create(region(0), None, t(10));
        oracle.on_region_create(region(1), None, t(20)); // Initially a second root

        // Fix by manually adding subregion relationship
        if let Some(entry) = oracle.regions.get_mut(&region(1)) {
            entry.parent = Some(region(0));
        }
        oracle.on_subregion_add(region(0), region(1));

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        crate::test_complete!("on_subregion_add_updates_parent");
    }

    // === Violation Display Tests ===

    #[test]
    fn violation_display_multiple_roots() {
        init_test("violation_display_multiple_roots");
        let v = RegionTreeViolation::MultipleRoots {
            roots: vec![region(0), region(1)],
        };
        let s = v.to_string();
        let has = s.contains("Multiple root");
        crate::assert_with_log!(has, "contains", true, has);
        crate::test_complete!("violation_display_multiple_roots");
    }

    #[test]
    fn violation_display_invalid_parent() {
        init_test("violation_display_invalid_parent");
        let v = RegionTreeViolation::InvalidParent {
            region: region(1),
            claimed_parent: region(99),
        };
        let s = v.to_string();
        let has = s.contains("does not exist");
        crate::assert_with_log!(has, "contains", true, has);
        crate::test_complete!("violation_display_invalid_parent");
    }

    #[test]
    fn violation_display_mismatch() {
        init_test("violation_display_mismatch");
        let v = RegionTreeViolation::ParentChildMismatch {
            region: region(1),
            parent: region(0),
        };
        let s = v.to_string();
        let has = s.contains("subregions");
        crate::assert_with_log!(has, "contains", true, has);
        crate::test_complete!("violation_display_mismatch");
    }

    #[test]
    fn violation_display_cycle() {
        init_test("violation_display_cycle");
        let v = RegionTreeViolation::CycleDetected {
            cycle: vec![region(0), region(1), region(2)],
        };
        let s = v.to_string();
        let has = s.contains("Cycle");
        crate::assert_with_log!(has, "contains", true, has);
        crate::test_complete!("violation_display_cycle");
    }

    #[test]
    fn violation_display_no_root() {
        init_test("violation_display_no_root");
        let v = RegionTreeViolation::NoRoot;
        let s = v.to_string();
        let has = s.contains("No root");
        crate::assert_with_log!(has, "contains", true, has);
        crate::test_complete!("violation_display_no_root");
    }

    // === Edge Cases ===

    #[test]
    fn late_parent_creation_handled() {
        init_test("late_parent_creation_handled");
        let mut oracle = RegionTreeOracle::new();

        // Create child before parent (unusual but possible in some scenarios)
        // This will initially have invalid parent
        oracle.on_region_create(region(1), Some(region(0)), t(10));

        // Now create parent
        oracle.on_region_create(region(0), None, t(5));

        // Need to manually fix the subregions relationship since parent was created later
        oracle.on_subregion_add(region(0), region(1));

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        crate::test_complete!("late_parent_creation_handled");
    }

    #[test]
    fn duplicate_region_create_reparents_cleanly() {
        init_test("duplicate_region_create_reparents_cleanly");
        let mut oracle = RegionTreeOracle::new();

        oracle.on_region_create(region(0), None, t(0));
        oracle.on_region_create(region(2), Some(region(0)), t(1));
        oracle.on_region_create(region(1), Some(region(0)), t(2));

        // Re-create region(1) with a new parent. Oracle should remove stale
        // region(0) -> region(1) edge automatically.
        oracle.on_region_create(region(1), Some(region(2)), t(3));

        assert!(oracle.check().is_ok());
        crate::test_complete!("duplicate_region_create_reparents_cleanly");
    }

    #[test]
    fn duplicate_region_create_reparent_preserves_existing_children() {
        init_test("duplicate_region_create_reparent_preserves_existing_children");
        let mut oracle = RegionTreeOracle::new();

        oracle.on_region_create(region(0), None, t(0));
        oracle.on_region_create(region(2), Some(region(0)), t(1));
        oracle.on_region_create(region(1), Some(region(0)), t(2));
        oracle.on_region_create(region(3), Some(region(1)), t(3));

        // Re-create region(1) with a new parent after it already has a child.
        // The oracle should preserve region(1) -> region(3) while removing the
        // stale region(0) -> region(1) edge.
        oracle.on_region_create(region(1), Some(region(2)), t(4));

        assert!(oracle.check().is_ok());
        assert_eq!(oracle.depth(region(3)), Some(3));
        crate::test_complete!("duplicate_region_create_reparent_preserves_existing_children");
    }

    #[test]
    fn many_siblings() {
        init_test("many_siblings");
        let mut oracle = RegionTreeOracle::new();

        oracle.on_region_create(region(0), None, t(10));

        // Create 100 children of root
        for i in 1..=100 {
            oracle.on_region_create(region(i), Some(region(0)), t(u64::from(i) * 10));
        }

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        let count = oracle.region_count();
        crate::assert_with_log!(count == 101, "region_count", 101, count);

        // Verify all children are at depth 1
        for i in 1..=100 {
            let depth = oracle.depth(region(i));
            crate::assert_with_log!(depth == Some(1), "depth", Some(1), depth);
        }
        crate::test_complete!("many_siblings");
    }

    // === Phantom Subregion Tests ===

    #[test]
    fn phantom_subregion_detected() {
        init_test("phantom_subregion_detected");
        let mut oracle = RegionTreeOracle::new();

        oracle.on_region_create(region(0), None, t(0));
        // Manually inject a phantom child via on_subregion_add without creating it.
        oracle.on_subregion_add(region(0), region(99));

        let result = oracle.check();
        assert!(result.is_err());
        match result.unwrap_err() {
            RegionTreeViolation::PhantomSubregion {
                parent,
                phantom_child,
            } => {
                assert_eq!(parent, region(0));
                assert_eq!(phantom_child, region(99));
            }
            other => panic!("expected PhantomSubregion, got {other:?}"),
        }

        crate::test_complete!("phantom_subregion_detected");
    }

    #[test]
    fn phantom_subregion_display() {
        init_test("phantom_subregion_display");
        let v = RegionTreeViolation::PhantomSubregion {
            parent: region(0),
            phantom_child: region(42),
        };
        let msg = v.to_string();
        assert!(msg.contains("non-existent subregion"), "got: {msg}");
        crate::test_complete!("phantom_subregion_display");
    }

    #[test]
    fn valid_subregion_add_passes() {
        init_test("valid_subregion_add_passes");
        let mut oracle = RegionTreeOracle::new();

        oracle.on_region_create(region(0), None, t(0));
        oracle.on_region_create(region(1), Some(region(0)), t(1));
        // Redundant add — child already in subregions from on_region_create.
        oracle.on_subregion_add(region(0), region(1));

        assert!(oracle.check().is_ok());
        crate::test_complete!("valid_subregion_add_passes");
    }

    // =========================================================================
    // Wave 49 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn region_tree_violation_debug_clone() {
        let v = RegionTreeViolation::NoRoot;
        let dbg = format!("{v:?}");
        assert!(dbg.contains("NoRoot"), "{dbg}");
        let cloned = v;
        assert!(format!("{cloned:?}").contains("NoRoot"));

        let v2 = RegionTreeViolation::MultipleRoots {
            roots: vec![region(0), region(1)],
        };
        let cloned2 = v2;
        assert!(format!("{cloned2:?}").contains("MultipleRoots"));
    }

    #[test]
    fn region_tree_oracle_default() {
        let def = RegionTreeOracle::default();
        let dbg = format!("{def:?}");
        assert!(dbg.contains("RegionTreeOracle"), "{dbg}");
        assert!(def.check().is_ok());
    }
