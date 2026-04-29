//! Demonstration of the specific idempotence property:
//! open(R) → close(R) → close(R) returns Ok-or-AlreadyClosed (not panic)

#[cfg(test)]
mod tests {
    use super::super::region_table::RegionTable;
    use crate::record::region::RegionState;
    use crate::types::{Budget, Time};

    /// **Primary Target**: open(R) → close(R) → close(R) idempotence
    /// This demonstrates the exact property the user requested.
    #[test]
    fn demonstrate_close_idempotence_no_panic() {
        // Create region table and root region (OPEN)
        let mut table = RegionTable::new();
        let region_id = table.create_root(Budget::default(), Time::ZERO);
        let region = table.get(region_id.arena_index()).unwrap();

        // Verify initial state
        assert_eq!(table.state(region_id), Some(RegionState::Open));

        // First close: open(R) → close(R)
        let close_result_1 = region.begin_close(None);
        println!("First close result: {}", close_result_1);

        // Verify state changed
        assert_eq!(table.state(region_id), Some(RegionState::Closing));

        // Second close: close(R) → close(R)
        // THIS MUST NOT PANIC and should return false (already closed)
        let close_result_2 = region.begin_close(None);
        println!("Second close result: {} (should be false)", close_result_2);
        assert!(
            !close_result_2,
            "Second close should return false - already closing"
        );

        // Third close: close(R) → close(R) → close(R)
        // Also must not panic
        let close_result_3 = region.begin_close(None);
        println!("Third close result: {} (should be false)", close_result_3);
        assert!(
            !close_result_3,
            "Third close should return false - idempotent"
        );

        // Verify state is stable
        assert_eq!(table.state(region_id), Some(RegionState::Closing));

        println!("✓ Idempotence verified: multiple close calls are safe and don't panic");
    }

    /// Extended test: full close sequence idempotence
    #[test]
    fn demonstrate_full_close_sequence_idempotence() {
        let mut table = RegionTable::new();
        let region_id = table.create_root(Budget::default(), Time::ZERO);
        let region = table.get(region_id.arena_index()).unwrap();

        // Define complete close sequence
        let perform_full_close = || {
            let begin_result = region.begin_close(None);
            let finalize_result = region.begin_finalize();
            let complete_result = region.complete_close();
            (begin_result, finalize_result, complete_result)
        };

        println!("Performing first close sequence...");
        let (begin1, fin1, comp1) = perform_full_close();
        println!(
            "Results: begin={}, finalize={}, complete={}",
            begin1, fin1, comp1
        );

        let state_after_first = table.state(region_id);
        println!("State after first sequence: {:?}", state_after_first);

        println!("Performing second close sequence (idempotence test)...");
        let (begin2, fin2, comp2) = perform_full_close();
        println!(
            "Results: begin={}, finalize={}, complete={}",
            begin2, fin2, comp2
        );

        // Key property: second sequence should not panic and should return false
        assert!(!begin2, "Second begin_close should return false");
        assert!(
            !comp2,
            "Second complete_close should return false (region may not be ready)"
        );

        let state_after_second = table.state(region_id);
        println!("State after second sequence: {:?}", state_after_second);

        println!("Performing third close sequence (extended idempotence)...");
        let (begin3, _fin3, _comp3) = perform_full_close();
        assert!(!begin3, "Third begin_close should return false");

        println!("✓ Full sequence idempotence verified: no panics on repeated close sequences");
    }

    /// Edge case: close operations on removed regions
    #[test]
    fn demonstrate_close_idempotence_on_removed_region() {
        let mut table = RegionTable::new();
        let region_id = table.create_root(Budget::default(), Time::ZERO);

        // Remove the region from table
        let removed_region = table.remove(region_id.arena_index()).unwrap();
        assert_eq!(removed_region.id, region_id);

        // Now the region record still exists but is detached from table
        // Close operations should still be idempotent and not panic

        println!("Testing close idempotence on removed region...");
        let close1 = removed_region.begin_close(None);
        let close2 = removed_region.begin_close(None);
        let close3 = removed_region.begin_close(None);

        // All should be safe (not panic)
        println!(
            "Close results on removed region: {}, {}, {}",
            close1, close2, close3
        );

        // Further operations should also be safe
        let _ = removed_region.begin_finalize();
        let _ = removed_region.complete_close();

        println!("✓ Close idempotence verified even on removed regions");
    }
}
