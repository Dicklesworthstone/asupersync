    #![allow(clippy::used_underscore_items)]

    use super::*;

    #[test]
    fn test_allocation_metrics() {
        reset_allocation_metrics();

        let initial = get_allocation_metrics();
        assert_eq!(initial.bytes_allocations, 0);
        assert_eq!(initial.bytes_mut_allocations, 0);

        // Simulate some allocations
        _profile_bytes_allocation();
        _profile_bytes_mut_allocation();
        _profile_bytes_mut_growth();
        _profile_split_to_copy(1024);
        _profile_freeze_operation();

        let after = get_allocation_metrics();
        assert_eq!(after.bytes_allocations, 1);
        assert_eq!(after.bytes_mut_allocations, 1);
        assert_eq!(after.bytes_mut_growth, 1);
        assert_eq!(after.split_to_copies, 1024);
        assert_eq!(after.freeze_operations, 1);

        reset_allocation_metrics();
        let reset = get_allocation_metrics();
        assert_eq!(reset.bytes_allocations, 0);
    }
