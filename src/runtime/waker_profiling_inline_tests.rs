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
    fn test_waker_metrics() {
        reset_waker_metrics();

        let initial = get_waker_metrics();
        assert_eq!(initial.waker_allocations, 0);
        assert_eq!(initial.wake_operations, 0);

        // Simulate some operations
        profile_waker_allocation();
        profile_wake_operation();
        profile_dedup_hit();
        profile_lock_acquisition();

        let after = get_waker_metrics();
        assert_eq!(after.waker_allocations, 1);
        assert_eq!(after.wake_operations, 1);
        assert_eq!(after.dedup_hits, 1);
        assert_eq!(after.lock_acquisitions, 1);

        reset_waker_metrics();
        let reset = get_waker_metrics();
        assert_eq!(reset.waker_allocations, 0);
    }
