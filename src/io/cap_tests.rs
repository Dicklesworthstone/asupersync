//! Quick validation test for IO cap counter overflow fuzzing approach
#[cfg(test)]
mod overflow_validation {
    use crate::io::cap::{IoCap, LabIoCap};

    #[test]
    fn test_counter_overflow_approach() {
        let cap = LabIoCap::new_for_tests();

        // Test basic operation
        cap.record_submit();
        cap.record_submit();
        cap.record_complete();

        let stats = cap.stats();
        assert_eq!(stats.submitted, 2);
        assert_eq!(stats.completed, 1);

        // Test massive counter increments (still far from overflow)
        for _ in 0..1000 {
            cap.record_submit();
        }

        let stats = cap.stats();
        assert_eq!(stats.submitted, 1002);
        assert_eq!(stats.completed, 1);
    }
}
