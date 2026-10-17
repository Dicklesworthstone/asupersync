    use super::*;

    #[test]
    fn test_quota_manager_creation() {
        let manager = QuotaManager::new(1000);
        assert_eq!(manager.limit, 1000);
        assert_eq!(manager.current_usage.bytes_used, 0);
    }

    #[test]
    fn test_quota_check_success() {
        let manager = QuotaManager::new(1000);
        let result = manager.check_quota(500);
        assert!(result.is_ok());
    }

    #[test]
    fn test_quota_check_failure() {
        let manager = QuotaManager::new(1000);
        let result = manager.check_quota(1500);
        assert!(result.is_err());
    }

    #[test]
    fn quota_check_rejects_byte_counter_overflow() {
        let mut manager = QuotaManager::new(u64::MAX);
        let reservation = manager.reserve_quota(u64::MAX).unwrap();

        let result = manager.check_quota(1);

        assert!(matches!(
            result,
            Err(MailboxError::QuotaExceeded {
                usage: u64::MAX,
                limit: u64::MAX
            })
        ));
        assert_eq!(manager.current_usage.bytes_used, u64::MAX);
        assert_eq!(manager.current_usage.active_transfers, 1);

        manager.release_quota(reservation);
    }

    #[test]
    fn reserve_quota_rejects_exhausted_reservation_id_space_without_mutation() {
        let mut manager = QuotaManager::new(1000);
        manager.next_reservation_id = u64::MAX;

        let result = manager.reserve_quota(10);

        assert!(matches!(
            result,
            Err(MailboxError::ConfigurationError { details }) if details.contains("reservation id space exhausted")
        ));
        assert_eq!(manager.current_usage.bytes_used, 0);
        assert_eq!(manager.current_usage.active_transfers, 0);
        assert!(manager.active_reservations.is_empty());
    }

    #[test]
    fn test_quota_reservation() {
        let mut manager = QuotaManager::new(1000);

        let reservation = manager.reserve_quota(200).unwrap();
        assert_eq!(manager.current_usage.bytes_used, 200);
        assert_eq!(manager.current_usage.active_transfers, 1);

        manager.release_quota(reservation);
        assert_eq!(manager.current_usage.bytes_used, 0);
        assert_eq!(manager.current_usage.active_transfers, 0);
        assert_eq!(manager.current_usage.total_transfers, 1);
    }

    #[test]
    fn test_quota_utilization() {
        let mut manager = QuotaManager::new(1000);
        manager.reserve_quota(300).unwrap();

        assert_eq!(manager.get_utilization(), 30.0);
    }

    #[test]
    fn test_cleanup_logic() {
        let mut manager = QuotaManager::new(1000);
        manager.reserve_quota(900).unwrap(); // High utilization

        assert!(manager.needs_cleanup());

        let result = manager.perform_cleanup();
        assert!(result.bytes_freed > 0);
        assert!(manager.current_usage.bytes_used < 900);
    }

    #[test]
    fn cleanup_threshold_uses_exact_integer_arithmetic_for_huge_limits() {
        let policy = QuotaPolicy {
            max_bytes: u64::MAX,
            max_active_transfers: 10,
            ..Default::default()
        };
        let mut manager = QuotaManager::with_policy(policy);
        let below_or_equal_threshold = percent_floor_u64(u64::MAX, CLEANUP_TARGET_PERCENT);
        manager.current_usage.bytes_used = below_or_equal_threshold;
        assert!(!manager.needs_cleanup());

        manager.current_usage.bytes_used = below_or_equal_threshold + 1;
        assert!(manager.needs_cleanup());
    }

    #[test]
    fn release_quota_saturates_historical_transfer_counter() {
        let mut manager = QuotaManager::new(1000);
        manager.current_usage.total_transfers = u64::MAX;
        let reservation = manager.reserve_quota(1).unwrap();

        manager.release_quota(reservation);

        assert_eq!(manager.current_usage.total_transfers, u64::MAX);
        assert_eq!(manager.current_usage.bytes_used, 0);
        assert_eq!(manager.current_usage.active_transfers, 0);
    }
