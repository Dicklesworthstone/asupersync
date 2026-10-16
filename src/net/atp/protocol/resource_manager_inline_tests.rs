    use super::*;

    #[test]
    fn test_memory_allocation_limits() {
        let mut manager = ResourceManager::new();
        let peer_id = PeerId::from_label("test-peer");

        // Should allow allocation within limit
        assert!(manager.allocate_memory(peer_id, 1000));
        assert_eq!(manager.peer_memory_usage(&peer_id), 1000);

        // Should allow more allocation up to limit
        let limit = manager.limits().max_memory_per_peer;
        assert!(manager.allocate_memory(peer_id, limit - 1500));

        // Should reject allocation that exceeds limit
        assert!(!manager.allocate_memory(peer_id, 1000));

        // Should allow deallocation
        manager.deallocate_memory(&peer_id, 500);
        assert_eq!(manager.peer_memory_usage(&peer_id), limit - 1000);
    }

    #[test]
    fn test_memory_accounting_rejects_u64_overflow() {
        let limits = ResourceLimits {
            max_memory_per_peer: u64::MAX,
            ..ResourceLimits::default()
        };
        let mut manager = ResourceManager::with_limits(limits);
        let peer_id = PeerId::from_label("overflow-peer");

        assert!(manager.allocate_memory(peer_id, u64::MAX - 1));
        assert!(!manager.can_allocate_memory(&peer_id, 2));
        assert!(!manager.allocate_memory(peer_id, 2));
        assert_eq!(manager.peer_memory_usage(&peer_id), u64::MAX - 1);
    }

    #[test]
    fn test_peer_usage_returns_public_snapshot() {
        let mut manager = ResourceManager::new();
        let peer_id = PeerId::from_label("snapshot-peer");

        assert!(manager.allocate_memory(peer_id, 4096));
        assert!(manager.record_frame(peer_id));
        assert!(manager.start_session(peer_id));
        assert!(manager.request_object(peer_id));

        let usage = manager
            .peer_usage(&peer_id)
            .expect("peer should be tracked");
        assert_eq!(usage.memory_usage, 4096);
        assert_eq!(usage.pending_frames, 1);
        assert_eq!(usage.recent_frame_count, 1);
        assert_eq!(usage.active_sessions, 1);
        assert_eq!(usage.pending_requests, 1);
    }

    #[test]
    fn test_frame_rate_limiting() {
        let limits = ResourceLimits {
            max_frame_rate: 2,
            rate_limit_window: 1,
            ..ResourceLimits::default()
        };
        let mut manager = ResourceManager::with_limits(limits);
        let peer_id = PeerId::from_label("test-peer");

        // Should allow frames within rate limit
        assert!(manager.record_frame(peer_id));
        assert!(manager.record_frame(peer_id));

        // Should reject frames exceeding rate limit
        assert!(!manager.record_frame(peer_id));

        // Marking frames as processed relieves pending-frame pressure, but it
        // must not erase the rate-limit history inside the active time window.
        manager.frame_processed(&peer_id);
        manager.frame_processed(&peer_id);
        assert!(!manager.record_frame(peer_id));
    }

    #[test]
    fn test_pending_frame_limit_recovers_after_processing() {
        let limits = ResourceLimits {
            max_frames_per_peer: 2,
            max_frame_rate: 100,
            ..ResourceLimits::default()
        };
        let mut manager = ResourceManager::with_limits(limits);
        let peer_id = PeerId::from_label("pending-frame-peer");

        assert!(manager.record_frame(peer_id));
        assert!(manager.record_frame(peer_id));
        assert!(!manager.record_frame(peer_id));

        manager.frame_processed(&peer_id);
        assert!(manager.record_frame(peer_id));
    }

    #[test]
    fn test_session_limits() {
        let limits = ResourceLimits {
            max_sessions_per_peer: 2,
            ..ResourceLimits::default()
        };
        let mut manager = ResourceManager::with_limits(limits);
        let peer_id = PeerId::from_label("test-peer");

        // Should allow sessions within limit
        assert!(manager.start_session(peer_id));
        assert!(manager.start_session(peer_id));

        // Should reject sessions exceeding limit
        assert!(!manager.start_session(peer_id));

        // Should allow new session after ending one
        manager.end_session(&peer_id);
        assert!(manager.start_session(peer_id));
    }

    #[test]
    fn test_object_request_limits() {
        let limits = ResourceLimits {
            max_pending_requests: 3,
            ..ResourceLimits::default()
        };
        let mut manager = ResourceManager::with_limits(limits);
        let peer_id = PeerId::from_label("test-peer");

        // Should allow requests within limit
        assert!(manager.request_object(peer_id));
        assert!(manager.request_object(peer_id));
        assert!(manager.request_object(peer_id));

        // Should reject requests exceeding limit
        assert!(!manager.request_object(peer_id));

        // Should allow new request after completing one
        manager.complete_request(&peer_id);
        assert!(manager.request_object(peer_id));
    }

    #[test]
    fn test_manifest_size_validation() {
        let limits = ResourceLimits {
            max_manifest_size: 1024,
            ..ResourceLimits::default()
        };
        let manager = ResourceManager::with_limits(limits);

        assert!(manager.validate_manifest_size(512));
        assert!(manager.validate_manifest_size(1024));
        assert!(!manager.validate_manifest_size(1025));
    }

    #[test]
    fn test_cleanup_inactive_peers() {
        let mut manager = ResourceManager::new();
        let peer_id = PeerId::from_label("test-peer");

        // Allocate some resources
        assert!(manager.allocate_memory(peer_id, 1000));
        assert_eq!(manager.peer_count(), 1);

        // Should not cleanup peer with active resources
        manager.cleanup_inactive_peers(Duration::from_secs(0));
        assert_eq!(manager.peer_count(), 1);

        // Should cleanup peer after freeing resources and time passing
        manager.deallocate_memory(&peer_id, 1000);
        manager.cleanup_inactive_peers(Duration::from_secs(0));
        assert_eq!(manager.peer_count(), 0);
    }

    #[test]
    fn test_cleanup_respects_inactivity_timeout() {
        let mut manager = ResourceManager::new();
        let peer_id = PeerId::from_label("recent-peer");

        assert!(manager.allocate_memory(peer_id, 1000));
        manager.deallocate_memory(&peer_id, 1000);

        manager.cleanup_inactive_peers(Duration::from_secs(300));
        assert_eq!(manager.peer_count(), 1);

        manager.cleanup_inactive_peers(Duration::from_secs(0));
        assert_eq!(manager.peer_count(), 0);
    }

    #[test]
    fn test_cleanup_preserves_recent_rate_limit_history() {
        let limits = ResourceLimits {
            max_frame_rate: 1,
            rate_limit_window: 60,
            ..ResourceLimits::default()
        };
        let mut manager = ResourceManager::with_limits(limits);
        let peer_id = PeerId::from_label("rate-history-peer");

        assert!(manager.record_frame(peer_id));
        manager.frame_processed(&peer_id);
        assert_eq!(manager.peer_pending_frames(&peer_id), 0);

        manager.cleanup_inactive_peers(Duration::from_secs(0));
        assert_eq!(manager.peer_count(), 1);
        assert!(!manager.record_frame(peer_id));
    }

    #[test]
    fn test_resource_pressure_detection() {
        let mut manager = ResourceManager::new();

        // Should not be under pressure initially
        assert!(!manager.is_under_pressure());

        // Create many peers to trigger pressure detection
        for i in 0..1001 {
            let peer_id = PeerId::from_label(&format!("peer-{}", i));
            manager.allocate_memory(peer_id, 1);
        }

        assert!(manager.is_under_pressure());
    }
