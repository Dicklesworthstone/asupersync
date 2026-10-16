    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    // =========================================================================
    // State Predicate Tests
    // =========================================================================

    #[test]
    fn initializing_predicates() {
        let state = DistributedRegionState::Initializing;
        assert!(!state.can_spawn());
        assert!(!state.is_terminal());
        assert!(!state.is_unhealthy());
        assert!(!state.can_read());
        assert!(!state.can_write());
    }

    #[test]
    fn active_predicates() {
        let state = DistributedRegionState::Active;
        assert!(state.can_spawn());
        assert!(!state.is_terminal());
        assert!(!state.is_unhealthy());
        assert!(state.can_read());
        assert!(state.can_write());
    }

    #[test]
    fn degraded_predicates() {
        let state = DistributedRegionState::Degraded;
        assert!(!state.can_spawn());
    }

    // =========================================================================
    // Partition Tolerance Tests
    // =========================================================================

    #[test]
    fn test_partition_detection() {
        let node_id = NodeId::new("test-node");
        let config = DistributedRegionConfig {
            min_quorum: 2,
            replication_factor: 3,
            replica_timeout: Duration::from_secs(10),
            ..Default::default()
        };

        let mut record = DistributedRegionRecord::new(
            RegionId::new_for_test(1, 0),
            config,
            None,
            Budget::new(),
            node_id.clone(),
        );

        // Add replicas
        record
            .add_replica(ReplicaInfo::new("replica1", "addr1"))
            .unwrap();
        record
            .add_replica(ReplicaInfo::new("replica2", "addr2"))
            .unwrap();

        let now = Time::from_secs(100);

        // Simulate heartbeat timeout
        let _transitions = record.detect_partition(now).unwrap();

        // Should detect suspects
        let suspect_count = record
            .replicas
            .iter()
            .filter(|r| r.status == ReplicaStatus::Suspect)
            .count();

        assert!(suspect_count > 0);
    }

    #[test]
    fn test_split_brain_detection() {
        let node_id = NodeId::new("test-node");
        let mut record = DistributedRegionRecord::new(
            RegionId::new_for_test(1, 0),
            DistributedRegionConfig::default(),
            None,
            Budget::new(),
            node_id,
        );

        // Activate with quorum
        record
            .add_replica(ReplicaInfo::new("replica1", "addr1"))
            .unwrap();
        record
            .add_replica(ReplicaInfo::new("replica2", "addr2"))
            .unwrap();

        let now = Time::from_secs(100);
        record.activate(now).unwrap();

        // Create a concurrent vector clock (simulating another partition)
        let other_node = NodeId::new("other-node");
        let mut other_clock = VectorClock::new();
        other_clock.increment(&other_node);
        other_clock.increment(&other_node);

        let other_clocks = vec![other_clock];

        // Should detect split-brain with concurrent clocks
        assert!(record.detect_split_brain(&other_clocks));
    }

    #[test]
    fn test_vector_clock_conflict_resolution() {
        let node_id = NodeId::new("local-node");
        let mut record = DistributedRegionRecord::new(
            RegionId::new_for_test(1, 0),
            DistributedRegionConfig::default(),
            None,
            Budget::new(),
            node_id.clone(),
        );

        // Create a remote vector clock that happened after local
        let remote_node = NodeId::new("remote-node");
        let mut remote_clock = record.vector_clock().clone();
        remote_clock.increment(&remote_node);
        remote_clock.increment(&remote_node);

        let now = Time::from_secs(100);
        let result = record.resolve_conflict(&remote_clock, 10, 5, now).unwrap();

        // Remote clock happened after, so should accept remote
        assert_eq!(result, ConflictResolutionResult::AcceptRemote);
    }

    #[test]
    fn recovering_predicates() {
        let state = DistributedRegionState::Recovering;
        assert!(!state.can_spawn());
        assert!(!state.is_terminal());
        assert!(state.is_unhealthy());
        assert!(state.can_read());
        assert!(!state.can_write());
    }

    #[test]
    fn closed_is_terminal() {
        let state = DistributedRegionState::Closed;
        assert!(state.is_terminal());
        assert!(!state.can_spawn());
        assert!(!state.can_read());
        assert!(!state.can_write());
    }

    // =========================================================================
    // Transition Validity Tests
    // =========================================================================

    #[test]
    fn initializing_valid_transitions() {
        let state = DistributedRegionState::Initializing;
        assert!(state.can_transition_to(DistributedRegionState::Active));
        assert!(state.can_transition_to(DistributedRegionState::Degraded));
        assert!(state.can_transition_to(DistributedRegionState::Closing));
        assert!(!state.can_transition_to(DistributedRegionState::Recovering));
        assert!(!state.can_transition_to(DistributedRegionState::Closed));
    }

    #[test]
    fn active_valid_transitions() {
        let state = DistributedRegionState::Active;
        assert!(state.can_transition_to(DistributedRegionState::Degraded));
        assert!(state.can_transition_to(DistributedRegionState::Closing));
        assert!(!state.can_transition_to(DistributedRegionState::Initializing));
        assert!(!state.can_transition_to(DistributedRegionState::Recovering));
    }

    #[test]
    fn degraded_valid_transitions() {
        let state = DistributedRegionState::Degraded;
        assert!(state.can_transition_to(DistributedRegionState::Recovering));
        assert!(state.can_transition_to(DistributedRegionState::Closing));
        assert!(!state.can_transition_to(DistributedRegionState::Active));
    }

    #[test]
    fn recovering_valid_transitions() {
        let state = DistributedRegionState::Recovering;
        assert!(state.can_transition_to(DistributedRegionState::Active));
        assert!(state.can_transition_to(DistributedRegionState::Closing));
        assert!(!state.can_transition_to(DistributedRegionState::Degraded));
    }

    #[test]
    fn closed_no_transitions() {
        let state = DistributedRegionState::Closed;
        assert!(state.allowed_transitions().is_empty());
        assert!(!state.can_transition_to(DistributedRegionState::Initializing));
        assert!(!state.can_transition_to(DistributedRegionState::Active));
    }

    // =========================================================================
    // Region Lifecycle Tests
    // =========================================================================

    #[test]
    fn happy_path_lifecycle() {
        let config = DistributedRegionConfig::default();
        let mut region = DistributedRegionRecord::new(
            RegionId::new_ephemeral(),
            config,
            None,
            Budget::default(),
            NodeId::new("test-node"),
        );
        assert_eq!(region.state, DistributedRegionState::Initializing);

        // Add replicas to reach quorum.
        region.add_replica(ReplicaInfo::new("r1", "addr1")).unwrap();
        region.add_replica(ReplicaInfo::new("r2", "addr2")).unwrap();

        // Activate.
        let transition = region.activate(Time::from_secs(1)).unwrap();
        assert_eq!(transition.to, DistributedRegionState::Active);
        assert_eq!(region.state, DistributedRegionState::Active);

        // Close.
        let _transition = region
            .begin_close(
                TransitionReason::UserClose { reason: None },
                Time::from_secs(10),
            )
            .unwrap();
        assert_eq!(region.state, DistributedRegionState::Closing);

        // Complete close.
        let _transition = region.complete_close(Time::from_secs(11)).unwrap();
        assert_eq!(region.state, DistributedRegionState::Closed);
    }

    #[test]
    fn degraded_path() {
        let mut region = create_active_region();

        // Lose a replica below quorum.
        let transition = region.replica_lost("r2", Time::from_secs(5)).unwrap();
        assert_eq!(transition.to, DistributedRegionState::Degraded);
        assert_eq!(region.state, DistributedRegionState::Degraded);

        // Verify read-only mode.
        assert!(region.state.can_read());
        assert!(!region.state.can_write());
    }

    #[test]
    fn recovery_path() {
        let mut region = create_degraded_region();

        // Trigger recovery.
        let transition = region
            .trigger_recovery("operator", Time::from_secs(10))
            .unwrap();
        assert_eq!(transition.to, DistributedRegionState::Recovering);
        assert_eq!(region.state, DistributedRegionState::Recovering);

        region
            .update_replica_status("r2", ReplicaStatus::Healthy, Time::from_secs(14))
            .unwrap();

        // Complete recovery.
        let transition = region.complete_recovery(42, Time::from_secs(15)).unwrap();
        assert_eq!(transition.to, DistributedRegionState::Active);
        assert_eq!(region.state, DistributedRegionState::Active);
    }

    #[test]
    fn complete_recovery_requires_quorum() {
        let mut region = create_degraded_region();

        region
            .trigger_recovery("operator", Time::from_secs(10))
            .unwrap();

        let result = region.complete_recovery(42, Time::from_secs(15));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::QuorumNotReached);
        assert_eq!(region.state, DistributedRegionState::Recovering);
    }

    #[test]
    fn recovery_failure() {
        let mut region = create_degraded_region();
        region
            .trigger_recovery("operator", Time::from_secs(10))
            .unwrap();

        // Fail recovery.
        let transition = region
            .fail_recovery("insufficient symbols".to_string(), Time::from_secs(15))
            .unwrap();
        assert_eq!(transition.to, DistributedRegionState::Closing);
        assert_eq!(region.state, DistributedRegionState::Closing);
    }

    // =========================================================================
    // Error Handling Tests
    // =========================================================================

    #[test]
    fn invalid_transition_error() {
        let mut region = create_active_region();

        // Cannot go directly to Recovering from Active.
        let result = region.trigger_recovery("test", Time::from_secs(1));
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().kind(),
            ErrorKind::InvalidStateTransition
        );
    }

    #[test]
    fn activate_without_quorum_error() {
        let config = DistributedRegionConfig {
            min_quorum: 2,
            ..Default::default()
        };
        let mut region = DistributedRegionRecord::new(
            RegionId::new_ephemeral(),
            config,
            None,
            Budget::default(),
            NodeId::new("test-node"),
        );

        // Only one replica.
        region.add_replica(ReplicaInfo::new("r1", "addr1")).unwrap();

        let result = region.activate(Time::from_secs(1));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::QuorumNotReached);
    }

    #[test]
    fn close_from_any_non_terminal_state() {
        for state in [
            DistributedRegionState::Initializing,
            DistributedRegionState::Active,
            DistributedRegionState::Degraded,
            DistributedRegionState::Recovering,
        ] {
            assert!(
                state.can_transition_to(DistributedRegionState::Closing),
                "should be able to close from {state}"
            );
        }
    }

    #[test]
    fn duplicate_replica_error() {
        let mut region = create_active_region();
        let result = region.add_replica(ReplicaInfo::new("r1", "addr1"));
        assert!(result.is_err());
    }

    #[test]
    fn remove_unknown_replica_error() {
        let mut region = create_active_region();
        let result = region.remove_replica("nonexistent", Time::from_secs(7));
        assert!(result.is_err());
    }

    #[test]
    fn replica_lost_unknown_replica_error_does_not_mutate_state() {
        let mut region = create_active_region();
        let prev_state = region.state;
        let prev_healthy = region.healthy_replicas();
        let prev_transitions = region.transitions.len();

        let result = region.replica_lost("nonexistent", Time::from_secs(9));
        assert!(result.is_err());
        assert_eq!(region.state, prev_state);
        assert_eq!(region.healthy_replicas(), prev_healthy);
        assert_eq!(region.transitions.len(), prev_transitions);
    }

    // =========================================================================
    // Quorum Tests
    // =========================================================================

    #[test]
    fn quorum_calculation() {
        let config = DistributedRegionConfig {
            min_quorum: 2,
            replication_factor: 3,
            ..Default::default()
        };
        let mut region = DistributedRegionRecord::new(
            RegionId::new_ephemeral(),
            config,
            None,
            Budget::default(),
            NodeId::new("test-node"),
        );

        assert_eq!(region.current_quorum(), 0);
        assert!(!region.has_quorum());

        region.add_replica(ReplicaInfo::new("r1", "addr1")).unwrap();
        assert_eq!(region.current_quorum(), 1);
        assert!(!region.has_quorum());

        region.add_replica(ReplicaInfo::new("r2", "addr2")).unwrap();
        assert_eq!(region.current_quorum(), 2);
        assert!(region.has_quorum());
    }

    #[test]
    fn replica_status_update() {
        let mut region = create_active_region();

        region
            .update_replica_status("r1", ReplicaStatus::Suspect, Time::from_secs(3))
            .unwrap();

        let r1 = region.replicas.iter().find(|r| r.id == "r1").unwrap();
        assert_eq!(r1.status, ReplicaStatus::Suspect);
        assert_eq!(region.state, DistributedRegionState::Degraded);
    }

    #[test]
    fn quorum_loss_closes_when_degraded_mode_disabled() {
        let config = DistributedRegionConfig {
            min_quorum: 2,
            replication_factor: 3,
            allow_degraded: false,
            ..Default::default()
        };
        let mut region = DistributedRegionRecord::new(
            RegionId::new_ephemeral(),
            config,
            None,
            Budget::default(),
            NodeId::new("test-node"),
        );

        region.add_replica(ReplicaInfo::new("r1", "addr1")).unwrap();
        region.add_replica(ReplicaInfo::new("r2", "addr2")).unwrap();
        region.add_replica(ReplicaInfo::new("r3", "addr3")).unwrap();
        region.activate(Time::from_secs(0)).unwrap();

        let first_loss = region.replica_lost("r1", Time::from_secs(5));
        assert!(first_loss.is_err());
        assert_eq!(region.state, DistributedRegionState::Active);

        let transition = region.replica_lost("r2", Time::from_secs(6)).unwrap();
        assert_eq!(transition.to, DistributedRegionState::Closing);
        assert_eq!(
            transition.reason,
            TransitionReason::QuorumLost {
                remaining: 1,
                required: 2,
            }
        );
        assert_eq!(region.state, DistributedRegionState::Closing);
    }

    #[test]
    fn active_region_closes_when_last_available_replica_is_lost() {
        let config = DistributedRegionConfig {
            min_quorum: 1,
            replication_factor: 1,
            allow_degraded: true,
            ..Default::default()
        };
        let mut region = DistributedRegionRecord::new(
            RegionId::new_ephemeral(),
            config,
            None,
            Budget::default(),
            NodeId::new("test-node"),
        );
        region.add_replica(ReplicaInfo::new("r1", "addr1")).unwrap();
        region.activate(Time::from_secs(0)).unwrap();

        let transition = region.replica_lost("r1", Time::from_secs(1)).unwrap();
        assert_eq!(transition.to, DistributedRegionState::Closing);
        assert_eq!(
            transition.reason,
            TransitionReason::QuorumLost {
                remaining: 0,
                required: 1,
            }
        );
        assert_eq!(region.state, DistributedRegionState::Closing);
    }

    #[test]
    fn degraded_region_closes_when_last_available_replica_is_lost() {
        let mut region = create_degraded_region();

        let transition = region.replica_lost("r1", Time::from_secs(6)).unwrap();
        assert_eq!(transition.to, DistributedRegionState::Closing);
        assert_eq!(
            transition.reason,
            TransitionReason::QuorumLost {
                remaining: 0,
                required: 2,
            }
        );
        assert_eq!(region.state, DistributedRegionState::Closing);
    }

    #[test]
    fn recovering_region_closes_when_last_available_replica_becomes_unavailable() {
        let mut region = create_degraded_region();
        region
            .trigger_recovery("operator", Time::from_secs(10))
            .unwrap();

        region
            .update_replica_status("r1", ReplicaStatus::Unavailable, Time::from_secs(11))
            .unwrap();

        let transition = region.transitions.back().expect("closing transition");
        assert_eq!(transition.to, DistributedRegionState::Closing);
        assert_eq!(
            transition.reason,
            TransitionReason::QuorumLost {
                remaining: 0,
                required: 2,
            }
        );
        assert_eq!(region.state, DistributedRegionState::Closing);
    }

    #[test]
    fn closing_region_rejects_replica_mutations() {
        let mut region = create_active_region();
        region
            .begin_close(
                TransitionReason::UserClose { reason: None },
                Time::from_secs(10),
            )
            .unwrap();

        let add_err = region
            .add_replica(ReplicaInfo::new("r3", "addr3"))
            .unwrap_err();
        assert_eq!(add_err.kind(), ErrorKind::InvalidStateTransition);

        let update_err = region
            .update_replica_status("r1", ReplicaStatus::Suspect, Time::from_secs(12))
            .unwrap_err();
        assert_eq!(update_err.kind(), ErrorKind::InvalidStateTransition);

        let remove_err = region
            .remove_replica("r1", Time::from_secs(13))
            .unwrap_err();
        assert_eq!(remove_err.kind(), ErrorKind::InvalidStateTransition);

        let lost_err = region.replica_lost("r1", Time::from_secs(14)).unwrap_err();
        assert_eq!(lost_err.kind(), ErrorKind::InvalidStateTransition);
    }

    #[test]
    fn remove_replica() {
        let mut region = create_active_region();
        let removed = region.remove_replica("r2", Time::from_secs(6)).unwrap();
        assert_eq!(removed.id, "r2");
        assert_eq!(region.replicas.len(), 1);
        assert_eq!(region.state, DistributedRegionState::Degraded);
    }

    #[test]
    fn remove_replica_closes_when_degraded_mode_disabled() {
        let config = DistributedRegionConfig {
            min_quorum: 2,
            replication_factor: 3,
            allow_degraded: false,
            ..Default::default()
        };
        let mut region = DistributedRegionRecord::new(
            RegionId::new_ephemeral(),
            config,
            None,
            Budget::default(),
            NodeId::new("test-node"),
        );
        region.add_replica(ReplicaInfo::new("r1", "addr1")).unwrap();
        region.add_replica(ReplicaInfo::new("r2", "addr2")).unwrap();
        region.activate(Time::from_secs(0)).unwrap();

        let removed = region.remove_replica("r2", Time::from_secs(6)).unwrap();
        assert_eq!(removed.id, "r2");
        assert_eq!(region.state, DistributedRegionState::Closing);
    }

    #[test]
    fn closed_region_rejects_replica_mutations() {
        let mut region = create_active_region();
        region
            .begin_close(
                TransitionReason::UserClose { reason: None },
                Time::from_secs(10),
            )
            .unwrap();
        region.complete_close(Time::from_secs(11)).unwrap();

        let add_err = region
            .add_replica(ReplicaInfo::new("r3", "addr3"))
            .unwrap_err();
        assert_eq!(add_err.kind(), ErrorKind::InvalidStateTransition);

        let update_err = region
            .update_replica_status("r1", ReplicaStatus::Suspect, Time::from_secs(12))
            .unwrap_err();
        assert_eq!(update_err.kind(), ErrorKind::InvalidStateTransition);

        let remove_err = region
            .remove_replica("r1", Time::from_secs(13))
            .unwrap_err();
        assert_eq!(remove_err.kind(), ErrorKind::InvalidStateTransition);

        let lost_err = region.replica_lost("r1", Time::from_secs(14)).unwrap_err();
        assert_eq!(lost_err.kind(), ErrorKind::InvalidStateTransition);
    }

    // =========================================================================
    // Display/Debug Tests
    // =========================================================================

    #[test]
    fn state_display() {
        assert_eq!(
            format!("{}", DistributedRegionState::Initializing),
            "initializing"
        );
        assert_eq!(format!("{}", DistributedRegionState::Active), "active");
        assert_eq!(format!("{}", DistributedRegionState::Degraded), "degraded");
        assert_eq!(
            format!("{}", DistributedRegionState::Recovering),
            "recovering"
        );
        assert_eq!(format!("{}", DistributedRegionState::Closing), "closing");
        assert_eq!(format!("{}", DistributedRegionState::Closed), "closed");
    }

    #[test]
    fn transition_history_bounded() {
        let mut region = create_active_region();

        // Close and reopen repeatedly to build up transitions.
        // We already have 1 transition from activate. Add more via begin_close + complete_close
        // cycles. Since we can't reopen, just verify history is bounded after many closes.
        for _ in 0..MAX_TRANSITION_HISTORY + 10 {
            // Reset state to test history bounding (artificially).
            region.state = DistributedRegionState::Initializing;
            let _ = region.activate(Time::from_secs(1));
        }

        assert!(region.transitions.len() <= MAX_TRANSITION_HISTORY);
    }

    #[test]
    fn config_default() {
        let config = DistributedRegionConfig::default();
        assert_eq!(config.min_quorum, 2);
        assert_eq!(config.replication_factor, 3);
        assert!(config.allow_degraded);
        assert_eq!(config.read_consistency, ConsistencyLevel::One);
        assert_eq!(config.write_consistency, ConsistencyLevel::Quorum);
    }

    #[test]
    #[should_panic(expected = "replication_factor >= 1")]
    fn distributed_region_new_rejects_zero_replication_factor() {
        let config = DistributedRegionConfig {
            min_quorum: 1,
            replication_factor: 0,
            ..Default::default()
        };

        let _ = DistributedRegionRecord::new(
            RegionId::new_ephemeral(),
            config,
            None,
            Budget::default(),
            NodeId::new("test-node"),
        );
    }

    #[test]
    #[should_panic(expected = "min_quorum in 1..=replication_factor")]
    fn distributed_region_new_rejects_zero_quorum() {
        let config = DistributedRegionConfig {
            min_quorum: 0,
            replication_factor: 1,
            ..Default::default()
        };

        let _ = DistributedRegionRecord::new(
            RegionId::new_ephemeral(),
            config,
            None,
            Budget::default(),
            NodeId::new("test-node"),
        );
    }

    #[test]
    #[should_panic(expected = "min_quorum in 1..=replication_factor")]
    fn distributed_region_new_rejects_quorum_above_replication_factor() {
        let config = DistributedRegionConfig {
            min_quorum: 3,
            replication_factor: 2,
            ..Default::default()
        };

        let _ = DistributedRegionRecord::new(
            RegionId::new_ephemeral(),
            config,
            None,
            Budget::default(),
            NodeId::new("test-node"),
        );
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    fn create_active_region() -> DistributedRegionRecord {
        let config = DistributedRegionConfig::default();
        let mut region = DistributedRegionRecord::new(
            RegionId::new_ephemeral(),
            config,
            None,
            Budget::default(),
            NodeId::new("test-node"),
        );
        region.add_replica(ReplicaInfo::new("r1", "addr1")).unwrap();
        region.add_replica(ReplicaInfo::new("r2", "addr2")).unwrap();
        region.activate(Time::from_secs(0)).unwrap();
        region
    }

    fn create_degraded_region() -> DistributedRegionRecord {
        let mut region = create_active_region();
        region.replica_lost("r2", Time::from_secs(5)).unwrap();
        region
    }

    #[test]
    fn distributed_region_state_debug_clone_copy_hash_eq() {
        use std::collections::HashSet;
        let s = DistributedRegionState::Active;
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Active"), "{dbg}");
        let copied: DistributedRegionState = s;
        let cloned = s;
        assert_eq!(copied, cloned);
        assert_ne!(s, DistributedRegionState::Closed);

        let mut set = HashSet::new();
        set.insert(DistributedRegionState::Initializing);
        set.insert(DistributedRegionState::Active);
        set.insert(DistributedRegionState::Degraded);
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn consistency_level_debug_clone_copy_eq() {
        let c = ConsistencyLevel::Quorum;
        let dbg = format!("{c:?}");
        assert!(dbg.contains("Quorum"), "{dbg}");
        let copied: ConsistencyLevel = c;
        let cloned = c;
        assert_eq!(copied, cloned);
        assert_ne!(c, ConsistencyLevel::All);
    }

    #[test]
    fn distributed_region_config_debug_clone_default() {
        let c = DistributedRegionConfig::default();
        let dbg = format!("{c:?}");
        assert!(dbg.contains("DistributedRegionConfig"), "{dbg}");
        assert_eq!(c.min_quorum, 2);
        let cloned = c;
        assert_eq!(format!("{cloned:?}"), dbg);
    }

    #[test]
    fn replica_status_debug_clone_copy_eq() {
        let s = ReplicaStatus::Healthy;
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Healthy"), "{dbg}");
        let copied: ReplicaStatus = s;
        let cloned = s;
        assert_eq!(copied, cloned);
        assert_ne!(s, ReplicaStatus::Unavailable);
    }
