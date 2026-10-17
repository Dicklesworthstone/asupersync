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
    fn test_resource_state_transitions() {
        use ResourceState::*;

        // Valid transitions
        assert!(Allocated.can_transition_to(Active));
        assert!(Allocated.can_transition_to(Cleaned));
        assert!(Active.can_transition_to(Cleaning));
        assert!(Active.can_transition_to(Cleaned));
        assert!(Cleaning.can_transition_to(Cleaned));
        assert!(Cleaned.can_transition_to(Cleaned));
        assert!(Active.can_transition_to(Leaked));
        assert!(Allocated.can_transition_to(Leaked));
        assert!(Cleaning.can_transition_to(Leaked));

        // Invalid transitions
        assert!(!Cleaned.can_transition_to(Active));
        assert!(!Leaked.can_transition_to(Cleaned));
        assert!(!Allocated.can_transition_to(Cleaning));
    }

    #[test]
    fn test_resource_record_lifecycle() -> Result<(), ResourceCleanupError> {
        let region_id = RegionId::new_ephemeral();
        let task_id = TaskId::new_ephemeral();

        let mut record =
            ResourceRecord::new(ResourceType::FileDescriptor, Some(region_id), Some(task_id));

        assert_eq!(record.state, ResourceState::Allocated);

        // Activate resource
        record.activate(region_id)?;
        assert_eq!(record.state, ResourceState::Active);
        assert_eq!(record.owner_region, Some(region_id));

        // Begin cleanup
        record.begin_cleanup()?;
        assert_eq!(record.state, ResourceState::Cleaning);

        // Complete cleanup
        record.complete_cleanup()?;
        assert_eq!(record.state, ResourceState::Cleaned);
        Ok(())
    }

    #[test]
    fn test_resource_cleanup_verifier() -> Result<(), ResourceCleanupError> {
        let config = ResourceCleanupConfig::default();
        let verifier = ResourceCleanupVerifier::new(config);

        // Start verification
        verifier.start()?;
        assert!(verifier.is_active());

        let region_id = RegionId::new_ephemeral();

        // Track resource allocation
        let resource_id =
            verifier.track_allocation(ResourceType::FileDescriptor, Some(region_id), None)?;

        // Verify region has the resource
        let region_resources = verifier.get_region_resources(region_id);
        assert_eq!(region_resources.len(), 1);
        assert_eq!(region_resources[0].id, resource_id);

        // Clean up the resource
        verifier.track_cleanup(resource_id)?;

        // Verify region cleanup
        verifier.verify_region_cleanup(region_id)?;

        let stats = verifier.get_stats();
        assert_eq!(stats.total_allocated, 1);
        assert_eq!(stats.total_cleaned, 1);
        assert_eq!(stats.total_leaked, 0);
        assert_eq!(stats.clean_region_closes, 1);
        Ok(())
    }

    #[test]
    fn filtered_resource_cleanup_is_a_noop() -> Result<(), ResourceCleanupError> {
        let mut tracked_resource_types = HashSet::new();
        tracked_resource_types.insert(ResourceType::FileDescriptor);
        let config = ResourceCleanupConfig {
            tracked_resource_types,
            ..Default::default()
        };
        let verifier = ResourceCleanupVerifier::new(config);
        verifier.start()?;

        let region_id = RegionId::new_ephemeral();
        let resource_id = verifier.track_allocation(ResourceType::Timer, Some(region_id), None)?;

        assert!(!resource_id.is_tracked());
        assert!(verifier.get_region_resources(region_id).is_empty());
        verifier.track_cleanup(resource_id)?;

        let stats = verifier.get_stats();
        assert_eq!(stats.total_allocated, 0);
        assert_eq!(stats.total_cleaned, 0);
        assert_eq!(stats.currently_tracked, 0);
        Ok(())
    }

    #[test]
    fn duplicate_cleanup_does_not_corrupt_statistics() -> Result<(), ResourceCleanupError> {
        let verifier = ResourceCleanupVerifier::new(ResourceCleanupConfig::default());
        verifier.start()?;

        let region_id = RegionId::new_ephemeral();
        let resource_id =
            verifier.track_allocation(ResourceType::FileDescriptor, Some(region_id), None)?;

        verifier.track_cleanup(resource_id)?;
        verifier.track_cleanup(resource_id)?;

        let stats = verifier.get_stats();
        assert_eq!(stats.total_allocated, 1);
        assert_eq!(stats.total_cleaned, 1);
        assert_eq!(stats.currently_tracked, 0);
        Ok(())
    }

    #[test]
    fn evicting_cleaned_resource_removes_region_index() -> Result<(), ResourceCleanupError> {
        let config = ResourceCleanupConfig {
            max_tracked_resources: 1,
            ..Default::default()
        };
        let verifier = ResourceCleanupVerifier::new(config);
        verifier.start()?;

        let first_region = RegionId::new_ephemeral();
        let first_resource =
            verifier.track_allocation(ResourceType::HeapAllocation, Some(first_region), None)?;
        verifier.track_cleanup(first_resource)?;

        let second_region = RegionId::new_ephemeral();
        let _second_resource =
            verifier.track_allocation(ResourceType::FileDescriptor, Some(second_region), None)?;

        assert!(
            verifier.get_region_resources(first_region).is_empty(),
            "evicted cleaned resources must not leave stale region ownership entries",
        );
        assert_eq!(verifier.get_region_resources(second_region).len(), 1);
        Ok(())
    }

    #[test]
    fn test_resource_leak_detection() -> Result<(), ResourceCleanupError> {
        let config = ResourceCleanupConfig {
            panic_on_leaks: false, // Don't panic in tests
            ..Default::default()
        };
        let verifier = ResourceCleanupVerifier::new(config);

        verifier.start()?;

        let region_id = RegionId::new_ephemeral();

        // Allocate resource but don't clean it up
        let _resource_id =
            verifier.track_allocation(ResourceType::FileDescriptor, Some(region_id), None)?;

        // Try to close region without cleaning up resource
        let result = verifier.verify_region_cleanup(region_id);
        assert!(matches!(
            result,
            Err(ResourceCleanupError::ResourceLeak { .. })
        ));
        let Err(ResourceCleanupError::ResourceLeak {
            region_id: leaked_region,
            leak_count,
            resource_types,
        }) = result
        else {
            return Ok(());
        };

        assert_eq!(leaked_region, region_id);
        assert_eq!(leak_count, 1);
        assert!(resource_types.contains(&ResourceType::FileDescriptor));

        let stats = verifier.get_stats();
        assert_eq!(stats.total_leaked, 1);
        assert_eq!(stats.leaked_region_closes, 1);
        Ok(())
    }

    #[test]
    fn test_pending_cleanup_does_not_close_region_mapping() -> Result<(), ResourceCleanupError> {
        let config = ResourceCleanupConfig {
            panic_on_leaks: false,
            cleanup_grace_period_ms: 60_000,
            ..Default::default()
        };
        let verifier = ResourceCleanupVerifier::new(config);
        verifier.start()?;

        let region_id = RegionId::new_ephemeral();
        let resource_id =
            verifier.track_allocation(ResourceType::NetworkConnection, Some(region_id), None)?;

        {
            let mut resources = verifier.resources.write();
            let Some(record) = resources.get_mut(&resource_id) else {
                return Err(ResourceCleanupError::AttributionFailed { resource_id });
            };
            record.begin_cleanup()?;
        }

        let result = verifier.verify_region_cleanup(region_id);
        assert!(matches!(
            result,
            Err(ResourceCleanupError::CleanupPending {
                pending_count: 1,
                ..
            })
        ));

        assert_eq!(
            verifier.get_region_resources(region_id).len(),
            1,
            "pending cleanup must remain attributed for a later recheck"
        );

        verifier.track_cleanup(resource_id)?;
        verifier.verify_region_cleanup(region_id)?;
        assert!(verifier.get_region_resources(region_id).is_empty());
        Ok(())
    }

    #[test]
    fn pending_cleanup_tolerates_system_clock_skew() -> Result<(), ResourceCleanupError> {
        let config = ResourceCleanupConfig {
            panic_on_leaks: false,
            cleanup_grace_period_ms: 10,
            ..Default::default()
        };
        let verifier = ResourceCleanupVerifier::new(config);
        verifier.start()?;

        let region_id = RegionId::new_ephemeral();
        let resource_id =
            verifier.track_allocation(ResourceType::NetworkConnection, Some(region_id), None)?;

        {
            let mut resources = verifier.resources.write();
            let Some(record) = resources.get_mut(&resource_id) else {
                return Err(ResourceCleanupError::AttributionFailed { resource_id });
            };
            record.begin_cleanup()?;
            record.last_updated = SystemTime::now() + Duration::from_secs(60);
        }

        let result = verifier.verify_region_cleanup(region_id);
        assert!(matches!(
            result,
            Err(ResourceCleanupError::CleanupPending {
                pending_count: 1,
                ..
            })
        ));

        let stats = verifier.get_stats();
        assert_eq!(stats.total_leaked, 0);
        assert_eq!(stats.leaked_region_closes, 0);
        assert_eq!(verifier.get_region_resources(region_id).len(), 1);
        Ok(())
    }
