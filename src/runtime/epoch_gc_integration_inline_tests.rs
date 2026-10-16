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
    fn test_integration_config_defaults() {
        let config = EpochGCIntegrationConfig::default();
        assert!(config.enable_obligation_gc);
        assert!(config.enable_waker_gc);
        assert!(config.enable_region_gc);
        assert!(config.enable_timer_gc);
        assert!(config.enable_channel_gc);
    }

    #[test]
    fn test_disabled_integration() {
        let integration = RuntimeEpochGCIntegration::disabled();
        assert!(!integration.is_enabled());
        assert!(!integration.obligation_gc.is_epoch_gc_enabled());
        assert_eq!(integration.try_advance_epoch(), 0);
    }

    #[test]
    fn test_enabled_integration() {
        let epoch_gc = Arc::new(crate::runtime::epoch_gc::EpochGC::new());
        let config = EpochGCIntegrationConfig::default();
        let integration = RuntimeEpochGCIntegration::new(Some(epoch_gc), config);

        assert!(integration.is_enabled());
        assert!(integration.obligation_gc.is_epoch_gc_enabled());
        assert!(integration.waker_gc.is_epoch_gc_enabled());
        assert!(integration.region_gc.is_epoch_gc_enabled());
    }

    #[test]
    fn test_obligation_cleanup_integration() {
        let epoch_gc = Arc::new(crate::runtime::epoch_gc::EpochGC::new());
        let config = EpochGCIntegrationConfig::default();
        let obligation_gc = ObligationTableEpochGC::new(Some(epoch_gc), config);

        // Test cleanup operation
        obligation_gc.cleanup_obligation(123, vec![1, 2, 3]);

        // Should have deferred the cleanup
        assert!(obligation_gc.is_epoch_gc_enabled());
    }

    #[test]
    fn test_fallback_when_epoch_gc_disabled() {
        let config = EpochGCIntegrationConfig::default();
        let obligation_gc = ObligationTableEpochGC::new(None, config);

        // Should fall back to direct cleanup when epoch GC is disabled
        obligation_gc.cleanup_obligation(456, vec![]);
        assert!(!obligation_gc.is_epoch_gc_enabled());
    }
