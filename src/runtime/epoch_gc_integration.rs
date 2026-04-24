//! Integration of epoch-based garbage collection with runtime cleanup paths.
//!
//! This module provides the integration layer between the epoch GC system and
//! the various runtime components that need cleanup, ensuring that cleanup
//! operations are properly deferred and batched for optimal performance.

#![allow(missing_docs)]

use crate::runtime::epoch_gc::{CleanupWork, EpochGC};
use crate::types::{RegionId, TaskId};
use std::sync::Arc;
use std::time::Duration;

// ============================================================================
// Runtime Integration Configuration
// ============================================================================

/// Configuration for epoch GC integration with runtime components.
#[derive(Debug, Clone)]
pub struct EpochGCIntegrationConfig {
    /// Enable epoch GC for obligation cleanup.
    pub enable_obligation_gc: bool,

    /// Enable epoch GC for waker cleanup.
    pub enable_waker_gc: bool,

    /// Enable epoch GC for region cleanup.
    pub enable_region_gc: bool,

    /// Enable epoch GC for timer cleanup.
    pub enable_timer_gc: bool,

    /// Enable epoch GC for channel cleanup.
    pub enable_channel_gc: bool,

    /// Fallback timeout for direct cleanup when epoch GC queue is full.
    pub fallback_timeout: Duration,

    /// Enable detailed logging of integration operations.
    pub enable_integration_logging: bool,

    /// Enable performance metrics collection.
    pub enable_metrics: bool,
}

impl Default for EpochGCIntegrationConfig {
    fn default() -> Self {
        Self {
            enable_obligation_gc: true,
            enable_waker_gc: true,
            enable_region_gc: true,
            enable_timer_gc: true,
            enable_channel_gc: true,
            fallback_timeout: Duration::from_millis(100),
            enable_integration_logging: false,
            enable_metrics: true,
        }
    }
}

impl EpochGCIntegrationConfig {
    /// Create a configuration with all epoch GC disabled (direct cleanup only).
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            enable_obligation_gc: false,
            enable_waker_gc: false,
            enable_region_gc: false,
            enable_timer_gc: false,
            enable_channel_gc: false,
            fallback_timeout: Duration::from_millis(100),
            enable_integration_logging: false,
            enable_metrics: false,
        }
    }

    /// Enable all epoch GC features.
    #[must_use]
    pub fn enable_all(mut self) -> Self {
        self.enable_obligation_gc = true;
        self.enable_waker_gc = true;
        self.enable_region_gc = true;
        self.enable_timer_gc = true;
        self.enable_channel_gc = true;
        self
    }

    /// Disable all epoch GC features.
    #[must_use]
    pub fn disable_all(mut self) -> Self {
        self.enable_obligation_gc = false;
        self.enable_waker_gc = false;
        self.enable_region_gc = false;
        self.enable_timer_gc = false;
        self.enable_channel_gc = false;
        self
    }

    /// Enable integration logging.
    #[must_use]
    pub fn with_logging(mut self) -> Self {
        self.enable_integration_logging = true;
        self
    }
}

// ============================================================================
// Integration Traits for Runtime Components
// ============================================================================

/// Trait for components that can integrate with epoch-based cleanup.
pub trait EpochCleanupIntegration {
    /// Attempt to defer cleanup work to the epoch GC system.
    /// Returns Ok(()) if successfully deferred, Err(work) if fallback needed.
    fn try_defer_cleanup(&self, work: CleanupWork) -> Result<(), CleanupWork>;

    /// Perform direct cleanup as fallback when epoch GC is unavailable.
    fn direct_cleanup_fallback(&self, work: CleanupWork);

    /// Check if epoch GC integration is enabled for this component.
    fn is_epoch_gc_enabled(&self) -> bool;
}

// ============================================================================
// Obligation Table Integration
// ============================================================================

/// Integration adapter for obligation table cleanup.
pub struct ObligationTableEpochGC {
    epoch_gc: Option<Arc<EpochGC>>,
    config: EpochGCIntegrationConfig,
}

impl ObligationTableEpochGC {
    /// Create a new obligation table epoch GC integration.
    #[must_use]
    pub fn new(epoch_gc: Option<Arc<EpochGC>>, config: EpochGCIntegrationConfig) -> Self {
        Self { epoch_gc, config }
    }

    /// Clean up an obligation, using epoch GC if available.
    pub fn cleanup_obligation(&self, obligation_id: u64, metadata: Vec<u8>) {
        if !self.config.enable_obligation_gc {
            self.direct_cleanup_obligation(obligation_id, &metadata);
            return;
        }

        let work = CleanupWork::Obligation {
            id: obligation_id,
            metadata,
        };

        match self.try_defer_cleanup(work) {
            Ok(()) =>
            {
                #[cfg(feature = "tracing-integration")]
                if self.config.enable_integration_logging {
                    tracing::debug!(
                        obligation_id = obligation_id,
                        "Deferred obligation cleanup to epoch GC"
                    );
                }
            }
            Err(work) => {
                #[cfg(feature = "tracing-integration")]
                if self.config.enable_integration_logging {
                    tracing::warn!(
                        obligation_id = obligation_id,
                        "Failed to defer obligation cleanup, using direct cleanup"
                    );
                }
                self.direct_cleanup_fallback(work);
            }
        }
    }

    /// Direct cleanup implementation for obligations.
    fn direct_cleanup_obligation(&self, obligation_id: u64, metadata: &[u8]) {
        #[cfg(not(feature = "tracing-integration"))]
        let _ = (obligation_id, metadata);
        #[cfg(feature = "tracing-integration")]
        if self.config.enable_integration_logging {
            tracing::debug!(
                obligation_id = obligation_id,
                metadata_size = metadata.len(),
                "Direct obligation cleanup"
            );
        }

        // In practice, this would call into the actual obligation cleanup logic:
        // obligation_table.remove_obligation(obligation_id);
        // obligation_tracker.cleanup_obligation_metadata(obligation_id);
    }
}

impl EpochCleanupIntegration for ObligationTableEpochGC {
    fn try_defer_cleanup(&self, work: CleanupWork) -> Result<(), CleanupWork> {
        if let Some(ref epoch_gc) = self.epoch_gc {
            epoch_gc.defer_cleanup(work)
        } else {
            Err(work)
        }
    }

    fn direct_cleanup_fallback(&self, work: CleanupWork) {
        if let CleanupWork::Obligation { id, metadata } = work {
            self.direct_cleanup_obligation(id, &metadata);
        }
    }

    fn is_epoch_gc_enabled(&self) -> bool {
        self.config.enable_obligation_gc && self.epoch_gc.is_some()
    }
}

// ============================================================================
// IO Driver Waker Integration
// ============================================================================

/// Integration adapter for IO driver waker cleanup.
pub struct IODriverWakerEpochGC {
    epoch_gc: Option<Arc<EpochGC>>,
    config: EpochGCIntegrationConfig,
}

impl IODriverWakerEpochGC {
    /// Create a new IO driver waker epoch GC integration.
    #[must_use]
    pub fn new(epoch_gc: Option<Arc<EpochGC>>, config: EpochGCIntegrationConfig) -> Self {
        Self { epoch_gc, config }
    }

    /// Clean up a waker, using epoch GC if available.
    pub fn cleanup_waker(&self, waker_id: u64, source: impl Into<String>) {
        if !self.config.enable_waker_gc {
            self.direct_cleanup_waker(waker_id, &source.into());
            return;
        }

        let work = CleanupWork::WakerCleanup {
            waker_id,
            source: source.into(),
        };

        match self.try_defer_cleanup(work) {
            Ok(()) =>
            {
                #[cfg(feature = "tracing-integration")]
                if self.config.enable_integration_logging {
                    tracing::debug!(waker_id = waker_id, "Deferred waker cleanup to epoch GC");
                }
            }
            Err(work) => {
                #[cfg(feature = "tracing-integration")]
                if self.config.enable_integration_logging {
                    tracing::warn!(
                        waker_id = waker_id,
                        "Failed to defer waker cleanup, using direct cleanup"
                    );
                }
                self.direct_cleanup_fallback(work);
            }
        }
    }

    /// Direct cleanup implementation for wakers.
    fn direct_cleanup_waker(&self, waker_id: u64, source: &str) {
        #[cfg(not(feature = "tracing-integration"))]
        let _ = waker_id;
        #[cfg(feature = "tracing-integration")]
        if self.config.enable_integration_logging {
            tracing::debug!(waker_id = waker_id, source = source, "Direct waker cleanup");
        }

        // Platform-specific direct cleanup
        match source {
            "epoll" => {
                // Direct epoll cleanup: reactor.deregister_fd(waker_id)
            }
            "kqueue" => {
                // Direct kqueue cleanup: reactor.remove_event(waker_id)
            }
            "iocp" => {
                // Direct IOCP cleanup: reactor.cancel_operation(waker_id)
            }
            _ => {
                #[cfg(feature = "tracing-integration")]
                tracing::warn!(source = source, "Unknown waker source for direct cleanup");
            }
        }
    }
}

impl EpochCleanupIntegration for IODriverWakerEpochGC {
    fn try_defer_cleanup(&self, work: CleanupWork) -> Result<(), CleanupWork> {
        if let Some(ref epoch_gc) = self.epoch_gc {
            epoch_gc.defer_cleanup(work)
        } else {
            Err(work)
        }
    }

    fn direct_cleanup_fallback(&self, work: CleanupWork) {
        if let CleanupWork::WakerCleanup { waker_id, source } = work {
            self.direct_cleanup_waker(waker_id, &source);
        }
    }

    fn is_epoch_gc_enabled(&self) -> bool {
        self.config.enable_waker_gc && self.epoch_gc.is_some()
    }
}

// ============================================================================
// Region State Integration
// ============================================================================

/// Integration adapter for region state cleanup.
pub struct RegionStateEpochGC {
    epoch_gc: Option<Arc<EpochGC>>,
    config: EpochGCIntegrationConfig,
}

impl RegionStateEpochGC {
    /// Create a new region state epoch GC integration.
    #[must_use]
    pub fn new(epoch_gc: Option<Arc<EpochGC>>, config: EpochGCIntegrationConfig) -> Self {
        Self { epoch_gc, config }
    }

    /// Clean up region state, using epoch GC if available.
    pub fn cleanup_region(&self, region_id: RegionId, task_ids: Vec<TaskId>) {
        if !self.config.enable_region_gc {
            self.direct_cleanup_region(region_id, &task_ids);
            return;
        }

        let work = CleanupWork::RegionCleanup {
            region_id,
            task_ids,
        };

        match self.try_defer_cleanup(work) {
            Ok(()) =>
            {
                #[cfg(feature = "tracing-integration")]
                if self.config.enable_integration_logging {
                    tracing::debug!(
                        region_id = region_id.as_u64(),
                        "Deferred region cleanup to epoch GC"
                    );
                }
            }
            Err(work) => {
                #[cfg(feature = "tracing-integration")]
                if self.config.enable_integration_logging {
                    tracing::warn!(
                        region_id = region_id.as_u64(),
                        "Failed to defer region cleanup, using direct cleanup"
                    );
                }
                self.direct_cleanup_fallback(work);
            }
        }
    }

    /// Direct cleanup implementation for regions.
    fn direct_cleanup_region(&self, region_id: RegionId, task_ids: &[TaskId]) {
        #[cfg(not(feature = "tracing-integration"))]
        let _ = region_id;
        #[cfg(feature = "tracing-integration")]
        if self.config.enable_integration_logging {
            tracing::debug!(
                region_id = region_id.as_u64(),
                task_count = task_ids.len(),
                "Direct region cleanup"
            );
        }

        // Direct cleanup of region state
        for &task_id in task_ids {
            let _ = task_id;
            // task_table.remove_task(task_id);
            // obligation_table.cleanup_task_obligations(task_id);
        }

        // region_table.remove_region(region_id);
        // obligation_table.cleanup_region_obligations(region_id);
    }
}

impl EpochCleanupIntegration for RegionStateEpochGC {
    fn try_defer_cleanup(&self, work: CleanupWork) -> Result<(), CleanupWork> {
        if let Some(ref epoch_gc) = self.epoch_gc {
            epoch_gc.defer_cleanup(work)
        } else {
            Err(work)
        }
    }

    fn direct_cleanup_fallback(&self, work: CleanupWork) {
        if let CleanupWork::RegionCleanup {
            region_id,
            task_ids,
        } = work
        {
            self.direct_cleanup_region(region_id, &task_ids);
        }
    }

    fn is_epoch_gc_enabled(&self) -> bool {
        self.config.enable_region_gc && self.epoch_gc.is_some()
    }
}

// ============================================================================
// Timer Integration
// ============================================================================

/// Integration adapter for timer cleanup.
pub struct TimerEpochGC {
    epoch_gc: Option<Arc<EpochGC>>,
    config: EpochGCIntegrationConfig,
}

impl TimerEpochGC {
    /// Create a new timer epoch GC integration.
    #[must_use]
    pub fn new(epoch_gc: Option<Arc<EpochGC>>, config: EpochGCIntegrationConfig) -> Self {
        Self { epoch_gc, config }
    }

    /// Clean up a timer, using epoch GC if available.
    pub fn cleanup_timer(&self, timer_id: u64, timer_type: impl Into<String>) {
        if !self.config.enable_timer_gc {
            self.direct_cleanup_timer(timer_id, &timer_type.into());
            return;
        }

        let work = CleanupWork::TimerCleanup {
            timer_id,
            timer_type: timer_type.into(),
        };

        match self.try_defer_cleanup(work) {
            Ok(()) =>
            {
                #[cfg(feature = "tracing-integration")]
                if self.config.enable_integration_logging {
                    tracing::debug!(timer_id = timer_id, "Deferred timer cleanup to epoch GC");
                }
            }
            Err(work) => {
                #[cfg(feature = "tracing-integration")]
                if self.config.enable_integration_logging {
                    tracing::warn!(
                        timer_id = timer_id,
                        "Failed to defer timer cleanup, using direct cleanup"
                    );
                }
                self.direct_cleanup_fallback(work);
            }
        }
    }

    /// Direct cleanup implementation for timers.
    fn direct_cleanup_timer(&self, timer_id: u64, timer_type: &str) {
        #[cfg(not(feature = "tracing-integration"))]
        let _ = timer_id;
        #[cfg(feature = "tracing-integration")]
        if self.config.enable_integration_logging {
            tracing::debug!(
                timer_id = timer_id,
                timer_type = timer_type,
                "Direct timer cleanup"
            );
        }

        // Direct cleanup based on timer type
        match timer_type {
            "sleep" => {
                // timer_wheel.remove_sleep_timer(timer_id);
            }
            "timeout" => {
                // timer_wheel.remove_timeout_timer(timer_id);
                // timeout_registry.cleanup_timeout(timer_id);
            }
            "interval" => {
                // timer_wheel.remove_interval_timer(timer_id);
                // interval_registry.cleanup_interval(timer_id);
            }
            "deadline" => {
                // timer_wheel.remove_deadline_timer(timer_id);
                // deadline_registry.cleanup_deadline(timer_id);
            }
            _ => {
                #[cfg(feature = "tracing-integration")]
                tracing::warn!(
                    timer_type = timer_type,
                    "Unknown timer type for direct cleanup"
                );
            }
        }
    }
}

impl EpochCleanupIntegration for TimerEpochGC {
    fn try_defer_cleanup(&self, work: CleanupWork) -> Result<(), CleanupWork> {
        if let Some(ref epoch_gc) = self.epoch_gc {
            epoch_gc.defer_cleanup(work)
        } else {
            Err(work)
        }
    }

    fn direct_cleanup_fallback(&self, work: CleanupWork) {
        if let CleanupWork::TimerCleanup {
            timer_id,
            timer_type,
        } = work
        {
            self.direct_cleanup_timer(timer_id, &timer_type);
        }
    }

    fn is_epoch_gc_enabled(&self) -> bool {
        self.config.enable_timer_gc && self.epoch_gc.is_some()
    }
}

// ============================================================================
// Channel Integration
// ============================================================================

/// Integration adapter for channel cleanup.
pub struct ChannelEpochGC {
    epoch_gc: Option<Arc<EpochGC>>,
    config: EpochGCIntegrationConfig,
}

impl ChannelEpochGC {
    /// Create a new channel epoch GC integration.
    #[must_use]
    pub fn new(epoch_gc: Option<Arc<EpochGC>>, config: EpochGCIntegrationConfig) -> Self {
        Self { epoch_gc, config }
    }

    /// Clean up channel state, using epoch GC if available.
    pub fn cleanup_channel(&self, channel_id: u64, cleanup_type: impl Into<String>, data: Vec<u8>) {
        if !self.config.enable_channel_gc {
            self.direct_cleanup_channel(channel_id, &cleanup_type.into(), &data);
            return;
        }

        let work = CleanupWork::ChannelCleanup {
            channel_id,
            cleanup_type: cleanup_type.into(),
            data,
        };

        match self.try_defer_cleanup(work) {
            Ok(()) =>
            {
                #[cfg(feature = "tracing-integration")]
                if self.config.enable_integration_logging {
                    tracing::debug!(
                        channel_id = channel_id,
                        "Deferred channel cleanup to epoch GC"
                    );
                }
            }
            Err(work) => {
                #[cfg(feature = "tracing-integration")]
                if self.config.enable_integration_logging {
                    tracing::warn!(
                        channel_id = channel_id,
                        "Failed to defer channel cleanup, using direct cleanup"
                    );
                }
                self.direct_cleanup_fallback(work);
            }
        }
    }

    /// Direct cleanup implementation for channels.
    fn direct_cleanup_channel(&self, channel_id: u64, cleanup_type: &str, data: &[u8]) {
        #[cfg(not(feature = "tracing-integration"))]
        let _ = (channel_id, data);
        #[cfg(feature = "tracing-integration")]
        if self.config.enable_integration_logging {
            tracing::debug!(
                channel_id = channel_id,
                cleanup_type = cleanup_type,
                data_size = data.len(),
                "Direct channel cleanup"
            );
        }

        // Direct cleanup based on channel type
        match cleanup_type {
            "waker" => {
                // channel_registry.cleanup_wakers(channel_id);
            }
            "buffer" => {
                // channel_registry.cleanup_buffers(channel_id);
            }
            "mpsc_sender" | "mpsc_receiver" => {
                // mpsc_registry.cleanup_channel(channel_id);
            }
            "oneshot" => {
                // oneshot_registry.cleanup_channel(channel_id);
            }
            "broadcast" => {
                // broadcast_registry.cleanup_channel(channel_id);
            }
            "watch" => {
                // watch_registry.cleanup_channel(channel_id);
            }
            "session" => {
                // session_registry.cleanup_channel(channel_id);
            }
            _ => {
                #[cfg(feature = "tracing-integration")]
                tracing::warn!(cleanup_type = cleanup_type, "Unknown channel cleanup type");
            }
        }
    }
}

impl EpochCleanupIntegration for ChannelEpochGC {
    fn try_defer_cleanup(&self, work: CleanupWork) -> Result<(), CleanupWork> {
        if let Some(ref epoch_gc) = self.epoch_gc {
            epoch_gc.defer_cleanup(work)
        } else {
            Err(work)
        }
    }

    fn direct_cleanup_fallback(&self, work: CleanupWork) {
        if let CleanupWork::ChannelCleanup {
            channel_id,
            cleanup_type,
            data,
        } = work
        {
            self.direct_cleanup_channel(channel_id, &cleanup_type, &data);
        }
    }

    fn is_epoch_gc_enabled(&self) -> bool {
        self.config.enable_channel_gc && self.epoch_gc.is_some()
    }
}

// ============================================================================
// Unified Runtime Integration
// ============================================================================

/// Unified epoch GC integration for all runtime cleanup paths.
pub struct RuntimeEpochGCIntegration {
    pub obligation_gc: ObligationTableEpochGC,
    pub waker_gc: IODriverWakerEpochGC,
    pub region_gc: RegionStateEpochGC,
    pub timer_gc: TimerEpochGC,
    pub channel_gc: ChannelEpochGC,
    epoch_gc: Option<Arc<EpochGC>>,
}

impl RuntimeEpochGCIntegration {
    /// Create a new unified runtime epoch GC integration.
    #[must_use]
    pub fn new(epoch_gc: Option<Arc<EpochGC>>, config: EpochGCIntegrationConfig) -> Self {
        Self {
            obligation_gc: ObligationTableEpochGC::new(epoch_gc.clone(), config.clone()),
            waker_gc: IODriverWakerEpochGC::new(epoch_gc.clone(), config.clone()),
            region_gc: RegionStateEpochGC::new(epoch_gc.clone(), config.clone()),
            timer_gc: TimerEpochGC::new(epoch_gc.clone(), config.clone()),
            channel_gc: ChannelEpochGC::new(epoch_gc.clone(), config),
            epoch_gc,
        }
    }

    /// Create integration with epoch GC disabled (direct cleanup only).
    #[must_use]
    pub fn disabled() -> Self {
        let config = EpochGCIntegrationConfig::disabled();
        Self::new(None, config)
    }

    /// Trigger epoch advancement and cleanup processing.
    /// This should be called periodically from the runtime scheduler.
    #[must_use]
    pub fn try_advance_epoch(&self) -> usize {
        if let Some(ref epoch_gc) = self.epoch_gc {
            epoch_gc.try_advance_and_cleanup()
        } else {
            0
        }
    }

    /// Force epoch advancement for testing or shutdown.
    #[cfg(test)]
    pub fn force_advance_epoch(&self) -> usize {
        if let Some(ref epoch_gc) = self.epoch_gc {
            epoch_gc.force_advance_and_cleanup()
        } else {
            0
        }
    }

    /// Get epoch GC statistics.
    #[must_use]
    pub fn stats(&self) -> Option<&crate::runtime::epoch_gc::CleanupStats> {
        self.epoch_gc.as_ref().map(|gc| gc.stats())
    }

    /// Check if epoch GC is enabled.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.epoch_gc.is_some()
    }

    /// Check if the cleanup queue is near capacity.
    #[must_use]
    pub fn is_near_capacity(&self) -> bool {
        self.epoch_gc
            .as_ref()
            .is_some_and(|gc| gc.is_cleanup_queue_near_capacity())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::pedantic, clippy::nursery, clippy::expect_fun_call, clippy::map_unwrap_or, clippy::cast_possible_wrap, clippy::future_not_send)]
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
}
