//! Runtime configuration types.
//!
//! These types hold the concrete values that drive runtime behavior. In most
//! cases you should use [`RuntimeBuilder`](super::builder::RuntimeBuilder) to
//! construct a runtime rather than creating a [`RuntimeConfig`] directly.
//!
//! # Defaults
//!
//! | Field | Default |
//! |-------|---------|
//! | `worker_threads` | available CPU parallelism |
//! | `thread_stack_size` | 2 MiB |
//! | `thread_name_prefix` | `"asupersync-worker"` |
//! | `global_queue_limit` | 0 (unbounded) |
//! | `steal_batch_size` | 16 |
//! | `enable_parking` | true |
//! | `poll_budget` | 128 |
//! | `root_region_limits` | `None` |
//! | `observability` | `None` |

use crate::observability::ObservabilityConfig;
use crate::observability::metrics::{MetricsProvider, NoOpMetrics};
use crate::record::RegionLimits;
use crate::runtime::deadline_monitor::{DeadlineWarning, MonitorConfig};
use crate::trace::distributed::LogicalClockMode;
use crate::types::CancelAttributionConfig;
use std::sync::Arc;

/// Configuration for the blocking pool.
#[derive(Clone, Default)]
pub struct BlockingPoolConfig {
    /// Minimum number of blocking threads.
    pub min_threads: usize,
    /// Maximum number of blocking threads.
    pub max_threads: usize,
}

impl BlockingPoolConfig {
    /// Normalize configuration values to safe defaults.
    pub fn normalize(&mut self) {
        if self.max_threads < self.min_threads {
            self.max_threads = self.min_threads;
        }
    }
}

/// Response policy when obligation leaks are detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObligationLeakResponse {
    /// Panic immediately with diagnostic details.
    Panic,
    /// Log the leak and continue.
    Log,
    /// Suppress logging for leaks (still marked as leaked).
    Silent,
    /// Automatically abort leaked obligations and log a warning.
    ///
    /// Unlike `Log`, this performs best-effort cleanup by aborting the
    /// obligation (transitioning to `Aborted` instead of `Leaked`),
    /// which releases associated resources. Useful in production where
    /// crashing is unacceptable but resource cleanup is important.
    Recover,
}

/// Escalation policy for obligation leaks.
///
/// When configured, the runtime tracks the cumulative number of leaks
/// and escalates from the base response to a stricter one after a
/// threshold is reached. For example, a service might log the first
/// few leaks but panic after 10 to prevent cascading resource exhaustion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeakEscalation {
    /// Number of leaks that trigger escalation.
    pub threshold: u64,
    /// Response to switch to after the threshold is reached.
    pub escalate_to: ObligationLeakResponse,
}

impl LeakEscalation {
    /// Creates a new escalation policy.
    #[must_use]
    pub const fn new(threshold: u64, escalate_to: ObligationLeakResponse) -> Self {
        let threshold = if threshold == 0 { 1 } else { threshold };
        Self {
            threshold,
            escalate_to,
        }
    }
}

/// Runtime configuration.
#[derive(Clone)]
pub struct RuntimeConfig {
    /// Number of worker threads (default: available parallelism).
    pub worker_threads: usize,
    /// Stack size per worker thread (default: 2MB).
    pub thread_stack_size: usize,
    /// Name prefix for worker threads.
    pub thread_name_prefix: String,
    /// Global queue size limit (0 = unbounded).
    pub global_queue_limit: usize,
    /// Work stealing batch size.
    pub steal_batch_size: usize,
    /// Blocking pool configuration.
    pub blocking: BlockingPoolConfig,
    /// Enable parking for idle workers.
    pub enable_parking: bool,
    /// Time slice for cooperative yielding (polls).
    pub poll_budget: u32,
    /// Maximum consecutive cancel-lane dispatches before yielding to other lanes.
    pub cancel_lane_max_streak: usize,
    /// Logical clock mode used for trace causal ordering.
    ///
    /// When `None`, the runtime chooses a default:
    /// - No reactor: Lamport (deterministic lab-friendly)
    /// - With reactor: Hybrid (wall-clock + logical)
    pub logical_clock_mode: Option<LogicalClockMode>,
    /// Admission limits applied to the root region (if set).
    pub root_region_limits: Option<RegionLimits>,
    /// Callback executed when a worker thread starts.
    pub on_thread_start: Option<Arc<dyn Fn() + Send + Sync>>,
    /// Callback executed when a worker thread stops.
    pub on_thread_stop: Option<Arc<dyn Fn() + Send + Sync>>,
    /// Deadline monitoring configuration (when enabled).
    pub deadline_monitor: Option<MonitorConfig>,
    /// Warning callback for deadline monitoring.
    pub deadline_warning_handler: Option<Arc<dyn Fn(DeadlineWarning) + Send + Sync>>,
    /// Metrics provider for runtime instrumentation.
    pub metrics_provider: Arc<dyn MetricsProvider>,
    /// Optional runtime observability configuration.
    pub observability: Option<ObservabilityConfig>,
    /// Limits for cancellation attribution cause chains.
    ///
    /// Used to bound memory growth when cancellation cascades across deep
    /// region trees or large cancellation graphs.
    pub cancel_attribution: CancelAttributionConfig,
    /// Response policy for obligation leaks detected at runtime.
    pub obligation_leak_response: ObligationLeakResponse,
    /// Optional escalation policy for obligation leaks.
    ///
    /// When set, the runtime escalates from `obligation_leak_response` to
    /// `escalation.escalate_to` after `escalation.threshold` leaks.
    pub leak_escalation: Option<LeakEscalation>,
    /// Enable the Lyapunov governor for scheduling suggestions.
    ///
    /// When enabled, the scheduler periodically snapshots runtime state and
    /// consults the governor for lane-ordering hints. When disabled (default),
    /// scheduling behavior is identical to the ungoverned baseline.
    pub enable_governor: bool,
    /// Number of scheduling steps between governor snapshots (default: 32).
    ///
    /// Lower values increase responsiveness but add snapshot overhead.
    /// Only relevant when `enable_governor` is true.
    pub governor_interval: u32,
}

impl RuntimeConfig {
    /// Normalize configuration values to safe defaults.
    pub fn normalize(&mut self) {
        if self.worker_threads == 0 {
            self.worker_threads = 1;
        }
        if self.thread_stack_size == 0 {
            self.thread_stack_size = 2 * 1024 * 1024;
        }
        if self.steal_batch_size == 0 {
            self.steal_batch_size = 1;
        }
        if self.poll_budget == 0 {
            self.poll_budget = 1;
        }
        if self.cancel_lane_max_streak == 0 {
            self.cancel_lane_max_streak = 1;
        }
        if self.governor_interval == 0 {
            self.governor_interval = 1;
        }
        if let Some(escalation) = self.leak_escalation.as_mut() {
            if escalation.threshold == 0 {
                escalation.threshold = 1;
            }
        }
        if self.thread_name_prefix.is_empty() {
            self.thread_name_prefix = "asupersync-worker".to_string();
        }
        self.blocking.normalize();
    }

    pub(crate) fn default_worker_threads() -> usize {
        std::thread::available_parallelism()
            .map_or(1, std::num::NonZeroUsize::get)
            .max(1)
    }
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            worker_threads: Self::default_worker_threads(),
            thread_stack_size: 2 * 1024 * 1024,
            thread_name_prefix: "asupersync-worker".to_string(),
            global_queue_limit: 0,
            steal_batch_size: 16,
            blocking: BlockingPoolConfig::default(),
            enable_parking: true,
            poll_budget: 128,
            cancel_lane_max_streak: 16,
            logical_clock_mode: None,
            root_region_limits: None,
            on_thread_start: None,
            on_thread_stop: None,
            deadline_monitor: None,
            deadline_warning_handler: None,
            metrics_provider: Arc::new(NoOpMetrics),
            observability: None,
            cancel_attribution: CancelAttributionConfig::default(),
            obligation_leak_response: ObligationLeakResponse::Log,
            leak_escalation: None,
            enable_governor: false,
            governor_interval: 32,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn test_default_config_sane() {
        init_test("test_default_config_sane");
        let config = RuntimeConfig::default();
        crate::assert_with_log!(
            config.worker_threads >= 1,
            "worker_threads",
            true,
            config.worker_threads >= 1
        );
        crate::assert_with_log!(
            config.thread_stack_size == 2 * 1024 * 1024,
            "thread_stack_size",
            2 * 1024 * 1024,
            config.thread_stack_size
        );
        crate::assert_with_log!(
            !config.thread_name_prefix.is_empty(),
            "thread_name_prefix",
            true,
            !config.thread_name_prefix.is_empty()
        );
        crate::assert_with_log!(
            config.poll_budget == 128,
            "poll_budget",
            128,
            config.poll_budget
        );
        crate::assert_with_log!(
            config.cancel_lane_max_streak == 16,
            "cancel_lane_max_streak",
            16,
            config.cancel_lane_max_streak
        );
        crate::assert_with_log!(
            config.logical_clock_mode.is_none(),
            "logical_clock_mode",
            "None",
            format!("{:?}", config.logical_clock_mode)
        );
        crate::assert_with_log!(
            config.obligation_leak_response == ObligationLeakResponse::Log,
            "obligation_leak_response",
            ObligationLeakResponse::Log,
            config.obligation_leak_response
        );
        crate::assert_with_log!(
            config.cancel_attribution == CancelAttributionConfig::default(),
            "cancel_attribution default",
            CancelAttributionConfig::default(),
            config.cancel_attribution
        );
        crate::test_complete!("test_default_config_sane");
    }

    #[test]
    fn test_normalize_enforces_minimums() {
        init_test("test_normalize_enforces_minimums");
        let mut config = RuntimeConfig {
            worker_threads: 0,
            thread_stack_size: 0,
            thread_name_prefix: String::new(),
            global_queue_limit: 0,
            steal_batch_size: 0,
            blocking: BlockingPoolConfig {
                min_threads: 4,
                max_threads: 1,
            },
            enable_parking: true,
            poll_budget: 0,
            cancel_lane_max_streak: 0,
            root_region_limits: None,
            on_thread_start: None,
            on_thread_stop: None,
            deadline_monitor: None,
            deadline_warning_handler: None,
            metrics_provider: Arc::new(NoOpMetrics),
            observability: None,
            cancel_attribution: CancelAttributionConfig::new(1, 256),
            obligation_leak_response: ObligationLeakResponse::Log,
            leak_escalation: None,
            logical_clock_mode: None,
            enable_governor: false,
            governor_interval: 0,
        };

        config.normalize();
        crate::assert_with_log!(
            config.worker_threads == 1,
            "worker_threads",
            1,
            config.worker_threads
        );
        crate::assert_with_log!(
            config.thread_stack_size == 2 * 1024 * 1024,
            "thread_stack_size",
            2 * 1024 * 1024,
            config.thread_stack_size
        );
        crate::assert_with_log!(
            config.steal_batch_size == 1,
            "steal_batch_size",
            1,
            config.steal_batch_size
        );
        crate::assert_with_log!(
            config.poll_budget == 1,
            "poll_budget",
            1,
            config.poll_budget
        );
        crate::assert_with_log!(
            config.cancel_lane_max_streak == 1,
            "cancel_lane_max_streak",
            1,
            config.cancel_lane_max_streak
        );
        crate::assert_with_log!(
            config.governor_interval == 1,
            "governor_interval",
            1,
            config.governor_interval
        );
        crate::assert_with_log!(
            config.thread_name_prefix == "asupersync-worker",
            "thread_name_prefix",
            "asupersync-worker",
            config.thread_name_prefix
        );
        crate::assert_with_log!(
            config.blocking.max_threads == config.blocking.min_threads,
            "blocking normalize",
            config.blocking.min_threads,
            config.blocking.max_threads
        );
        crate::test_complete!("test_normalize_enforces_minimums");
    }

    #[test]
    fn test_blocking_pool_normalize() {
        init_test("test_blocking_pool_normalize");
        let mut blocking = BlockingPoolConfig {
            min_threads: 2,
            max_threads: 1,
        };
        blocking.normalize();
        crate::assert_with_log!(
            blocking.max_threads == blocking.min_threads,
            "blocking max>=min",
            blocking.min_threads,
            blocking.max_threads
        );
        crate::test_complete!("test_blocking_pool_normalize");
    }

    #[test]
    fn test_leak_escalation_new_clamps_zero_threshold() {
        init_test("test_leak_escalation_new_clamps_zero_threshold");
        let escalation = LeakEscalation::new(0, ObligationLeakResponse::Panic);
        crate::assert_with_log!(
            escalation.threshold == 1,
            "leak_escalation.threshold",
            1,
            escalation.threshold
        );
        crate::assert_with_log!(
            escalation.escalate_to == ObligationLeakResponse::Panic,
            "leak_escalation.escalate_to",
            ObligationLeakResponse::Panic,
            escalation.escalate_to
        );
        crate::test_complete!("test_leak_escalation_new_clamps_zero_threshold");
    }

    #[test]
    fn test_normalize_clamps_zero_leak_escalation_threshold() {
        init_test("test_normalize_clamps_zero_leak_escalation_threshold");
        let mut config = RuntimeConfig {
            leak_escalation: Some(LeakEscalation {
                threshold: 0,
                escalate_to: ObligationLeakResponse::Recover,
            }),
            ..RuntimeConfig::default()
        };

        config.normalize();

        let escalation = config
            .leak_escalation
            .expect("leak escalation should remain configured");
        crate::assert_with_log!(
            escalation.threshold == 1,
            "leak_escalation.threshold",
            1,
            escalation.threshold
        );
        crate::assert_with_log!(
            escalation.escalate_to == ObligationLeakResponse::Recover,
            "leak_escalation.escalate_to",
            ObligationLeakResponse::Recover,
            escalation.escalate_to
        );
        crate::test_complete!("test_normalize_clamps_zero_leak_escalation_threshold");
    }

    #[test]
    fn test_default_worker_threads_nonzero() {
        init_test("test_default_worker_threads_nonzero");
        let threads = RuntimeConfig::default_worker_threads();
        crate::assert_with_log!(threads >= 1, "default_worker_threads", true, threads >= 1);
        crate::test_complete!("test_default_worker_threads_nonzero");
    }

    #[test]
    fn test_normalize_preserves_custom_values() {
        init_test("test_normalize_preserves_custom_values");
        let mut config = RuntimeConfig {
            worker_threads: 4,
            thread_stack_size: 1024,
            thread_name_prefix: "custom".to_string(),
            global_queue_limit: 64,
            steal_batch_size: 8,
            blocking: BlockingPoolConfig {
                min_threads: 2,
                max_threads: 4,
            },
            enable_parking: false,
            poll_budget: 32,
            cancel_lane_max_streak: 16,
            root_region_limits: None,
            on_thread_start: None,
            on_thread_stop: None,
            deadline_monitor: None,
            deadline_warning_handler: None,
            metrics_provider: Arc::new(NoOpMetrics),
            observability: None,
            cancel_attribution: CancelAttributionConfig::new(8, 1024),
            obligation_leak_response: ObligationLeakResponse::Silent,
            leak_escalation: None,
            logical_clock_mode: None,
            enable_governor: false,
            governor_interval: 7,
        };

        config.normalize();
        crate::assert_with_log!(
            config.worker_threads == 4,
            "worker_threads",
            4,
            config.worker_threads
        );
        crate::assert_with_log!(
            config.thread_stack_size == 1024,
            "thread_stack_size",
            1024,
            config.thread_stack_size
        );
        crate::assert_with_log!(
            config.thread_name_prefix == "custom",
            "thread_name_prefix",
            "custom",
            config.thread_name_prefix
        );
        crate::assert_with_log!(
            config.steal_batch_size == 8,
            "steal_batch_size",
            8,
            config.steal_batch_size
        );
        crate::assert_with_log!(
            config.poll_budget == 32,
            "poll_budget",
            32,
            config.poll_budget
        );
        crate::assert_with_log!(
            config.cancel_lane_max_streak == 16,
            "cancel_lane_max_streak",
            16,
            config.cancel_lane_max_streak
        );
        crate::assert_with_log!(
            config.governor_interval == 7,
            "governor_interval",
            7,
            config.governor_interval
        );
        crate::assert_with_log!(
            config.blocking.max_threads == 4,
            "blocking max",
            4,
            config.blocking.max_threads
        );
        crate::assert_with_log!(
            config.obligation_leak_response == ObligationLeakResponse::Silent,
            "obligation_leak_response",
            ObligationLeakResponse::Silent,
            config.obligation_leak_response
        );
        crate::test_complete!("test_normalize_preserves_custom_values");
    }

    // ========================================================================
    // Pure data-type tests (wave 10 – CyanBarn)
    // ========================================================================

    #[test]
    fn obligation_leak_response_clone_copy() {
        let a = ObligationLeakResponse::Recover;
        let b = a; // Copy
        let c = a.clone();
        assert_eq!(a, b);
        assert_eq!(a, c);
    }

    #[test]
    fn leak_escalation_debug_eq() {
        let a = LeakEscalation::new(5, ObligationLeakResponse::Panic);
        let b = LeakEscalation::new(5, ObligationLeakResponse::Panic);
        assert_eq!(a, b);
        let dbg = format!("{a:?}");
        assert!(dbg.contains("LeakEscalation"), "{dbg}");
    }

    #[test]
    fn leak_escalation_clone_copy() {
        let a = LeakEscalation::new(10, ObligationLeakResponse::Log);
        let b = a; // Copy
        let c = a.clone();
        assert_eq!(a, b);
        assert_eq!(a, c);
    }

    #[test]
    fn blocking_pool_config_default() {
        let bp = BlockingPoolConfig::default();
        assert_eq!(bp.min_threads, 0);
        assert_eq!(bp.max_threads, 0);
    }

    #[test]
    fn blocking_pool_config_clone() {
        let bp = BlockingPoolConfig {
            min_threads: 2,
            max_threads: 8,
        };
        let cloned = bp.clone();
        assert_eq!(cloned.min_threads, 2);
        assert_eq!(cloned.max_threads, 8);
    }

    #[test]
    fn runtime_config_clone() {
        let config = RuntimeConfig::default();
        let cloned = config.clone();
        assert_eq!(cloned.worker_threads, config.worker_threads);
        assert_eq!(cloned.poll_budget, config.poll_budget);
        assert_eq!(
            cloned.obligation_leak_response,
            config.obligation_leak_response
        );
    }

    /// Invariant: ObligationLeakResponse variants are distinct and Debug-printable.
    #[test]
    fn test_obligation_leak_response_variants() {
        init_test("test_obligation_leak_response_variants");
        let variants = [
            ObligationLeakResponse::Panic,
            ObligationLeakResponse::Log,
            ObligationLeakResponse::Silent,
            ObligationLeakResponse::Recover,
        ];
        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                if i == j {
                    crate::assert_with_log!(*a == *b, "same variant eq", true, *a == *b);
                } else {
                    crate::assert_with_log!(*a != *b, "diff variant ne", true, *a != *b);
                }
            }
            let dbg = format!("{a:?}");
            crate::assert_with_log!(!dbg.is_empty(), "Debug non-empty", true, !dbg.is_empty());
        }
        crate::test_complete!("test_obligation_leak_response_variants");
    }

    /// Invariant: LeakEscalation preserves non-zero threshold.
    #[test]
    fn test_leak_escalation_preserves_nonzero() {
        init_test("test_leak_escalation_preserves_nonzero");
        let escalation = LeakEscalation::new(10, ObligationLeakResponse::Recover);
        crate::assert_with_log!(
            escalation.threshold == 10,
            "threshold preserved",
            10,
            escalation.threshold
        );
        crate::assert_with_log!(
            escalation.escalate_to == ObligationLeakResponse::Recover,
            "escalate_to",
            ObligationLeakResponse::Recover,
            escalation.escalate_to
        );
        crate::test_complete!("test_leak_escalation_preserves_nonzero");
    }

    /// Invariant: RuntimeConfig default governor settings are off with interval 32.
    #[test]
    fn test_default_governor_settings() {
        init_test("test_default_governor_settings");
        let config = RuntimeConfig::default();
        crate::assert_with_log!(
            !config.enable_governor,
            "governor disabled by default",
            false,
            config.enable_governor
        );
        crate::assert_with_log!(
            config.governor_interval == 32,
            "default governor interval",
            32,
            config.governor_interval
        );
        crate::test_complete!("test_default_governor_settings");
    }
}
