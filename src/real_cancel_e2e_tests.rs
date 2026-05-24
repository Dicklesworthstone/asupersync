//! [br-e2e-12] Real Cancel Propagation E2E Tests
//!
//! Implements real-service E2E testing for asupersync cancel propagation through nested scope trees.
//! Tests actual cancel signal propagation, task spawning hierarchies, and cancellation protocol
//! with no mocks - using real structured concurrency primitives.
//!
//! Key principle: "If a mock hides a bug that would break production, the mock is worse than no test at all."
//! We test real cancel propagation with actual task hierarchies and scope trees.

#[cfg(all(test, feature = "real-service-e2e"))]
use crate::{
    cancel::{CancelReason, CancelRequest, CancelToken, cancel_after, cancel_scope},
    channel::{mpsc, oneshot},
    combinator::{join, race, timeout},
    cx::Cx,
    error::{AsupersyncError, Outcome},
    runtime::{Region, RuntimeBuilder},
    sync::{Arc, Barrier},
    time::{Duration, Instant, sleep},
    types::{RegionId, TaskId},
};

#[cfg(all(test, feature = "real-service-e2e"))]
use std::{
    collections::{HashMap, VecDeque},
    sync::Mutex,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

#[cfg(all(test, feature = "real-service-e2e"))]
use serde::{Deserialize, Serialize};

/// Real cancel propagation manager that coordinates actual cancel signal testing
/// Uses asupersync cancel primitives with real task hierarchies and scope trees
#[cfg(all(test, feature = "real-service-e2e"))]
struct RealCancelManager {
    test_name: String,
    stats: Arc<CancelE2EStats>,
    logger: CancelE2ELogger,
}

/// Comprehensive statistics for cancel propagation E2E operations
#[cfg(all(test, feature = "real-service-e2e"))]
#[derive(Debug, Clone)]
struct CancelE2EStats {
    scopes_created: AtomicU64,
    tasks_spawned: AtomicU64,
    cancel_signals_sent: AtomicU64,
    cancel_signals_received: AtomicU64,
    graceful_cancellations: AtomicU64,
    forced_cancellations: AtomicU64,
    cancel_propagation_depth: AtomicU64,
    max_nesting_level: AtomicU64,
    cancel_latency_total_ns: AtomicU64,
    tasks_completed_before_cancel: AtomicU64,
    orphaned_tasks: AtomicU64,
}

/// Structured logger for cancel propagation E2E test observability
#[cfg(all(test, feature = "real-service-e2e"))]
#[derive(Debug, Clone)]
struct CancelE2ELogger {
    test_id: String,
    component: String,
}

/// Cancel propagation operation result with timing measurements
#[cfg(all(test, feature = "real-service-e2e"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CancelOperation {
    operation_type: CancelOperationType,
    scope_tree_depth: u64,
    tasks_in_hierarchy: u64,
    cancel_propagation_latency_ns: u64,
    cancellation_success_rate: f64,
    orphaned_task_count: u64,
}

/// Types of cancel propagation operations under test
#[cfg(all(test, feature = "real-service-e2e"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
enum CancelOperationType {
    LinearHierarchy,
    TreeHierarchy,
    DeepNesting,
    ConcurrentCancel,
    GracefulShutdown,
    ForcedTermination,
}

/// Configuration for cancel propagation E2E tests
#[cfg(all(test, feature = "real-service-e2e"))]
#[derive(Debug, Clone)]
struct CancelE2EConfig {
    max_nesting_depth: usize,
    tasks_per_level: usize,
    cancel_delay_ms: u64,
    graceful_timeout_ms: u64,
    tree_branching_factor: usize,
}

/// Task hierarchy node for tracking cancel propagation
#[cfg(all(test, feature = "real-service-e2e"))]
#[derive(Debug, Clone)]
struct TaskHierarchyNode {
    task_id: u64,
    level: usize,
    parent_id: Option<u64>,
    children: Vec<u64>,
    cancel_received: Arc<AtomicBool>,
    completion_time: Arc<Mutex<Option<Instant>>>,
}

#[cfg(all(test, feature = "real-service-e2e"))]
impl RealCancelManager {
    /// Create a new real cancel propagation manager for E2E testing
    fn new(test_name: &str) -> Self {
        let stats = Arc::new(CancelE2EStats {
            scopes_created: AtomicU64::new(0),
            tasks_spawned: AtomicU64::new(0),
            cancel_signals_sent: AtomicU64::new(0),
            cancel_signals_received: AtomicU64::new(0),
            graceful_cancellations: AtomicU64::new(0),
            forced_cancellations: AtomicU64::new(0),
            cancel_propagation_depth: AtomicU64::new(0),
            max_nesting_level: AtomicU64::new(0),
            cancel_latency_total_ns: AtomicU64::new(0),
            tasks_completed_before_cancel: AtomicU64::new(0),
            orphaned_tasks: AtomicU64::new(0),
        });

        Self {
            test_name: test_name.to_string(),
            stats,
            logger: CancelE2ELogger::new(test_name, "cancel-manager"),
        }
    }

    /// Test linear hierarchy cancel propagation (parent → child → grandchild)
    async fn test_linear_hierarchy_cancel(
        &self,
        cx: &Cx,
        depth: usize,
    ) -> Result<CancelOperation, AsupersyncError> {
        self.logger.log_phase("linear_hierarchy_cancel_start");
        let start_time = Instant::now();

        let cancel_token = CancelToken::new();
        // Use bounded channel to prevent memory exhaustion from status updates
        const STATUS_CHANNEL_CAPACITY: usize = 1000;
        let (status_sender, mut status_receiver) = mpsc::channel(STATUS_CHANNEL_CAPACITY);
        let mut hierarchy_nodes = HashMap::new();

        // Build linear hierarchy of nested scopes
        let hierarchy_handle = cx.spawn(async move {
            self.build_linear_hierarchy(
                cx,
                depth,
                0,
                None,
                &cancel_token,
                &status_sender,
                &mut hierarchy_nodes,
            )
            .await
        });

        // Wait for hierarchy to establish
        sleep(Duration::from_millis(100)).await;

        // Send cancel signal
        let cancel_start = Instant::now();
        cancel_token.cancel(CancelReason::UserRequested);
        self.stats
            .cancel_signals_sent
            .fetch_add(1, Ordering::Relaxed);

        // Collect status updates from hierarchy
        let mut received_cancels = 0;
        let mut total_nodes = 0;

        while let Some(status) = status_receiver.recv().await {
            match status {
                TaskStatus::Created => total_nodes += 1,
                TaskStatus::CancelReceived => {
                    received_cancels += 1;
                    self.stats
                        .cancel_signals_received
                        .fetch_add(1, Ordering::Relaxed);
                }
                TaskStatus::Completed => {
                    self.stats
                        .tasks_completed_before_cancel
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        let _ = hierarchy_handle.await;
        let end_time = Instant::now();

        let propagation_latency = end_time.duration_since(cancel_start).as_nanos() as u64;
        self.stats
            .cancel_latency_total_ns
            .fetch_add(propagation_latency, Ordering::Relaxed);
        self.stats
            .max_nesting_level
            .store(depth as u64, Ordering::Relaxed);

        let success_rate = if total_nodes > 0 {
            received_cancels as f64 / total_nodes as f64
        } else {
            0.0
        };

        self.logger.log_operation(
            "linear_hierarchy",
            depth as u64,
            total_nodes,
            received_cancels,
        );

        Ok(CancelOperation {
            operation_type: CancelOperationType::LinearHierarchy,
            scope_tree_depth: depth as u64,
            tasks_in_hierarchy: total_nodes,
            cancel_propagation_latency_ns: propagation_latency,
            cancellation_success_rate: success_rate,
            orphaned_task_count: total_nodes - received_cancels,
        })
    }

    /// Build linear hierarchy of nested scopes with cancel propagation
    async fn build_linear_hierarchy(
        &self,
        cx: &Cx,
        remaining_depth: usize,
        current_level: usize,
        parent_id: Option<u64>,
        cancel_token: &CancelToken,
        status_sender: &mpsc::UnboundedSender<TaskStatus>,
        hierarchy_nodes: &mut HashMap<u64, TaskHierarchyNode>,
    ) -> Result<(), AsupersyncError> {
        if remaining_depth == 0 {
            return Ok(());
        }

        let task_id = current_level as u64;
        let cancel_received = Arc::new(AtomicBool::new(false));
        let completion_time = Arc::new(Mutex::new(None));

        // Create task hierarchy node
        let node = TaskHierarchyNode {
            task_id,
            level: current_level,
            parent_id,
            children: Vec::new(),
            cancel_received: cancel_received.clone(),
            completion_time: completion_time.clone(),
        };

        hierarchy_nodes.insert(task_id, node);
        self.stats.tasks_spawned.fetch_add(1, Ordering::Relaxed);

        let _ = status_sender.send(TaskStatus::Created).await;

        // Create child scope
        let child_cancel_token = cancel_token.clone();
        let child_status_sender = status_sender.clone();
        let child_cancel_received = cancel_received.clone();

        cancel_scope(cx, |child_cx| async move {
            self.stats.scopes_created.fetch_add(1, Ordering::Relaxed);

            // Set up cancel monitoring for this level
            let monitor_cancel_token = child_cancel_token.clone();
            let monitor_cancel_received = child_cancel_received.clone();
            let monitor_status_sender = child_status_sender.clone();

            let cancel_monitor = child_cx.spawn(async move {
                monitor_cancel_token.cancelled().await;
                monitor_cancel_received.store(true, Ordering::Relaxed);
                let _ = monitor_status_sender.send(TaskStatus::CancelReceived).await;
            });

            // Recursively create child hierarchy
            if remaining_depth > 1 {
                let mut child_hierarchy = HashMap::new();
                self.build_linear_hierarchy(
                    child_cx,
                    remaining_depth - 1,
                    current_level + 1,
                    Some(task_id),
                    &child_cancel_token,
                    &child_status_sender,
                    &mut child_hierarchy,
                )
                .await?;
            }

            // Simulate some work at this level
            let work_result = timeout(
                Duration::from_millis(200),
                self.simulate_task_work(current_level),
            )
            .await;

            match work_result {
                Outcome::Ok(()) => {
                    let _ = child_status_sender.send(TaskStatus::Completed).await;
                    *completion_time.lock().unwrap() = Some(Instant::now());
                }
                Outcome::Cancelled => {
                    // Task was cancelled before completing
                }
                _ => {
                    // Timeout or error
                }
            }

            let _ = cancel_monitor.await;
            Ok(())
        })
        .await
    }

    /// Test tree hierarchy cancel propagation (parent with multiple children)
    async fn test_tree_hierarchy_cancel(
        &self,
        cx: &Cx,
        config: &CancelE2EConfig,
    ) -> Result<CancelOperation, AsupersyncError> {
        self.logger.log_phase("tree_hierarchy_cancel_start");
        let start_time = Instant::now();

        let cancel_token = CancelToken::new();
        let (status_sender, mut status_receiver) = mpsc::unbounded();

        // Build tree hierarchy with branching factor
        let tree_handle = cx.spawn(async move {
            self.build_tree_hierarchy(
                cx,
                config.max_nesting_depth,
                config.tree_branching_factor,
                0,
                0,
                &cancel_token,
                &status_sender,
            )
            .await
        });

        // Wait for tree to establish
        sleep(Duration::from_millis(150)).await;

        // Send cancel signal
        let cancel_start = Instant::now();
        cancel_token.cancel(CancelReason::UserRequested);
        self.stats
            .cancel_signals_sent
            .fetch_add(1, Ordering::Relaxed);

        // Collect status updates from tree hierarchy
        let mut received_cancels = 0;
        let mut total_nodes = 0;

        // Use timeout to avoid infinite wait
        let collection_result = timeout(Duration::from_millis(2000), async {
            while let Some(status) = status_receiver.recv().await {
                match status {
                    TaskStatus::Created => total_nodes += 1,
                    TaskStatus::CancelReceived => {
                        received_cancels += 1;
                        self.stats
                            .cancel_signals_received
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    TaskStatus::Completed => {
                        self.stats
                            .tasks_completed_before_cancel
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        })
        .await;

        let _ = tree_handle.await;
        let end_time = Instant::now();

        let propagation_latency = end_time.duration_since(cancel_start).as_nanos() as u64;
        self.stats
            .cancel_latency_total_ns
            .fetch_add(propagation_latency, Ordering::Relaxed);

        let success_rate = if total_nodes > 0 {
            received_cancels as f64 / total_nodes as f64
        } else {
            0.0
        };

        self.logger.log_operation(
            "tree_hierarchy",
            config.max_nesting_depth as u64,
            total_nodes,
            received_cancels,
        );

        Ok(CancelOperation {
            operation_type: CancelOperationType::TreeHierarchy,
            scope_tree_depth: config.max_nesting_depth as u64,
            tasks_in_hierarchy: total_nodes,
            cancel_propagation_latency_ns: propagation_latency,
            cancellation_success_rate: success_rate,
            orphaned_task_count: total_nodes - received_cancels,
        })
    }

    /// Build tree hierarchy with specified branching factor
    async fn build_tree_hierarchy(
        &self,
        cx: &Cx,
        remaining_depth: usize,
        branching_factor: usize,
        current_level: usize,
        node_id: u64,
        cancel_token: &CancelToken,
        status_sender: &mpsc::UnboundedSender<TaskStatus>,
    ) -> Result<(), AsupersyncError> {
        if remaining_depth == 0 {
            return Ok(());
        }

        self.stats.tasks_spawned.fetch_add(1, Ordering::Relaxed);
        let _ = status_sender.send(TaskStatus::Created).await;

        cancel_scope(cx, |scope_cx| async move {
            self.stats.scopes_created.fetch_add(1, Ordering::Relaxed);

            // Set up cancel monitoring for this node
            let monitor_cancel_token = cancel_token.clone();
            let monitor_status_sender = status_sender.clone();

            let cancel_monitor = scope_cx.spawn(async move {
                monitor_cancel_token.cancelled().await;
                let _ = monitor_status_sender.send(TaskStatus::CancelReceived).await;
            });

            // Spawn child nodes
            let mut child_handles = Vec::new();
            for i in 0..branching_factor {
                let child_node_id = node_id * branching_factor as u64 + i as u64 + 1;
                let child_cancel_token = cancel_token.clone();
                let child_status_sender = status_sender.clone();

                let child_handle = scope_cx.spawn(async move {
                    self.build_tree_hierarchy(
                        scope_cx,
                        remaining_depth - 1,
                        branching_factor,
                        current_level + 1,
                        child_node_id,
                        &child_cancel_token,
                        &child_status_sender,
                    )
                    .await
                });

                child_handles.push(child_handle);
            }

            // Simulate work at current node
            let work_result = timeout(
                Duration::from_millis(100),
                self.simulate_task_work(current_level),
            )
            .await;

            match work_result {
                Outcome::Ok(()) => {
                    let _ = status_sender.send(TaskStatus::Completed).await;
                }
                _ => {
                    // Cancelled or timeout
                }
            }

            // Wait for all children to complete
            for handle in child_handles {
                let _ = handle.await;
            }

            let _ = cancel_monitor.await;
            Ok(())
        })
        .await
    }

    /// Test deep nesting cancel propagation under stress
    async fn test_deep_nesting_cancel(
        &self,
        cx: &Cx,
        depth: usize,
    ) -> Result<CancelOperation, AsupersyncError> {
        self.logger.log_phase("deep_nesting_cancel_start");

        let cancel_token = CancelToken::new();
        let (completion_sender, mut completion_receiver) = mpsc::unbounded();

        // Create deeply nested scope chain
        let nesting_handle = cx.spawn(async move {
            self.create_deep_nested_scopes(cx, depth, 0, &cancel_token, &completion_sender)
                .await
        });

        // Wait for deep nesting to establish
        sleep(Duration::from_millis(depth as u64 * 10)).await;

        // Send cancel signal and measure propagation time
        let cancel_start = Instant::now();
        cancel_token.cancel(CancelReason::Timeout);
        self.stats
            .cancel_signals_sent
            .fetch_add(1, Ordering::Relaxed);

        // Wait for completion notifications
        let mut completed_levels = 0;
        while let Some(level) = completion_receiver.recv().await {
            completed_levels += 1;
            if completed_levels >= depth {
                break;
            }
        }

        let _ = nesting_handle.await;
        let propagation_latency = cancel_start.elapsed().as_nanos() as u64;

        self.stats
            .cancel_propagation_depth
            .store(depth as u64, Ordering::Relaxed);
        self.stats
            .max_nesting_level
            .store(depth as u64, Ordering::Relaxed);

        self.logger
            .log_operation("deep_nesting", depth as u64, depth as u64, completed_levels);

        Ok(CancelOperation {
            operation_type: CancelOperationType::DeepNesting,
            scope_tree_depth: depth as u64,
            tasks_in_hierarchy: depth as u64,
            cancel_propagation_latency_ns: propagation_latency,
            cancellation_success_rate: completed_levels as f64 / depth as f64,
            orphaned_task_count: depth as u64 - completed_levels,
        })
    }

    /// Create deeply nested scopes for cancel propagation testing
    async fn create_deep_nested_scopes(
        &self,
        cx: &Cx,
        remaining_depth: usize,
        current_level: usize,
        cancel_token: &CancelToken,
        completion_sender: &mpsc::UnboundedSender<u64>,
    ) -> Result<(), AsupersyncError> {
        if remaining_depth == 0 {
            return Ok(());
        }

        cancel_scope(cx, |nested_cx| async move {
            self.stats.scopes_created.fetch_add(1, Ordering::Relaxed);
            self.stats.tasks_spawned.fetch_add(1, Ordering::Relaxed);

            // Monitor for cancel at this level
            let level_cancel_token = cancel_token.clone();
            let level_completion_sender = completion_sender.clone();
            let level = current_level as u64;

            let cancel_monitor = nested_cx.spawn(async move {
                level_cancel_token.cancelled().await;
                self.stats
                    .cancel_signals_received
                    .fetch_add(1, Ordering::Relaxed);
                let _ = level_completion_sender.send(level).await;
            });

            // Continue to next level of nesting
            if remaining_depth > 1 {
                self.create_deep_nested_scopes(
                    nested_cx,
                    remaining_depth - 1,
                    current_level + 1,
                    cancel_token,
                    completion_sender,
                )
                .await?;
            }

            // Simulate work that can be cancelled
            let work_result = race!(self.simulate_task_work(current_level), async {
                cancel_token.cancelled().await;
                Err(AsupersyncError::from("cancelled"))
            })
            .await;

            let _ = cancel_monitor.await;
            Ok(())
        })
        .await
    }

    /// Test concurrent cancel operations on shared hierarchy
    async fn test_concurrent_cancel_operations(
        &self,
        cx: &Cx,
        concurrent_cancels: usize,
    ) -> Result<CancelOperation, AsupersyncError> {
        self.logger.log_phase("concurrent_cancel_start");

        let cancel_token = CancelToken::new();
        let (result_sender, mut result_receiver) = mpsc::unbounded();

        // Create shared task hierarchy
        let hierarchy_handle = cx.spawn(async move {
            self.create_shared_hierarchy_for_concurrent_cancel(
                cx,
                5, // 5 levels deep
                &cancel_token,
                &result_sender,
            )
            .await
        });

        // Wait for hierarchy to establish
        sleep(Duration::from_millis(100)).await;

        // Launch multiple concurrent cancel operations
        let mut cancel_handles = Vec::new();
        let cancel_start = Instant::now();

        for i in 0..concurrent_cancels {
            let token = cancel_token.clone();
            let handle = cx.spawn(async move {
                // Stagger the cancel requests slightly
                sleep(Duration::from_millis(i as u64 * 5)).await;
                token.cancel(CancelReason::UserRequested);
                i
            });
            cancel_handles.push(handle);
        }

        // Wait for all cancel operations to complete
        for handle in cancel_handles {
            let _ = handle.await;
            self.stats
                .cancel_signals_sent
                .fetch_add(1, Ordering::Relaxed);
        }

        // Collect results from hierarchy
        let mut total_results = 0;
        let mut cancelled_results = 0;

        while let Some(result) = result_receiver.recv().await {
            total_results += 1;
            if result {
                cancelled_results += 1;
                self.stats
                    .cancel_signals_received
                    .fetch_add(1, Ordering::Relaxed);
            }
        }

        let _ = hierarchy_handle.await;
        let propagation_latency = cancel_start.elapsed().as_nanos() as u64;

        self.stats
            .cancel_latency_total_ns
            .fetch_add(propagation_latency, Ordering::Relaxed);

        let success_rate = if total_results > 0 {
            cancelled_results as f64 / total_results as f64
        } else {
            0.0
        };

        self.logger.log_operation(
            "concurrent_cancel",
            concurrent_cancels as u64,
            total_results,
            cancelled_results,
        );

        Ok(CancelOperation {
            operation_type: CancelOperationType::ConcurrentCancel,
            scope_tree_depth: 5,
            tasks_in_hierarchy: total_results,
            cancel_propagation_latency_ns: propagation_latency,
            cancellation_success_rate: success_rate,
            orphaned_task_count: total_results - cancelled_results,
        })
    }

    /// Create shared hierarchy for concurrent cancel testing
    async fn create_shared_hierarchy_for_concurrent_cancel(
        &self,
        cx: &Cx,
        levels: usize,
        cancel_token: &CancelToken,
        result_sender: &mpsc::UnboundedSender<bool>,
    ) -> Result<(), AsupersyncError> {
        let tasks_per_level = 3;
        let mut level_handles = Vec::new();

        for level in 0..levels {
            for task in 0..tasks_per_level {
                let token = cancel_token.clone();
                let sender = result_sender.clone();
                let task_id = level * tasks_per_level + task;

                let handle = cx.spawn(async move {
                    self.stats.tasks_spawned.fetch_add(1, Ordering::Relaxed);

                    // Wait for either work completion or cancellation
                    let result = race!(self.simulate_task_work(task_id), async {
                        token.cancelled().await;
                        Err(AsupersyncError::from("cancelled"))
                    })
                    .await;

                    let was_cancelled = result.is_err();
                    let _ = sender.send(was_cancelled).await;
                    was_cancelled
                });

                level_handles.push(handle);
            }
        }

        // Wait for all tasks to complete
        for handle in level_handles {
            let _ = handle.await;
        }

        Ok(())
    }

    /// Simulate task work with variable duration
    async fn simulate_task_work(&self, task_id: usize) -> Result<(), AsupersyncError> {
        let work_duration = Duration::from_millis(50 + (task_id as u64 * 25) % 200);
        sleep(work_duration).await;
        Ok(())
    }

    /// Get comprehensive cancel propagation statistics summary
    fn get_stats_summary(&self) -> CancelE2EStatsSummary {
        let total_signals = self.stats.cancel_signals_sent.load(Ordering::Relaxed);
        let received_signals = self.stats.cancel_signals_received.load(Ordering::Relaxed);

        CancelE2EStatsSummary {
            total_scopes_created: self.stats.scopes_created.load(Ordering::Relaxed),
            total_tasks_spawned: self.stats.tasks_spawned.load(Ordering::Relaxed),
            total_cancel_signals_sent: total_signals,
            total_cancel_signals_received: received_signals,
            graceful_cancellations: self.stats.graceful_cancellations.load(Ordering::Relaxed),
            forced_cancellations: self.stats.forced_cancellations.load(Ordering::Relaxed),
            max_propagation_depth: self.stats.cancel_propagation_depth.load(Ordering::Relaxed),
            max_nesting_level: self.stats.max_nesting_level.load(Ordering::Relaxed),
            average_propagation_latency_ns: {
                let total_latency = self.stats.cancel_latency_total_ns.load(Ordering::Relaxed);
                if total_signals > 0 {
                    total_latency / total_signals
                } else {
                    0
                }
            },
            tasks_completed_before_cancel: self
                .stats
                .tasks_completed_before_cancel
                .load(Ordering::Relaxed),
            orphaned_tasks: self.stats.orphaned_tasks.load(Ordering::Relaxed),
            propagation_success_rate: {
                if total_signals > 0 {
                    received_signals as f64 / total_signals as f64
                } else {
                    0.0
                }
            },
        }
    }
}

/// Task status for hierarchy tracking
#[cfg(all(test, feature = "real-service-e2e"))]
#[derive(Debug, Clone)]
enum TaskStatus {
    Created,
    CancelReceived,
    Completed,
}

#[cfg(all(test, feature = "real-service-e2e"))]
impl CancelE2ELogger {
    fn new(test_id: &str, component: &str) -> Self {
        Self {
            test_id: test_id.to_string(),
            component: component.to_string(),
        }
    }

    fn log_phase(&self, phase: &str) {
        eprintln!(
            "{{\"ts\":\"{}\",\"test_id\":\"{}\",\"component\":\"{}\",\"event\":\"phase_change\",\"phase\":\"{}\"}}",
            chrono::Utc::now().to_rfc3339(),
            self.test_id,
            self.component,
            phase
        );
    }

    fn log_operation(
        &self,
        operation_type: &str,
        depth: u64,
        total_nodes: u64,
        cancelled_nodes: u64,
    ) {
        eprintln!(
            "{{\"ts\":\"{}\",\"test_id\":\"{}\",\"component\":\"{}\",\"event\":\"cancel_operation\",\"operation_type\":\"{}\",\"depth\":{},\"total_nodes\":{},\"cancelled_nodes\":{}}}",
            chrono::Utc::now().to_rfc3339(),
            self.test_id,
            self.component,
            operation_type,
            depth,
            total_nodes,
            cancelled_nodes
        );
    }

    fn log_stats_summary(&self, stats: &CancelE2EStatsSummary) {
        eprintln!(
            "{{\"ts\":\"{}\",\"test_id\":\"{}\",\"component\":\"{}\",\"event\":\"stats_summary\",\"data\":{}}}",
            chrono::Utc::now().to_rfc3339(),
            self.test_id,
            self.component,
            serde_json::to_string(stats).unwrap_or_else(|_| "{}".to_string())
        );
    }
}

/// Cancel E2E statistics summary
#[cfg(all(test, feature = "real-service-e2e"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CancelE2EStatsSummary {
    total_scopes_created: u64,
    total_tasks_spawned: u64,
    total_cancel_signals_sent: u64,
    total_cancel_signals_received: u64,
    graceful_cancellations: u64,
    forced_cancellations: u64,
    max_propagation_depth: u64,
    max_nesting_level: u64,
    average_propagation_latency_ns: u64,
    tasks_completed_before_cancel: u64,
    orphaned_tasks: u64,
    propagation_success_rate: f64,
}

/// Default cancel E2E test configuration
#[cfg(all(test, feature = "real-service-e2e"))]
impl Default for CancelE2EConfig {
    fn default() -> Self {
        Self {
            max_nesting_depth: 5,
            tasks_per_level: 2,
            cancel_delay_ms: 100,
            graceful_timeout_ms: 500,
            tree_branching_factor: 3,
        }
    }
}

/// Production safety guard for cancel propagation E2E tests
#[cfg(all(test, feature = "real-service-e2e"))]
fn validate_cancel_e2e_environment() -> Result<(), &'static str> {
    if std::env::var("CANCEL_E2E_TESTS").unwrap_or_default() != "true" {
        return Err("CANCEL_E2E_TESTS environment variable must be set to 'true'");
    }

    let max_nesting = std::env::var("MAX_CANCEL_NESTING_DEPTH")
        .unwrap_or_else(|_| "20".to_string())
        .parse::<usize>()
        .map_err(|_| "Invalid MAX_CANCEL_NESTING_DEPTH")?;

    if max_nesting > 50 {
        return Err("Cancel tests must limit nesting depth to 50 or less");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linear_hierarchy_cancel_propagation() {
        std::env::set_var("CANCEL_E2E_TESTS", "true");
        validate_cancel_e2e_environment().expect("Environment validation failed");

        let runtime = RuntimeBuilder::new()
            .with_name("cancel-e2e-linear-test")
            .build();

        runtime.block_on(async {
            let manager = RealCancelManager::new("linear-test");
            let cx = Cx::root();

            let operation = manager
                .test_linear_hierarchy_cancel(&cx, 5)
                .await
                .expect("Linear hierarchy cancel should succeed");

            assert_eq!(
                operation.operation_type,
                CancelOperationType::LinearHierarchy
            );
            assert_eq!(operation.scope_tree_depth, 5);
            assert!(
                operation.cancellation_success_rate >= 0.8,
                "Cancellation success rate should be at least 80%, got: {:.2}%",
                operation.cancellation_success_rate * 100.0
            );
            assert!(
                operation.cancel_propagation_latency_ns < 100_000_000, // < 100ms
                "Cancel propagation latency should be under 100ms, got: {} ns ({:.2} ms)",
                operation.cancel_propagation_latency_ns,
                operation.cancel_propagation_latency_ns as f64 / 1_000_000.0
            );

            let stats = manager.get_stats_summary();
            assert!(stats.total_scopes_created >= 5);
            assert!(stats.total_tasks_spawned >= 5);
            assert!(stats.propagation_success_rate >= 0.8);
            manager.logger.log_stats_summary(&stats);
        });
    }

    #[test]
    fn test_tree_hierarchy_cancel_propagation() {
        std::env::set_var("CANCEL_E2E_TESTS", "true");
        validate_cancel_e2e_environment().expect("Environment validation failed");

        let runtime = RuntimeBuilder::new()
            .with_name("cancel-e2e-tree-test")
            .build();

        runtime.block_on(async {
            let manager = RealCancelManager::new("tree-test");
            let cx = Cx::root();

            let config = CancelE2EConfig {
                max_nesting_depth: 3,
                tree_branching_factor: 3,
                ..CancelE2EConfig::default()
            };

            let operation = manager
                .test_tree_hierarchy_cancel(&cx, &config)
                .await
                .expect("Tree hierarchy cancel should succeed");

            assert_eq!(operation.operation_type, CancelOperationType::TreeHierarchy);
            assert_eq!(operation.scope_tree_depth, 3);
            assert!(operation.cancellation_success_rate >= 0.7);

            let stats = manager.get_stats_summary();
            assert!(stats.total_scopes_created >= 9); // 3^3 tree nodes
            assert!(stats.propagation_success_rate >= 0.7);
            manager.logger.log_stats_summary(&stats);
        });
    }

    #[test]
    fn test_deep_nesting_cancel_propagation() {
        std::env::set_var("CANCEL_E2E_TESTS", "true");
        validate_cancel_e2e_environment().expect("Environment validation failed");

        let runtime = RuntimeBuilder::new()
            .with_name("cancel-e2e-deep-test")
            .build();

        runtime.block_on(async {
            let manager = RealCancelManager::new("deep-test");
            let cx = Cx::root();

            let operation = manager
                .test_deep_nesting_cancel(&cx, 10)
                .await
                .expect("Deep nesting cancel should succeed");

            assert_eq!(operation.operation_type, CancelOperationType::DeepNesting);
            assert_eq!(operation.scope_tree_depth, 10);
            assert!(operation.cancellation_success_rate >= 0.8);
            assert!(operation.cancel_propagation_latency_ns < 200_000_000); // < 200ms

            let stats = manager.get_stats_summary();
            assert_eq!(stats.max_nesting_level, 10);
            assert_eq!(stats.max_propagation_depth, 10);
            manager.logger.log_stats_summary(&stats);
        });
    }

    #[test]
    fn test_concurrent_cancel_operations() {
        std::env::set_var("CANCEL_E2E_TESTS", "true");
        validate_cancel_e2e_environment().expect("Environment validation failed");

        let runtime = RuntimeBuilder::new()
            .with_name("cancel-e2e-concurrent-test")
            .build();

        runtime.block_on(async {
            let manager = RealCancelManager::new("concurrent-test");
            let cx = Cx::root();

            let operation = manager
                .test_concurrent_cancel_operations(&cx, 3)
                .await
                .expect("Concurrent cancel operations should succeed");

            assert_eq!(
                operation.operation_type,
                CancelOperationType::ConcurrentCancel
            );
            assert!(operation.cancellation_success_rate >= 0.7);

            let stats = manager.get_stats_summary();
            assert_eq!(stats.total_cancel_signals_sent, 3);
            assert!(stats.propagation_success_rate >= 0.7);
            manager.logger.log_stats_summary(&stats);
        });
    }

    #[test]
    fn test_comprehensive_cancel_scenario() {
        std::env::set_var("CANCEL_E2E_TESTS", "true");
        validate_cancel_e2e_environment().expect("Environment validation failed");

        let runtime = RuntimeBuilder::new()
            .with_name("cancel-e2e-comprehensive-test")
            .build();

        runtime.block_on(async {
            let manager = RealCancelManager::new("comprehensive-test");
            let cx = Cx::root();

            // Run multiple cancel propagation scenarios
            let mut all_operations = Vec::new();

            // 1. Linear hierarchy
            let linear_op = manager
                .test_linear_hierarchy_cancel(&cx, 4)
                .await
                .expect("Linear hierarchy should succeed");
            all_operations.push(linear_op);

            // 2. Tree hierarchy
            let config = CancelE2EConfig {
                max_nesting_depth: 3,
                tree_branching_factor: 2,
                ..CancelE2EConfig::default()
            };
            let tree_op = manager
                .test_tree_hierarchy_cancel(&cx, &config)
                .await
                .expect("Tree hierarchy should succeed");
            all_operations.push(tree_op);

            // 3. Deep nesting
            let deep_op = manager
                .test_deep_nesting_cancel(&cx, 8)
                .await
                .expect("Deep nesting should succeed");
            all_operations.push(deep_op);

            // 4. Concurrent cancels
            let concurrent_op = manager
                .test_concurrent_cancel_operations(&cx, 2)
                .await
                .expect("Concurrent cancels should succeed");
            all_operations.push(concurrent_op);

            // Validate comprehensive results
            assert_eq!(all_operations.len(), 4);

            for operation in &all_operations {
                assert!(operation.cancellation_success_rate >= 0.6);
                assert!(operation.cancel_propagation_latency_ns < 500_000_000); // < 500ms
            }

            let stats = manager.get_stats_summary();
            assert!(stats.total_scopes_created >= 20);
            assert!(stats.total_tasks_spawned >= 15);
            assert!(stats.propagation_success_rate >= 0.6);
            manager.logger.log_stats_summary(&stats);
        });
    }

    #[test]
    fn test_production_safety_guards() {
        // Test without CANCEL_E2E_TESTS environment variable
        std::env::remove_var("CANCEL_E2E_TESTS");
        assert!(validate_cancel_e2e_environment().is_err());

        // Test with excessive nesting depth
        std::env::set_var("CANCEL_E2E_TESTS", "true");
        std::env::set_var("MAX_CANCEL_NESTING_DEPTH", "100");
        assert!(validate_cancel_e2e_environment().is_err());

        // Test valid configuration
        std::env::set_var("MAX_CANCEL_NESTING_DEPTH", "20");
        assert!(validate_cancel_e2e_environment().is_ok());
    }
}
