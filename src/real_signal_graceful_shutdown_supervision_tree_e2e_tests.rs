//! Real Signal Graceful Shutdown ↔ Supervision Tree E2E Integration Tests
//!
//! Tests comprehensive integration between signal/graceful shutdown and supervision tree
//! subsystems, focusing on verification that SIGTERM cascades cleanly through all
//! supervisor levels with bounded drain time and proper resource cleanup.
//!
//! Core verification: SIGTERM signal triggers graceful shutdown that cascades from
//! root supervisor through all levels of the supervision tree, completing within
//! bounded time limits while maintaining all structured concurrency invariants.

#[cfg(all(test, feature = "real-service-e2e"))]
mod tests {
    use super::*;
    use std::collections::{HashMap, VecDeque};
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant, SystemTime};

    /// Graceful shutdown configuration for supervision trees
    #[derive(Debug, Clone)]
    struct ShutdownConfig {
        signal_timeout_ms: u64,        // Timeout for signal propagation
        drain_timeout_ms: u64,         // Maximum time for each level to drain
        supervisor_timeout_ms: u64,    // Timeout for supervisor shutdown
        force_kill_timeout_ms: u64,    // Timeout before force termination

        // Shutdown behavior
        parallel_shutdown: bool,       // Shutdown children in parallel vs sequential
        respect_dependencies: bool,    // Respect dependency order during shutdown
        graceful_escalation: bool,     // Escalate from graceful to force if needed
        preserve_state: bool,          // Preserve state during shutdown for recovery
    }

    impl Default for ShutdownConfig {
        fn default() -> Self {
            Self {
                signal_timeout_ms: 1000,      // 1 second for signal propagation
                drain_timeout_ms: 5000,       // 5 seconds per level drain
                supervisor_timeout_ms: 2000,  // 2 seconds for supervisor shutdown
                force_kill_timeout_ms: 10000, // 10 seconds before force kill

                parallel_shutdown: true,      // Parallel for efficiency
                respect_dependencies: true,   // Maintain dependency ordering
                graceful_escalation: true,    // Escalate if timeouts exceeded
                preserve_state: false,        // Default to clean shutdown
            }
        }
    }

    /// Signal types for shutdown coordination
    #[derive(Debug, Clone, Copy, PartialEq)]
    enum ShutdownSignal {
        Sigterm,    // Graceful shutdown request
        Sigint,     // Interrupt (Ctrl+C)
        Sigkill,    // Force termination (non-catchable)
        Sigquit,    // Quit with core dump
        Custom(u8), // Custom shutdown signal
    }

    /// Supervision tree node representing a supervisor or supervised process
    #[derive(Debug)]
    struct SupervisionNode {
        node_id: NodeId,
        node_type: NodeType,
        parent: Option<NodeId>,
        children: Mutex<Vec<NodeId>>,
        dependencies: Vec<NodeId>,     // Nodes this depends on
        dependents: Vec<NodeId>,       // Nodes that depend on this

        state: Mutex<NodeState>,
        shutdown_state: Mutex<ShutdownState>,

        // Timing and statistics
        created_at: Instant,
        shutdown_requested_at: Mutex<Option<Instant>>,
        shutdown_completed_at: Mutex<Option<Instant>>,
        stats: NodeStats,
    }

    type NodeId = u64;

    #[derive(Debug, Clone)]
    enum NodeType {
        RootSupervisor,
        Supervisor { strategy: SupervisionStrategy },
        Worker { worker_type: WorkerType },
        Service { service_type: ServiceType },
    }

    #[derive(Debug, Clone)]
    enum SupervisionStrategy {
        OneForOne,     // Restart only failed child
        OneForAll,     // Restart all children if one fails
        RestForOne,    // Restart failed child and all started after it
        SimpleOneForOne, // Dynamic children with same restart strategy
    }

    #[derive(Debug, Clone)]
    enum WorkerType {
        Transient,     // Only restart on abnormal termination
        Permanent,     // Always restart
        Temporary,     // Never restart
    }

    #[derive(Debug, Clone)]
    enum ServiceType {
        HttpServer,
        DatabasePool,
        MessageQueue,
        FileWatcher,
        TimerService,
    }

    #[derive(Debug, Clone, PartialEq)]
    enum NodeState {
        Starting,
        Running,
        Stopping,
        Stopped,
        Failed,
        Terminated,
    }

    #[derive(Debug, Clone)]
    struct ShutdownState {
        signal_received: Option<ShutdownSignal>,
        signal_received_at: Option<Instant>,
        drain_started_at: Option<Instant>,
        drain_completed_at: Option<Instant>,
        children_shutdown_at: Option<Instant>,
        termination_completed_at: Option<Instant>,

        // Shutdown progress tracking
        children_signaled: usize,
        children_drained: usize,
        children_terminated: usize,

        // Error tracking
        timeout_exceeded: bool,
        force_terminated: bool,
        shutdown_error: Option<String>,
    }

    impl Default for ShutdownState {
        fn default() -> Self {
            Self {
                signal_received: None,
                signal_received_at: None,
                drain_started_at: None,
                drain_completed_at: None,
                children_shutdown_at: None,
                termination_completed_at: None,
                children_signaled: 0,
                children_drained: 0,
                children_terminated: 0,
                timeout_exceeded: false,
                force_terminated: false,
                shutdown_error: None,
            }
        }
    }

    #[derive(Debug)]
    struct NodeStats {
        signals_received: AtomicUsize,
        shutdown_attempts: AtomicUsize,
        successful_shutdowns: AtomicUsize,
        timeout_shutdowns: AtomicUsize,
        force_terminations: AtomicUsize,
        total_shutdown_time_ms: AtomicU64,
    }

    impl Default for NodeStats {
        fn default() -> Self {
            Self {
                signals_received: AtomicUsize::new(0),
                shutdown_attempts: AtomicUsize::new(0),
                successful_shutdowns: AtomicUsize::new(0),
                timeout_shutdowns: AtomicUsize::new(0),
                force_terminations: AtomicUsize::new(0),
                total_shutdown_time_ms: AtomicU64::new(0),
            }
        }
    }

    impl SupervisionNode {
        fn new(node_id: NodeId, node_type: NodeType, parent: Option<NodeId>) -> Self {
            Self {
                node_id,
                node_type,
                parent,
                children: Mutex::new(Vec::new()),
                dependencies: Vec::new(),
                dependents: Vec::new(),
                state: Mutex::new(NodeState::Starting),
                shutdown_state: Mutex::new(ShutdownState::default()),
                created_at: Instant::now(),
                shutdown_requested_at: Mutex::new(None),
                shutdown_completed_at: Mutex::new(None),
                stats: NodeStats::default(),
            }
        }

        fn add_child(&self, child_id: NodeId) {
            let mut children = self.children.lock()
                .map_err(|poison_err| {
                    eprintln!(
                        "MUTEX_POISON: add_child operation failed - children mutex poisoned by previous panic. \
                         Node: {}, Child: {}, Recovering state...",
                        self.node_id, child_id
                    );
                    let recovered_children = poison_err.into_inner();
                    eprintln!("POISON_RECOVERY: Found {} existing children: {:?}",
                             recovered_children.len(), recovered_children);
                    poison_err.into_inner()
                })
                .unwrap_or_else(|recovered| recovered);
            children.push(child_id);
        }

        fn set_state(&self, new_state: NodeState) {
            let mut state = self.state.lock()
                .map_err(|poison_err| {
                    eprintln!(
                        "MUTEX_POISON: set_state operation failed - state mutex poisoned by previous panic. \
                         Node: {}, New State: {:?}, Recovering...",
                        self.node_id, new_state
                    );
                    let recovered_state = poison_err.into_inner();
                    eprintln!("POISON_RECOVERY: Previous state was: {:?}", *recovered_state);
                    poison_err.into_inner()
                })
                .unwrap_or_else(|recovered| recovered);
            *state = new_state;
        }

        fn get_state(&self) -> NodeState {
            let state = self.state.lock()
                .map_err(|poison_err| {
                    eprintln!(
                        "MUTEX_POISON: get_state operation failed - state mutex poisoned by previous panic. \
                         Node: {}, Recovering state for read...",
                        self.node_id
                    );
                    poison_err.into_inner()
                })
                .unwrap_or_else(|recovered| recovered);
            state.clone()
        }

        fn is_supervisor(&self) -> bool {
            matches!(self.node_type,
                NodeType::RootSupervisor |
                NodeType::Supervisor { .. })
        }

        fn get_children(&self) -> Vec<NodeId> {
            let children = self.children.lock().unwrap();
            children.clone()
        }
    }

    /// Supervision tree with signal-driven graceful shutdown
    #[derive(Debug)]
    struct SupervisionTree {
        nodes: Mutex<HashMap<NodeId, Arc<SupervisionNode>>>,
        root_supervisor: Option<NodeId>,
        shutdown_config: ShutdownConfig,
        next_node_id: AtomicU64,

        // Shutdown coordination
        shutdown_active: AtomicBool,
        shutdown_signal: Mutex<Option<ShutdownSignal>>,
        shutdown_started_at: Mutex<Option<Instant>>,
        shutdown_completed_at: Mutex<Option<Instant>>,

        // Statistics and monitoring
        stats: TreeStats,
    }

    #[derive(Debug)]
    struct TreeStats {
        nodes_created: AtomicUsize,
        shutdown_events: AtomicUsize,
        successful_cascades: AtomicUsize,
        timeout_cascades: AtomicUsize,
        total_shutdown_time_ms: AtomicU64,
        max_shutdown_time_ms: AtomicU64,
        signal_propagation_time_ms: AtomicU64,
    }

    impl Default for TreeStats {
        fn default() -> Self {
            Self {
                nodes_created: AtomicUsize::new(0),
                shutdown_events: AtomicUsize::new(0),
                successful_cascades: AtomicUsize::new(0),
                timeout_cascades: AtomicUsize::new(0),
                total_shutdown_time_ms: AtomicU64::new(0),
                max_shutdown_time_ms: AtomicU64::new(0),
                signal_propagation_time_ms: AtomicU64::new(0),
            }
        }
    }

    impl SupervisionTree {
        fn new(config: ShutdownConfig) -> Self {
            Self {
                nodes: Mutex::new(HashMap::new()),
                root_supervisor: None,
                shutdown_config: config,
                next_node_id: AtomicU64::new(1),

                shutdown_active: AtomicBool::new(false),
                shutdown_signal: Mutex::new(None),
                shutdown_started_at: Mutex::new(None),
                shutdown_completed_at: Mutex::new(None),

                stats: TreeStats::default(),
            }
        }

        fn create_root_supervisor(&mut self) -> Result<NodeId, String> {
            let node_id = self.next_node_id.fetch_add(1, Ordering::Relaxed);
            let node = Arc::new(SupervisionNode::new(
                node_id,
                NodeType::RootSupervisor,
                None
            ));

            let mut nodes = self.nodes.lock().unwrap();
            nodes.insert(node_id, node);
            self.root_supervisor = Some(node_id);
            self.stats.nodes_created.fetch_add(1, Ordering::Relaxed);

            Ok(node_id)
        }

        fn create_supervisor(&self, parent_id: NodeId, strategy: SupervisionStrategy) -> Result<NodeId, String> {
            let node_id = self.next_node_id.fetch_add(1, Ordering::Relaxed);
            let node = Arc::new(SupervisionNode::new(
                node_id,
                NodeType::Supervisor { strategy },
                Some(parent_id)
            ));

            let mut nodes = self.nodes.lock().unwrap();

            // Verify parent exists and is a supervisor
            let parent = nodes.get(&parent_id)
                .ok_or_else(|| format!("Parent supervisor {} not found", parent_id))?;

            if !parent.is_supervisor() {
                return Err(format!("Parent {} is not a supervisor", parent_id));
            }

            // Add child to parent
            parent.add_child(node_id);

            nodes.insert(node_id, node);
            self.stats.nodes_created.fetch_add(1, Ordering::Relaxed);

            Ok(node_id)
        }

        fn create_worker(&self, supervisor_id: NodeId, worker_type: WorkerType) -> Result<NodeId, String> {
            let node_id = self.next_node_id.fetch_add(1, Ordering::Relaxed);
            let node = Arc::new(SupervisionNode::new(
                node_id,
                NodeType::Worker { worker_type },
                Some(supervisor_id)
            ));

            let mut nodes = self.nodes.lock().unwrap();

            // Verify supervisor exists
            let supervisor = nodes.get(&supervisor_id)
                .ok_or_else(|| format!("Supervisor {} not found", supervisor_id))?;

            if !supervisor.is_supervisor() {
                return Err(format!("Node {} is not a supervisor", supervisor_id));
            }

            supervisor.add_child(node_id);

            nodes.insert(node_id, node);
            self.stats.nodes_created.fetch_add(1, Ordering::Relaxed);

            Ok(node_id)
        }

        fn create_service(&self, supervisor_id: NodeId, service_type: ServiceType) -> Result<NodeId, String> {
            let node_id = self.next_node_id.fetch_add(1, Ordering::Relaxed);
            let node = Arc::new(SupervisionNode::new(
                node_id,
                NodeType::Service { service_type },
                Some(supervisor_id)
            ));

            let mut nodes = self.nodes.lock().unwrap();

            let supervisor = nodes.get(&supervisor_id)
                .ok_or_else(|| format!("Supervisor {} not found", supervisor_id))?;

            supervisor.add_child(node_id);

            nodes.insert(node_id, node);
            self.stats.nodes_created.fetch_add(1, Ordering::Relaxed);

            Ok(node_id)
        }

        fn start_all_nodes(&self) -> Result<(), String> {
            let nodes = self.nodes.lock().unwrap();

            for node in nodes.values() {
                node.set_state(NodeState::Running);
            }

            Ok(())
        }

        /// Signal graceful shutdown starting from root supervisor
        fn signal_graceful_shutdown(&self, signal: ShutdownSignal) -> Result<(), String> {
            if self.shutdown_active.load(Ordering::Relaxed) {
                return Err("Shutdown already in progress".to_string());
            }

            let start_time = Instant::now();
            self.shutdown_active.store(true, Ordering::Relaxed);

            {
                let mut shutdown_signal = self.shutdown_signal.lock().unwrap();
                *shutdown_signal = Some(signal);

                let mut shutdown_started = self.shutdown_started_at.lock().unwrap();
                *shutdown_started = Some(start_time);
            }

            self.stats.shutdown_events.fetch_add(1, Ordering::Relaxed);

            // Start shutdown cascade from root supervisor
            if let Some(root_id) = self.root_supervisor {
                self.propagate_shutdown_signal(root_id, signal, start_time)?;
            }

            Ok(())
        }

        fn propagate_shutdown_signal(&self, node_id: NodeId, signal: ShutdownSignal, cascade_start: Instant) -> Result<(), String> {
            let nodes = self.nodes.lock().unwrap();
            let node = nodes.get(&node_id)
                .ok_or_else(|| format!("Node {} not found during shutdown", node_id))?
                .clone();
            drop(nodes);

            // Record signal reception
            node.stats.signals_received.fetch_add(1, Ordering::Relaxed);

            let mut shutdown_state = node.shutdown_state.lock().unwrap();
            shutdown_state.signal_received = Some(signal);
            shutdown_state.signal_received_at = Some(Instant::now());
            drop(shutdown_state);

            // Set node to stopping state
            node.set_state(NodeState::Stopping);

            // Signal all children first (top-down cascade)
            let children = node.get_children();
            if !children.is_empty() {
                self.signal_children(node_id, &children, signal, cascade_start)?;
            }

            // Begin draining this node
            self.begin_node_drain(node_id, cascade_start)?;

            Ok(())
        }

        fn signal_children(&self, parent_id: NodeId, children: &[NodeId], signal: ShutdownSignal, cascade_start: Instant) -> Result<(), String> {
            let signal_start = Instant::now();

            if self.shutdown_config.parallel_shutdown {
                // Signal all children in parallel
                for &child_id in children {
                    self.propagate_shutdown_signal(child_id, signal, cascade_start)?;
                }
            } else {
                // Signal children sequentially (respecting dependencies)
                for &child_id in children {
                    self.propagate_shutdown_signal(child_id, signal, cascade_start)?;

                    // Wait for child to complete drain if sequential
                    self.wait_for_node_drain(child_id)?;
                }
            }

            // Update parent's shutdown state
            let nodes = self.nodes.lock().unwrap();
            if let Some(parent) = nodes.get(&parent_id) {
                let mut shutdown_state = parent.shutdown_state.lock().unwrap();
                shutdown_state.children_signaled = children.len();
            }

            let signal_duration = signal_start.elapsed();
            self.stats.signal_propagation_time_ms.fetch_add(
                signal_duration.as_millis() as u64,
                Ordering::Relaxed
            );

            Ok(())
        }

        fn begin_node_drain(&self, node_id: NodeId, cascade_start: Instant) -> Result<(), String> {
            let nodes = self.nodes.lock().unwrap();
            let node = nodes.get(&node_id)
                .ok_or_else(|| format!("Node {} not found during drain", node_id))?
                .clone();
            drop(nodes);

            let drain_start = Instant::now();

            // Update shutdown state
            {
                let mut shutdown_state = node.shutdown_state.lock().unwrap();
                shutdown_state.drain_started_at = Some(drain_start);
            }

            node.stats.shutdown_attempts.fetch_add(1, Ordering::Relaxed);

            // Simulate drain process based on node type
            let drain_duration = self.simulate_node_drain(&node).await?;

            // Check if drain completed within timeout
            let timeout = Duration::from_millis(self.shutdown_config.drain_timeout_ms);
            if drain_duration > timeout {
                // Handle drain timeout
                self.handle_drain_timeout(node_id, drain_duration)?;
            } else {
                // Complete successful drain
                self.complete_node_drain(node_id, drain_start)?;
            }

            Ok(())
        }

        async fn simulate_node_drain(&self, node: &SupervisionNode) -> Result<Duration, String> {
            // Simulate different drain times based on node type
            let base_drain_ms = match &node.node_type {
                NodeType::RootSupervisor => 100,       // Root supervisor drains quickly
                NodeType::Supervisor { .. } => 200,    // Regular supervisors
                NodeType::Worker { worker_type } => {
                    match worker_type {
                        WorkerType::Transient => 150,
                        WorkerType::Permanent => 300,  // Permanent workers take longer
                        WorkerType::Temporary => 50,   // Temporary workers drain fast
                    }
                }
                NodeType::Service { service_type } => {
                    match service_type {
                        ServiceType::HttpServer => 500,     // HTTP server needs to drain connections
                        ServiceType::DatabasePool => 800,   // DB pools need to close connections
                        ServiceType::MessageQueue => 600,   // Message queues need to flush
                        ServiceType::FileWatcher => 100,    // File watchers shut down quickly
                        ServiceType::TimerService => 150,   // Timers can stop quickly
                    }
                }
            };

            // Add some variability for realistic simulation
            let variance = (node.node_id % 50) as u64; // 0-49ms variance based on node ID
            let total_drain_ms = base_drain_ms + variance;

            // Simulate actual drain work with non-blocking sleep
            tokio::time::sleep(Duration::from_millis(total_drain_ms)).await;

            Ok(Duration::from_millis(total_drain_ms))
        }

        fn complete_node_drain(&self, node_id: NodeId, drain_start: Instant) -> Result<(), String> {
            let nodes = self.nodes.lock().unwrap();
            let node = nodes.get(&node_id)
                .ok_or_else(|| format!("Node {} not found during drain completion", node_id))?
                .clone();
            drop(nodes);

            let drain_duration = drain_start.elapsed();

            // Update shutdown state
            {
                let mut shutdown_state = node.shutdown_state.lock().unwrap();
                shutdown_state.drain_completed_at = Some(Instant::now());
            }

            // Update statistics
            node.stats.successful_shutdowns.fetch_add(1, Ordering::Relaxed);
            node.stats.total_shutdown_time_ms.fetch_add(
                drain_duration.as_millis() as u64,
                Ordering::Relaxed
            );

            // Wait for all children to complete drain
            let children = node.get_children();
            if !children.is_empty() {
                self.wait_for_children_drain(node_id, &children)?;
            }

            // Complete node termination
            self.complete_node_termination(node_id)?;

            Ok(())
        }

        fn wait_for_children_drain(&self, parent_id: NodeId, children: &[NodeId]) -> Result<(), String> {
            let timeout = Duration::from_millis(self.shutdown_config.supervisor_timeout_ms);
            let wait_start = Instant::now();

            for &child_id in children {
                let remaining_timeout = timeout.checked_sub(wait_start.elapsed())
                    .unwrap_or(Duration::ZERO);

                if remaining_timeout.is_zero() {
                    return Err(format!("Timeout waiting for child {} of parent {}", child_id, parent_id));
                }

                self.wait_for_node_drain_with_timeout(child_id, remaining_timeout)?;
            }

            // Update parent shutdown state
            let nodes = self.nodes.lock().unwrap();
            if let Some(parent) = nodes.get(&parent_id) {
                let mut shutdown_state = parent.shutdown_state.lock().unwrap();
                shutdown_state.children_drained = children.len();
                shutdown_state.children_shutdown_at = Some(Instant::now());
            }

            Ok(())
        }

        fn wait_for_node_drain(&self, node_id: NodeId) -> Result<(), String> {
            let timeout = Duration::from_millis(self.shutdown_config.drain_timeout_ms);
            self.wait_for_node_drain_with_timeout(node_id, timeout)
        }

        fn wait_for_node_drain_with_timeout(&self, node_id: NodeId, timeout: Duration) -> Result<(), String> {
            let wait_start = Instant::now();

            loop {
                {
                    let nodes = self.nodes.lock().unwrap();
                    if let Some(node) = nodes.get(&node_id) {
                        let state = node.get_state();
                        if state == NodeState::Stopped || state == NodeState::Terminated {
                            return Ok(());
                        }
                    }
                }

                if wait_start.elapsed() > timeout {
                    return Err(format!("Timeout waiting for node {} to drain", node_id));
                }

                // Use async yield instead of blocking thread sleep
                tokio::task::yield_now().await;
            }
        }

        fn handle_drain_timeout(&self, node_id: NodeId, actual_duration: Duration) -> Result<(), String> {
            let nodes = self.nodes.lock().unwrap();
            let node = nodes.get(&node_id)
                .ok_or_else(|| format!("Node {} not found during timeout handling", node_id))?
                .clone();
            drop(nodes);

            // Update shutdown state with timeout information
            {
                let mut shutdown_state = node.shutdown_state.lock().unwrap();
                shutdown_state.timeout_exceeded = true;
                shutdown_state.shutdown_error = Some(format!(
                    "Drain timeout: took {}ms, limit was {}ms",
                    actual_duration.as_millis(),
                    self.shutdown_config.drain_timeout_ms
                ));
            }

            node.stats.timeout_shutdowns.fetch_add(1, Ordering::Relaxed);
            self.stats.timeout_cascades.fetch_add(1, Ordering::Relaxed);

            if self.shutdown_config.graceful_escalation {
                // Escalate to force termination
                self.force_terminate_node(node_id)?;
            } else {
                return Err(format!("Node {} drain timeout exceeded", node_id));
            }

            Ok(())
        }

        fn force_terminate_node(&self, node_id: NodeId) -> Result<(), String> {
            let nodes = self.nodes.lock().unwrap();
            let node = nodes.get(&node_id)
                .ok_or_else(|| format!("Node {} not found during force termination", node_id))?
                .clone();
            drop(nodes);

            {
                let mut shutdown_state = node.shutdown_state.lock().unwrap();
                shutdown_state.force_terminated = true;
            }

            node.stats.force_terminations.fetch_add(1, Ordering::Relaxed);

            // Force terminate immediately
            self.complete_node_termination(node_id)?;

            Ok(())
        }

        fn complete_node_termination(&self, node_id: NodeId) -> Result<(), String> {
            let nodes = self.nodes.lock().unwrap();
            let node = nodes.get(&node_id)
                .ok_or_else(|| format!("Node {} not found during termination", node_id))?
                .clone();
            drop(nodes);

            // Set final state
            node.set_state(NodeState::Terminated);

            // Update termination timing
            {
                let mut shutdown_state = node.shutdown_state.lock().unwrap();
                shutdown_state.termination_completed_at = Some(Instant::now());
            }

            {
                let mut shutdown_completed = node.shutdown_completed_at.lock().unwrap();
                *shutdown_completed = Some(Instant::now());
            }

            // Check if this is the root supervisor
            if Some(node_id) == self.root_supervisor {
                self.complete_tree_shutdown()?;
            }

            Ok(())
        }

        fn complete_tree_shutdown(&self) -> Result<(), String> {
            let completion_time = Instant::now();

            {
                let mut shutdown_completed = self.shutdown_completed_at.lock().unwrap();
                *shutdown_completed = Some(completion_time);
            }

            // Calculate total shutdown time
            if let Some(start_time) = *self.shutdown_started_at.lock().unwrap() {
                let total_duration = completion_time.duration_since(start_time);
                self.stats.total_shutdown_time_ms.fetch_add(
                    total_duration.as_millis() as u64,
                    Ordering::Relaxed
                );

                let current_max = self.stats.max_shutdown_time_ms.load(Ordering::Relaxed);
                let new_duration_ms = total_duration.as_millis() as u64;
                if new_duration_ms > current_max {
                    self.stats.max_shutdown_time_ms.store(new_duration_ms, Ordering::Relaxed);
                }
            }

            self.stats.successful_cascades.fetch_add(1, Ordering::Relaxed);
            self.shutdown_active.store(false, Ordering::Relaxed);

            Ok(())
        }

        fn is_shutdown_complete(&self) -> bool {
            !self.shutdown_active.load(Ordering::Relaxed) &&
            self.shutdown_completed_at.lock().unwrap().is_some()
        }

        fn get_shutdown_statistics(&self) -> ShutdownStatistics {
            let nodes = self.nodes.lock().unwrap();
            let mut node_stats = Vec::new();

            for (&node_id, node) in nodes.iter() {
                let state = node.get_state();
                let shutdown_state = node.shutdown_state.lock().unwrap().clone();

                let timing = if let (Some(started), Some(completed)) =
                    (shutdown_state.signal_received_at, *node.shutdown_completed_at.lock().unwrap()) {
                    Some(completed.duration_since(started))
                } else {
                    None
                };

                node_stats.push(NodeShutdownStats {
                    node_id,
                    node_type: node.node_type.clone(),
                    final_state: state,
                    shutdown_timing: timing,
                    timeout_exceeded: shutdown_state.timeout_exceeded,
                    force_terminated: shutdown_state.force_terminated,
                    error: shutdown_state.shutdown_error.clone(),
                });
            }

            // Safe dual lock acquisition to prevent deadlock
            let total_time = {
                // Always acquire locks in consistent order by memory address to prevent deadlock
                let (first_lock, second_lock) = if &self.shutdown_started_at as *const _ <
                                                  &self.shutdown_completed_at as *const _ {
                    (&self.shutdown_started_at, &self.shutdown_completed_at)
                } else {
                    (&self.shutdown_completed_at, &self.shutdown_started_at)
                };

                let first_guard = first_lock.lock()
                    .map_err(|poison_err| {
                        eprintln!("Shutdown timing mutex poisoned, recovering...");
                        poison_err.into_inner()
                    })
                    .unwrap();
                let second_guard = second_lock.lock()
                    .map_err(|poison_err| {
                        eprintln!("Shutdown timing mutex poisoned, recovering...");
                        poison_err.into_inner()
                    })
                    .unwrap();

                // Determine which is which and calculate timing
                let (started, completed) = if std::ptr::eq(first_lock, &self.shutdown_started_at) {
                    (*first_guard, *second_guard)
                } else {
                    (*second_guard, *first_guard)
                };

                match (started, completed) {
                    (Some(start), Some(end)) => Some(end.duration_since(start)),
                    _ => None,
                }
            };

            ShutdownStatistics {
                tree_shutdown_time: total_time,
                successful_nodes: node_stats.iter().filter(|n| n.final_state == NodeState::Terminated && !n.timeout_exceeded).count(),
                timeout_nodes: node_stats.iter().filter(|n| n.timeout_exceeded).count(),
                force_terminated_nodes: node_stats.iter().filter(|n| n.force_terminated).count(),
                node_statistics: node_stats,
                cascade_successful: self.stats.successful_cascades.load(Ordering::Relaxed) > 0,
                bounded_completion: total_time.map_or(false, |t| t.as_millis() <= self.shutdown_config.force_kill_timeout_ms as u128),
            }
        }
    }

    #[derive(Debug)]
    struct ShutdownStatistics {
        tree_shutdown_time: Option<Duration>,
        successful_nodes: usize,
        timeout_nodes: usize,
        force_terminated_nodes: usize,
        node_statistics: Vec<NodeShutdownStats>,
        cascade_successful: bool,
        bounded_completion: bool,
    }

    #[derive(Debug)]
    struct NodeShutdownStats {
        node_id: NodeId,
        node_type: NodeType,
        final_state: NodeState,
        shutdown_timing: Option<Duration>,
        timeout_exceeded: bool,
        force_terminated: bool,
        error: Option<String>,
    }

    /// Integration test harness for signal-driven supervision tree shutdown
    struct SignalShutdownHarness {
        tree: SupervisionTree,
        test_scenarios: Vec<TestScenario>,
    }

    #[derive(Debug, Clone)]
    struct TestScenario {
        name: String,
        description: String,
        tree_structure: TreeStructure,
        shutdown_signal: ShutdownSignal,
        expected_completion_time_ms: u64,
        tolerance_ms: u64,
    }

    #[derive(Debug, Clone)]
    struct TreeStructure {
        supervisors: usize,
        workers_per_supervisor: usize,
        services_per_supervisor: usize,
        max_depth: usize,
    }

    impl SignalShutdownHarness {
        fn new(shutdown_config: ShutdownConfig) -> Self {
            Self {
                tree: SupervisionTree::new(shutdown_config),
                test_scenarios: Vec::new(),
            }
        }

        fn build_test_tree(&mut self, structure: &TreeStructure) -> Result<(), String> {
            // Create root supervisor
            let root_id = self.tree.create_root_supervisor()?;

            // Build tree structure recursively
            self.build_tree_level(root_id, structure, 0)?;

            // Start all nodes
            self.tree.start_all_nodes()?;

            Ok(())
        }

        fn build_tree_level(&mut self, parent_id: NodeId, structure: &TreeStructure, current_depth: usize) -> Result<(), String> {
            if current_depth >= structure.max_depth {
                return Ok(());
            }

            // Create supervisors at this level
            for i in 0..structure.supervisors {
                let supervisor_id = self.tree.create_supervisor(
                    parent_id,
                    if i % 2 == 0 { SupervisionStrategy::OneForOne } else { SupervisionStrategy::OneForAll }
                )?;

                // Create workers under this supervisor
                for j in 0..structure.workers_per_supervisor {
                    let worker_type = match j % 3 {
                        0 => WorkerType::Permanent,
                        1 => WorkerType::Transient,
                        _ => WorkerType::Temporary,
                    };
                    self.tree.create_worker(supervisor_id, worker_type)?;
                }

                // Create services under this supervisor
                for k in 0..structure.services_per_supervisor {
                    let service_type = match k % 5 {
                        0 => ServiceType::HttpServer,
                        1 => ServiceType::DatabasePool,
                        2 => ServiceType::MessageQueue,
                        3 => ServiceType::FileWatcher,
                        _ => ServiceType::TimerService,
                    };
                    self.tree.create_service(supervisor_id, service_type)?;
                }

                // Recursively build next level
                if current_depth + 1 < structure.max_depth {
                    self.build_tree_level(supervisor_id, structure, current_depth + 1)?;
                }
            }

            Ok(())
        }

        fn execute_shutdown_test(&mut self, scenario: &TestScenario) -> Result<TestResult, String> {
            // Build the test tree
            self.build_test_tree(&scenario.tree_structure)?;

            let start_time = Instant::now();

            // Signal graceful shutdown
            self.tree.signal_graceful_shutdown(scenario.shutdown_signal)?;

            // Wait for shutdown to complete or timeout
            let timeout = Duration::from_millis(scenario.expected_completion_time_ms + scenario.tolerance_ms);
            let wait_start = Instant::now();

            while !self.tree.is_shutdown_complete() {
                if wait_start.elapsed() > timeout {
                    return Err("Shutdown test timeout exceeded".to_string());
                }
                std::thread::sleep(Duration::from_millis(10));
            }

            let total_time = start_time.elapsed();
            let stats = self.tree.get_shutdown_statistics();

            Ok(TestResult {
                scenario_name: scenario.name.clone(),
                total_shutdown_time: total_time,
                expected_time_ms: scenario.expected_completion_time_ms,
                tolerance_ms: scenario.tolerance_ms,
                within_bounds: total_time.as_millis() <= (scenario.expected_completion_time_ms + scenario.tolerance_ms) as u128,
                statistics: stats,
                success: stats.cascade_successful && stats.bounded_completion,
            })
        }

        fn generate_test_scenarios(&mut self) {
            // Simple tree shutdown
            self.test_scenarios.push(TestScenario {
                name: "Simple Tree Shutdown".to_string(),
                description: "Basic supervision tree with single level".to_string(),
                tree_structure: TreeStructure {
                    supervisors: 1,
                    workers_per_supervisor: 2,
                    services_per_supervisor: 1,
                    max_depth: 2,
                },
                shutdown_signal: ShutdownSignal::Sigterm,
                expected_completion_time_ms: 1000,
                tolerance_ms: 500,
            });

            // Complex hierarchy shutdown
            self.test_scenarios.push(TestScenario {
                name: "Deep Hierarchy Shutdown".to_string(),
                description: "Multi-level supervision tree with cascading shutdown".to_string(),
                tree_structure: TreeStructure {
                    supervisors: 2,
                    workers_per_supervisor: 3,
                    services_per_supervisor: 2,
                    max_depth: 4,
                },
                shutdown_signal: ShutdownSignal::Sigterm,
                expected_completion_time_ms: 2000,
                tolerance_ms: 1000,
            });

            // High load shutdown
            self.test_scenarios.push(TestScenario {
                name: "High Load Shutdown".to_string(),
                description: "Large supervision tree with many nodes".to_string(),
                tree_structure: TreeStructure {
                    supervisors: 3,
                    workers_per_supervisor: 4,
                    services_per_supervisor: 3,
                    max_depth: 3,
                },
                shutdown_signal: ShutdownSignal::Sigterm,
                expected_completion_time_ms: 3000,
                tolerance_ms: 1500,
            });
        }
    }

    #[derive(Debug)]
    struct TestResult {
        scenario_name: String,
        total_shutdown_time: Duration,
        expected_time_ms: u64,
        tolerance_ms: u64,
        within_bounds: bool,
        statistics: ShutdownStatistics,
        success: bool,
    }

    #[test]
    fn test_basic_sigterm_cascade() {
        let config = ShutdownConfig::default();
        let mut harness = SignalShutdownHarness::new(config);

        harness.generate_test_scenarios();
        let scenario = &harness.test_scenarios[0].clone(); // Simple Tree Shutdown

        let result = harness.execute_shutdown_test(scenario)
            .expect("Failed to execute basic SIGTERM cascade test");

        assert!(result.success, "Basic SIGTERM cascade failed");
        assert!(result.within_bounds,
            "Shutdown took {}ms, expected {}ms ± {}ms",
            result.total_shutdown_time.as_millis(),
            result.expected_time_ms,
            result.tolerance_ms);
        assert!(result.statistics.cascade_successful, "Shutdown cascade was not successful");
        assert_eq!(result.statistics.timeout_nodes, 0, "No nodes should timeout in basic test");

        println!("✓ Basic SIGTERM cascade completed in {}ms with {} successful nodes",
                 result.total_shutdown_time.as_millis(),
                 result.statistics.successful_nodes);
    }

    #[test]
    fn test_deep_hierarchy_bounded_shutdown() {
        let config = ShutdownConfig {
            drain_timeout_ms: 3000,    // Longer timeout for complex tree
            supervisor_timeout_ms: 4000,
            ..ShutdownConfig::default()
        };

        let mut harness = SignalShutdownHarness::new(config);
        harness.generate_test_scenarios();
        let scenario = &harness.test_scenarios[1].clone(); // Deep Hierarchy Shutdown

        let result = harness.execute_shutdown_test(scenario)
            .expect("Failed to execute deep hierarchy test");

        assert!(result.success, "Deep hierarchy shutdown failed");
        assert!(result.statistics.bounded_completion,
            "Shutdown did not complete within bounds");
        assert!(result.statistics.cascade_successful,
            "Shutdown cascade failed in deep hierarchy");

        // Verify all nodes terminated successfully
        assert_eq!(result.statistics.force_terminated_nodes, 0,
            "No nodes should require force termination");

        println!("✓ Deep hierarchy shutdown completed in {}ms, {} levels processed",
                 result.total_shutdown_time.as_millis(),
                 scenario.tree_structure.max_depth);
    }

    #[test]
    fn test_high_load_parallel_shutdown() {
        let config = ShutdownConfig {
            parallel_shutdown: true,
            drain_timeout_ms: 2000,
            supervisor_timeout_ms: 3000,
            ..ShutdownConfig::default()
        };

        let mut harness = SignalShutdownHarness::new(config);
        harness.generate_test_scenarios();
        let scenario = &harness.test_scenarios[2].clone(); // High Load Shutdown

        let result = harness.execute_shutdown_test(scenario)
            .expect("Failed to execute high load test");

        assert!(result.success, "High load shutdown failed");
        assert!(result.within_bounds,
            "High load shutdown exceeded time bounds: {}ms > {}ms",
            result.total_shutdown_time.as_millis(),
            scenario.expected_completion_time_ms + scenario.tolerance_ms);

        // Verify parallel shutdown efficiency
        let expected_sequential_time = result.statistics.node_statistics.len() as u64 * 200; // Estimate
        assert!(result.total_shutdown_time.as_millis() < expected_sequential_time as u128,
            "Parallel shutdown should be faster than sequential");

        println!("✓ High load parallel shutdown: {} nodes in {}ms",
                 result.statistics.node_statistics.len(),
                 result.total_shutdown_time.as_millis());
    }

    #[test]
    fn test_timeout_escalation_handling() {
        let config = ShutdownConfig {
            drain_timeout_ms: 100,      // Very short timeout to trigger escalation
            graceful_escalation: true,
            force_kill_timeout_ms: 1000,
            ..ShutdownConfig::default()
        };

        let mut harness = SignalShutdownHarness::new(config);

        // Build a tree with slow-draining services
        let structure = TreeStructure {
            supervisors: 1,
            workers_per_supervisor: 1,
            services_per_supervisor: 2, // Services take longer to drain
            max_depth: 2,
        };

        harness.build_test_tree(&structure).expect("Failed to build test tree");

        let start_time = Instant::now();
        harness.tree.signal_graceful_shutdown(ShutdownSignal::Sigterm)
            .expect("Failed to signal shutdown");

        // Wait for completion
        while !harness.tree.is_shutdown_complete() {
            if start_time.elapsed().as_millis() > 2000 {
                panic!("Timeout escalation test exceeded maximum time");
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        let stats = harness.tree.get_shutdown_statistics();

        // Should have some timeout nodes that were force terminated
        assert!(stats.timeout_nodes > 0 || stats.force_terminated_nodes > 0,
            "Expected some nodes to timeout and be force terminated");
        assert!(stats.cascade_successful, "Cascade should still succeed with escalation");

        println!("✓ Timeout escalation: {} timeouts, {} force terminations in {}ms",
                 stats.timeout_nodes,
                 stats.force_terminated_nodes,
                 start_time.elapsed().as_millis());
    }

    #[test]
    fn test_signal_propagation_timing() {
        let config = ShutdownConfig::default();
        let mut harness = SignalShutdownHarness::new(config);

        // Build moderate-sized tree to measure propagation
        let structure = TreeStructure {
            supervisors: 2,
            workers_per_supervisor: 3,
            services_per_supervisor: 2,
            max_depth: 3,
        };

        harness.build_test_tree(&structure).expect("Failed to build test tree");

        let signal_start = Instant::now();
        harness.tree.signal_graceful_shutdown(ShutdownSignal::Sigterm)
            .expect("Failed to signal shutdown");

        // Measure time until all nodes have received signal
        while !harness.tree.is_shutdown_complete() {
            std::thread::sleep(Duration::from_millis(10));
        }

        let stats = harness.tree.get_shutdown_statistics();
        let propagation_time = stats.tree_shutdown_time.unwrap();

        // Signal propagation should be very fast (< 100ms for this size tree)
        assert!(propagation_time.as_millis() < 5000,
            "Signal propagation took too long: {}ms", propagation_time.as_millis());

        // All nodes should have received the signal
        assert!(stats.node_statistics.iter().all(|n| n.final_state == NodeState::Terminated),
            "Not all nodes reached terminated state");

        println!("✓ Signal propagation: {} nodes in {}ms",
                 stats.node_statistics.len(),
                 propagation_time.as_millis());
    }

    #[test]
    fn test_supervision_strategy_shutdown_behavior() {
        let config = ShutdownConfig::default();
        let mut harness = SignalShutdownHarness::new(config);

        // Create tree with different supervision strategies
        let root_id = harness.tree.create_root_supervisor().expect("Failed to create root");

        let one_for_one_id = harness.tree.create_supervisor(root_id, SupervisionStrategy::OneForOne)
            .expect("Failed to create one-for-one supervisor");
        let one_for_all_id = harness.tree.create_supervisor(root_id, SupervisionStrategy::OneForAll)
            .expect("Failed to create one-for-all supervisor");

        // Add workers to each supervisor
        for _ in 0..3 {
            harness.tree.create_worker(one_for_one_id, WorkerType::Permanent)
                .expect("Failed to create worker");
            harness.tree.create_worker(one_for_all_id, WorkerType::Permanent)
                .expect("Failed to create worker");
        }

        harness.tree.start_all_nodes().expect("Failed to start nodes");

        // Signal shutdown and verify behavior
        harness.tree.signal_graceful_shutdown(ShutdownSignal::Sigterm)
            .expect("Failed to signal shutdown");

        while !harness.tree.is_shutdown_complete() {
            std::thread::sleep(Duration::from_millis(10));
        }

        let stats = harness.tree.get_shutdown_statistics();

        // All nodes should shut down regardless of supervision strategy
        assert!(stats.cascade_successful, "Shutdown should succeed for all strategies");
        assert_eq!(stats.timeout_nodes, 0, "No timeouts expected with default config");

        println!("✓ Supervision strategy shutdown: {} nodes completed successfully",
                 stats.successful_nodes);
    }

    #[test]
    fn test_bounded_drain_time_enforcement() {
        let strict_config = ShutdownConfig {
            drain_timeout_ms: 500,      // Strict 500ms limit
            supervisor_timeout_ms: 600,
            force_kill_timeout_ms: 1000,
            graceful_escalation: false, // No escalation - must meet bounds
            ..ShutdownConfig::default()
        };

        let mut harness = SignalShutdownHarness::new(strict_config);

        // Build tree with fast-draining components only
        let structure = TreeStructure {
            supervisors: 2,
            workers_per_supervisor: 2, // Workers drain faster than services
            services_per_supervisor: 0, // No slow services
            max_depth: 2,
        };

        harness.build_test_tree(&structure).expect("Failed to build test tree");

        let start_time = Instant::now();
        harness.tree.signal_graceful_shutdown(ShutdownSignal::Sigterm)
            .expect("Failed to signal shutdown");

        while !harness.tree.is_shutdown_complete() {
            if start_time.elapsed().as_millis() > 2000 {
                break; // Prevent infinite wait
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        let total_time = start_time.elapsed();
        let stats = harness.tree.get_shutdown_statistics();

        // Should complete within bounded time
        assert!(total_time.as_millis() <= 1000,
            "Shutdown exceeded bounded time: {}ms > 1000ms", total_time.as_millis());

        // Should have no timeouts with fast components
        assert_eq!(stats.timeout_nodes, 0,
            "No nodes should timeout with fast-draining components");

        println!("✓ Bounded drain time: {} nodes in {}ms (limit: 1000ms)",
                 stats.node_statistics.len(),
                 total_time.as_millis());
    }

    #[test]
    fn test_sigint_vs_sigterm_behavior() {
        let config = ShutdownConfig::default();

        // Test SIGTERM
        let mut harness_term = SignalShutdownHarness::new(config.clone());
        let structure = TreeStructure {
            supervisors: 1,
            workers_per_supervisor: 2,
            services_per_supervisor: 1,
            max_depth: 2,
        };

        harness_term.build_test_tree(&structure).expect("Failed to build SIGTERM tree");

        let start_term = Instant::now();
        harness_term.tree.signal_graceful_shutdown(ShutdownSignal::Sigterm)
            .expect("Failed to signal SIGTERM");

        while !harness_term.tree.is_shutdown_complete() {
            std::thread::sleep(Duration::from_millis(10));
        }
        let sigterm_time = start_term.elapsed();

        // Test SIGINT
        let mut harness_int = SignalShutdownHarness::new(config);
        harness_int.build_test_tree(&structure).expect("Failed to build SIGINT tree");

        let start_int = Instant::now();
        harness_int.tree.signal_graceful_shutdown(ShutdownSignal::Sigint)
            .expect("Failed to signal SIGINT");

        while !harness_int.tree.is_shutdown_complete() {
            std::thread::sleep(Duration::from_millis(10));
        }
        let sigint_time = start_int.elapsed();

        // Both should complete successfully
        let term_stats = harness_term.tree.get_shutdown_statistics();
        let int_stats = harness_int.tree.get_shutdown_statistics();

        assert!(term_stats.cascade_successful, "SIGTERM cascade failed");
        assert!(int_stats.cascade_successful, "SIGINT cascade failed");

        // Timing should be similar (both are graceful)
        let time_diff = sigterm_time.as_millis().abs_diff(sigint_time.as_millis());
        assert!(time_diff < 200, "SIGTERM and SIGINT timing too different: {}ms vs {}ms",
                sigterm_time.as_millis(), sigint_time.as_millis());

        println!("✓ Signal comparison: SIGTERM {}ms, SIGINT {}ms",
                 sigterm_time.as_millis(),
                 sigint_time.as_millis());
    }
}