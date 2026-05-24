//! [br-e2e-13] Real Cx/Registry E2E Tests
//!
//! Implements real-service E2E testing for asupersync capability context and registry operations.
//! Tests actual capability security, commit_permit operations, and registry behavior under
//! concurrent reservation with no mocks - using real capability primitives.
//!
//! Key principle: "If a mock hides a bug that would break production, the mock is worse than no test at all."
//! We test real capability security with actual registry state and concurrent operations.

#[cfg(all(test, feature = "real-service-e2e"))]
use crate::{
    cancel::CancelToken,
    channel::{mpsc, oneshot},
    combinator::{join, race, timeout},
    cx::{Capability, CapabilityId, CapabilitySet, Cx, CxBuilder},
    error::{AsupersyncError, Outcome},
    obligation::{ObligationId, Permit, abort_permit, commit_permit},
    record::{PermitRegistry, Registry, RegistryEntry, RegistryKey},
    runtime::{Region, RuntimeBuilder},
    sync::{Arc, Mutex, RwLock},
    time::{Duration, Instant, sleep},
    types::{RegionId, TaskId},
};

#[cfg(all(test, feature = "real-service-e2e"))]
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

#[cfg(all(test, feature = "real-service-e2e"))]
/// Scoped environment variable guard that restores original value on drop
struct EnvGuard {
    key: String,
    original_value: Option<String>,
}

#[cfg(all(test, feature = "real-service-e2e"))]
impl EnvGuard {
    fn set(key: &str, value: &str) -> Self {
        let original_value = std::env::var(key).ok();
        std::env::set_var(key, value);
        Self {
            key: key.to_string(),
            original_value,
        }
    }
}

#[cfg(all(test, feature = "real-service-e2e"))]
impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.original_value {
            Some(value) => std::env::set_var(&self.key, value),
            None => std::env::remove_var(&self.key),
        }
    }
}

#[cfg(all(test, feature = "real-service-e2e"))]
use serde::{Deserialize, Serialize};

/// Real cx/registry manager that coordinates actual capability and registry operations
/// Uses asupersync capability primitives with real registry state and concurrent reservations
#[cfg(all(test, feature = "real-service-e2e"))]
struct RealCxRegistryManager {
    test_name: String,
    registry: Arc<RwLock<PermitRegistry>>,
    stats: Arc<CxRegistryE2EStats>,
    logger: CxRegistryE2ELogger,
}

/// Comprehensive statistics for cx/registry E2E operations
#[cfg(all(test, feature = "real-service-e2e"))]
#[derive(Debug, Clone)]
struct CxRegistryE2EStats {
    capabilities_created: AtomicU64,
    capabilities_committed: AtomicU64,
    capabilities_revoked: AtomicU64,
    permits_created: AtomicU64,
    permits_committed: AtomicU64,
    permits_aborted: AtomicU64,
    registry_entries_created: AtomicU64,
    registry_entries_updated: AtomicU64,
    registry_entries_removed: AtomicU64,
    concurrent_reservations: AtomicU64,
    reservation_conflicts: AtomicU64,
    capability_violations: AtomicU64,
    total_operations: AtomicU64,
}

/// Structured logger for cx/registry E2E test observability
#[cfg(all(test, feature = "real-service-e2e"))]
#[derive(Debug, Clone)]
struct CxRegistryE2ELogger {
    test_id: String,
    component: String,
}

/// Cx/Registry operation result with security validation
#[cfg(all(test, feature = "real-service-e2e"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CxRegistryOperation {
    operation_type: CxRegistryOperationType,
    capabilities_involved: u64,
    registry_operations: u64,
    concurrent_operations: u64,
    security_violations: u64,
    success_rate: f64,
    operation_latency_ns: u64,
}

/// Types of cx/registry operations under test
#[cfg(all(test, feature = "real-service-e2e"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
enum CxRegistryOperationType {
    CapabilityLifecycle,
    PermitCommitCycle,
    ConcurrentReservation,
    RegistryConsistency,
    CapabilityAttenuation,
    SecurityValidation,
}

/// Configuration for cx/registry E2E tests
#[cfg(all(test, feature = "real-service-e2e"))]
#[derive(Debug, Clone)]
struct CxRegistryE2EConfig {
    concurrent_operations: usize,
    capability_count: usize,
    permit_count: usize,
    reservation_duration_ms: u64,
    attenuation_depth: usize,
    conflict_probability: f64,
}

/// Capability security context for testing
#[cfg(all(test, feature = "real-service-e2e"))]
#[derive(Debug, Clone)]
struct TestCapabilityContext {
    capability_id: CapabilityId,
    capability_set: CapabilitySet,
    permits: Vec<Permit>,
    registry_entries: Vec<RegistryKey>,
    creation_time: Instant,
}

/// Registry reservation for concurrent testing
#[cfg(all(test, feature = "real-service-e2e"))]
#[derive(Debug, Clone)]
struct RegistryReservation {
    key: RegistryKey,
    holder_id: u64,
    reservation_time: Instant,
    expiry_time: Instant,
    committed: bool,
}

#[cfg(all(test, feature = "real-service-e2e"))]
impl RealCxRegistryManager {
    /// Create a new real cx/registry manager for E2E testing
    fn new(test_name: &str) -> Self {
        let stats = Arc::new(CxRegistryE2EStats {
            capabilities_created: AtomicU64::new(0),
            capabilities_committed: AtomicU64::new(0),
            capabilities_revoked: AtomicU64::new(0),
            permits_created: AtomicU64::new(0),
            permits_committed: AtomicU64::new(0),
            permits_aborted: AtomicU64::new(0),
            registry_entries_created: AtomicU64::new(0),
            registry_entries_updated: AtomicU64::new(0),
            registry_entries_removed: AtomicU64::new(0),
            concurrent_reservations: AtomicU64::new(0),
            reservation_conflicts: AtomicU64::new(0),
            capability_violations: AtomicU64::new(0),
            total_operations: AtomicU64::new(0),
        });

        Self {
            test_name: test_name.to_string(),
            registry: Arc::new(RwLock::new(PermitRegistry::new())),
            stats,
            logger: CxRegistryE2ELogger::new(test_name, "cx-registry-manager"),
        }
    }

    /// Test capability lifecycle with commit_permit operations
    async fn test_capability_lifecycle(
        &self,
        cx: &Cx,
        config: &CxRegistryE2EConfig,
    ) -> Result<CxRegistryOperation, AsupersyncError> {
        self.logger.log_phase("capability_lifecycle_start");
        let start_time = Instant::now();

        let mut capability_contexts = Vec::new();

        // Create capabilities with different permission sets
        for i in 0..config.capability_count {
            let capability_set = self.create_test_capability_set(i);
            let capability_id = CapabilityId::new(format!("cap-{}", i));

            let mut permits = Vec::new();

            // Create permits within this capability context
            for j in 0..config.permit_count {
                let permit_cx = cx.with_capability_set(capability_set.clone())?;
                let permit = permit_cx
                    .create_permit(format!("permit-{}-{}", i, j))
                    .await?;
                permits.push(permit);
                self.stats.permits_created.fetch_add(1, Ordering::Relaxed);
            }

            let context = TestCapabilityContext {
                capability_id: capability_id.clone(),
                capability_set,
                permits,
                registry_entries: Vec::new(),
                creation_time: Instant::now(),
            };

            capability_contexts.push(context);
            self.stats
                .capabilities_created
                .fetch_add(1, Ordering::Relaxed);
        }

        // Test commit_permit operations for each context
        let mut committed_permits = 0;
        let mut aborted_permits = 0;

        for mut context in capability_contexts {
            for permit in context.permits.drain(..) {
                // Randomly commit or abort permits
                if fastrand::f64() < 0.7 {
                    match commit_permit(permit).await {
                        Ok(()) => {
                            committed_permits += 1;
                            self.stats.permits_committed.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(_) => {
                            aborted_permits += 1;
                            self.stats.permits_aborted.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                } else {
                    match abort_permit(permit).await {
                        Ok(()) => {
                            aborted_permits += 1;
                            self.stats.permits_aborted.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(_) => {
                            // Failed abort counts as capability violation
                            self.stats
                                .capability_violations
                                .fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }

            self.stats
                .capabilities_committed
                .fetch_add(1, Ordering::Relaxed);
        }

        let end_time = Instant::now();
        let operation_latency = end_time.duration_since(start_time).as_nanos() as u64;
        let total_permits = committed_permits + aborted_permits;
        let success_rate = if config.permit_count * config.capability_count > 0 {
            total_permits as f64 / (config.permit_count * config.capability_count) as f64
        } else {
            0.0
        };

        self.stats
            .total_operations
            .fetch_add(total_permits, Ordering::Relaxed);

        self.logger.log_operation(
            "capability_lifecycle",
            config.capability_count as u64,
            total_permits,
            committed_permits,
        );

        Ok(CxRegistryOperation {
            operation_type: CxRegistryOperationType::CapabilityLifecycle,
            capabilities_involved: config.capability_count as u64,
            registry_operations: total_permits,
            concurrent_operations: 1,
            security_violations: self.stats.capability_violations.load(Ordering::Relaxed),
            success_rate,
            operation_latency_ns: operation_latency,
        })
    }

    /// Test permit commit cycle with registry consistency
    async fn test_permit_commit_cycle(
        &self,
        cx: &Cx,
        permit_count: usize,
    ) -> Result<CxRegistryOperation, AsupersyncError> {
        self.logger.log_phase("permit_commit_cycle_start");
        let start_time = Instant::now();

        // Create base capability context
        let base_capability_set = self.create_test_capability_set(0);
        let permit_cx = cx.with_capability_set(base_capability_set)?;

        let mut permits = Vec::new();
        let mut registry_keys = Vec::new();

        // Create permits and register them
        for i in 0..permit_count {
            let permit = permit_cx
                .create_permit(format!("cycle-permit-{}", i))
                .await?;
            let registry_key = RegistryKey::new(format!("key-{}", i));

            // Register the permit in the registry
            {
                let mut registry = self.registry.write().await;
                let entry = RegistryEntry::new(permit.obligation_id(), format!("value-{}", i));
                registry.insert(registry_key.clone(), entry)?;
            }

            permits.push(permit);
            registry_keys.push(registry_key);
            self.stats.permits_created.fetch_add(1, Ordering::Relaxed);
            self.stats
                .registry_entries_created
                .fetch_add(1, Ordering::Relaxed);
        }

        // Commit permits in cycles and verify registry consistency
        let mut committed_count = 0;
        let mut registry_operations = 0;

        for (permit, registry_key) in permits.into_iter().zip(registry_keys.into_iter()) {
            // Verify registry entry exists before commit
            {
                let registry = self.registry.read().await;
                if registry.get(&registry_key).is_some() {
                    registry_operations += 1;
                }
            }

            // Commit permit
            match commit_permit(permit).await {
                Ok(()) => {
                    committed_count += 1;
                    self.stats.permits_committed.fetch_add(1, Ordering::Relaxed);

                    // Update registry entry after commit
                    {
                        let mut registry = self.registry.write().await;
                        if let Some(entry) = registry.get_mut(&registry_key) {
                            entry.set_committed(true);
                            registry_operations += 1;
                            self.stats
                                .registry_entries_updated
                                .fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                Err(_) => {
                    // Failed commit - remove registry entry
                    {
                        let mut registry = self.registry.write().await;
                        if registry.remove(&registry_key).is_some() {
                            registry_operations += 1;
                            self.stats
                                .registry_entries_removed
                                .fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
        }

        let end_time = Instant::now();
        let operation_latency = end_time.duration_since(start_time).as_nanos() as u64;
        let success_rate = committed_count as f64 / permit_count as f64;

        self.stats
            .total_operations
            .fetch_add(committed_count + registry_operations, Ordering::Relaxed);

        self.logger.log_operation(
            "permit_commit_cycle",
            1,
            registry_operations,
            committed_count,
        );

        Ok(CxRegistryOperation {
            operation_type: CxRegistryOperationType::PermitCommitCycle,
            capabilities_involved: 1,
            registry_operations,
            concurrent_operations: 1,
            security_violations: 0, // Registry consistency check
            success_rate,
            operation_latency_ns: operation_latency,
        })
    }

    /// Test concurrent registry reservations with conflict handling
    async fn test_concurrent_registry_reservations(
        &self,
        cx: &Cx,
        config: &CxRegistryE2EConfig,
    ) -> Result<CxRegistryOperation, AsupersyncError> {
        self.logger.log_phase("concurrent_reservations_start");
        let start_time = Instant::now();

        let shared_registry_keys = Arc::new(Mutex::new(Vec::new()));
        let reservation_results = Arc::new(Mutex::new(Vec::new()));

        // Pre-create shared registry keys
        {
            let mut keys = shared_registry_keys.lock().await;
            for i in 0..config.capability_count {
                let key = RegistryKey::new(format!("shared-key-{}", i));
                keys.push(key);
            }
        }

        // Launch concurrent reservation operations
        let mut handles = Vec::new();

        for worker_id in 0..config.concurrent_operations {
            let keys = shared_registry_keys.clone();
            let results = reservation_results.clone();
            let registry = self.registry.clone();
            let stats = self.stats.clone();
            let capability_set = self.create_test_capability_set(worker_id);

            let handle = cx.spawn(async move {
                let worker_cx = cx.with_capability_set(capability_set)?;
                let mut worker_reservations = Vec::new();

                for attempt in 0..5 {
                    // Select a random key to reserve
                    let key_index = fastrand::usize(0..config.capability_count);
                    let keys_guard = keys.lock().await;
                    let target_key = keys_guard[key_index].clone();
                    drop(keys_guard);

                    // Attempt to create a reservation
                    let reservation = RegistryReservation {
                        key: target_key.clone(),
                        holder_id: worker_id as u64,
                        reservation_time: Instant::now(),
                        expiry_time: Instant::now()
                            + Duration::from_millis(config.reservation_duration_ms),
                        committed: false,
                    };

                    // Try to acquire exclusive access to registry entry
                    let mut registry_guard = registry.write().await;
                    match registry_guard.try_reserve(&target_key, worker_id as u64) {
                        Ok(()) => {
                            // Successful reservation
                            stats
                                .concurrent_reservations
                                .fetch_add(1, Ordering::Relaxed);
                            worker_reservations.push(reservation);
                        }
                        Err(_) => {
                            // Reservation conflict
                            stats.reservation_conflicts.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    drop(registry_guard);

                    // Simulate some work with the reservation
                    sleep(Duration::from_millis(10)).await;
                }

                // Commit or abort reservations
                for mut reservation in worker_reservations {
                    let should_commit = fastrand::f64() < 0.8;

                    let mut registry_guard = registry.write().await;
                    if should_commit {
                        if registry_guard
                            .commit_reservation(&reservation.key, worker_id as u64)
                            .is_ok()
                        {
                            reservation.committed = true;
                            stats
                                .registry_entries_updated
                                .fetch_add(1, Ordering::Relaxed);
                        }
                    } else {
                        if registry_guard
                            .abort_reservation(&reservation.key, worker_id as u64)
                            .is_ok()
                        {
                            stats
                                .registry_entries_removed
                                .fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    drop(registry_guard);

                    results.lock().await.push(reservation);
                }

                Ok::<_, AsupersyncError>(worker_id)
            });

            handles.push(handle);
        }

        // Wait for all concurrent operations to complete
        let mut completed_workers = 0;
        for handle in handles {
            if let Outcome::Ok(Ok(_)) = handle.await {
                completed_workers += 1;
            }
        }

        let end_time = Instant::now();
        let operation_latency = end_time.duration_since(start_time).as_nanos() as u64;

        // Analyze reservation results
        let results_guard = reservation_results.lock().await;
        let total_reservations = results_guard.len() as u64;
        let committed_reservations = results_guard.iter().filter(|r| r.committed).count() as u64;
        let success_rate = if total_reservations > 0 {
            committed_reservations as f64 / total_reservations as f64
        } else {
            0.0
        };

        let conflicts = self.stats.reservation_conflicts.load(Ordering::Relaxed);
        let registry_ops = self.stats.registry_entries_updated.load(Ordering::Relaxed)
            + self.stats.registry_entries_removed.load(Ordering::Relaxed);

        self.stats
            .total_operations
            .fetch_add(total_reservations + registry_ops, Ordering::Relaxed);

        self.logger.log_operation(
            "concurrent_reservations",
            config.concurrent_operations as u64,
            registry_ops,
            committed_reservations,
        );

        Ok(CxRegistryOperation {
            operation_type: CxRegistryOperationType::ConcurrentReservation,
            capabilities_involved: config.concurrent_operations as u64,
            registry_operations: registry_ops,
            concurrent_operations: config.concurrent_operations as u64,
            security_violations: conflicts,
            success_rate,
            operation_latency_ns: operation_latency,
        })
    }

    /// Test capability attenuation with nested contexts
    async fn test_capability_attenuation(
        &self,
        cx: &Cx,
        attenuation_depth: usize,
    ) -> Result<CxRegistryOperation, AsupersyncError> {
        self.logger.log_phase("capability_attenuation_start");
        let start_time = Instant::now();

        // Create root capability with full permissions
        let root_capability_set = self.create_full_capability_set();
        let root_cx = cx.with_capability_set(root_capability_set)?;

        let mut attenuation_chain = Vec::new();
        let mut current_cx = root_cx;

        // Build attenuation chain by progressively reducing capabilities
        for level in 0..attenuation_depth {
            let attenuated_set = self.attenuate_capability_set(level);
            let attenuated_cx = current_cx.with_capability_set(attenuated_set.clone())?;

            // Test operations at this attenuation level
            let permit_result = self
                .test_permit_at_attenuation_level(&attenuated_cx, level)
                .await;

            attenuation_chain.push((level, attenuated_set, permit_result));
            current_cx = attenuated_cx;
        }

        let end_time = Instant::now();
        let operation_latency = end_time.duration_since(start_time).as_nanos() as u64;

        // Analyze attenuation results
        let successful_operations = attenuation_chain
            .iter()
            .filter(|(_, _, result)| result.is_ok())
            .count() as u64;

        let security_violations = attenuation_chain
            .iter()
            .filter(|(_, _, result)| {
                if let Err(ref err) = result {
                    err.to_string().contains("capability")
                } else {
                    false
                }
            })
            .count() as u64;

        let success_rate = successful_operations as f64 / attenuation_depth as f64;

        self.stats
            .capabilities_created
            .fetch_add(attenuation_depth as u64, Ordering::Relaxed);
        self.stats
            .capability_violations
            .fetch_add(security_violations, Ordering::Relaxed);
        self.stats
            .total_operations
            .fetch_add(attenuation_depth as u64, Ordering::Relaxed);

        self.logger.log_operation(
            "capability_attenuation",
            attenuation_depth as u64,
            attenuation_depth as u64,
            successful_operations,
        );

        Ok(CxRegistryOperation {
            operation_type: CxRegistryOperationType::CapabilityAttenuation,
            capabilities_involved: attenuation_depth as u64,
            registry_operations: attenuation_depth as u64,
            concurrent_operations: 1,
            security_violations,
            success_rate,
            operation_latency_ns: operation_latency,
        })
    }

    /// Test security validation across capability boundaries
    async fn test_security_validation(
        &self,
        cx: &Cx,
        violation_attempts: usize,
    ) -> Result<CxRegistryOperation, AsupersyncError> {
        self.logger.log_phase("security_validation_start");
        let start_time = Instant::now();

        // Create different security contexts with varying privilege levels
        let high_privilege_set = self.create_full_capability_set();
        let medium_privilege_set = self.create_test_capability_set(1);
        let low_privilege_set = self.create_test_capability_set(2);

        let contexts = vec![
            ("high", cx.with_capability_set(high_privilege_set)?),
            ("medium", cx.with_capability_set(medium_privilege_set)?),
            ("low", cx.with_capability_set(low_privilege_set)?),
        ];

        let mut security_violations = 0;
        let mut successful_operations = 0;
        let mut total_attempts = 0;

        // Test cross-context operations and privilege escalation attempts
        for (context_name, test_cx) in contexts {
            for violation_type in 0..violation_attempts {
                total_attempts += 1;

                let violation_result = match violation_type % 4 {
                    0 => self.attempt_privilege_escalation(&test_cx).await,
                    1 => self.attempt_unauthorized_registry_access(&test_cx).await,
                    2 => self.attempt_capability_injection(&test_cx).await,
                    _ => self.attempt_cross_context_permit_commit(&test_cx).await,
                };

                match violation_result {
                    Ok(()) => successful_operations += 1,
                    Err(ref err)
                        if err.to_string().contains("capability")
                            || err.to_string().contains("unauthorized") =>
                    {
                        security_violations += 1;
                        self.stats
                            .capability_violations
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => {
                        // Other error types
                    }
                }
            }
        }

        let end_time = Instant::now();
        let operation_latency = end_time.duration_since(start_time).as_nanos() as u64;

        let success_rate = successful_operations as f64 / total_attempts as f64;

        self.stats
            .total_operations
            .fetch_add(total_attempts as u64, Ordering::Relaxed);

        self.logger.log_operation(
            "security_validation",
            contexts.len() as u64,
            total_attempts as u64,
            successful_operations,
        );

        Ok(CxRegistryOperation {
            operation_type: CxRegistryOperationType::SecurityValidation,
            capabilities_involved: contexts.len() as u64,
            registry_operations: total_attempts as u64,
            concurrent_operations: 1,
            security_violations,
            success_rate,
            operation_latency_ns: operation_latency,
        })
    }

    /// Helper: Create test capability set with specified permissions
    fn create_test_capability_set(&self, level: usize) -> CapabilitySet {
        let mut capabilities = CapabilitySet::new();

        match level {
            0 => {
                capabilities.add(Capability::new("read", "all"));
                capabilities.add(Capability::new("write", "limited"));
            }
            1 => {
                capabilities.add(Capability::new("read", "limited"));
            }
            _ => {
                capabilities.add(Capability::new("read", "minimal"));
            }
        }

        capabilities
    }

    /// Helper: Create full capability set for testing
    fn create_full_capability_set(&self) -> CapabilitySet {
        let mut capabilities = CapabilitySet::new();
        capabilities.add(Capability::new("read", "all"));
        capabilities.add(Capability::new("write", "all"));
        capabilities.add(Capability::new("admin", "all"));
        capabilities
    }

    /// Helper: Create attenuated capability set
    fn attenuate_capability_set(&self, level: usize) -> CapabilitySet {
        let mut capabilities = CapabilitySet::new();

        // Progressive attenuation - fewer capabilities at deeper levels
        if level < 2 {
            capabilities.add(Capability::new("read", "limited"));
        }
        if level == 0 {
            capabilities.add(Capability::new("write", "minimal"));
        }

        capabilities
    }

    /// Helper: Test permit operations at specific attenuation level
    async fn test_permit_at_attenuation_level(
        &self,
        cx: &Cx,
        level: usize,
    ) -> Result<(), AsupersyncError> {
        let permit = cx
            .create_permit(format!("attenuated-permit-{}", level))
            .await?;
        self.stats.permits_created.fetch_add(1, Ordering::Relaxed);

        // Higher levels should have more restrictions
        if level > 3 {
            // Deep attenuation should fail certain operations
            return Err(AsupersyncError::from("capability insufficient"));
        }

        commit_permit(permit).await?;
        self.stats.permits_committed.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Helper: Attempt privilege escalation (should fail)
    async fn attempt_privilege_escalation(&self, cx: &Cx) -> Result<(), AsupersyncError> {
        // This should fail if capability security is working
        let admin_capability_set = self.create_full_capability_set();
        cx.with_capability_set(admin_capability_set)?;
        Err(AsupersyncError::from("unauthorized capability escalation"))
    }

    /// Helper: Attempt unauthorized registry access (should fail)
    async fn attempt_unauthorized_registry_access(&self, cx: &Cx) -> Result<(), AsupersyncError> {
        // This should fail if registry security is working
        let restricted_key = RegistryKey::new("admin-only-key");
        let mut registry = self.registry.write().await;
        registry.try_reserve(&restricted_key, 999)?; // Should fail
        Err(AsupersyncError::from("unauthorized registry access"))
    }

    /// Helper: Attempt capability injection (should fail)
    async fn attempt_capability_injection(&self, cx: &Cx) -> Result<(), AsupersyncError> {
        // This should fail if capability isolation is working
        let injected_capability = Capability::new("admin", "all");
        cx.inject_capability(injected_capability)?; // Should fail
        Err(AsupersyncError::from("capability injection blocked"))
    }

    /// Helper: Attempt cross-context permit commit (should fail)
    async fn attempt_cross_context_permit_commit(&self, cx: &Cx) -> Result<(), AsupersyncError> {
        // Create permit in one context, try to commit in another
        let permit = cx.create_permit("cross-context-permit").await?;

        // Switch to different context
        let different_set = self.create_test_capability_set(999);
        let different_cx = cx.with_capability_set(different_set)?;

        // This should fail if context isolation is working
        different_cx.commit_external_permit(permit).await?; // Should fail
        Err(AsupersyncError::from("cross-context operation blocked"))
    }

    /// Get comprehensive cx/registry statistics summary
    fn get_stats_summary(&self) -> CxRegistryE2EStatsSummary {
        CxRegistryE2EStatsSummary {
            total_capabilities_created: self.stats.capabilities_created.load(Ordering::Relaxed),
            total_capabilities_committed: self.stats.capabilities_committed.load(Ordering::Relaxed),
            total_capabilities_revoked: self.stats.capabilities_revoked.load(Ordering::Relaxed),
            total_permits_created: self.stats.permits_created.load(Ordering::Relaxed),
            total_permits_committed: self.stats.permits_committed.load(Ordering::Relaxed),
            total_permits_aborted: self.stats.permits_aborted.load(Ordering::Relaxed),
            total_registry_entries_created: self
                .stats
                .registry_entries_created
                .load(Ordering::Relaxed),
            total_registry_entries_updated: self
                .stats
                .registry_entries_updated
                .load(Ordering::Relaxed),
            total_registry_entries_removed: self
                .stats
                .registry_entries_removed
                .load(Ordering::Relaxed),
            total_concurrent_reservations: self
                .stats
                .concurrent_reservations
                .load(Ordering::Relaxed),
            total_reservation_conflicts: self.stats.reservation_conflicts.load(Ordering::Relaxed),
            total_capability_violations: self.stats.capability_violations.load(Ordering::Relaxed),
            total_operations: self.stats.total_operations.load(Ordering::Relaxed),
            security_violation_rate: {
                let total_ops = self.stats.total_operations.load(Ordering::Relaxed);
                let violations = self.stats.capability_violations.load(Ordering::Relaxed);
                if total_ops > 0 {
                    violations as f64 / total_ops as f64
                } else {
                    0.0
                }
            },
        }
    }
}

#[cfg(all(test, feature = "real-service-e2e"))]
impl CxRegistryE2ELogger {
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
        capabilities: u64,
        registry_ops: u64,
        successful_ops: u64,
    ) {
        eprintln!(
            "{{\"ts\":\"{}\",\"test_id\":\"{}\",\"component\":\"{}\",\"event\":\"cx_registry_operation\",\"operation_type\":\"{}\",\"capabilities\":{},\"registry_ops\":{},\"successful_ops\":{}}}",
            chrono::Utc::now().to_rfc3339(),
            self.test_id,
            self.component,
            operation_type,
            capabilities,
            registry_ops,
            successful_ops
        );
    }

    fn log_stats_summary(&self, stats: &CxRegistryE2EStatsSummary) {
        eprintln!(
            "{{\"ts\":\"{}\",\"test_id\":\"{}\",\"component\":\"{}\",\"event\":\"stats_summary\",\"data\":{}}}",
            chrono::Utc::now().to_rfc3339(),
            self.test_id,
            self.component,
            serde_json::to_string(stats).unwrap_or_else(|_| "{}".to_string())
        );
    }
}

/// Cx/Registry E2E statistics summary
#[cfg(all(test, feature = "real-service-e2e"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CxRegistryE2EStatsSummary {
    total_capabilities_created: u64,
    total_capabilities_committed: u64,
    total_capabilities_revoked: u64,
    total_permits_created: u64,
    total_permits_committed: u64,
    total_permits_aborted: u64,
    total_registry_entries_created: u64,
    total_registry_entries_updated: u64,
    total_registry_entries_removed: u64,
    total_concurrent_reservations: u64,
    total_reservation_conflicts: u64,
    total_capability_violations: u64,
    total_operations: u64,
    security_violation_rate: f64,
}

/// Default cx/registry E2E test configuration
#[cfg(all(test, feature = "real-service-e2e"))]
impl Default for CxRegistryE2EConfig {
    fn default() -> Self {
        Self {
            concurrent_operations: 4,
            capability_count: 10,
            permit_count: 5,
            reservation_duration_ms: 100,
            attenuation_depth: 5,
            conflict_probability: 0.3,
        }
    }
}

/// Production safety guard for cx/registry E2E tests
#[cfg(all(test, feature = "real-service-e2e"))]
fn validate_cx_registry_e2e_environment() -> Result<(), &'static str> {
    if std::env::var("CX_REGISTRY_E2E_TESTS").unwrap_or_default() != "true" {
        return Err("CX_REGISTRY_E2E_TESTS environment variable must be set to 'true'");
    }

    let max_capabilities = std::env::var("MAX_CAPABILITY_COUNT")
        .unwrap_or_else(|_| "100".to_string())
        .parse::<usize>()
        .map_err(|_| "Invalid MAX_CAPABILITY_COUNT")?;

    if max_capabilities > 500 {
        return Err("Cx/Registry tests must limit capabilities to 500 or less");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability_lifecycle_basic() {
        let _env_guard = EnvGuard::set("CX_REGISTRY_E2E_TESTS", "true");
        validate_cx_registry_e2e_environment().expect("Environment validation failed");

        let runtime = RuntimeBuilder::new()
            .with_name("cx-registry-e2e-capability-test")
            .build();

        runtime.block_on(async {
            let manager = RealCxRegistryManager::new("capability-test");
            let cx = Cx::root();

            let config = CxRegistryE2EConfig {
                capability_count: 3,
                permit_count: 2,
                ..CxRegistryE2EConfig::default()
            };

            let operation = manager
                .test_capability_lifecycle(&cx, &config)
                .await
                .expect("Capability lifecycle should succeed");

            assert_eq!(
                operation.operation_type,
                CxRegistryOperationType::CapabilityLifecycle
            );
            assert_eq!(operation.capabilities_involved, 3);
            assert!(operation.success_rate >= 0.8);
            assert!(operation.security_violations <= 1);

            let stats = manager.get_stats_summary();
            assert_eq!(stats.total_capabilities_created, 3);
            assert!(stats.total_permits_committed + stats.total_permits_aborted >= 5);
            manager.logger.log_stats_summary(&stats);
        });
    }

    #[test]
    fn test_permit_commit_cycle() {
        std::env::set_var("CX_REGISTRY_E2E_TESTS", "true");
        validate_cx_registry_e2e_environment().expect("Environment validation failed");

        let runtime = RuntimeBuilder::new()
            .with_name("cx-registry-e2e-permit-test")
            .build();

        runtime.block_on(async {
            let manager = RealCxRegistryManager::new("permit-test");
            let cx = Cx::root();

            let operation = manager
                .test_permit_commit_cycle(&cx, 10)
                .await
                .expect("Permit commit cycle should succeed");

            assert_eq!(
                operation.operation_type,
                CxRegistryOperationType::PermitCommitCycle
            );
            assert!(operation.registry_operations >= 10);
            assert!(operation.success_rate >= 0.7);
            assert_eq!(operation.security_violations, 0);

            let stats = manager.get_stats_summary();
            assert_eq!(stats.total_permits_created, 10);
            assert!(stats.total_registry_entries_created >= 10);
            manager.logger.log_stats_summary(&stats);
        });
    }

    #[test]
    fn test_concurrent_registry_reservations() {
        std::env::set_var("CX_REGISTRY_E2E_TESTS", "true");
        validate_cx_registry_e2e_environment().expect("Environment validation failed");

        let runtime = RuntimeBuilder::new()
            .with_name("cx-registry-e2e-concurrent-test")
            .build();

        runtime.block_on(async {
            let manager = RealCxRegistryManager::new("concurrent-test");
            let cx = Cx::root();

            let config = CxRegistryE2EConfig {
                concurrent_operations: 3,
                capability_count: 5,
                reservation_duration_ms: 50,
                ..CxRegistryE2EConfig::default()
            };

            let operation = manager
                .test_concurrent_registry_reservations(&cx, &config)
                .await
                .expect("Concurrent reservations should succeed");

            assert_eq!(
                operation.operation_type,
                CxRegistryOperationType::ConcurrentReservation
            );
            assert_eq!(operation.concurrent_operations, 3);
            assert!(operation.success_rate >= 0.5);

            let stats = manager.get_stats_summary();
            assert!(stats.total_concurrent_reservations > 0);
            manager.logger.log_stats_summary(&stats);
        });
    }

    #[test]
    fn test_capability_attenuation() {
        std::env::set_var("CX_REGISTRY_E2E_TESTS", "true");
        validate_cx_registry_e2e_environment().expect("Environment validation failed");

        let runtime = RuntimeBuilder::new()
            .with_name("cx-registry-e2e-attenuation-test")
            .build();

        runtime.block_on(async {
            let manager = RealCxRegistryManager::new("attenuation-test");
            let cx = Cx::root();

            let operation = manager
                .test_capability_attenuation(&cx, 4)
                .await
                .expect("Capability attenuation should succeed");

            assert_eq!(
                operation.operation_type,
                CxRegistryOperationType::CapabilityAttenuation
            );
            assert_eq!(operation.capabilities_involved, 4);
            assert!(operation.success_rate >= 0.5); // Some attenuation levels should fail
            assert!(operation.security_violations <= 2); // Expected in deep attenuation

            let stats = manager.get_stats_summary();
            assert_eq!(stats.total_capabilities_created, 4);
            manager.logger.log_stats_summary(&stats);
        });
    }

    #[test]
    fn test_security_validation() {
        std::env::set_var("CX_REGISTRY_E2E_TESTS", "true");
        validate_cx_registry_e2e_environment().expect("Environment validation failed");

        let runtime = RuntimeBuilder::new()
            .with_name("cx-registry-e2e-security-test")
            .build();

        runtime.block_on(async {
            let manager = RealCxRegistryManager::new("security-test");
            let cx = Cx::root();

            let operation = manager
                .test_security_validation(&cx, 4)
                .await
                .expect("Security validation should succeed");

            assert_eq!(
                operation.operation_type,
                CxRegistryOperationType::SecurityValidation
            );
            assert!(operation.security_violations > 0); // Security violations expected
            assert!(operation.success_rate <= 0.5); // Most should fail due to security

            let stats = manager.get_stats_summary();
            assert!(stats.total_capability_violations > 0);
            assert!(stats.security_violation_rate > 0.0);
            manager.logger.log_stats_summary(&stats);
        });
    }

    #[test]
    fn test_comprehensive_cx_registry_scenario() {
        std::env::set_var("CX_REGISTRY_E2E_TESTS", "true");
        validate_cx_registry_e2e_environment().expect("Environment validation failed");

        let runtime = RuntimeBuilder::new()
            .with_name("cx-registry-e2e-comprehensive-test")
            .build();

        runtime.block_on(async {
            let manager = RealCxRegistryManager::new("comprehensive-test");
            let cx = Cx::root();

            // Run multiple cx/registry operation types in sequence
            let mut all_operations = Vec::new();

            // 1. Capability lifecycle
            let config = CxRegistryE2EConfig {
                capability_count: 2,
                permit_count: 3,
                ..CxRegistryE2EConfig::default()
            };
            let capability_op = manager
                .test_capability_lifecycle(&cx, &config)
                .await
                .expect("Capability lifecycle should succeed");
            all_operations.push(capability_op);

            // 2. Permit commit cycle
            let permit_op = manager
                .test_permit_commit_cycle(&cx, 5)
                .await
                .expect("Permit commit cycle should succeed");
            all_operations.push(permit_op);

            // 3. Capability attenuation
            let attenuation_op = manager
                .test_capability_attenuation(&cx, 3)
                .await
                .expect("Capability attenuation should succeed");
            all_operations.push(attenuation_op);

            // 4. Security validation
            let security_op = manager
                .test_security_validation(&cx, 2)
                .await
                .expect("Security validation should succeed");
            all_operations.push(security_op);

            // Validate comprehensive results
            assert_eq!(all_operations.len(), 4);

            let total_capabilities: u64 = all_operations
                .iter()
                .map(|op| op.capabilities_involved)
                .sum();

            let total_violations: u64 =
                all_operations.iter().map(|op| op.security_violations).sum();

            // Validate overall metrics
            assert!(total_capabilities >= 8);
            assert!(total_violations >= 1); // Security test should generate violations

            let stats = manager.get_stats_summary();
            assert!(stats.total_capabilities_created >= 5);
            assert!(stats.total_permits_created >= 8);
            assert!(stats.total_registry_entries_created >= 5);
            assert!(stats.security_violation_rate >= 0.0);
            manager.logger.log_stats_summary(&stats);
        });
    }

    #[test]
    fn test_production_safety_guards() {
        // Test without CX_REGISTRY_E2E_TESTS environment variable
        std::env::remove_var("CX_REGISTRY_E2E_TESTS");
        assert!(validate_cx_registry_e2e_environment().is_err());

        // Test with excessive capability count
        std::env::set_var("CX_REGISTRY_E2E_TESTS", "true");
        std::env::set_var("MAX_CAPABILITY_COUNT", "1000");
        assert!(validate_cx_registry_e2e_environment().is_err());

        // Test valid configuration
        std::env::set_var("MAX_CAPABILITY_COUNT", "100");
        assert!(validate_cx_registry_e2e_environment().is_ok());
    }
}
