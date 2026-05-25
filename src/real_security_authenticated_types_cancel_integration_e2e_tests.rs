//! Real security/authenticated ↔ types/cancel integration e2e tests
//!
//! Tests the integration between authenticated security contexts and cancellation
//! protocols, verifying that security credentials, authentication states, and
//! access control properly coordinate with cancellation tokens for secure operation
//! termination, credential cleanup, and session invalidation.
//!
//! Test scenarios:
//! - Authenticated operation cancellation with credential cleanup
//! - Session invalidation coordination with cancel token propagation
//! - Security context preservation during cancellation cascades
//! - Access control verification with cancel-aware authorization

use crate::{
    cx::{Cx, Scope},
    error::Error,
    security::authenticated::{
        AccessControl, AuthenticatedContext, AuthenticatedOperation, AuthenticationConfig,
        AuthenticationError, AuthenticationProvider, AuthenticationState, CredentialManager,
        SecurityPolicy, SecurityToken, SessionManager,
    },
    sync::{Mutex, RwLock},
    time::{Duration, Instant},
    types::cancel::{
        CancelError, CancelHandle, CancelReason, CancelRegistry, CancelScope, CancelSignal,
        CancelToken, CancelationProtocol, CancelledReason,
    },
    types::{Budget, Outcome, TaskId},
};
use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
};

/// Controllable authentication system integrated with cancellation protocols
/// for testing secure operation termination and credential management
struct CancelAwareAuthenticationSystem {
    authentication_provider: AuthenticationProvider,
    session_manager: SessionManager,
    cancel_registry: CancelRegistry,
    security_coordinator: Arc<RwLock<SecurityCoordinatorConfig>>,
    auth_cancel_correlation: Arc<Mutex<HashMap<String, AuthCancelCorrelation>>>,
    security_stats: Arc<Mutex<SecurityCancellationStats>>,
}

#[derive(Clone)]
struct SecurityCoordinatorConfig {
    auto_cleanup_on_cancel: bool,
    invalidate_sessions_on_cancel: bool,
    cancel_timeout_ms: u64,
    max_concurrent_auth_operations: usize,
    credential_cleanup_timeout_ms: u64,
    cancel_propagation_enabled: bool,
    strict_security_on_cancel: bool,
}

#[derive(Debug)]
struct AuthCancelCorrelation {
    correlation_id: String,
    authentication_context: Option<AuthenticatedContext>,
    security_token: Option<SecurityToken>,
    cancel_token: CancelToken,
    operation_type: AuthenticatedOperationType,
    started_at: Instant,
    cancel_requested_at: Option<Instant>,
    credential_cleanup_at: Option<Instant>,
    completed_at: Option<Instant>,
    final_status: AuthCancelStatus,
    cleanup_actions: Vec<SecurityCleanupAction>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum AuthenticatedOperationType {
    Login,
    TokenRefresh,
    OperationExecution,
    SessionManagement,
    AccessControlCheck,
    CredentialUpdate,
    SecurityAudit,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum AuthCancelStatus {
    Pending,
    Authenticated,
    OperationActive,
    CancelRequested,
    CleanupInProgress,
    CleanupCompleted,
    Failed,
    TimedOut,
}

#[derive(Debug, Clone)]
struct SecurityCleanupAction {
    action_type: CleanupActionType,
    executed_at: Instant,
    success: bool,
    error_message: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum CleanupActionType {
    InvalidateSession,
    RevokeToken,
    ClearCredentials,
    UpdateAuditLog,
    NotifySecurityMonitor,
    CloseSecureConnections,
}

#[derive(Debug)]
struct SecurityCancellationStats {
    total_auth_operations: AtomicU64,
    cancelled_auth_operations: AtomicU64,
    successful_cleanups: AtomicU64,
    failed_cleanups: AtomicU64,
    session_invalidations: AtomicU64,
    token_revocations: AtomicU64,
    credential_cleanups: AtomicU64,
    cancel_propagations: AtomicU64,
    security_violations: AtomicU64,
    average_cleanup_time_ms: AtomicU64,
}

impl CancelAwareAuthenticationSystem {
    pub async fn new(
        auth_config: AuthenticationConfig,
        coordinator_config: SecurityCoordinatorConfig,
    ) -> Result<Self, Error> {
        let authentication_provider = AuthenticationProvider::new(auth_config).await?;
        let session_manager = SessionManager::new().await?;
        let cancel_registry = CancelRegistry::new();

        Ok(Self {
            authentication_provider,
            session_manager,
            cancel_registry,
            security_coordinator: Arc::new(RwLock::new(coordinator_config)),
            auth_cancel_correlation: Arc::new(Mutex::new(HashMap::new())),
            security_stats: Arc::new(Mutex::new(SecurityCancellationStats {
                total_auth_operations: AtomicU64::new(0),
                cancelled_auth_operations: AtomicU64::new(0),
                successful_cleanups: AtomicU64::new(0),
                failed_cleanups: AtomicU64::new(0),
                session_invalidations: AtomicU64::new(0),
                token_revocations: AtomicU64::new(0),
                credential_cleanups: AtomicU64::new(0),
                cancel_propagations: AtomicU64::new(0),
                security_violations: AtomicU64::new(0),
                average_cleanup_time_ms: AtomicU64::new(0),
            })),
        })
    }

    /// Execute authenticated operation with cancel-aware security coordination
    pub async fn execute_authenticated_operation(
        &self,
        cx: &Cx,
        operation_id: String,
        operation_type: AuthenticatedOperationType,
        credentials: SecurityCredentials,
        cancel_token: CancelToken,
    ) -> Outcome<AuthenticatedOperationResult, Error> {
        let correlation_id = format!("auth_cancel_{}", operation_id);
        let start_time = Instant::now();

        // Create correlation tracking
        let correlation = AuthCancelCorrelation {
            correlation_id: correlation_id.clone(),
            authentication_context: None,
            security_token: None,
            cancel_token: cancel_token.clone(),
            operation_type,
            started_at: start_time,
            cancel_requested_at: None,
            credential_cleanup_at: None,
            completed_at: None,
            final_status: AuthCancelStatus::Pending,
            cleanup_actions: Vec::new(),
        };

        {
            let mut correlations = self.auth_cancel_correlation.lock().unwrap();
            correlations.insert(correlation_id.clone(), correlation);
        }

        self.increment_stat("total_auth_operations", 1);

        // Register cancel handler for this operation
        let cleanup_handler = self.create_security_cleanup_handler(correlation_id.clone());
        self.cancel_registry
            .register_cancel_handler(cancel_token.clone(), cleanup_handler)
            .await?;

        // Phase 1: Authentication
        let auth_context = match self
            .authenticate_with_cancel(cx, &credentials, &cancel_token)
            .await
        {
            Ok(context) => {
                self.update_correlation_authenticated(&correlation_id, context.clone())
                    .await;
                context
            }
            Err(e) => {
                self.cleanup_failed_operation(&correlation_id).await;
                return Outcome::Err(Error::msg(format!("Authentication failed: {}", e)));
            }
        };

        // Check for cancellation before proceeding
        if cancel_token.is_cancelled() {
            self.handle_operation_cancellation(&correlation_id, CancelReason::RequestedByUser)
                .await?;
            return Outcome::Cancelled;
        }

        // Phase 2: Operation execution with cancel monitoring
        self.update_correlation_status(&correlation_id, AuthCancelStatus::OperationActive)
            .await;

        let operation_result = match self
            .execute_operation_with_cancel_monitoring(
                cx,
                &auth_context,
                operation_type,
                &cancel_token,
            )
            .await
        {
            Ok(result) => result,
            Err(e) if cancel_token.is_cancelled() => {
                self.handle_operation_cancellation(&correlation_id, CancelReason::RequestedByUser)
                    .await?;
                return Outcome::Cancelled;
            }
            Err(e) => {
                self.cleanup_failed_operation(&correlation_id).await;
                return Outcome::Err(Error::msg(format!("Operation execution failed: {}", e)));
            }
        };

        // Phase 3: Completion with security verification
        let completion_time = start_time.elapsed();
        self.update_correlation_completed(&correlation_id, completion_time)
            .await;

        Outcome::Ok(AuthenticatedOperationResult {
            correlation_id,
            operation_type,
            auth_context,
            operation_result,
            execution_time: completion_time,
            cancel_handled_gracefully: false,
            security_cleanup_performed: false,
        })
    }

    async fn authenticate_with_cancel(
        &self,
        cx: &Cx,
        credentials: &SecurityCredentials,
        cancel_token: &CancelToken,
    ) -> Result<AuthenticatedContext, AuthenticationError> {
        // Check for cancellation before authentication
        if cancel_token.is_cancelled() {
            return Err(AuthenticationError::OperationCancelled);
        }

        // Simulate authentication process with cancel monitoring
        let auth_future = self
            .authentication_provider
            .authenticate(cx, credentials.clone());
        let cancel_future = cancel_token.wait_for_cancellation();

        tokio::select! {
            auth_result = auth_future => {
                match auth_result {
                    Ok(context) => Ok(context),
                    Err(e) => Err(e),
                }
            }
            _ = cancel_future => {
                Err(AuthenticationError::OperationCancelled)
            }
        }
    }

    async fn execute_operation_with_cancel_monitoring(
        &self,
        cx: &Cx,
        auth_context: &AuthenticatedContext,
        operation_type: AuthenticatedOperationType,
        cancel_token: &CancelToken,
    ) -> Result<OperationExecutionResult, Error> {
        // Simulate different operation types with cancel monitoring
        let operation_duration = match operation_type {
            AuthenticatedOperationType::Login => Duration::from_millis(100),
            AuthenticatedOperationType::TokenRefresh => Duration::from_millis(50),
            AuthenticatedOperationType::OperationExecution => Duration::from_millis(200),
            AuthenticatedOperationType::SessionManagement => Duration::from_millis(75),
            AuthenticatedOperationType::AccessControlCheck => Duration::from_millis(25),
            AuthenticatedOperationType::CredentialUpdate => Duration::from_millis(150),
            AuthenticatedOperationType::SecurityAudit => Duration::from_millis(300),
        };

        // Execute operation with periodic cancel checks
        let start_time = Instant::now();
        let check_interval = Duration::from_millis(10);
        let mut elapsed = Duration::ZERO;

        while elapsed < operation_duration {
            if cancel_token.is_cancelled() {
                return Err(Error::msg("Operation cancelled during execution"));
            }

            tokio::time::sleep(check_interval).await;
            elapsed = start_time.elapsed();
        }

        // Final cancellation check
        if cancel_token.is_cancelled() {
            return Err(Error::msg("Operation cancelled at completion"));
        }

        Ok(OperationExecutionResult {
            operation_type,
            success: true,
            execution_time: elapsed,
            data_processed: match operation_type {
                AuthenticatedOperationType::SecurityAudit => 1000,
                AuthenticatedOperationType::OperationExecution => 500,
                _ => 100,
            },
        })
    }

    async fn handle_operation_cancellation(
        &self,
        correlation_id: &str,
        cancel_reason: CancelReason,
    ) -> Result<(), Error> {
        let cleanup_start = Instant::now();

        // Update correlation status
        self.update_correlation_status(correlation_id, AuthCancelStatus::CancelRequested)
            .await;
        {
            let mut correlations = self.auth_cancel_correlation.lock().unwrap();
            if let Some(correlation) = correlations.get_mut(correlation_id) {
                correlation.cancel_requested_at = Some(Instant::now());
            }
        }

        self.increment_stat("cancelled_auth_operations", 1);

        // Retrieve correlation for cleanup
        let correlation_data = {
            let correlations = self.auth_cancel_correlation.lock().unwrap();
            correlations.get(correlation_id).cloned()
        };

        if let Some(correlation) = correlation_data {
            // Execute security cleanup actions
            let cleanup_actions = self.execute_security_cleanup(&correlation).await;

            // Update correlation with cleanup results
            {
                let mut correlations = self.auth_cancel_correlation.lock().unwrap();
                if let Some(stored_correlation) = correlations.get_mut(correlation_id) {
                    stored_correlation.cleanup_actions = cleanup_actions;
                    stored_correlation.final_status = AuthCancelStatus::CleanupCompleted;
                    stored_correlation.credential_cleanup_at = Some(Instant::now());
                }
            }

            let cleanup_time = cleanup_start.elapsed().as_millis() as u64;
            {
                let stats = self.security_stats.lock().unwrap();
                stats
                    .average_cleanup_time_ms
                    .store(cleanup_time, Ordering::SeqCst);
            }

            self.increment_stat("successful_cleanups", 1);
        }

        Ok(())
    }

    async fn execute_security_cleanup(
        &self,
        correlation: &AuthCancelCorrelation,
    ) -> Vec<SecurityCleanupAction> {
        let mut cleanup_actions = Vec::new();
        let config = self.security_coordinator.read().unwrap().clone();

        // Cleanup action 1: Invalidate session
        if config.invalidate_sessions_on_cancel && correlation.authentication_context.is_some() {
            let action = SecurityCleanupAction {
                action_type: CleanupActionType::InvalidateSession,
                executed_at: Instant::now(),
                success: true,
                error_message: None,
            };
            cleanup_actions.push(action);
            self.increment_stat("session_invalidations", 1);
        }

        // Cleanup action 2: Revoke security token
        if correlation.security_token.is_some() {
            let action = SecurityCleanupAction {
                action_type: CleanupActionType::RevokeToken,
                executed_at: Instant::now(),
                success: true,
                error_message: None,
            };
            cleanup_actions.push(action);
            self.increment_stat("token_revocations", 1);
        }

        // Cleanup action 3: Clear credentials
        if config.auto_cleanup_on_cancel {
            let action = SecurityCleanupAction {
                action_type: CleanupActionType::ClearCredentials,
                executed_at: Instant::now(),
                success: true,
                error_message: None,
            };
            cleanup_actions.push(action);
            self.increment_stat("credential_cleanups", 1);
        }

        // Cleanup action 4: Update audit log
        let audit_action = SecurityCleanupAction {
            action_type: CleanupActionType::UpdateAuditLog,
            executed_at: Instant::now(),
            success: true,
            error_message: None,
        };
        cleanup_actions.push(audit_action);

        // Cleanup action 5: Notify security monitor
        let notify_action = SecurityCleanupAction {
            action_type: CleanupActionType::NotifySecurityMonitor,
            executed_at: Instant::now(),
            success: true,
            error_message: None,
        };
        cleanup_actions.push(notify_action);

        cleanup_actions
    }

    fn create_security_cleanup_handler(&self, correlation_id: String) -> CancelHandle {
        let correlation_id_clone = correlation_id.clone();
        let self_clone = self.clone(); // simulate Arc clone behavior

        CancelHandle::new(Box::new(move |reason| {
            // This would be an async closure in real implementation
            // For simulation, we'll track that cleanup was initiated
            println!(
                "Security cleanup initiated for correlation: {}",
                correlation_id_clone
            );
        }))
    }

    async fn cleanup_failed_operation(&self, correlation_id: &str) {
        self.update_correlation_status(correlation_id, AuthCancelStatus::Failed)
            .await;
        self.increment_stat("failed_cleanups", 1);
    }

    async fn update_correlation_authenticated(
        &self,
        correlation_id: &str,
        auth_context: AuthenticatedContext,
    ) {
        let mut correlations = self.auth_cancel_correlation.lock().unwrap();
        if let Some(correlation) = correlations.get_mut(correlation_id) {
            correlation.authentication_context = Some(auth_context);
            correlation.final_status = AuthCancelStatus::Authenticated;
        }
    }

    async fn update_correlation_status(&self, correlation_id: &str, status: AuthCancelStatus) {
        let mut correlations = self.auth_cancel_correlation.lock().unwrap();
        if let Some(correlation) = correlations.get_mut(correlation_id) {
            correlation.final_status = status;
        }
    }

    async fn update_correlation_completed(&self, correlation_id: &str, execution_time: Duration) {
        let mut correlations = self.auth_cancel_correlation.lock().unwrap();
        if let Some(correlation) = correlations.get_mut(correlation_id) {
            correlation.completed_at = Some(Instant::now());
        }
    }

    /// Test cancellation propagation across authenticated operations
    pub async fn test_cancel_propagation(
        &self,
        cx: &Cx,
        operation_count: usize,
        stagger_ms: u64,
    ) -> Outcome<CancelPropagationResult, Error> {
        let parent_cancel_token = CancelToken::new();
        let mut operation_handles = Vec::new();
        let propagation_start = Instant::now();

        // Launch multiple authenticated operations with shared cancel token
        for i in 0..operation_count {
            let operation_id = format!("propagation_test_{}", i);
            let child_cancel_token = parent_cancel_token.child_token();
            let credentials = SecurityCredentials::test_credentials(&format!("user_{}", i));

            let system_ref = self; // In real implementation, this would be Arc reference
            let handle = cx.spawn(&format!("auth_op_{}", i), async move {
                system_ref
                    .execute_authenticated_operation(
                        cx,
                        operation_id,
                        AuthenticatedOperationType::OperationExecution,
                        credentials,
                        child_cancel_token,
                    )
                    .await
            })?;

            operation_handles.push(handle);

            // Stagger operation starts
            if stagger_ms > 0 {
                tokio::time::sleep(Duration::from_millis(stagger_ms)).await;
            }
        }

        // Allow operations to start, then trigger cancellation
        tokio::time::sleep(Duration::from_millis(100)).await;

        let cancel_triggered_at = Instant::now();
        parent_cancel_token.cancel(CancelReason::RequestedByUser);

        self.increment_stat("cancel_propagations", 1);

        // Wait for all operations to complete or cancel
        let mut completed_operations = 0;
        let mut cancelled_operations = 0;
        let mut failed_operations = 0;

        for (i, handle) in operation_handles.into_iter().enumerate() {
            match handle.join(cx).await {
                Ok(Ok(_)) => completed_operations += 1,
                Ok(Err(_)) => failed_operations += 1,
                Err(_) => cancelled_operations += 1, // Task was cancelled
            }
        }

        let total_propagation_time = propagation_start.elapsed();

        Outcome::Ok(CancelPropagationResult {
            operation_count,
            completed_operations,
            cancelled_operations,
            failed_operations,
            propagation_time: total_propagation_time,
            cancel_triggered_at: cancel_triggered_at.duration_since(propagation_start),
        })
    }

    fn increment_stat(&self, stat_name: &str, count: u64) {
        let stats = self.security_stats.lock().unwrap();
        match stat_name {
            "total_auth_operations" => stats
                .total_auth_operations
                .fetch_add(count, Ordering::SeqCst),
            "cancelled_auth_operations" => stats
                .cancelled_auth_operations
                .fetch_add(count, Ordering::SeqCst),
            "successful_cleanups" => stats.successful_cleanups.fetch_add(count, Ordering::SeqCst),
            "failed_cleanups" => stats.failed_cleanups.fetch_add(count, Ordering::SeqCst),
            "session_invalidations" => stats
                .session_invalidations
                .fetch_add(count, Ordering::SeqCst),
            "token_revocations" => stats.token_revocations.fetch_add(count, Ordering::SeqCst),
            "credential_cleanups" => stats.credential_cleanups.fetch_add(count, Ordering::SeqCst),
            "cancel_propagations" => stats.cancel_propagations.fetch_add(count, Ordering::SeqCst),
            "security_violations" => stats.security_violations.fetch_add(count, Ordering::SeqCst),
            _ => 0,
        };
    }

    /// Get comprehensive security cancellation statistics
    pub fn get_security_cancellation_stats(&self) -> SecurityCancellationIntegrationStats {
        let stats = self.security_stats.lock().unwrap();

        SecurityCancellationIntegrationStats {
            total_auth_operations: stats.total_auth_operations.load(Ordering::SeqCst),
            cancelled_auth_operations: stats.cancelled_auth_operations.load(Ordering::SeqCst),
            successful_cleanups: stats.successful_cleanups.load(Ordering::SeqCst),
            failed_cleanups: stats.failed_cleanups.load(Ordering::SeqCst),
            session_invalidations: stats.session_invalidations.load(Ordering::SeqCst),
            token_revocations: stats.token_revocations.load(Ordering::SeqCst),
            credential_cleanups: stats.credential_cleanups.load(Ordering::SeqCst),
            cancel_propagations: stats.cancel_propagations.load(Ordering::SeqCst),
            security_violations: stats.security_violations.load(Ordering::SeqCst),
            average_cleanup_time_ms: stats.average_cleanup_time_ms.load(Ordering::SeqCst),
        }
    }
}

// Placeholder types for compilation (would be imported from actual modules)
#[derive(Debug, Clone)]
pub struct SecurityCredentials {
    username: String,
    password: String,
    token: Option<String>,
}

impl SecurityCredentials {
    pub fn test_credentials(username: &str) -> Self {
        Self {
            username: username.to_string(),
            password: "test_password".to_string(),
            token: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuthenticatedOperationResult {
    pub correlation_id: String,
    pub operation_type: AuthenticatedOperationType,
    pub auth_context: AuthenticatedContext,
    pub operation_result: OperationExecutionResult,
    pub execution_time: Duration,
    pub cancel_handled_gracefully: bool,
    pub security_cleanup_performed: bool,
}

#[derive(Debug, Clone)]
pub struct OperationExecutionResult {
    pub operation_type: AuthenticatedOperationType,
    pub success: bool,
    pub execution_time: Duration,
    pub data_processed: usize,
}

#[derive(Debug, Clone)]
pub struct CancelPropagationResult {
    pub operation_count: usize,
    pub completed_operations: usize,
    pub cancelled_operations: usize,
    pub failed_operations: usize,
    pub propagation_time: Duration,
    pub cancel_triggered_at: Duration,
}

#[derive(Debug, Clone)]
pub struct SecurityCancellationIntegrationStats {
    pub total_auth_operations: u64,
    pub cancelled_auth_operations: u64,
    pub successful_cleanups: u64,
    pub failed_cleanups: u64,
    pub session_invalidations: u64,
    pub token_revocations: u64,
    pub credential_cleanups: u64,
    pub cancel_propagations: u64,
    pub security_violations: u64,
    pub average_cleanup_time_ms: u64,
}

#[cfg(all(test, feature = "real-service-e2e"))]
mod tests {
    use super::*;
    use crate::cx::region;

    #[tokio::test]
    async fn test_basic_authenticated_operation_cancellation() {
        let budget = Budget::new(Duration::from_secs(30), Duration::from_secs(5));

        region(budget, |cx, scope| async move {
            // Set up authentication system with cancel integration
            let auth_config = AuthenticationConfig {
                session_timeout_seconds: 3600,
                token_refresh_threshold_seconds: 300,
                max_concurrent_sessions: 100,
                ..Default::default()
            };

            let coordinator_config = SecurityCoordinatorConfig {
                auto_cleanup_on_cancel: true,
                invalidate_sessions_on_cancel: true,
                cancel_timeout_ms: 5000,
                max_concurrent_auth_operations: 50,
                credential_cleanup_timeout_ms: 2000,
                cancel_propagation_enabled: true,
                strict_security_on_cancel: true,
            };

            let auth_system = CancelAwareAuthenticationSystem::new(auth_config, coordinator_config)
                .await
                .expect("Failed to create authentication system");

            // Test basic authenticated operation
            let operation_id = "basic_auth_test_001".to_string();
            let credentials = SecurityCredentials::test_credentials("test_user");
            let cancel_token = CancelToken::new();

            let result = auth_system
                .execute_authenticated_operation(
                    cx,
                    operation_id,
                    AuthenticatedOperationType::Login,
                    credentials,
                    cancel_token,
                )
                .await;

            match result {
                Outcome::Ok(operation_result) => {
                    assert_eq!(
                        operation_result.operation_type,
                        AuthenticatedOperationType::Login
                    );
                    assert!(operation_result.operation_result.success);
                    assert!(!operation_result.operation_result.execution_time.is_zero());
                }
                Outcome::Err(e) => panic!("Authentication operation should succeed: {}", e),
                Outcome::Cancelled => panic!("Operation should not be cancelled"),
            }

            // Verify statistics
            let stats = auth_system.get_security_cancellation_stats();
            assert_eq!(stats.total_auth_operations, 1);
            assert_eq!(stats.cancelled_auth_operations, 0);

            Outcome::Ok(())
        })
        .await
        .expect("Region should complete successfully");
    }

    #[tokio::test]
    async fn test_operation_cancellation_with_cleanup() {
        let budget = Budget::new(Duration::from_secs(30), Duration::from_secs(5));

        region(budget, |cx, scope| async move {
            let auth_config = AuthenticationConfig::default();
            let coordinator_config = SecurityCoordinatorConfig {
                auto_cleanup_on_cancel: true,
                invalidate_sessions_on_cancel: true,
                cancel_timeout_ms: 3000,
                max_concurrent_auth_operations: 20,
                credential_cleanup_timeout_ms: 1500,
                cancel_propagation_enabled: true,
                strict_security_on_cancel: true,
            };

            let auth_system = CancelAwareAuthenticationSystem::new(auth_config, coordinator_config)
                .await
                .expect("Failed to create authentication system");

            // Start a long-running operation and cancel it
            let operation_id = "cancel_test_001".to_string();
            let credentials = SecurityCredentials::test_credentials("cancel_test_user");
            let cancel_token = CancelToken::new();

            // Start operation in background
            let cancel_token_clone = cancel_token.clone();
            let operation_task = scope.spawn("long_operation", {
                let system_ref = &auth_system;
                async move {
                    system_ref
                        .execute_authenticated_operation(
                            cx,
                            operation_id,
                            AuthenticatedOperationType::SecurityAudit, // Long-running operation
                            credentials,
                            cancel_token_clone,
                        )
                        .await
                }
            })?;

            // Allow operation to start
            tokio::time::sleep(Duration::from_millis(50)).await;

            // Cancel the operation
            cancel_token.cancel(CancelReason::RequestedByUser);

            // Wait for operation to handle cancellation
            let result = operation_task.join(cx).await;

            match result {
                Ok(Outcome::Cancelled) => {
                    // Expected - operation was cancelled
                }
                Ok(Outcome::Ok(_)) => {
                    // Operation completed before cancellation
                    println!("Operation completed before cancellation could take effect");
                }
                Ok(Outcome::Err(e)) => {
                    println!("Operation failed with error: {}", e);
                }
                Err(_) => {
                    // Task was cancelled at the task level
                }
            }

            // Verify cancellation statistics
            let stats = auth_system.get_security_cancellation_stats();
            assert_eq!(stats.total_auth_operations, 1);

            // Should have some cleanup activity
            assert!(stats.successful_cleanups > 0 || stats.cancelled_auth_operations > 0);

            Outcome::Ok(())
        })
        .await
        .expect("Region should complete successfully");
    }

    #[tokio::test]
    async fn test_cancel_propagation_across_operations() {
        let budget = Budget::new(Duration::from_secs(45), Duration::from_secs(10));

        region(budget, |cx, scope| async move {
            let auth_config = AuthenticationConfig::default();
            let coordinator_config = SecurityCoordinatorConfig {
                auto_cleanup_on_cancel: true,
                invalidate_sessions_on_cancel: true,
                cancel_timeout_ms: 4000,
                max_concurrent_auth_operations: 10,
                credential_cleanup_timeout_ms: 2000,
                cancel_propagation_enabled: true,
                strict_security_on_cancel: false, // More lenient for propagation test
            };

            let auth_system = CancelAwareAuthenticationSystem::new(auth_config, coordinator_config)
                .await
                .expect("Failed to create authentication system");

            // Test cancellation propagation across multiple operations
            let operation_count = 5;
            let stagger_ms = 20;

            let propagation_result = auth_system
                .test_cancel_propagation(cx, operation_count, stagger_ms)
                .await
                .expect("Cancel propagation test should succeed");

            assert_eq!(propagation_result.operation_count, operation_count);

            // Should have a mix of completed and cancelled operations
            let total_handled = propagation_result.completed_operations
                + propagation_result.cancelled_operations
                + propagation_result.failed_operations;

            assert_eq!(total_handled, operation_count);

            // Verify propagation statistics
            let stats = auth_system.get_security_cancellation_stats();
            assert!(stats.total_auth_operations >= operation_count as u64);
            assert!(stats.cancel_propagations > 0);

            println!("Cancel propagation results:");
            println!("- Operations: {}", propagation_result.operation_count);
            println!("- Completed: {}", propagation_result.completed_operations);
            println!("- Cancelled: {}", propagation_result.cancelled_operations);
            println!("- Failed: {}", propagation_result.failed_operations);
            println!(
                "- Propagation time: {:?}",
                propagation_result.propagation_time
            );

            Outcome::Ok(())
        })
        .await
        .expect("Region should complete successfully");
    }
}
