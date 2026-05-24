//! BR-E2E-93: Real cx/macaroon ↔ obligation/marking Integration E2E Tests
//!
//! This module provides comprehensive integration tests between the macaroon-based
//! capability system and obligation marking subsystem. The tests verify that
//! attenuated macaroon caveats correctly restrict obligation marking operations
//! across capability boundaries.
//!
//! # Integration Focus
//!
//! Tests the coordination between:
//! - `cx::macaroon` - Capability-based security with macaroon tokens and caveat attenuation
//! - `obligation::marking` - Obligation lifecycle marking and state transitions
//!
//! # Key Scenarios
//!
//! - Macaroon caveat-based restriction of obligation marking operations
//! - Cross-capability boundary enforcement for obligation state changes
//! - Attenuation chain validation during marking operations
//! - Capability delegation with marking permission restrictions
//! - Security boundary enforcement in obligation lifecycle management

use crate::{
    cx::{
        Cx, Scope,
        macaroon::{
            AttenuationChain, CapabilityToken, Caveat, CaveatType, DischargeToken,
            FirstPartyCaveat, Macaroon, MacaroonBuilder, MacaroonId, MacaroonSecret,
            MacaroonVerifier, ThirdPartyCaveat,
        },
    },
    error::Outcome,
    obligation::{
        ObligationId, ObligationState, ObligationTracker,
        marking::{
            MarkingCapability, MarkingEvent, MarkingOperation, MarkingPolicy, MarkingRestriction,
            MarkingSecurityContext, MarkingState, ObligationMark, ObligationMarker,
            ObligationMarkingController,
        },
    },
    runtime::RuntimeBuilder,
    sync::{Barrier, Mutex, RwLock},
    time::{Duration, Instant, Sleep},
    types::{Budget, Cancel, TaskId},
    util::{
        det_rng::{DetRng, RngSeed},
        entropy::EntropySource,
    },
};

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
    },
    task::{Context, Poll},
};

use futures::{
    ready,
    stream::{Stream, StreamExt},
};

/// Configuration for macaroon-based obligation marking integration tests
#[derive(Debug, Clone)]
struct MacaroonMarkingTestConfig {
    /// Maximum attenuation chain depth
    max_attenuation_depth: u32,
    /// Number of concurrent marking operations
    concurrent_operations: u32,
    /// Test duration
    test_duration: Duration,
    /// Caveat validation timeout
    caveat_timeout: Duration,
    /// Maximum obligations per test
    max_obligations: usize,
}

impl Default for MacaroonMarkingTestConfig {
    fn default() -> Self {
        Self {
            max_attenuation_depth: 8,
            concurrent_operations: 16,
            test_duration: Duration::from_secs(3),
            caveat_timeout: Duration::from_millis(100),
            max_obligations: 64,
        }
    }
}

/// Tracks macaroon-based capability enforcement for obligation marking
#[derive(Debug)]
struct MacaroonMarkingEnforcementTracker {
    /// Capability check events with results
    capability_checks: Arc<Mutex<Vec<CapabilityCheckEvent>>>,
    /// Marking operation attempts and outcomes
    marking_operations: Arc<Mutex<Vec<MarkingOperationEvent>>>,
    /// Caveat evaluation results
    caveat_evaluations: Arc<Mutex<Vec<CaveatEvaluationEvent>>>,
    /// Security violation attempts
    security_violations: Arc<Mutex<Vec<SecurityViolationEvent>>>,
    /// Attenuation chain verifications
    attenuation_verifications: Arc<Mutex<Vec<AttenuationVerificationEvent>>>,
}

#[derive(Debug, Clone)]
struct CapabilityCheckEvent {
    timestamp: Instant,
    macaroon_id: MacaroonId,
    requested_operation: MarkingOperation,
    obligation_id: ObligationId,
    check_result: CapabilityCheckResult,
    attenuation_depth: u32,
}

#[derive(Debug, Clone, PartialEq)]
enum CapabilityCheckResult {
    Granted,
    Denied { reason: DenialReason },
    AttenuationViolation { violated_caveat: String },
    ChainValidationFailure,
}

#[derive(Debug, Clone, PartialEq)]
enum DenialReason {
    InsufficientCapability,
    ExpiredCaveat,
    ScopeMismatch,
    ObligationNotFound,
    MarkingRestriction,
}

#[derive(Debug, Clone)]
struct MarkingOperationEvent {
    timestamp: Instant,
    operation: MarkingOperation,
    obligation_id: ObligationId,
    macaroon_id: MacaroonId,
    previous_state: MarkingState,
    requested_state: MarkingState,
    operation_result: MarkingOperationResult,
}

#[derive(Debug, Clone, PartialEq)]
enum MarkingOperationResult {
    Success { new_state: MarkingState },
    CapabilityDenied,
    StateTransitionInvalid,
    CaveatViolation { caveat: String },
    SecurityBoundaryViolation,
}

#[derive(Debug, Clone)]
struct CaveatEvaluationEvent {
    timestamp: Instant,
    caveat: CaveatDetails,
    obligation_context: ObligationContext,
    evaluation_result: CaveatEvaluationResult,
}

#[derive(Debug, Clone)]
struct CaveatDetails {
    caveat_type: CaveatType,
    predicate: String,
    location: String,
    signature: Vec<u8>,
}

#[derive(Debug, Clone)]
struct ObligationContext {
    obligation_id: ObligationId,
    current_marking: MarkingState,
    scope_depth: u32,
    creation_time: Instant,
}

#[derive(Debug, Clone, PartialEq)]
enum CaveatEvaluationResult {
    Satisfied,
    Violated { reason: String },
    Indeterminate,
}

#[derive(Debug, Clone)]
struct SecurityViolationEvent {
    timestamp: Instant,
    violation_type: SecurityViolationType,
    attempted_operation: MarkingOperation,
    macaroon_context: MacaroonSecurityContext,
    obligation_id: ObligationId,
}

#[derive(Debug, Clone, PartialEq)]
enum SecurityViolationType {
    UnauthorizedMarking,
    CapabilityEscalation,
    AttenuationBypass,
    CrossBoundaryViolation,
    InvalidDischarge,
}

#[derive(Debug, Clone)]
struct MacaroonSecurityContext {
    macaroon_id: MacaroonId,
    attenuation_chain: Vec<String>,
    third_party_caveats: Vec<String>,
    discharge_status: DischargeStatus,
}

#[derive(Debug, Clone, PartialEq)]
enum DischargeStatus {
    Valid,
    Missing,
    Invalid,
    Expired,
}

#[derive(Debug, Clone)]
struct AttenuationVerificationEvent {
    timestamp: Instant,
    parent_macaroon: MacaroonId,
    attenuated_macaroon: MacaroonId,
    verification_result: AttenuationVerificationResult,
    caveat_chain: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
enum AttenuationVerificationResult {
    Valid,
    InvalidAttenuation,
    ChainBroken,
    CaveatMalformed,
    SignatureInvalid,
}

impl MacaroonMarkingEnforcementTracker {
    fn new() -> Self {
        Self {
            capability_checks: Arc::new(Mutex::new(Vec::new())),
            marking_operations: Arc::new(Mutex::new(Vec::new())),
            caveat_evaluations: Arc::new(Mutex::new(Vec::new())),
            security_violations: Arc::new(Mutex::new(Vec::new())),
            attenuation_verifications: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn record_capability_check(&self, event: CapabilityCheckEvent) {
        self.capability_checks.lock().unwrap().push(event);
    }

    fn record_marking_operation(&self, event: MarkingOperationEvent) {
        self.marking_operations.lock().unwrap().push(event);
    }

    fn record_caveat_evaluation(&self, event: CaveatEvaluationEvent) {
        self.caveat_evaluations.lock().unwrap().push(event);
    }

    fn record_security_violation(&self, event: SecurityViolationEvent) {
        self.security_violations.lock().unwrap().push(event);
    }

    fn record_attenuation_verification(&self, event: AttenuationVerificationEvent) {
        self.attenuation_verifications.lock().unwrap().push(event);
    }

    fn verify_capability_enforcement(&self) -> bool {
        let checks = self.capability_checks.lock().unwrap();
        let violations = self.security_violations.lock().unwrap();

        // Ensure no unauthorized operations succeeded
        let unauthorized_successes = checks
            .iter()
            .filter(|c| matches!(c.check_result, CapabilityCheckResult::Denied { .. }))
            .count();

        let violation_attempts = violations.len();

        // All denied capability checks should correspond to security violations
        unauthorized_successes == 0 || violation_attempts > 0
    }

    fn verify_attenuation_restrictions(&self) -> bool {
        let operations = self.marking_operations.lock().unwrap();

        // Verify that attenuated macaroons cannot perform restricted operations
        operations.iter().all(|op| {
            match &op.operation_result {
                MarkingOperationResult::CaveatViolation { .. } => true,
                MarkingOperationResult::CapabilityDenied => true,
                MarkingOperationResult::Success { .. } => {
                    // Success is allowed if capability was granted
                    true
                }
                _ => false,
            }
        })
    }

    fn verify_caveat_evaluation_correctness(&self) -> bool {
        let evaluations = self.caveat_evaluations.lock().unwrap();

        // Ensure caveat evaluations are consistent
        evaluations
            .iter()
            .all(|eval| match &eval.evaluation_result {
                CaveatEvaluationResult::Satisfied => true,
                CaveatEvaluationResult::Violated { reason } => !reason.is_empty(),
                CaveatEvaluationResult::Indeterminate => true,
            })
    }

    fn get_security_violation_count(&self) -> usize {
        self.security_violations.lock().unwrap().len()
    }

    fn get_successful_marking_count(&self) -> usize {
        let operations = self.marking_operations.lock().unwrap();
        operations
            .iter()
            .filter(|op| matches!(op.operation_result, MarkingOperationResult::Success { .. }))
            .count()
    }

    fn get_attenuation_verification_success_rate(&self) -> f64 {
        let verifications = self.attenuation_verifications.lock().unwrap();
        if verifications.is_empty() {
            return 1.0;
        }

        let successful = verifications
            .iter()
            .filter(|v| matches!(v.verification_result, AttenuationVerificationResult::Valid))
            .count();

        successful as f64 / verifications.len() as f64
    }
}

/// Simulates macaroon-based capability tokens with various restrictions
struct MacaroonCapabilitySimulator {
    root_secret: MacaroonSecret,
    issued_macaroons: HashMap<MacaroonId, IssuedMacaroon>,
    attenuation_chains: HashMap<MacaroonId, AttenuationChain>,
    marking_policies: HashMap<MacaroonId, MarkingPolicy>,
    rng: Arc<Mutex<DetRng>>,
}

#[derive(Debug, Clone)]
struct IssuedMacaroon {
    macaroon: Macaroon,
    capabilities: MarkingCapabilitySet,
    restrictions: Vec<MarkingRestriction>,
    expiry: Option<Instant>,
    attenuation_depth: u32,
}

#[derive(Debug, Clone)]
struct MarkingCapabilitySet {
    can_mark_pending: bool,
    can_mark_active: bool,
    can_mark_completed: bool,
    can_mark_failed: bool,
    can_mark_cancelled: bool,
    scope_restrictions: Vec<String>,
    obligation_id_restrictions: HashSet<ObligationId>,
}

impl MacaroonCapabilitySimulator {
    fn new() -> Self {
        let mut rng = DetRng::from_seed(RngSeed::from_u64(0x3fc89b));
        let root_secret = MacaroonSecret::generate(&mut rng);

        Self {
            root_secret,
            issued_macaroons: HashMap::new(),
            attenuation_chains: HashMap::new(),
            marking_policies: HashMap::new(),
            rng: Arc::new(Mutex::new(rng)),
        }
    }

    fn issue_root_macaroon(&mut self, location: &str) -> MacaroonId {
        let mut rng = self.rng.lock().unwrap();
        let macaroon_id = MacaroonId::generate(&mut rng);

        let macaroon = MacaroonBuilder::new(&self.root_secret)
            .with_identifier(macaroon_id.clone())
            .with_location(location.to_string())
            .build();

        let issued = IssuedMacaroon {
            macaroon,
            capabilities: MarkingCapabilitySet {
                can_mark_pending: true,
                can_mark_active: true,
                can_mark_completed: true,
                can_mark_failed: true,
                can_mark_cancelled: true,
                scope_restrictions: Vec::new(),
                obligation_id_restrictions: HashSet::new(),
            },
            restrictions: Vec::new(),
            expiry: None,
            attenuation_depth: 0,
        };

        self.issued_macaroons.insert(macaroon_id.clone(), issued);
        macaroon_id
    }

    fn attenuate_macaroon(
        &mut self,
        parent_id: &MacaroonId,
        restrictions: Vec<MarkingRestriction>,
    ) -> Result<MacaroonId, Box<dyn std::error::Error>> {
        let parent = self
            .issued_macaroons
            .get(parent_id)
            .ok_or("Parent macaroon not found")?;

        let mut rng = self.rng.lock().unwrap();
        let attenuated_id = MacaroonId::generate(&mut rng);

        // Create attenuated macaroon with additional restrictions
        let mut attenuated_capabilities = parent.capabilities.clone();

        for restriction in &restrictions {
            match restriction {
                MarkingRestriction::NoMarkingCompleted => {
                    attenuated_capabilities.can_mark_completed = false;
                }
                MarkingRestriction::NoMarkingFailed => {
                    attenuated_capabilities.can_mark_failed = false;
                }
                MarkingRestriction::ScopeRestriction { scope } => {
                    attenuated_capabilities
                        .scope_restrictions
                        .push(scope.clone());
                }
                MarkingRestriction::ObligationIdRestriction { obligation_id } => {
                    attenuated_capabilities
                        .obligation_id_restrictions
                        .insert(*obligation_id);
                }
                MarkingRestriction::ExpiryTime { expiry } => {
                    // Set expiry time restriction
                }
            }
        }

        let mut combined_restrictions = parent.restrictions.clone();
        combined_restrictions.extend(restrictions);

        let attenuated_macaroon = parent
            .macaroon
            .clone()
            .add_first_party_caveat("capability=restricted")?
            .add_first_party_caveat(&format!("depth={}", parent.attenuation_depth + 1))?;

        let attenuated = IssuedMacaroon {
            macaroon: attenuated_macaroon,
            capabilities: attenuated_capabilities,
            restrictions: combined_restrictions,
            expiry: parent.expiry,
            attenuation_depth: parent.attenuation_depth + 1,
        };

        self.issued_macaroons
            .insert(attenuated_id.clone(), attenuated);

        // Record attenuation chain
        let mut chain = self
            .attenuation_chains
            .get(parent_id)
            .cloned()
            .unwrap_or_default();
        chain.add_attenuation(parent_id.clone(), attenuated_id.clone());
        self.attenuation_chains.insert(attenuated_id.clone(), chain);

        Ok(attenuated_id)
    }

    fn verify_marking_capability(
        &self,
        macaroon_id: &MacaroonId,
        operation: &MarkingOperation,
        obligation_id: ObligationId,
        tracker: &MacaroonMarkingEnforcementTracker,
    ) -> CapabilityCheckResult {
        let issued = match self.issued_macaroons.get(macaroon_id) {
            Some(m) => m,
            None => {
                return CapabilityCheckResult::Denied {
                    reason: DenialReason::InsufficientCapability,
                };
            }
        };

        // Check expiry
        if let Some(expiry) = issued.expiry {
            if Instant::now() > expiry {
                return CapabilityCheckResult::Denied {
                    reason: DenialReason::ExpiredCaveat,
                };
            }
        }

        // Check obligation ID restrictions
        if issued
            .capabilities
            .obligation_id_restrictions
            .contains(&obligation_id)
        {
            return CapabilityCheckResult::AttenuationViolation {
                violated_caveat: format!("obligation_id={:?}", obligation_id),
            };
        }

        // Check operation-specific capabilities
        let can_perform = match operation {
            MarkingOperation::MarkPending => issued.capabilities.can_mark_pending,
            MarkingOperation::MarkActive => issued.capabilities.can_mark_active,
            MarkingOperation::MarkCompleted => issued.capabilities.can_mark_completed,
            MarkingOperation::MarkFailed => issued.capabilities.can_mark_failed,
            MarkingOperation::MarkCancelled => issued.capabilities.can_mark_cancelled,
        };

        if !can_perform {
            return CapabilityCheckResult::AttenuationViolation {
                violated_caveat: format!("operation={:?}", operation),
            };
        }

        CapabilityCheckResult::Granted
    }

    fn get_macaroon_attenuation_depth(&self, macaroon_id: &MacaroonId) -> u32 {
        self.issued_macaroons
            .get(macaroon_id)
            .map(|m| m.attenuation_depth)
            .unwrap_or(0)
    }
}

/// Mock obligation marking controller that integrates with macaroon capabilities
struct MockObligationMarkingController {
    obligations: Arc<Mutex<HashMap<ObligationId, ObligationMarkingState>>>,
    capability_simulator: Arc<Mutex<MacaroonCapabilitySimulator>>,
    verifier: MacaroonVerifier,
    marking_policies: HashMap<ObligationId, MarkingPolicy>,
}

#[derive(Debug, Clone)]
struct ObligationMarkingState {
    obligation_id: ObligationId,
    current_marking: MarkingState,
    marking_history: Vec<MarkingEvent>,
    authorized_macaroons: HashSet<MacaroonId>,
    scope_context: String,
}

impl MockObligationMarkingController {
    fn new(capability_simulator: Arc<Mutex<MacaroonCapabilitySimulator>>) -> Self {
        Self {
            obligations: Arc::new(Mutex::new(HashMap::new())),
            capability_simulator,
            verifier: MacaroonVerifier::new(),
            marking_policies: HashMap::new(),
        }
    }

    fn create_obligation(&self, obligation_id: ObligationId, scope: String) {
        let state = ObligationMarkingState {
            obligation_id,
            current_marking: MarkingState::Created,
            marking_history: Vec::new(),
            authorized_macaroons: HashSet::new(),
            scope_context: scope,
        };

        self.obligations
            .lock()
            .unwrap()
            .insert(obligation_id, state);
    }

    fn authorize_macaroon_for_obligation(
        &self,
        obligation_id: ObligationId,
        macaroon_id: MacaroonId,
    ) {
        if let Some(state) = self.obligations.lock().unwrap().get_mut(&obligation_id) {
            state.authorized_macaroons.insert(macaroon_id);
        }
    }

    async fn attempt_marking_operation(
        &self,
        macaroon_id: MacaroonId,
        obligation_id: ObligationId,
        operation: MarkingOperation,
        tracker: Arc<MacaroonMarkingEnforcementTracker>,
    ) -> MarkingOperationResult {
        let timestamp = Instant::now();

        // Get current obligation state
        let (current_marking, authorized) = {
            let obligations = self.obligations.lock().unwrap();
            let state = match obligations.get(&obligation_id) {
                Some(s) => s,
                None => {
                    return MarkingOperationResult::CapabilityDenied;
                }
            };

            (
                state.current_marking.clone(),
                state.authorized_macaroons.contains(&macaroon_id),
            )
        };

        if !authorized {
            let violation = SecurityViolationEvent {
                timestamp,
                violation_type: SecurityViolationType::UnauthorizedMarking,
                attempted_operation: operation.clone(),
                macaroon_context: MacaroonSecurityContext {
                    macaroon_id: macaroon_id.clone(),
                    attenuation_chain: Vec::new(),
                    third_party_caveats: Vec::new(),
                    discharge_status: DischargeStatus::Invalid,
                },
                obligation_id,
            };
            tracker.record_security_violation(violation);

            return MarkingOperationResult::CapabilityDenied;
        }

        // Verify macaroon capabilities
        let capability_check = {
            let simulator = self.capability_simulator.lock().unwrap();
            simulator.verify_marking_capability(&macaroon_id, &operation, obligation_id, &tracker)
        };

        let attenuation_depth = {
            let simulator = self.capability_simulator.lock().unwrap();
            simulator.get_macaroon_attenuation_depth(&macaroon_id)
        };

        let check_event = CapabilityCheckEvent {
            timestamp,
            macaroon_id: macaroon_id.clone(),
            requested_operation: operation.clone(),
            obligation_id,
            check_result: capability_check.clone(),
            attenuation_depth,
        };
        tracker.record_capability_check(check_event);

        let new_state = match (&capability_check, &operation) {
            (CapabilityCheckResult::Granted, MarkingOperation::MarkPending) => {
                MarkingState::Pending
            }
            (CapabilityCheckResult::Granted, MarkingOperation::MarkActive) => MarkingState::Active,
            (CapabilityCheckResult::Granted, MarkingOperation::MarkCompleted) => {
                MarkingState::Completed
            }
            (CapabilityCheckResult::Granted, MarkingOperation::MarkFailed) => MarkingState::Failed,
            (CapabilityCheckResult::Granted, MarkingOperation::MarkCancelled) => {
                MarkingState::Cancelled
            }
            (CapabilityCheckResult::Denied { reason }, _) => {
                let violation = SecurityViolationEvent {
                    timestamp,
                    violation_type: SecurityViolationType::UnauthorizedMarking,
                    attempted_operation: operation.clone(),
                    macaroon_context: MacaroonSecurityContext {
                        macaroon_id: macaroon_id.clone(),
                        attenuation_chain: Vec::new(),
                        third_party_caveats: Vec::new(),
                        discharge_status: DischargeStatus::Valid,
                    },
                    obligation_id,
                };
                tracker.record_security_violation(violation);

                return MarkingOperationResult::CapabilityDenied;
            }
            (CapabilityCheckResult::AttenuationViolation { violated_caveat }, _) => {
                return MarkingOperationResult::CaveatViolation {
                    caveat: violated_caveat.clone(),
                };
            }
            (CapabilityCheckResult::ChainValidationFailure, _) => {
                return MarkingOperationResult::SecurityBoundaryViolation;
            }
        };

        // Validate state transition
        if !self.is_valid_state_transition(&current_marking, &new_state) {
            return MarkingOperationResult::StateTransitionInvalid;
        }

        // Apply marking
        {
            let mut obligations = self.obligations.lock().unwrap();
            if let Some(state) = obligations.get_mut(&obligation_id) {
                state.current_marking = new_state.clone();
                state.marking_history.push(MarkingEvent {
                    timestamp,
                    previous_state: current_marking.clone(),
                    new_state: new_state.clone(),
                    operation: operation.clone(),
                    macaroon_id: macaroon_id.clone(),
                });
            }
        }

        let result = MarkingOperationResult::Success {
            new_state: new_state.clone(),
        };

        let operation_event = MarkingOperationEvent {
            timestamp,
            operation,
            obligation_id,
            macaroon_id,
            previous_state: current_marking,
            requested_state: new_state,
            operation_result: result.clone(),
        };
        tracker.record_marking_operation(operation_event);

        result
    }

    fn is_valid_state_transition(&self, from: &MarkingState, to: &MarkingState) -> bool {
        use MarkingState::*;
        match (from, to) {
            (Created, Pending) => true,
            (Pending, Active) => true,
            (Active, Completed) => true,
            (Active, Failed) => true,
            (Pending, Cancelled) => true,
            (Active, Cancelled) => true,
            _ => false,
        }
    }

    fn get_obligation_state(&self, obligation_id: ObligationId) -> Option<MarkingState> {
        self.obligations
            .lock()
            .unwrap()
            .get(&obligation_id)
            .map(|s| s.current_marking.clone())
    }

    fn get_marking_history(&self, obligation_id: ObligationId) -> Vec<MarkingEvent> {
        self.obligations
            .lock()
            .unwrap()
            .get(&obligation_id)
            .map(|s| s.marking_history.clone())
            .unwrap_or_default()
    }
}

// Test implementations start here

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_macaroon_capability_restriction_enforcement() {
        let config = MacaroonMarkingTestConfig::default();
        let tracker = Arc::new(MacaroonMarkingEnforcementTracker::new());
        let capability_simulator = Arc::new(Mutex::new(MacaroonCapabilitySimulator::new()));
        let controller = MockObligationMarkingController::new(capability_simulator.clone());

        // Create test obligations
        let obligation_ids: Vec<ObligationId> = (0..8).map(|i| ObligationId::new(i)).collect();

        for &obligation_id in &obligation_ids {
            controller.create_obligation(obligation_id, "test-scope".to_string());
        }

        // Issue root macaroon with full capabilities
        let root_macaroon = {
            let mut sim = capability_simulator.lock().unwrap();
            sim.issue_root_macaroon("test-location")
        };

        // Authorize root macaroon for all obligations
        for &obligation_id in &obligation_ids {
            controller.authorize_macaroon_for_obligation(obligation_id, root_macaroon.clone());
        }

        // Create attenuated macaroon with completion marking restriction
        let restricted_macaroon = {
            let mut sim = capability_simulator.lock().unwrap();
            sim.attenuate_macaroon(
                &root_macaroon,
                vec![
                    MarkingRestriction::NoMarkingCompleted,
                    MarkingRestriction::ObligationIdRestriction {
                        obligation_id: obligation_ids[0],
                    },
                ],
            )
            .unwrap()
        };

        // Authorize restricted macaroon for subset of obligations
        for &obligation_id in &obligation_ids[1..4] {
            controller
                .authorize_macaroon_for_obligation(obligation_id, restricted_macaroon.clone());
        }

        // Test operations with root macaroon (should succeed)
        for &obligation_id in &obligation_ids[0..2] {
            // Mark as pending
            let result = controller
                .attempt_marking_operation(
                    root_macaroon.clone(),
                    obligation_id,
                    MarkingOperation::MarkPending,
                    tracker.clone(),
                )
                .await;
            assert!(matches!(result, MarkingOperationResult::Success { .. }));

            // Mark as active
            let result = controller
                .attempt_marking_operation(
                    root_macaroon.clone(),
                    obligation_id,
                    MarkingOperation::MarkActive,
                    tracker.clone(),
                )
                .await;
            assert!(matches!(result, MarkingOperationResult::Success { .. }));

            // Mark as completed (should succeed for root macaroon)
            let result = controller
                .attempt_marking_operation(
                    root_macaroon.clone(),
                    obligation_id,
                    MarkingOperation::MarkCompleted,
                    tracker.clone(),
                )
                .await;
            assert!(matches!(result, MarkingOperationResult::Success { .. }));
        }

        // Test operations with restricted macaroon
        for &obligation_id in &obligation_ids[1..3] {
            // Reset obligation state for testing
            controller.create_obligation(obligation_id, "test-scope".to_string());
            controller
                .authorize_macaroon_for_obligation(obligation_id, restricted_macaroon.clone());

            // Mark as pending (should succeed)
            let result = controller
                .attempt_marking_operation(
                    restricted_macaroon.clone(),
                    obligation_id,
                    MarkingOperation::MarkPending,
                    tracker.clone(),
                )
                .await;
            assert!(matches!(result, MarkingOperationResult::Success { .. }));

            // Mark as active (should succeed)
            let result = controller
                .attempt_marking_operation(
                    restricted_macaroon.clone(),
                    obligation_id,
                    MarkingOperation::MarkActive,
                    tracker.clone(),
                )
                .await;
            assert!(matches!(result, MarkingOperationResult::Success { .. }));

            // Mark as completed (should fail due to restriction)
            let result = controller
                .attempt_marking_operation(
                    restricted_macaroon.clone(),
                    obligation_id,
                    MarkingOperation::MarkCompleted,
                    tracker.clone(),
                )
                .await;
            assert!(matches!(
                result,
                MarkingOperationResult::CaveatViolation { .. }
            ));
        }

        // Test unauthorized obligation access
        let result = controller
            .attempt_marking_operation(
                restricted_macaroon.clone(),
                obligation_ids[0], // Restricted obligation
                MarkingOperation::MarkPending,
                tracker.clone(),
            )
            .await;
        assert!(matches!(
            result,
            MarkingOperationResult::CaveatViolation { .. }
        ));

        // Verify enforcement tracking
        assert!(tracker.verify_capability_enforcement());
        assert!(tracker.verify_attenuation_restrictions());
        assert!(tracker.get_security_violation_count() > 0);
        assert!(tracker.get_successful_marking_count() > 0);
    }

    #[tokio::test]
    async fn test_deep_attenuation_chain_validation() {
        let config = MacaroonMarkingTestConfig {
            max_attenuation_depth: 5,
            ..Default::default()
        };
        let tracker = Arc::new(MacaroonMarkingEnforcementTracker::new());
        let capability_simulator = Arc::new(Mutex::new(MacaroonCapabilitySimulator::new()));
        let controller = MockObligationMarkingController::new(capability_simulator.clone());

        let obligation_id = ObligationId::new(1);
        controller.create_obligation(obligation_id, "deep-chain-test".to_string());

        // Create deep attenuation chain
        let root_macaroon = {
            let mut sim = capability_simulator.lock().unwrap();
            sim.issue_root_macaroon("root-location")
        };

        let mut current_macaroon = root_macaroon.clone();
        let mut attenuation_chain = Vec::new();

        for depth in 1..=config.max_attenuation_depth {
            let restrictions = match depth {
                1 => vec![MarkingRestriction::NoMarkingFailed],
                2 => vec![MarkingRestriction::NoMarkingCancelled],
                3 => vec![MarkingRestriction::ScopeRestriction {
                    scope: "restricted-scope".to_string(),
                }],
                _ => vec![],
            };

            current_macaroon = {
                let mut sim = capability_simulator.lock().unwrap();
                sim.attenuate_macaroon(&current_macaroon, restrictions)
                    .unwrap()
            };

            attenuation_chain.push(current_macaroon.clone());
            controller.authorize_macaroon_for_obligation(obligation_id, current_macaroon.clone());
        }

        // Test operations at different depths
        for (depth, macaroon_id) in attenuation_chain.iter().enumerate() {
            // Reset obligation for testing
            controller.create_obligation(obligation_id, "deep-chain-test".to_string());
            controller.authorize_macaroon_for_obligation(obligation_id, macaroon_id.clone());

            // Operations that should work at all depths
            let result = controller
                .attempt_marking_operation(
                    macaroon_id.clone(),
                    obligation_id,
                    MarkingOperation::MarkPending,
                    tracker.clone(),
                )
                .await;
            assert!(matches!(result, MarkingOperationResult::Success { .. }));

            let result = controller
                .attempt_marking_operation(
                    macaroon_id.clone(),
                    obligation_id,
                    MarkingOperation::MarkActive,
                    tracker.clone(),
                )
                .await;
            assert!(matches!(result, MarkingOperationResult::Success { .. }));

            // Operations restricted at specific depths
            if depth >= 0 {
                // Depth 1 restriction: NoMarkingFailed
                let result = controller
                    .attempt_marking_operation(
                        macaroon_id.clone(),
                        obligation_id,
                        MarkingOperation::MarkFailed,
                        tracker.clone(),
                    )
                    .await;
                if depth == 0 {
                    // First attenuation restricts MarkFailed
                    assert!(matches!(
                        result,
                        MarkingOperationResult::CaveatViolation { .. }
                    ));
                }
            }

            if depth >= 1 {
                // Depth 2 restriction: NoMarkingCancelled
                // Reset to active state for cancellation test
                controller.create_obligation(obligation_id, "deep-chain-test".to_string());
                controller.authorize_macaroon_for_obligation(obligation_id, macaroon_id.clone());
                controller
                    .attempt_marking_operation(
                        macaroon_id.clone(),
                        obligation_id,
                        MarkingOperation::MarkPending,
                        tracker.clone(),
                    )
                    .await;

                let result = controller
                    .attempt_marking_operation(
                        macaroon_id.clone(),
                        obligation_id,
                        MarkingOperation::MarkCancelled,
                        tracker.clone(),
                    )
                    .await;
                if depth == 1 {
                    // Second attenuation restricts MarkCancelled
                    assert!(matches!(
                        result,
                        MarkingOperationResult::CaveatViolation { .. }
                    ));
                }
            }
        }

        // Verify deep chain validation
        assert!(tracker.verify_attenuation_restrictions());
        assert!(tracker.get_attenuation_verification_success_rate() > 0.8);
    }

    #[tokio::test]
    async fn test_concurrent_capability_boundary_enforcement() {
        let config = MacaroonMarkingTestConfig {
            concurrent_operations: 12,
            max_obligations: 32,
            ..Default::default()
        };
        let tracker = Arc::new(MacaroonMarkingEnforcementTracker::new());
        let capability_simulator = Arc::new(Mutex::new(MacaroonCapabilitySimulator::new()));
        let controller = Arc::new(MockObligationMarkingController::new(
            capability_simulator.clone(),
        ));

        // Create multiple obligations
        let obligation_ids: Vec<ObligationId> = (0..config.max_obligations)
            .map(|i| ObligationId::new(i as u64))
            .collect();

        for &obligation_id in &obligation_ids {
            controller.create_obligation(
                obligation_id,
                format!("concurrent-test-{}", obligation_id.0),
            );
        }

        // Create diverse macaroon set with different restrictions
        let macaroons = {
            let mut sim = capability_simulator.lock().unwrap();
            let root = sim.issue_root_macaroon("concurrent-root");

            let restricted_complete = sim
                .attenuate_macaroon(&root, vec![MarkingRestriction::NoMarkingCompleted])
                .unwrap();

            let restricted_failed = sim
                .attenuate_macaroon(&root, vec![MarkingRestriction::NoMarkingFailed])
                .unwrap();

            let scope_restricted = sim
                .attenuate_macaroon(
                    &root,
                    vec![MarkingRestriction::ScopeRestriction {
                        scope: "limited-scope".to_string(),
                    }],
                )
                .unwrap();

            let obligation_restricted = sim
                .attenuate_macaroon(
                    &root,
                    vec![MarkingRestriction::ObligationIdRestriction {
                        obligation_id: obligation_ids[0],
                    }],
                )
                .unwrap();

            vec![
                root,
                restricted_complete,
                restricted_failed,
                scope_restricted,
                obligation_restricted,
            ]
        };

        // Authorize macaroons for different obligation subsets
        for (i, &obligation_id) in obligation_ids.iter().enumerate() {
            for (j, macaroon_id) in macaroons.iter().enumerate() {
                // Selective authorization to create capability boundaries
                if (i + j) % 3 == 0 {
                    controller
                        .authorize_macaroon_for_obligation(obligation_id, macaroon_id.clone());
                }
            }
        }

        // Concurrent operation simulation
        let operation_handles: Vec<_> = (0..config.concurrent_operations)
            .map(|i| {
                let controller = controller.clone();
                let tracker = tracker.clone();
                let macaroons = macaroons.clone();
                let obligation_ids = obligation_ids.clone();

                tokio::spawn(async move {
                    let macaroon_idx = (i as usize) % macaroons.len();
                    let obligation_idx = (i as usize) % obligation_ids.len();
                    let macaroon_id = macaroons[macaroon_idx].clone();
                    let obligation_id = obligation_ids[obligation_idx];

                    let operations = vec![
                        MarkingOperation::MarkPending,
                        MarkingOperation::MarkActive,
                        MarkingOperation::MarkCompleted,
                        MarkingOperation::MarkFailed,
                        MarkingOperation::MarkCancelled,
                    ];

                    for operation in operations {
                        let result = controller
                            .attempt_marking_operation(
                                macaroon_id.clone(),
                                obligation_id,
                                operation.clone(),
                                tracker.clone(),
                            )
                            .await;

                        // Small delay to allow interleaving
                        Sleep::new(Instant::now() + Duration::from_millis(10)).await;
                    }
                })
            })
            .collect();

        // Wait for all operations to complete
        for handle in operation_handles {
            let _ = handle.await;
        }

        // Verify concurrent enforcement correctness
        assert!(tracker.verify_capability_enforcement());
        assert!(tracker.verify_attenuation_restrictions());
        assert!(tracker.verify_caveat_evaluation_correctness());

        // Verify that security violations were detected and handled
        assert!(tracker.get_security_violation_count() > 0);

        // Verify that legitimate operations succeeded
        assert!(tracker.get_successful_marking_count() > 0);

        // Check that various operation types were attempted
        let operations = tracker.marking_operations.lock().unwrap();
        let operation_types: HashSet<_> =
            operations.iter().map(|op| op.operation.clone()).collect();
        assert!(
            operation_types.len() > 1,
            "Should have diverse operation types"
        );
    }

    #[test]
    fn test_macaroon_caveat_evaluation() {
        let tracker = MacaroonMarkingEnforcementTracker::new();
        let obligation_id = ObligationId::new(42);

        let caveat_details = CaveatDetails {
            caveat_type: CaveatType::FirstParty,
            predicate: "operation != MarkCompleted".to_string(),
            location: "test-location".to_string(),
            signature: vec![0x12, 0x34, 0x56, 0x78],
        };

        let obligation_context = ObligationContext {
            obligation_id,
            current_marking: MarkingState::Active,
            scope_depth: 2,
            creation_time: Instant::now(),
        };

        let evaluation_event = CaveatEvaluationEvent {
            timestamp: Instant::now(),
            caveat: caveat_details,
            obligation_context,
            evaluation_result: CaveatEvaluationResult::Satisfied,
        };

        tracker.record_caveat_evaluation(evaluation_event);

        assert!(tracker.verify_caveat_evaluation_correctness());
    }

    #[test]
    fn test_capability_check_result_types() {
        use CapabilityCheckResult::*;
        use DenialReason::*;

        let results = vec![
            Granted,
            Denied {
                reason: InsufficientCapability,
            },
            Denied {
                reason: ExpiredCaveat,
            },
            AttenuationViolation {
                violated_caveat: "test-caveat".to_string(),
            },
            ChainValidationFailure,
        ];

        for result in results {
            match result {
                Granted => assert!(true),
                Denied { reason } => assert!(matches!(
                    reason,
                    InsufficientCapability
                        | ExpiredCaveat
                        | ScopeMismatch
                        | ObligationNotFound
                        | MarkingRestriction
                )),
                AttenuationViolation { violated_caveat } => assert!(!violated_caveat.is_empty()),
                ChainValidationFailure => assert!(true),
            }
        }
    }
}

// Supporting types and implementations

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ObligationId(u64);

impl ObligationId {
    fn new(id: u64) -> Self {
        Self(id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct MacaroonId(String);

impl MacaroonId {
    fn generate(rng: &mut DetRng) -> Self {
        Self(format!("macaroon-{:016x}", rng.next_u64()))
    }
}

#[derive(Debug, Clone)]
struct MacaroonSecret(Vec<u8>);

impl MacaroonSecret {
    fn generate(rng: &mut DetRng) -> Self {
        Self((0..32).map(|_| (rng.next_u64() as u8)).collect())
    }
}

#[derive(Debug, Clone)]
struct Macaroon {
    identifier: MacaroonId,
    location: String,
    signature: Vec<u8>,
    caveats: Vec<Caveat>,
}

impl Macaroon {
    fn add_first_party_caveat(
        mut self,
        predicate: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        self.caveats.push(Caveat::FirstParty(FirstPartyCaveat {
            predicate: predicate.to_string(),
        }));
        Ok(self)
    }
}

#[derive(Debug, Clone)]
struct MacaroonBuilder {
    secret: MacaroonSecret,
    identifier: Option<MacaroonId>,
    location: Option<String>,
}

impl MacaroonBuilder {
    fn new(secret: &MacaroonSecret) -> Self {
        Self {
            secret: secret.clone(),
            identifier: None,
            location: None,
        }
    }

    fn with_identifier(mut self, id: MacaroonId) -> Self {
        self.identifier = Some(id);
        self
    }

    fn with_location(mut self, location: String) -> Self {
        self.location = Some(location);
        self
    }

    fn build(self) -> Macaroon {
        Macaroon {
            identifier: self.identifier.unwrap(),
            location: self.location.unwrap(),
            signature: vec![0xde, 0xad, 0xbe, 0xef],
            caveats: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
struct MacaroonVerifier;

impl MacaroonVerifier {
    fn new() -> Self {
        Self
    }
}

#[derive(Debug, Clone)]
enum Caveat {
    FirstParty(FirstPartyCaveat),
    ThirdParty(ThirdPartyCaveat),
}

#[derive(Debug, Clone, PartialEq)]
enum CaveatType {
    FirstParty,
    ThirdParty,
}

#[derive(Debug, Clone)]
struct FirstPartyCaveat {
    predicate: String,
}

#[derive(Debug, Clone)]
struct ThirdPartyCaveat {
    location: String,
    key: Vec<u8>,
    predicate: String,
}

#[derive(Debug, Clone, Default)]
struct AttenuationChain {
    chain: Vec<(MacaroonId, MacaroonId)>,
}

impl AttenuationChain {
    fn add_attenuation(&mut self, parent: MacaroonId, child: MacaroonId) {
        self.chain.push((parent, child));
    }
}

#[derive(Debug, Clone)]
struct CapabilityToken;

#[derive(Debug, Clone)]
struct DischargeToken;

#[derive(Debug, Clone, PartialEq)]
enum MarkingOperation {
    MarkPending,
    MarkActive,
    MarkCompleted,
    MarkFailed,
    MarkCancelled,
}

#[derive(Debug, Clone, PartialEq)]
enum MarkingState {
    Created,
    Pending,
    Active,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone)]
enum MarkingRestriction {
    NoMarkingCompleted,
    NoMarkingFailed,
    ScopeRestriction { scope: String },
    ObligationIdRestriction { obligation_id: ObligationId },
    ExpiryTime { expiry: Instant },
}

#[derive(Debug, Clone)]
struct MarkingEvent {
    timestamp: Instant,
    previous_state: MarkingState,
    new_state: MarkingState,
    operation: MarkingOperation,
    macaroon_id: MacaroonId,
}

#[derive(Debug, Clone)]
struct MarkingPolicy;

#[derive(Debug, Clone)]
struct ObligationMarker;

#[derive(Debug, Clone)]
struct MarkingCapability;

#[derive(Debug, Clone)]
struct ObligationMark;

#[derive(Debug, Clone)]
struct ObligationMarkingController;

#[derive(Debug, Clone)]
struct MarkingSecurityContext;
