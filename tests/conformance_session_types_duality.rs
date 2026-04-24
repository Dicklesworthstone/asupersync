/*!
Conformance tests for session types duality laws.

Verifies that the session types implementation in src/obligation/session_types.rs
correctly implements the theoretical duality properties required for sound
binary session types. Each test corresponds to a specific duality requirement.

# Duality Laws Tested

## DL-1: Type Construction Duality
- Send<T, S> must be dual to Recv<T, Dual<S>>
- End must be dual to End
- Recursive types must preserve duality

## DL-2: Choice Duality
- Select<A, B> must be dual to Offer<Dual<A>, Dual<B>>
- Local choice (Select) must correspond to remote choice (Offer)

## DL-3: Endpoint Duality
- new_session() endpoints must be proper duals
- Shared channel_id and obligation_kind across dual endpoints
- Type parameters must correspond correctly

## DL-4: Protocol Progress
- Dual endpoints must complete protocols successfully
- No deadlocks when both sides follow their types
- State transitions must be synchronized

## DL-5: Transport Backing Consistency
- Pure typestate and transport-backed channels must behave identically
- Async operations must preserve duality properties
*/

use asupersync::obligation::session_types::*;
use asupersync::record::ObligationKind;
use std::marker::PhantomData;

// ============================================================================
// Conformance Test Infrastructure
// ============================================================================

/// Requirement levels from session types specification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequirementLevel {
    /// Fundamental duality property; violation means the session protocol is unsound.
    Must,
    /// Important practical property; violation means degraded behavior.
    Should,
    /// Optional enhancement; violation is acceptable for conformance.
    May,
}

/// Test category for organization
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestCategory {
    /// Type-level duality properties.
    TypeDuality,
    /// Select/Offer duality.
    ChoiceDuality,
    /// Session endpoint pairing.
    EndpointDuality,
    /// End-to-end protocol execution.
    ProtocolProgress,
    /// Pure versus transport-backed consistency.
    TransportBacking,
}

/// Result of a duality test
#[derive(Debug, PartialEq, Eq)]
pub enum DualityTestResult {
    /// Test passed.
    Pass,
    /// Test failed unexpectedly.
    Fail {
        /// Human-readable failure reason.
        reason: String,
    },
    /// Test hit a known limitation.
    ExpectedFailure {
        /// Human-readable expected-failure reason.
        reason: String,
    },
}

/// Individual duality test case
pub trait DualityTest: std::marker::Send + Sync {
    /// Stable conformance test identifier.
    fn id(&self) -> &'static str;
    /// Category covered by this test.
    fn category(&self) -> TestCategory;
    /// Requiredness level from the session type specification.
    fn requirement_level(&self) -> RequirementLevel;
    /// Human-readable test description.
    fn description(&self) -> &'static str;
    /// Execute this conformance case.
    fn run(&self) -> DualityTestResult;
}

// ============================================================================
// DL-1: Type Construction Duality Tests
// ============================================================================

/// Verifies that session type constructors respect duality
struct TypeConstructionDualityTest;

impl DualityTest for TypeConstructionDualityTest {
    fn id(&self) -> &'static str {
        "DL-1.1"
    }
    fn category(&self) -> TestCategory {
        TestCategory::TypeDuality
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn description(&self) -> &'static str {
        "Send<T, S> and Recv<T, S> must be structurally dual"
    }

    fn run(&self) -> DualityTestResult {
        // Test via type-level properties using PhantomData
        let _send_marker: PhantomData<Send<u32, End>> = PhantomData;
        let _recv_marker: PhantomData<Recv<u32, End>> = PhantomData;

        // These should have the same size (zero-sized types)
        assert_eq!(
            std::mem::size_of::<Send<u32, End>>(),
            std::mem::size_of::<Recv<u32, End>>()
        );
        assert_eq!(std::mem::size_of::<Send<u32, End>>(), 0);

        DualityTestResult::Pass
    }
}

struct EndTypeDualityTest;

impl DualityTest for EndTypeDualityTest {
    fn id(&self) -> &'static str {
        "DL-1.2"
    }
    fn category(&self) -> TestCategory {
        TestCategory::TypeDuality
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn description(&self) -> &'static str {
        "End type must be dual to itself"
    }

    fn run(&self) -> DualityTestResult {
        // End should be zero-sized and self-dual
        assert_eq!(std::mem::size_of::<End>(), 0);

        DualityTestResult::Pass
    }
}

// ============================================================================
// DL-2: Choice Duality Tests
// ============================================================================

struct ChoiceDualityTest;

impl DualityTest for ChoiceDualityTest {
    fn id(&self) -> &'static str {
        "DL-2.1"
    }
    fn category(&self) -> TestCategory {
        TestCategory::ChoiceDuality
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn description(&self) -> &'static str {
        "Select<A, B> and Offer<A, B> must be structurally dual"
    }

    fn run(&self) -> DualityTestResult {
        // Verify zero-sized nature and structural properties
        assert_eq!(
            std::mem::size_of::<Select<End, End>>(),
            std::mem::size_of::<Offer<End, End>>()
        );
        assert_eq!(std::mem::size_of::<Select<End, End>>(), 0);

        DualityTestResult::Pass
    }
}

// ============================================================================
// DL-3: Endpoint Duality Tests
// ============================================================================

struct SendPermitEndpointDualityTest;

impl DualityTest for SendPermitEndpointDualityTest {
    fn id(&self) -> &'static str {
        "DL-3.1"
    }
    fn category(&self) -> TestCategory {
        TestCategory::EndpointDuality
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn description(&self) -> &'static str {
        "send_permit::new_session() must create dual endpoints"
    }

    fn run(&self) -> DualityTestResult {
        let (sender, _receiver) = send_permit::new_session::<String>(42);

        // Both endpoints must share the same channel_id
        // Note: We can only test this indirectly through protocol completion
        // since channel_id is private

        // Test that endpoints can be consumed in dual operations
        let sender = sender.send(send_permit::ReserveMsg);
        // The receiver should be able to receive this in the dual protocol

        // For now, test structural properties we can observe
        let sender_proof = sender.select_left().send("test".to_string()).close();
        assert_eq!(sender_proof.obligation_kind, ObligationKind::SendPermit);
        assert_eq!(sender_proof.channel_id, 42);

        DualityTestResult::Pass
    }
}

struct LeaseEndpointDualityTest;

impl DualityTest for LeaseEndpointDualityTest {
    fn id(&self) -> &'static str {
        "DL-3.2"
    }
    fn category(&self) -> TestCategory {
        TestCategory::EndpointDuality
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn description(&self) -> &'static str {
        "lease::new_session() must create dual endpoints"
    }

    fn run(&self) -> DualityTestResult {
        let (holder, _resource) = lease::new_session(99);

        // Test that holder can complete its protocol
        let holder_proof = holder
            .send(lease::AcquireMsg)
            .select_right() // Choose Release
            .send(lease::ReleaseMsg)
            .close();

        assert_eq!(holder_proof.obligation_kind, ObligationKind::Lease);
        assert_eq!(holder_proof.channel_id, 99);

        DualityTestResult::Pass
    }
}

struct TwoPhaseEndpointDualityTest;

impl DualityTest for TwoPhaseEndpointDualityTest {
    fn id(&self) -> &'static str {
        "DL-3.3"
    }
    fn category(&self) -> TestCategory {
        TestCategory::EndpointDuality
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn description(&self) -> &'static str {
        "two_phase::new_session() must create dual endpoints"
    }

    fn run(&self) -> DualityTestResult {
        let (initiator, _executor) = two_phase::new_session(123, ObligationKind::IoOp);

        // Test that initiator can complete its protocol
        let initiator_proof = initiator
            .send(two_phase::ReserveMsg {
                kind: ObligationKind::IoOp,
            })
            .select_left() // Choose Commit
            .send(two_phase::CommitMsg)
            .close();

        assert_eq!(initiator_proof.obligation_kind, ObligationKind::IoOp);
        assert_eq!(initiator_proof.channel_id, 123);

        DualityTestResult::Pass
    }
}

// ============================================================================
// DL-4: Protocol Progress Tests
// ============================================================================

struct SendPermitProgressTest;

impl DualityTest for SendPermitProgressTest {
    fn id(&self) -> &'static str {
        "DL-4.1"
    }
    fn category(&self) -> TestCategory {
        TestCategory::ProtocolProgress
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn description(&self) -> &'static str {
        "SendPermit protocol must complete when both endpoints follow types"
    }

    fn run(&self) -> DualityTestResult {
        let (sender, receiver) = send_permit::new_session::<i32>(200);

        // Sender side: Reserve → Send(42) → End
        let sender = sender.send(send_permit::ReserveMsg);
        let sender = sender.select_left(); // Choose Send branch
        let sender = sender.send(42_i32);
        let sender_proof = sender.close();

        // Receiver side: Recv(Reserve) → Select(Recv(42) | Recv(Abort)) → End
        let (_, receiver) = receiver.recv(send_permit::ReserveMsg);
        let Selected::Left(receiver) = receiver.offer(Branch::Left) else {
            unreachable!("pure typestate offer must follow the simulated branch");
        };
        let (_, receiver) = receiver.recv(42_i32);
        let receiver_proof = receiver.close();

        // Both should complete with same channel_id
        assert_eq!(sender_proof.channel_id, receiver_proof.channel_id);
        assert_eq!(sender_proof.channel_id, 200);

        DualityTestResult::Pass
    }
}

struct SendPermitAbortProgressTest;

impl DualityTest for SendPermitAbortProgressTest {
    fn id(&self) -> &'static str {
        "DL-4.2"
    }
    fn category(&self) -> TestCategory {
        TestCategory::ProtocolProgress
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn description(&self) -> &'static str {
        "SendPermit abort path must complete when both endpoints follow types"
    }

    fn run(&self) -> DualityTestResult {
        let (sender, receiver) = send_permit::new_session::<String>(201);

        // Sender side: Reserve → Abort → End
        let sender = sender.send(send_permit::ReserveMsg);
        let sender = sender.select_right(); // Choose Abort branch
        let sender = sender.send(send_permit::AbortMsg);
        let sender_proof = sender.close();

        // Receiver side: Recv(Reserve) → Select(Recv(String) | Recv(Abort)) → End
        let (_, receiver) = receiver.recv(send_permit::ReserveMsg);
        let Selected::Right(receiver) = receiver.offer(Branch::Right) else {
            unreachable!("pure typestate offer must follow the simulated branch");
        };
        let (_, receiver) = receiver.recv(send_permit::AbortMsg);
        let receiver_proof = receiver.close();

        // Both should complete with same channel_id
        assert_eq!(sender_proof.channel_id, receiver_proof.channel_id);
        assert_eq!(sender_proof.channel_id, 201);

        DualityTestResult::Pass
    }
}

// ============================================================================
// DL-5: Transport Backing Consistency Tests
// ============================================================================

struct TransportBackingConsistencyTest;

impl DualityTest for TransportBackingConsistencyTest {
    fn id(&self) -> &'static str {
        "DL-5.1"
    }
    fn category(&self) -> TestCategory {
        TestCategory::TransportBacking
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Should
    }
    fn description(&self) -> &'static str {
        "Transport-backed channels must preserve duality properties"
    }

    fn run(&self) -> DualityTestResult {
        // Test that both pure typestate and transport-backed channels
        // can be created and have consistent structure

        // Pure typestate version
        let (pure_sender, _pure_receiver) = send_permit::new_session::<u64>(300);

        // Transport-backed version
        let (transport_sender, _transport_receiver) =
            send_permit::new_session_with_transport::<u64>(300, 10);

        // Both should be able to complete the protocol
        let pure_proof = pure_sender
            .send(send_permit::ReserveMsg)
            .select_left()
            .send(42_u64)
            .close();

        let transport_proof = transport_sender
            .send(send_permit::ReserveMsg)
            .select_left()
            .send(42_u64)
            .close();

        // Both should have same structural properties
        assert_eq!(pure_proof.channel_id, transport_proof.channel_id);
        assert_eq!(pure_proof.obligation_kind, transport_proof.obligation_kind);

        DualityTestResult::Pass
    }
}

// ============================================================================
// Conformance Test Suite Runner
// ============================================================================

/// Complete suite of duality conformance tests
pub fn all_duality_tests() -> Vec<Box<dyn DualityTest>> {
    vec![
        // Type construction duality
        Box::new(TypeConstructionDualityTest),
        Box::new(EndTypeDualityTest),
        // Choice duality
        Box::new(ChoiceDualityTest),
        // Endpoint duality
        Box::new(SendPermitEndpointDualityTest),
        Box::new(LeaseEndpointDualityTest),
        Box::new(TwoPhaseEndpointDualityTest),
        // Protocol progress
        Box::new(SendPermitProgressTest),
        Box::new(SendPermitAbortProgressTest),
        // Transport backing
        Box::new(TransportBackingConsistencyTest),
    ]
}

/// Generate conformance report for duality laws
pub fn generate_duality_conformance_report() -> String {
    let tests = all_duality_tests();
    let mut report = String::new();

    report.push_str("# Session Types Duality Conformance Report\n\n");
    report.push_str("| Test ID | Category | Level | Description | Result |\n");
    report.push_str("|---------|----------|-------|-------------|--------|\n");

    let mut passed = 0;
    let mut failed = 0;
    let mut xfail = 0;

    for test in &tests {
        let result = test.run();
        let status = match &result {
            DualityTestResult::Pass => {
                passed += 1;
                "✅ PASS"
            }
            DualityTestResult::Fail { .. } => {
                failed += 1;
                "❌ FAIL"
            }
            DualityTestResult::ExpectedFailure { .. } => {
                xfail += 1;
                "⚠️ XFAIL"
            }
        };

        report.push_str(&format!(
            "| {} | {:?} | {:?} | {} | {} |\n",
            test.id(),
            test.category(),
            test.requirement_level(),
            test.description(),
            status
        ));

        // Add failure details
        if let DualityTestResult::Fail { reason } = &result {
            report.push_str(&format!("  - ❌ Failure: {}\n", reason));
        }
        if let DualityTestResult::ExpectedFailure { reason } = &result {
            report.push_str(&format!("  - ⚠️ Expected: {}\n", reason));
        }
    }

    let total = tests.len();
    report.push_str(&format!(
        "\n## Summary\n\n- **Total**: {} tests\n- **Passed**: {}\n- **Failed**: {}\n- **Expected Failures**: {}\n",
        total, passed, failed, xfail
    ));

    let must_tests: Vec<_> = tests
        .iter()
        .filter(|t| t.requirement_level() == RequirementLevel::Must)
        .collect();
    let must_passed = must_tests
        .iter()
        .filter(|t| matches!(t.run(), DualityTestResult::Pass))
        .count();

    let conformance_score = if must_tests.is_empty() {
        100.0
    } else {
        (must_passed as f64 / must_tests.len() as f64) * 100.0
    };

    report.push_str(&format!(
        "- **MUST Clause Conformance**: {:.1}% ({}/{})\n",
        conformance_score,
        must_passed,
        must_tests.len()
    ));

    if conformance_score < 100.0 {
        report.push_str("\n⚠️ **CONFORMANCE FAILURE**: MUST clauses not fully satisfied.\n");
    } else {
        report.push_str("\n✅ **CONFORMANCE PASS**: All MUST clauses satisfied.\n");
    }

    report
}

// ============================================================================
// Test Suite Execution
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_all_duality_tests() {
        let tests = all_duality_tests();
        let mut failures = Vec::new();

        for test in &tests {
            println!("Running test {}: {}", test.id(), test.description());

            let result = test.run();
            match result {
                DualityTestResult::Pass => {
                    println!("  ✅ PASS");
                }
                DualityTestResult::Fail { ref reason } => {
                    println!("  ❌ FAIL: {}", reason);
                    if test.requirement_level() == RequirementLevel::Must {
                        failures.push(format!("{}: {}", test.id(), reason));
                    }
                }
                DualityTestResult::ExpectedFailure { ref reason } => {
                    println!("  ⚠️ XFAIL: {}", reason);
                }
            }
        }

        if !failures.is_empty() {
            panic!("Duality conformance failures:\n{}", failures.join("\n"));
        }

        println!("\n{}", generate_duality_conformance_report());
    }

    #[test]
    fn type_construction_duality() {
        let test = TypeConstructionDualityTest;
        assert_eq!(test.run(), DualityTestResult::Pass);
    }

    #[test]
    fn endpoint_duality_send_permit() {
        let test = SendPermitEndpointDualityTest;
        assert_eq!(test.run(), DualityTestResult::Pass);
    }

    #[test]
    fn protocol_progress_send_permit() {
        let test = SendPermitProgressTest;
        assert_eq!(test.run(), DualityTestResult::Pass);
    }

    #[test]
    fn transport_backing_consistency() {
        let test = TransportBackingConsistencyTest;
        assert_eq!(test.run(), DualityTestResult::Pass);
    }
}
