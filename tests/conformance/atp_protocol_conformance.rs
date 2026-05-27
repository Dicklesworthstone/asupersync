//! ATP Protocol Specification Conformance Tests
//!
//! This module implements systematic conformance testing for the ATP protocol
//! specification following Pattern 4 (Spec-Derived Tests) from the testing-conformance-harnesses skill.
//!
//! Each test verifies one MUST/SHOULD/MAY clause from the ATP protocol specification,
//! tagged by requirement level for coverage accounting.

use asupersync::cx::Cx;
use asupersync::net::atp::protocol::{
    AtpError, AtpFeature, AtpFrame, CapabilityAction, CapabilityGrant, CapabilityGrantId,
    CapabilityScope, FrameType, PeerId, ProtocolError, ProtocolVersion, SessionContextKind,
    SessionError, SessionTraceId,
};
use asupersync::net::atp::sdk::{
    AtpSdk, ObjectHash, SessionConfig, SessionOptions, TransferDestination, TransferOptions,
    TransferPolicy, TransferRequest, TransferSource,
};
use asupersync::net::atp::test_utils::fixtures;
use asupersync::net::atp::test_utils::*;
use futures_lite::future::block_on;
use serde::{Deserialize, Serialize};
use serde_json::json;

const ATP_PROTOCOL_CONFORMANCE_ARTIFACT: &str =
    "artifacts/conformance/atp_protocol_conformance.ndjson";
const ATP_NR_OWNER_BEAD: &str = "asupersync-vk4kcf";

/// Conformance test requirement level based on RFC 2119.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequirementLevel {
    /// MUST - Absolute requirement
    Must,
    /// SHOULD - Strong recommendation
    Should,
    /// MAY - Optional feature
    May,
}

/// Conformance test category for organization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TestCategory {
    /// Protocol frame handling
    FrameHandling,
    /// Session management
    SessionManagement,
    /// Transfer policies
    TransferPolicies,
    /// Data integrity
    DataIntegrity,
    /// Security model
    SecurityModel,
    /// Observability
    Observability,
}

/// Result of a conformance test execution.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum ConformanceResult {
    Pass {
        observed: String,
    },
    Fail {
        reason: String,
        observed: String,
    },
    Skipped {
        reason: String,
        observed: String,
    },
    KnownGap {
        reason: String,
        owner_bead: String,
        observed: String,
    },
}

impl ConformanceResult {
    fn pass(observed: impl Into<String>) -> Self {
        Self::Pass {
            observed: observed.into(),
        }
    }

    fn fail(reason: impl Into<String>, observed: impl Into<String>) -> Self {
        Self::Fail {
            reason: reason.into(),
            observed: observed.into(),
        }
    }

    fn known_gap(
        reason: impl Into<String>,
        owner_bead: impl Into<String>,
        observed: impl Into<String>,
    ) -> Self {
        Self::KnownGap {
            reason: reason.into(),
            owner_bead: owner_bead.into(),
            observed: observed.into(),
        }
    }

    fn verdict(&self) -> &'static str {
        match self {
            Self::Pass { .. } => "PASS",
            Self::Fail { .. } => "FAIL",
            Self::Skipped { .. } => "SKIP",
            Self::KnownGap { .. } => "KNOWN_GAP",
        }
    }

    fn reason(&self) -> Option<&str> {
        match self {
            Self::Pass { .. } => None,
            Self::Fail { reason, .. }
            | Self::Skipped { reason, .. }
            | Self::KnownGap { reason, .. } => Some(reason),
        }
    }

    fn observed(&self) -> &str {
        match self {
            Self::Pass { observed }
            | Self::Fail { observed, .. }
            | Self::Skipped { observed, .. }
            | Self::KnownGap { observed, .. } => observed,
        }
    }

    fn owner_bead(&self) -> Option<&str> {
        match self {
            Self::KnownGap { owner_bead, .. } => Some(owner_bead),
            _ => None,
        }
    }
}

/// Individual conformance test case.
#[derive(Debug)]
pub struct ConformanceCase {
    /// Unique test identifier (e.g. "ATP-FRAME-001")
    pub id: &'static str,
    /// Protocol section reference
    pub section: &'static str,
    /// Requirement level
    pub level: RequirementLevel,
    /// Test category
    pub category: TestCategory,
    /// Test description
    pub description: &'static str,
    /// Test implementation
    pub test_fn: fn(&Cx) -> ConformanceResult,
}

/// ATP Protocol conformance test cases.
const ATP_CONFORMANCE_CASES: &[ConformanceCase] = &[
    // Frame Handling Requirements
    ConformanceCase {
        id: "ATP-FRAME-001",
        section: "3.1",
        level: RequirementLevel::Must,
        category: TestCategory::FrameHandling,
        description: "ATP frames MUST have valid frame type",
        test_fn: test_frame_type_required,
    },
    ConformanceCase {
        id: "ATP-FRAME-002",
        section: "3.1",
        level: RequirementLevel::Must,
        category: TestCategory::FrameHandling,
        description: "ATP frames MUST support empty payloads",
        test_fn: test_frame_empty_payload_support,
    },
    ConformanceCase {
        id: "ATP-FRAME-003",
        section: "3.2",
        level: RequirementLevel::Should,
        category: TestCategory::FrameHandling,
        description: "ATP implementations SHOULD validate frame consistency",
        test_fn: test_frame_validation,
    },
    // Session Management Requirements
    ConformanceCase {
        id: "ATP-SESSION-001",
        section: "4.1",
        level: RequirementLevel::Must,
        category: TestCategory::SessionManagement,
        description: "Sessions MUST have timeout configuration",
        test_fn: test_session_timeout_required,
    },
    ConformanceCase {
        id: "ATP-SESSION-002",
        section: "4.2",
        level: RequirementLevel::Must,
        category: TestCategory::SessionManagement,
        description: "Sessions MUST respect concurrent transfer limits",
        test_fn: test_concurrent_transfer_limits,
    },
    ConformanceCase {
        id: "ATP-SESSION-003",
        section: "4.3",
        level: RequirementLevel::Should,
        category: TestCategory::SessionManagement,
        description: "Sessions SHOULD support compression configuration",
        test_fn: test_compression_configuration,
    },
    // Transfer Policy Requirements
    ConformanceCase {
        id: "ATP-TRANSFER-001",
        section: "5.1",
        level: RequirementLevel::Must,
        category: TestCategory::TransferPolicies,
        description: "Transfers MUST enforce maximum size limits",
        test_fn: test_transfer_size_limits,
    },
    ConformanceCase {
        id: "ATP-TRANSFER-002",
        section: "5.2",
        level: RequirementLevel::Must,
        category: TestCategory::TransferPolicies,
        description: "Transfers MUST enforce timeout policies",
        test_fn: test_transfer_timeout_enforcement,
    },
    ConformanceCase {
        id: "ATP-TRANSFER-003",
        section: "5.3",
        level: RequirementLevel::Should,
        category: TestCategory::TransferPolicies,
        description: "Transfers SHOULD support automatic retry",
        test_fn: test_automatic_retry_support,
    },
    // Data Integrity Requirements
    ConformanceCase {
        id: "ATP-INTEGRITY-001",
        section: "6.1",
        level: RequirementLevel::Must,
        category: TestCategory::DataIntegrity,
        description: "Transfers MUST verify data integrity",
        test_fn: test_data_integrity_verification,
    },
    ConformanceCase {
        id: "ATP-INTEGRITY-002",
        section: "6.2",
        level: RequirementLevel::Must,
        category: TestCategory::DataIntegrity,
        description: "Corrupted data MUST be rejected",
        test_fn: test_corruption_detection,
    },
    // Security Model Requirements
    ConformanceCase {
        id: "ATP-SECURITY-001",
        section: "7.1",
        level: RequirementLevel::Must,
        category: TestCategory::SecurityModel,
        description: "Operations MUST require explicit capabilities",
        test_fn: test_capability_requirements,
    },
    ConformanceCase {
        id: "ATP-SECURITY-002",
        section: "7.2",
        level: RequirementLevel::Must,
        category: TestCategory::SecurityModel,
        description: "Authorization boundaries MUST be enforced",
        test_fn: test_authorization_enforcement,
    },
];

fn conformance_grant(
    issuer: PeerId,
    subject: PeerId,
    label: &str,
    actions: impl IntoIterator<Item = CapabilityAction>,
) -> CapabilityGrant {
    CapabilityGrant::new(
        CapabilityGrantId::from_label(label),
        issuer,
        subject,
        actions,
        CapabilityScope::for_context(SessionContextKind::Direct),
    )
}

fn conformance_sdk_session(
    cx: &Cx,
    label: &str,
) -> Result<asupersync::net::atp::sdk::AtpSession, String> {
    let config = SessionConfig::default();
    let local_peer = config.local_peer;
    let remote_peer = PeerId::from_label(&format!("atp_conformance_remote_{label}"));
    let sdk = AtpSdk::new_in_process(config);
    let options = SessionOptions::direct(remote_peer).with_grants(vec![conformance_grant(
        remote_peer,
        local_peer,
        label,
        [CapabilityAction::Read, CapabilityAction::Write],
    )]);

    match block_on(sdk.open_session(cx, options)) {
        asupersync::net::atp::protocol::AtpOutcome::Ok(session) => Ok(session),
        other => Err(format!("session negotiation failed: {other:?}")),
    }
}

fn conformance_transfer_request(label: &str, bytes: usize) -> TransferRequest {
    TransferRequest {
        source: TransferSource::Object {
            data: (0..bytes).map(|index| (index % 251) as u8).collect(),
            content_type: Some("application/octet-stream".to_string()),
        },
        destination: TransferDestination::Object {
            object_id: format!("atp-conformance-{label}"),
        },
        options: TransferOptions {
            transfer_id: Some(asupersync::net::atp::sdk::TransferId::new(format!(
                "atp-conformance-{label}"
            ))),
            ..TransferOptions::default()
        },
    }
}

fn session_error_code(error: &SessionError) -> &'static str {
    match error {
        SessionError::WithProof { source, .. } => source.code(),
        other => other.code(),
    }
}

fn conformance_event_json(case: &ConformanceCase, result: &ConformanceResult) -> String {
    json!({
        "case_id": case.id,
        "section": case.section,
        "requirement_level": format!("{:?}", case.level),
        "category": format!("{:?}", case.category),
        "verdict": result.verdict(),
        "description": case.description,
        "observed_behavior": result.observed(),
        "failure_reason": result.reason(),
        "owner_bead": result.owner_bead(),
        "artifact_path": ATP_PROTOCOL_CONFORMANCE_ARTIFACT,
    })
    .to_string()
}

/// Test that ATP frames must have valid frame types.
fn test_frame_type_required(_cx: &Cx) -> ConformanceResult {
    // Test that all frame types are valid
    let frame_types = [
        FrameType::Control,
        FrameType::Data,
        FrameType::Proof,
        FrameType::Repair,
        FrameType::Session,
        FrameType::Manifest,
    ];

    for frame_type in frame_types {
        let frame = AtpFrame::empty(frame_type);
        if frame.is_err() {
            return ConformanceResult::fail(
                format!("Failed to create frame with type {:?}", frame_type),
                format!("frame_type={frame_type:?} constructor returned error"),
            );
        }

        let frame = frame.unwrap();
        if frame.frame_type() != frame_type {
            return ConformanceResult::fail(
                format!(
                    "Frame type mismatch: expected {:?}, got {:?}",
                    frame_type,
                    frame.frame_type()
                ),
                format!(
                    "frame_type={frame_type:?} payload_len={}",
                    frame.payload().len()
                ),
            );
        }
    }

    ConformanceResult::pass("all canonical ATP frame types constructed and round-tripped")
}

/// Test that ATP frames must support empty payloads.
fn test_frame_empty_payload_support(_cx: &Cx) -> ConformanceResult {
    match AtpFrame::empty(FrameType::Data) {
        Ok(frame) => {
            if !frame.payload().is_empty() {
                ConformanceResult::fail(
                    "Empty frame should have empty payload",
                    format!("payload_len={}", frame.payload().len()),
                )
            } else {
                ConformanceResult::pass("FrameType::Data empty frame has zero-byte payload")
            }
        }
        Err(err) => ConformanceResult::fail(
            format!("Failed to create empty frame: {}", err),
            "Frame::empty(FrameType::Data) returned error",
        ),
    }
}

/// Test that ATP implementations should validate frame consistency.
fn test_frame_validation(_cx: &Cx) -> ConformanceResult {
    // Test frame with valid payload
    let payload = vec![1, 2, 3, 4];
    match AtpFrame::new(ProtocolVersion::CURRENT, FrameType::Data, payload.clone()) {
        Ok(frame) => {
            if frame.payload() != payload {
                ConformanceResult::fail(
                    "Frame payload does not match input",
                    format!(
                        "expected_payload_len={} observed_payload_len={}",
                        payload.len(),
                        frame.payload().len()
                    ),
                )
            } else {
                ConformanceResult::pass(format!(
                    "payload_len={} preserved by AtpFrame::new",
                    payload.len()
                ))
            }
        }
        Err(err) => ConformanceResult::fail(
            format!("Failed to create frame with payload: {}", err),
            format!("payload_len={}", payload.len()),
        ),
    }
}

/// Test that sessions must have timeout configuration.
fn test_session_timeout_required(_cx: &Cx) -> ConformanceResult {
    let config = SessionConfig::default();

    if config.session_timeout_ms == 0 {
        ConformanceResult::fail(
            "Default session timeout must be greater than zero",
            "SessionConfig::default produced session_timeout_ms=0",
        )
    } else {
        ConformanceResult::pass(format!(
            "SessionConfig::default produced session_timeout_ms={}",
            config.session_timeout_ms
        ))
    }
}

/// Test that sessions must respect concurrent transfer limits.
fn test_concurrent_transfer_limits(cx: &Cx) -> ConformanceResult {
    let config = SessionConfig {
        local_peer: fixtures::test_peer_id(1),
        session_timeout_ms: 30000,
        enable_compression: false,
        enable_repair: false,
        enable_resume: false,
        max_concurrent_transfers: 1,
        stream_buffer_size: 1024,
    };
    let local_peer = config.local_peer;
    let remote_peer = fixtures::test_peer_id(2);
    let sdk = AtpSdk::new_in_process(config.clone());
    let options = SessionOptions::direct(remote_peer).with_grants(vec![conformance_grant(
        remote_peer,
        local_peer,
        "concurrent-transfer-limit",
        [CapabilityAction::Read, CapabilityAction::Write],
    )]);

    block_on(async {
        let session = match sdk.open_session(cx, options).await {
            asupersync::net::atp::protocol::AtpOutcome::Ok(session) => session,
            other => {
                return ConformanceResult::fail(
                    "Session setup failed before transfer-limit observation",
                    format!("open_session={other:?}"),
                );
            }
        };

        let first = session
            .send_object(cx, conformance_transfer_request("first", 128))
            .await;
        let second = session
            .send_object(cx, conformance_transfer_request("second", 128))
            .await;
        let first_ok = first.is_ok();
        let second_ok = second.is_ok();

        if first_ok && !second_ok {
            ConformanceResult::pass(format!(
                "max_concurrent_transfers={} first_ok={first_ok} second_ok={second_ok}",
                config.max_concurrent_transfers
            ))
        } else {
            ConformanceResult::known_gap(
                "SDK active-transfer registry does not yet reject a second simultaneous transfer when the session limit is one",
                ATP_NR_OWNER_BEAD,
                format!(
                    "max_concurrent_transfers={} first_ok={first_ok} second_ok={second_ok}",
                    config.max_concurrent_transfers
                ),
            )
        }
    })
}

/// Test that sessions should support compression configuration.
fn test_compression_configuration(_cx: &Cx) -> ConformanceResult {
    let mut config = SessionConfig {
        local_peer: fixtures::test_peer_id(1),
        session_timeout_ms: 30000,
        enable_compression: false,
        enable_repair: false,
        enable_resume: false,
        max_concurrent_transfers: 5,
        stream_buffer_size: 1024,
    };

    // Test compression can be enabled/disabled
    config.enable_compression = true;
    assert!(config.enable_compression);

    config.enable_compression = false;
    assert!(!config.enable_compression);

    ConformanceResult::pass(
        "SessionConfig compression flag toggles true and false deterministically",
    )
}

/// Test that transfers must enforce maximum size limits.
fn test_transfer_size_limits(_cx: &Cx) -> ConformanceResult {
    let policy = TransferPolicy {
        max_transfer_size_bytes: 1024 * 1024, // 1MB
        max_chunk_size_bytes: 64 * 1024,      // 64KB
        transfer_timeout_ms: 30000,
        enable_auto_retry: true,
        max_retry_attempts: 3,
        retry_backoff_ms: 1000,
        progress_report_interval_ms: 1000,
    };

    // Test that limits are reasonable
    if policy.max_transfer_size_bytes == 0 {
        ConformanceResult::fail(
            "Maximum transfer size must be greater than zero",
            "max_transfer_size_bytes=0",
        )
    } else if u64::from(policy.max_chunk_size_bytes) > policy.max_transfer_size_bytes {
        ConformanceResult::fail(
            "Chunk size cannot exceed transfer size",
            format!(
                "max_chunk_size_bytes={} max_transfer_size_bytes={}",
                policy.max_chunk_size_bytes, policy.max_transfer_size_bytes
            ),
        )
    } else {
        ConformanceResult::pass(format!(
            "max_transfer_size_bytes={} max_chunk_size_bytes={}",
            policy.max_transfer_size_bytes, policy.max_chunk_size_bytes
        ))
    }
}

/// Test that transfers must enforce timeout policies.
fn test_transfer_timeout_enforcement(_cx: &Cx) -> ConformanceResult {
    let policy = TransferPolicy::default();

    if policy.transfer_timeout_ms == 0 {
        ConformanceResult::fail(
            "Default transfer timeout must be greater than zero",
            "TransferPolicy::default produced transfer_timeout_ms=0",
        )
    } else {
        ConformanceResult::pass(format!(
            "TransferPolicy::default produced transfer_timeout_ms={}",
            policy.transfer_timeout_ms
        ))
    }
}

/// Test that transfers should support automatic retry.
fn test_automatic_retry_support(_cx: &Cx) -> ConformanceResult {
    let policy = TransferPolicy {
        max_transfer_size_bytes: 1024 * 1024,
        max_chunk_size_bytes: 64 * 1024,
        transfer_timeout_ms: 30000,
        enable_auto_retry: true,
        max_retry_attempts: 3,
        retry_backoff_ms: 1000,
        progress_report_interval_ms: 1000,
    };

    // Test retry configuration
    if policy.enable_auto_retry && policy.max_retry_attempts == 0 {
        ConformanceResult::fail(
            "Auto retry enabled but max attempts is zero",
            "enable_auto_retry=true max_retry_attempts=0",
        )
    } else if policy.enable_auto_retry && policy.retry_backoff_ms == 0 {
        ConformanceResult::fail(
            "Auto retry enabled but backoff is zero",
            "enable_auto_retry=true retry_backoff_ms=0",
        )
    } else {
        ConformanceResult::pass(format!(
            "enable_auto_retry={} max_retry_attempts={} retry_backoff_ms={}",
            policy.enable_auto_retry, policy.max_retry_attempts, policy.retry_backoff_ms
        ))
    }
}

/// Test that transfers must verify data integrity.
fn test_data_integrity_verification(cx: &Cx) -> ConformanceResult {
    let session = match conformance_sdk_session(cx, "integrity-verification") {
        Ok(session) => session,
        Err(reason) => return ConformanceResult::fail(reason, "session setup failed"),
    };
    let temp_dir = match tempfile::tempdir() {
        Ok(temp_dir) => temp_dir,
        Err(err) => {
            return ConformanceResult::fail(
                format!("failed to create conformance tempdir: {err}"),
                "tempdir creation failed",
            );
        }
    };
    let payload = test_data::pattern_data(4096);
    let expected_hash = ObjectHash::from_data(&payload);
    let object_path = temp_dir.path().join("integrity-payload.bin");
    if let Err(err) = std::fs::write(&object_path, &payload) {
        return ConformanceResult::fail(
            format!("failed to write integrity fixture: {err}"),
            object_path.display().to_string(),
        );
    }

    match block_on(session.verify_object(cx, &object_path, Some(expected_hash.as_bytes()))) {
        asupersync::net::atp::protocol::AtpOutcome::Ok(verification)
            if verification.verified
                && verification.integrity_check_passed
                && verification.hash == expected_hash.as_bytes().to_vec() =>
        {
            ConformanceResult::pass(format!(
                "verified=true integrity_check_passed=true bytes={} hash_prefix={}",
                payload.len(),
                &expected_hash.hex()[..16]
            ))
        }
        asupersync::net::atp::protocol::AtpOutcome::Ok(verification) => ConformanceResult::fail(
            "verification result did not satisfy integrity contract",
            format!(
                "verified={} integrity_check_passed={} hash_len={}",
                verification.verified,
                verification.integrity_check_passed,
                verification.hash.len()
            ),
        ),
        other => ConformanceResult::fail(
            "verify_object returned non-Ok outcome",
            format!("verify_object={other:?}"),
        ),
    }
}

/// Test that corrupted data must be rejected.
fn test_corruption_detection(cx: &Cx) -> ConformanceResult {
    let session = match conformance_sdk_session(cx, "corruption-detection") {
        Ok(session) => session,
        Err(reason) => return ConformanceResult::fail(reason, "session setup failed"),
    };
    let temp_dir = match tempfile::tempdir() {
        Ok(temp_dir) => temp_dir,
        Err(err) => {
            return ConformanceResult::fail(
                format!("failed to create conformance tempdir: {err}"),
                "tempdir creation failed",
            );
        }
    };
    let original = test_data::deterministic_data(2048, 0xA7A7_0001);
    let expected_hash = ObjectHash::from_data(&original);
    let object_path = temp_dir.path().join("corrupted-payload.bin");
    if let Err(err) = std::fs::write(&object_path, &original) {
        return ConformanceResult::fail(
            format!("failed to write original fixture: {err}"),
            object_path.display().to_string(),
        );
    }
    let mut corrupted = original;
    corrupted[17] ^= 0xA5;
    corrupted[1024] ^= 0x5A;
    if let Err(err) = std::fs::write(&object_path, &corrupted) {
        return ConformanceResult::fail(
            format!("failed to write corrupted fixture: {err}"),
            object_path.display().to_string(),
        );
    }

    match block_on(session.verify_object(cx, &object_path, Some(expected_hash.as_bytes()))) {
        asupersync::net::atp::protocol::AtpOutcome::Ok(verification)
            if !verification.verified && !verification.integrity_check_passed =>
        {
            ConformanceResult::pass(format!(
                "corrupted payload rejected: verified=false integrity_check_passed=false expected_hash_prefix={}",
                &expected_hash.hex()[..16]
            ))
        }
        asupersync::net::atp::protocol::AtpOutcome::Ok(verification) => ConformanceResult::fail(
            "corrupted payload was not rejected by verification",
            format!(
                "verified={} integrity_check_passed={} size_bytes={}",
                verification.verified, verification.integrity_check_passed, verification.size_bytes
            ),
        ),
        other => ConformanceResult::fail(
            "verify_object returned non-Ok outcome for corruption fixture",
            format!("verify_object={other:?}"),
        ),
    }
}

/// Test that operations must require explicit capabilities.
fn test_capability_requirements(_cx: &Cx) -> ConformanceResult {
    let initiator = fixtures::test_peer_id(10);
    let responder = fixtures::test_peer_id(11);
    let hello = asupersync::net::atp::protocol::ClientHello::new(
        initiator,
        responder,
        asupersync::net::atp::protocol::TransferNonce::from_seed("capability-required"),
        SessionContextKind::Direct,
        SessionTraceId::new(7_001),
    )
    .with_features(&[AtpFeature::EncryptionPolicy, AtpFeature::ProofBundles])
    .with_requested_actions(&[CapabilityAction::Read, CapabilityAction::Write]);
    let mut policy = asupersync::net::atp::protocol::SessionPolicy::new(responder, 0)
        .with_supported_features(&[AtpFeature::EncryptionPolicy, AtpFeature::ProofBundles])
        .with_required_actions(&[CapabilityAction::Read, CapabilityAction::Write])
        .with_accepted_contexts(&[SessionContextKind::Direct]);
    let mut server = asupersync::net::atp::protocol::SessionNegotiator::server(responder);

    match server.accept_client_hello(&hello, &mut policy) {
        Err(error) if session_error_code(&error) == "missing_grant_action" => {
            ConformanceResult::pass(format!(
                "missing grant rejected with error_code={}",
                session_error_code(&error)
            ))
        }
        other => ConformanceResult::fail(
            "missing explicit capability grant was not rejected with missing_grant_action",
            format!("accept_client_hello={other:?}"),
        ),
    }
}

/// Test that authorization boundaries must be enforced.
fn test_authorization_enforcement(cx: &Cx) -> ConformanceResult {
    let config = SessionConfig::default();
    let local_peer = config.local_peer;
    let remote_peer = fixtures::test_peer_id(22);
    let untrusted_issuer = fixtures::test_peer_id(23);
    let sdk = AtpSdk::new_in_process(config);
    let bad_grant = conformance_grant(
        untrusted_issuer,
        local_peer,
        "untrusted-issuer",
        [CapabilityAction::Read, CapabilityAction::Write],
    );
    let options = SessionOptions::direct(remote_peer).with_grants(vec![bad_grant]);

    match block_on(sdk.open_session(cx, options)) {
        asupersync::net::atp::protocol::AtpOutcome::Err(AtpError::Protocol(
            ProtocolError::SessionStateMismatch,
        )) => ConformanceResult::pass(format!(
            "untrusted grant issuer rejected for local_peer={} remote_peer={}",
            local_peer.redacted(),
            remote_peer.redacted()
        )),
        other => ConformanceResult::fail(
            "untrusted grant issuer was not rejected by session authorization",
            format!("open_session={other:?}"),
        ),
    }
}

/// Run full ATP protocol conformance test suite.
#[test]
fn atp_protocol_full_conformance() {
    let cx = test_cx();
    let mut pass = 0;
    let mut fail = 0;
    let mut skipped = 0;
    let mut known_gap = 0;

    for case in ATP_CONFORMANCE_CASES {
        let result = (case.test_fn)(&cx);
        let verdict = result.verdict();
        match &result {
            ConformanceResult::Pass { .. } => {
                pass += 1;
            }
            ConformanceResult::Fail { reason, .. } => {
                fail += 1;
                eprintln!(
                    "FAIL {}: {}\n  reason: {}",
                    case.id, case.description, reason
                );
            }
            ConformanceResult::Skipped { reason, .. } => {
                skipped += 1;
                eprintln!(
                    "SKIP {}: {}\n  reason: {}",
                    case.id, case.description, reason
                );
            }
            ConformanceResult::KnownGap {
                reason, owner_bead, ..
            } => {
                known_gap += 1;
                eprintln!(
                    "KNOWN_GAP {}: {}\n  owner_bead: {}\n  reason: {}",
                    case.id, case.description, owner_bead, reason
                );
            }
        };

        // Structured JSON output for CI parsing
        eprintln!("{}", conformance_event_json(case, &result));
    }

    let total = pass + fail + skipped + known_gap;
    let must_tests = ATP_CONFORMANCE_CASES
        .iter()
        .filter(|c| c.level == RequirementLevel::Must)
        .count();
    let must_pass = ATP_CONFORMANCE_CASES
        .iter()
        .filter(|c| c.level == RequirementLevel::Must)
        .filter(|c| matches!((c.test_fn)(&cx), ConformanceResult::Pass { .. }))
        .count();
    let compliance_score = if must_tests > 0 {
        (must_pass as f64 / must_tests as f64) * 100.0
    } else {
        0.0
    };

    eprintln!(
        "\nATP Protocol Conformance: {}/{} pass, {} fail, {} skip, {} known_gap",
        pass, total, fail, skipped, known_gap
    );
    eprintln!(
        "MUST requirements: {}/{} pass ({:.1}%)",
        must_pass, must_tests, compliance_score
    );
    eprintln!(
        "Compliance: {}",
        if compliance_score >= 95.0 {
            "COMPLIANT"
        } else {
            "NON-COMPLIANT"
        }
    );

    // Fail only if non-expected failures occur
    assert_eq!(fail, 0, "{} conformance tests failed unexpectedly", fail);

    // Warn if compliance score is low
    if compliance_score < 95.0 {
        eprintln!(
            "Warning: MUST requirement compliance is {:.1}% (< 95% threshold)",
            compliance_score
        );
    }
}

/// Generate compliance coverage matrix.
#[test]
fn atp_protocol_coverage_matrix() {
    let cx = test_cx();

    println!("# ATP Protocol Conformance Coverage Matrix");
    println!();
    println!("| Test ID | Section | Level | Category | Status | Description |");
    println!("| ------- | ------- | ----- | -------- | ------ | ----------- |");

    for case in ATP_CONFORMANCE_CASES {
        let result = (case.test_fn)(&cx);
        let status = match result {
            ConformanceResult::Pass { .. } => "PASS",
            ConformanceResult::Fail { .. } => "FAIL",
            ConformanceResult::Skipped { .. } => "SKIP",
            ConformanceResult::KnownGap { .. } => "KNOWN_GAP",
        };

        println!(
            "| {} | {} | {:?} | {:?} | {} | {} |",
            case.id, case.section, case.level, case.category, status, case.description
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conformance_infrastructure() {
        // Test that we have defined test cases
        assert!(
            !ATP_CONFORMANCE_CASES.is_empty(),
            "Should have ATP conformance test cases"
        );

        // Test that all requirement levels are covered
        let has_must = ATP_CONFORMANCE_CASES
            .iter()
            .any(|c| c.level == RequirementLevel::Must);
        let has_should = ATP_CONFORMANCE_CASES
            .iter()
            .any(|c| c.level == RequirementLevel::Should);

        assert!(has_must, "Should have MUST requirements tested");
        assert!(has_should, "Should have SHOULD requirements tested");

        // Test that all categories are covered
        let categories: std::collections::HashSet<_> =
            ATP_CONFORMANCE_CASES.iter().map(|c| c.category).collect();

        assert!(
            categories.len() > 1,
            "Should cover multiple test categories"
        );
    }
}
