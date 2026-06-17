//! ATP Preflight Planner Integration Tests
//!
//! Tests the transfer preflight planner functionality including dry-run,
//! cost modeling, plan generation, and execution tracking.

use asupersync::atp::{
    AtpTransferPlanner, PlannerConfig, PlannerOptions, TransferMode, TransferType,
};
use asupersync::cx::Cx;
use std::collections::HashMap;
use tempfile::TempDir;

struct TestRuntime {
    cx: Cx,
}

impl TestRuntime {
    fn new() -> Result<Self, String> {
        Ok(Self {
            cx: Cx::for_testing(),
        })
    }

    fn root_cx(&self) -> Cx {
        self.cx.clone()
    }
}

#[tokio::test]
async fn test_planner_input_validation() {
    let runtime = TestRuntime::new().unwrap();
    let cx = runtime.root_cx();
    let planner = AtpTransferPlanner::new_default();

    let temp_dir = TempDir::new().unwrap();
    let non_existent_path = temp_dir.path().join("non_existent.txt");
    let dest_path = temp_dir.path().join("destination.txt");

    let options = PlannerOptions::default();

    // Test with non-existent source
    let result = planner
        .plan_transfer(
            &cx,
            TransferType::Send,
            &non_existent_path,
            &dest_path,
            options,
        )
        .await;

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("does not exist"));
}

#[tokio::test]
async fn test_cache_hit_scenario() {
    let runtime = TestRuntime::new().unwrap();
    let cx = runtime.root_cx();
    let planner = AtpTransferPlanner::new_default();

    let temp_dir = TempDir::new().unwrap();
    let source_path = temp_dir.path().join("source.txt");
    let dest_path = temp_dir.path().join("destination.txt");

    // Create test file
    std::fs::write(&source_path, b"test content for cache scenario").unwrap();

    let options = PlannerOptions {
        cache_enabled: true,
        transfer_mode: TransferMode::Direct,
        ..Default::default()
    };

    let plan = planner
        .plan_transfer(&cx, TransferType::Send, &source_path, &dest_path, options)
        .await
        .unwrap();

    assert!(plan.cache_analysis.local_hit_ratio > 0.0);
    assert!(plan.cache_analysis.bytes_from_cache > 0);
    assert!(!plan.cache_analysis.cache_locations.is_empty());
    assert!(
        plan.cache_analysis
            .cache_locations
            .contains(&"local".to_string())
    );
}

#[tokio::test]
async fn test_relay_only_scenario() {
    let runtime = TestRuntime::new().unwrap();
    let cx = runtime.root_cx();
    let planner = AtpTransferPlanner::new_default();

    let temp_dir = TempDir::new().unwrap();
    let source_path = temp_dir.path().join("source.txt");
    let dest_path = temp_dir.path().join("destination.txt");

    std::fs::write(&source_path, b"test content for relay scenario").unwrap();

    let options = PlannerOptions {
        transfer_mode: TransferMode::RelayOnly,
        ..Default::default()
    };

    let plan = planner
        .plan_transfer(&cx, TransferType::Send, &source_path, &dest_path, options)
        .await
        .unwrap();

    assert_eq!(plan.transfer_mode, TransferMode::RelayOnly);
    assert_eq!(plan.path_candidates.len(), 1);
    assert_eq!(plan.path_candidates[0].path_type, "relay");
    assert!(plan.path_candidates[0].preferred);
}

#[tokio::test]
async fn test_mailbox_scenario() {
    let runtime = TestRuntime::new().unwrap();
    let cx = runtime.root_cx();
    let planner = AtpTransferPlanner::new_default();

    let temp_dir = TempDir::new().unwrap();
    let source_path = temp_dir.path().join("source.txt");
    let dest_path = temp_dir.path().join("destination.txt");

    std::fs::write(&source_path, b"test content for mailbox scenario").unwrap();

    let options = PlannerOptions {
        transfer_mode: TransferMode::Mailbox,
        ..Default::default()
    };

    let plan = planner
        .plan_transfer(&cx, TransferType::Send, &source_path, &dest_path, options)
        .await
        .unwrap();

    assert_eq!(plan.transfer_mode, TransferMode::Mailbox);
    assert_eq!(plan.path_candidates[0].path_type, "mailbox");
    // Mailbox should have high reliability but lower bandwidth
    assert!(plan.path_candidates[0].reliability_score > 0.9);
}

#[tokio::test]
async fn test_swarm_scenario() {
    let runtime = TestRuntime::new().unwrap();
    let cx = runtime.root_cx();
    let planner = AtpTransferPlanner::new_default();

    let temp_dir = TempDir::new().unwrap();
    let source_path = temp_dir.path().join("source.txt");
    let dest_path = temp_dir.path().join("destination.txt");

    std::fs::write(&source_path, b"test content for swarm scenario").unwrap();

    let options = PlannerOptions {
        transfer_mode: TransferMode::Swarm,
        ..Default::default()
    };

    let plan = planner
        .plan_transfer(&cx, TransferType::Send, &source_path, &dest_path, options)
        .await
        .unwrap();

    assert_eq!(plan.transfer_mode, TransferMode::Swarm);
    assert_eq!(plan.path_candidates.len(), 3); // Multiple peers

    // First peer should be preferred
    assert!(plan.path_candidates[0].preferred);
    assert!(!plan.path_candidates[1].preferred);
    assert!(!plan.path_candidates[2].preferred);
}

#[tokio::test]
async fn test_sparse_image_scenario() {
    let runtime = TestRuntime::new().unwrap();
    let cx = runtime.root_cx();
    let planner = AtpTransferPlanner::new_default();

    let temp_dir = TempDir::new().unwrap();
    let source_path = temp_dir.path().join("source.img");
    let dest_path = temp_dir.path().join("destination.img");

    std::fs::write(&source_path, b"sparse image content").unwrap();

    let options = PlannerOptions {
        transfer_mode: TransferMode::SparseImage,
        ..Default::default()
    };

    let plan = planner
        .plan_transfer(&cx, TransferType::Send, &source_path, &dest_path, options)
        .await
        .unwrap();

    assert_eq!(plan.transfer_mode, TransferMode::SparseImage);
    assert_eq!(plan.path_candidates[0].path_type, "direct_sparse");
}

#[tokio::test]
async fn test_governance_profile() {
    let runtime = TestRuntime::new().unwrap();
    let cx = runtime.root_cx();
    let planner = AtpTransferPlanner::new_default();

    let temp_dir = TempDir::new().unwrap();
    let source_path = temp_dir.path().join("source.txt");
    let dest_path = temp_dir.path().join("destination.txt");

    std::fs::write(&source_path, b"test content").unwrap();

    let options = PlannerOptions {
        max_connections: Some(8),
        bandwidth_limit: Some(100 * 1024 * 1024), // 100 Mbps
        memory_limit: Some(1024 * 1024 * 1024),   // 1GB
        cpu_limit: Some(50.0),                    // 50%
        ..Default::default()
    };

    let plan = planner
        .plan_transfer(&cx, TransferType::Send, &source_path, &dest_path, options)
        .await
        .unwrap();

    assert_eq!(plan.governance_profile.max_connections, 8);
    assert_eq!(
        plan.governance_profile.bandwidth_limit,
        Some(100 * 1024 * 1024)
    );
    assert_eq!(
        plan.governance_profile.memory_limit,
        Some(1024 * 1024 * 1024)
    );
    assert_eq!(plan.governance_profile.cpu_limit, Some(50.0));
}

#[tokio::test]
async fn test_proof_outputs_configuration() {
    let runtime = TestRuntime::new().unwrap();
    let cx = runtime.root_cx();
    let planner = AtpTransferPlanner::new_default();

    let temp_dir = TempDir::new().unwrap();
    let source_path = temp_dir.path().join("source.txt");
    let dest_path = temp_dir.path().join("destination.txt");

    std::fs::write(&source_path, b"test content").unwrap();

    let mut proof_outputs = HashMap::new();
    proof_outputs.insert("manifest".to_string(), "/tmp/manifest.json".to_string());
    proof_outputs.insert("trace".to_string(), "/tmp/trace.log".to_string());

    let options = PlannerOptions {
        proof_outputs: Some(proof_outputs),
        ..Default::default()
    };

    let plan = planner
        .plan_transfer(&cx, TransferType::Send, &source_path, &dest_path, options)
        .await
        .unwrap();

    assert!(!plan.proof_outputs.is_empty());
    assert!(plan.proof_outputs.contains_key("manifest"));
    assert!(plan.proof_outputs.contains_key("trace"));
    assert_eq!(plan.proof_outputs["manifest"], "/tmp/manifest.json");
}

#[tokio::test]
async fn test_plan_validation_success() {
    let runtime = TestRuntime::new().unwrap();
    let cx = runtime.root_cx();
    let planner = AtpTransferPlanner::new_default();

    let temp_dir = TempDir::new().unwrap();
    let source_path = temp_dir.path().join("source.txt");
    let dest_path = temp_dir.path().join("destination.txt");

    std::fs::write(&source_path, b"test content").unwrap();

    let options = PlannerOptions::default();

    let plan = planner
        .plan_transfer(&cx, TransferType::Send, &source_path, &dest_path, options)
        .await
        .unwrap();

    let warnings = planner.validate_plan(&cx, &plan).await.unwrap();
    assert!(
        warnings.is_empty(),
        "default direct plan should validate without confidence warnings: {warnings:?}"
    );
}

#[tokio::test]
async fn test_plan_validation_disk_space_error() {
    let runtime = TestRuntime::new().unwrap();
    let cx = runtime.root_cx();

    let config = PlannerConfig::default();
    let planner = AtpTransferPlanner::new(config);

    let temp_dir = TempDir::new().unwrap();
    let source_path = temp_dir.path().join("source.txt");
    let dest_path = temp_dir.path().join("destination.txt");

    std::fs::write(&source_path, b"test content").unwrap();

    let options = PlannerOptions::default();

    let mut plan = planner
        .plan_transfer(&cx, TransferType::Send, &source_path, &dest_path, options)
        .await
        .unwrap();

    // Simulate insufficient disk space
    plan.disk_allocation.required_space = 1_000_000_000_000; // 1TB
    plan.disk_allocation.available_space = 1000; // 1KB

    let result = planner.validate_plan(&cx, &plan).await;
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Insufficient disk space")
    );
}

#[tokio::test]
async fn test_execution_tracker() {
    let planner = AtpTransferPlanner::new_default();
    let mut tracker = planner.create_execution_tracker("test_plan_123".to_string());

    // Record some deviations
    tracker.record_deviation(
        "bandwidth".to_string(),
        "100 Mbps".to_string(),
        "50 Mbps".to_string(),
        "network congestion".to_string(),
        "medium".to_string(),
    );

    tracker.record_deviation(
        "path".to_string(),
        "direct".to_string(),
        "relay".to_string(),
        "direct path unavailable".to_string(),
        "low".to_string(),
    );

    let mut final_stats = HashMap::new();
    final_stats.insert(
        "actual_bytes".to_string(),
        serde_json::Value::from(1024 * 1024),
    );
    final_stats.insert(
        "actual_duration_ms".to_string(),
        serde_json::Value::from(30000),
    );

    let report = tracker.generate_report(true, None, final_stats);

    assert_eq!(report.plan_id, "test_plan_123");
    assert!(report.success);
    assert!(report.completed_at.is_some());
    assert_eq!(report.deviations.len(), 2);
    assert!(report.final_stats.contains_key("actual_bytes"));
}

#[tokio::test]
async fn test_directory_sync_scenario() {
    let runtime = TestRuntime::new().unwrap();
    let cx = runtime.root_cx();
    let planner = AtpTransferPlanner::new_default();

    let temp_dir = TempDir::new().unwrap();
    let source_dir = temp_dir.path().join("source_dir");
    let dest_dir = temp_dir.path().join("dest_dir");

    std::fs::create_dir(&source_dir).unwrap();
    std::fs::write(source_dir.join("file1.txt"), b"content1").unwrap();
    std::fs::write(source_dir.join("file2.txt"), b"content2").unwrap();

    let options = PlannerOptions::default();

    let plan = planner
        .plan_transfer(&cx, TransferType::Sync, &source_dir, &dest_dir, options)
        .await
        .unwrap();

    assert_eq!(plan.transfer_type, TransferType::Sync);
    // Directory should have estimated multiple objects
    assert!(plan.object_graph.object_count > 1);
    assert!(plan.object_graph.file_count > 0);
    assert!(plan.object_graph.directory_count > 0);
}

#[tokio::test]
async fn test_mirror_with_deletes_scenario() {
    let runtime = TestRuntime::new().unwrap();
    let cx = runtime.root_cx();
    let planner = AtpTransferPlanner::new_default();

    let temp_dir = TempDir::new().unwrap();
    let source_dir = temp_dir.path().join("source_dir");
    let dest_dir = temp_dir.path().join("dest_dir");

    std::fs::create_dir(&source_dir).unwrap();
    std::fs::write(source_dir.join("keep.txt"), b"keep this file").unwrap();

    let options = PlannerOptions::default();

    let plan = planner
        .plan_transfer(&cx, TransferType::Mirror, &source_dir, &dest_dir, options)
        .await
        .unwrap();

    assert_eq!(plan.transfer_type, TransferType::Mirror);
    assert!(plan.object_graph.total_bytes > 0);
}

#[tokio::test]
async fn test_resume_scenario() {
    let runtime = TestRuntime::new().unwrap();
    let cx = runtime.root_cx();
    let planner = AtpTransferPlanner::new_default();

    let temp_dir = TempDir::new().unwrap();
    let source_path = temp_dir.path().join("source.txt");
    let dest_path = temp_dir.path().join("destination.txt");

    let source_bytes = b"test content for resume";
    std::fs::write(&source_path, source_bytes).unwrap();
    // Create partial destination to simulate resume
    let partial_bytes = b"partial";
    std::fs::write(&dest_path, partial_bytes).unwrap();

    let options = PlannerOptions {
        allow_resume: true,
        ..Default::default()
    };

    let plan = planner
        .plan_transfer(&cx, TransferType::Send, &source_path, &dest_path, options)
        .await
        .unwrap();

    assert!(plan.resume_state.resume_available);
    assert!(
        plan.resume_state
            .resume_token
            .as_deref()
            .is_some_and(|token| token.starts_with("journal://atp-resume/v1/"))
    );
    assert_eq!(
        plan.resume_state.bytes_completed,
        partial_bytes.len() as u64
    );
    assert_eq!(
        plan.resume_state.bytes_remaining,
        (source_bytes.len() - partial_bytes.len()) as u64
    );
    assert_eq!(plan.resume_state.chunks_completed, 0);
    assert_eq!(plan.resume_state.next_chunk_index, 0);
}

#[tokio::test]
async fn test_resume_token_is_stable_for_unchanged_checkpoint() {
    let runtime = TestRuntime::new().unwrap();
    let cx = runtime.root_cx();
    let planner = AtpTransferPlanner::new_default();

    let temp_dir = TempDir::new().unwrap();
    let source_path = temp_dir.path().join("source.txt");
    let dest_path = temp_dir.path().join("destination.txt");

    std::fs::write(&source_path, b"stable source content for resume").unwrap();
    std::fs::write(&dest_path, b"stable partial").unwrap();

    let options = PlannerOptions {
        allow_resume: true,
        ..Default::default()
    };

    let first = planner
        .plan_transfer(
            &cx,
            TransferType::Send,
            &source_path,
            &dest_path,
            options.clone(),
        )
        .await
        .unwrap();
    let second = planner
        .plan_transfer(&cx, TransferType::Send, &source_path, &dest_path, options)
        .await
        .unwrap();

    assert_eq!(
        first.resume_state.resume_token,
        second.resume_state.resume_token
    );
}

#[tokio::test]
async fn test_resume_rejects_checkpoint_past_source_graph() {
    let runtime = TestRuntime::new().unwrap();
    let cx = runtime.root_cx();
    let planner = AtpTransferPlanner::new_default();

    let temp_dir = TempDir::new().unwrap();
    let source_path = temp_dir.path().join("source.txt");
    let dest_path = temp_dir.path().join("destination.txt");

    std::fs::write(&source_path, b"small").unwrap();
    std::fs::write(&dest_path, b"destination is larger than the source").unwrap();

    let options = PlannerOptions {
        allow_resume: true,
        ..Default::default()
    };

    let error = planner
        .plan_transfer(&cx, TransferType::Send, &source_path, &dest_path, options)
        .await
        .expect_err("resume checkpoint beyond the source graph must fail closed")
        .to_string();

    assert!(
        error.contains("exceeds source object graph size"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn test_resume_chunk_accounting_keeps_partial_chunk_unverified() {
    let runtime = TestRuntime::new().unwrap();
    let cx = runtime.root_cx();
    let planner = AtpTransferPlanner::new(PlannerConfig::default());

    let temp_dir = TempDir::new().unwrap();
    let source_path = temp_dir.path().join("source.bin");
    let dest_path = temp_dir.path().join("destination.bin");

    std::fs::write(&source_path, vec![b's'; 600 * 1024]).unwrap();
    std::fs::write(&dest_path, vec![b'd'; 64 * 1024 + 1]).unwrap();

    let options = PlannerOptions {
        allow_resume: true,
        ..Default::default()
    };

    let plan = planner
        .plan_transfer(&cx, TransferType::Send, &source_path, &dest_path, options)
        .await
        .unwrap();

    assert_eq!(plan.chunking_profile.chunk_size, 64 * 1024);
    assert_eq!(plan.resume_state.bytes_completed, 64 * 1024 + 1);
    assert_eq!(plan.resume_state.chunks_completed, 1);
    assert_eq!(plan.resume_state.next_chunk_index, 1);
}

#[tokio::test]
async fn test_plan_schema_versions() {
    use asupersync::atp::{ATP_PLAN_EXECUTION_REPORT_SCHEMA, ATP_TRANSFER_PLAN_SCHEMA};

    let runtime = TestRuntime::new().unwrap();
    let cx = runtime.root_cx();
    let planner = AtpTransferPlanner::new_default();

    let temp_dir = TempDir::new().unwrap();
    let source_path = temp_dir.path().join("source.txt");
    let dest_path = temp_dir.path().join("destination.txt");

    std::fs::write(&source_path, b"test").unwrap();

    let options = PlannerOptions::default();

    let plan = planner
        .plan_transfer(&cx, TransferType::Send, &source_path, &dest_path, options)
        .await
        .unwrap();

    assert_eq!(plan.schema_version, ATP_TRANSFER_PLAN_SCHEMA);

    let tracker = planner.create_execution_tracker("test".to_string());
    let report = tracker.generate_report(true, None, HashMap::new());

    assert_eq!(report.schema_version, ATP_PLAN_EXECUTION_REPORT_SCHEMA);
}

#[tokio::test]
async fn test_uncertainty_tracking() {
    let runtime = TestRuntime::new().unwrap();
    let cx = runtime.root_cx();
    let planner = AtpTransferPlanner::new_default();

    let temp_dir = TempDir::new().unwrap();
    let source_path = temp_dir.path().join("source.txt");
    let dest_path = temp_dir.path().join("destination.txt");

    std::fs::write(&source_path, b"test content").unwrap();

    let options = PlannerOptions::default();

    let plan = planner
        .plan_transfer(&cx, TransferType::Send, &source_path, &dest_path, options)
        .await
        .unwrap();

    // Check uncertainty fields
    assert!(plan.uncertainty.bandwidth_confidence >= 0.0);
    assert!(plan.uncertainty.bandwidth_confidence <= 1.0);
    assert!(plan.uncertainty.path_confidence >= 0.0);
    assert!(plan.uncertainty.peer_confidence >= 0.0);
    assert!(plan.uncertainty.resource_confidence >= 0.0);
    assert!(!plan.uncertainty.uncertainty_factors.is_empty());
}

#[tokio::test]
async fn test_redacted_output() {
    let runtime = TestRuntime::new().unwrap();
    let cx = runtime.root_cx();
    let planner = AtpTransferPlanner::new_default();

    let temp_dir = TempDir::new().unwrap();
    let source_path = temp_dir.path().join("source.txt");
    let dest_path = temp_dir.path().join("destination.txt");

    std::fs::write(&source_path, b"test content").unwrap();

    let options = PlannerOptions::default();

    let plan = planner
        .plan_transfer(&cx, TransferType::Send, &source_path, &dest_path, options)
        .await
        .unwrap();

    // Plan should be serializable (for JSON output)
    let json = serde_json::to_string(&plan).unwrap();
    assert!(!json.is_empty());

    // Should be deserializable
    let _deserialized: asupersync::atp::AtpTransferPlan = serde_json::from_str(&json).unwrap();
}
