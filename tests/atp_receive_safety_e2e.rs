//! E2e scenarios for ATP receive-side safety preflight and destination policy.

use asupersync::atp::object::{Object, ObjectGraph, ObjectEdge, ObjectId};
use asupersync::atp::safety::{
    DestinationPolicy, ReceiveConsentSource, ReceiveMetadataPolicy, ReceivePreflightInput,
    RollbackResumePolicy, StorageEvidence, build_receive_plan, consent_token, ReceiveDecision,
    ReceiveRejectReason,
};
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

#[cfg(test)]
mod tests {
    use super::*;

    /// E2e scenario: Interactive receive with explicit consent confirms safe transfers.
    #[test]
    fn e2e_interactive_receive_with_consent() {
        let temp = TempDir::new().expect("create temp dir");
        let (graph, manifest_root) = create_safe_transfer_graph();

        let input = ReceivePreflightInput {
            sender_identity: "trusted-peer-alice".to_string(),
            grant_id: Some("grant-safe-123".to_string()),
            capability_scope: Some("path:/safe/downloads".to_string()),
            manifest_root: &manifest_root,
            graph: &graph,
            destination_policy: DestinationPolicy::AllowListed {
                allowed_roots: std::iter::once(temp.path().to_path_buf()).collect(),
                require_quarantine: false,
                allow_overwrite: false,
                allow_symlinks: false,
                allow_executables: false,
                allow_special_files: false,
                case_sensitive: true,
                max_bytes: Some(10_000),
            },
            destination_root: temp.path().to_path_buf(),
            destination_relative_path: PathBuf::from("safe-document.txt"),
            existing_destination_paths: BTreeSet::new(),
            storage_evidence: StorageEvidence {
                available_bytes: Some(100_000),
                quota_remaining_bytes: Some(50_000),
                safety_margin_bytes: 1_000,
            },
            metadata_policy: ReceiveMetadataPolicy::PortableOnly,
            consent_source: ReceiveConsentSource::CliConfirmation {
                token: "consent-placeholder".to_string(),
            },
            rollback_resume: RollbackResumePolicy::RollbackQuarantineKeepJournal,
            trace_id: Some("e2e-interactive-consent-123".to_string()),
            replay_pointer: Some("proof://e2e-consent-bundle".to_string()),
        };

        // Generate correct consent token for this plan
        let mut plan = build_receive_plan(input).expect("build plan");
        let expected_token = consent_token(&plan);

        // Re-build plan with correct token
        let input_with_token = ReceivePreflightInput {
            sender_identity: "trusted-peer-alice".to_string(),
            grant_id: Some("grant-safe-123".to_string()),
            capability_scope: Some("path:/safe/downloads".to_string()),
            manifest_root: &manifest_root,
            graph: &graph,
            destination_policy: DestinationPolicy::AllowListed {
                allowed_roots: std::iter::once(temp.path().to_path_buf()).collect(),
                require_quarantine: false,
                allow_overwrite: false,
                allow_symlinks: false,
                allow_executables: false,
                allow_special_files: false,
                case_sensitive: true,
                max_bytes: Some(10_000),
            },
            destination_root: temp.path().to_path_buf(),
            destination_relative_path: PathBuf::from("safe-document.txt"),
            existing_destination_paths: BTreeSet::new(),
            storage_evidence: StorageEvidence {
                available_bytes: Some(100_000),
                quota_remaining_bytes: Some(50_000),
                safety_margin_bytes: 1_000,
            },
            metadata_policy: ReceiveMetadataPolicy::PortableOnly,
            consent_source: ReceiveConsentSource::CliConfirmation {
                token: expected_token,
            },
            rollback_resume: RollbackResumePolicy::RollbackQuarantineKeepJournal,
            trace_id: Some("e2e-interactive-consent-123".to_string()),
            replay_pointer: Some("proof://e2e-consent-bundle".to_string()),
        };

        plan = build_receive_plan(input_with_token).expect("build plan with correct token");

        // Verify plan is admitted with proper consent
        assert_eq!(plan.decision, ReceiveDecision::AllowFinalCommit);
        assert!(plan.rejected_reasons.is_empty());
        assert_eq!(plan.sender_identity, "trusted-peer-alice");
        assert_eq!(plan.object_graph_summary.expected_bytes, 13); // "Hello, world!".len()

        // Verify proof artifacts are recorded
        assert_eq!(plan.trace_id, Some("e2e-interactive-consent-123".to_string()));
        assert_eq!(plan.replay_pointer, Some("proof://e2e-consent-bundle".to_string()));
    }

    /// E2e scenario: Daemon allow rule permits authorized transfers without interaction.
    #[test]
    fn e2e_daemon_allow_rule_permits_transfer() {
        let temp = TempDir::new().expect("create temp dir");
        let (graph, manifest_root) = create_safe_transfer_graph();

        let input = ReceivePreflightInput {
            sender_identity: "workspace-peer-bob".to_string(),
            grant_id: Some("workspace-grant-456".to_string()),
            capability_scope: Some("workspace:/shared/projects".to_string()),
            manifest_root: &manifest_root,
            graph: &graph,
            destination_policy: DestinationPolicy::AllowListed {
                allowed_roots: std::iter::once(temp.path().to_path_buf()).collect(),
                require_quarantine: true,
                allow_overwrite: false,
                allow_symlinks: false,
                allow_executables: false,
                allow_special_files: false,
                case_sensitive: true,
                max_bytes: Some(1_000_000),
            },
            destination_root: temp.path().to_path_buf(),
            destination_relative_path: PathBuf::from("project-file.txt"),
            existing_destination_paths: BTreeSet::new(),
            storage_evidence: StorageEvidence {
                available_bytes: Some(10_000_000),
                quota_remaining_bytes: Some(5_000_000),
                safety_margin_bytes: 100_000,
            },
            metadata_policy: ReceiveMetadataPolicy::PortableOnly,
            consent_source: ReceiveConsentSource::DaemonAllowRule {
                rule_id: "workspace-auto-allow-rule".to_string(),
            },
            rollback_resume: RollbackResumePolicy::ResumeFromVerifiedJournal,
            trace_id: Some("e2e-daemon-allow-456".to_string()),
            replay_pointer: None,
        };

        let plan = build_receive_plan(input).expect("build plan");

        // Verify daemon rule permits quarantine-then-commit
        assert_eq!(plan.decision, ReceiveDecision::AllowFinalCommit);
        assert!(plan.rejected_reasons.is_empty());
        assert!(plan.quarantine.required);
        assert_eq!(plan.consent_source, ReceiveConsentSource::DaemonAllowRule {
            rule_id: "workspace-auto-allow-rule".to_string(),
        });
    }

    /// E2e scenario: Malicious transfer is denied by path traversal detection.
    #[test]
    fn e2e_path_traversal_attack_blocked() {
        let temp = TempDir::new().expect("create temp dir");
        let (graph, manifest_root) = create_malicious_traversal_graph();

        let input = ReceivePreflightInput {
            sender_identity: "suspicious-peer".to_string(),
            grant_id: None,
            capability_scope: None,
            manifest_root: &manifest_root,
            graph: &graph,
            destination_policy: DestinationPolicy::AllowListed {
                allowed_roots: std::iter::once(temp.path().to_path_buf()).collect(),
                require_quarantine: false,
                allow_overwrite: false,
                allow_symlinks: false,
                allow_executables: false,
                allow_special_files: false,
                case_sensitive: true,
                max_bytes: None,
            },
            destination_root: temp.path().to_path_buf(),
            destination_relative_path: PathBuf::from("../../../etc/passwd"),
            existing_destination_paths: BTreeSet::new(),
            storage_evidence: StorageEvidence::default(),
            metadata_policy: ReceiveMetadataPolicy::PortableOnly,
            consent_source: ReceiveConsentSource::CliConfirmation {
                token: "fake-consent".to_string(),
            },
            rollback_resume: RollbackResumePolicy::RetainQuarantineForReview,
            trace_id: Some("e2e-traversal-attack".to_string()),
            replay_pointer: Some("proof://attack-attempt".to_string()),
        };

        let plan = build_receive_plan(input).expect("build plan");

        // Verify attack is blocked
        assert_eq!(plan.decision, ReceiveDecision::Deny);
        assert!(plan.rejected_reasons.iter().any(|r| matches!(r,
            ReceiveRejectReason::UnsafeDestinationPath(_)
        )));

        // Verify attack details are recorded for audit
        assert_eq!(plan.sender_identity, "suspicious-peer");
        assert_eq!(plan.trace_id, Some("e2e-traversal-attack".to_string()));
    }

    /// E2e scenario: Executable payload is quarantined under conservative policy.
    #[test]
    fn e2e_executable_payload_quarantined() {
        let temp = TempDir::new().expect("create temp dir");
        let (graph, manifest_root) = create_executable_graph();

        let input = ReceivePreflightInput {
            sender_identity: "build-server".to_string(),
            grant_id: Some("build-artifact-grant".to_string()),
            capability_scope: Some("ci:/build/artifacts".to_string()),
            manifest_root: &manifest_root,
            graph: &graph,
            destination_policy: DestinationPolicy::AllowListed {
                allowed_roots: std::iter::once(temp.path().to_path_buf()).collect(),
                require_quarantine: true,
                allow_overwrite: false,
                allow_symlinks: false,
                allow_executables: false, // Conservative: deny executables
                allow_special_files: false,
                case_sensitive: true,
                max_bytes: Some(50_000),
            },
            destination_root: temp.path().to_path_buf(),
            destination_relative_path: PathBuf::from("build-output"),
            existing_destination_paths: BTreeSet::new(),
            storage_evidence: StorageEvidence {
                available_bytes: Some(1_000_000),
                quota_remaining_bytes: Some(100_000),
                safety_margin_bytes: 10_000,
            },
            metadata_policy: ReceiveMetadataPolicy::RecordOnly,
            consent_source: ReceiveConsentSource::DaemonAllowRule {
                rule_id: "ci-quarantine-rule".to_string(),
            },
            rollback_resume: RollbackResumePolicy::RollbackQuarantineKeepJournal,
            trace_id: Some("e2e-executable-quarantine".to_string()),
            replay_pointer: Some("proof://ci-build-123".to_string()),
        };

        let plan = build_receive_plan(input).expect("build plan");

        // Verify executable is denied due to policy
        assert_eq!(plan.decision, ReceiveDecision::Deny);
        assert!(plan.rejected_reasons.iter().any(|r| matches!(r,
            ReceiveRejectReason::ExecutableDenied(_)
        )));
        assert_eq!(plan.object_graph_summary.executable_count, 1);

        // Verify quarantine path is prepared for manual review
        assert!(plan.quarantine.required);
        assert!(plan.quarantine.path.to_string_lossy().contains("quarantine"));
    }

    /// E2e scenario: Disk full condition prevents transfer with clear error.
    #[test]
    fn e2e_disk_full_prevents_transfer() {
        let temp = TempDir::new().expect("create temp dir");
        let (graph, manifest_root) = create_large_transfer_graph();

        let input = ReceivePreflightInput {
            sender_identity: "backup-server".to_string(),
            grant_id: Some("backup-restore-grant".to_string()),
            capability_scope: Some("backup:/restore".to_string()),
            manifest_root: &manifest_root,
            graph: &graph,
            destination_policy: DestinationPolicy::AllowListed {
                allowed_roots: std::iter::once(temp.path().to_path_buf()).collect(),
                require_quarantine: false,
                allow_overwrite: false,
                allow_symlinks: false,
                allow_executables: false,
                allow_special_files: false,
                case_sensitive: true,
                max_bytes: None,
            },
            destination_root: temp.path().to_path_buf(),
            destination_relative_path: PathBuf::from("large-backup.tar"),
            existing_destination_paths: BTreeSet::new(),
            storage_evidence: StorageEvidence {
                available_bytes: Some(1_000), // Only 1KB available
                quota_remaining_bytes: Some(500), // Only 500 bytes quota
                safety_margin_bytes: 100,
            },
            metadata_policy: ReceiveMetadataPolicy::PortableOnly,
            consent_source: ReceiveConsentSource::ReceiveGrant {
                grant_id: "backup-restore-grant".to_string(),
            },
            rollback_resume: RollbackResumePolicy::RollbackQuarantineKeepJournal,
            trace_id: Some("e2e-disk-full".to_string()),
            replay_pointer: Some("proof://backup-123".to_string()),
        };

        let plan = build_receive_plan(input).expect("build plan");

        // Verify disk full blocks transfer
        assert_eq!(plan.decision, ReceiveDecision::Deny);
        assert!(plan.rejected_reasons.iter().any(|r| matches!(r,
            ReceiveRejectReason::StorageDenied(_)
        )));

        // Verify storage arithmetic details are recorded
        assert_eq!(plan.storage.expected_bytes, 1_048_576); // 1MB
        assert_eq!(plan.storage.safety_margin_bytes, 100);
        assert_eq!(plan.storage.quota_remaining_bytes, Some(500));
    }

    /// E2e scenario: Mailbox policy accepts transfer for quarantine-only storage.
    #[test]
    fn e2e_mailbox_policy_quarantine_only() {
        let temp = TempDir::new().expect("create temp dir");
        let (graph, manifest_root) = create_safe_transfer_graph();

        let input = ReceivePreflightInput {
            sender_identity: "mobile-peer".to_string(),
            grant_id: Some("mailbox-grant-789".to_string()),
            capability_scope: Some("mailbox:/offline".to_string()),
            manifest_root: &manifest_root,
            graph: &graph,
            destination_policy: DestinationPolicy::QuarantineOnly {
                quarantine_root: temp.path().join(".mailbox-quarantine"),
            },
            destination_root: temp.path().to_path_buf(),
            destination_relative_path: PathBuf::from("offline-sync.txt"),
            existing_destination_paths: BTreeSet::new(),
            storage_evidence: StorageEvidence {
                available_bytes: Some(10_000_000),
                quota_remaining_bytes: Some(1_000_000),
                safety_margin_bytes: 50_000,
            },
            metadata_policy: ReceiveMetadataPolicy::RecordOnly,
            consent_source: ReceiveConsentSource::MailboxPolicy {
                policy_id: "auto-quarantine-mobile".to_string(),
            },
            rollback_resume: RollbackResumePolicy::RetainQuarantineForReview,
            trace_id: Some("e2e-mailbox-quarantine".to_string()),
            replay_pointer: Some("proof://mailbox-789".to_string()),
        };

        let plan = build_receive_plan(input).expect("build plan");

        // Verify mailbox policy accepts quarantine-only transfer
        assert_eq!(plan.decision, ReceiveDecision::QuarantineOnly);
        assert!(plan.rejected_reasons.is_empty());
        assert!(plan.quarantine.required);
        assert_eq!(plan.quarantine.path, temp.path().join(".mailbox-quarantine").join("pending"));

        // Verify mailbox consent is recorded
        assert_eq!(plan.consent_source, ReceiveConsentSource::MailboxPolicy {
            policy_id: "auto-quarantine-mobile".to_string(),
        });
    }

    // Helper functions for creating test object graphs

    fn create_safe_transfer_graph() -> (ObjectGraph, ObjectId) {
        let file = Object::file(b"Hello, world!".to_vec());
        let file_id = file.id.clone();
        let directory = Object::directory(vec![ObjectEdge::new(file_id, "hello.txt".to_string())]);
        let root = directory.id.clone();
        let mut graph = ObjectGraph::new();
        graph.add_object(file).expect("file object inserts");
        graph.add_root(directory).expect("directory root inserts");
        (graph, root)
    }

    fn create_malicious_traversal_graph() -> (ObjectGraph, ObjectId) {
        let file = Object::file(b"root:x:0:0:root:/root:/bin/bash".to_vec());
        let file_id = file.id.clone();
        let directory = Object::directory(vec![ObjectEdge::new(file_id, "passwd".to_string())]);
        let root = directory.id.clone();
        let mut graph = ObjectGraph::new();
        graph.add_object(file).expect("file object inserts");
        graph.add_root(directory).expect("directory root inserts");
        (graph, root)
    }

    fn create_executable_graph() -> (ObjectGraph, ObjectId) {
        use asupersync::atp::object::PlatformMetadata;

        let mut executable = Object::file(b"#!/bin/sh\necho hello".to_vec());
        executable.metadata.platform = PlatformMetadata {
            unix_mode: Some(0o100_755), // Regular file with execute permission
            ..PlatformMetadata::default()
        };
        let exec_id = executable.id.clone();
        let directory = Object::directory(vec![ObjectEdge::new(exec_id, "script.sh".to_string())]);
        let root = directory.id.clone();
        let mut graph = ObjectGraph::new();
        graph.add_object(executable).expect("executable object inserts");
        graph.add_root(directory).expect("directory root inserts");
        (graph, root)
    }

    fn create_large_transfer_graph() -> (ObjectGraph, ObjectId) {
        // Create a mock large file (1MB)
        let large_content = vec![0u8; 1_048_576];
        let file = Object::file(large_content);
        let file_id = file.id.clone();
        let directory = Object::directory(vec![ObjectEdge::new(file_id, "large.bin".to_string())]);
        let root = directory.id.clone();
        let mut graph = ObjectGraph::new();
        graph.add_object(file).expect("file object inserts");
        graph.add_root(directory).expect("directory root inserts");
        (graph, root)
    }
}