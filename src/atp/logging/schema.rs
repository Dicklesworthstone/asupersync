//! ATP Event Schema Definitions
//!
//! Defines event types for each ATP subsystem to ensure consistent logging.

/// Path subsystem event types
pub fn path_event_types() -> Vec<String> {
    vec![
        "discovery_started".to_string(),
        "discovery_completed".to_string(),
        "candidate_found".to_string(),
        "candidate_validated".to_string(),
        "candidate_failed".to_string(),
        "path_selected".to_string(),
        "path_migration_started".to_string(),
        "path_migration_completed".to_string(),
        "nat_classification".to_string(),
        "relay_connection_established".to_string(),
        "tailscale_candidate_discovered".to_string(),
        "stun_binding_request".to_string(),
        "stun_binding_response".to_string(),
        "ice_gathering_started".to_string(),
        "ice_gathering_completed".to_string(),
    ]
}

/// QUIC subsystem event types
pub fn quic_event_types() -> Vec<String> {
    vec![
        "connection_initiated".to_string(),
        "connection_established".to_string(),
        "connection_closed".to_string(),
        "handshake_started".to_string(),
        "handshake_completed".to_string(),
        "version_negotiation".to_string(),
        "retry_packet_sent".to_string(),
        "packet_sent".to_string(),
        "packet_received".to_string(),
        "packet_dropped".to_string(),
        "ack_received".to_string(),
        "loss_detected".to_string(),
        "pto_fired".to_string(),
        "congestion_control_update".to_string(),
        "stream_created".to_string(),
        "stream_data_sent".to_string(),
        "stream_data_received".to_string(),
        "stream_reset".to_string(),
        "flow_control_blocked".to_string(),
        "key_update".to_string(),
    ]
}

/// Transfer subsystem event types
pub fn transfer_event_types() -> Vec<String> {
    vec![
        "transfer_requested".to_string(),
        "transfer_started".to_string(),
        "transfer_progress".to_string(),
        "transfer_completed".to_string(),
        "transfer_failed".to_string(),
        "transfer_cancelled".to_string(),
        "chunk_scheduled".to_string(),
        "chunk_transmitted".to_string(),
        "chunk_received".to_string(),
        "chunk_verified".to_string(),
        "object_manifest_created".to_string(),
        "object_verification_started".to_string(),
        "object_verification_completed".to_string(),
        "bandwidth_measurement".to_string(),
        "preflight_check".to_string(),
    ]
}

/// Scheduler subsystem event types
pub fn scheduler_event_types() -> Vec<String> {
    vec![
        "job_queued".to_string(),
        "job_started".to_string(),
        "job_completed".to_string(),
        "job_failed".to_string(),
        "job_cancelled".to_string(),
        "priority_adjusted".to_string(),
        "resource_allocated".to_string(),
        "resource_released".to_string(),
        "deadline_missed".to_string(),
        "scheduling_decision".to_string(),
        "load_balancing_update".to_string(),
        "worker_pool_resize".to_string(),
        "task_timeout".to_string(),
        "backpressure_detected".to_string(),
    ]
}

/// Repair subsystem event types
pub fn repair_event_types() -> Vec<String> {
    vec![
        "repair_needed".to_string(),
        "repair_started".to_string(),
        "repair_completed".to_string(),
        "repair_failed".to_string(),
        "repair_chunk_requested".to_string(),
        "repair_chunk_received".to_string(),
        "raptorq_decode_started".to_string(),
        "raptorq_decode_completed".to_string(),
        "raptorq_encode_started".to_string(),
        "raptorq_encode_completed".to_string(),
        "repair_roi_calculated".to_string(),
        "repair_policy_applied".to_string(),
        "repair_strategy_selected".to_string(),
        "redundancy_level_adjusted".to_string(),
    ]
}

/// Disk subsystem event types
pub fn disk_event_types() -> Vec<String> {
    vec![
        "file_read_started".to_string(),
        "file_read_completed".to_string(),
        "file_write_started".to_string(),
        "file_write_completed".to_string(),
        "disk_space_check".to_string(),
        "disk_usage_warning".to_string(),
        "file_integrity_check".to_string(),
        "file_corruption_detected".to_string(),
        "cache_hit".to_string(),
        "cache_miss".to_string(),
        "cache_eviction".to_string(),
        "sync_operation".to_string(),
        "disk_io_error".to_string(),
        "permission_check".to_string(),
    ]
}

/// Journal subsystem event types
pub fn journal_event_types() -> Vec<String> {
    vec![
        "entry_written".to_string(),
        "entry_read".to_string(),
        "checkpoint_created".to_string(),
        "checkpoint_restored".to_string(),
        "replay_started".to_string(),
        "replay_completed".to_string(),
        "journal_compaction".to_string(),
        "journal_corruption_detected".to_string(),
        "recovery_started".to_string(),
        "recovery_completed".to_string(),
        "transaction_committed".to_string(),
        "transaction_rolled_back".to_string(),
    ]
}

/// Verifier subsystem event types
pub fn verifier_event_types() -> Vec<String> {
    vec![
        "verification_started".to_string(),
        "verification_completed".to_string(),
        "verification_failed".to_string(),
        "hash_computed".to_string(),
        "hash_verified".to_string(),
        "signature_verified".to_string(),
        "certificate_validated".to_string(),
        "proof_generated".to_string(),
        "proof_verified".to_string(),
        "integrity_check_passed".to_string(),
        "integrity_check_failed".to_string(),
        "merkle_tree_built".to_string(),
        "merkle_proof_verified".to_string(),
    ]
}

/// Daemon subsystem event types
pub fn daemon_event_types() -> Vec<String> {
    vec![
        "daemon_started".to_string(),
        "daemon_stopped".to_string(),
        "daemon_restarted".to_string(),
        "config_loaded".to_string(),
        "config_reloaded".to_string(),
        "service_registered".to_string(),
        "service_deregistered".to_string(),
        "health_check_passed".to_string(),
        "health_check_failed".to_string(),
        "resource_monitoring".to_string(),
        "cleanup_started".to_string(),
        "cleanup_completed".to_string(),
        "signal_received".to_string(),
    ]
}

/// CLI subsystem event types
pub fn cli_event_types() -> Vec<String> {
    vec![
        "command_started".to_string(),
        "command_completed".to_string(),
        "command_failed".to_string(),
        "argument_parsed".to_string(),
        "config_validation".to_string(),
        "progress_update".to_string(),
        "user_confirmation_requested".to_string(),
        "user_confirmation_received".to_string(),
        "output_formatted".to_string(),
        "error_displayed".to_string(),
        "help_displayed".to_string(),
        "version_displayed".to_string(),
    ]
}

/// Relay subsystem event types
pub fn relay_event_types() -> Vec<String> {
    vec![
        "relay_connected".to_string(),
        "relay_disconnected".to_string(),
        "relay_message_sent".to_string(),
        "relay_message_received".to_string(),
        "relay_quota_check".to_string(),
        "relay_quota_exceeded".to_string(),
        "relay_authentication".to_string(),
        "relay_authorization".to_string(),
        "relay_load_balancing".to_string(),
        "relay_health_check".to_string(),
        "relay_bandwidth_measurement".to_string(),
        "relay_cost_calculation".to_string(),
    ]
}

/// Mailbox subsystem event types
pub fn mailbox_event_types() -> Vec<String> {
    vec![
        "message_stored".to_string(),
        "message_retrieved".to_string(),
        "message_deleted".to_string(),
        "message_expired".to_string(),
        "mailbox_created".to_string(),
        "mailbox_accessed".to_string(),
        "mailbox_quota_check".to_string(),
        "mailbox_cleanup".to_string(),
        "encryption_applied".to_string(),
        "decryption_performed".to_string(),
        "access_policy_enforced".to_string(),
        "notification_sent".to_string(),
    ]
}

/// Security subsystem event types
pub fn security_event_types() -> Vec<String> {
    vec![
        "authentication_started".to_string(),
        "authentication_succeeded".to_string(),
        "authentication_failed".to_string(),
        "authorization_check".to_string(),
        "permission_granted".to_string(),
        "permission_denied".to_string(),
        "capability_issued".to_string(),
        "capability_revoked".to_string(),
        "key_generated".to_string(),
        "key_rotated".to_string(),
        "certificate_issued".to_string(),
        "certificate_expired".to_string(),
        "security_policy_applied".to_string(),
        "threat_detected".to_string(),
        "quarantine_applied".to_string(),
        "audit_event".to_string(),
    ]
}

/// ATP test-lane event types shared by unit, lab, e2e, benchmark, and release
/// proof lanes.
pub fn test_lane_event_types() -> Vec<String> {
    vec![
        "test_started".to_string(),
        "test_completed".to_string(),
        "test_failed".to_string(),
        "seed_selected".to_string(),
        "fixture_loaded".to_string(),
        "oracle_checked".to_string(),
        "artifact_written".to_string(),
        "failure_bundle_created".to_string(),
        "replay_command_created".to_string(),
        "snapshot_compared".to_string(),
    ]
}
