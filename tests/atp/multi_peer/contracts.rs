//! Multi-peer test contracts and validation
//!
//! Defines test contracts, schemas, and validation logic for ATP multi-peer scenarios.

use crate::atp::multi_peer::*;
use serde_json::Value;
use std::collections::HashSet;

/// Contract for multi-peer test execution
pub trait MultiPeerContract {
    /// Validate scenario before execution
    fn validate_scenario(&self, scenario: &MultiPeerScenario) -> Result<(), String>;

    /// Execute the scenario
    fn execute_scenario(&self, scenario: &MultiPeerScenario) -> Result<MultiPeerResult, String>;

    /// Validate execution results
    fn validate_result(&self, result: &MultiPeerResult) -> Result<(), String>;
}

/// Mailbox scenario contract
pub struct MailboxContract;

impl MultiPeerContract for MailboxContract {
    fn validate_scenario(&self, scenario: &MultiPeerScenario) -> Result<(), String> {
        // Basic scenario validation
        scenario.validate()?;

        // Mailbox-specific validation
        if !matches!(scenario.scenario_type, ScenarioType::Mailbox) {
            return Err("Expected mailbox scenario type".to_string());
        }

        let senders = scenario.peers_by_role(&PeerRole::Sender);
        let receivers = scenario.peers_by_role(&PeerRole::Receiver);
        let mailboxes = scenario.peers_by_role(&PeerRole::Mailbox);

        if senders.len() != 1 {
            return Err("Mailbox scenario requires exactly one sender".to_string());
        }

        if receivers.len() != 1 {
            return Err("Mailbox scenario requires exactly one receiver".to_string());
        }

        if mailboxes.is_empty() {
            return Err("Mailbox scenario requires at least one mailbox peer".to_string());
        }

        // Validate availability schedules for offline behavior
        let sender = &senders[0];
        let receiver = &receivers[0];

        if sender.availability.initially_online && receiver.availability.initially_online {
            // Both online initially - need to check if one goes offline
            let sender_goes_offline = sender
                .availability
                .schedule
                .iter()
                .any(|(_, online)| !online);
            let receiver_goes_offline = receiver
                .availability
                .schedule
                .iter()
                .any(|(_, online)| !online);

            if !sender_goes_offline && !receiver_goes_offline {
                return Err(
                    "Mailbox scenario should have offline behavior - both peers always online"
                        .to_string(),
                );
            }
        }

        Ok(())
    }

    fn execute_scenario(&self, _scenario: &MultiPeerScenario) -> Result<MultiPeerResult, String> {
        // Implementation placeholder - will be filled when ATP mailbox is implemented
        Err("Mailbox execution not yet implemented - waiting for ATP-J1".to_string())
    }

    fn validate_result(&self, result: &MultiPeerResult) -> Result<(), String> {
        // Validate mailbox-specific requirements
        if !matches!(result.scenario.scenario_type, ScenarioType::Mailbox) {
            return Err("Expected mailbox scenario result".to_string());
        }

        // Verify encryption requirement
        if result.scenario.transfer.encrypted {
            // Check that mailbox never saw plaintext
            let mailbox_peers: Vec<_> = result.scenario.peers_by_role(&PeerRole::Mailbox);
            for mailbox_peer in mailbox_peers {
                let peer_result = result.peer_results.get(&mailbox_peer.peer_id);
                if let Some(peer_result) = peer_result {
                    // Check log for any plaintext access (this would be implementation-specific)
                    // For now, we just verify the peer participated
                    if peer_result.bytes_received > 0 && peer_result.bytes_sent == 0 {
                        return Err(format!(
                            "Mailbox peer {} appears to have only received data without forwarding",
                            mailbox_peer.peer_id
                        ));
                    }
                }
            }
        }

        // Verify transfer completed successfully if expected
        if result.scenario.expectations.success {
            if !result.success {
                return Err(format!(
                    "Expected successful transfer but got: {:?}",
                    result.error
                ));
            }

            if let Some(expected_bytes) = result.scenario.expectations.bytes_transferred {
                if result.transfer_metrics.verified_bytes != expected_bytes {
                    return Err(format!(
                        "Expected {} verified bytes but got {}",
                        expected_bytes, result.transfer_metrics.verified_bytes
                    ));
                }
            }
        }

        Ok(())
    }
}

/// Swarm scenario contract
pub struct SwarmContract;

impl MultiPeerContract for SwarmContract {
    fn validate_scenario(&self, scenario: &MultiPeerScenario) -> Result<(), String> {
        scenario.validate()?;

        if !matches!(scenario.scenario_type, ScenarioType::Swarm) {
            return Err("Expected swarm scenario type".to_string());
        }

        let receivers = scenario.peers_by_role(&PeerRole::Receiver);
        let seeds = scenario.peers_by_role(&PeerRole::Seed);

        if receivers.len() != 1 {
            return Err("Swarm scenario requires exactly one receiver".to_string());
        }

        if seeds.len() < 2 {
            return Err(
                "Swarm scenario requires at least 2 seed peers for multi-source transfer"
                    .to_string(),
            );
        }

        // Validate repair configuration for multi-source
        if let Some(repair_config) = &scenario.transfer.repair_config {
            if repair_config.n < repair_config.k {
                return Err("Invalid repair config: n must be >= k".to_string());
            }
        }

        Ok(())
    }

    fn execute_scenario(&self, _scenario: &MultiPeerScenario) -> Result<MultiPeerResult, String> {
        // Implementation placeholder - will be filled when ATP swarm is implemented
        Err("Swarm execution not yet implemented - waiting for ATP-J2".to_string())
    }

    fn validate_result(&self, result: &MultiPeerResult) -> Result<(), String> {
        if !matches!(result.scenario.scenario_type, ScenarioType::Swarm) {
            return Err("Expected swarm scenario result".to_string());
        }

        // Verify multi-source behavior
        let seeds = result.scenario.peers_by_role(&PeerRole::Seed);
        if seeds.len() >= 2 {
            // Check that receiver connected to multiple sources
            let receiver = result.scenario.peers_by_role(&PeerRole::Receiver);
            if let Some(receiver_peer) = receiver.first() {
                if let Some(receiver_result) = result.peer_results.get(&receiver_peer.peer_id) {
                    let unique_sources: HashSet<_> = receiver_result
                        .connections
                        .iter()
                        .filter(|conn| conn.event_type == "connect")
                        .map(|conn| &conn.remote_peer)
                        .collect();

                    if unique_sources.len() < 2 {
                        return Err("Swarm transfer should connect to multiple sources".to_string());
                    }
                }
            }
        }

        // Verify verification of chunks from different peers
        if result.transfer_metrics.peer_rejections > 0 {
            // Check that malicious peers were properly rejected
            let malicious_peers = result.scenario.peers_by_role(&PeerRole::Malicious);
            if malicious_peers.is_empty() {
                return Err(
                    "Peer rejections occurred but no malicious peers configured".to_string()
                );
            }
        }

        Ok(())
    }
}

/// Cache scenario contract
pub struct CacheContract;

impl MultiPeerContract for CacheContract {
    fn validate_scenario(&self, scenario: &MultiPeerScenario) -> Result<(), String> {
        scenario.validate()?;

        if !matches!(scenario.scenario_type, ScenarioType::Cache) {
            return Err("Expected cache scenario type".to_string());
        }

        // Verify at least one peer has cache enabled
        let cache_enabled = scenario
            .peers
            .iter()
            .any(|peer| peer.capabilities.cache_enabled);

        if !cache_enabled {
            return Err("Cache scenario requires at least one peer with cache enabled".to_string());
        }

        for peer in &scenario.peers {
            if peer.capabilities.cache_enabled {
                let Some(quota) = peer.capabilities.storage_quota else {
                    return Err(format!(
                        "Cache-enabled peer {} must declare a storage quota",
                        peer.peer_id
                    ));
                };

                if quota == 0 {
                    return Err(format!(
                        "Cache-enabled peer {} must declare a nonzero storage quota",
                        peer.peer_id
                    ));
                }
            }

            if peer.capabilities.seeding_enabled && !peer.capabilities.cache_enabled {
                return Err(format!(
                    "Seeding peer {} must have cache enabled so served chunks are indexed by policy",
                    peer.peer_id
                ));
            }
        }

        let has_shared_cache_provider = scenario.peers.iter().any(|peer| {
            peer.capabilities.cache_enabled
                && (peer.capabilities.seeding_enabled || matches!(peer.role, PeerRole::Relay))
        });

        if has_shared_cache_provider
            && !scenario.transfer.encrypted
            && !has_explicit_public_cache_policy_marker(scenario)
        {
            return Err(
                "Shared cache providers require encrypted transfers until explicit public-data cache policy exists"
                    .to_string(),
            );
        }

        // Verify quota configurations for cache eviction tests
        if scenario.scenario_id.contains("eviction") {
            let has_quota = scenario
                .peers
                .iter()
                .any(|peer| peer.capabilities.storage_quota.is_some());

            if !has_quota {
                return Err(
                    "Cache eviction scenario requires storage quota configuration".to_string(),
                );
            }
        }

        Ok(())
    }

    fn execute_scenario(&self, _scenario: &MultiPeerScenario) -> Result<MultiPeerResult, String> {
        // Implementation placeholder - will be filled when ATP cache is implemented
        Err("Cache execution not yet implemented - waiting for ATP-J3".to_string())
    }

    fn validate_result(&self, result: &MultiPeerResult) -> Result<(), String> {
        if !matches!(result.scenario.scenario_type, ScenarioType::Cache) {
            return Err("Expected cache scenario result".to_string());
        }

        // Verify cache metrics were collected
        if result.cache_metrics.is_empty() {
            return Err("Cache scenario should produce cache metrics".to_string());
        }

        // Validate expected cache behavior
        if let Some(expected_cache) = &result.scenario.expectations.cache_metrics {
            for actual_metrics in result.cache_metrics.values() {
                if let Some(expected_hits) = expected_cache.hits {
                    if actual_metrics.hits.unwrap_or(0) != expected_hits {
                        return Err(format!(
                            "Expected {} cache hits but got {:?}",
                            expected_hits, actual_metrics.hits
                        ));
                    }
                }
            }
        }

        validate_cache_corruption_failures(result)?;
        validate_expired_cache_grant_failures(result)?;

        Ok(())
    }
}

fn validate_cache_corruption_failures(result: &MultiPeerResult) -> Result<(), String> {
    for failure in result
        .verification_results
        .failures
        .iter()
        .filter(|failure| failure.verification_type == "cache_integrity")
    {
        if result.success {
            return Err(
                "Cache corruption failure must not produce a successful cache result".to_string(),
            );
        }

        for field in [
            "cache_key",
            "manifest_root",
            "stored_digest",
            "exposure_decision",
        ] {
            let Some(value) = failure.context.get(field) else {
                return Err(format!(
                    "Cache corruption failure must include `{field}` context"
                ));
            };
            if value.trim().is_empty() {
                return Err(format!(
                    "Cache corruption failure context `{field}` must not be empty"
                ));
            }
        }

        if failure
            .context
            .get("exposure_decision")
            .is_none_or(|decision| decision != "quarantined")
        {
            return Err(
                "Cache corruption failure must mark exposure_decision=quarantined".to_string(),
            );
        }
    }

    Ok(())
}

fn validate_expired_cache_grant_failures(result: &MultiPeerResult) -> Result<(), String> {
    for failure in result
        .verification_results
        .failures
        .iter()
        .filter(|failure| failure.verification_type == "cache_grant_expired")
    {
        if result.success {
            return Err(
                "Expired cache grant failure must not produce a successful cache result"
                    .to_string(),
            );
        }

        if result.transfer_metrics.verified_bytes != 0 {
            return Err(
                "Expired cache grant failure must not expose verified cache bytes".to_string(),
            );
        }

        for field in [
            "grant_id",
            "peer_id",
            "cache_key",
            "manifest_root",
            "grant_state",
            "grant_expires_at_epoch_secs",
            "checked_at_epoch_secs",
            "exposure_decision",
        ] {
            require_failure_context(failure, field)?;
        }

        if failure
            .context
            .get("grant_state")
            .is_none_or(|state| state != "expired")
        {
            return Err("Expired cache grant failure must mark grant_state=expired".to_string());
        }

        if failure
            .context
            .get("exposure_decision")
            .is_none_or(|decision| decision != "denied")
        {
            return Err(
                "Expired cache grant failure must mark exposure_decision=denied".to_string(),
            );
        }

        let expires_at = parse_u64_failure_context(failure, "grant_expires_at_epoch_secs")?;
        let checked_at = parse_u64_failure_context(failure, "checked_at_epoch_secs")?;
        if checked_at <= expires_at {
            return Err(
                "Expired cache grant failure checked_at_epoch_secs must be after grant expiry"
                    .to_string(),
            );
        }
    }

    Ok(())
}

fn require_failure_context(failure: &VerificationFailure, field: &str) -> Result<(), String> {
    let Some(value) = failure.context.get(field) else {
        return Err(format!(
            "{} failure must include `{field}` context",
            failure.verification_type
        ));
    };
    if value.trim().is_empty() {
        return Err(format!(
            "{} failure context `{field}` must not be empty",
            failure.verification_type
        ));
    }
    Ok(())
}

fn parse_u64_failure_context(failure: &VerificationFailure, field: &str) -> Result<u64, String> {
    failure
        .context
        .get(field)
        .expect("required context checked before parsing")
        .parse::<u64>()
        .map_err(|_| {
            format!(
                "{} failure context `{field}` must be an unsigned integer",
                failure.verification_type
            )
        })
}

fn has_explicit_public_cache_policy_marker(scenario: &MultiPeerScenario) -> bool {
    scenario.expectations.log_events.iter().any(|event| {
        matches!(
            event.event_type.as_str(),
            "cache_store" | "relay_cache_store"
        ) && event
            .required_fields
            .iter()
            .any(|field| field == "storage_class")
            && event
                .required_fields
                .iter()
                .any(|field| field == "public_policy_id")
    })
}

/// Adversarial scenario contract
pub struct AdversarialContract;

impl MultiPeerContract for AdversarialContract {
    fn validate_scenario(&self, scenario: &MultiPeerScenario) -> Result<(), String> {
        scenario.validate()?;

        if !matches!(scenario.scenario_type, ScenarioType::Adversarial) {
            return Err("Expected adversarial scenario type".to_string());
        }

        // Verify at least one malicious peer
        let malicious_peers = scenario.peers_by_role(&PeerRole::Malicious);
        if malicious_peers.is_empty() {
            return Err("Adversarial scenario requires at least one malicious peer".to_string());
        }

        // Verify honest peers exist
        let honest_peer_count = scenario
            .peers
            .iter()
            .filter(|peer| !matches!(peer.role, PeerRole::Malicious))
            .count();

        if honest_peer_count < 2 {
            return Err("Adversarial scenario requires at least 2 honest peers".to_string());
        }

        Ok(())
    }

    fn execute_scenario(&self, _scenario: &MultiPeerScenario) -> Result<MultiPeerResult, String> {
        // Implementation placeholder
        Err("Adversarial execution not yet implemented".to_string())
    }

    fn validate_result(&self, result: &MultiPeerResult) -> Result<(), String> {
        if !matches!(result.scenario.scenario_type, ScenarioType::Adversarial) {
            return Err("Expected adversarial scenario result".to_string());
        }

        // Verify malicious peers were detected and rejected
        if result.transfer_metrics.peer_rejections == 0 {
            return Err("Adversarial scenario should result in peer rejections".to_string());
        }

        // Verify transfer still succeeded despite malicious peers (if expected)
        if result.scenario.expectations.success && !result.success {
            return Err("Expected transfer to succeed despite malicious peers".to_string());
        }

        // Verify source selection decisions include rejection reasons
        for selection in &result.transfer_metrics.source_selections {
            if !selection.rejected_peers.is_empty() {
                // Check that rejection reasons are provided
                for reason in selection.rejected_peers.values() {
                    if reason.is_empty() {
                        return Err("Peer rejection must include reason".to_string());
                    }
                }
            }
        }

        Ok(())
    }
}

/// Schema validation for multi-peer test artifacts
pub struct SchemaValidator;

impl SchemaValidator {
    /// Validate multi-peer result schema
    pub fn validate_result_schema(result_json: &str) -> Result<MultiPeerResult, String> {
        let parsed: Value =
            serde_json::from_str(result_json).map_err(|e| format!("Invalid JSON: {}", e))?;

        // Check required top-level fields
        let required_fields = [
            "schema_version",
            "scenario",
            "executed_at",
            "success",
            "duration",
            "peer_results",
            "transfer_metrics",
            "artifacts",
        ];

        for field in &required_fields {
            if parsed.get(field).is_none() {
                return Err(format!("Missing required field: {}", field));
            }
        }

        // Verify schema version
        if let Some(version) = parsed.get("schema_version").and_then(|v| v.as_str()) {
            if version != MULTI_PEER_REPORT_SCHEMA {
                return Err(format!(
                    "Unsupported schema version: {} (expected {})",
                    version, MULTI_PEER_REPORT_SCHEMA
                ));
            }
        }

        // Deserialize to struct for full validation
        serde_json::from_str(result_json).map_err(|e| format!("Schema validation failed: {}", e))
    }

    /// Validate event schema
    pub fn validate_event_schema(event_json: &str) -> Result<NetworkEvent, String> {
        let parsed: Value =
            serde_json::from_str(event_json).map_err(|e| format!("Invalid JSON: {}", e))?;

        // Check required fields
        let required_fields = ["timestamp", "event_type", "peers"];
        for field in &required_fields {
            if parsed.get(field).is_none() {
                return Err(format!("Missing required field: {}", field));
            }
        }

        serde_json::from_str(event_json)
            .map_err(|e| format!("Event schema validation failed: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::time::SystemTime;

    #[test]
    fn test_mailbox_contract_validation() {
        let mut scenario = MultiPeerScenario::default();
        scenario.scenario_type = ScenarioType::Mailbox;

        // Empty peers should fail
        let contract = MailboxContract;
        assert!(contract.validate_scenario(&scenario).is_err());

        // Add required peers
        scenario.peers = vec![
            PeerConfig {
                peer_id: "sender".to_string(),
                role: PeerRole::Sender,
                availability: AvailabilitySchedule {
                    initially_online: true,
                    schedule: vec![(Duration::from_secs(10), false)], // Goes offline
                },
                capabilities: PeerCapabilities {
                    storage_quota: None,
                    bandwidth_limit: None,
                    cache_enabled: false,
                    seeding_enabled: false,
                    relay_enabled: false,
                },
                work_dir: None,
            },
            PeerConfig {
                peer_id: "receiver".to_string(),
                role: PeerRole::Receiver,
                availability: AvailabilitySchedule {
                    initially_online: false,
                    schedule: vec![(Duration::from_secs(60), true)], // Comes online later
                },
                capabilities: PeerCapabilities {
                    storage_quota: None,
                    bandwidth_limit: None,
                    cache_enabled: false,
                    seeding_enabled: false,
                    relay_enabled: false,
                },
                work_dir: None,
            },
            PeerConfig {
                peer_id: "mailbox".to_string(),
                role: PeerRole::Mailbox,
                availability: AvailabilitySchedule {
                    initially_online: true,
                    schedule: vec![], // Always online
                },
                capabilities: PeerCapabilities {
                    storage_quota: Some(100 * 1024 * 1024), // 100MB quota
                    bandwidth_limit: None,
                    cache_enabled: true,
                    seeding_enabled: false,
                    relay_enabled: true,
                },
                work_dir: None,
            },
        ];

        // Should now pass validation
        assert!(contract.validate_scenario(&scenario).is_ok());
    }

    #[test]
    fn test_swarm_contract_validation() {
        let mut scenario = MultiPeerScenario::default();
        scenario.scenario_type = ScenarioType::Swarm;

        // Add receiver and multiple seeds
        scenario.peers = vec![
            PeerConfig {
                peer_id: "receiver".to_string(),
                role: PeerRole::Receiver,
                availability: AvailabilitySchedule {
                    initially_online: true,
                    schedule: vec![],
                },
                capabilities: PeerCapabilities {
                    storage_quota: None,
                    bandwidth_limit: None,
                    cache_enabled: false,
                    seeding_enabled: false,
                    relay_enabled: false,
                },
                work_dir: None,
            },
            PeerConfig {
                peer_id: "seed1".to_string(),
                role: PeerRole::Seed,
                availability: AvailabilitySchedule {
                    initially_online: true,
                    schedule: vec![],
                },
                capabilities: PeerCapabilities {
                    storage_quota: None,
                    bandwidth_limit: None,
                    cache_enabled: true,
                    seeding_enabled: true,
                    relay_enabled: false,
                },
                work_dir: None,
            },
            PeerConfig {
                peer_id: "seed2".to_string(),
                role: PeerRole::Seed,
                availability: AvailabilitySchedule {
                    initially_online: true,
                    schedule: vec![],
                },
                capabilities: PeerCapabilities {
                    storage_quota: None,
                    bandwidth_limit: None,
                    cache_enabled: true,
                    seeding_enabled: true,
                    relay_enabled: false,
                },
                work_dir: None,
            },
        ];

        let contract = SwarmContract;
        assert!(contract.validate_scenario(&scenario).is_ok());
    }

    #[test]
    fn test_schema_validation() {
        let result = MultiPeerResult {
            schema_version: MULTI_PEER_REPORT_SCHEMA.to_string(),
            scenario: MultiPeerScenario::default(),
            executed_at: SystemTime::now(),
            success: true,
            error: None,
            duration: Duration::from_secs(30),
            peer_results: std::collections::HashMap::new(),
            network_events: Vec::new(),
            transfer_metrics: TransferMetrics {
                total_bytes: 1024,
                verified_bytes: 1024,
                chunks_transferred: 16,
                repair_blocks_used: 0,
                peer_rejections: 0,
                source_selections: Vec::new(),
            },
            cache_metrics: std::collections::HashMap::new(),
            verification_results: VerificationResults {
                crypto_verified: true,
                manifest_verified: true,
                proof_verified: true,
                failures: Vec::new(),
            },
            artifacts: ArtifactPaths {
                report: "/tmp/report.json".into(),
                logs: "/tmp/logs".into(),
                traces: Vec::new(),
                sources: Vec::new(),
                destinations: Vec::new(),
            },
        };

        let json = serde_json::to_string(&result).unwrap();
        let validated = SchemaValidator::validate_result_schema(&json);
        assert!(validated.is_ok());
    }

    fn cache_result_with_integrity_failure(
        success: bool,
        failure_context: HashMap<String, String>,
    ) -> MultiPeerResult {
        let mut scenario = MultiPeerScenario::default();
        scenario.scenario_type = ScenarioType::Cache;

        MultiPeerResult {
            schema_version: MULTI_PEER_REPORT_SCHEMA.to_string(),
            scenario,
            executed_at: SystemTime::now(),
            success,
            error: (!success).then(|| "cache integrity failure".to_string()),
            duration: Duration::from_secs(30),
            peer_results: HashMap::new(),
            network_events: Vec::new(),
            transfer_metrics: TransferMetrics {
                total_bytes: 1024,
                verified_bytes: 0,
                chunks_transferred: 1,
                repair_blocks_used: 0,
                peer_rejections: 0,
                source_selections: Vec::new(),
            },
            cache_metrics: std::iter::once((
                "relay-cache".to_string(),
                CacheMetrics {
                    hits: Some(0),
                    misses: Some(1),
                    evictions: Some(0),
                },
            ))
            .collect(),
            verification_results: VerificationResults {
                crypto_verified: false,
                manifest_verified: true,
                proof_verified: true,
                failures: vec![VerificationFailure {
                    verification_type: "cache_integrity".to_string(),
                    reason: "stored digest did not match manifest root".to_string(),
                    context: failure_context,
                }],
            },
            artifacts: ArtifactPaths {
                report: "/tmp/report.json".into(),
                logs: "/tmp/logs".into(),
                traces: Vec::new(),
                sources: Vec::new(),
                destinations: Vec::new(),
            },
        }
    }

    fn cache_corruption_context() -> HashMap<String, String> {
        [
            ("cache_key", "cache:manifest-7"),
            ("manifest_root", "sha256:070707070707"),
            ("stored_digest", "sha256:abababababab"),
            ("exposure_decision", "quarantined"),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
    }

    #[test]
    fn cache_corruption_result_requires_quarantine_context() {
        let contract = CacheContract;
        let clean_failure = cache_result_with_integrity_failure(false, cache_corruption_context());
        contract
            .validate_result(&clean_failure)
            .expect("cache corruption failure with quarantine context should validate");

        let mut missing_context = cache_corruption_context();
        missing_context.remove("stored_digest");
        let missing_context_result = cache_result_with_integrity_failure(false, missing_context);
        let error = contract
            .validate_result(&missing_context_result)
            .expect_err("cache corruption failure must include stored digest context");
        assert!(
            error.contains("stored_digest"),
            "unexpected validation error: {error}"
        );

        let successful_corruption =
            cache_result_with_integrity_failure(true, cache_corruption_context());
        let error = contract
            .validate_result(&successful_corruption)
            .expect_err("cache corruption failure must fail closed");
        assert!(
            error.contains("successful cache result"),
            "unexpected validation error: {error}"
        );
    }

    fn cache_result_with_expired_grant_failure(
        success: bool,
        verified_bytes: u64,
        failure_context: HashMap<String, String>,
    ) -> MultiPeerResult {
        let mut scenario = MultiPeerScenario::default();
        scenario.scenario_type = ScenarioType::Cache;

        MultiPeerResult {
            schema_version: MULTI_PEER_REPORT_SCHEMA.to_string(),
            scenario,
            executed_at: SystemTime::now(),
            success,
            error: (!success).then(|| "cache grant expired".to_string()),
            duration: Duration::from_secs(5),
            peer_results: HashMap::new(),
            network_events: Vec::new(),
            transfer_metrics: TransferMetrics {
                total_bytes: 4096,
                verified_bytes,
                chunks_transferred: 0,
                repair_blocks_used: 0,
                peer_rejections: 1,
                source_selections: Vec::new(),
            },
            cache_metrics: std::iter::once((
                "seed-cache".to_string(),
                CacheMetrics {
                    hits: Some(0),
                    misses: Some(0),
                    evictions: Some(0),
                },
            ))
            .collect(),
            verification_results: VerificationResults {
                crypto_verified: false,
                manifest_verified: true,
                proof_verified: true,
                failures: vec![VerificationFailure {
                    verification_type: "cache_grant_expired".to_string(),
                    reason: "cache grant expired before seed exposure".to_string(),
                    context: failure_context,
                }],
            },
            artifacts: ArtifactPaths {
                report: "/tmp/report.json".into(),
                logs: "/tmp/logs".into(),
                traces: Vec::new(),
                sources: Vec::new(),
                destinations: Vec::new(),
            },
        }
    }

    fn expired_grant_context() -> HashMap<String, String> {
        [
            ("grant_id", "grant-cache-seed-7"),
            ("peer_id", "seed-cache"),
            ("cache_key", "cache:manifest-7"),
            ("manifest_root", "sha256:070707070707"),
            ("grant_state", "expired"),
            ("grant_expires_at_epoch_secs", "1700000100"),
            ("checked_at_epoch_secs", "1700000200"),
            ("exposure_decision", "denied"),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
    }

    #[test]
    fn expired_cache_grant_result_requires_fail_closed_context() {
        let contract = CacheContract;
        let denied_failure =
            cache_result_with_expired_grant_failure(false, 0, expired_grant_context());
        contract
            .validate_result(&denied_failure)
            .expect("expired cache grant with deny context should validate");

        let mut stale_timing = expired_grant_context();
        stale_timing.insert(
            "checked_at_epoch_secs".to_string(),
            "1700000100".to_string(),
        );
        let stale_timing_result = cache_result_with_expired_grant_failure(false, 0, stale_timing);
        let error = contract
            .validate_result(&stale_timing_result)
            .expect_err("expired grant evidence must be checked after expiry");
        assert!(
            error.contains("checked_at_epoch_secs"),
            "unexpected validation error: {error}"
        );

        let successful_expired_grant =
            cache_result_with_expired_grant_failure(true, 0, expired_grant_context());
        let error = contract
            .validate_result(&successful_expired_grant)
            .expect_err("expired grant failure must fail closed");
        assert!(
            error.contains("successful cache result"),
            "unexpected validation error: {error}"
        );

        let exposed_bytes =
            cache_result_with_expired_grant_failure(false, 256, expired_grant_context());
        let error = contract
            .validate_result(&exposed_bytes)
            .expect_err("expired grant failure must not expose bytes");
        assert!(
            error.contains("verified cache bytes"),
            "unexpected validation error: {error}"
        );
    }
}
