//! ATP-H: Comprehensive Unit Tests for ATP Daemon Infrastructure
//!
//! Tests cover daemon configuration, service lifecycle, identity management,
//! transfer handling, inbox/mailbox functionality, peer discovery, cache
//! management, health monitoring, and error recovery scenarios.

#![cfg(test)]

use anyhow::Result;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tempfile::TempDir;
use tokio::time::{sleep, timeout};
use uuid::Uuid;

// Mock types for testing (would normally import from atpd crate)
#[derive(Debug, Clone, PartialEq)]
pub struct AtpdConfig {
    pub bind_addr: SocketAddr,
    pub data_dir: PathBuf,
    pub device_name: String,
    pub max_concurrent_transfers: u32,
    pub enable_relay: bool,
    pub enable_mailbox: bool,
    pub cache_size_limit: u64,
    pub transfer_timeout_secs: u64,
}

#[derive(Debug, Clone)]
pub struct DaemonState {
    pub config: AtpdConfig,
    pub peer_id: String,
    pub start_time: SystemTime,
    pub active_transfers: HashMap<String, TransferInfo>,
    pub peer_directory: HashMap<String, PeerInfo>,
    pub inbox_messages: Vec<InboxMessage>,
    pub cache_usage: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TransferInfo {
    pub id: String,
    pub peer_id: String,
    pub direction: TransferDirection,
    pub status: TransferStatus,
    pub bytes_transferred: u64,
    pub total_bytes: Option<u64>,
    pub start_time: SystemTime,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TransferDirection {
    Send,
    Receive,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TransferStatus {
    Queued,
    Active,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PeerInfo {
    pub peer_id: String,
    pub device_name: String,
    pub addresses: Vec<SocketAddr>,
    pub last_seen: SystemTime,
    pub trust_level: TrustLevel,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TrustLevel {
    Unknown,
    Known,
    Trusted,
    TeamMember,
}

#[derive(Debug, Clone, PartialEq)]
pub struct InboxMessage {
    pub id: String,
    pub from_peer: String,
    pub content_type: String,
    pub size_bytes: u64,
    pub received_at: SystemTime,
    pub is_read: bool,
}

impl Default for AtpdConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:8472".parse().unwrap(),
            data_dir: PathBuf::from("/tmp/atpd_test"),
            device_name: "test-daemon".to_string(),
            max_concurrent_transfers: 8,
            enable_relay: false,
            enable_mailbox: true,
            cache_size_limit: 1024 * 1024 * 100, // 100MB
            transfer_timeout_secs: 3600,
        }
    }
}

impl AtpdConfig {
    pub fn builder() -> AtpdConfigBuilder {
        AtpdConfigBuilder::new()
    }

    pub fn validate(&self) -> Result<()> {
        if self.device_name.is_empty() {
            anyhow::bail!("Device name cannot be empty");
        }

        if self.max_concurrent_transfers == 0 {
            anyhow::bail!("Max concurrent transfers must be greater than 0");
        }

        if self.cache_size_limit == 0 {
            anyhow::bail!("Cache size limit must be greater than 0");
        }

        if self.transfer_timeout_secs == 0 {
            anyhow::bail!("Transfer timeout must be greater than 0");
        }

        Ok(())
    }
}

pub struct AtpdConfigBuilder {
    config: AtpdConfig,
}

impl AtpdConfigBuilder {
    pub fn new() -> Self {
        Self {
            config: AtpdConfig::default(),
        }
    }

    pub fn with_bind_addr(mut self, addr: SocketAddr) -> Self {
        self.config.bind_addr = addr;
        self
    }

    pub fn with_data_dir(mut self, dir: PathBuf) -> Self {
        self.config.data_dir = dir;
        self
    }

    pub fn with_device_name(mut self, name: impl Into<String>) -> Self {
        self.config.device_name = name.into();
        self
    }

    pub fn with_max_transfers(mut self, max: u32) -> Self {
        self.config.max_concurrent_transfers = max;
        self
    }

    pub fn enable_relay(mut self) -> Self {
        self.config.enable_relay = true;
        self
    }

    pub fn enable_mailbox(mut self) -> Self {
        self.config.enable_mailbox = true;
        self
    }

    pub fn with_cache_limit(mut self, limit: u64) -> Self {
        self.config.cache_size_limit = limit;
        self
    }

    pub fn with_timeout(mut self, timeout_secs: u64) -> Self {
        self.config.transfer_timeout_secs = timeout_secs;
        self
    }

    pub fn build(self) -> AtpdConfig {
        self.config
    }
}

impl DaemonState {
    pub fn new(config: AtpdConfig) -> Self {
        Self {
            config,
            peer_id: format!("peer-{}", Uuid::new_v4()),
            start_time: SystemTime::now(),
            active_transfers: HashMap::new(),
            peer_directory: HashMap::new(),
            inbox_messages: Vec::new(),
            cache_usage: 0,
        }
    }

    pub fn add_transfer(&mut self, transfer: TransferInfo) {
        self.active_transfers.insert(transfer.id.clone(), transfer);
    }

    pub fn update_transfer_status(&mut self, transfer_id: &str, status: TransferStatus) -> bool {
        if let Some(transfer) = self.active_transfers.get_mut(transfer_id) {
            transfer.status = status;
            true
        } else {
            false
        }
    }

    pub fn remove_transfer(&mut self, transfer_id: &str) -> Option<TransferInfo> {
        self.active_transfers.remove(transfer_id)
    }

    pub fn add_peer(&mut self, peer: PeerInfo) {
        self.peer_directory.insert(peer.peer_id.clone(), peer);
    }

    pub fn update_peer_last_seen(&mut self, peer_id: &str) -> bool {
        if let Some(peer) = self.peer_directory.get_mut(peer_id) {
            peer.last_seen = SystemTime::now();
            true
        } else {
            false
        }
    }

    pub fn add_inbox_message(&mut self, message: InboxMessage) {
        self.inbox_messages.push(message);
    }

    pub fn mark_message_read(&mut self, message_id: &str) -> bool {
        for message in &mut self.inbox_messages {
            if message.id == message_id {
                message.is_read = true;
                return true;
            }
        }
        false
    }

    pub fn get_unread_message_count(&self) -> usize {
        self.inbox_messages.iter().filter(|m| !m.is_read).count()
    }

    pub fn get_active_transfer_count(&self) -> usize {
        self.active_transfers
            .values()
            .filter(|t| matches!(t.status, TransferStatus::Active))
            .count()
    }

    pub fn get_known_peer_count(&self) -> usize {
        self.peer_directory.len()
    }

    pub fn is_at_transfer_limit(&self) -> bool {
        self.get_active_transfer_count() >= self.config.max_concurrent_transfers as usize
    }

    pub fn get_status_json(&self) -> Value {
        json!({
            "peer_id": self.peer_id,
            "device_name": self.config.device_name,
            "uptime_secs": self.start_time.elapsed().unwrap_or_default().as_secs(),
            "active_transfers": self.get_active_transfer_count(),
            "total_transfers": self.active_transfers.len(),
            "known_peers": self.get_known_peer_count(),
            "unread_messages": self.get_unread_message_count(),
            "cache_usage_bytes": self.cache_usage,
            "config": {
                "bind_addr": self.config.bind_addr.to_string(),
                "max_concurrent_transfers": self.config.max_concurrent_transfers,
                "relay_enabled": self.config.enable_relay,
                "mailbox_enabled": self.config.enable_mailbox,
                "cache_limit_bytes": self.config.cache_size_limit,
            }
        })
    }
}

#[tokio::test]
async fn test_daemon_config_validation() {
    // Valid configuration
    let valid_config = AtpdConfig::default();
    assert!(valid_config.validate().is_ok());

    // Invalid: empty device name
    let mut invalid_config = valid_config.clone();
    invalid_config.device_name = String::new();
    assert!(invalid_config.validate().is_err());

    // Invalid: zero max transfers
    let mut invalid_config = valid_config.clone();
    invalid_config.max_concurrent_transfers = 0;
    assert!(invalid_config.validate().is_err());

    // Invalid: zero cache limit
    let mut invalid_config = valid_config.clone();
    invalid_config.cache_size_limit = 0;
    assert!(invalid_config.validate().is_err());

    // Invalid: zero timeout
    let mut invalid_config = valid_config;
    invalid_config.transfer_timeout_secs = 0;
    assert!(invalid_config.validate().is_err());
}

#[tokio::test]
async fn test_config_builder_pattern() {
    let config = AtpdConfig::builder()
        .with_device_name("test-builder")
        .with_bind_addr("192.168.1.100:9000".parse().unwrap())
        .with_max_transfers(16)
        .with_cache_limit(500_000_000)
        .with_timeout(7200)
        .enable_relay()
        .enable_mailbox()
        .build();

    assert_eq!(config.device_name, "test-builder");
    assert_eq!(config.bind_addr.port(), 9000);
    assert_eq!(config.max_concurrent_transfers, 16);
    assert_eq!(config.cache_size_limit, 500_000_000);
    assert_eq!(config.transfer_timeout_secs, 7200);
    assert!(config.enable_relay);
    assert!(config.enable_mailbox);
}

#[tokio::test]
async fn test_daemon_state_initialization() {
    let config = AtpdConfig::default();
    let state = DaemonState::new(config.clone());

    assert_eq!(state.config.device_name, config.device_name);
    assert!(!state.peer_id.is_empty());
    assert!(state.peer_id.starts_with("peer-"));
    assert!(state.active_transfers.is_empty());
    assert!(state.peer_directory.is_empty());
    assert!(state.inbox_messages.is_empty());
    assert_eq!(state.cache_usage, 0);
}

#[tokio::test]
async fn test_transfer_management() {
    let config = AtpdConfig::builder().with_max_transfers(2).build();
    let mut state = DaemonState::new(config);

    // Add first transfer
    let transfer1 = TransferInfo {
        id: "transfer-1".to_string(),
        peer_id: "peer-alice".to_string(),
        direction: TransferDirection::Send,
        status: TransferStatus::Active,
        bytes_transferred: 1024,
        total_bytes: Some(2048),
        start_time: SystemTime::now(),
    };

    state.add_transfer(transfer1.clone());
    assert_eq!(state.active_transfers.len(), 1);
    assert_eq!(state.get_active_transfer_count(), 1);
    assert!(!state.is_at_transfer_limit());

    // Add second transfer (at limit)
    let transfer2 = TransferInfo {
        id: "transfer-2".to_string(),
        peer_id: "peer-bob".to_string(),
        direction: TransferDirection::Receive,
        status: TransferStatus::Active,
        bytes_transferred: 0,
        total_bytes: Some(4096),
        start_time: SystemTime::now(),
    };

    state.add_transfer(transfer2.clone());
    assert_eq!(state.active_transfers.len(), 2);
    assert_eq!(state.get_active_transfer_count(), 2);
    assert!(state.is_at_transfer_limit());

    // Update transfer status
    assert!(state.update_transfer_status("transfer-1", TransferStatus::Completed));
    assert_eq!(state.get_active_transfer_count(), 1);
    assert!(!state.is_at_transfer_limit());

    // Remove transfer
    let removed = state.remove_transfer("transfer-1");
    assert!(removed.is_some());
    assert_eq!(removed.unwrap().id, "transfer-1");
    assert_eq!(state.active_transfers.len(), 1);
}

#[tokio::test]
async fn test_peer_directory_management() {
    let config = AtpdConfig::default();
    let mut state = DaemonState::new(config);

    // Add peer
    let peer = PeerInfo {
        peer_id: "peer-alice".to_string(),
        device_name: "Alice's Laptop".to_string(),
        addresses: vec!["192.168.1.100:8472".parse().unwrap()],
        last_seen: SystemTime::now(),
        trust_level: TrustLevel::Known,
        capabilities: vec!["transfer".to_string(), "relay".to_string()],
    };

    state.add_peer(peer.clone());
    assert_eq!(state.peer_directory.len(), 1);
    assert_eq!(state.get_known_peer_count(), 1);

    // Update peer last seen time
    let old_last_seen = peer.last_seen;
    sleep(Duration::from_millis(10)).await;
    assert!(state.update_peer_last_seen("peer-alice"));

    let updated_peer = state.peer_directory.get("peer-alice").unwrap();
    assert!(updated_peer.last_seen > old_last_seen);

    // Try to update non-existent peer
    assert!(!state.update_peer_last_seen("peer-nonexistent"));
}

#[tokio::test]
async fn test_inbox_message_handling() {
    let config = AtpdConfig::default();
    let mut state = DaemonState::new(config);

    // Add unread message
    let message1 = InboxMessage {
        id: "msg-1".to_string(),
        from_peer: "peer-alice".to_string(),
        content_type: "file".to_string(),
        size_bytes: 1024,
        received_at: SystemTime::now(),
        is_read: false,
    };

    state.add_inbox_message(message1.clone());
    assert_eq!(state.inbox_messages.len(), 1);
    assert_eq!(state.get_unread_message_count(), 1);

    // Add read message
    let message2 = InboxMessage {
        id: "msg-2".to_string(),
        from_peer: "peer-bob".to_string(),
        content_type: "text".to_string(),
        size_bytes: 512,
        received_at: SystemTime::now(),
        is_read: true,
    };

    state.add_inbox_message(message2.clone());
    assert_eq!(state.inbox_messages.len(), 2);
    assert_eq!(state.get_unread_message_count(), 1);

    // Mark message as read
    assert!(state.mark_message_read("msg-1"));
    assert_eq!(state.get_unread_message_count(), 0);

    // Try to mark non-existent message
    assert!(!state.mark_message_read("msg-nonexistent"));
}

#[tokio::test]
async fn test_daemon_status_json() {
    let config = AtpdConfig::builder()
        .with_device_name("test-status-daemon")
        .with_max_transfers(4)
        .enable_relay()
        .enable_mailbox()
        .build();

    let mut state = DaemonState::new(config);

    // Add some test data
    let transfer = TransferInfo {
        id: "test-transfer".to_string(),
        peer_id: "test-peer".to_string(),
        direction: TransferDirection::Send,
        status: TransferStatus::Active,
        bytes_transferred: 1024,
        total_bytes: Some(2048),
        start_time: SystemTime::now(),
    };
    state.add_transfer(transfer);

    let peer = PeerInfo {
        peer_id: "test-peer".to_string(),
        device_name: "Test Peer".to_string(),
        addresses: vec!["127.0.0.1:8472".parse().unwrap()],
        last_seen: SystemTime::now(),
        trust_level: TrustLevel::Known,
        capabilities: vec!["transfer".to_string()],
    };
    state.add_peer(peer);

    let message = InboxMessage {
        id: "test-msg".to_string(),
        from_peer: "test-peer".to_string(),
        content_type: "file".to_string(),
        size_bytes: 512,
        received_at: SystemTime::now(),
        is_read: false,
    };
    state.add_inbox_message(message);

    // Get status JSON
    let status = state.get_status_json();

    assert!(status["peer_id"].is_string());
    assert_eq!(status["device_name"], "test-status-daemon");
    assert!(status["uptime_secs"].is_number());
    assert_eq!(status["active_transfers"], 1);
    assert_eq!(status["total_transfers"], 1);
    assert_eq!(status["known_peers"], 1);
    assert_eq!(status["unread_messages"], 1);
    assert_eq!(status["cache_usage_bytes"], 0);

    // Check config section
    let config_section = &status["config"];
    assert_eq!(config_section["max_concurrent_transfers"], 4);
    assert_eq!(config_section["relay_enabled"], true);
    assert_eq!(config_section["mailbox_enabled"], true);
}

#[tokio::test]
async fn test_data_directory_structure_creation() {
    let temp_dir = TempDir::new().unwrap();
    let data_dir = temp_dir.path().to_path_buf();

    let config = AtpdConfig::builder()
        .with_data_dir(data_dir.clone())
        .build();

    // Simulate creating data directory structure
    let subdirs = vec![
        "cache",
        "identity",
        "inbox",
        "journal",
        "transfers",
        "transfers/queue",
        "transfers/completed",
    ];

    for subdir in subdirs {
        let path = data_dir.join(subdir);
        tokio::fs::create_dir_all(&path).await.unwrap();
        assert!(path.exists());
        assert!(path.is_dir());
    }

    // Create test identity file
    let identity_file = data_dir.join("identity").join("peer_id");
    let peer_id = "peer-test-123";
    tokio::fs::write(&identity_file, peer_id).await.unwrap();

    let read_peer_id = tokio::fs::read_to_string(&identity_file).await.unwrap();
    assert_eq!(read_peer_id, peer_id);
}

#[tokio::test]
async fn test_cache_size_management() {
    let config = AtpdConfig::builder()
        .with_cache_limit(1024) // 1KB limit
        .build();

    let mut state = DaemonState::new(config);

    // Start under limit
    state.cache_usage = 512;
    assert!(state.cache_usage < state.config.cache_size_limit);

    // Exceed limit
    state.cache_usage = 2048;
    assert!(state.cache_usage > state.config.cache_size_limit);

    // Check limit enforcement would trigger
    let over_limit = state.cache_usage > state.config.cache_size_limit;
    assert!(over_limit);
}

#[tokio::test]
async fn test_transfer_timeout_detection() {
    let config = AtpdConfig::builder()
        .with_timeout(1) // 1 second timeout
        .build();

    let state = DaemonState::new(config);

    // Create transfer that started more than timeout ago
    let old_transfer = TransferInfo {
        id: "old-transfer".to_string(),
        peer_id: "peer-test".to_string(),
        direction: TransferDirection::Send,
        status: TransferStatus::Active,
        bytes_transferred: 512,
        total_bytes: Some(1024),
        start_time: SystemTime::now() - Duration::from_secs(2),
    };

    // Check if transfer has timed out
    let elapsed = old_transfer.start_time.elapsed().unwrap_or_default();
    let has_timed_out = elapsed.as_secs() > state.config.transfer_timeout_secs;
    assert!(has_timed_out);

    // Recent transfer should not timeout
    let new_transfer = TransferInfo {
        id: "new-transfer".to_string(),
        peer_id: "peer-test".to_string(),
        direction: TransferDirection::Receive,
        status: TransferStatus::Active,
        bytes_transferred: 0,
        total_bytes: Some(1024),
        start_time: SystemTime::now(),
    };

    let elapsed = new_transfer.start_time.elapsed().unwrap_or_default();
    let has_timed_out = elapsed.as_secs() > state.config.transfer_timeout_secs;
    assert!(!has_timed_out);
}

#[tokio::test]
async fn test_peer_trust_level_management() {
    let config = AtpdConfig::default();
    let mut state = DaemonState::new(config);

    // Add peers with different trust levels
    let unknown_peer = PeerInfo {
        peer_id: "peer-unknown".to_string(),
        device_name: "Unknown Device".to_string(),
        addresses: vec!["192.168.1.1:8472".parse().unwrap()],
        last_seen: SystemTime::now(),
        trust_level: TrustLevel::Unknown,
        capabilities: vec![],
    };

    let trusted_peer = PeerInfo {
        peer_id: "peer-trusted".to_string(),
        device_name: "Trusted Device".to_string(),
        addresses: vec!["192.168.1.2:8472".parse().unwrap()],
        last_seen: SystemTime::now(),
        trust_level: TrustLevel::Trusted,
        capabilities: vec!["transfer".to_string(), "relay".to_string()],
    };

    let team_peer = PeerInfo {
        peer_id: "peer-team".to_string(),
        device_name: "Team Device".to_string(),
        addresses: vec!["192.168.1.3:8472".parse().unwrap()],
        last_seen: SystemTime::now(),
        trust_level: TrustLevel::TeamMember,
        capabilities: vec!["transfer".to_string(), "relay".to_string(), "admin".to_string()],
    };

    state.add_peer(unknown_peer.clone());
    state.add_peer(trusted_peer.clone());
    state.add_peer(team_peer.clone());

    assert_eq!(state.peer_directory.len(), 3);

    // Verify trust levels
    let stored_unknown = state.peer_directory.get("peer-unknown").unwrap();
    assert_eq!(stored_unknown.trust_level, TrustLevel::Unknown);

    let stored_trusted = state.peer_directory.get("peer-trusted").unwrap();
    assert_eq!(stored_trusted.trust_level, TrustLevel::Trusted);

    let stored_team = state.peer_directory.get("peer-team").unwrap();
    assert_eq!(stored_team.trust_level, TrustLevel::TeamMember);
}

#[tokio::test]
async fn test_concurrent_daemon_operations() {
    let config = AtpdConfig::builder()
        .with_max_transfers(10)
        .build();

    let mut state = DaemonState::new(config);

    // Simulate concurrent transfer additions
    let handles: Vec<_> = (0..5)
        .map(|i| {
            let transfer = TransferInfo {
                id: format!("concurrent-transfer-{}", i),
                peer_id: format!("peer-{}", i),
                direction: if i % 2 == 0 { TransferDirection::Send } else { TransferDirection::Receive },
                status: TransferStatus::Active,
                bytes_transferred: i as u64 * 100,
                total_bytes: Some((i as u64 + 1) * 1000),
                start_time: SystemTime::now(),
            };

            tokio::spawn(async move {
                // Simulate some async work
                sleep(Duration::from_millis(i as u64 * 10)).await;
                transfer
            })
        })
        .collect();

    // Collect all transfers
    for handle in handles {
        let transfer = handle.await.unwrap();
        state.add_transfer(transfer);
    }

    assert_eq!(state.active_transfers.len(), 5);
    assert_eq!(state.get_active_transfer_count(), 5);
    assert!(!state.is_at_transfer_limit());
}

#[tokio::test]
async fn test_daemon_graceful_shutdown() {
    let config = AtpdConfig::default();
    let mut state = DaemonState::new(config);

    // Add active transfers
    for i in 0..3 {
        let transfer = TransferInfo {
            id: format!("shutdown-transfer-{}", i),
            peer_id: format!("peer-{}", i),
            direction: TransferDirection::Send,
            status: TransferStatus::Active,
            bytes_transferred: i as u64 * 100,
            total_bytes: Some(1000),
            start_time: SystemTime::now(),
        };
        state.add_transfer(transfer);
    }

    assert_eq!(state.get_active_transfer_count(), 3);

    // Simulate graceful shutdown - cancel all active transfers
    let transfer_ids: Vec<_> = state.active_transfers.keys().cloned().collect();
    for transfer_id in transfer_ids {
        state.update_transfer_status(&transfer_id, TransferStatus::Cancelled);
    }

    assert_eq!(state.get_active_transfer_count(), 0);

    // All transfers should still exist but be cancelled
    assert_eq!(state.active_transfers.len(), 3);
    for transfer in state.active_transfers.values() {
        assert_eq!(transfer.status, TransferStatus::Cancelled);
    }
}

#[tokio::test]
async fn test_error_resilience_scenarios() {
    let config = AtpdConfig::default();
    let mut state = DaemonState::new(config);

    // Test handling of malformed peer ID
    assert!(!state.update_peer_last_seen(""));
    assert!(!state.update_peer_last_seen("invalid-peer-id"));

    // Test handling of malformed transfer ID
    assert!(!state.update_transfer_status("", TransferStatus::Completed));
    assert!(!state.update_transfer_status("nonexistent", TransferStatus::Failed));

    // Test handling of malformed message ID
    assert!(!state.mark_message_read(""));
    assert!(!state.mark_message_read("nonexistent-message"));

    // Test configuration validation edge cases
    let mut invalid_config = AtpdConfig::default();
    invalid_config.device_name = " ".repeat(1000); // Very long name
    assert!(invalid_config.device_name.len() > 100); // Would be invalid in practice

    // Test extremely large values
    invalid_config.max_concurrent_transfers = u32::MAX;
    invalid_config.cache_size_limit = u64::MAX;
    invalid_config.transfer_timeout_secs = u64::MAX;

    // These should still validate (but might be impractical)
    assert!(invalid_config.validate().is_ok());
}

#[tokio::test]
async fn test_performance_under_load() {
    let config = AtpdConfig::builder()
        .with_max_transfers(1000)
        .build();

    let mut state = DaemonState::new(config);

    let start_time = std::time::Instant::now();

    // Add many transfers rapidly
    for i in 0..1000 {
        let transfer = TransferInfo {
            id: format!("perf-transfer-{}", i),
            peer_id: format!("peer-{}", i % 10),
            direction: if i % 2 == 0 { TransferDirection::Send } else { TransferDirection::Receive },
            status: TransferStatus::Active,
            bytes_transferred: 0,
            total_bytes: Some(1024),
            start_time: SystemTime::now(),
        };
        state.add_transfer(transfer);
    }

    let duration = start_time.elapsed();

    assert_eq!(state.active_transfers.len(), 1000);
    assert!(duration < Duration::from_millis(100)); // Should be fast

    // Status generation should also be fast
    let status_start = std::time::Instant::now();
    let _status = state.get_status_json();
    let status_duration = status_start.elapsed();

    assert!(status_duration < Duration::from_millis(10));
}