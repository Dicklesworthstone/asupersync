//! Basic ATP Daemon Example
//!
//! Demonstrates how to set up and run an ATP daemon with basic configuration.

use anyhow::Result;
use asupersync::atp::identity::PeerId;
use asupersync::runtime::{RuntimeBuilder, RuntimeConfig};
use asupersync::supervision::{SupervisorConfig, SupervisorTree};
use asupersync::types::Time;
use serde_json::json;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{info, warn};

// Import atpd types (would normally be from a library crate)
// For now, we'll define simplified versions for the example

#[derive(Debug, Clone)]
pub struct SimpleAtpdConfig {
    pub bind_addr: SocketAddr,
    pub data_dir: PathBuf,
    pub device_name: String,
    pub max_concurrent_transfers: u32,
    pub enable_relay: bool,
    pub enable_mailbox: bool,
}

#[derive(Debug)]
pub struct SimpleAtpdService {
    config: SimpleAtpdConfig,
    start_time: Time,
    active_transfers: HashMap<String, TransferInfo>,
    peer_directory: HashMap<String, PeerInfo>,
}

#[derive(Debug, Clone)]
pub struct TransferInfo {
    pub id: String,
    pub peer: String,
    pub status: String,
    pub bytes_transferred: u64,
}

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub id: String,
    pub name: String,
    pub address: SocketAddr,
    pub last_seen: Time,
}

impl SimpleAtpdConfig {
    pub fn new() -> Self {
        Self {
            bind_addr: "127.0.0.1:8472".parse().unwrap(),
            data_dir: PathBuf::from("./atp_daemon_data"),
            device_name: "example-atp-node".to_string(),
            max_concurrent_transfers: 8,
            enable_relay: false,
            enable_mailbox: true,
        }
    }

    pub fn with_bind_addr(mut self, addr: SocketAddr) -> Self {
        self.bind_addr = addr;
        self
    }

    pub fn with_data_dir(mut self, dir: PathBuf) -> Self {
        self.data_dir = dir;
        self
    }

    pub fn with_device_name(mut self, name: impl Into<String>) -> Self {
        self.device_name = name.into();
        self
    }

    pub fn enable_relay(mut self) -> Self {
        self.enable_relay = true;
        self
    }

    pub fn enable_mailbox(mut self) -> Self {
        self.enable_mailbox = true;
        self
    }
}

impl SimpleAtpdService {
    pub fn new(config: SimpleAtpdConfig) -> Self {
        Self {
            config,
            start_time: Time::now(),
            active_transfers: HashMap::new(),
            peer_directory: HashMap::new(),
        }
    }

    pub async fn start(&mut self) -> Result<()> {
        info!("Starting ATP daemon service...");
        info!("Device name: {}", self.config.device_name);
        info!("Bind address: {}", self.config.bind_addr);
        info!("Data directory: {}", self.config.data_dir.display());
        info!(
            "Max concurrent transfers: {}",
            self.config.max_concurrent_transfers
        );
        info!("Relay enabled: {}", self.config.enable_relay);
        info!("Mailbox enabled: {}", self.config.enable_mailbox);

        // Create data directory structure
        self.create_data_directories().await?;

        // Initialize daemon services
        self.initialize_services().await?;

        // Start background tasks
        self.start_background_tasks().await?;

        info!("ATP daemon service started successfully");
        Ok(())
    }

    async fn create_data_directories(&self) -> Result<()> {
        let data_dir = &self.config.data_dir;

        tokio::fs::create_dir_all(data_dir).await?;
        tokio::fs::create_dir_all(data_dir.join("cache")).await?;
        tokio::fs::create_dir_all(data_dir.join("inbox")).await?;
        tokio::fs::create_dir_all(data_dir.join("identity")).await?;
        tokio::fs::create_dir_all(data_dir.join("journal")).await?;
        tokio::fs::create_dir_all(data_dir.join("transfers")).await?;

        info!("Created data directory structure at {}", data_dir.display());
        Ok(())
    }

    async fn initialize_services(&mut self) -> Result<()> {
        info!("Initializing ATP daemon services...");

        // Initialize identity service
        self.initialize_identity_service().await?;

        // Initialize transfer service
        self.initialize_transfer_service().await?;

        // Initialize inbox service
        self.initialize_inbox_service().await?;

        // Initialize discovery service
        self.initialize_discovery_service().await?;

        Ok(())
    }

    async fn initialize_identity_service(&self) -> Result<()> {
        info!("Initializing identity service...");

        // Check for existing identity
        let identity_path = self.config.data_dir.join("identity").join("peer_id");

        if !identity_path.exists() {
            // Generate new identity
            let peer_id = format!("peer-{}", uuid::Uuid::new_v4());
            tokio::fs::write(&identity_path, &peer_id).await?;
            info!("Generated new peer identity: {}", peer_id);
        } else {
            let peer_id = tokio::fs::read_to_string(&identity_path).await?;
            info!("Loaded existing peer identity: {}", peer_id.trim());
        }

        Ok(())
    }

    async fn initialize_transfer_service(&self) -> Result<()> {
        info!("Initializing transfer service...");
        info!(
            "Max concurrent transfers: {}",
            self.config.max_concurrent_transfers
        );

        // Create transfer queue directory
        let queue_dir = self.config.data_dir.join("transfers").join("queue");
        tokio::fs::create_dir_all(&queue_dir).await?;

        Ok(())
    }

    async fn initialize_inbox_service(&self) -> Result<()> {
        if !self.config.enable_mailbox {
            info!("Mailbox service disabled, skipping inbox initialization");
            return Ok(());
        }

        info!("Initializing inbox service...");

        // Create inbox directory structure
        let inbox_dir = self.config.data_dir.join("inbox");
        tokio::fs::create_dir_all(inbox_dir.join("received")).await?;
        tokio::fs::create_dir_all(inbox_dir.join("pending")).await?;
        tokio::fs::create_dir_all(inbox_dir.join("processed")).await?;

        Ok(())
    }

    async fn initialize_discovery_service(&self) -> Result<()> {
        info!("Initializing peer discovery service...");

        if self.config.enable_relay {
            info!("Relay mode enabled - will advertise as relay node");
        }

        // Initialize local peer discovery
        self.start_local_discovery().await?;

        Ok(())
    }

    async fn start_local_discovery(&self) -> Result<()> {
        info!("Starting local network discovery...");

        // Create discovery announcement
        let announcement = json!({
            "device_name": self.config.device_name,
            "bind_addr": self.config.bind_addr.to_string(),
            "capabilities": {
                "relay": self.config.enable_relay,
                "mailbox": self.config.enable_mailbox,
            },
            "protocol_version": "ATP/1.0"
        });

        info!("Discovery announcement: {}", announcement);
        Ok(())
    }

    async fn start_background_tasks(&mut self) -> Result<()> {
        info!("Starting background tasks...");

        // Start health check task
        self.start_health_check_task().await?;

        // Start transfer monitor task
        self.start_transfer_monitor_task().await?;

        // Start peer discovery task
        self.start_peer_discovery_task().await?;

        // Start cache cleanup task
        self.start_cache_cleanup_task().await?;

        Ok(())
    }

    async fn start_health_check_task(&self) -> Result<()> {
        info!("Starting health check task...");

        let data_dir = self.config.data_dir.clone();
        let device_name = self.config.device_name.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));

            loop {
                interval.tick().await;

                // Perform health checks
                let uptime = Time::now().duration_since(Time::UNIX_EPOCH);

                match Self::check_system_health(&data_dir).await {
                    Ok(health_status) => {
                        info!("Health check passed for {}: {}", device_name, health_status);
                    }
                    Err(e) => {
                        warn!("Health check failed for {}: {}", device_name, e);
                    }
                }
            }
        });

        Ok(())
    }

    async fn start_transfer_monitor_task(&self) -> Result<()> {
        info!("Starting transfer monitor task...");

        let transfers_dir = self.config.data_dir.join("transfers");

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));

            loop {
                interval.tick().await;

                // Monitor active transfers
                if let Err(e) = Self::monitor_transfers(&transfers_dir).await {
                    warn!("Transfer monitoring failed: {}", e);
                }
            }
        });

        Ok(())
    }

    async fn start_peer_discovery_task(&self) -> Result<()> {
        info!("Starting peer discovery task...");

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));

            loop {
                interval.tick().await;

                // Perform peer discovery
                info!("Running peer discovery scan...");
                // TODO: Implement actual peer discovery
            }
        });

        Ok(())
    }

    async fn start_cache_cleanup_task(&self) -> Result<()> {
        info!("Starting cache cleanup task...");

        let cache_dir = self.config.data_dir.join("cache");

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(3600)); // Every hour

            loop {
                interval.tick().await;

                // Clean up old cache files
                if let Err(e) = Self::cleanup_cache(&cache_dir).await {
                    warn!("Cache cleanup failed: {}", e);
                }
            }
        });

        Ok(())
    }

    async fn check_system_health(data_dir: &std::path::Path) -> Result<String> {
        // Check disk space
        let metadata = tokio::fs::metadata(data_dir).await?;

        // Check data directory accessibility
        let test_file = data_dir.join(".health_check");
        tokio::fs::write(&test_file, "health_check").await?;
        tokio::fs::remove_file(&test_file).await?;

        Ok("healthy".to_string())
    }

    async fn monitor_transfers(transfers_dir: &std::path::Path) -> Result<()> {
        let queue_dir = transfers_dir.join("queue");

        if queue_dir.exists() {
            let mut entries = tokio::fs::read_dir(&queue_dir).await?;
            let mut count = 0;

            while let Some(_entry) = entries.next_entry().await? {
                count += 1;
            }

            if count > 0 {
                info!("Monitoring {} queued transfers", count);
            }
        }

        Ok(())
    }

    async fn cleanup_cache(cache_dir: &std::path::Path) -> Result<()> {
        if !cache_dir.exists() {
            return Ok(());
        }

        info!("Running cache cleanup in {}", cache_dir.display());

        // Simple cleanup: remove files older than 7 days
        let cutoff_time = std::time::SystemTime::now() - Duration::from_secs(7 * 24 * 3600);

        let mut entries = tokio::fs::read_dir(cache_dir).await?;
        let mut cleaned_count = 0;

        while let Some(entry) = entries.next_entry().await? {
            let metadata = entry.metadata().await?;

            if let Ok(modified) = metadata.modified() {
                if modified < cutoff_time {
                    if let Err(e) = tokio::fs::remove_file(entry.path()).await {
                        warn!(
                            "Failed to remove cache file {}: {}",
                            entry.path().display(),
                            e
                        );
                    } else {
                        cleaned_count += 1;
                    }
                }
            }
        }

        if cleaned_count > 0 {
            info!("Cleaned up {} old cache files", cleaned_count);
        }

        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        info!("Stopping ATP daemon service...");

        // Graceful shutdown logic here
        info!("ATP daemon service stopped");
        Ok(())
    }

    pub fn get_status(&self) -> serde_json::Value {
        json!({
            "device_name": self.config.device_name,
            "bind_addr": self.config.bind_addr.to_string(),
            "start_time": self.start_time,
            "uptime_seconds": Time::now().duration_since(self.start_time).as_secs(),
            "active_transfers": self.active_transfers.len(),
            "known_peers": self.peer_directory.len(),
            "config": {
                "max_concurrent_transfers": self.config.max_concurrent_transfers,
                "relay_enabled": self.config.enable_relay,
                "mailbox_enabled": self.config.enable_mailbox,
            }
        })
    }
}

async fn run_example() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .with_line_number(true)
        .init();

    info!("Starting ATP daemon example");

    // Create ATP daemon configuration
    let config = SimpleAtpdConfig::new()
        .with_bind_addr("127.0.0.1:18472".parse().unwrap())
        .with_data_dir(PathBuf::from("./example_atp_data"))
        .with_device_name("example-node-1")
        .enable_mailbox();

    // Create and start the daemon service
    let mut daemon = SimpleAtpdService::new(config);
    daemon.start().await?;

    // Show daemon status
    let status = daemon.get_status();
    info!("Daemon status: {}", serde_json::to_string_pretty(&status)?);

    // Run for a short time to demonstrate
    info!("Running daemon for 30 seconds...");
    sleep(Duration::from_secs(30)).await;

    // Stop the daemon
    daemon.stop().await?;

    info!("ATP daemon example completed");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    run_example().await
}

// Additional helper functions and examples

pub fn create_example_config() -> SimpleAtpdConfig {
    SimpleAtpdConfig::new()
        .with_bind_addr("0.0.0.0:8472".parse().unwrap())
        .with_device_name("production-atp-node")
        .enable_relay()
        .enable_mailbox()
}

pub async fn example_daemon_lifecycle() -> Result<()> {
    let config = create_example_config();
    let mut daemon = SimpleAtpdService::new(config);

    // Start daemon
    daemon.start().await?;

    // Simulate some work
    for i in 1..=5 {
        sleep(Duration::from_secs(2)).await;
        info!("Daemon heartbeat {}/5", i);

        let status = daemon.get_status();
        println!("Status: {}", serde_json::to_string_pretty(&status)?);
    }

    // Stop daemon
    daemon.stop().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_daemon_initialization() {
        let temp_dir = TempDir::new().unwrap();

        let config = SimpleAtpdConfig::new().with_data_dir(temp_dir.path().to_path_buf());

        let mut daemon = SimpleAtpdService::new(config);
        assert!(daemon.start().await.is_ok());
        assert!(daemon.stop().await.is_ok());
    }

    #[tokio::test]
    async fn test_config_builder() {
        let config = SimpleAtpdConfig::new()
            .with_device_name("test-node")
            .enable_relay()
            .enable_mailbox();

        assert_eq!(config.device_name, "test-node");
        assert!(config.enable_relay);
        assert!(config.enable_mailbox);
    }

    #[test]
    fn test_daemon_status() {
        let config = SimpleAtpdConfig::new();
        let daemon = SimpleAtpdService::new(config);

        let status = daemon.get_status();
        assert!(status.is_object());
        assert!(status["device_name"].is_string());
        assert!(status["active_transfers"].is_number());
    }
}
