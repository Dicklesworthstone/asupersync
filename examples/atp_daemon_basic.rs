//! Basic ATP Daemon Example
//!
//! Demonstrates how to set up and run an ATP daemon with basic configuration.

use serde_json::json;
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

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
    start_time: Instant,
    start_time_unix_secs: u64,
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
    pub last_seen_unix_secs: u64,
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
            start_time: Instant::now(),
            start_time_unix_secs: unix_now_secs(),
            active_transfers: HashMap::new(),
            peer_directory: HashMap::new(),
        }
    }

    pub fn start(&mut self) -> Result<()> {
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
        self.create_data_directories()?;

        // Initialize daemon services
        self.initialize_services()?;

        // Start background tasks
        self.start_background_tasks()?;

        info!("ATP daemon service started successfully");
        Ok(())
    }

    fn create_data_directories(&self) -> Result<()> {
        let data_dir = &self.config.data_dir;

        fs::create_dir_all(data_dir)?;
        fs::create_dir_all(data_dir.join("cache"))?;
        fs::create_dir_all(data_dir.join("inbox"))?;
        fs::create_dir_all(data_dir.join("identity"))?;
        fs::create_dir_all(data_dir.join("journal"))?;
        fs::create_dir_all(data_dir.join("transfers"))?;

        info!("Created data directory structure at {}", data_dir.display());
        Ok(())
    }

    fn initialize_services(&mut self) -> Result<()> {
        info!("Initializing ATP daemon services...");

        // Initialize identity service
        self.initialize_identity_service()?;

        // Initialize transfer service
        self.initialize_transfer_service()?;

        // Initialize inbox service
        self.initialize_inbox_service()?;

        // Initialize discovery service
        self.initialize_discovery_service()?;

        Ok(())
    }

    fn initialize_identity_service(&self) -> Result<()> {
        info!("Initializing identity service...");

        // Check for existing identity
        let identity_path = self.config.data_dir.join("identity").join("peer_id");

        if !identity_path.exists() {
            // Generate new identity
            let peer_id = format!(
                "peer-{}-{}-{}",
                self.config.device_name,
                std::process::id(),
                unix_now_secs()
            );
            fs::write(&identity_path, &peer_id)?;
            info!("Generated new peer identity: {}", peer_id);
        } else {
            let peer_id = fs::read_to_string(&identity_path)?;
            info!("Loaded existing peer identity: {}", peer_id.trim());
        }

        Ok(())
    }

    fn initialize_transfer_service(&self) -> Result<()> {
        info!("Initializing transfer service...");
        info!(
            "Max concurrent transfers: {}",
            self.config.max_concurrent_transfers
        );

        // Create transfer queue directory
        let queue_dir = self.config.data_dir.join("transfers").join("queue");
        fs::create_dir_all(&queue_dir)?;

        Ok(())
    }

    fn initialize_inbox_service(&self) -> Result<()> {
        if !self.config.enable_mailbox {
            info!("Mailbox service disabled, skipping inbox initialization");
            return Ok(());
        }

        info!("Initializing inbox service...");

        // Create inbox directory structure
        let inbox_dir = self.config.data_dir.join("inbox");
        fs::create_dir_all(inbox_dir.join("received"))?;
        fs::create_dir_all(inbox_dir.join("pending"))?;
        fs::create_dir_all(inbox_dir.join("processed"))?;

        Ok(())
    }

    fn initialize_discovery_service(&self) -> Result<()> {
        info!("Initializing peer discovery service...");

        if self.config.enable_relay {
            info!("Relay mode enabled - will advertise as relay node");
        }

        // Initialize local peer discovery
        self.start_local_discovery()?;

        Ok(())
    }

    fn start_local_discovery(&self) -> Result<()> {
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

    fn start_background_tasks(&mut self) -> Result<()> {
        info!("Starting background tasks...");

        // The example keeps background work explicit and single-shot so it can
        // be compiled and tested without requiring a separate async executor.
        self.run_health_check()?;
        self.run_transfer_monitor()?;
        self.run_peer_discovery();
        self.run_cache_cleanup()?;

        Ok(())
    }

    fn run_health_check(&self) -> Result<()> {
        match Self::check_system_health(&self.config.data_dir) {
            Ok(health_status) => {
                info!(
                    "Health check passed for {}: {}",
                    self.config.device_name, health_status
                );
                Ok(())
            }
            Err(error) => {
                warn!(
                    "Health check failed for {}: {}",
                    self.config.device_name, error
                );
                Err(error)
            }
        }
    }

    fn run_transfer_monitor(&self) -> Result<()> {
        let transfers_dir = self.config.data_dir.join("transfers");
        Self::monitor_transfers(&transfers_dir)
    }

    fn run_peer_discovery(&self) {
        info!("Running peer discovery scan...");
    }

    fn run_cache_cleanup(&self) -> Result<()> {
        Self::cleanup_cache(&self.config.data_dir.join("cache"))
    }

    fn check_system_health(data_dir: &std::path::Path) -> Result<String> {
        // Check disk space
        let _metadata = fs::metadata(data_dir)?;

        // Check data directory accessibility
        let test_file = data_dir.join(".health_check");
        fs::write(&test_file, "health_check")?;
        fs::remove_file(&test_file)?;

        Ok("healthy".to_string())
    }

    fn monitor_transfers(transfers_dir: &std::path::Path) -> Result<()> {
        let queue_dir = transfers_dir.join("queue");

        if queue_dir.exists() {
            let count = fs::read_dir(&queue_dir)?.count();

            if count > 0 {
                info!("Monitoring {} queued transfers", count);
            }
        }

        Ok(())
    }

    fn cleanup_cache(cache_dir: &std::path::Path) -> Result<()> {
        if !cache_dir.exists() {
            return Ok(());
        }

        info!("Running cache cleanup in {}", cache_dir.display());

        // Simple cleanup: remove files older than 7 days
        let cutoff_time = std::time::SystemTime::now() - Duration::from_secs(7 * 24 * 3600);

        let mut cleaned_count = 0;

        for entry in fs::read_dir(cache_dir)? {
            let entry = entry?;
            let metadata = entry.metadata()?;

            if let Ok(modified) = metadata.modified() {
                if modified < cutoff_time {
                    if let Err(e) = fs::remove_file(entry.path()) {
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

    pub fn stop(&self) -> Result<()> {
        info!("Stopping ATP daemon service...");

        // Graceful shutdown logic here
        info!("ATP daemon service stopped");
        Ok(())
    }

    pub fn get_status(&self) -> serde_json::Value {
        json!({
            "device_name": self.config.device_name,
            "bind_addr": self.config.bind_addr.to_string(),
            "start_time_unix_secs": self.start_time_unix_secs,
            "uptime_seconds": self.start_time.elapsed().as_secs(),
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

fn run_example() -> Result<()> {
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
    daemon.start()?;

    // Show daemon status
    let status = daemon.get_status();
    info!("Daemon status: {}", serde_json::to_string_pretty(&status)?);

    // Run for a short time to demonstrate
    info!("Running daemon for 30 seconds...");
    sleep(Duration::from_secs(30));

    // Stop the daemon
    daemon.stop()?;

    info!("ATP daemon example completed");
    Ok(())
}

fn main() -> Result<()> {
    run_example()
}

// Additional helper functions and examples

pub fn create_example_config() -> SimpleAtpdConfig {
    SimpleAtpdConfig::new()
        .with_bind_addr("0.0.0.0:8472".parse().unwrap())
        .with_device_name("production-atp-node")
        .enable_relay()
        .enable_mailbox()
}

pub fn example_daemon_lifecycle() -> Result<()> {
    let config = create_example_config();
    let mut daemon = SimpleAtpdService::new(config);

    // Start daemon
    daemon.start()?;

    // Simulate some work
    for i in 1..=5 {
        sleep(Duration::from_secs(2));
        info!("Daemon heartbeat {}/5", i);

        let status = daemon.get_status();
        println!("Status: {}", serde_json::to_string_pretty(&status)?);
    }

    // Stop daemon
    daemon.stop()?;

    Ok(())
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_daemon_initialization() {
        let temp_dir = TempDir::new().unwrap();

        let config = SimpleAtpdConfig::new().with_data_dir(temp_dir.path().to_path_buf());

        let mut daemon = SimpleAtpdService::new(config);
        assert!(daemon.start().is_ok());
        assert!(daemon.stop().is_ok());
    }

    #[test]
    fn test_config_builder() {
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
