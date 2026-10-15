//! Integration helpers for CLI upgrade daemon control.
//!
//! This module provides the bridge between the secure daemon controller
//! and the CLI upgrade commands. It can be integrated with src/cli/upgrade.rs
//! once MCP reservations allow.

use crate::atp::daemon_control::{
    DaemonControlCapability, SecureDaemonController, create_atp_daemon_controller,
};
use crate::cx::Cx;
use crate::error::{Error, ErrorKind};
use crate::types::RegionId;
use std::path::Path;

/// Integration wrapper for CLI upgrade daemon operations.
pub struct UpgradeDaemonController {
    controller: SecureDaemonController,
}

impl UpgradeDaemonController {
    /// Creates a new upgrade daemon controller with minimal required capabilities.
    pub fn new_for_upgrade(region_id: RegionId, config_dir: &Path) -> Result<Self, Error> {
        let capabilities = vec![
            DaemonControlCapability::Status,
            DaemonControlCapability::Start,
            DaemonControlCapability::Stop,
            DaemonControlCapability::Restart,
        ];

        let controller = create_atp_daemon_controller(region_id, capabilities, config_dir)?;
        Ok(Self { controller })
    }

    /// Stops daemon if running (integrates with stop_daemon_if_running).
    pub async fn stop_daemon_if_running(&mut self, cx: &Cx) -> Result<bool, Error> {
        match self.controller.status(cx) {
            Ok(status) if status.pid.is_some() => match self.controller.stop(cx)? {
                crate::atp::daemon_control::DaemonControlResult::Success { .. } => Ok(true),
                crate::atp::daemon_control::DaemonControlResult::Failed { error, .. } => {
                    Err(Error::new(ErrorKind::OperationFailed)
                        .with_message(format!("Failed to stop daemon: {}", error)))
                }
                crate::atp::daemon_control::DaemonControlResult::PermissionDenied { .. } => {
                    Err(Error::new(ErrorKind::AdmissionDenied)
                        .with_message("Permission denied to stop daemon"))
                }
            },
            Ok(_) => Ok(false), // Not running
            Err(e) => Err(e),
        }
    }

    /// Checks if daemon is running (integrates with is_daemon_running).
    pub async fn is_daemon_running(&mut self, cx: &Cx) -> Result<bool, Error> {
        match self.controller.status(cx) {
            Ok(status) => Ok(status.pid.is_some()),
            Err(_) => Ok(false), // Assume not running if we can't check
        }
    }

    /// Starts daemon (integrates with start_daemon).
    pub async fn start_daemon(&mut self, cx: &Cx) -> Result<(), Error> {
        match self.controller.start(cx)? {
            crate::atp::daemon_control::DaemonControlResult::Success { .. } => Ok(()),
            crate::atp::daemon_control::DaemonControlResult::Failed { error, .. } => {
                Err(Error::new(ErrorKind::OperationFailed)
                    .with_message(format!("Failed to start daemon: {}", error)))
            }
            crate::atp::daemon_control::DaemonControlResult::PermissionDenied { .. } => {
                Err(Error::new(ErrorKind::AdmissionDenied)
                    .with_message("Permission denied to start daemon"))
            }
        }
    }
}

/// Factory function for creating upgrade controllers with standard configuration.
pub fn create_upgrade_daemon_controller(
    region_id: RegionId,
    config_dir: &Path,
) -> Result<UpgradeDaemonController, Error> {
    UpgradeDaemonController::new_for_upgrade(region_id, config_dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_upgrade_controller_creation() {
        let temp_dir = TempDir::new().unwrap();
        let config_dir = temp_dir.path();

        // Create a minimal config file.
        std::fs::write(config_dir.join("config.toml"), "# test config").unwrap();

        let result = create_upgrade_daemon_controller(RegionId::new_for_test(1, 0), config_dir);

        assert!(result.is_ok());
    }
}
