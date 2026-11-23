//! Integration helpers for CLI upgrade daemon control.
//!
//! This module provides the bridge between the secure daemon controller
//! and the CLI upgrade commands. It can be integrated with src/cli/upgrade.rs
//! once MCP reservations allow.

use crate::atp::daemon_control::{
    DaemonControlCapability, DaemonControlResult, DaemonState, SecureDaemonController,
    create_atp_daemon_controller, create_atp_daemon_controller_with_executable,
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
    ///
    /// This preserves the current-executable factory for callers running inside
    /// `atpd`. An embedding application should use
    /// [`Self::new_for_upgrade_with_executable`] to select the daemon binary.
    pub fn new_for_upgrade(region_id: RegionId, config_dir: &Path) -> Result<Self, Error> {
        let controller = create_atp_daemon_controller(region_id, Self::capabilities(), config_dir)?;
        Ok(Self { controller })
    }

    /// Creates an upgrade controller for an explicitly selected `atpd` binary.
    ///
    /// The daemon executable and configuration are validated by the same
    /// controller constructor as the current-executable factory. No daemon is
    /// started until [`Self::start_daemon`] is called with an authorized context.
    pub fn new_for_upgrade_with_executable(
        region_id: RegionId,
        config_dir: &Path,
        daemon_path: &Path,
    ) -> Result<Self, Error> {
        let controller = create_atp_daemon_controller_with_executable(
            region_id,
            Self::capabilities(),
            config_dir,
            daemon_path,
        )?;
        Ok(Self { controller })
    }

    fn capabilities() -> Vec<DaemonControlCapability> {
        vec![
            DaemonControlCapability::Status,
            DaemonControlCapability::Start,
            DaemonControlCapability::Stop,
            DaemonControlCapability::Restart,
        ]
    }

    /// Stops daemon if running (integrates with stop_daemon_if_running).
    ///
    /// Uses legacy best-effort status discovery. Use
    /// [`Self::try_stop_daemon_if_running`] to reject an inconclusive PID claim
    /// before an upgrade proceeds.
    pub async fn stop_daemon_if_running(&mut self, cx: &Cx) -> Result<bool, Error> {
        let status = self.controller.status(cx)?;
        if status.pid.is_none() {
            return Ok(false);
        }
        Self::check_stop_result(self.controller.stop(cx)?).map(|_| true)
    }

    /// Stops a running daemon after strict status discovery.
    ///
    /// Returns `false` when discovery finds no daemon. Malformed or unreadable
    /// PID claims and unavailable process identity are errors, so the caller
    /// can abort the upgrade instead of assuming the daemon is stopped.
    pub async fn try_stop_daemon_if_running(&mut self, cx: &Cx) -> Result<bool, Error> {
        Self::check_stop_result(self.controller.stop_strict(cx)?)
            .map(|previous_state| previous_state != DaemonState::Stopped)
    }

    fn check_stop_result(result: DaemonControlResult) -> Result<DaemonState, Error> {
        match result {
            DaemonControlResult::Success { previous_state, .. } => Ok(previous_state),
            DaemonControlResult::Failed { error, .. } => {
                Err(Error::new(ErrorKind::OperationFailed)
                    .with_message(format!("Failed to stop daemon: {}", error)))
            }
            DaemonControlResult::PermissionDenied { .. } => {
                Err(Error::new(ErrorKind::AdmissionDenied)
                    .with_message("Permission denied to stop daemon"))
            }
        }
    }

    /// Checks if daemon is running (integrates with is_daemon_running).
    ///
    /// This legacy query maps status errors to `false`. Use
    /// [`Self::try_is_daemon_running`] when a failed authorization or process
    /// query must not be mistaken for a stopped daemon.
    pub async fn is_daemon_running(&mut self, cx: &Cx) -> Result<bool, Error> {
        match self.controller.status(cx) {
            Ok(status) => Ok(status.pid.is_some()),
            Err(_) => Ok(false), // Assume not running if we can't check
        }
    }

    /// Checks daemon status without treating an inconclusive query as stopped.
    ///
    /// Preserves authorization and process-observation errors so an upgrade
    /// caller can abort before changing files belonging to a running daemon.
    pub async fn try_is_daemon_running(&mut self, cx: &Cx) -> Result<bool, Error> {
        self.controller
            .status_strict(cx)
            .map(|status| status.pid.is_some())
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

/// Creates an upgrade controller for a daemon binary distinct from the caller.
pub fn create_upgrade_daemon_controller_with_executable(
    region_id: RegionId,
    config_dir: &Path,
    daemon_path: &Path,
) -> Result<UpgradeDaemonController, Error> {
    UpgradeDaemonController::new_for_upgrade_with_executable(region_id, config_dir, daemon_path)
}

#[cfg(test)]
#[path = "upgrade_integration_inline_tests.rs"]
mod tests;
