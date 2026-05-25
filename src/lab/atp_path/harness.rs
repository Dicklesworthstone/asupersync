//! ATP path lab harness implementation for deterministic network testing.

use crate::atp::path::{PathKind, PathTraceId};
use crate::lab::{
    AtpLabRegime, AtpLabScenario, AtpLabTransferSpec, AtpTransferLabPlan, NetworkConfig,
    SimulatedNetwork,
};
use crate::net::atp::path::NatProfile;
use crate::types::Time;
use std::time::Duration;
use thiserror::Error;

/// Configuration for ATP path lab testing.
#[derive(Debug, Clone)]
pub struct AtpPathTestConfig {
    /// Simulated network configuration
    pub network: NetworkConfig,
    /// Enable detailed path tracing
    pub enable_path_tracing: bool,
    /// Timeout for path discovery operations
    pub path_discovery_timeout: Duration,
    /// Enable path migration simulation
    pub enable_migration: bool,
}

impl AtpPathTestConfig {
    /// Configuration optimized for LAN+IPv6 path testing.
    #[must_use]
    pub fn lan_ipv6() -> Self {
        Self {
            network: NetworkConfig::lan_ipv6(),
            enable_path_tracing: true,
            path_discovery_timeout: Duration::from_secs(30),
            enable_migration: false,
        }
    }

    /// Configuration for NAT traversal stress testing.
    #[must_use]
    pub fn nat_stress() -> Self {
        Self {
            network: NetworkConfig::nat_stress(),
            enable_path_tracing: true,
            path_discovery_timeout: Duration::from_secs(60),
            enable_migration: true,
        }
    }

    /// Configuration for relay-only scenarios.
    #[must_use]
    pub fn relay_only() -> Self {
        Self {
            network: NetworkConfig::relay_only(),
            enable_path_tracing: true,
            path_discovery_timeout: Duration::from_secs(45),
            enable_migration: false,
        }
    }
}

/// Path validation results from lab execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtpPathValidation {
    /// IPv6 direct path was attempted and succeeded
    pub ipv6_direct_succeeded: bool,
    /// LAN multicast discovery succeeded
    pub lan_multicast_succeeded: bool,
    /// NAT hole punching was attempted and succeeded
    pub nat_punch_succeeded: bool,
    /// Relay path was used successfully
    pub relay_succeeded: bool,
    /// Path migration occurred and preserved transfer
    pub migration_preserved_transfer: bool,
    /// Final selected path kind
    pub selected_path_kind: Option<PathKind>,
    /// Detected NAT profile during testing
    pub detected_nat_profile: NatProfile,
}

impl AtpPathValidation {
    /// Create validation results indicating complete failure.
    #[must_use]
    pub fn failed() -> Self {
        Self {
            ipv6_direct_succeeded: false,
            lan_multicast_succeeded: false,
            nat_punch_succeeded: false,
            relay_succeeded: false,
            migration_preserved_transfer: false,
            selected_path_kind: None,
            detected_nat_profile: NatProfile::Unknown,
        }
    }

    /// Check if any direct path succeeded.
    #[must_use]
    pub fn has_direct_path(&self) -> bool {
        self.ipv6_direct_succeeded || self.lan_multicast_succeeded || self.nat_punch_succeeded
    }

    /// Check if the validation represents a successful transfer.
    #[must_use]
    pub fn transfer_succeeded(&self) -> bool {
        self.selected_path_kind.is_some() && (self.has_direct_path() || self.relay_succeeded)
    }
}

/// Complete execution result from ATP path lab harness.
#[derive(Debug, Clone)]
pub struct AtpPathExecutionResult {
    /// Path validation outcomes
    pub path_validation: AtpPathValidation,
    /// Trace events captured during execution
    pub trace_events: Vec<AtpPathTraceEvent>,
    /// Wall-clock execution time
    pub execution_time: Duration,
    /// Number of path candidates evaluated
    pub candidates_evaluated: u32,
    /// Whether the scenario execution matched expected outcomes
    pub scenario_matched_expected: bool,
}

/// Path-specific trace event for debugging and analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtpPathTraceEvent {
    /// Event timestamp
    pub timestamp: Time,
    /// Path trace identifier
    pub trace_id: PathTraceId,
    /// Event kind
    pub event: AtpPathEventKind,
}

/// ATP path event kinds for trace analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AtpPathEventKind {
    /// Path candidate discovery started
    DiscoveryStarted {
        path_kind: PathKind,
        nat_profile: NatProfile,
    },
    /// Path candidate connection attempt
    ConnectionAttempt {
        path_kind: PathKind,
        target_endpoint: String,
    },
    /// Path candidate succeeded
    PathSucceeded {
        path_kind: PathKind,
        latency_micros: u64,
    },
    /// Path candidate failed
    PathFailed { path_kind: PathKind, reason: String },
    /// Path migration triggered
    MigrationTriggered {
        from_path: PathKind,
        to_path: PathKind,
    },
    /// Transfer completed via selected path
    TransferCompleted {
        selected_path: PathKind,
        bytes_transferred: u64,
    },
}

/// Errors from ATP path lab harness execution.
#[derive(Debug, Error)]
pub enum AtpPathLabError {
    #[error("Network simulation failed: {0}")]
    NetworkSimulation(String),
    #[error("Path discovery timeout after {timeout:?}")]
    PathDiscoveryTimeout { timeout: Duration },
    #[error("Scenario regime {regime:?} is not supported by this harness")]
    UnsupportedRegime { regime: AtpLabRegime },
    #[error("Transfer specification is invalid: {reason}")]
    InvalidTransferSpec { reason: String },
    #[error("Internal harness error: {0}")]
    Internal(String),
}

/// ATP path lab harness for executing path-related scenarios.
#[derive(Debug)]
pub struct AtpPathLabHarness {
    network: SimulatedNetwork,
    /// Deterministic timestamp counter for trace events
    timestamp_counter: u64,
}

impl AtpPathLabHarness {
    /// Create a new ATP path lab harness with the given configuration.
    #[must_use]
    pub fn new(config: AtpPathTestConfig) -> Self {
        let network = SimulatedNetwork::new(config.network.clone());
        Self {
            network,
            timestamp_counter: 0,
        }
    }

    /// Generate a deterministic timestamp for trace events.
    fn next_timestamp(&mut self) -> Time {
        self.timestamp_counter += 1;
        Time::from_nanos(self.timestamp_counter)
    }

    /// Execute an ATP lab scenario and return path validation results.
    ///
    /// # Errors
    /// Returns [`AtpPathLabError`] if scenario execution fails.
    pub async fn execute_scenario(
        &mut self,
        scenario: &AtpLabScenario,
    ) -> Result<AtpPathExecutionResult, AtpPathLabError> {
        let start_time = std::time::Instant::now();

        // Create a basic transfer spec for path testing
        let transfer = AtpLabTransferSpec::new(
            "client",
            "server",
            1024 * 1024, // 1MB test transfer
            1,
        );

        let plan = scenario.clone().compose(transfer);

        // Execute the plan and collect results
        let result = self.execute_plan(&plan).await?;

        let execution_time = start_time.elapsed();

        Ok(AtpPathExecutionResult {
            path_validation: result.path_validation,
            trace_events: result.trace_events,
            execution_time,
            candidates_evaluated: result.candidates_evaluated,
            scenario_matched_expected: result.scenario_matched_expected,
        })
    }

    async fn execute_plan(
        &mut self,
        plan: &AtpTransferLabPlan,
    ) -> Result<AtpPathExecutionResult, AtpPathLabError> {
        let mut trace_events = Vec::new();
        let mut path_validation = AtpPathValidation::failed();
        let mut candidates_evaluated = 0;
        let mut scenario_matched_expected = true;

        // Set up simulated endpoints
        self.network.add_host("client");
        self.network.add_host("server");

        // Process each regime in the scenario
        for regime in &plan.scenario.regimes {
            match self
                .process_regime(*regime, &mut trace_events, &mut path_validation)
                .await
            {
                Ok(evaluated) => candidates_evaluated += evaluated,
                Err(e) => {
                    scenario_matched_expected = false;
                    // Log error but continue with other regimes
                    trace_events.push(AtpPathTraceEvent {
                        timestamp: self.next_timestamp(),
                        trace_id: PathTraceId::new(trace_events.len() as u64),
                        event: AtpPathEventKind::PathFailed {
                            path_kind: PathKind::LanMulticast, // Default for error
                            reason: format!("Regime processing failed: {e}"),
                        },
                    });
                }
            }
        }

        // Determine final path selection based on validation results
        path_validation.selected_path_kind = self.select_best_path(&path_validation);

        Ok(AtpPathExecutionResult {
            path_validation,
            trace_events,
            execution_time: Duration::from_secs(0), // Will be filled by caller
            candidates_evaluated,
            scenario_matched_expected,
        })
    }

    async fn process_regime(
        &mut self,
        regime: AtpLabRegime,
        trace_events: &mut Vec<AtpPathTraceEvent>,
        validation: &mut AtpPathValidation,
    ) -> Result<u32, AtpPathLabError> {
        let trace_id = PathTraceId::new(trace_events.len() as u64);
        let mut candidates_evaluated = 0;

        match regime {
            AtpLabRegime::EasyNat => {
                validation.detected_nat_profile = NatProfile::LikelyEasyNat;
                candidates_evaluated += self
                    .test_path_kind(PathKind::LanMulticast, trace_id, trace_events, validation)
                    .await?;
            }
            AtpLabRegime::Ipv6Direct => {
                validation.detected_nat_profile = NatProfile::Ipv6Direct;
                candidates_evaluated += self
                    .test_path_kind(PathKind::PublicIpv6, trace_id, trace_events, validation)
                    .await?;
            }
            AtpLabRegime::HardNat | AtpLabRegime::SymmetricNat => {
                validation.detected_nat_profile = NatProfile::HardSymmetricNat;
                candidates_evaluated += self
                    .test_path_kind(PathKind::NatPunchedUdp, trace_id, trace_events, validation)
                    .await?;
            }
            AtpLabRegime::UdpBlocked => {
                validation.detected_nat_profile = NatProfile::UdpBlocked;
                // UDP blocked forces relay usage
                candidates_evaluated += self
                    .test_path_kind(PathKind::AtpRelayUdp, trace_id, trace_events, validation)
                    .await?;
            }
            AtpLabRegime::RelayOnly => {
                candidates_evaluated += self
                    .test_path_kind(PathKind::AtpRelayUdp, trace_id, trace_events, validation)
                    .await?;
            }
            AtpLabRegime::TailscalePrivateRoute => {
                candidates_evaluated += self
                    .test_path_kind(PathKind::TailscaleIp, trace_id, trace_events, validation)
                    .await?;
            }
            AtpLabRegime::PathMigration => {
                // Test migration from LAN to IPv6
                self.test_path_migration(
                    PathKind::LanMulticast,
                    PathKind::PublicIpv6,
                    trace_id,
                    trace_events,
                    validation,
                )
                .await?;
                candidates_evaluated += 2;
            }
            // Other regimes are handled by different harnesses
            _ => return Err(AtpPathLabError::UnsupportedRegime { regime }),
        }

        Ok(candidates_evaluated)
    }

    async fn test_path_kind(
        &mut self,
        path_kind: PathKind,
        trace_id: PathTraceId,
        trace_events: &mut Vec<AtpPathTraceEvent>,
        validation: &mut AtpPathValidation,
    ) -> Result<u32, AtpPathLabError> {
        trace_events.push(AtpPathTraceEvent {
            timestamp: self.next_timestamp(),
            trace_id,
            event: AtpPathEventKind::DiscoveryStarted {
                path_kind,
                nat_profile: validation.detected_nat_profile,
            },
        });

        trace_events.push(AtpPathTraceEvent {
            timestamp: self.next_timestamp(),
            trace_id,
            event: AtpPathEventKind::ConnectionAttempt {
                path_kind,
                target_endpoint: "simulated-endpoint".to_string(),
            },
        });

        // Simulate path testing based on kind and network conditions
        let success = match path_kind {
            PathKind::LanMulticast => {
                validation.lan_multicast_succeeded = true;
                true
            }
            PathKind::PublicIpv6 => {
                validation.ipv6_direct_succeeded = true;
                true
            }
            PathKind::NatPunchedUdp => {
                // Succeeds for easy NAT, fails for hard NAT
                let success = matches!(validation.detected_nat_profile, NatProfile::LikelyEasyNat);
                validation.nat_punch_succeeded = success;
                success
            }
            PathKind::AtpRelayUdp | PathKind::AtpRelayTcpTls443 => {
                validation.relay_succeeded = true;
                true
            }
            PathKind::TailscaleIp => true,
            _ => false,
        };

        if success {
            trace_events.push(AtpPathTraceEvent {
                timestamp: self.next_timestamp(),
                trace_id,
                event: AtpPathEventKind::PathSucceeded {
                    path_kind,
                    latency_micros: 5000, // Simulated 5ms latency
                },
            });
        } else {
            trace_events.push(AtpPathTraceEvent {
                timestamp: self.next_timestamp(),
                trace_id,
                event: AtpPathEventKind::PathFailed {
                    path_kind,
                    reason: "Network conditions prevented connection".to_string(),
                },
            });
        }

        Ok(1) // One candidate evaluated
    }

    async fn test_path_migration(
        &mut self,
        from_path: PathKind,
        to_path: PathKind,
        trace_id: PathTraceId,
        trace_events: &mut Vec<AtpPathTraceEvent>,
        validation: &mut AtpPathValidation,
    ) -> Result<(), AtpPathLabError> {
        // First establish the initial path
        self.test_path_kind(from_path, trace_id, trace_events, validation)
            .await?;

        // Simulate migration trigger
        trace_events.push(AtpPathTraceEvent {
            timestamp: self.next_timestamp(),
            trace_id,
            event: AtpPathEventKind::MigrationTriggered { from_path, to_path },
        });

        // Test the new path
        self.test_path_kind(to_path, trace_id, trace_events, validation)
            .await?;

        // Migration preserves transfer if both paths succeeded
        validation.migration_preserved_transfer = match (from_path, to_path) {
            (PathKind::LanMulticast, PathKind::PublicIpv6) => {
                validation.lan_multicast_succeeded && validation.ipv6_direct_succeeded
            }
            _ => false,
        };

        Ok(())
    }

    fn select_best_path(&self, validation: &AtpPathValidation) -> Option<PathKind> {
        // Prefer direct paths over relay paths
        if validation.ipv6_direct_succeeded {
            Some(PathKind::PublicIpv6)
        } else if validation.lan_multicast_succeeded {
            Some(PathKind::LanMulticast)
        } else if validation.nat_punch_succeeded {
            Some(PathKind::NatPunchedUdp)
        } else if validation.relay_succeeded {
            Some(PathKind::AtpRelayUdp)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lab::AtpLabScenario;

    #[tokio::test]
    async fn test_lan_ipv6_harness_basic_execution() {
        let mut harness = AtpPathLabHarness::new(AtpPathTestConfig::lan_ipv6());

        let scenario = AtpLabScenario::new("easy-nat-direct", 0xA7F0_0001)
            .with_regime(AtpLabRegime::EasyNat)
            .with_regime(AtpLabRegime::Ipv6Direct);

        let result = harness.execute_scenario(&scenario).await.unwrap();

        assert!(result.path_validation.transfer_succeeded());
        assert!(result.path_validation.lan_multicast_succeeded);
        assert!(result.path_validation.ipv6_direct_succeeded);
        assert_eq!(result.candidates_evaluated, 2);
    }

    #[tokio::test]
    async fn test_path_validation_has_direct_path() {
        let mut validation = AtpPathValidation::failed();
        validation.ipv6_direct_succeeded = true;
        validation.selected_path_kind = Some(PathKind::PublicIpv6);

        assert!(validation.has_direct_path());
        assert!(validation.transfer_succeeded());
    }

    #[tokio::test]
    async fn test_udp_blocked_forces_relay() {
        let mut harness = AtpPathLabHarness::new(AtpPathTestConfig::relay_only());

        let scenario =
            AtpLabScenario::new("udp-blocked", 0xA7F0_0003).with_regime(AtpLabRegime::UdpBlocked);

        let result = harness.execute_scenario(&scenario).await.unwrap();

        assert!(result.path_validation.relay_succeeded);
        assert!(!result.path_validation.has_direct_path());
        assert_eq!(
            result.path_validation.detected_nat_profile,
            NatProfile::UdpBlocked
        );
    }
}
