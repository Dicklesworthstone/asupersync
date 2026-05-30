//! ATP path lab harness implementation for deterministic network testing.

use crate::atp::path::{PathKind, PathTraceId};
use crate::lab::{
    AtpLabRegime, AtpLabScenario, AtpLabTransferSpec, AtpTransferLabPlan, DeterministicNetwork,
    NetworkConfig,
};
use crate::net::atp::path::NatProfile;
use crate::types::Time;
use std::time::Duration;
use thiserror::Error;

/// Configuration for ATP path lab testing.
#[derive(Debug, Clone)]
pub struct AtpPathTestConfig {
    /// Deterministic network configuration
    pub network: NetworkConfig,
    /// Enable detailed path tracing
    pub enable_path_tracing: bool,
    /// Timeout for path discovery operations
    pub path_discovery_timeout: Duration,
    /// Enable path migration modeling
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
    /// Explicit public UDP endpoint succeeded
    pub explicit_public_udp_succeeded: bool,
    /// NAT hole punching was attempted and succeeded
    pub nat_punch_succeeded: bool,
    /// Relay path was used successfully
    pub relay_succeeded: bool,
    /// Relay over TCP/TLS 443 was used successfully
    pub relay_tcp_tls_443_succeeded: bool,
    /// MASQUE/CONNECT-UDP proxy path was used successfully
    pub masque_connect_udp_succeeded: bool,
    /// Tailscale-like private route was used successfully
    pub tailscale_private_route_succeeded: bool,
    /// Offline mailbox store-and-forward path was used successfully
    pub offline_mailbox_succeeded: bool,
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
            explicit_public_udp_succeeded: false,
            nat_punch_succeeded: false,
            relay_succeeded: false,
            relay_tcp_tls_443_succeeded: false,
            masque_connect_udp_succeeded: false,
            tailscale_private_route_succeeded: false,
            offline_mailbox_succeeded: false,
            migration_preserved_transfer: false,
            selected_path_kind: None,
            detected_nat_profile: NatProfile::Unknown,
        }
    }

    /// Check if any direct path succeeded.
    #[must_use]
    pub fn has_direct_path(&self) -> bool {
        self.ipv6_direct_succeeded
            || self.lan_multicast_succeeded
            || self.explicit_public_udp_succeeded
            || self.nat_punch_succeeded
    }

    /// Check if the validation represents a successful transfer.
    #[must_use]
    pub fn transfer_succeeded(&self) -> bool {
        self.selected_path_kind.is_some()
            && (self.has_direct_path()
                || self.tailscale_private_route_succeeded
                || self.relay_succeeded
                || self.offline_mailbox_succeeded)
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
    /// A fallback path was selected after a preferred candidate failed.
    FallbackSelected {
        from_path: PathKind,
        to_path: PathKind,
        reason: String,
        relay_cost_micros: Option<u64>,
    },
    /// A path-race loser was explicitly drained after selection.
    LoserPathDrained { path_kind: PathKind, reason: String },
    /// Transfer completed via selected path
    TransferCompleted {
        selected_path: PathKind,
        bytes_transferred: u64,
    },
}

/// Errors from ATP path lab harness execution.
#[derive(Debug, Error)]
pub enum AtpPathLabError {
    #[error("Network model failed: {0}")]
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
    network: DeterministicNetwork,
    /// Deterministic timestamp counter for trace events
    timestamp_counter: u64,
    /// Deterministic trace ID counter for trace events
    trace_id_counter: u64,
}

impl AtpPathLabHarness {
    /// Create a new ATP path lab harness with the given configuration.
    #[must_use]
    pub fn new(config: AtpPathTestConfig) -> Self {
        let network = DeterministicNetwork::new(config.network.clone());
        Self {
            network,
            timestamp_counter: 0,
            trace_id_counter: 0,
        }
    }

    /// Generate a deterministic timestamp for trace events.
    fn next_timestamp(&mut self) -> Time {
        self.timestamp_counter += 1;
        Time::from_nanos(self.timestamp_counter)
    }

    /// Generate a deterministic trace ID for trace events.
    fn next_trace_id(&mut self) -> PathTraceId {
        self.trace_id_counter += 1;
        PathTraceId::new(self.trace_id_counter)
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

        // Set up deterministic virtual endpoints.
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
                        trace_id: self.next_trace_id(),
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
        if let Some(selected_path) = path_validation.selected_path_kind {
            trace_events.push(AtpPathTraceEvent {
                timestamp: self.next_timestamp(),
                trace_id: self.next_trace_id(),
                event: AtpPathEventKind::TransferCompleted {
                    selected_path,
                    bytes_transferred: plan.transfer.bytes,
                },
            });
        }

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
        let mut candidates_evaluated = 0;

        match regime {
            AtpLabRegime::LanMulticast => {
                candidates_evaluated += self
                    .test_path_kind(PathKind::LanMulticast, trace_events, validation)
                    .await?;
            }
            AtpLabRegime::EasyNat => {
                validation.detected_nat_profile = NatProfile::LikelyEasyNat;
                candidates_evaluated += self
                    .test_path_kind(PathKind::NatPunchedUdp, trace_events, validation)
                    .await?;
            }
            AtpLabRegime::ExplicitPublicUdp => {
                candidates_evaluated += self
                    .test_path_kind(PathKind::ExplicitPublicUdp, trace_events, validation)
                    .await?;
            }
            AtpLabRegime::Ipv6Direct => {
                validation.detected_nat_profile = NatProfile::Ipv6Direct;
                candidates_evaluated += self
                    .test_path_kind(PathKind::PublicIpv6, trace_events, validation)
                    .await?;
            }
            AtpLabRegime::HardNat | AtpLabRegime::SymmetricNat => {
                validation.detected_nat_profile = NatProfile::HardSymmetricNat;
                candidates_evaluated += self
                    .test_path_kind(PathKind::NatPunchedUdp, trace_events, validation)
                    .await?;
            }
            AtpLabRegime::UdpBlocked => {
                validation.detected_nat_profile = NatProfile::UdpBlocked;
                candidates_evaluated += self
                    .test_path_kind(PathKind::NatPunchedUdp, trace_events, validation)
                    .await?;
                candidates_evaluated += self
                    .test_path_kind(PathKind::AtpRelayUdp, trace_events, validation)
                    .await?;
                trace_events.push(AtpPathTraceEvent {
                    timestamp: self.next_timestamp(),
                    trace_id: self.next_trace_id(),
                    event: AtpPathEventKind::FallbackSelected {
                        from_path: PathKind::NatPunchedUdp,
                        to_path: PathKind::AtpRelayUdp,
                        reason: "udp_blocked_direct_datagrams".to_string(),
                        relay_cost_micros: Some(55_000),
                    },
                });
                trace_events.push(AtpPathTraceEvent {
                    timestamp: self.next_timestamp(),
                    trace_id: self.next_trace_id(),
                    event: AtpPathEventKind::LoserPathDrained {
                        path_kind: PathKind::NatPunchedUdp,
                        reason: "direct_udp_candidate_failed_before_relay_selection".to_string(),
                    },
                });
            }
            AtpLabRegime::RelayOnly => {
                candidates_evaluated += self
                    .test_path_kind(PathKind::AtpRelayUdp, trace_events, validation)
                    .await?;
            }
            AtpLabRegime::RelayTcpTls443 => {
                candidates_evaluated += self
                    .test_path_kind(PathKind::AtpRelayTcpTls443, trace_events, validation)
                    .await?;
            }
            AtpLabRegime::TailscalePrivateRoute => {
                candidates_evaluated += self
                    .test_path_kind(PathKind::TailscaleIp, trace_events, validation)
                    .await?;
            }
            AtpLabRegime::MasqueConnectUdpProxy => {
                candidates_evaluated += self
                    .test_path_kind(PathKind::MasqueConnectUdp, trace_events, validation)
                    .await?;
            }
            AtpLabRegime::OfflineMailbox => {
                candidates_evaluated += self
                    .test_path_kind(PathKind::OfflineMailbox, trace_events, validation)
                    .await?;
            }
            AtpLabRegime::PathMigration => {
                // Test migration from LAN to IPv6
                self.test_path_migration(
                    PathKind::LanMulticast,
                    PathKind::PublicIpv6,
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
        trace_events: &mut Vec<AtpPathTraceEvent>,
        validation: &mut AtpPathValidation,
    ) -> Result<u32, AtpPathLabError> {
        trace_events.push(AtpPathTraceEvent {
            timestamp: self.next_timestamp(),
            trace_id: self.next_trace_id(),
            event: AtpPathEventKind::DiscoveryStarted {
                path_kind,
                nat_profile: validation.detected_nat_profile,
            },
        });

        trace_events.push(AtpPathTraceEvent {
            timestamp: self.next_timestamp(),
            trace_id: self.next_trace_id(),
            event: AtpPathEventKind::ConnectionAttempt {
                path_kind,
                target_endpoint: target_endpoint_for_path(path_kind).to_string(),
            },
        });

        // Evaluate path testing based on kind and network conditions.
        let success = match path_kind {
            PathKind::LanMulticast => {
                validation.lan_multicast_succeeded = true;
                true
            }
            PathKind::ExplicitPublicUdp => {
                validation.explicit_public_udp_succeeded = true;
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
            PathKind::AtpRelayUdp => {
                validation.relay_succeeded = true;
                true
            }
            PathKind::AtpRelayTcpTls443 => {
                validation.relay_succeeded = true;
                validation.relay_tcp_tls_443_succeeded = true;
                true
            }
            PathKind::MasqueConnectUdp => {
                validation.relay_succeeded = true;
                validation.masque_connect_udp_succeeded = true;
                true
            }
            PathKind::TailscaleIp => {
                validation.tailscale_private_route_succeeded = true;
                true
            }
            PathKind::OfflineMailbox => {
                validation.offline_mailbox_succeeded = true;
                true
            }
        };

        if success {
            trace_events.push(AtpPathTraceEvent {
                timestamp: self.next_timestamp(),
                trace_id: self.next_trace_id(),
                event: AtpPathEventKind::PathSucceeded {
                    path_kind,
                    latency_micros: 5000, // Deterministic 5ms latency.
                },
            });
        } else {
            let reason = match (path_kind, validation.detected_nat_profile) {
                (PathKind::NatPunchedUdp, NatProfile::UdpBlocked) => {
                    "UDP blocked direct datagrams before relay fallback"
                }
                (PathKind::NatPunchedUdp, NatProfile::HardSymmetricNat) => {
                    "Hard or symmetric NAT prevented hole punching"
                }
                _ => "Network conditions prevented connection",
            };
            trace_events.push(AtpPathTraceEvent {
                timestamp: self.next_timestamp(),
                trace_id: self.next_trace_id(),
                event: AtpPathEventKind::PathFailed {
                    path_kind,
                    reason: reason.to_string(),
                },
            });
        }

        Ok(1) // One candidate evaluated
    }

    async fn test_path_migration(
        &mut self,
        from_path: PathKind,
        to_path: PathKind,
        trace_events: &mut Vec<AtpPathTraceEvent>,
        validation: &mut AtpPathValidation,
    ) -> Result<(), AtpPathLabError> {
        // First establish the initial path
        self.test_path_kind(from_path, trace_events, validation)
            .await?;

        // Trigger modeled migration.
        trace_events.push(AtpPathTraceEvent {
            timestamp: self.next_timestamp(),
            trace_id: self.next_trace_id(),
            event: AtpPathEventKind::MigrationTriggered { from_path, to_path },
        });

        // Test the new path
        self.test_path_kind(to_path, trace_events, validation)
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
        } else if validation.explicit_public_udp_succeeded {
            Some(PathKind::ExplicitPublicUdp)
        } else if validation.lan_multicast_succeeded {
            Some(PathKind::LanMulticast)
        } else if validation.nat_punch_succeeded {
            Some(PathKind::NatPunchedUdp)
        } else if validation.tailscale_private_route_succeeded {
            Some(PathKind::TailscaleIp)
        } else if validation.masque_connect_udp_succeeded {
            Some(PathKind::MasqueConnectUdp)
        } else if validation.relay_tcp_tls_443_succeeded {
            Some(PathKind::AtpRelayTcpTls443)
        } else if validation.relay_succeeded {
            Some(PathKind::AtpRelayUdp)
        } else if validation.offline_mailbox_succeeded {
            Some(PathKind::OfflineMailbox)
        } else {
            None
        }
    }
}

fn target_endpoint_for_path(path_kind: PathKind) -> &'static str {
    if path_kind.uses_connect_udp_proxy() {
        "masque-connect-udp-proxy:443"
    } else {
        "virtual-endpoint"
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
            .with_regime(AtpLabRegime::LanMulticast)
            .with_regime(AtpLabRegime::EasyNat)
            .with_regime(AtpLabRegime::Ipv6Direct);

        let result = harness.execute_scenario(&scenario).await.unwrap();

        assert!(result.path_validation.transfer_succeeded());
        assert!(result.path_validation.lan_multicast_succeeded);
        assert!(result.path_validation.nat_punch_succeeded);
        assert!(result.path_validation.ipv6_direct_succeeded);
        assert_eq!(result.candidates_evaluated, 3);
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

    #[tokio::test]
    async fn test_masque_connect_udp_relay_adapter_path() {
        let mut harness = AtpPathLabHarness::new(AtpPathTestConfig::relay_only());

        let scenario = AtpLabScenario::new("masque-proxy", 0xA7F0_0007)
            .with_regime(AtpLabRegime::MasqueConnectUdpProxy);

        let result = harness.execute_scenario(&scenario).await.unwrap();

        assert!(result.path_validation.relay_succeeded);
        assert!(result.path_validation.masque_connect_udp_succeeded);
        assert!(!result.path_validation.has_direct_path());
        assert_eq!(
            result.path_validation.selected_path_kind,
            Some(PathKind::MasqueConnectUdp)
        );
        assert!(result.trace_events.iter().any(|event| matches!(
            &event.event,
            AtpPathEventKind::ConnectionAttempt {
                path_kind: PathKind::MasqueConnectUdp,
                target_endpoint,
            } if target_endpoint == "masque-connect-udp-proxy:443"
        )));
    }

    #[tokio::test]
    async fn test_path_migration_lan_to_ipv6() {
        let mut harness = AtpPathLabHarness::new(AtpPathTestConfig::lan_ipv6());

        let scenario = AtpLabScenario::new("path-migration", 0xA7F0_0008)
            .with_regime(AtpLabRegime::PathMigration);

        let result = harness.execute_scenario(&scenario).await.unwrap();

        assert!(result.path_validation.migration_preserved_transfer);
        assert!(result.path_validation.lan_multicast_succeeded);
        assert!(result.path_validation.ipv6_direct_succeeded);
        assert_eq!(result.candidates_evaluated, 2);

        // Verify migration trace events
        let migration_event = result
            .trace_events
            .iter()
            .find(|event| matches!(&event.event, AtpPathEventKind::MigrationTriggered { .. }));
        assert!(migration_event.is_some());

        if let Some(event) = migration_event {
            if let AtpPathEventKind::MigrationTriggered { from_path, to_path } = &event.event {
                assert_eq!(*from_path, PathKind::LanMulticast);
                assert_eq!(*to_path, PathKind::PublicIpv6);
            }
        }
    }

    #[tokio::test]
    async fn test_hard_symmetric_nat_behavior() {
        let mut harness = AtpPathLabHarness::new(AtpPathTestConfig::nat_stress());

        let scenario =
            AtpLabScenario::new("hard-nat", 0xA7F0_0009).with_regime(AtpLabRegime::SymmetricNat);

        let result = harness.execute_scenario(&scenario).await.unwrap();

        assert_eq!(
            result.path_validation.detected_nat_profile,
            NatProfile::HardSymmetricNat
        );
        assert!(!result.path_validation.nat_punch_succeeded);
        assert!(!result.path_validation.has_direct_path());

        // Verify failure trace event for NAT punching
        let failure_event = result.trace_events.iter().find(|event| {
            matches!(
                &event.event,
                AtpPathEventKind::PathFailed {
                    path_kind: PathKind::NatPunchedUdp,
                    reason,
                } if reason.contains("Hard or symmetric NAT prevented hole punching")
            )
        });
        assert!(failure_event.is_some());
    }

    #[tokio::test]
    async fn test_relay_tcp_tls_443_fallback() {
        let mut harness = AtpPathLabHarness::new(AtpPathTestConfig::relay_only());

        let scenario =
            AtpLabScenario::new("relay-tls", 0xA7F0_000A).with_regime(AtpLabRegime::RelayTcpTls443);

        let result = harness.execute_scenario(&scenario).await.unwrap();

        assert!(result.path_validation.relay_succeeded);
        assert!(result.path_validation.relay_tcp_tls_443_succeeded);
        assert_eq!(
            result.path_validation.selected_path_kind,
            Some(PathKind::AtpRelayTcpTls443)
        );

        // Verify connection attempt to correct path
        let connection_attempt = result.trace_events.iter().find(|event| {
            matches!(
                &event.event,
                AtpPathEventKind::ConnectionAttempt {
                    path_kind: PathKind::AtpRelayTcpTls443,
                    ..
                }
            )
        });
        assert!(connection_attempt.is_some());
    }

    #[tokio::test]
    async fn test_tailscale_private_route_success() {
        let mut harness = AtpPathLabHarness::new(AtpPathTestConfig::lan_ipv6());

        let scenario = AtpLabScenario::new("tailscale", 0xA7F0_000B)
            .with_regime(AtpLabRegime::TailscalePrivateRoute);

        let result = harness.execute_scenario(&scenario).await.unwrap();

        assert!(result.path_validation.tailscale_private_route_succeeded);
        assert!(result.path_validation.transfer_succeeded());
        assert_eq!(
            result.path_validation.selected_path_kind,
            Some(PathKind::TailscaleIp)
        );
    }

    #[tokio::test]
    async fn test_offline_mailbox_store_and_forward() {
        let mut harness = AtpPathLabHarness::new(AtpPathTestConfig::relay_only());

        let scenario = AtpLabScenario::new("offline-mailbox", 0xA7F0_000C)
            .with_regime(AtpLabRegime::OfflineMailbox);

        let result = harness.execute_scenario(&scenario).await.unwrap();

        assert!(result.path_validation.offline_mailbox_succeeded);
        assert!(result.path_validation.transfer_succeeded());
        assert_eq!(
            result.path_validation.selected_path_kind,
            Some(PathKind::OfflineMailbox)
        );

        // Verify transfer completion event
        let transfer_complete = result.trace_events.iter().find(|event| {
            matches!(
                &event.event,
                AtpPathEventKind::TransferCompleted {
                    selected_path: PathKind::OfflineMailbox,
                    bytes_transferred: 1048576, // 1MB
                }
            )
        });
        assert!(transfer_complete.is_some());
    }

    #[tokio::test]
    async fn test_explicit_public_udp_direct_path() {
        let mut harness = AtpPathLabHarness::new(AtpPathTestConfig::lan_ipv6());

        let scenario = AtpLabScenario::new("explicit-udp", 0xA7F0_000D)
            .with_regime(AtpLabRegime::ExplicitPublicUdp);

        let result = harness.execute_scenario(&scenario).await.unwrap();

        assert!(result.path_validation.explicit_public_udp_succeeded);
        assert!(result.path_validation.has_direct_path());
        assert_eq!(
            result.path_validation.selected_path_kind,
            Some(PathKind::ExplicitPublicUdp)
        );
    }

    #[tokio::test]
    async fn test_udp_blocked_fallback_with_loser_drain() {
        let mut harness = AtpPathLabHarness::new(AtpPathTestConfig::nat_stress());

        let scenario = AtpLabScenario::new("udp-blocked-drain", 0xA7F0_000E)
            .with_regime(AtpLabRegime::UdpBlocked);

        let result = harness.execute_scenario(&scenario).await.unwrap();

        assert_eq!(
            result.path_validation.detected_nat_profile,
            NatProfile::UdpBlocked
        );
        assert!(result.path_validation.relay_succeeded);

        // Verify fallback selection event
        let fallback_event = result.trace_events.iter().find(|event| {
            matches!(
                &event.event,
                AtpPathEventKind::FallbackSelected {
                    from_path: PathKind::NatPunchedUdp,
                    to_path: PathKind::AtpRelayUdp,
                    reason,
                    relay_cost_micros: Some(55_000),
                } if reason == "udp_blocked_direct_datagrams"
            )
        });
        assert!(fallback_event.is_some());

        // Verify loser drain event
        let drain_event = result.trace_events.iter().find(|event| {
            matches!(
                &event.event,
                AtpPathEventKind::LoserPathDrained {
                    path_kind: PathKind::NatPunchedUdp,
                    reason,
                } if reason == "direct_udp_candidate_failed_before_relay_selection"
            )
        });
        assert!(drain_event.is_some());
    }

    #[tokio::test]
    async fn test_path_selection_priority_order() {
        // Test that best path selection prioritizes direct paths over relay paths
        let validation = AtpPathValidation {
            ipv6_direct_succeeded: true,
            lan_multicast_succeeded: true,
            explicit_public_udp_succeeded: true,
            nat_punch_succeeded: true,
            relay_succeeded: true,
            relay_tcp_tls_443_succeeded: true,
            masque_connect_udp_succeeded: true,
            tailscale_private_route_succeeded: true,
            offline_mailbox_succeeded: true,
            migration_preserved_transfer: false,
            selected_path_kind: None,
            detected_nat_profile: NatProfile::Ipv6Direct,
        };

        let harness = AtpPathLabHarness::new(AtpPathTestConfig::lan_ipv6());
        let selected = harness.select_best_path(&validation);

        // IPv6 direct should be preferred over all other paths
        assert_eq!(selected, Some(PathKind::PublicIpv6));
    }

    #[tokio::test]
    async fn test_path_selection_relay_fallback_priority() {
        // Test relay path priority when no direct paths succeed
        let validation = AtpPathValidation {
            ipv6_direct_succeeded: false,
            lan_multicast_succeeded: false,
            explicit_public_udp_succeeded: false,
            nat_punch_succeeded: false,
            relay_succeeded: true,
            relay_tcp_tls_443_succeeded: true,
            masque_connect_udp_succeeded: true,
            tailscale_private_route_succeeded: true,
            offline_mailbox_succeeded: true,
            migration_preserved_transfer: false,
            selected_path_kind: None,
            detected_nat_profile: NatProfile::UdpBlocked,
        };

        let harness = AtpPathLabHarness::new(AtpPathTestConfig::relay_only());
        let selected = harness.select_best_path(&validation);

        // Tailscale private route should be preferred over relay paths
        assert_eq!(selected, Some(PathKind::TailscaleIp));
    }

    #[tokio::test]
    async fn test_target_endpoint_selection() {
        // Test endpoint selection for different path kinds
        assert_eq!(
            target_endpoint_for_path(PathKind::MasqueConnectUdp),
            "masque-connect-udp-proxy:443"
        );
        assert_eq!(
            target_endpoint_for_path(PathKind::LanMulticast),
            "virtual-endpoint"
        );
        assert_eq!(
            target_endpoint_for_path(PathKind::AtpRelayUdp),
            "virtual-endpoint"
        );
    }

    #[tokio::test]
    async fn test_trace_event_deterministic_timestamps() {
        let mut harness = AtpPathLabHarness::new(AtpPathTestConfig::lan_ipv6());

        let scenario = AtpLabScenario::new("timestamp-test", 0xA7F0_000F)
            .with_regime(AtpLabRegime::LanMulticast);

        let result = harness.execute_scenario(&scenario).await.unwrap();

        // Verify timestamps are monotonically increasing
        let mut prev_timestamp = Time::from_nanos(0);
        for event in &result.trace_events {
            assert!(event.timestamp >= prev_timestamp);
            prev_timestamp = event.timestamp;
        }

        // Verify all events have unique trace IDs
        let trace_ids: Vec<_> = result.trace_events.iter().map(|e| e.trace_id).collect();
        let mut unique_trace_ids = trace_ids.clone();
        unique_trace_ids.sort();
        unique_trace_ids.dedup();
        assert_eq!(trace_ids.len(), unique_trace_ids.len());
    }

    #[tokio::test]
    async fn test_comprehensive_trace_event_coverage() {
        let mut harness = AtpPathLabHarness::new(AtpPathTestConfig::nat_stress());

        let scenario = AtpLabScenario::new("comprehensive-trace", 0xA7F0_0010)
            .with_regime(AtpLabRegime::UdpBlocked);

        let result = harness.execute_scenario(&scenario).await.unwrap();

        // Verify we have all expected trace event types
        // Should have discovery started, connection attempt, path failed,
        // fallback selected, loser drained, and transfer completed events
        assert!(result.trace_events.len() >= 6);

        // Verify we have discovery started events
        assert!(
            result
                .trace_events
                .iter()
                .any(|e| matches!(&e.event, AtpPathEventKind::DiscoveryStarted { .. }))
        );

        // Verify we have connection attempt events
        assert!(
            result
                .trace_events
                .iter()
                .any(|e| matches!(&e.event, AtpPathEventKind::ConnectionAttempt { .. }))
        );

        // Verify we have path failed events
        assert!(
            result
                .trace_events
                .iter()
                .any(|e| matches!(&e.event, AtpPathEventKind::PathFailed { .. }))
        );
    }

    #[tokio::test]
    async fn test_multi_regime_scenario_execution() {
        let mut harness = AtpPathLabHarness::new(AtpPathTestConfig::nat_stress());

        let scenario = AtpLabScenario::new("multi-regime", 0xA7F0_0011)
            .with_regime(AtpLabRegime::LanMulticast)
            .with_regime(AtpLabRegime::EasyNat)
            .with_regime(AtpLabRegime::HardNat)
            .with_regime(AtpLabRegime::RelayOnly);

        let result = harness.execute_scenario(&scenario).await.unwrap();

        // Should have evaluated candidates from all regimes
        assert_eq!(result.candidates_evaluated, 4);

        // Should have succeeded with some paths
        assert!(result.path_validation.transfer_succeeded());

        // Verify NAT profile was detected from hard NAT regime
        assert_eq!(
            result.path_validation.detected_nat_profile,
            NatProfile::HardSymmetricNat
        );
    }

    #[tokio::test]
    async fn test_config_variations() {
        // Test different configuration presets
        let lan_config = AtpPathTestConfig::lan_ipv6();
        assert!(lan_config.enable_path_tracing);
        assert_eq!(lan_config.path_discovery_timeout, Duration::from_secs(30));
        assert!(!lan_config.enable_migration);

        let nat_config = AtpPathTestConfig::nat_stress();
        assert!(nat_config.enable_path_tracing);
        assert_eq!(nat_config.path_discovery_timeout, Duration::from_secs(60));
        assert!(nat_config.enable_migration);

        let relay_config = AtpPathTestConfig::relay_only();
        assert!(relay_config.enable_path_tracing);
        assert_eq!(relay_config.path_discovery_timeout, Duration::from_secs(45));
        assert!(!relay_config.enable_migration);
    }

    #[tokio::test]
    async fn test_path_validation_edge_cases() {
        // Test failed validation
        let failed = AtpPathValidation::failed();
        assert!(!failed.has_direct_path());
        assert!(!failed.transfer_succeeded());
        assert_eq!(failed.selected_path_kind, None);
        assert_eq!(failed.detected_nat_profile, NatProfile::Unknown);

        // Test partial success scenarios
        let mut partial = AtpPathValidation::failed();
        partial.relay_succeeded = true;
        partial.selected_path_kind = Some(PathKind::AtpRelayUdp);
        assert!(!partial.has_direct_path());
        assert!(partial.transfer_succeeded());

        // Test migration success
        let mut with_migration = AtpPathValidation::failed();
        with_migration.lan_multicast_succeeded = true;
        with_migration.ipv6_direct_succeeded = true;
        with_migration.migration_preserved_transfer = true;
        with_migration.selected_path_kind = Some(PathKind::PublicIpv6);
        assert!(with_migration.has_direct_path());
        assert!(with_migration.transfer_succeeded());
    }
}
