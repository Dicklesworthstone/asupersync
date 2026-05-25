//! Deterministic ATP lab models for network, disk, crash, and adversary cases.
//!
//! The model is intentionally endpoint-free: it produces replayable scenario
//! plans and failure artifacts that transfer tests can consume without using
//! real sockets, real disks, or process crashes.

use crate::util::DetRng;
use sha2::{Digest, Sha256};

/// Schema version for serialized ATP lab artifacts.
pub const ATP_LAB_MODEL_SCHEMA_VERSION: u32 = 1;

/// Deterministic ATP transfer scenario.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AtpLabScenario {
    /// Stable human-readable scenario name.
    pub name: String,
    /// Fixed seed that drives all generated events.
    pub seed: u64,
    /// Fault regimes included in this scenario.
    pub regimes: Vec<AtpLabRegime>,
    /// Oracle toggles to apply when tests execute the plan.
    pub oracle_config: AtpLabOracleConfig,
}

impl AtpLabScenario {
    /// Create an empty scenario with a fixed seed.
    #[must_use]
    pub fn new(name: impl Into<String>, seed: u64) -> Self {
        Self {
            name: name.into(),
            seed,
            regimes: Vec::new(),
            oracle_config: AtpLabOracleConfig::default(),
        }
    }

    /// Add one regime.
    #[must_use]
    pub fn with_regime(mut self, regime: AtpLabRegime) -> Self {
        self.regimes.push(regime);
        self
    }

    /// Enable futurelock and leak oracles.
    #[must_use]
    pub fn with_futurelock_and_leak_oracles(mut self) -> Self {
        self.oracle_config.futurelock = true;
        self.oracle_config.task_leak = true;
        self.oracle_config.obligation_leak = true;
        self.oracle_config.region_leak = true;
        self
    }

    /// Enable retained failure artifacts.
    #[must_use]
    pub fn with_artifact_retention(mut self) -> Self {
        self.oracle_config.preserve_failure_artifacts = true;
        self
    }

    /// Compose this scenario with one transfer specification.
    #[must_use]
    pub fn compose(self, transfer: AtpLabTransferSpec) -> AtpTransferLabPlan {
        let events = generate_events(&self, &transfer);
        let replay = AtpLabReplayMetadata::from_parts(&self, &transfer, &events);
        AtpTransferLabPlan {
            scenario: self,
            transfer,
            events,
            replay,
        }
    }

    /// Return the required ATP-L1 coverage matrix.
    #[must_use]
    pub fn required_matrix() -> Vec<Self> {
        vec![
            Self::new("easy-nat-direct", 0xA7F0_0001)
                .with_regime(AtpLabRegime::LanMulticast)
                .with_regime(AtpLabRegime::EasyNat)
                .with_regime(AtpLabRegime::ExplicitPublicUdp)
                .with_regime(AtpLabRegime::Ipv6Direct),
            Self::new("hard-nat-relay", 0xA7F0_0002)
                .with_regime(AtpLabRegime::HardNat)
                .with_regime(AtpLabRegime::SymmetricNat)
                .with_regime(AtpLabRegime::RelayOnly)
                .with_regime(AtpLabRegime::RelayTcpTls443),
            Self::new("udp-blocked-private-route", 0xA7F0_0003)
                .with_regime(AtpLabRegime::UdpBlocked)
                .with_regime(AtpLabRegime::TailscalePrivateRoute),
            Self::new("enterprise-masque-connect-udp", 0xA7F0_0007)
                .with_regime(AtpLabRegime::UdpBlocked)
                .with_regime(AtpLabRegime::MasqueConnectUdpProxy),
            Self::new("mailbox-only-store-forward", 0xA7F0_0008)
                .with_regime(AtpLabRegime::UdpBlocked)
                .with_regime(AtpLabRegime::OfflineMailbox),
            Self::new("path-migration-loss", 0xA7F0_0004)
                .with_regime(AtpLabRegime::PathMigration)
                .with_regime(AtpLabRegime::PacketDuplication)
                .with_regime(AtpLabRegime::DelayedAck)
                .with_regime(AtpLabRegime::AckLoss)
                .with_regime(AtpLabRegime::PtoStorm),
            Self::new("disk-crash-replay", 0xA7F0_0005)
                .with_regime(AtpLabRegime::DiskStall)
                .with_regime(AtpLabRegime::Crash)
                .with_artifact_retention(),
            Self::new("adversarial-relay-repair", 0xA7F0_0006)
                .with_regime(AtpLabRegime::PacketTruncation)
                .with_regime(AtpLabRegime::MaliciousChunks)
                .with_regime(AtpLabRegime::CorruptedRepairSymbols)
                .with_regime(AtpLabRegime::LyingRelay)
                .with_regime(AtpLabRegime::StalledReceiver)
                .with_regime(AtpLabRegime::Cancellation)
                .with_futurelock_and_leak_oracles()
                .with_artifact_retention(),
        ]
    }
}

/// One transfer shape that can be combined with ATP lab regimes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AtpLabTransferSpec {
    /// Stable source endpoint label.
    pub source: String,
    /// Stable destination endpoint label.
    pub destination: String,
    /// Logical bytes in the transfer.
    pub bytes: u64,
    /// Number of manifest objects in the transfer.
    pub object_count: u64,
}

impl AtpLabTransferSpec {
    /// Create a transfer spec.
    #[must_use]
    pub fn new(
        source: impl Into<String>,
        destination: impl Into<String>,
        bytes: u64,
        object_count: u64,
    ) -> Self {
        Self {
            source: source.into(),
            destination: destination.into(),
            bytes,
            object_count,
        }
    }
}

/// Composed transfer lab plan.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AtpTransferLabPlan {
    /// Scenario model.
    pub scenario: AtpLabScenario,
    /// Transfer under test.
    pub transfer: AtpLabTransferSpec,
    /// Deterministic event script.
    pub events: Vec<AtpLabEvent>,
    /// Replay metadata for this exact plan.
    pub replay: AtpLabReplayMetadata,
}

impl AtpTransferLabPlan {
    /// Execute the model and produce an artifact bundle.
    #[must_use]
    pub fn run_model(&self) -> AtpLabArtifact {
        let failure = self
            .events
            .iter()
            .find(|event| event.fault.is_failure())
            .map(|event| AtpLabFailure {
                step: event.step,
                fault: event.fault.clone(),
                replay_hint: format!(
                    "replay {} from seed {} at step {}",
                    self.replay.minimization_key, self.replay.seed, event.step
                ),
            });

        let attachments =
            if failure.is_some() && self.scenario.oracle_config.preserve_failure_artifacts {
                vec![
                    AtpLabAttachment::from_text(
                        "events.txt",
                        self.events
                            .iter()
                            .map(AtpLabEvent::artifact_line)
                            .collect::<Vec<_>>()
                            .join("\n"),
                    ),
                    AtpLabAttachment::from_text("replay.txt", self.replay.replay_command.clone()),
                ]
            } else {
                Vec::new()
            };

        AtpLabArtifact {
            replay: self.replay.clone(),
            oracle_config: self.scenario.oracle_config.clone(),
            events: self.events.clone(),
            failure,
            attachments,
        }
    }
}

/// Fault regimes that ATP transfer tests can compose.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum AtpLabRegime {
    /// LAN multicast or same-link local discovery is available.
    LanMulticast,
    /// Easy endpoint-independent NAT.
    EasyNat,
    /// Explicit user-provided public UDP endpoint is available.
    ExplicitPublicUdp,
    /// Hard port-restricted NAT.
    HardNat,
    /// Symmetric NAT.
    SymmetricNat,
    /// UDP is blocked and direct datagrams fail.
    UdpBlocked,
    /// IPv6 direct path is available.
    Ipv6Direct,
    /// Relay is the only viable path.
    RelayOnly,
    /// UDP-hostile network requires ATP relay over TCP/TLS 443.
    RelayTcpTls443,
    /// Tailscale-like private route is available.
    TailscalePrivateRoute,
    /// MASQUE/CONNECT-UDP proxy is available for enterprise egress.
    MasqueConnectUdpProxy,
    /// Store-and-forward encrypted mailbox is the only viable path.
    OfflineMailbox,
    /// Active path migration occurs mid-transfer.
    PathMigration,
    /// Packets may be duplicated.
    PacketDuplication,
    /// Packets may be truncated.
    PacketTruncation,
    /// ACKs are delayed.
    DelayedAck,
    /// ACKs are lost.
    AckLoss,
    /// Probe timeout storms are injected.
    PtoStorm,
    /// Disk writes stall.
    DiskStall,
    /// Crash and restart occurs.
    Crash,
    /// Malicious chunks are injected.
    MaliciousChunks,
    /// Repair symbols are corrupted.
    CorruptedRepairSymbols,
    /// Relay lies about delivery or availability.
    LyingRelay,
    /// Receiver stops draining.
    StalledReceiver,
    /// Cancellation is requested during transfer.
    Cancellation,
}

impl AtpLabRegime {
    /// Stable regime label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::LanMulticast => "lan_multicast",
            Self::EasyNat => "easy_nat",
            Self::ExplicitPublicUdp => "explicit_public_udp",
            Self::HardNat => "hard_nat",
            Self::SymmetricNat => "symmetric_nat",
            Self::UdpBlocked => "udp_blocked",
            Self::Ipv6Direct => "ipv6_direct",
            Self::RelayOnly => "relay_only",
            Self::RelayTcpTls443 => "relay_tcp_tls_443",
            Self::TailscalePrivateRoute => "tailscale_private_route",
            Self::MasqueConnectUdpProxy => "masque_connect_udp_proxy",
            Self::OfflineMailbox => "offline_mailbox",
            Self::PathMigration => "path_migration",
            Self::PacketDuplication => "packet_duplication",
            Self::PacketTruncation => "packet_truncation",
            Self::DelayedAck => "delayed_ack",
            Self::AckLoss => "ack_loss",
            Self::PtoStorm => "pto_storm",
            Self::DiskStall => "disk_stall",
            Self::Crash => "crash",
            Self::MaliciousChunks => "malicious_chunks",
            Self::CorruptedRepairSymbols => "corrupted_repair_symbols",
            Self::LyingRelay => "lying_relay",
            Self::StalledReceiver => "stalled_receiver",
            Self::Cancellation => "cancellation",
        }
    }
}

/// Concrete fault emitted into an event script.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AtpLabFault {
    /// Direct path is allowed.
    DirectPath,
    /// Explicit public UDP path is selected.
    ExplicitPublicUdpPath,
    /// Direct path is denied.
    DirectPathBlocked,
    /// Relay path is selected.
    RelayPath,
    /// Relay over TCP/TLS 443 is selected.
    RelayTcpTls443Path,
    /// Private route is selected.
    PrivateRoute,
    /// MASQUE/CONNECT-UDP proxy path is selected.
    MasqueProxyPath,
    /// Offline mailbox path is selected.
    OfflineMailboxPath,
    /// Path migration is triggered.
    PathMigrated,
    /// Packet duplication occurs.
    PacketDuplicated,
    /// Packet truncation occurs.
    PacketTruncated,
    /// ACK is delayed by this many microseconds.
    AckDelayed { micros: u64 },
    /// ACK is dropped.
    AckLost,
    /// Probe timeout burst count.
    PtoStorm { bursts: u8 },
    /// Disk stall duration.
    DiskStall { micros: u64 },
    /// Crash occurs and restarts after this many microseconds.
    Crash { restart_after_micros: u64 },
    /// Malicious data chunk is injected.
    MaliciousChunk,
    /// Repair symbol is corrupted.
    CorruptedRepairSymbol,
    /// Relay lies.
    LyingRelay,
    /// Receiver stalls for this many microseconds.
    StalledReceiver { micros: u64 },
    /// Cancellation is requested.
    CancellationRequested,
}

impl AtpLabFault {
    fn is_failure(&self) -> bool {
        matches!(
            self,
            Self::PacketTruncated
                | Self::Crash { .. }
                | Self::MaliciousChunk
                | Self::CorruptedRepairSymbol
                | Self::LyingRelay
                | Self::StalledReceiver { .. }
                | Self::CancellationRequested
        )
    }

    fn label(&self) -> &'static str {
        match self {
            Self::DirectPath => "direct_path",
            Self::ExplicitPublicUdpPath => "explicit_public_udp_path",
            Self::DirectPathBlocked => "direct_path_blocked",
            Self::RelayPath => "relay_path",
            Self::RelayTcpTls443Path => "relay_tcp_tls_443_path",
            Self::PrivateRoute => "private_route",
            Self::MasqueProxyPath => "masque_proxy_path",
            Self::OfflineMailboxPath => "offline_mailbox_path",
            Self::PathMigrated => "path_migrated",
            Self::PacketDuplicated => "packet_duplicated",
            Self::PacketTruncated => "packet_truncated",
            Self::AckDelayed { .. } => "ack_delayed",
            Self::AckLost => "ack_lost",
            Self::PtoStorm { .. } => "pto_storm",
            Self::DiskStall { .. } => "disk_stall",
            Self::Crash { .. } => "crash",
            Self::MaliciousChunk => "malicious_chunk",
            Self::CorruptedRepairSymbol => "corrupted_repair_symbol",
            Self::LyingRelay => "lying_relay",
            Self::StalledReceiver { .. } => "stalled_receiver",
            Self::CancellationRequested => "cancellation_requested",
        }
    }
}

/// One deterministic ATP lab event.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AtpLabEvent {
    /// Monotonic event index.
    pub step: u64,
    /// Virtual time in microseconds.
    pub tick_micros: u64,
    /// Regime that generated the event.
    pub regime: AtpLabRegime,
    /// Concrete fault.
    pub fault: AtpLabFault,
}

impl AtpLabEvent {
    fn artifact_line(&self) -> String {
        format!(
            "step={} tick={} regime={} fault={}",
            self.step,
            self.tick_micros,
            self.regime.label(),
            self.fault.label()
        )
    }
}

/// Oracle toggles for ATP lab executions.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AtpLabOracleConfig {
    /// Enable futurelock detection.
    pub futurelock: bool,
    /// Enable task leak detection.
    pub task_leak: bool,
    /// Enable obligation leak detection.
    pub obligation_leak: bool,
    /// Enable region leak detection.
    pub region_leak: bool,
    /// Preserve failure artifacts.
    pub preserve_failure_artifacts: bool,
    /// Enable minimization metadata.
    pub minimization: bool,
}

impl Default for AtpLabOracleConfig {
    fn default() -> Self {
        Self {
            futurelock: false,
            task_leak: true,
            obligation_leak: true,
            region_leak: true,
            preserve_failure_artifacts: true,
            minimization: true,
        }
    }
}

/// Replay metadata for a lab plan.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AtpLabReplayMetadata {
    /// Artifact schema version.
    pub schema_version: u32,
    /// Fixed scenario seed.
    pub seed: u64,
    /// Scenario name.
    pub scenario_name: String,
    /// Stable fingerprint for events and transfer shape.
    pub fingerprint_hex: String,
    /// Minimization key for this scenario.
    pub minimization_key: String,
    /// Human-readable replay command.
    pub replay_command: String,
}

impl AtpLabReplayMetadata {
    fn from_parts(
        scenario: &AtpLabScenario,
        transfer: &AtpLabTransferSpec,
        events: &[AtpLabEvent],
    ) -> Self {
        let fingerprint_hex = fingerprint_hex(scenario, transfer, events);
        let minimization_key = format!("atp-lab-{}-{}", scenario.name, &fingerprint_hex[..12]);
        Self {
            schema_version: ATP_LAB_MODEL_SCHEMA_VERSION,
            seed: scenario.seed,
            scenario_name: scenario.name.clone(),
            fingerprint_hex,
            replay_command: format!(
                "cargo test -p asupersync atp_lab -- --exact {}",
                scenario.name
            ),
            minimization_key,
        }
    }
}

/// Preserved failure artifact.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AtpLabAttachment {
    /// Artifact name.
    pub name: String,
    /// Artifact size in bytes.
    pub byte_len: u64,
    /// SHA-256 digest of artifact contents.
    pub sha256_hex: String,
    /// UTF-8 text retained for deterministic tests.
    pub text: String,
}

impl AtpLabAttachment {
    fn from_text(name: impl Into<String>, text: String) -> Self {
        let digest = Sha256::digest(text.as_bytes());
        Self {
            name: name.into(),
            byte_len: u64::try_from(text.len()).unwrap_or(u64::MAX),
            sha256_hex: hex::encode(digest),
            text,
        }
    }
}

/// Failure summary for replay and minimization.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AtpLabFailure {
    /// Step where failure surfaced.
    pub step: u64,
    /// Fault that caused the failure.
    pub fault: AtpLabFault,
    /// Replay hint.
    pub replay_hint: String,
}

/// Complete ATP lab artifact.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AtpLabArtifact {
    /// Replay metadata.
    pub replay: AtpLabReplayMetadata,
    /// Oracle toggles used by the run.
    pub oracle_config: AtpLabOracleConfig,
    /// Event script.
    pub events: Vec<AtpLabEvent>,
    /// Failure, if one occurred.
    pub failure: Option<AtpLabFailure>,
    /// Retained artifacts.
    pub attachments: Vec<AtpLabAttachment>,
}

fn generate_events(scenario: &AtpLabScenario, transfer: &AtpLabTransferSpec) -> Vec<AtpLabEvent> {
    let mut rng = DetRng::new(scenario.seed ^ transfer.bytes ^ transfer.object_count);
    let mut events = Vec::new();
    for regime in &scenario.regimes {
        let step = u64::try_from(events.len()).unwrap_or(u64::MAX);
        let jitter = rng.next_u64() % 997;
        let tick_micros = step.saturating_mul(10_000).saturating_add(jitter);
        events.push(AtpLabEvent {
            step,
            tick_micros,
            regime: *regime,
            fault: fault_for_regime(*regime, &mut rng),
        });
    }
    events
}

fn fault_for_regime(regime: AtpLabRegime, rng: &mut DetRng) -> AtpLabFault {
    match regime {
        AtpLabRegime::LanMulticast | AtpLabRegime::EasyNat | AtpLabRegime::Ipv6Direct => {
            AtpLabFault::DirectPath
        }
        AtpLabRegime::ExplicitPublicUdp => AtpLabFault::ExplicitPublicUdpPath,
        AtpLabRegime::HardNat | AtpLabRegime::SymmetricNat | AtpLabRegime::UdpBlocked => {
            AtpLabFault::DirectPathBlocked
        }
        AtpLabRegime::RelayOnly => AtpLabFault::RelayPath,
        AtpLabRegime::RelayTcpTls443 => AtpLabFault::RelayTcpTls443Path,
        AtpLabRegime::TailscalePrivateRoute => AtpLabFault::PrivateRoute,
        AtpLabRegime::MasqueConnectUdpProxy => AtpLabFault::MasqueProxyPath,
        AtpLabRegime::OfflineMailbox => AtpLabFault::OfflineMailboxPath,
        AtpLabRegime::PathMigration => AtpLabFault::PathMigrated,
        AtpLabRegime::PacketDuplication => AtpLabFault::PacketDuplicated,
        AtpLabRegime::PacketTruncation => AtpLabFault::PacketTruncated,
        AtpLabRegime::DelayedAck => AtpLabFault::AckDelayed {
            micros: 5_000 + (rng.next_u64() % 20_000),
        },
        AtpLabRegime::AckLoss => AtpLabFault::AckLost,
        AtpLabRegime::PtoStorm => AtpLabFault::PtoStorm {
            bursts: 1 + u8::try_from(rng.next_u64() % 4).unwrap_or(0),
        },
        AtpLabRegime::DiskStall => AtpLabFault::DiskStall {
            micros: 50_000 + (rng.next_u64() % 500_000),
        },
        AtpLabRegime::Crash => AtpLabFault::Crash {
            restart_after_micros: 100_000 + (rng.next_u64() % 1_000_000),
        },
        AtpLabRegime::MaliciousChunks => AtpLabFault::MaliciousChunk,
        AtpLabRegime::CorruptedRepairSymbols => AtpLabFault::CorruptedRepairSymbol,
        AtpLabRegime::LyingRelay => AtpLabFault::LyingRelay,
        AtpLabRegime::StalledReceiver => AtpLabFault::StalledReceiver {
            micros: 250_000 + (rng.next_u64() % 750_000),
        },
        AtpLabRegime::Cancellation => AtpLabFault::CancellationRequested,
    }
}

fn fingerprint_hex(
    scenario: &AtpLabScenario,
    transfer: &AtpLabTransferSpec,
    events: &[AtpLabEvent],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(ATP_LAB_MODEL_SCHEMA_VERSION.to_be_bytes());
    hasher.update(scenario.name.as_bytes());
    hasher.update(scenario.seed.to_be_bytes());
    hasher.update(transfer.source.as_bytes());
    hasher.update(transfer.destination.as_bytes());
    hasher.update(transfer.bytes.to_be_bytes());
    hasher.update(transfer.object_count.to_be_bytes());
    for event in events {
        hasher.update(event.step.to_be_bytes());
        hasher.update(event.tick_micros.to_be_bytes());
        hasher.update(event.regime.label().as_bytes());
        hasher.update(event.fault.label().as_bytes());
    }
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn transfer() -> AtpLabTransferSpec {
        AtpLabTransferSpec::new("alice-laptop", "gpu-box", 8 * 1024 * 1024, 3)
    }

    #[test]
    fn required_matrix_covers_acceptance_regimes() {
        let covered: BTreeSet<_> = AtpLabScenario::required_matrix()
            .into_iter()
            .flat_map(|scenario| scenario.regimes)
            .collect();
        let required = BTreeSet::from([
            AtpLabRegime::LanMulticast,
            AtpLabRegime::EasyNat,
            AtpLabRegime::ExplicitPublicUdp,
            AtpLabRegime::HardNat,
            AtpLabRegime::SymmetricNat,
            AtpLabRegime::UdpBlocked,
            AtpLabRegime::Ipv6Direct,
            AtpLabRegime::RelayOnly,
            AtpLabRegime::RelayTcpTls443,
            AtpLabRegime::TailscalePrivateRoute,
            AtpLabRegime::MasqueConnectUdpProxy,
            AtpLabRegime::OfflineMailbox,
            AtpLabRegime::PathMigration,
            AtpLabRegime::PacketDuplication,
            AtpLabRegime::PacketTruncation,
            AtpLabRegime::DelayedAck,
            AtpLabRegime::AckLoss,
            AtpLabRegime::PtoStorm,
            AtpLabRegime::DiskStall,
            AtpLabRegime::Crash,
            AtpLabRegime::MaliciousChunks,
            AtpLabRegime::CorruptedRepairSymbols,
            AtpLabRegime::LyingRelay,
            AtpLabRegime::StalledReceiver,
            AtpLabRegime::Cancellation,
        ]);
        assert_eq!(covered, required);
    }

    #[test]
    fn composed_transfer_plan_is_deterministic() {
        let scenario = AtpLabScenario::new("path-migration", 42)
            .with_regime(AtpLabRegime::PathMigration)
            .with_regime(AtpLabRegime::AckLoss);
        let first = scenario.clone().compose(transfer());
        let second = scenario.compose(transfer());
        assert_eq!(first.events, second.events);
        assert_eq!(first.replay.fingerprint_hex, second.replay.fingerprint_hex);
    }

    #[test]
    fn futurelock_and_leak_oracles_can_be_enabled() {
        let scenario = AtpLabScenario::new("oracles", 7).with_futurelock_and_leak_oracles();
        assert!(scenario.oracle_config.futurelock);
        assert!(scenario.oracle_config.task_leak);
        assert!(scenario.oracle_config.obligation_leak);
        assert!(scenario.oracle_config.region_leak);
    }

    #[test]
    fn failure_preserves_replay_and_minimization_artifacts() {
        let plan = AtpLabScenario::new("adversary", 99)
            .with_regime(AtpLabRegime::LyingRelay)
            .with_artifact_retention()
            .compose(transfer());
        let artifact = plan.run_model();
        assert!(artifact.failure.is_some());
        assert_eq!(artifact.attachments.len(), 2);
        assert!(
            artifact
                .replay
                .minimization_key
                .starts_with("atp-lab-adversary")
        );
        assert!(artifact.attachments[0].text.contains("fault=lying_relay"));
    }

    #[test]
    fn masque_proxy_regime_emits_non_failure_adapter_event() {
        let plan = AtpLabScenario::new("masque-proxy", 0xA7F0_0007)
            .with_regime(AtpLabRegime::MasqueConnectUdpProxy)
            .compose(transfer());

        assert_eq!(plan.events.len(), 1);
        assert_eq!(plan.events[0].fault, AtpLabFault::MasqueProxyPath);
        assert_eq!(plan.events[0].fault.label(), "masque_proxy_path");
        assert!(plan.run_model().failure.is_none());
    }
}
