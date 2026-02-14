//! FrankenLab scenario format (bd-1hu19.1).
//!
//! A scenario file describes a deterministic test execution:
//! participants, fault schedule, assertions, seed, and virtual time
//! configuration.  The canonical on-disk format is YAML, but JSON and
//! TOML roundtrip cleanly via serde.
//!
//! # Format overview
//!
//! ```yaml
//! schema_version: 1
//! id: smoke-sendpermit-ack
//! description: Happy-path SendPermit/Ack under light chaos
//!
//! lab:
//!   seed: 42
//!   worker_count: 2
//!   trace_capacity: 8192
//!   max_steps: 100000
//!   panic_on_obligation_leak: true
//!   panic_on_futurelock: true
//!   futurelock_max_idle_steps: 10000
//!
//! chaos:
//!   preset: light           # off | light | heavy | custom
//!
//! network:
//!   preset: lan             # ideal | local | lan | wan | satellite | congested | lossy
//!
//! faults:
//!   - at_ms: 100
//!     action: partition
//!     args: { from: alice, to: bob }
//!   - at_ms: 500
//!     action: heal
//!     args: { from: alice, to: bob }
//!
//! participants:
//!   - name: alice
//!     role: sender
//!   - name: bob
//!     role: receiver
//!
//! oracles:
//!   - all
//!
//! cancellation:
//!   strategy: random_sample
//!   count: 100
//! ```
//!
//! # Composability
//!
//! Scenarios may include other scenarios via `include`:
//!
//! ```yaml
//! include:
//!   - path: base_config.yaml
//! ```
//!
//! Included fields are merged with the current file; the current file
//! wins on conflict.
//!
//! # Determinism
//!
//! All randomness is seeded via `lab.seed`.  Given the same YAML + the
//! same runtime binary, execution is bit-identical.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Top-level scenario
// ---------------------------------------------------------------------------

/// Current scenario schema version.
pub const SCENARIO_SCHEMA_VERSION: u32 = 1;

/// A complete FrankenLab test scenario.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scenario {
    /// Schema version (must be 1).
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,

    /// Stable, unique scenario identifier (e.g. `"smoke-sendpermit-ack"`).
    pub id: String,

    /// Human-readable description.
    #[serde(default)]
    pub description: String,

    /// Lab runtime configuration.
    #[serde(default)]
    pub lab: LabSection,

    /// Chaos injection configuration.
    #[serde(default)]
    pub chaos: ChaosSection,

    /// Network simulation configuration.
    #[serde(default)]
    pub network: NetworkSection,

    /// Timed fault injection events.
    #[serde(default)]
    pub faults: Vec<FaultEvent>,

    /// Named participants (actors/tasks).
    #[serde(default)]
    pub participants: Vec<Participant>,

    /// Oracle names to enable.  `["all"]` enables every oracle.
    #[serde(default = "default_oracles")]
    pub oracles: Vec<String>,

    /// Cancellation injection strategy.
    #[serde(default)]
    pub cancellation: Option<CancellationSection>,

    /// Optional includes (for composability).
    #[serde(default)]
    pub include: Vec<IncludeRef>,

    /// Arbitrary key-value metadata (git sha, author, tags).
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

fn default_schema_version() -> u32 {
    SCENARIO_SCHEMA_VERSION
}

fn default_oracles() -> Vec<String> {
    vec!["all".to_string()]
}

// ---------------------------------------------------------------------------
// Lab section
// ---------------------------------------------------------------------------

/// Lab runtime knobs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabSection {
    /// PRNG seed for deterministic scheduling.
    #[serde(default = "default_seed")]
    pub seed: u64,

    /// Optional separate entropy seed (defaults to `seed`).
    pub entropy_seed: Option<u64>,

    /// Number of virtual workers.
    #[serde(default = "default_worker_count")]
    pub worker_count: usize,

    /// Trace event buffer capacity.
    #[serde(default = "default_trace_capacity")]
    pub trace_capacity: usize,

    /// Maximum scheduler steps before forced termination.
    #[serde(default = "default_max_steps")]
    pub max_steps: Option<u64>,

    /// Panic on obligation leak.
    #[serde(default = "default_true")]
    pub panic_on_obligation_leak: bool,

    /// Panic on futurelock detection.
    #[serde(default = "default_true")]
    pub panic_on_futurelock: bool,

    /// Idle steps before futurelock fires.
    #[serde(default = "default_futurelock_max_idle")]
    pub futurelock_max_idle_steps: u64,

    /// Enable replay recording.
    #[serde(default)]
    pub replay_recording: bool,
}

impl Default for LabSection {
    fn default() -> Self {
        Self {
            seed: 42,
            entropy_seed: None,
            worker_count: 1,
            trace_capacity: 4096,
            max_steps: Some(100_000),
            panic_on_obligation_leak: true,
            panic_on_futurelock: true,
            futurelock_max_idle_steps: 10_000,
            replay_recording: false,
        }
    }
}

fn default_seed() -> u64 {
    42
}
fn default_worker_count() -> usize {
    1
}
fn default_trace_capacity() -> usize {
    4096
}
#[allow(clippy::unnecessary_wraps)]
fn default_max_steps() -> Option<u64> {
    Some(100_000)
}
fn default_true() -> bool {
    true
}
fn default_futurelock_max_idle() -> u64 {
    10_000
}

// ---------------------------------------------------------------------------
// Chaos section
// ---------------------------------------------------------------------------

/// Chaos injection configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(tag = "preset", rename_all = "snake_case")]
pub enum ChaosSection {
    /// Chaos disabled.
    #[default]
    Off,
    /// CI-friendly defaults (1% cancel, 5% delay, 2% I/O error).
    Light,
    /// Thorough testing (10% cancel, 20% delay, 15% I/O error).
    Heavy,
    /// Fully specified probabilities.
    Custom {
        /// Cancellation injection probability (0.0-1.0).
        #[serde(default)]
        cancel_probability: f64,
        /// Delay injection probability (0.0-1.0).
        #[serde(default)]
        delay_probability: f64,
        /// Minimum injected delay (milliseconds).
        #[serde(default)]
        delay_min_ms: u64,
        /// Maximum injected delay (milliseconds).
        #[serde(default = "default_delay_max_ms")]
        delay_max_ms: u64,
        /// I/O error injection probability (0.0-1.0).
        #[serde(default)]
        io_error_probability: f64,
        /// Wakeup storm probability (0.0-1.0).
        #[serde(default)]
        wakeup_storm_probability: f64,
        /// Budget exhaustion probability (0.0-1.0).
        #[serde(default)]
        budget_exhaustion_probability: f64,
    },
}

fn default_delay_max_ms() -> u64 {
    10
}

// ---------------------------------------------------------------------------
// Network section
// ---------------------------------------------------------------------------

/// Network simulation configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSection {
    /// Preset network conditions.
    #[serde(default = "default_network_preset")]
    pub preset: NetworkPreset,

    /// Per-link overrides (key = "alice->bob").
    #[serde(default)]
    pub links: BTreeMap<String, LinkConditions>,
}

impl Default for NetworkSection {
    fn default() -> Self {
        Self {
            preset: NetworkPreset::Ideal,
            links: BTreeMap::new(),
        }
    }
}

fn default_network_preset() -> NetworkPreset {
    NetworkPreset::Ideal
}

/// Named network condition presets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPreset {
    /// No latency, loss, or corruption.
    Ideal,
    /// ~1ms latency.
    Local,
    /// 1-5ms latency, 0.01% loss.
    Lan,
    /// 20-100ms latency, 0.1% loss.
    Wan,
    /// ~600ms latency, 1% loss.
    Satellite,
    /// ~100ms latency with congestion effects.
    Congested,
    /// 10% packet loss.
    Lossy,
}

/// Per-link network condition overrides.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkConditions {
    /// Latency model.
    #[serde(default)]
    pub latency: Option<LatencySpec>,
    /// Packet loss probability (0.0-1.0).
    #[serde(default)]
    pub packet_loss: Option<f64>,
    /// Packet corruption probability (0.0-1.0).
    #[serde(default)]
    pub packet_corrupt: Option<f64>,
    /// Packet duplication probability (0.0-1.0).
    #[serde(default)]
    pub packet_duplicate: Option<f64>,
    /// Packet reordering probability (0.0-1.0).
    #[serde(default)]
    pub packet_reorder: Option<f64>,
    /// Bandwidth limit (bytes/second).
    #[serde(default)]
    pub bandwidth: Option<u64>,
}

/// Latency model specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "model", rename_all = "snake_case")]
pub enum LatencySpec {
    /// Fixed latency.
    Fixed {
        /// Latency in milliseconds.
        ms: u64,
    },
    /// Uniform distribution \[min_ms, max_ms\].
    Uniform {
        /// Minimum latency in milliseconds.
        min_ms: u64,
        /// Maximum latency in milliseconds.
        max_ms: u64,
    },
    /// Normal distribution (mean +/- stddev), clamped to \[0, inf).
    Normal {
        /// Mean latency in milliseconds.
        mean_ms: u64,
        /// Standard deviation in milliseconds.
        stddev_ms: u64,
    },
}

// ---------------------------------------------------------------------------
// Fault events
// ---------------------------------------------------------------------------

/// A timed fault injection event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaultEvent {
    /// Virtual time (milliseconds) at which the fault fires.
    pub at_ms: u64,

    /// The fault action.
    pub action: FaultAction,

    /// Action arguments.
    #[serde(default)]
    pub args: BTreeMap<String, serde_json::Value>,
}

/// Fault action types.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FaultAction {
    /// Network partition between two participants.
    Partition,
    /// Heal a previously applied partition.
    Heal,
    /// Crash a host (stop processing).
    HostCrash,
    /// Restart a previously crashed host.
    HostRestart,
    /// Inject clock skew on a participant.
    ClockSkew,
    /// Reset clock skew to zero on a participant.
    ClockReset,
}

// ---------------------------------------------------------------------------
// Participants
// ---------------------------------------------------------------------------

/// A named participant in the scenario.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Participant {
    /// Unique name within the scenario.
    pub name: String,

    /// Role hint (free-form: "sender", "receiver", "coordinator", ...).
    #[serde(default)]
    pub role: String,

    /// Arbitrary properties for the participant.
    #[serde(default)]
    pub properties: BTreeMap<String, serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Cancellation injection
// ---------------------------------------------------------------------------

/// Cancellation injection configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancellationSection {
    /// The injection strategy.
    pub strategy: CancellationStrategy,

    /// Parameter for strategies that take a count.
    #[serde(default)]
    pub count: Option<usize>,

    /// Probability parameter (for `probabilistic` strategy).
    #[serde(default)]
    pub probability: Option<f64>,
}

/// Cancellation injection strategies.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CancellationStrategy {
    /// No cancellation injection (recording only).
    Never,
    /// Test all await points (N+1 runs).
    AllPoints,
    /// Random sample of await points.
    RandomSample,
    /// First N await points.
    FirstN,
    /// Last N await points.
    LastN,
    /// Every Nth await point.
    EveryNth,
    /// Probabilistic per-point injection.
    Probabilistic,
}

// ---------------------------------------------------------------------------
// Include
// ---------------------------------------------------------------------------

/// Reference to an included scenario file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncludeRef {
    /// Relative path to the included YAML.
    pub path: String,
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validation error for a scenario file.
#[derive(Debug, Clone)]
pub struct ValidationError {
    /// Path within the scenario (e.g. "lab.seed").
    pub field: String,
    /// What is wrong.
    pub message: String,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.field, self.message)
    }
}

impl std::error::Error for ValidationError {}

impl Scenario {
    /// Validate the scenario for structural correctness.
    ///
    /// Returns an empty `Vec` if valid.
    #[must_use]
    pub fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        self.validate_header(&mut errors);
        self.validate_chaos(&mut errors);
        self.validate_network(&mut errors);
        self.validate_faults(&mut errors);
        self.validate_participants(&mut errors);
        self.validate_cancellation(&mut errors);
        errors
    }

    fn validate_header(&self, errors: &mut Vec<ValidationError>) {
        if self.schema_version != SCENARIO_SCHEMA_VERSION {
            errors.push(ValidationError {
                field: "schema_version".into(),
                message: format!(
                    "unsupported version {}, expected {SCENARIO_SCHEMA_VERSION}",
                    self.schema_version
                ),
            });
        }
        if self.id.is_empty() {
            errors.push(ValidationError {
                field: "id".into(),
                message: "scenario id must not be empty".into(),
            });
        }
        if self.lab.worker_count == 0 {
            errors.push(ValidationError {
                field: "lab.worker_count".into(),
                message: "worker_count must be >= 1".into(),
            });
        }
        if self.lab.trace_capacity == 0 {
            errors.push(ValidationError {
                field: "lab.trace_capacity".into(),
                message: "trace_capacity must be > 0".into(),
            });
        }
    }

    fn validate_chaos(&self, errors: &mut Vec<ValidationError>) {
        if let ChaosSection::Custom {
            cancel_probability,
            delay_probability,
            io_error_probability,
            wakeup_storm_probability,
            budget_exhaustion_probability,
            ..
        } = &self.chaos
        {
            for (name, val) in [
                ("chaos.cancel_probability", cancel_probability),
                ("chaos.delay_probability", delay_probability),
                ("chaos.io_error_probability", io_error_probability),
                ("chaos.wakeup_storm_probability", wakeup_storm_probability),
                (
                    "chaos.budget_exhaustion_probability",
                    budget_exhaustion_probability,
                ),
            ] {
                if !(0.0..=1.0).contains(val) {
                    errors.push(ValidationError {
                        field: name.into(),
                        message: format!("probability must be in [0.0, 1.0], got {val}"),
                    });
                }
            }
        }
    }

    fn validate_network(&self, errors: &mut Vec<ValidationError>) {
        for key in self.network.links.keys() {
            if !key.contains("->") {
                errors.push(ValidationError {
                    field: format!("network.links.{key}"),
                    message: "link key must be in format \"from->to\"".into(),
                });
            }
        }
    }

    fn validate_faults(&self, errors: &mut Vec<ValidationError>) {
        for window in self.faults.windows(2) {
            if window[1].at_ms < window[0].at_ms {
                errors.push(ValidationError {
                    field: "faults".into(),
                    message: format!(
                        "fault events must be ordered by at_ms: {} comes before {}",
                        window[0].at_ms, window[1].at_ms
                    ),
                });
                break;
            }
        }
    }

    fn validate_participants(&self, errors: &mut Vec<ValidationError>) {
        let mut seen_names = std::collections::HashSet::new();
        for p in &self.participants {
            if !seen_names.insert(&p.name) {
                errors.push(ValidationError {
                    field: format!("participants.{}", p.name),
                    message: "duplicate participant name".into(),
                });
            }
        }
    }

    fn validate_cancellation(&self, errors: &mut Vec<ValidationError>) {
        let Some(ref cancel) = self.cancellation else {
            return;
        };
        match cancel.strategy {
            CancellationStrategy::RandomSample
            | CancellationStrategy::FirstN
            | CancellationStrategy::LastN
            | CancellationStrategy::EveryNth => {
                if cancel.count.is_none() {
                    errors.push(ValidationError {
                        field: "cancellation.count".into(),
                        message: format!(
                            "strategy {:?} requires a count parameter",
                            cancel.strategy
                        ),
                    });
                }
            }
            CancellationStrategy::Probabilistic => {
                if cancel.probability.is_none() {
                    errors.push(ValidationError {
                        field: "cancellation.probability".into(),
                        message: "strategy probabilistic requires a probability parameter".into(),
                    });
                }
            }
            CancellationStrategy::Never | CancellationStrategy::AllPoints => {}
        }
    }

    /// Convert this scenario to a [`super::config::LabConfig`].
    #[must_use]
    pub fn to_lab_config(&self) -> super::config::LabConfig {
        let mut config = super::config::LabConfig::new(self.lab.seed)
            .worker_count(self.lab.worker_count)
            .trace_capacity(self.lab.trace_capacity)
            .panic_on_leak(self.lab.panic_on_obligation_leak)
            .panic_on_futurelock(self.lab.panic_on_futurelock)
            .futurelock_max_idle_steps(self.lab.futurelock_max_idle_steps);

        if let Some(entropy) = self.lab.entropy_seed {
            config = config.entropy_seed(entropy);
        }

        if let Some(max) = self.lab.max_steps {
            config = config.max_steps(max);
        } else {
            config = config.no_step_limit();
        }

        // Apply chaos preset
        config = match &self.chaos {
            ChaosSection::Off => config,
            ChaosSection::Light => config.with_light_chaos(),
            ChaosSection::Heavy => config.with_heavy_chaos(),
            ChaosSection::Custom {
                cancel_probability,
                delay_probability,
                delay_min_ms,
                delay_max_ms,
                io_error_probability,
                wakeup_storm_probability,
                budget_exhaustion_probability,
            } => {
                use std::time::Duration;
                let chaos = super::chaos::ChaosConfig::new(self.lab.seed)
                    .with_cancel_probability(*cancel_probability)
                    .with_delay_probability(*delay_probability)
                    .with_delay_range(
                        Duration::from_millis(*delay_min_ms)..Duration::from_millis(*delay_max_ms),
                    )
                    .with_io_error_probability(*io_error_probability)
                    .with_wakeup_storm_probability(*wakeup_storm_probability)
                    .with_budget_exhaust_probability(*budget_exhaustion_probability);
                config.with_chaos(chaos)
            }
        };

        if self.lab.replay_recording {
            config = config.with_default_replay_recording();
        }

        config
    }

    /// Parse a scenario from a JSON string.
    ///
    /// # Errors
    ///
    /// Returns a `serde_json::Error` if the JSON is malformed.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Serialize this scenario to pretty-printed JSON.
    ///
    /// # Errors
    ///
    /// Returns a `serde_json::Error` if serialization fails.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_json() -> &'static str {
        r#"{
            "id": "test-scenario",
            "description": "minimal test"
        }"#
    }

    #[test]
    fn parse_minimal_scenario() {
        let s: Scenario = serde_json::from_str(minimal_json()).unwrap();
        assert_eq!(s.id, "test-scenario");
        assert_eq!(s.schema_version, 1);
        assert_eq!(s.lab.seed, 42);
        assert_eq!(s.lab.worker_count, 1);
        assert!(s.faults.is_empty());
        assert!(s.participants.is_empty());
        assert_eq!(s.oracles, vec!["all"]);
    }

    #[test]
    fn validate_minimal_scenario() {
        let s: Scenario = serde_json::from_str(minimal_json()).unwrap();
        let errors = s.validate();
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
    }

    #[test]
    fn validate_empty_id_rejected() {
        let json = r#"{"id": "", "description": "bad"}"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        let errors = s.validate();
        assert!(errors.iter().any(|e| e.field == "id"));
    }

    #[test]
    fn validate_bad_schema_version() {
        let json = r#"{"schema_version": 99, "id": "x"}"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        let errors = s.validate();
        assert!(errors.iter().any(|e| e.field == "schema_version"));
    }

    #[test]
    fn parse_chaos_preset_light() {
        let json = r#"{"id": "x", "chaos": {"preset": "light"}}"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        assert!(matches!(s.chaos, ChaosSection::Light));
    }

    #[test]
    fn parse_chaos_custom() {
        let json = r#"{
            "id": "x",
            "chaos": {
                "preset": "custom",
                "cancel_probability": 0.05,
                "delay_probability": 0.3,
                "io_error_probability": 0.1
            }
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        match s.chaos {
            ChaosSection::Custom {
                cancel_probability,
                delay_probability,
                io_error_probability,
                ..
            } => {
                assert!((cancel_probability - 0.05).abs() < f64::EPSILON);
                assert!((delay_probability - 0.3).abs() < f64::EPSILON);
                assert!((io_error_probability - 0.1).abs() < f64::EPSILON);
            }
            other => panic!("expected Custom, got {other:?}"),
        }
    }

    #[test]
    fn validate_chaos_bad_probability() {
        let json = r#"{
            "id": "x",
            "chaos": {"preset": "custom", "cancel_probability": 1.5}
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        let errors = s.validate();
        assert!(errors.iter().any(|e| e.field == "chaos.cancel_probability"));
    }

    #[test]
    fn parse_network_preset_wan() {
        let json = r#"{"id": "x", "network": {"preset": "wan"}}"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        assert_eq!(s.network.preset, NetworkPreset::Wan);
    }

    #[test]
    fn parse_network_link_override() {
        let json = r#"{
            "id": "x",
            "network": {
                "preset": "lan",
                "links": {
                    "alice->bob": { "packet_loss": 0.5 }
                }
            }
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        let link = s.network.links.get("alice->bob").unwrap();
        assert!((link.packet_loss.unwrap() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn validate_bad_link_key() {
        let json = r#"{
            "id": "x",
            "network": {"links": {"alice_bob": {}}}
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        let errors = s.validate();
        assert!(errors.iter().any(|e| e.field.contains("network.links")));
    }

    #[test]
    fn parse_fault_events() {
        let json = r#"{
            "id": "x",
            "faults": [
                {"at_ms": 100, "action": "partition", "args": {"from": "a", "to": "b"}},
                {"at_ms": 500, "action": "heal", "args": {"from": "a", "to": "b"}}
            ]
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        assert_eq!(s.faults.len(), 2);
        assert_eq!(s.faults[0].at_ms, 100);
        assert!(matches!(s.faults[0].action, FaultAction::Partition));
        assert_eq!(s.faults[1].at_ms, 500);
        assert!(matches!(s.faults[1].action, FaultAction::Heal));
    }

    #[test]
    fn validate_unordered_faults() {
        let json = r#"{
            "id": "x",
            "faults": [
                {"at_ms": 500, "action": "partition"},
                {"at_ms": 100, "action": "heal"}
            ]
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        let errors = s.validate();
        assert!(errors.iter().any(|e| e.field == "faults"));
    }

    #[test]
    fn parse_participants() {
        let json = r#"{
            "id": "x",
            "participants": [
                {"name": "alice", "role": "sender"},
                {"name": "bob", "role": "receiver"}
            ]
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        assert_eq!(s.participants.len(), 2);
        assert_eq!(s.participants[0].name, "alice");
        assert_eq!(s.participants[1].role, "receiver");
    }

    #[test]
    fn validate_duplicate_participant() {
        let json = r#"{
            "id": "x",
            "participants": [
                {"name": "alice"},
                {"name": "alice"}
            ]
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        let errors = s.validate();
        assert!(errors.iter().any(|e| e.message.contains("duplicate")));
    }

    #[test]
    fn parse_cancellation_strategy() {
        let json = r#"{
            "id": "x",
            "cancellation": {
                "strategy": "random_sample",
                "count": 100
            }
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        let cancel = s.cancellation.as_ref().unwrap();
        assert!(matches!(
            cancel.strategy,
            CancellationStrategy::RandomSample
        ));
        assert_eq!(cancel.count, Some(100));
    }

    #[test]
    fn validate_missing_count() {
        let json = r#"{
            "id": "x",
            "cancellation": {"strategy": "random_sample"}
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        let errors = s.validate();
        assert!(errors.iter().any(|e| e.field == "cancellation.count"));
    }

    #[test]
    fn to_lab_config_defaults() {
        let s: Scenario = serde_json::from_str(minimal_json()).unwrap();
        let config = s.to_lab_config();
        assert_eq!(config.seed, 42);
        assert_eq!(config.worker_count, 1);
        assert_eq!(config.trace_capacity, 4096);
        assert!(config.panic_on_obligation_leak);
    }

    #[test]
    fn to_lab_config_chaos_light() {
        let json = r#"{"id": "x", "chaos": {"preset": "light"}}"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        let config = s.to_lab_config();
        assert!(config.has_chaos());
    }

    #[test]
    fn to_lab_config_custom_seed() {
        let json = r#"{"id": "x", "lab": {"seed": 12345, "worker_count": 4}}"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        let config = s.to_lab_config();
        assert_eq!(config.seed, 12345);
        assert_eq!(config.worker_count, 4);
    }

    #[test]
    fn json_roundtrip() {
        let json = r#"{
            "id": "roundtrip-test",
            "description": "full roundtrip",
            "lab": {"seed": 99, "worker_count": 2},
            "chaos": {"preset": "heavy"},
            "network": {"preset": "wan"},
            "participants": [{"name": "alice", "role": "sender"}],
            "faults": [{"at_ms": 100, "action": "partition"}]
        }"#;
        let s1: Scenario = serde_json::from_str(json).unwrap();
        let serialized = s1.to_json().unwrap();
        let s2: Scenario = Scenario::from_json(&serialized).unwrap();
        assert_eq!(s1.id, s2.id);
        assert_eq!(s1.lab.seed, s2.lab.seed);
        assert_eq!(s1.participants.len(), s2.participants.len());
        assert_eq!(s1.faults.len(), s2.faults.len());
    }

    #[test]
    fn parse_metadata() {
        let json = r#"{
            "id": "x",
            "metadata": {"git_sha": "abc123", "author": "bot"}
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        assert_eq!(s.metadata.get("git_sha").unwrap(), "abc123");
    }

    #[test]
    fn parse_latency_models() {
        let json = r#"{
            "id": "x",
            "network": {
                "preset": "ideal",
                "links": {
                    "a->b": {"latency": {"model": "fixed", "ms": 5}},
                    "b->c": {"latency": {"model": "uniform", "min_ms": 1, "max_ms": 10}},
                    "c->d": {"latency": {"model": "normal", "mean_ms": 50, "stddev_ms": 10}}
                }
            }
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        assert_eq!(s.network.links.len(), 3);
        let ab = s.network.links.get("a->b").unwrap();
        assert!(matches!(ab.latency, Some(LatencySpec::Fixed { ms: 5 })));
    }

    #[test]
    fn parse_include() {
        let json = r#"{
            "id": "x",
            "include": [{"path": "base.yaml"}]
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        assert_eq!(s.include.len(), 1);
        assert_eq!(s.include[0].path, "base.yaml");
    }
}
