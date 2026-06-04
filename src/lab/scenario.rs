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
//!
//! resource_caps:
//!   max_artifact_bytes: 65536
//!   max_fault_events: 8
//!   max_counterexample_events: 16
//!
//! expected_invariants:
//!   - quiescence
//!   - losers_drained
//!   - no_obligation_leaks
//!   - deterministic_replay
//!
//! minimization:
//!   enabled: true
//!   max_evaluations: 64
//!   max_counterexample_events: 16
//!
//! golden_projection:
//!   format: json
//!   canonicalized: true
//!   redacted: true
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
use std::collections::{BTreeMap, HashSet};

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

    /// Resource caps for bounded artifact and counterexample emission.
    #[serde(default)]
    pub resource_caps: ResourceCapsSection,

    /// Invariants the scenario expects the runner to enforce or report.
    #[serde(default = "default_expected_invariants")]
    pub expected_invariants: Vec<String>,

    /// Counterexample minimization settings.
    #[serde(default)]
    pub minimization: MinimizationSection,

    /// Golden projection settings for stable, redacted scenario output.
    #[serde(default)]
    pub golden_projection: GoldenProjectionSection,

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

/// Source-owned invariant names understood by the chaos scenario DSL.
pub const SUPPORTED_EXPECTED_INVARIANTS: &[&str] = &[
    "quiescence",
    "losers_drained",
    "no_obligation_leaks",
    "bounded_artifact_output",
    "deterministic_replay",
];

fn default_expected_invariants() -> Vec<String> {
    [
        "quiescence",
        "losers_drained",
        "no_obligation_leaks",
        "deterministic_replay",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

impl Default for Scenario {
    fn default() -> Self {
        Self {
            schema_version: default_schema_version(),
            id: String::new(),
            description: String::new(),
            lab: LabSection::default(),
            chaos: ChaosSection::default(),
            network: NetworkSection::default(),
            faults: Vec::new(),
            participants: Vec::new(),
            oracles: default_oracles(),
            cancellation: None,
            resource_caps: ResourceCapsSection::default(),
            expected_invariants: default_expected_invariants(),
            minimization: MinimizationSection::default(),
            golden_projection: GoldenProjectionSection::default(),
            include: Vec::new(),
            metadata: BTreeMap::new(),
        }
    }
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
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkSection {
    /// Preset network conditions.
    #[serde(default)]
    pub preset: NetworkPreset,

    /// Per-link overrides (key = "alice->bob").
    #[serde(default)]
    pub links: BTreeMap<String, LinkConditions>,
}

/// Named network condition presets.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPreset {
    /// No latency, loss, or corruption.
    #[default]
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
    /// Apply disk-pressure accounting for an artifact or scratch path.
    DiskPressure,
    /// Clear disk-pressure accounting for an artifact or scratch path.
    DiskRecovered,
    /// Delay cleanup/finalizer progress for a named phase.
    DelayedCleanup,
    /// Stall a participant process for a bounded virtual duration.
    ProcessStall,
    /// Resume a previously stalled participant process.
    ProcessResume,
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
// Resource caps, invariants, and golden projection
// ---------------------------------------------------------------------------

/// Resource bounds applied to scenario execution and emitted artifacts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceCapsSection {
    /// Maximum bytes allowed for scenario artifacts.
    #[serde(default)]
    pub max_artifact_bytes: Option<u64>,

    /// Maximum fault events permitted by the scenario definition.
    #[serde(default)]
    pub max_fault_events: Option<usize>,

    /// Maximum events retained in minimized counterexample output.
    #[serde(default)]
    pub max_counterexample_events: Option<usize>,
}

/// Counterexample minimization policy for failing scenario runs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinimizationSection {
    /// Whether counterexample minimization is required for this scenario.
    #[serde(default)]
    pub enabled: bool,

    /// Maximum minimizer evaluations before fail-closed exhaustion.
    #[serde(default)]
    pub max_evaluations: Option<usize>,

    /// Maximum events retained in minimized counterexample output.
    #[serde(default)]
    pub max_counterexample_events: Option<usize>,
}

/// Stable projection formats for chaos scenario goldens.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GoldenProjectionFormat {
    /// Canonical JSON projection.
    #[default]
    Json,
    /// Markdown summary projection.
    Markdown,
}

/// Golden-output policy for deterministic chaos scenario artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoldenProjectionSection {
    /// Projection format.
    #[serde(default)]
    pub format: GoldenProjectionFormat,

    /// Projection must use stable canonical ordering.
    #[serde(default = "default_true")]
    pub canonicalized: bool,

    /// Projection must redact host/user/coordination-sensitive data.
    #[serde(default = "default_true")]
    pub redacted: bool,
}

impl Default for GoldenProjectionSection {
    fn default() -> Self {
        Self {
            format: GoldenProjectionFormat::Json,
            canonicalized: true,
            redacted: true,
        }
    }
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
        self.validate_resource_caps(&mut errors);
        self.validate_expected_invariants(&mut errors);
        self.validate_minimization(&mut errors);
        self.validate_golden_projection(&mut errors);
        self.validate_includes(&mut errors);
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
            delay_min_ms,
            delay_max_ms,
            io_error_probability,
            wakeup_storm_probability,
            budget_exhaustion_probability,
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
                // br-asupersync-cb440b: the existing `(0.0..=1.0).contains(val)`
                // check did already reject NaN (every NaN comparison returns
                // false), but it produced an opaque
                // "probability must be in [0.0, 1.0], got NaN" error and
                // silently treated +Inf the same way. Match the explicit
                // `is_finite()` pattern used in the network validator
                // (validate_network below) so that NaN/Inf are rejected with
                // a clear, descriptive error message and the validator's
                // intent is unambiguous to future readers and to anyone
                // diffing the chaos surface against the network surface.
                if !val.is_finite() {
                    errors.push(ValidationError {
                        field: name.into(),
                        message: format!(
                            "probability must be a finite number in [0.0, 1.0], got {val}"
                        ),
                    });
                } else if !(0.0..=1.0).contains(val) {
                    errors.push(ValidationError {
                        field: name.into(),
                        message: format!("probability must be in [0.0, 1.0], got {val}"),
                    });
                }
            }
            if *delay_min_ms > *delay_max_ms {
                errors.push(ValidationError {
                    field: "chaos.delay_min_ms".into(),
                    message: format!(
                        "delay_min_ms ({delay_min_ms}) must be <= delay_max_ms ({delay_max_ms})"
                    ),
                });
            }
        }
    }

    fn validate_network(&self, errors: &mut Vec<ValidationError>) {
        for (key, link) in &self.network.links {
            let key_valid = key
                .split_once("->")
                .is_some_and(|(from, to)| !from.is_empty() && !to.is_empty() && !to.contains("->"));
            if !key_valid {
                errors.push(ValidationError {
                    field: format!("network.links.{key}"),
                    message: "link key must be in format \"from->to\"".into(),
                });
            }

            for (name, value) in [
                ("packet_loss", link.packet_loss),
                ("packet_corrupt", link.packet_corrupt),
                ("packet_duplicate", link.packet_duplicate),
                ("packet_reorder", link.packet_reorder),
            ] {
                if let Some(probability) = value {
                    if !probability.is_finite() || !(0.0..=1.0).contains(&probability) {
                        errors.push(ValidationError {
                            field: format!("network.links.{key}.{name}"),
                            message: format!(
                                "probability must be finite and in [0.0, 1.0], got {probability}"
                            ),
                        });
                    }
                }
            }

            if let Some(LatencySpec::Uniform { min_ms, max_ms }) = &link.latency {
                if min_ms > max_ms {
                    errors.push(ValidationError {
                        field: format!("network.links.{key}.latency"),
                        message: format!(
                            "uniform latency min_ms ({min_ms}) must be <= max_ms ({max_ms})"
                        ),
                    });
                }
            }
        }
    }

    fn validate_faults(&self, errors: &mut Vec<ValidationError>) {
        let participant_names: HashSet<&str> =
            self.participants.iter().map(|p| p.name.as_str()).collect();

        for (index, fault) in self.faults.iter().enumerate() {
            Self::validate_fault_args(index, fault, &participant_names, errors);
        }

        for window in self.faults.windows(2) {
            if window[1].at_ms < window[0].at_ms {
                errors.push(ValidationError {
                    field: "faults".into(),
                    message: format!(
                        "fault events must be ordered by at_ms: {} comes before {}",
                        window[0].at_ms, window[1].at_ms
                    ),
                });
            }
        }
    }

    fn validate_fault_args(
        fault_index: usize,
        fault: &FaultEvent,
        participant_names: &HashSet<&str>,
        errors: &mut Vec<ValidationError>,
    ) {
        match &fault.action {
            FaultAction::Partition | FaultAction::Heal => {
                let from =
                    Self::required_fault_string_arg(fault_index, &fault.args, "from", errors);
                let to = Self::required_fault_string_arg(fault_index, &fault.args, "to", errors);

                if let (Some(from), Some(to)) = (from, to) {
                    if from == to {
                        errors.push(ValidationError {
                            field: format!("faults[{fault_index}].args.to"),
                            message: "partition/heal endpoints must be distinct".into(),
                        });
                    }
                    Self::validate_fault_participant_ref(
                        fault_index,
                        "from",
                        from,
                        participant_names,
                        errors,
                    );
                    Self::validate_fault_participant_ref(
                        fault_index,
                        "to",
                        to,
                        participant_names,
                        errors,
                    );
                }
            }
            FaultAction::DiskPressure => {
                Self::required_fault_string_arg(fault_index, &fault.args, "path", errors);
                Self::required_fault_u64_arg(fault_index, &fault.args, "bytes", errors);
            }
            FaultAction::DiskRecovered => {
                Self::required_fault_string_arg(fault_index, &fault.args, "path", errors);
            }
            FaultAction::DelayedCleanup => {
                Self::required_fault_string_arg(fault_index, &fault.args, "phase", errors);
                Self::required_fault_u64_arg(fault_index, &fault.args, "delay_ms", errors);
            }
            FaultAction::ProcessStall => {
                if let Some(host) =
                    Self::required_fault_string_arg(fault_index, &fault.args, "host", errors)
                {
                    Self::validate_fault_participant_ref(
                        fault_index,
                        "host",
                        host,
                        participant_names,
                        errors,
                    );
                }
                Self::required_fault_u64_arg(fault_index, &fault.args, "duration_ms", errors);
            }
            FaultAction::ProcessResume => {
                if let Some(host) =
                    Self::required_fault_string_arg(fault_index, &fault.args, "host", errors)
                {
                    Self::validate_fault_participant_ref(
                        fault_index,
                        "host",
                        host,
                        participant_names,
                        errors,
                    );
                }
            }
            FaultAction::HostCrash | FaultAction::HostRestart | FaultAction::ClockReset => {
                if let Some(host) =
                    Self::required_fault_string_arg(fault_index, &fault.args, "host", errors)
                {
                    Self::validate_fault_participant_ref(
                        fault_index,
                        "host",
                        host,
                        participant_names,
                        errors,
                    );
                }
            }
            FaultAction::ClockSkew => {
                if let Some(host) =
                    Self::required_fault_string_arg(fault_index, &fault.args, "host", errors)
                {
                    Self::validate_fault_participant_ref(
                        fault_index,
                        "host",
                        host,
                        participant_names,
                        errors,
                    );
                }
                Self::required_fault_i64_arg(fault_index, &fault.args, "skew_ms", errors);
            }
        }
    }

    fn required_fault_u64_arg(
        fault_index: usize,
        args: &BTreeMap<String, serde_json::Value>,
        key: &str,
        errors: &mut Vec<ValidationError>,
    ) {
        let value = args.get(key).and_then(serde_json::Value::as_u64);
        if value.is_none_or(|value| value == 0) {
            errors.push(ValidationError {
                field: format!("faults[{fault_index}].args.{key}"),
                message: format!("fault action requires positive integer arg `{key}`"),
            });
        }
    }

    fn required_fault_string_arg<'a>(
        fault_index: usize,
        args: &'a BTreeMap<String, serde_json::Value>,
        key: &str,
        errors: &mut Vec<ValidationError>,
    ) -> Option<&'a str> {
        let value = args
            .get(key)
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty());

        if value.is_none() {
            errors.push(ValidationError {
                field: format!("faults[{fault_index}].args.{key}"),
                message: format!("fault action requires non-empty string arg `{key}`"),
            });
        }

        value
    }

    fn required_fault_i64_arg(
        fault_index: usize,
        args: &BTreeMap<String, serde_json::Value>,
        key: &str,
        errors: &mut Vec<ValidationError>,
    ) {
        if args.get(key).and_then(serde_json::Value::as_i64).is_none() {
            errors.push(ValidationError {
                field: format!("faults[{fault_index}].args.{key}"),
                message: format!("fault action requires integer arg `{key}`"),
            });
        }
    }

    fn validate_fault_participant_ref(
        fault_index: usize,
        key: &str,
        value: &str,
        participant_names: &HashSet<&str>,
        errors: &mut Vec<ValidationError>,
    ) {
        if participant_names.is_empty() || participant_names.contains(value) {
            return;
        }

        errors.push(ValidationError {
            field: format!("faults[{fault_index}].args.{key}"),
            message: format!("unknown participant `{value}`"),
        });
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
                } else if cancel.count == Some(0) {
                    errors.push(ValidationError {
                        field: "cancellation.count".into(),
                        message: "count must be >= 1".into(),
                    });
                }
            }
            CancellationStrategy::Probabilistic => {
                if let Some(p) = cancel.probability {
                    if !p.is_finite() || !(0.0..=1.0).contains(&p) {
                        errors.push(ValidationError {
                            field: "cancellation.probability".into(),
                            message: format!("probability must be in [0.0, 1.0], got {p}"),
                        });
                    }
                } else {
                    errors.push(ValidationError {
                        field: "cancellation.probability".into(),
                        message: "strategy probabilistic requires a probability parameter".into(),
                    });
                }
            }
            CancellationStrategy::Never | CancellationStrategy::AllPoints => {}
        }
    }

    fn validate_resource_caps(&self, errors: &mut Vec<ValidationError>) {
        if self.resource_caps.max_artifact_bytes == Some(0) {
            errors.push(ValidationError {
                field: "resource_caps.max_artifact_bytes".into(),
                message: "max_artifact_bytes must be >= 1 when set".into(),
            });
        }

        if let Some(max_fault_events) = self.resource_caps.max_fault_events {
            if max_fault_events == 0 {
                errors.push(ValidationError {
                    field: "resource_caps.max_fault_events".into(),
                    message: "max_fault_events must be >= 1 when set".into(),
                });
            } else if self.faults.len() > max_fault_events {
                errors.push(ValidationError {
                    field: "resource_caps.max_fault_events".into(),
                    message: format!(
                        "scenario defines {} fault event(s), exceeding cap {max_fault_events}",
                        self.faults.len()
                    ),
                });
            }
        }

        if self.resource_caps.max_counterexample_events == Some(0) {
            errors.push(ValidationError {
                field: "resource_caps.max_counterexample_events".into(),
                message: "max_counterexample_events must be >= 1 when set".into(),
            });
        }
    }

    fn validate_expected_invariants(&self, errors: &mut Vec<ValidationError>) {
        if self.expected_invariants.is_empty() {
            errors.push(ValidationError {
                field: "expected_invariants".into(),
                message: "at least one expected invariant is required".into(),
            });
            return;
        }

        let mut seen = HashSet::new();
        for (index, invariant) in self.expected_invariants.iter().enumerate() {
            let invariant = invariant.trim();
            if invariant.is_empty() {
                errors.push(ValidationError {
                    field: format!("expected_invariants[{index}]"),
                    message: "expected invariant name must not be empty".into(),
                });
                continue;
            }

            if !SUPPORTED_EXPECTED_INVARIANTS.contains(&invariant) {
                errors.push(ValidationError {
                    field: format!("expected_invariants[{index}]"),
                    message: format!("unsupported expected invariant `{invariant}`"),
                });
            }

            if !seen.insert(invariant) {
                errors.push(ValidationError {
                    field: format!("expected_invariants[{index}]"),
                    message: format!("duplicate expected invariant `{invariant}`"),
                });
            }
        }
    }

    fn validate_minimization(&self, errors: &mut Vec<ValidationError>) {
        if self.minimization.enabled {
            match self.minimization.max_evaluations {
                Some(0) => errors.push(ValidationError {
                    field: "minimization.max_evaluations".into(),
                    message: "enabled minimization requires max_evaluations >= 1".into(),
                }),
                None => errors.push(ValidationError {
                    field: "minimization.max_evaluations".into(),
                    message: "enabled minimization requires max_evaluations".into(),
                }),
                Some(_) => {}
            }
        }

        if self.minimization.max_counterexample_events == Some(0) {
            errors.push(ValidationError {
                field: "minimization.max_counterexample_events".into(),
                message: "max_counterexample_events must be >= 1 when set".into(),
            });
        }
    }

    fn validate_golden_projection(&self, errors: &mut Vec<ValidationError>) {
        if !self.golden_projection.canonicalized {
            errors.push(ValidationError {
                field: "golden_projection.canonicalized".into(),
                message: "golden projection must be canonicalized".into(),
            });
        }
        if !self.golden_projection.redacted {
            errors.push(ValidationError {
                field: "golden_projection.redacted".into(),
                message: "golden projection must be redacted".into(),
            });
        }
    }

    fn validate_includes(&self, errors: &mut Vec<ValidationError>) {
        for (index, include) in self.include.iter().enumerate() {
            let field = format!("include[{index}].path");

            // Security: Reject empty paths
            if include.path.is_empty() {
                errors.push(ValidationError {
                    field: field.clone(),
                    message: "include path must not be empty".into(),
                });
                continue;
            }

            // Security: Reject absolute paths
            if include.path.starts_with('/') || include.path.starts_with('\\') {
                errors.push(ValidationError {
                    field: field.clone(),
                    message: "include path must not be absolute (no leading / or \\)".into(),
                });
                continue;
            }

            // Security: Reject path traversal attempts
            if include.path.contains("..") {
                errors.push(ValidationError {
                    field: field.clone(),
                    message: "include path must not contain '..' (path traversal attack)".into(),
                });
                continue;
            }

            // Security: Reject paths with null bytes or control characters
            if include.path.chars().any(|c| c.is_control() || c == '\0') {
                errors.push(ValidationError {
                    field: field.clone(),
                    message: "include path must not contain control characters or null bytes"
                        .into(),
                });
                continue;
            }

            // Security: Restrict to reasonable filename characters
            let allowed_chars = |c: char| c.is_alphanumeric() || matches!(c, '.' | '_' | '-' | '/');
            if !include.path.chars().all(allowed_chars) {
                errors.push(ValidationError {
                    field: field.clone(),
                    message: "include path contains invalid characters (only alphanumeric, '.', '_', '-', '/' allowed)".into(),
                });
                continue;
            }

            // Security: Reject excessively long paths
            if include.path.len() > 255 {
                errors.push(ValidationError {
                    field: field.clone(),
                    message: "include path too long (maximum 255 characters)".into(),
                });
                continue;
            }

            // Security: Require .yaml or .yml extension
            let has_yaml_extension = std::path::Path::new(&include.path)
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| {
                    extension.eq_ignore_ascii_case("yaml") || extension.eq_ignore_ascii_case("yml")
                });
            if !has_yaml_extension {
                errors.push(ValidationError {
                    field,
                    message: "include path must end with .yaml or .yml extension".into(),
                });
            }
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
                let chaos_seed = self.lab.entropy_seed.unwrap_or(self.lab.seed);
                let chaos = crate::lab::chaos::ChaosConfig::new(chaos_seed)
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
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
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
        assert_eq!(s.resource_caps, ResourceCapsSection::default());
        assert_eq!(s.expected_invariants, default_expected_invariants());
        assert_eq!(s.minimization, MinimizationSection::default());
        assert_eq!(s.golden_projection, GoldenProjectionSection::default());
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
            other => panic!("expected Custom, got {other:?}"), // ubs:ignore - test helper
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

    // br-asupersync-cb440b: NaN/Inf chaos probabilities must be rejected
    // with an explicit "must be a finite number" error rather than the
    // generic out-of-range message. This is the regression that proves
    // the chaos validator now matches the network validator's
    // is_finite-first pattern, instead of relying on the subtle fact
    // that NaN comparisons against a RangeInclusive happen to return
    // false.
    #[test]
    fn validate_chaos_rejects_nan_probability_with_finite_error() {
        // NaN cannot be expressed as a JSON literal, so we parse a
        // minimal scenario then mutate the chaos section directly.
        let mut s: Scenario = serde_json::from_str(r#"{"id":"x"}"#).unwrap();
        s.chaos = ChaosSection::Custom {
            cancel_probability: f64::NAN,
            delay_probability: 0.0,
            delay_min_ms: 0,
            delay_max_ms: 1,
            io_error_probability: 0.0,
            wakeup_storm_probability: 0.0,
            budget_exhaustion_probability: 0.0,
        };
        let errors = s.validate();
        let nan_error = errors
            .iter()
            .find(|e| e.field == "chaos.cancel_probability")
            .expect("chaos.cancel_probability NaN must be flagged");
        assert!(
            nan_error.message.contains("finite"),
            "NaN error message must say 'finite', got: {}",
            nan_error.message
        );
        assert!(
            nan_error.message.contains("NaN"),
            "NaN error message must include 'NaN', got: {}",
            nan_error.message
        );
    }

    #[test]
    fn validate_chaos_rejects_infinity_probability_with_finite_error() {
        let mut s: Scenario = serde_json::from_str(r#"{"id":"x"}"#).unwrap();
        s.chaos = ChaosSection::Custom {
            cancel_probability: 0.0,
            delay_probability: 0.0,
            delay_min_ms: 0,
            delay_max_ms: 1,
            io_error_probability: 0.0,
            wakeup_storm_probability: f64::INFINITY,
            budget_exhaustion_probability: f64::NEG_INFINITY,
        };
        let errors = s.validate();
        let inf_storm = errors
            .iter()
            .find(|e| e.field == "chaos.wakeup_storm_probability")
            .expect("chaos.wakeup_storm_probability +Inf must be flagged");
        assert!(
            inf_storm.message.contains("finite"),
            "+Inf error must say 'finite', got: {}",
            inf_storm.message
        );
        let neg_inf_budget = errors
            .iter()
            .find(|e| e.field == "chaos.budget_exhaustion_probability")
            .expect("chaos.budget_exhaustion_probability -Inf must be flagged");
        assert!(
            neg_inf_budget.message.contains("finite"),
            "-Inf error must say 'finite', got: {}",
            neg_inf_budget.message
        );
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
    fn validate_link_probability_out_of_range() {
        let json = r#"{
            "id": "x",
            "network": {
                "links": {
                    "alice->bob": { "packet_loss": 1.5 }
                }
            }
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        let errors = s.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.field == "network.links.alice->bob.packet_loss")
        );
    }

    #[test]
    fn validate_uniform_latency_min_max_order() {
        let json = r#"{
            "id": "x",
            "network": {
                "links": {
                    "alice->bob": {
                        "latency": { "model": "uniform", "min_ms": 20, "max_ms": 10 }
                    }
                }
            }
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        let errors = s.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.field == "network.links.alice->bob.latency")
        );
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
    fn validate_fault_action_args_fail_closed() {
        let json = r#"{
            "id": "x",
            "faults": [
                {"at_ms": 1, "action": "partition"},
                {"at_ms": 2, "action": "host_crash", "args": {"host": ""}},
                {"at_ms": 3, "action": "clock_skew", "args": {"host": "alice", "skew_ms": "fast"}},
                {"at_ms": 4, "action": "disk_pressure", "args": {"path": "", "bytes": 0}},
                {"at_ms": 5, "action": "delayed_cleanup", "args": {"phase": "", "delay_ms": 0}},
                {"at_ms": 6, "action": "process_stall", "args": {"host": "", "duration_ms": 0}}
            ]
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        let errors = s.validate();

        assert!(errors.iter().any(|e| e.field == "faults[0].args.from"));
        assert!(errors.iter().any(|e| e.field == "faults[0].args.to"));
        assert!(errors.iter().any(|e| e.field == "faults[1].args.host"));
        assert!(errors.iter().any(|e| e.field == "faults[2].args.skew_ms"));
        assert!(errors.iter().any(|e| e.field == "faults[3].args.path"));
        assert!(errors.iter().any(|e| e.field == "faults[3].args.bytes"));
        assert!(errors.iter().any(|e| e.field == "faults[4].args.phase"));
        assert!(errors.iter().any(|e| e.field == "faults[4].args.delay_ms"));
        assert!(errors.iter().any(|e| e.field == "faults[5].args.host"));
        assert!(
            errors
                .iter()
                .any(|e| e.field == "faults[5].args.duration_ms")
        );
    }

    #[test]
    fn validate_fault_args_reference_declared_participants() {
        let json = r#"{
            "id": "x",
            "participants": [
                {"name": "alice"},
                {"name": "bob"}
            ],
            "faults": [
                {"at_ms": 1, "action": "partition", "args": {"from": "alice", "to": "mallory"}},
                {"at_ms": 2, "action": "heal", "args": {"from": "bob", "to": "bob"}},
                {"at_ms": 3, "action": "clock_reset", "args": {"host": "mallory"}},
                {"at_ms": 4, "action": "process_stall", "args": {"host": "mallory", "duration_ms": 10}}
            ]
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        let errors = s.validate();

        assert!(errors.iter().any(|e| {
            e.field == "faults[0].args.to" && e.message.contains("unknown participant")
        }));
        assert!(
            errors
                .iter()
                .any(|e| { e.field == "faults[1].args.to" && e.message.contains("distinct") })
        );
        assert!(errors.iter().any(|e| {
            e.field == "faults[2].args.host" && e.message.contains("unknown participant")
        }));
        assert!(errors.iter().any(|e| {
            e.field == "faults[3].args.host" && e.message.contains("unknown participant")
        }));
    }

    #[test]
    fn parse_disk_process_and_cleanup_fault_events() {
        let json = r#"{
            "id": "x",
            "participants": [{"name": "worker-a"}],
            "faults": [
                {"at_ms": 10, "action": "disk_pressure", "args": {"path": "target/proof", "bytes": 4096}},
                {"at_ms": 20, "action": "delayed_cleanup", "args": {"phase": "finalizers", "delay_ms": 25}},
                {"at_ms": 30, "action": "process_stall", "args": {"host": "worker-a", "duration_ms": 40}},
                {"at_ms": 80, "action": "process_resume", "args": {"host": "worker-a"}},
                {"at_ms": 90, "action": "disk_recovered", "args": {"path": "target/proof"}}
            ]
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        assert_eq!(s.faults.len(), 5);
        assert!(matches!(s.faults[0].action, FaultAction::DiskPressure));
        assert!(matches!(s.faults[1].action, FaultAction::DelayedCleanup));
        assert!(matches!(s.faults[2].action, FaultAction::ProcessStall));
        assert!(matches!(s.faults[3].action, FaultAction::ProcessResume));
        assert!(matches!(s.faults[4].action, FaultAction::DiskRecovered));
        assert!(
            s.validate().is_empty(),
            "new DSL fault actions must validate"
        );
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
    fn parse_source_backed_dsl_fields() {
        let json = r#"{
            "id": "chaos-partition-cancel-storm",
            "description": "partition plus cancellation storm",
            "lab": {"seed": 340334, "worker_count": 2, "max_steps": 1000},
            "participants": [
                {"name": "alice", "role": "sender"},
                {"name": "bob", "role": "receiver"}
            ],
            "faults": [
                {"at_ms": 100, "action": "partition", "args": {"from": "alice", "to": "bob"}},
                {"at_ms": 500, "action": "heal", "args": {"from": "alice", "to": "bob"}}
            ],
            "cancellation": {"strategy": "random_sample", "count": 8},
            "resource_caps": {
                "max_artifact_bytes": 65536,
                "max_fault_events": 8,
                "max_counterexample_events": 16
            },
            "expected_invariants": [
                "quiescence",
                "losers_drained",
                "no_obligation_leaks",
                "deterministic_replay"
            ],
            "minimization": {
                "enabled": true,
                "max_evaluations": 64,
                "max_counterexample_events": 16
            },
            "golden_projection": {
                "format": "json",
                "canonicalized": true,
                "redacted": true
            }
        }"#;

        let s: Scenario = serde_json::from_str(json).unwrap();
        assert_eq!(s.lab.seed, 340_334);
        assert_eq!(s.resource_caps.max_artifact_bytes, Some(65_536));
        assert_eq!(s.resource_caps.max_fault_events, Some(8));
        assert_eq!(s.resource_caps.max_counterexample_events, Some(16));
        assert_eq!(
            s.expected_invariants,
            vec![
                "quiescence".to_string(),
                "losers_drained".to_string(),
                "no_obligation_leaks".to_string(),
                "deterministic_replay".to_string()
            ]
        );
        assert!(s.minimization.enabled);
        assert_eq!(s.minimization.max_evaluations, Some(64));
        assert_eq!(s.minimization.max_counterexample_events, Some(16));
        assert_eq!(s.golden_projection.format, GoldenProjectionFormat::Json);
        assert!(s.golden_projection.canonicalized);
        assert!(s.golden_projection.redacted);
        assert!(
            s.validate().is_empty(),
            "source-backed scenario must validate"
        );
    }

    #[test]
    fn validate_resource_caps_bound_fault_count() {
        let json = r#"{
            "id": "x",
            "participants": [{"name": "alice"}, {"name": "bob"}],
            "faults": [
                {"at_ms": 1, "action": "partition", "args": {"from": "alice", "to": "bob"}},
                {"at_ms": 2, "action": "heal", "args": {"from": "alice", "to": "bob"}}
            ],
            "resource_caps": {
                "max_artifact_bytes": 0,
                "max_fault_events": 1,
                "max_counterexample_events": 0
            }
        }"#;

        let s: Scenario = serde_json::from_str(json).unwrap();
        let errors = s.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.field == "resource_caps.max_artifact_bytes")
        );
        assert!(
            errors
                .iter()
                .any(|e| e.field == "resource_caps.max_fault_events")
        );
        assert!(
            errors
                .iter()
                .any(|e| e.field == "resource_caps.max_counterexample_events")
        );
    }

    #[test]
    fn validate_expected_invariants_fail_closed() {
        let json = r#"{
            "id": "x",
            "expected_invariants": ["quiescence", "", "quiescence", "mystery"]
        }"#;

        let s: Scenario = serde_json::from_str(json).unwrap();
        let errors = s.validate();
        assert!(errors.iter().any(|e| {
            e.field == "expected_invariants[1]" && e.message.contains("must not be empty")
        }));
        assert!(
            errors.iter().any(|e| {
                e.field == "expected_invariants[2]" && e.message.contains("duplicate")
            })
        );
        assert!(
            errors.iter().any(|e| {
                e.field == "expected_invariants[3]" && e.message.contains("unsupported")
            })
        );
    }

    #[test]
    fn validate_minimization_requires_positive_budget_when_enabled() {
        let json = r#"{
            "id": "x",
            "minimization": {
                "enabled": true,
                "max_counterexample_events": 0
            }
        }"#;

        let s: Scenario = serde_json::from_str(json).unwrap();
        let errors = s.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.field == "minimization.max_evaluations")
        );
        assert!(
            errors
                .iter()
                .any(|e| e.field == "minimization.max_counterexample_events")
        );
    }

    #[test]
    fn validate_golden_projection_requires_canonical_redacted_output() {
        let json = r#"{
            "id": "x",
            "golden_projection": {
                "format": "markdown",
                "canonicalized": false,
                "redacted": false
            }
        }"#;

        let s: Scenario = serde_json::from_str(json).unwrap();
        let errors = s.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.field == "golden_projection.canonicalized")
        );
        assert!(
            errors
                .iter()
                .any(|e| e.field == "golden_projection.redacted")
        );
    }

    #[test]
    fn validate_includes_path_traversal_security() {
        // Test empty path rejection
        let json = r#"{
            "id": "test",
            "include": [{"path": ""}]
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        let errors = s.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.field == "include[0].path" && e.message.contains("empty"))
        );

        // Test absolute path rejection (Unix style)
        let json = r#"{
            "id": "test",
            "include": [{"path": "/etc/passwd"}]
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        let errors = s.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.field == "include[0].path" && e.message.contains("absolute"))
        );

        // Test absolute path rejection (Windows style)
        let json = r#"{
            "id": "test",
            "include": [{"path": "\\windows\\system32\\config\\sam"}]
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        let errors = s.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.field == "include[0].path" && e.message.contains("absolute"))
        );

        // Test path traversal rejection
        let json = r#"{
            "id": "test",
            "include": [{"path": "../../../etc/passwd.yaml"}]
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        let errors = s.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.field == "include[0].path" && e.message.contains("path traversal"))
        );

        // Test subtler path traversal
        let json = r#"{
            "id": "test",
            "include": [{"path": "configs/../secrets.yaml"}]
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        let errors = s.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.field == "include[0].path" && e.message.contains("path traversal"))
        );

        // Test control character rejection (null byte)
        let json = r#"{
            "id": "test",
            "include": [{"path": "config\u0000.yaml"}]
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        let errors = s.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.field == "include[0].path" && e.message.contains("control characters"))
        );

        // Test invalid character rejection
        let json = r#"{
            "id": "test",
            "include": [{"path": "config$evil.yaml"}]
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        let errors = s.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.field == "include[0].path" && e.message.contains("invalid characters"))
        );

        // Test path length limit
        let long_path = "a".repeat(256) + ".yaml";
        let json = format!(
            r#"{{"id": "test", "include": [{{"path": "{}"}}]}}"#,
            long_path
        );
        let s: Scenario = serde_json::from_str(&json).unwrap();
        let errors = s.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.field == "include[0].path" && e.message.contains("too long"))
        );

        // Test extension requirement (missing extension)
        let json = r#"{
            "id": "test",
            "include": [{"path": "config.txt"}]
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        let errors = s.validate();
        assert!(
            errors.iter().any(|e| e.field == "include[0].path"
                && e.message.contains("must end with .yaml or .yml"))
        );

        // Test valid path passes all checks
        let json = r#"{
            "id": "test",
            "include": [{"path": "config/base.yaml"}]
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        let errors = s.validate();
        assert!(
            errors
                .iter()
                .all(|e| !e.field.starts_with("include[0].path"))
        );
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
            "faults": [{"at_ms": 100, "action": "partition"}],
            "resource_caps": {"max_artifact_bytes": 1024, "max_fault_events": 2},
            "expected_invariants": ["quiescence", "deterministic_replay"],
            "minimization": {"enabled": false, "max_counterexample_events": 8},
            "golden_projection": {"format": "markdown", "canonicalized": true, "redacted": true}
        }"#;
        let s1: Scenario = serde_json::from_str(json).unwrap();
        let serialized = s1.to_json().unwrap();
        let s2: Scenario = Scenario::from_json(&serialized).unwrap();
        assert_eq!(s1.id, s2.id);
        assert_eq!(s1.lab.seed, s2.lab.seed);
        assert_eq!(s1.participants.len(), s2.participants.len());
        assert_eq!(s1.faults.len(), s2.faults.len());
        assert_eq!(s1.resource_caps, s2.resource_caps);
        assert_eq!(s1.expected_invariants, s2.expected_invariants);
        assert_eq!(s1.minimization, s2.minimization);
        assert_eq!(s1.golden_projection, s2.golden_projection);
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

    #[test]
    fn network_preset_debug_clone_copy_eq() {
        let p = NetworkPreset::Wan;
        let dbg = format!("{p:?}");
        assert!(dbg.contains("Wan"));

        let p2 = p;
        assert_eq!(p, p2);

        let p3 = p;
        assert_eq!(p, p3);

        assert_ne!(NetworkPreset::Ideal, NetworkPreset::Lossy);
    }

    #[test]
    fn chaos_section_debug_clone_default() {
        let c = ChaosSection::default();
        let dbg = format!("{c:?}");
        assert!(dbg.contains("Off"));

        let c2 = c;
        let dbg2 = format!("{c2:?}");
        assert_eq!(dbg, dbg2);
    }

    #[test]
    fn fault_action_debug_clone() {
        let a = FaultAction::Partition;
        let dbg = format!("{a:?}");
        assert!(dbg.contains("Partition"));

        let a2 = a;
        let dbg2 = format!("{a2:?}");
        assert_eq!(dbg, dbg2);
    }

    #[test]
    fn validation_error_debug_clone() {
        let e = ValidationError {
            field: "lab.seed".into(),
            message: "must be positive".into(),
        };
        let dbg = format!("{e:?}");
        assert!(dbg.contains("lab.seed"));

        let e2 = e;
        assert_eq!(e2.field, "lab.seed");
        assert_eq!(e2.message, "must be positive");
    }
}
