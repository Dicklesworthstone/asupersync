//! Discoverable registry for lab invariant oracles.
//!
//! The registry is the agent-facing index of built-in lab oracles. It keeps
//! names, descriptions, applicability metadata, and scenario-selection
//! validation in one place so scenario YAML, docs, and tests do not drift.
//!
//! # Examples
//!
//! List reportable oracle names:
//!
//! ```
//! use asupersync::lab::OracleRegistry;
//!
//! let names = OracleRegistry::reported_names();
//! assert!(names.contains(&"task_leak"));
//! assert!(names.contains(&"quiescence"));
//! ```
//!
//! Find oracles by invariant text:
//!
//! ```
//! use asupersync::lab::OracleRegistry;
//!
//! let matches = OracleRegistry::find_by_invariant("region close");
//! assert!(matches.iter().any(|descriptor| descriptor.name == "quiescence"));
//! ```
//!
//! Instantiate an object-safe oracle by name:
//!
//! ```
//! use asupersync::lab::OracleRegistry;
//!
//! let oracle = OracleRegistry::instantiate("quiescence").unwrap();
//! assert_eq!(oracle.invariant_name(), "quiescence");
//! ```

use super::Oracle;
use super::quiescence::QuiescenceOracle;

#[cfg(feature = "messaging-fabric")]
use super::fabric::{
    FabricPublishOracle, FabricQuiescenceOracle, FabricRedeliveryOracle, FabricReplyOracle,
};

/// Special scenario selection token meaning "all suite-reported oracles".
pub const ORACLE_ALL: &str = "all";

/// Invariant name for the task leak oracle.
pub const INVARIANT_TASK_LEAK: &str = "task_leak";
/// Invariant name for the obligation leak oracle.
pub const INVARIANT_OBLIGATION_LEAK: &str = "obligation_leak";
/// Invariant name for the quiescence oracle.
pub const INVARIANT_QUIESCENCE: &str = "quiescence";
/// Invariant name for the loser drain oracle.
pub const INVARIANT_LOSER_DRAIN: &str = "loser_drain";
/// Invariant name for the finalizer oracle.
pub const INVARIANT_FINALIZER: &str = "finalizer";
/// Invariant name for the region tree oracle.
pub const INVARIANT_REGION_TREE: &str = "region_tree";
/// Invariant name for the region leak oracle.
pub const INVARIANT_REGION_LEAK: &str = "region_leak";
/// Invariant name for the ambient authority oracle.
pub const INVARIANT_AMBIENT_AUTHORITY: &str = "ambient_authority";
/// Invariant name for the deadline monotonicity oracle.
pub const INVARIANT_DEADLINE_MONOTONE: &str = "deadline_monotone";
/// Invariant name for the cancellation protocol oracle.
pub const INVARIANT_CANCELLATION_PROTOCOL: &str = "cancellation_protocol";
/// Invariant name for the cancel-correctness oracle.
pub const INVARIANT_CANCEL_CORRECTNESS: &str = "cancel_correctness";
/// Invariant name for the cancel debt accumulation oracle.
pub const INVARIANT_CANCEL_DEBT: &str = "cancel_debt";
/// Invariant name for the cancel signal ordering oracle.
pub const INVARIANT_CANCEL_ORDERING: &str = "cancel_signal_ordering";
/// Invariant name for the runtime epoch consistency oracle.
pub const INVARIANT_RUNTIME_EPOCH: &str = "runtime_epoch";
/// Invariant name for the channel atomicity oracle.
pub const INVARIANT_CHANNEL_ATOMICITY: &str = "channel_atomicity";
/// Invariant name for the waker deduplication oracle.
pub const INVARIANT_WAKER_DEDUP: &str = "waker_dedup";
/// Invariant name for the actor leak oracle.
pub const INVARIANT_ACTOR_LEAK: &str = "actor_leak";
/// Invariant name for the supervision oracle.
pub const INVARIANT_SUPERVISION: &str = "supervision";
/// Invariant name for the mailbox oracle.
pub const INVARIANT_MAILBOX: &str = "mailbox";
/// Invariant name for the RRef access oracle.
pub const INVARIANT_RREF_ACCESS: &str = "rref_access";
/// Invariant name for the reply linearity oracle.
pub const INVARIANT_REPLY_LINEARITY: &str = "reply_linearity";
/// Invariant name for the registry lease oracle.
pub const INVARIANT_REGISTRY_LEASE: &str = "registry_lease";
/// Invariant name for the deterministic DOWN ordering oracle.
pub const INVARIANT_DOWN_ORDER: &str = "down_order";
/// Invariant name for the supervisor quiescence oracle.
pub const INVARIANT_SUPERVISOR_QUIESCENCE: &str = "supervisor_quiescence";
/// Invariant name for the priority inversion oracle.
pub const INVARIANT_PRIORITY_INVERSION: &str = "priority_inversion";
/// Invariant name for the FABRIC publish oracle.
#[cfg(feature = "messaging-fabric")]
pub const INVARIANT_FABRIC_PUBLISH: &str = "fabric_publish";
/// Invariant name for the FABRIC reply oracle.
#[cfg(feature = "messaging-fabric")]
pub const INVARIANT_FABRIC_REPLY: &str = "fabric_reply";
/// Invariant name for the FABRIC quiescence oracle.
#[cfg(feature = "messaging-fabric")]
pub const INVARIANT_FABRIC_QUIESCENCE: &str = "fabric_quiescence";
/// Invariant name for the FABRIC redelivery oracle.
#[cfg(feature = "messaging-fabric")]
pub const INVARIANT_FABRIC_REDELIVERY: &str = "fabric_redelivery";

/// Ordered list of names emitted by [`super::OracleSuite::report`].
///
/// This is intentionally the legacy public invariant-name list used by meta
/// reports and scenario filtering. It excludes registered oracles that do not
/// yet emit `OracleReport` entries.
pub const ALL_REPORTED_ORACLE_NAMES: &[&str] = &[
    INVARIANT_TASK_LEAK,
    INVARIANT_QUIESCENCE,
    INVARIANT_CANCELLATION_PROTOCOL,
    INVARIANT_LOSER_DRAIN,
    INVARIANT_OBLIGATION_LEAK,
    INVARIANT_AMBIENT_AUTHORITY,
    INVARIANT_FINALIZER,
    INVARIANT_REGION_TREE,
    INVARIANT_REGION_LEAK,
    INVARIANT_DEADLINE_MONOTONE,
    INVARIANT_CANCEL_CORRECTNESS,
    INVARIANT_CANCEL_DEBT,
    INVARIANT_CANCEL_ORDERING,
    INVARIANT_RUNTIME_EPOCH,
    INVARIANT_CHANNEL_ATOMICITY,
    INVARIANT_WAKER_DEDUP,
    INVARIANT_ACTOR_LEAK,
    INVARIANT_SUPERVISION,
    INVARIANT_MAILBOX,
    INVARIANT_RREF_ACCESS,
    INVARIANT_REPLY_LINEARITY,
    INVARIANT_REGISTRY_LEASE,
    INVARIANT_DOWN_ORDER,
    INVARIANT_SUPERVISOR_QUIESCENCE,
    #[cfg(feature = "messaging-fabric")]
    INVARIANT_FABRIC_PUBLISH,
    #[cfg(feature = "messaging-fabric")]
    INVARIANT_FABRIC_REPLY,
    #[cfg(feature = "messaging-fabric")]
    INVARIANT_FABRIC_QUIESCENCE,
    #[cfg(feature = "messaging-fabric")]
    INVARIANT_FABRIC_REDELIVERY,
];

/// Function pointer for oracles that can be constructed behind the common
/// [`Oracle`] trait today.
pub type OracleConstructor = fn() -> Box<dyn Oracle>;

/// Metadata for one registered lab oracle.
#[derive(Debug, Clone, Copy)]
pub struct OracleDescriptor {
    /// Stable machine name used in reports, scenario YAML, and evidence rows.
    pub name: &'static str,
    /// Human-readable invariant statement checked by the oracle.
    pub invariant: &'static str,
    /// Short description for docs and operator output.
    pub description: &'static str,
    /// Whether `oracles: ["all"]` includes this oracle through `OracleSuite`.
    pub default_enabled: bool,
    /// Feature flags, config gates, or integration status required to use it.
    pub requires: &'static [&'static str],
    /// Small usage snippet for generated docs or CLI help.
    pub example: &'static str,
    /// Stable ASUP error-code family expected for diagnostics from this oracle.
    pub asup_code_family: &'static str,
    /// Whether this oracle currently emits an `OracleReport` entry.
    pub report_entry: bool,
    /// Constructor for object-safe oracles already adapted to [`Oracle`].
    pub constructor: Option<OracleConstructor>,
}

fn quiescence_constructor() -> Box<dyn Oracle> {
    Box::new(QuiescenceOracle::new())
}

#[cfg(feature = "messaging-fabric")]
fn fabric_publish_constructor() -> Box<dyn Oracle> {
    Box::new(FabricPublishOracle::new())
}

#[cfg(feature = "messaging-fabric")]
fn fabric_reply_constructor() -> Box<dyn Oracle> {
    Box::new(FabricReplyOracle::new())
}

#[cfg(feature = "messaging-fabric")]
fn fabric_quiescence_constructor() -> Box<dyn Oracle> {
    Box::new(FabricQuiescenceOracle::new())
}

#[cfg(feature = "messaging-fabric")]
fn fabric_redelivery_constructor() -> Box<dyn Oracle> {
    Box::new(FabricRedeliveryOracle::new())
}

/// Static descriptor table for built-in lab oracles.
pub const ORACLE_DESCRIPTORS: &[OracleDescriptor] = &[
    OracleDescriptor {
        name: INVARIANT_TASK_LEAK,
        invariant: "structured concurrency: every task is owned and completed before region close",
        description: "Detects live tasks left behind when their owning region closes.",
        default_enabled: true,
        requires: &[],
        example: r#"LabConfig::new(42).with_oracles(&["task_leak"])"#,
        asup_code_family: "ASUP-E0xx",
        report_entry: true,
        constructor: None,
    },
    OracleDescriptor {
        name: INVARIANT_OBLIGATION_LEAK,
        invariant: "no obligation leaks: permits, acks, and leases resolve before close",
        description: "Detects unresolved obligations at region close.",
        default_enabled: true,
        requires: &[],
        example: r#"LabConfig::new(42).with_oracles(&["obligation_leak"])"#,
        asup_code_family: "ASUP-E1xx",
        report_entry: true,
        constructor: None,
    },
    OracleDescriptor {
        name: INVARIANT_QUIESCENCE,
        invariant: "region close => quiescence",
        description: "Checks that closed regions have no live children, tasks, finalizers, or obligations.",
        default_enabled: true,
        requires: &[],
        example: r#"LabConfig::new(42).with_oracles(&["quiescence"])"#,
        asup_code_family: "ASUP-E0xx",
        report_entry: true,
        constructor: Some(quiescence_constructor),
    },
    OracleDescriptor {
        name: INVARIANT_LOSER_DRAIN,
        invariant: "race losers are canceled and fully drained",
        description: "Detects race participants that remain incomplete after a race winner resolves.",
        default_enabled: true,
        requires: &[],
        example: r#"LabConfig::new(42).with_oracles(&["loser_drain"])"#,
        asup_code_family: "ASUP-E3xx",
        report_entry: true,
        constructor: None,
    },
    OracleDescriptor {
        name: INVARIANT_FINALIZER,
        invariant: "registered finalizers run before close completes",
        description: "Checks finalizer registration, execution, and closed-region accounting.",
        default_enabled: true,
        requires: &[],
        example: r#"LabConfig::new(42).with_oracles(&["finalizer"])"#,
        asup_code_family: "ASUP-E0xx",
        report_entry: true,
        constructor: None,
    },
    OracleDescriptor {
        name: INVARIANT_REGION_TREE,
        invariant: "regions form one rooted ownership tree",
        description: "Checks parent links, roots, and region-tree structure.",
        default_enabled: true,
        requires: &[],
        example: r#"LabConfig::new(42).with_oracles(&["region_tree"])"#,
        asup_code_family: "ASUP-E0xx",
        report_entry: true,
        constructor: None,
    },
    OracleDescriptor {
        name: INVARIANT_REGION_LEAK,
        invariant: "regions do not remain stuck or leaked past lifecycle bounds",
        description: "Detects stuck region creation, close, and task lifecycle leaks.",
        default_enabled: true,
        requires: &[],
        example: r#"LabConfig::new(42).with_oracles(&["region_leak"])"#,
        asup_code_family: "ASUP-E0xx",
        report_entry: true,
        constructor: None,
    },
    OracleDescriptor {
        name: INVARIANT_AMBIENT_AUTHORITY,
        invariant: "effects require explicit Cx capabilities",
        description: "Detects effects performed without the corresponding explicit capability.",
        default_enabled: true,
        requires: &[],
        example: r#"LabConfig::new(42).with_oracles(&["ambient_authority"])"#,
        asup_code_family: "ASUP-E0xx",
        report_entry: true,
        constructor: None,
    },
    OracleDescriptor {
        name: INVARIANT_DEADLINE_MONOTONE,
        invariant: "child deadlines are no looser than parent deadlines",
        description: "Checks deadline monotonicity across parent and child regions.",
        default_enabled: true,
        requires: &[],
        example: r#"LabConfig::new(42).with_oracles(&["deadline_monotone"])"#,
        asup_code_family: "ASUP-E0xx",
        report_entry: true,
        constructor: None,
    },
    OracleDescriptor {
        name: INVARIANT_CANCELLATION_PROTOCOL,
        invariant: "cancellation follows request, drain, finalize",
        description: "Checks cancellation requests, acknowledgements, transitions, and final states.",
        default_enabled: true,
        requires: &[],
        example: r#"LabConfig::new(42).with_oracles(&["cancellation_protocol"])"#,
        asup_code_family: "ASUP-E3xx",
        report_entry: true,
        constructor: None,
    },
    OracleDescriptor {
        name: INVARIANT_CANCEL_CORRECTNESS,
        invariant: "cancel-correctness witnesses start from valid initial states",
        description: "Checks cancel-correct witness validity and observed task lifecycle consistency.",
        default_enabled: true,
        requires: &[],
        example: r#"LabConfig::new(42).with_oracles(&["cancel_correctness"])"#,
        asup_code_family: "ASUP-E3xx",
        report_entry: true,
        constructor: None,
    },
    OracleDescriptor {
        name: INVARIANT_CANCEL_DEBT,
        invariant: "cancellation debt remains bounded and drains",
        description: "Tracks cancellation backlog and overdue cleanup work.",
        default_enabled: true,
        requires: &[],
        example: r#"LabConfig::new(42).with_oracles(&["cancel_debt"])"#,
        asup_code_family: "ASUP-E3xx",
        report_entry: true,
        constructor: None,
    },
    OracleDescriptor {
        name: INVARIANT_CANCEL_ORDERING,
        invariant: "cancel signal order is deterministic and causally valid",
        description: "Checks cancel-signal sequencing and ordering constraints.",
        default_enabled: true,
        requires: &[],
        example: r#"LabConfig::new(42).with_oracles(&["cancel_signal_ordering"])"#,
        asup_code_family: "ASUP-E3xx",
        report_entry: true,
        constructor: None,
    },
    OracleDescriptor {
        name: INVARIANT_RUNTIME_EPOCH,
        invariant: "runtime module epochs advance consistently",
        description: "Checks runtime epoch transitions across tracked modules.",
        default_enabled: true,
        requires: &[],
        example: r#"LabConfig::new(42).with_oracles(&["runtime_epoch"])"#,
        asup_code_family: "ASUP-E4xx",
        report_entry: true,
        constructor: None,
    },
    OracleDescriptor {
        name: INVARIANT_CHANNEL_ATOMICITY,
        invariant: "channel reservations and wakes are atomic",
        description: "Checks reservation commit/abort visibility and waker accounting.",
        default_enabled: true,
        requires: &[],
        example: r#"LabConfig::new(42).with_oracles(&["channel_atomicity"])"#,
        asup_code_family: "ASUP-E2xx",
        report_entry: true,
        constructor: None,
    },
    OracleDescriptor {
        name: INVARIANT_WAKER_DEDUP,
        invariant: "waker registration and wake delivery are deduplicated",
        description: "Detects lost, duplicate, or spurious wakeup state transitions.",
        default_enabled: true,
        requires: &[],
        example: r#"LabConfig::new(42).with_oracles(&["waker_dedup"])"#,
        asup_code_family: "ASUP-E4xx",
        report_entry: true,
        constructor: None,
    },
    OracleDescriptor {
        name: INVARIANT_ACTOR_LEAK,
        invariant: "actors stop before their owning region closes",
        description: "Detects actors left running at region close.",
        default_enabled: true,
        requires: &[],
        example: r#"LabConfig::new(42).with_oracles(&["actor_leak"])"#,
        asup_code_family: "ASUP-E0xx",
        report_entry: true,
        constructor: None,
    },
    OracleDescriptor {
        name: INVARIANT_SUPERVISION,
        invariant: "supervision restarts and escalations follow policy",
        description: "Checks supervisor restart limits, sibling restart policy, and escalation behavior.",
        default_enabled: true,
        requires: &[],
        example: r#"LabConfig::new(42).with_oracles(&["supervision"])"#,
        asup_code_family: "ASUP-E0xx",
        report_entry: true,
        constructor: None,
    },
    OracleDescriptor {
        name: INVARIANT_MAILBOX,
        invariant: "mailbox capacity and backpressure invariants hold",
        description: "Checks mailbox capacity, delivery, and backpressure accounting.",
        default_enabled: true,
        requires: &[],
        example: r#"LabConfig::new(42).with_oracles(&["mailbox"])"#,
        asup_code_family: "ASUP-E2xx",
        report_entry: true,
        constructor: None,
    },
    OracleDescriptor {
        name: INVARIANT_RREF_ACCESS,
        invariant: "RRef access respects region and witness boundaries",
        description: "Detects cross-region, post-close, or witness-mismatch RRef access.",
        default_enabled: true,
        requires: &[],
        example: r#"LabConfig::new(42).with_oracles(&["rref_access"])"#,
        asup_code_family: "ASUP-E0xx",
        report_entry: true,
        constructor: None,
    },
    OracleDescriptor {
        name: INVARIANT_REPLY_LINEARITY,
        invariant: "Spork replies resolve exactly once",
        description: "Checks reply obligations for send-or-abort linearity.",
        default_enabled: true,
        requires: &["spork"],
        example: r#"LabConfig::new(42).with_oracles(&["reply_linearity"])"#,
        asup_code_family: "ASUP-E1xx",
        report_entry: true,
        constructor: None,
    },
    OracleDescriptor {
        name: INVARIANT_REGISTRY_LEASE,
        invariant: "Spork registry leases are committed or aborted",
        description: "Checks name-registry lease linearity.",
        default_enabled: true,
        requires: &["spork"],
        example: r#"LabConfig::new(42).with_oracles(&["registry_lease"])"#,
        asup_code_family: "ASUP-E1xx",
        report_entry: true,
        constructor: None,
    },
    OracleDescriptor {
        name: INVARIANT_DOWN_ORDER,
        invariant: "DOWN messages are delivered in deterministic order",
        description: "Checks deterministic ordering of process DOWN notifications.",
        default_enabled: true,
        requires: &["spork"],
        example: r#"LabConfig::new(42).with_oracles(&["down_order"])"#,
        asup_code_family: "ASUP-E4xx",
        report_entry: true,
        constructor: None,
    },
    OracleDescriptor {
        name: INVARIANT_SUPERVISOR_QUIESCENCE,
        invariant: "supervisor regions close with no active children",
        description: "Checks Spork supervisor region quiescence.",
        default_enabled: true,
        requires: &["spork"],
        example: r#"LabConfig::new(42).with_oracles(&["supervisor_quiescence"])"#,
        asup_code_family: "ASUP-E0xx",
        report_entry: true,
        constructor: None,
    },
    OracleDescriptor {
        name: INVARIANT_PRIORITY_INVERSION,
        invariant: "higher-priority work is not blocked indefinitely by lower-priority holders",
        description: "Tracks priority inversion witnesses; not yet emitted by OracleSuite::report.",
        default_enabled: false,
        requires: &["manual instrumentation", "not in OracleSuite::report"],
        example: r"PriorityInversionOracle::new(config)",
        asup_code_family: "ASUP-E4xx",
        report_entry: false,
        constructor: None,
    },
    #[cfg(feature = "messaging-fabric")]
    OracleDescriptor {
        name: INVARIANT_FABRIC_PUBLISH,
        invariant: "FABRIC committed publishes reach matching subscribers",
        description: "Checks native FABRIC publish delivery.",
        default_enabled: true,
        requires: &["messaging-fabric"],
        example: r#"LabConfig::new(42).with_oracles(&["fabric_publish"])"#,
        asup_code_family: "ASUP-E7xx",
        report_entry: true,
        constructor: Some(fabric_publish_constructor),
    },
    #[cfg(feature = "messaging-fabric")]
    OracleDescriptor {
        name: INVARIANT_FABRIC_REPLY,
        invariant: "FABRIC obligation-backed replies resolve before close",
        description: "Checks native FABRIC request/reply obligation resolution.",
        default_enabled: true,
        requires: &["messaging-fabric"],
        example: r#"LabConfig::new(42).with_oracles(&["fabric_reply"])"#,
        asup_code_family: "ASUP-E7xx",
        report_entry: true,
        constructor: Some(fabric_reply_constructor),
    },
    #[cfg(feature = "messaging-fabric")]
    OracleDescriptor {
        name: INVARIANT_FABRIC_QUIESCENCE,
        invariant: "FABRIC cells are quiescent when regions close",
        description: "Checks native FABRIC cell emptiness at region close.",
        default_enabled: true,
        requires: &["messaging-fabric"],
        example: r#"LabConfig::new(42).with_oracles(&["fabric_quiescence"])"#,
        asup_code_family: "ASUP-E7xx",
        report_entry: true,
        constructor: Some(fabric_quiescence_constructor),
    },
    #[cfg(feature = "messaging-fabric")]
    OracleDescriptor {
        name: INVARIANT_FABRIC_REDELIVERY,
        invariant: "FABRIC redelivery remains within its explicit bound",
        description: "Checks native FABRIC redelivery attempts against configured limits.",
        default_enabled: true,
        requires: &["messaging-fabric"],
        example: r#"LabConfig::new(42).with_oracles(&["fabric_redelivery"])"#,
        asup_code_family: "ASUP-E7xx",
        report_entry: true,
        constructor: Some(fabric_redelivery_constructor),
    },
];

/// Registry validation and instantiation error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OracleRegistryError {
    /// The requested oracle name is unknown.
    UnknownOracle {
        /// Unknown name supplied by the caller.
        name: String,
        /// Closest known oracle name, when one is useful.
        suggestion: Option<&'static str>,
    },
    /// The oracle is known but not yet selectable from scenario reports.
    NotReportable {
        /// Known name supplied by the caller.
        name: String,
    },
    /// The oracle is known but has no object-safe constructor yet.
    NotInstantiable {
        /// Known name supplied by the caller.
        name: String,
    },
}

impl OracleRegistryError {
    /// Unknown or non-reportable name that triggered this error.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::UnknownOracle { name, .. }
            | Self::NotReportable { name }
            | Self::NotInstantiable { name } => name,
        }
    }
}

impl std::fmt::Display for OracleRegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownOracle { name, suggestion } => {
                write!(f, "unknown oracle `{name}`")?;
                if let Some(suggestion) = suggestion {
                    write!(f, "; did you mean `{suggestion}`")?;
                }
                write!(
                    f,
                    "; valid names: {}",
                    OracleRegistry::reported_names().join(", ")
                )
            }
            Self::NotReportable { name } => write!(
                f,
                "oracle `{name}` is registered but is not emitted by OracleSuite::report yet"
            ),
            Self::NotInstantiable { name } => write!(
                f,
                "oracle `{name}` is registered but does not expose an object-safe constructor yet"
            ),
        }
    }
}

impl std::error::Error for OracleRegistryError {}

/// Static entry point for querying built-in lab oracle metadata.
#[derive(Debug, Clone, Copy, Default)]
pub struct OracleRegistry;

impl OracleRegistry {
    /// Return every registered oracle descriptor, including non-reportable ones.
    #[must_use]
    pub const fn list_all() -> &'static [OracleDescriptor] {
        ORACLE_DESCRIPTORS
    }

    /// Return every oracle name emitted by `OracleSuite::report`.
    #[must_use]
    pub const fn reported_names() -> &'static [&'static str] {
        ALL_REPORTED_ORACLE_NAMES
    }

    /// Return descriptors that are emitted by `OracleSuite::report`.
    pub fn reported_descriptors() -> impl Iterator<Item = &'static OracleDescriptor> {
        ORACLE_DESCRIPTORS
            .iter()
            .filter(|descriptor| descriptor.report_entry)
    }

    /// Find one descriptor by its stable machine name.
    #[must_use]
    pub fn find(name: &str) -> Option<&'static OracleDescriptor> {
        ORACLE_DESCRIPTORS
            .iter()
            .find(|descriptor| descriptor.name == name)
    }

    /// Return true if the name is known to the registry.
    #[must_use]
    pub fn contains(name: &str) -> bool {
        Self::find(name).is_some()
    }

    /// Return true if the name is known and emitted by `OracleSuite::report`.
    #[must_use]
    pub fn is_reportable(name: &str) -> bool {
        Self::find(name).is_some_and(|descriptor| descriptor.report_entry)
    }

    /// Search descriptors by name, invariant text, or description.
    #[must_use]
    pub fn find_by_invariant(query: &str) -> Vec<&'static OracleDescriptor> {
        let needle = query.trim().to_ascii_lowercase();
        if needle.is_empty() {
            return Vec::new();
        }

        ORACLE_DESCRIPTORS
            .iter()
            .filter(|descriptor| {
                descriptor.name.contains(needle.as_str())
                    || descriptor
                        .invariant
                        .to_ascii_lowercase()
                        .contains(needle.as_str())
                    || descriptor
                        .description
                        .to_ascii_lowercase()
                        .contains(needle.as_str())
            })
            .collect()
    }

    /// Return true if the selection requests every reportable oracle.
    #[must_use]
    pub fn is_all_selection(names: &[String]) -> bool {
        names.iter().any(|name| name == ORACLE_ALL)
    }

    /// Resolve a string slice selection into reportable oracle names.
    pub fn select_reported(names: &[String]) -> Result<Vec<&'static str>, OracleRegistryError> {
        if names.is_empty() {
            return Ok(Self::reported_names().to_vec());
        }

        let mut has_all = false;
        let mut selected = Vec::with_capacity(names.len());
        for name in names {
            if name == ORACLE_ALL {
                has_all = true;
            } else {
                selected.push(Self::validate_reported_name(name)?);
            }
        }

        if has_all {
            Ok(Self::reported_names().to_vec())
        } else {
            Ok(selected)
        }
    }

    /// Resolve a borrowed string selection into reportable oracle names.
    pub fn select_reported_strs(names: &[&str]) -> Result<Vec<&'static str>, OracleRegistryError> {
        if names.is_empty() {
            return Ok(Self::reported_names().to_vec());
        }

        let mut has_all = false;
        let mut selected = Vec::with_capacity(names.len());
        for name in names {
            if *name == ORACLE_ALL {
                has_all = true;
            } else {
                selected.push(Self::validate_reported_name(name)?);
            }
        }

        if has_all {
            Ok(Self::reported_names().to_vec())
        } else {
            Ok(selected)
        }
    }

    /// Validate all names in a scenario-style selection.
    pub fn validate_reported_selection(names: &[String]) -> Result<(), OracleRegistryError> {
        Self::select_reported(names).map(|_| ())
    }

    /// Instantiate an oracle that already exposes the common object-safe trait.
    pub fn instantiate(name: &str) -> Result<Box<dyn Oracle>, OracleRegistryError> {
        let descriptor = Self::find(name).ok_or_else(|| OracleRegistryError::UnknownOracle {
            name: name.to_owned(),
            suggestion: Self::suggestion_for(name),
        })?;
        let constructor =
            descriptor
                .constructor
                .ok_or_else(|| OracleRegistryError::NotInstantiable {
                    name: name.to_owned(),
                })?;
        Ok(constructor())
    }

    /// Suggest the closest known oracle name when edit distance is small.
    #[must_use]
    pub fn suggestion_for(name: &str) -> Option<&'static str> {
        ORACLE_DESCRIPTORS
            .iter()
            .map(|descriptor| (descriptor.name, levenshtein(name, descriptor.name)))
            .filter(|(_, distance)| *distance <= 3)
            .min_by_key(|(_, distance)| *distance)
            .map(|(name, _)| name)
    }

    fn validate_reported_name(name: &str) -> Result<&'static str, OracleRegistryError> {
        let descriptor = Self::find(name).ok_or_else(|| OracleRegistryError::UnknownOracle {
            name: name.to_owned(),
            suggestion: Self::suggestion_for(name),
        })?;

        if !descriptor.report_entry {
            return Err(OracleRegistryError::NotReportable {
                name: name.to_owned(),
            });
        }

        Ok(descriptor.name)
    }
}

fn levenshtein(left: &str, right: &str) -> usize {
    if left == right {
        return 0;
    }
    if left.is_empty() {
        return right.chars().count();
    }
    if right.is_empty() {
        return left.chars().count();
    }

    let right_chars = right.chars().collect::<Vec<_>>();
    let mut previous = (0..=right_chars.len()).collect::<Vec<_>>();
    let mut current = vec![0; right_chars.len() + 1];

    for (left_index, left_char) in left.chars().enumerate() {
        current[0] = left_index + 1;
        for (right_index, right_char) in right_chars.iter().enumerate() {
            let substitution_cost = usize::from(left_char != *right_char);
            current[right_index + 1] = (current[right_index] + 1)
                .min(previous[right_index + 1] + 1)
                .min(previous[right_index] + substitution_cost);
        }
        std::mem::swap(&mut previous, &mut current);
    }

    previous[right_chars.len()]
}

#[cfg(test)]
mod tests {
    #![allow(clippy::pedantic, clippy::nursery)]

    use super::*;
    use crate::lab::oracle::OracleSuite;
    use crate::types::Time;
    use std::collections::BTreeSet;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn registry_descriptors_are_complete_and_unique() {
        init_test("registry_descriptors_are_complete_and_unique");
        let mut names = BTreeSet::new();
        for descriptor in OracleRegistry::list_all() {
            assert!(!descriptor.name.is_empty());
            assert!(!descriptor.invariant.is_empty());
            assert!(!descriptor.description.is_empty());
            assert!(!descriptor.example.is_empty());
            assert!(!descriptor.asup_code_family.is_empty());
            assert!(
                names.insert(descriptor.name),
                "duplicate {}",
                descriptor.name
            );
        }
        assert!(OracleRegistry::contains(INVARIANT_PRIORITY_INVERSION));
        crate::test_complete!("registry_descriptors_are_complete_and_unique");
    }

    #[test]
    fn registry_reported_names_match_oracle_suite_report() {
        init_test("registry_reported_names_match_oracle_suite_report");
        let mut suite = OracleSuite::new();
        let report = suite.report(Time::ZERO);
        let report_names = report
            .entries
            .iter()
            .map(|entry| entry.invariant.as_str())
            .collect::<BTreeSet<_>>();
        let registry_names = OracleRegistry::reported_descriptors()
            .map(|descriptor| descriptor.name)
            .collect::<BTreeSet<_>>();
        assert_eq!(report_names, registry_names);
        crate::test_complete!("registry_reported_names_match_oracle_suite_report");
    }

    #[test]
    fn registry_selection_expands_all_and_rejects_unknowns() {
        init_test("registry_selection_expands_all_and_rejects_unknowns");
        let all = OracleRegistry::select_reported_strs(&[ORACLE_ALL]).expect("all resolves");
        assert_eq!(all.len(), OracleRegistry::reported_names().len());

        let selected =
            OracleRegistry::select_reported_strs(&[INVARIANT_TASK_LEAK, INVARIANT_OBLIGATION_LEAK])
                .expect("known names resolve");
        assert_eq!(
            selected,
            vec![INVARIANT_TASK_LEAK, INVARIANT_OBLIGATION_LEAK]
        );

        let err = OracleRegistry::select_reported_strs(&["task_lek"])
            .expect_err("unknown oracle rejects");
        assert!(matches!(
            err,
            OracleRegistryError::UnknownOracle {
                suggestion: Some(INVARIANT_TASK_LEAK),
                ..
            }
        ));

        let err = OracleRegistry::select_reported_strs(&[ORACLE_ALL, "task_lek"])
            .expect_err("all should not hide unknown oracle names");
        assert!(matches!(
            err,
            OracleRegistryError::UnknownOracle {
                suggestion: Some(INVARIANT_TASK_LEAK),
                ..
            }
        ));
        crate::test_complete!("registry_selection_expands_all_and_rejects_unknowns");
    }

    #[test]
    fn registry_finds_quiescence_by_invariant_text_and_instantiates_it() {
        init_test("registry_finds_quiescence_by_invariant_text_and_instantiates_it");
        let matches = OracleRegistry::find_by_invariant("region close");
        assert!(matches.iter().any(|d| d.name == INVARIANT_QUIESCENCE));

        let oracle = OracleRegistry::instantiate(INVARIANT_QUIESCENCE)
            .expect("quiescence has object-safe constructor");
        assert_eq!(oracle.invariant_name(), INVARIANT_QUIESCENCE);

        let err = match OracleRegistry::instantiate(INVARIANT_TASK_LEAK) {
            Ok(_) => panic!("task_leak constructor is not adapted yet"),
            Err(err) => err,
        };
        assert!(matches!(err, OracleRegistryError::NotInstantiable { .. }));
        crate::test_complete!("registry_finds_quiescence_by_invariant_text_and_instantiates_it");
    }

    #[test]
    fn testing_for_agents_lists_reported_registry_names() {
        init_test("testing_for_agents_lists_reported_registry_names");
        let docs = include_str!("../../../TESTING_FOR_AGENTS.md");
        assert!(docs.contains("asupersync::lab::OracleRegistry"));
        for name in OracleRegistry::reported_names() {
            assert!(
                docs.contains(&format!("`{name}`")),
                "TESTING_FOR_AGENTS.md must list `{name}`"
            );
        }
        crate::test_complete!("testing_for_agents_lists_reported_registry_names");
    }
}
