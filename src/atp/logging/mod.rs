//! ATP Structured Logging and Trace Redaction
//!
//! Provides consistent, deterministic, and safe logging for all ATP subsystems.
//! Implements trace redaction, failure bundles, and replay artifacts per ATP-N6.

pub mod failure_bundle;
pub mod redaction;
pub mod replay_artifacts;
pub mod schema;

#[cfg(all(test, feature = "legacy-internal-test-harnesses"))]
mod tests;

#[cfg(all(test, feature = "legacy-internal-test-harnesses"))]
mod contract_validation_tests;

pub use failure_bundle::ATP_FAILURE_BUNDLE_SCHEMA_VERSION;
pub use replay_artifacts::ATP_REPLAY_ARTIFACT_SCHEMA_ID;

use crate::observability::level::LogLevel as Level;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::OnceLock;

/// Stable ATP structured-log event schema.
pub const ATP_LOG_EVENT_SCHEMA_VERSION: &str = "asupersync.atp.log.event.v1";

/// ATP event schema for consistent logging across all subsystems
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtpEvent {
    /// Stable schema version for machine validation.
    pub schema_version: String,
    /// Event timestamp in RFC3339 format
    pub timestamp: String,
    /// Log level
    #[serde(with = "log_level_serde")]
    pub level: Level,
    /// ATP subsystem that generated the event
    pub subsystem: AtpSubsystem,
    /// Event type within the subsystem
    pub event_type: String,
    /// Structured event data
    pub data: serde_json::Value,
    /// Context identifiers for correlation
    pub context: EventContext,
    /// Redacted fields (for audit trails)
    pub redacted_fields: Vec<String>,
}

/// ATP subsystems for event categorization
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AtpSubsystem {
    /// Path discovery and management
    Path,
    /// QUIC protocol and transport
    Quic,
    /// Transfer coordination and scheduling
    Transfer,
    /// Task and job scheduling
    Scheduler,
    /// RaptorQ repair coordination
    Repair,
    /// Disk I/O and storage
    Disk,
    /// Journal and persistence
    Journal,
    /// Proof verification and generation
    Verifier,
    /// ATP daemon operations
    Daemon,
    /// CLI interface and commands
    Cli,
    /// Relay operations
    Relay,
    /// Mailbox operations
    Mailbox,
    /// Security and access control
    Security,
    /// Unit tests
    UnitTest,
    /// Lab/integration tests
    LabTest,
    /// End-to-end tests
    E2eTest,
    /// Benchmark tests
    BenchmarkTest,
    /// Release proof tests
    ReleaseProofTest,
}

impl AtpSubsystem {
    /// All ATP subsystems and ATP test lanes covered by the logging contract.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Path,
            Self::Quic,
            Self::Transfer,
            Self::Scheduler,
            Self::Repair,
            Self::Disk,
            Self::Journal,
            Self::Verifier,
            Self::Daemon,
            Self::Cli,
            Self::Relay,
            Self::Mailbox,
            Self::Security,
            Self::UnitTest,
            Self::LabTest,
            Self::E2eTest,
            Self::BenchmarkTest,
            Self::ReleaseProofTest,
        ]
    }

    /// Stable subsystem name used in human diagnostics.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Path => "path",
            Self::Quic => "quic",
            Self::Transfer => "transfer",
            Self::Scheduler => "scheduler",
            Self::Repair => "repair",
            Self::Disk => "disk",
            Self::Journal => "journal",
            Self::Verifier => "verifier",
            Self::Daemon => "daemon",
            Self::Cli => "cli",
            Self::Relay => "relay",
            Self::Mailbox => "mailbox",
            Self::Security => "security",
            Self::UnitTest => "unit_test",
            Self::LabTest => "lab_test",
            Self::E2eTest => "e2e_test",
            Self::BenchmarkTest => "benchmark_test",
            Self::ReleaseProofTest => "release_proof_test",
        }
    }
}

/// Event correlation context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventContext {
    /// Unique session identifier
    pub session_id: String,
    /// Transfer operation ID (if applicable)
    pub transfer_id: Option<String>,
    /// Connection ID (if applicable)
    pub connection_id: Option<String>,
    /// Peer identity token. Shareable artifacts redact this by default.
    pub peer_id: Option<String>,
    /// Test case ID (for test events)
    pub test_case_id: Option<String>,
    /// Trace ID for distributed tracing
    pub trace_id: String,
    /// Span ID for distributed tracing
    pub span_id: String,
}

impl EventContext {
    /// Deterministic context helper for tests and replay artifacts.
    #[must_use]
    pub fn deterministic(session_id: impl Into<String>, trace_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            transfer_id: None,
            connection_id: None,
            peer_id: None,
            test_case_id: None,
            trace_id: trace_id.into(),
            span_id: "root".to_string(),
        }
    }
}

/// ATP logger configuration
#[derive(Debug, Clone)]
pub struct AtpLoggerConfig {
    /// Enable structured logging
    pub structured: bool,
    /// Enable trace redaction
    pub redaction_enabled: bool,
    /// Output format (json, human)
    pub format: LogFormat,
    /// Minimum log level
    pub min_level: Level,
    /// Redaction rules
    pub redaction_rules: Vec<RedactionRule>,
}

/// Log output format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogFormat {
    Json,
    Human,
}

/// Rendering or schema-validation error for ATP log events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AtpLogError {
    /// Event type is not in the subsystem schema.
    UnknownEventType {
        subsystem: AtpSubsystem,
        event_type: String,
    },
    /// JSON serialization failed.
    Serialization(String),
}

impl std::fmt::Display for AtpLogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownEventType {
                subsystem,
                event_type,
            } => write!(
                f,
                "unknown ATP event type {event_type:?} for subsystem {}",
                subsystem.as_str()
            ),
            Self::Serialization(message) => write!(f, "ATP log serialization failed: {message}"),
        }
    }
}

impl std::error::Error for AtpLogError {}

/// Redaction rule for sensitive data
#[derive(Debug, Clone)]
pub struct RedactionRule {
    /// Field pattern to match
    pub field_pattern: String,
    /// Redaction type
    pub redaction_type: RedactionType,
    /// Replacement value
    pub replacement: String,
}

/// Types of redaction
#[derive(Debug, Clone)]
pub enum RedactionType {
    /// Hide private keys completely
    PrivateKey,
    /// Hide auth tokens
    AuthToken,
    /// Hide capability secrets
    CapabilitySecret,
    /// Hide sensitive file paths
    SensitivePath,
    /// Hide content hashes (policy-dependent)
    ContentHash,
    /// Custom redaction with regex
    Custom(String),
}

impl Default for AtpLoggerConfig {
    fn default() -> Self {
        Self {
            structured: true,
            redaction_enabled: true,
            format: LogFormat::Json,
            min_level: Level::Info,
            redaction_rules: default_redaction_rules(),
        }
    }
}

/// Default redaction rules for ATP logging
fn default_redaction_rules() -> Vec<RedactionRule> {
    vec![
        RedactionRule {
            field_pattern: "private_key".to_string(),
            redaction_type: RedactionType::PrivateKey,
            replacement: "[REDACTED_PRIVATE_KEY]".to_string(),
        },
        RedactionRule {
            field_pattern: "auth_token".to_string(),
            redaction_type: RedactionType::AuthToken,
            replacement: "[REDACTED_TOKEN]".to_string(),
        },
        RedactionRule {
            field_pattern: "token".to_string(),
            redaction_type: RedactionType::AuthToken,
            replacement: "[REDACTED_TOKEN]".to_string(),
        },
        RedactionRule {
            field_pattern: "authorization".to_string(),
            redaction_type: RedactionType::AuthToken,
            replacement: "[REDACTED_TOKEN]".to_string(),
        },
        RedactionRule {
            field_pattern: "password".to_string(),
            redaction_type: RedactionType::AuthToken,
            replacement: "[REDACTED_TOKEN]".to_string(),
        },
        RedactionRule {
            field_pattern: "capability_secret".to_string(),
            redaction_type: RedactionType::CapabilitySecret,
            replacement: "[REDACTED_CAPABILITY]".to_string(),
        },
        RedactionRule {
            field_pattern: "capability".to_string(),
            redaction_type: RedactionType::CapabilitySecret,
            replacement: "[REDACTED_CAPABILITY]".to_string(),
        },
        RedactionRule {
            field_pattern: "context.peer_id".to_string(),
            redaction_type: RedactionType::Custom("peer".to_string()),
            replacement: "[REDACTED_PEER_ID]".to_string(),
        },
        RedactionRule {
            field_pattern: "peer_id".to_string(),
            redaction_type: RedactionType::Custom("peer".to_string()),
            replacement: "[REDACTED_PEER_ID]".to_string(),
        },
        RedactionRule {
            field_pattern: "path".to_string(),
            redaction_type: RedactionType::SensitivePath,
            replacement: "[REDACTED_PATH]".to_string(),
        },
        RedactionRule {
            field_pattern: "content_hash".to_string(),
            redaction_type: RedactionType::ContentHash,
            replacement: "[REDACTED_CONTENT_HASH]".to_string(),
        },
        RedactionRule {
            field_pattern: r".*\.key$".to_string(),
            redaction_type: RedactionType::Custom(r".*\.key$".to_string()),
            replacement: "[REDACTED_KEY_FILE]".to_string(),
        },
    ]
}

/// ATP structured logger
pub struct AtpLogger {
    config: AtpLoggerConfig,
    event_schemas: HashMap<AtpSubsystem, Vec<String>>,
}

impl AtpLogger {
    /// Create new ATP logger with default configuration
    pub fn new() -> Self {
        Self::with_config(AtpLoggerConfig::default())
    }

    /// Create new ATP logger with custom configuration
    pub fn with_config(config: AtpLoggerConfig) -> Self {
        let mut logger = Self {
            config,
            event_schemas: HashMap::new(),
        };
        logger.load_schemas();
        logger
    }

    /// Load event schemas for all subsystems
    fn load_schemas(&mut self) {
        // Schema definitions will be added in schema.rs
        self.event_schemas
            .insert(AtpSubsystem::Path, schema::path_event_types());
        self.event_schemas
            .insert(AtpSubsystem::Quic, schema::quic_event_types());
        self.event_schemas
            .insert(AtpSubsystem::Transfer, schema::transfer_event_types());
        self.event_schemas
            .insert(AtpSubsystem::Scheduler, schema::scheduler_event_types());
        self.event_schemas
            .insert(AtpSubsystem::Repair, schema::repair_event_types());
        self.event_schemas
            .insert(AtpSubsystem::Disk, schema::disk_event_types());
        self.event_schemas
            .insert(AtpSubsystem::Journal, schema::journal_event_types());
        self.event_schemas
            .insert(AtpSubsystem::Verifier, schema::verifier_event_types());
        self.event_schemas
            .insert(AtpSubsystem::Daemon, schema::daemon_event_types());
        self.event_schemas
            .insert(AtpSubsystem::Cli, schema::cli_event_types());
        self.event_schemas
            .insert(AtpSubsystem::Relay, schema::relay_event_types());
        self.event_schemas
            .insert(AtpSubsystem::Mailbox, schema::mailbox_event_types());
        self.event_schemas
            .insert(AtpSubsystem::Security, schema::security_event_types());
        self.event_schemas
            .insert(AtpSubsystem::UnitTest, schema::test_lane_event_types());
        self.event_schemas
            .insert(AtpSubsystem::LabTest, schema::test_lane_event_types());
        self.event_schemas
            .insert(AtpSubsystem::E2eTest, schema::test_lane_event_types());
        self.event_schemas
            .insert(AtpSubsystem::BenchmarkTest, schema::test_lane_event_types());
        self.event_schemas.insert(
            AtpSubsystem::ReleaseProofTest,
            schema::test_lane_event_types(),
        );
    }

    /// Validate an ATP event against the registered subsystem schema.
    pub fn validate_event(&self, event: &AtpEvent) -> Result<(), AtpLogError> {
        let Some(event_types) = self.event_schemas.get(&event.subsystem) else {
            return Err(AtpLogError::UnknownEventType {
                subsystem: event.subsystem.clone(),
                event_type: event.event_type.clone(),
            });
        };

        if event_types
            .iter()
            .any(|allowed_event| allowed_event == &event.event_type)
        {
            Ok(())
        } else {
            Err(AtpLogError::UnknownEventType {
                subsystem: event.subsystem.clone(),
                event_type: event.event_type.clone(),
            })
        }
    }

    /// Return event types registered for a subsystem.
    #[must_use]
    pub fn schema_event_types(&self, subsystem: &AtpSubsystem) -> Option<&[String]> {
        self.event_schemas.get(subsystem).map(Vec::as_slice)
    }

    /// Render an ATP event with automatic redaction.
    ///
    /// Core code returns the formatted record to the caller instead of writing
    /// to stdout/stderr.
    pub fn render_event(&self, event: &AtpEvent) -> Result<String, AtpLogError> {
        let mut event = event.clone();
        if self.config.redaction_enabled {
            redaction::apply_redaction(&mut event, &self.config.redaction_rules);
        }
        self.validate_event(&event)?;

        match self.config.format {
            LogFormat::Json => serde_json::to_string(&event)
                .map_err(|err| AtpLogError::Serialization(err.to_string())),
            LogFormat::Human => Ok(render_human_event(&event)),
        }
    }

    /// Redact, validate, and render an event in place.
    pub fn log_event(&self, event: &mut AtpEvent) -> Result<String, AtpLogError> {
        if self.config.redaction_enabled {
            redaction::apply_redaction(event, &self.config.redaction_rules);
        }
        self.validate_event(event)?;

        match self.config.format {
            LogFormat::Json => serde_json::to_string(event)
                .map_err(|err| AtpLogError::Serialization(err.to_string())),
            LogFormat::Human => Ok(render_human_event(event)),
        }
    }

    /// Create a failure bundle for debugging and replay
    pub fn create_failure_bundle(
        &self,
        error_context: &str,
        additional_data: serde_json::Value,
    ) -> failure_bundle::FailureBundle {
        failure_bundle::create_bundle(error_context, additional_data, &self.config)
    }

    /// Generate replay artifacts for deterministic failure reproduction
    pub fn generate_replay_artifacts(
        &self,
        session_id: &str,
        seed: u64,
    ) -> replay_artifacts::ReplayArtifacts {
        replay_artifacts::generate(session_id, seed, &self.config)
    }
}

fn render_human_event(event: &AtpEvent) -> String {
    format!(
        "{} [{}] schema={} {}.{} trace={} span={} data={} redacted={}",
        event.timestamp,
        event.level,
        event.schema_version,
        event.subsystem.as_str(),
        event.event_type,
        event.context.trace_id,
        event.context.span_id,
        event.data,
        event.redacted_fields.join(",")
    )
}

impl Default for AtpLogger {
    fn default() -> Self {
        Self::new()
    }
}

/// Global ATP logger instance for boundary adapters that cannot pass a logger
/// directly. Core paths should prefer explicit `AtpLogger` values.
static ATP_LOGGER: OnceLock<AtpLogger> = OnceLock::new();

/// Initialize the global ATP logger
pub fn init_atp_logger(config: Option<AtpLoggerConfig>) -> bool {
    ATP_LOGGER
        .set(AtpLogger::with_config(config.unwrap_or_default()))
        .is_ok()
}

/// Get reference to global ATP logger
pub fn atp_logger() -> Option<&'static AtpLogger> {
    ATP_LOGGER.get()
}

/// Convenience macro for ATP logging
#[macro_export]
macro_rules! atp_log {
    ($subsystem:expr, $event_type:expr, $level:expr, $data:expr, $context:expr) => {
        if let Some(logger) = $crate::atp::logging::atp_logger() {
            let mut event = $crate::atp::logging::AtpEvent {
                schema_version: $crate::atp::logging::ATP_LOG_EVENT_SCHEMA_VERSION.to_string(),
                timestamp: $crate::atp::logging::current_timestamp(),
                level: $level,
                subsystem: $subsystem,
                event_type: $event_type.to_string(),
                data: $crate::atp::logging::atp_log_data_value($data),
                context: $context,
                redacted_fields: Vec::new(),
            };
            let _ = logger.log_event(&mut event);
        }
    };
}

#[doc(hidden)]
pub fn atp_log_data_value<T: Serialize>(data: T) -> serde_json::Value {
    serde_json::to_value(data).unwrap_or_default()
}

/// Get the current observability timestamp in RFC3339 UTC format.
pub fn current_timestamp() -> String {
    format_system_time_rfc3339(crate::observability::replayable_system_time())
}

fn format_system_time_rfc3339(time: std::time::SystemTime) -> String {
    let seconds_since_epoch = time
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    format_unix_seconds_rfc3339(seconds_since_epoch)
}

fn format_unix_seconds_rfc3339(seconds_since_epoch: u64) -> String {
    const SECONDS_PER_DAY: u64 = 86_400;

    let days = seconds_since_epoch / SECONDS_PER_DAY;
    let seconds_of_day = seconds_since_epoch % SECONDS_PER_DAY;
    let (year, month, day) = civil_from_unix_days(days);

    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn civil_from_unix_days(days_since_epoch: u64) -> (i64, i64, i64) {
    let days = i64::try_from(days_since_epoch).unwrap_or(i64::MAX - 719_468);
    let z = days.saturating_add(719_468);
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }

    (year, month, day)
}

mod log_level_serde {
    use super::Level;
    use serde::{Deserialize, Deserializer, Serializer};
    use std::str::FromStr;

    pub fn serialize<S>(level: &Level, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(level.as_str_lower())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Level, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Level::from_str(&value).map_err(serde::de::Error::custom)
    }
}
