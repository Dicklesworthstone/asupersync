//! CLI utilities for Asupersync tools.
//!
//! This module provides a comprehensive framework for building CLI tools that are
//! both human-friendly and machine-readable. Key features:
//!
//! - **Dual-mode output**: Automatic JSON/human output based on environment
//! - **Structured errors**: RFC 9457-style errors with context and suggestions
//! - **Semantic exit codes**: Machine-parseable exit codes for automation
//! - **Progress reporting**: Streaming progress with cancellation support
//! - **Signal handling**: Graceful shutdown with cancellation tokens
//! - **Shell completions**: Generation for bash, zsh, fish, PowerShell, elvish
//! - **First-run setup**: Interactive and automatic ATP configuration
//! - **Service integration**: Platform daemon/service management
//! - **Upgrade/rollback**: Version management with state preservation
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use asupersync::cli::{Output, OutputFormat, CliError, ExitCode};
//!
//! // Auto-detect output format (JSON in CI/pipes, human in terminal)
//! let format = OutputFormat::auto_detect();
//! let mut output = Output::new(format);
//!
//! // Write structured output
//! output.write(&my_data)?;
//!
//! // Handle errors with context
//! let error = CliError::new("config_error", "Invalid configuration")
//!     .detail("The 'timeout' field must be a positive integer")
//!     .suggestion("Set timeout to a value like 30 or 60")
//!     .context("field", "timeout")
//!     .exit_code(ExitCode::USER_ERROR);
//! ```
//!
//! # Output Format Detection
//!
//! The output format is automatically detected based on:
//! 1. `ASUPERSYNC_OUTPUT_FORMAT` environment variable
//! 2. `CI` environment variable (forces JSON)
//! 3. TTY detection (JSON for pipes, human for terminals)
//!
//! # Color Support
//!
//! Colors are automatically enabled for terminals and respect:
//! - `NO_COLOR` environment variable (disables colors)
//! - `CLICOLOR_FORCE` environment variable (forces colors)
//!
//! # Exit Codes
//!
//! Standard exit codes for automation:
//! - 0: Success
//! - 1: User error (bad input)
//! - 2: Runtime error
//! - 3: Internal error (bug)
//! - 4: Cancelled
//! - 5: Partial success
//! - 10-13: Application-specific (test failure, oracle violation, etc.)

pub mod args;
pub mod atp_command_tree;
pub mod atp_config;
pub mod atp_user_journey;
pub mod atp_workflows;
pub mod completion;
pub mod doctor;
pub mod error;
pub mod exit;
pub mod first_run;
pub mod output;
pub mod progress;
pub mod signal;
pub mod upgrade;

// Re-export commonly used types
pub use args::{
    AtpDoctorArgs, AtpProofArgs, AtpReplayArgs, AtpVerifyArgs, COMMON_ARGS_HELP, CommonArgs,
    parse_color_choice, parse_output_format,
};
pub use atp_command_tree::{
    AtpArchiveAction, AtpArchiveArgs, AtpArchiveCompactArgs, AtpArchiveEntry, AtpArchiveExportArgs,
    AtpArchiveListArgs, AtpArchiveOutput, AtpArchiveRetrieveArgs, AtpArchiveStorageStats,
    AtpArchiveStoreArgs, AtpArchiveSummary, AtpArchiveVerifyArgs, AtpCiAction, AtpCiArgs,
    AtpCiArtifact, AtpCiCacheStats, AtpCiCleanArgs, AtpCiListArgs, AtpCiOutput, AtpCiPullArgs,
    AtpCiPushArgs, AtpCiStatusArgs, AtpCiSummary, AtpCommand, AtpConfig, AtpDatasetAction,
    AtpDatasetArgs, AtpDatasetGetArgs, AtpDatasetInfo, AtpDatasetListArgs, AtpDatasetOutput,
    AtpDatasetPinArgs, AtpDatasetSeedArgs, AtpDatasetStatusArgs, AtpDatasetSummary,
    AtpDatasetUnpinArgs, AtpDownloadRegion, AtpFuzzAction, AtpFuzzArgs, AtpFuzzCorpusStats,
    AtpFuzzCoverage, AtpFuzzMergeArgs, AtpFuzzMinimizeArgs, AtpFuzzOutput, AtpFuzzPullArgs,
    AtpFuzzPushArgs, AtpFuzzStatsArgs, AtpFuzzSummary, AtpFuzzSyncArgs, AtpIntegrityStatus,
    AtpNodeRegion, AtpProfile, AtpReleaseAction, AtpReleaseArgs, AtpReleaseDiffArgs,
    AtpReleaseInfo, AtpReleaseInfoArgs, AtpReleaseInstallArgs, AtpReleaseListArgs,
    AtpReleaseMetrics, AtpReleaseOutput, AtpReleasePublishArgs, AtpReleaseSummary,
    AtpReleaseVerifyArgs, AtpSwarmHealth, AtpTierStats, ConflictStrategy,
};
pub use atp_user_journey::{
    ATP_USER_JOURNEY_CONTRACT_VERSION, ATP_USER_JOURNEY_REQUIRED_LOG_FIELDS,
    AtpUserJourneyContract, AtpUserJourneyScenario, atp_user_journey_contract,
    atp_user_journey_required_log_fields, atp_user_journey_scenarios,
};
pub use atp_workflows::AtpWorkflowCoordinator;
pub use completion::{Completable, CompletionItem, Shell, generate_completions};
pub use doctor::{
    AgentSwarmGitStatus, AgentSwarmProofFrontierItem, AgentSwarmRchStatus,
    AgentSwarmRecommendation, AgentSwarmReservation, AgentSwarmStatusContract,
    AgentSwarmStatusEvent, AgentSwarmStatusSnapshot, CapabilityEdge, ContractCompatibility,
    ContractErrorEnvelope, CoreDiagnosticsCommand, CoreDiagnosticsEvidence, CoreDiagnosticsFinding,
    CoreDiagnosticsFixture, CoreDiagnosticsProvenance, CoreDiagnosticsReport,
    CoreDiagnosticsReportBundle, CoreDiagnosticsReportContract, CoreDiagnosticsSummary,
    CorrelationPrimitiveSpec, DecisionLoop, DecisionStep, EvidenceIngestionReport,
    EvidenceProvenance, EvidenceRecord, ExchangeOutcome, IngestionEvent, InvariantAnalyzerReport,
    InvariantFinding, InvariantRuleTrace, LockContentionAnalyzerReport, LockContentionHotspot,
    LockContentionRuleTrace, LockOrderViolation, LoggingFieldSpec, LoggingFlowSpec,
    MigrationGuidance, OperatorModelContract, OperatorPersona, PayloadField, PayloadSchema,
    RejectedArtifact, RejectedPayloadLog, RemediationConfidenceInput, RemediationConfidenceScore,
    RemediationConfidenceWeight, RemediationPrecondition, RemediationRecipe,
    RemediationRecipeBundle, RemediationRecipeContract, RemediationRecipeFixture,
    RemediationRiskBand, RemediationRollbackPlan, RuntimeArtifact, ScanEvent, ScreenContract,
    ScreenEngineContract, ScreenExchangeEnvelope, ScreenExchangeRequest, StateTransition,
    StructuredLogEvent, StructuredLoggingContract, WorkspaceMember, WorkspaceScanReport,
    agent_swarm_status_contract, analyze_workspace_invariants, analyze_workspace_lock_contention,
    build_agent_swarm_status_snapshot, compute_remediation_confidence_score,
    core_diagnostics_report_bundle, core_diagnostics_report_contract,
    core_diagnostics_report_fixtures, emit_lock_contention_structured_events,
    emit_structured_log_event, execute_screen_exchange, ingest_runtime_artifacts,
    is_screen_contract_version_supported, operator_model_contract, parse_git_short_status,
    parse_remediation_recipe, remediation_recipe_bundle, remediation_recipe_contract,
    remediation_recipe_fixtures, run_agent_swarm_status_smoke, run_core_diagnostics_report_smoke,
    run_remediation_recipe_smoke, run_structured_logging_smoke, scan_workspace,
    screen_engine_contract, structured_logging_contract, validate_agent_swarm_status_contract,
    validate_core_diagnostics_report, validate_core_diagnostics_report_contract,
    validate_evidence_ingestion_report, validate_operator_model_contract,
    validate_remediation_recipe, validate_remediation_recipe_contract,
    validate_screen_engine_contract, validate_structured_log_event,
    validate_structured_logging_contract, validate_structured_logging_event_stream,
};
pub use error::{CliError, errors};
pub use exit::ExitCode;
pub use output::{ColorChoice, Output, OutputFormat, Outputtable};
pub use progress::{ProgressEvent, ProgressKind, ProgressReporter};
pub use signal::{CancellationToken, Signal, SignalHandler};

/// Prelude for convenient imports.
///
/// ```rust,ignore
/// use asupersync::cli::prelude::*;
/// ```
pub mod prelude {
    pub use super::args::{COMMON_ARGS_HELP, CommonArgs};
    pub use super::atp_user_journey::{
        ATP_USER_JOURNEY_CONTRACT_VERSION, ATP_USER_JOURNEY_REQUIRED_LOG_FIELDS,
        AtpUserJourneyContract, AtpUserJourneyScenario, atp_user_journey_contract,
        atp_user_journey_required_log_fields, atp_user_journey_scenarios,
    };
    pub use super::doctor::{
        AgentSwarmGitStatus, AgentSwarmProofFrontierItem, AgentSwarmRchStatus,
        AgentSwarmRecommendation, AgentSwarmReservation, AgentSwarmStatusContract,
        AgentSwarmStatusEvent, AgentSwarmStatusSnapshot, CapabilityEdge, ContractCompatibility,
        ContractErrorEnvelope, CoreDiagnosticsCommand, CoreDiagnosticsEvidence,
        CoreDiagnosticsFinding, CoreDiagnosticsFixture, CoreDiagnosticsProvenance,
        CoreDiagnosticsReport, CoreDiagnosticsReportBundle, CoreDiagnosticsReportContract,
        CoreDiagnosticsSummary, CorrelationPrimitiveSpec, DecisionLoop, DecisionStep,
        EvidenceIngestionReport, EvidenceProvenance, EvidenceRecord, ExchangeOutcome,
        IngestionEvent, InvariantAnalyzerReport, InvariantFinding, InvariantRuleTrace,
        LockContentionAnalyzerReport, LockContentionHotspot, LockContentionRuleTrace,
        LockOrderViolation, LoggingFieldSpec, LoggingFlowSpec, MigrationGuidance,
        OperatorModelContract, OperatorPersona, PayloadField, PayloadSchema, RejectedArtifact,
        RejectedPayloadLog, RemediationConfidenceInput, RemediationConfidenceScore,
        RemediationConfidenceWeight, RemediationPrecondition, RemediationRecipe,
        RemediationRecipeBundle, RemediationRecipeContract, RemediationRecipeFixture,
        RemediationRiskBand, RemediationRollbackPlan, RuntimeArtifact, ScanEvent, ScreenContract,
        ScreenEngineContract, ScreenExchangeEnvelope, ScreenExchangeRequest, StateTransition,
        StructuredLogEvent, StructuredLoggingContract, WorkspaceMember, WorkspaceScanReport,
        agent_swarm_status_contract, analyze_workspace_invariants,
        analyze_workspace_lock_contention, build_agent_swarm_status_snapshot,
        compute_remediation_confidence_score, core_diagnostics_report_bundle,
        core_diagnostics_report_contract, core_diagnostics_report_fixtures,
        emit_lock_contention_structured_events, emit_structured_log_event, execute_screen_exchange,
        ingest_runtime_artifacts, is_screen_contract_version_supported, operator_model_contract,
        parse_git_short_status, parse_remediation_recipe, remediation_recipe_bundle,
        remediation_recipe_contract, remediation_recipe_fixtures, run_agent_swarm_status_smoke,
        run_core_diagnostics_report_smoke, run_remediation_recipe_smoke,
        run_structured_logging_smoke, scan_workspace, screen_engine_contract,
        structured_logging_contract, validate_agent_swarm_status_contract,
        validate_core_diagnostics_report, validate_core_diagnostics_report_contract,
        validate_evidence_ingestion_report, validate_operator_model_contract,
        validate_remediation_recipe, validate_remediation_recipe_contract,
        validate_screen_engine_contract, validate_structured_log_event,
        validate_structured_logging_contract, validate_structured_logging_event_stream,
    };
    pub use super::error::{CliError, errors};
    pub use super::exit::ExitCode;
    pub use super::output::{ColorChoice, Output, OutputFormat, Outputtable};
    pub use super::progress::{ProgressEvent, ProgressReporter};
    pub use super::signal::{CancellationToken, SignalHandler};
}

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
    use serde::Serialize;
    use std::io::Cursor;

    #[derive(Serialize)]
    struct TestData {
        value: i32,
    }

    impl Outputtable for TestData {
        fn human_format(&self) -> String {
            format!("Value: {}", self.value)
        }
    }

    struct TestCmd;

    impl Completable for TestCmd {
        fn command_name(&self) -> &'static str {
            "test"
        }

        fn subcommands(&self) -> Vec<CompletionItem> {
            vec![CompletionItem::new("run")]
        }

        fn global_options(&self) -> Vec<CompletionItem> {
            vec![CompletionItem::new("--help")]
        }

        fn subcommand_options(&self, subcommand: &str) -> Vec<CompletionItem> {
            if subcommand == "run" {
                vec![CompletionItem::new("--dry-run")]
            } else {
                vec![]
            }
        }
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn prelude_exports_work() {
        init_test("prelude_exports_work");
        // Verify prelude exports compile
        let _ = ExitCode::SUCCESS;
        let _ = OutputFormat::Human;
        let _ = ColorChoice::Auto;
        crate::test_complete!("prelude_exports_work");
    }

    #[test]
    fn error_integration() {
        init_test("error_integration");
        // Test that error module integrates with exit codes
        let error = errors::invalid_argument("test", "invalid");
        crate::assert_with_log!(
            error.exit_code == ExitCode::USER_ERROR,
            "exit_code",
            ExitCode::USER_ERROR,
            error.exit_code
        );
        crate::test_complete!("error_integration");
    }

    #[test]
    fn output_integration() {
        init_test("output_integration");

        let cursor = Cursor::new(Vec::new());
        let mut output = Output::with_writer(OutputFormat::Json, cursor);
        let data = TestData { value: 42 };
        output.write(&data).unwrap();
        crate::test_complete!("output_integration");
    }

    #[test]
    fn signal_integration() {
        init_test("signal_integration");
        let handler = SignalHandler::new();
        let token = handler.cancellation_token();

        let cancelled = token.is_cancelled();
        crate::assert_with_log!(!cancelled, "token not cancelled", false, cancelled);
        let _ = handler.record_signal();
        let cancelled = token.is_cancelled();
        crate::assert_with_log!(cancelled, "token cancelled", true, cancelled);
        crate::test_complete!("signal_integration");
    }

    #[test]
    fn completion_integration() {
        init_test("completion_integration");
        let mut buf = Vec::new();
        generate_completions(Shell::Bash, &TestCmd, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let contains = output.contains("test");
        crate::assert_with_log!(contains, "contains test", true, contains);
        let has_subcommand_option = output.contains("--dry-run");
        crate::assert_with_log!(
            has_subcommand_option,
            "contains subcommand option",
            true,
            has_subcommand_option
        );
        crate::test_complete!("completion_integration");
    }
}
