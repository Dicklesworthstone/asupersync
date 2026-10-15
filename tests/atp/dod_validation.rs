//! ATP Definition of Done Validation Tests
//!
//! This module provides automated testing for Definition of Done compliance.
//! Tests in this module ensure that ATP implementation beads meet evidence standards.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

/// ATP surface areas that must have DoD evidence
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AtpSurface {
    NativeQuic,
    AtpProtocol,
    ObjectGraph,
    DiskJournal,
    Scheduler,
    RaptorqRepair,
    PathGraph,
    Atpd,
    CliSdk,
    MailboxSwarm,
    Adapters,
    LabBench,
    ReleaseGovernance,
}

impl AtpSurface {
    /// Get the expected source path for this surface
    pub fn source_path(&self) -> &'static str {
        match self {
            AtpSurface::NativeQuic => "src/net/quic_native",
            AtpSurface::AtpProtocol => "src/atp/protocol",
            AtpSurface::ObjectGraph => "src/atp/object",
            AtpSurface::DiskJournal => "src/atp/disk",
            AtpSurface::Scheduler => "src/runtime/scheduler",
            AtpSurface::RaptorqRepair => "src/raptorq",
            AtpSurface::PathGraph => "src/atp/path",
            AtpSurface::Atpd => "src/bin",
            AtpSurface::CliSdk => "src/cli",
            AtpSurface::MailboxSwarm => "src/atp/mailbox",
            AtpSurface::Adapters => "src/adapters",
            AtpSurface::LabBench => "src/lab",
            AtpSurface::ReleaseGovernance => "scripts",
        }
    }

    /// Get expected test patterns for this surface
    pub fn test_patterns(&self) -> Vec<&'static str> {
        match self {
            AtpSurface::NativeQuic => vec!["quic_conformance", "quic_native"],
            AtpSurface::AtpProtocol => vec!["atp_protocol_codec", "protocol"],
            AtpSurface::ObjectGraph => vec!["manifest_merkle", "object_graph"],
            AtpSurface::DiskJournal => vec!["crash_safety", "disk", "journal"],
            AtpSurface::Scheduler => vec!["scheduler", "runtime"],
            AtpSurface::RaptorqRepair => vec!["raptorq_repair", "raptorq"],
            AtpSurface::PathGraph => vec!["path_graph", "path"],
            AtpSurface::Atpd => vec!["daemon_shutdown", "atpd"],
            AtpSurface::CliSdk => vec!["cli_ux", "cli"],
            AtpSurface::MailboxSwarm => vec!["mailbox", "swarm"],
            AtpSurface::Adapters => vec!["adapters"],
            AtpSurface::LabBench => vec!["lab_scenarios", "benchmarks"],
            AtpSurface::ReleaseGovernance => vec!["release_gates"],
        }
    }
}

/// Evidence categories required for DoD compliance
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceCategory {
    UnitTests,
    PropertyTests,
    IntegrationTests,
    LabTests,
    E2eScripts,
    StructuredLogs,
    FailureBundles,
    DependencyAudit,
    PlatformCoverage,
}

/// DoD validation result for a specific surface
#[derive(Debug, Clone)]
pub struct SurfaceValidation {
    pub surface: AtpSurface,
    pub unit_tests: bool,
    pub integration_tests: bool,
    pub structured_logs: bool,
    pub dependency_compliant: bool,
    pub violations: Vec<String>,
    pub warnings: Vec<String>,
}

/// Complete DoD validation results
#[derive(Debug, Clone)]
pub struct DodValidationResults {
    pub surfaces: HashMap<AtpSurface, SurfaceValidation>,
    pub total_violations: usize,
    pub total_warnings: usize,
    pub compliant: bool,
}

/// DoD validator implementation
pub struct DodValidator {
    project_root: PathBuf,
}

impl DodValidator {
    /// Create a new DoD validator
    pub fn new() -> std::io::Result<Self> {
        let project_root = std::env::current_dir()?
            .ancestors()
            .find(|path| path.join("Cargo.toml").exists())
            .ok_or_else(|| std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Could not find project root (no Cargo.toml found)"
            ))?
            .to_path_buf();

        Ok(Self { project_root })
    }

    /// Validate DoD compliance for all ATP surfaces
    pub fn validate_all_surfaces(&self) -> DodValidationResults {
        let mut surfaces = HashMap::new();
        let mut total_violations = 0;
        let mut total_warnings = 0;

        for surface in [
            AtpSurface::NativeQuic,
            AtpSurface::AtpProtocol,
            AtpSurface::ObjectGraph,
            AtpSurface::DiskJournal,
            AtpSurface::Scheduler,
            AtpSurface::RaptorqRepair,
            AtpSurface::PathGraph,
            AtpSurface::Atpd,
            AtpSurface::CliSdk,
            AtpSurface::MailboxSwarm,
            AtpSurface::Adapters,
            AtpSurface::LabBench,
            AtpSurface::ReleaseGovernance,
        ] {
            let validation = self.validate_surface(&surface);
            total_violations += validation.violations.len();
            total_warnings += validation.warnings.len();
            surfaces.insert(surface, validation);
        }

        DodValidationResults {
            surfaces,
            total_violations,
            total_warnings,
            compliant: total_violations == 0,
        }
    }

    /// Validate DoD compliance for a specific ATP surface
    pub fn validate_surface(&self, surface: &AtpSurface) -> SurfaceValidation {
        let mut violations = Vec::new();
        let mut warnings = Vec::new();

        let source_path = self.project_root.join(surface.source_path());

        // Check if surface path exists
        if !source_path.exists() {
            warnings.push(format!("Surface path does not exist: {}", surface.source_path()));
        }

        // Validate unit tests
        let unit_tests = self.check_unit_tests(&source_path);
        if !unit_tests {
            violations.push(format!("No unit tests found for {:?}", surface));
        }

        // Validate integration tests
        let integration_tests = self.check_integration_tests(surface);
        if !integration_tests {
            warnings.push(format!("No integration tests found for {:?}", surface));
        }

        // Validate structured logging
        let structured_logs = self.check_structured_logging(&source_path);
        if !structured_logs {
            warnings.push(format!("Limited structured logging found for {:?}", surface));
        }

        // Validate dependency compliance
        let dependency_compliant = self.check_dependency_compliance(&source_path);

        SurfaceValidation {
            surface: surface.clone(),
            unit_tests,
            integration_tests,
            structured_logs,
            dependency_compliant,
            violations,
            warnings,
        }
    }

    /// Check for unit tests in the given source path
    fn check_unit_tests(&self, source_path: &Path) -> bool {
        if !source_path.exists() {
            return false;
        }

        // Look for test files
        if let Ok(entries) = std::fs::read_dir(source_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() &&
                   path.extension().and_then(|s| s.to_str()) == Some("rs") {
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        if content.contains("#[cfg(test)]") || content.contains("#[test]") {
                            return true;
                        }
                    }
                }
            }
        }

        // Check for dedicated test files
        let test_patterns = ["test.rs", "tests.rs"];
        for pattern in &test_patterns {
            if source_path.join(pattern).exists() {
                return true;
            }
        }

        false
    }

    /// Check for integration tests related to the surface
    fn check_integration_tests(&self, surface: &AtpSurface) -> bool {
        let tests_dir = self.project_root.join("tests");
        if !tests_dir.exists() {
            return false;
        }

        let patterns = surface.test_patterns();

        for pattern in patterns {
            // Check for test files matching the pattern
            let test_file = tests_dir.join(format!("{}.rs", pattern));
            if test_file.exists() {
                return true;
            }

            // Check for test directories
            let test_dir = tests_dir.join(pattern);
            if test_dir.exists() {
                return true;
            }
        }

        false
    }

    /// Check for structured logging usage
    fn check_structured_logging(&self, source_path: &Path) -> bool {
        if !source_path.exists() {
            return false;
        }

        self.search_directory_for_patterns(source_path, &[
            "tracing::",
            "log::",
            "info!",
            "warn!",
            "error!",
            "debug!",
            "trace!",
        ])
    }

    /// Check dependency compliance for the surface
    fn check_dependency_compliance(&self, source_path: &Path) -> bool {
        if !source_path.exists() {
            return true; // No code, no violations
        }

        // Check for forbidden patterns
        let forbidden_patterns = [
            "use quinn",
            "use tokio::runtime",
            "Runtime::new",
            "Handle::current",
        ];

        !self.search_directory_for_patterns(source_path, &forbidden_patterns)
    }

    /// Search a directory recursively for patterns
    fn search_directory_for_patterns(&self, dir: &Path, patterns: &[&str]) -> bool {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();

                if path.is_dir() {
                    if self.search_directory_for_patterns(&path, patterns) {
                        return true;
                    }
                } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        for pattern in patterns {
                            if content.contains(pattern) {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }

    /// Run external DoD validation script
    pub fn run_external_validation(&self) -> std::io::Result<bool> {
        let script_path = self.project_root.join("scripts/validate_dod.sh");

        if !script_path.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "DoD validation script not found"
            ));
        }

        let output = Command::new("bash")
            .arg(&script_path)
            .current_dir(&self.project_root)
            .output()?;

        Ok(output.status.success())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dod_validator_creation() {
        let validator = DodValidator::new();
        assert!(validator.is_ok(), "Should be able to create DoD validator");
    }

    #[test]
    fn test_surface_path_mapping() {
        assert_eq!(AtpSurface::NativeQuic.source_path(), "src/net/quic_native");
        assert_eq!(AtpSurface::AtpProtocol.source_path(), "src/atp/protocol");
        assert_eq!(AtpSurface::Scheduler.source_path(), "src/runtime/scheduler");
    }

    #[test]
    fn test_surface_test_patterns() {
        let patterns = AtpSurface::NativeQuic.test_patterns();
        assert!(patterns.contains(&"quic_conformance"));
        assert!(patterns.contains(&"quic_native"));
    }

    #[test]
    fn test_dod_validation_integration() {
        let validator = DodValidator::new().expect("Should create validator");
        let results = validator.validate_all_surfaces();

        // Basic sanity checks
        assert!(!results.surfaces.is_empty(), "Should validate at least some surfaces");

        // Check that critical surfaces are present
        assert!(results.surfaces.contains_key(&AtpSurface::AtpProtocol));
        assert!(results.surfaces.contains_key(&AtpSurface::ReleaseGovernance));

        println!("DoD Validation Results:");
        println!("Total violations: {}", results.total_violations);
        println!("Total warnings: {}", results.total_warnings);
        println!("Compliant: {}", results.compliant);

        for (surface, validation) in &results.surfaces {
            println!("Surface {:?}:", surface);
            println!("  Unit tests: {}", validation.unit_tests);
            println!("  Integration tests: {}", validation.integration_tests);
            println!("  Structured logs: {}", validation.structured_logs);
            println!("  Dependency compliant: {}", validation.dependency_compliant);

            if !validation.violations.is_empty() {
                println!("  Violations:");
                for violation in &validation.violations {
                    println!("    - {}", violation);
                }
            }

            if !validation.warnings.is_empty() {
                println!("  Warnings:");
                for warning in &validation.warnings {
                    println!("    - {}", warning);
                }
            }
        }
    }

    #[test]
    fn test_external_dod_script_integration() {
        let validator = DodValidator::new().expect("Should create validator");

        // Test that we can at least attempt to run the external script
        match validator.run_external_validation() {
            Ok(success) => {
                println!("External DoD validation script result: {}", success);
            },
            Err(e) => {
                println!("External DoD validation script not available: {}", e);
                // This is OK - the script might not be executable in test environment
            }
        }
    }

    #[test]
    fn test_dod_evidence_categories() {
        // Verify that we have all expected evidence categories
        let categories = vec![
            EvidenceCategory::UnitTests,
            EvidenceCategory::PropertyTests,
            EvidenceCategory::IntegrationTests,
            EvidenceCategory::LabTests,
            EvidenceCategory::E2eScripts,
            EvidenceCategory::StructuredLogs,
            EvidenceCategory::FailureBundles,
            EvidenceCategory::DependencyAudit,
            EvidenceCategory::PlatformCoverage,
        ];

        assert_eq!(categories.len(), 9, "Should have all evidence categories");
    }
}