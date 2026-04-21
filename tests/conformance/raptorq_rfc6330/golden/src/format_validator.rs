#![allow(clippy::all)]
//! Golden file format validation for RaptorQ conformance testing.
//!
//! This module validates the structure and content of golden files to ensure
//! they meet expected format requirements and can be safely used for regression
//! testing. It performs schema validation, data integrity checks, and format
//! compliance verification.

use crate::golden_file_manager::{GoldenFileEntry, GoldenMetadata};
use crate::round_trip_harness::RoundTripOutput;
use serde_json::Value;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Format validation configuration
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ValidationConfig {
    /// Require specific metadata fields
    pub required_metadata_fields: HashSet<String>,
    /// Maximum allowed golden file size in bytes
    pub max_file_size: u64,
    /// Whether to validate checksums
    pub validate_checksums: bool,
    /// Whether to validate RFC 6330 compliance
    pub validate_rfc_compliance: bool,
    /// Allowed symbol size values
    pub allowed_symbol_sizes: HashSet<usize>,
    /// Maximum number of source symbols
    pub max_source_symbols: usize,
    /// Maximum number of repair symbols
    pub max_repair_symbols: usize,
}

impl Default for ValidationConfig {
    #[allow(dead_code)]
    fn default() -> Self {
        let mut required_fields = HashSet::new();
        required_fields.insert("test_name".to_string());
        required_fields.insert("rfc_section".to_string());
        required_fields.insert("description".to_string());
        required_fields.insert("last_updated".to_string());
        required_fields.insert("checksum".to_string());

        let mut allowed_sizes = HashSet::new();
        // Common symbol sizes from RFC 6330
        for size in [64, 128, 256, 512, 1024, 2048, 4096, 8192] {
            allowed_sizes.insert(size);
        }

        Self {
            required_metadata_fields: required_fields,
            max_file_size: 100 * 1024 * 1024, // 100MB
            validate_checksums: true,
            validate_rfc_compliance: true,
            allowed_symbol_sizes: allowed_sizes,
            max_source_symbols: 8192, // RFC 6330 limit
            max_repair_symbols: 16384,
        }
    }
}

/// Result of golden file format validation
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ValidationResult {
    /// Whether validation passed
    pub is_valid: bool,
    /// Detected issues and warnings
    pub issues: Vec<ValidationIssue>,
    /// File metadata summary
    pub metadata_summary: MetadataSummary,
    /// Data integrity status
    pub data_integrity: DataIntegrityStatus,
    /// RFC 6330 compliance status
    pub rfc_compliance: RfcComplianceStatus,
}

#[allow(dead_code)]

impl ValidationResult {
    /// Returns true if there are no critical issues
    #[allow(dead_code)]
    pub fn has_critical_issues(&self) -> bool {
        self.issues
            .iter()
            .any(|issue| issue.severity == IssueSeverity::Critical)
    }

    /// Returns the number of issues at each severity level
    #[allow(dead_code)]
    pub fn issue_counts(&self) -> (usize, usize, usize) {
        let mut critical = 0;
        let mut warning = 0;
        let mut info = 0;

        for issue in &self.issues {
            match issue.severity {
                IssueSeverity::Critical => critical += 1,
                IssueSeverity::Warning => warning += 1,
                IssueSeverity::Info => info += 1,
            }
        }

        (critical, warning, info)
    }
}

/// Individual validation issue
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ValidationIssue {
    /// Issue severity level
    pub severity: IssueSeverity,
    /// Issue category
    pub category: IssueCategory,
    /// Human-readable description
    pub description: String,
    /// Suggested fix or remediation
    pub suggested_fix: Option<String>,
    /// Location within the file (if applicable)
    pub location: Option<String>,
}

/// Severity level of validation issues
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum IssueSeverity {
    /// Critical issues that prevent using the golden file
    Critical,
    /// Warnings that should be addressed but don't prevent usage
    Warning,
    /// Informational notices
    Info,
}

/// Categories of validation issues
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum IssueCategory {
    /// JSON structure or schema issues
    Schema,
    /// Missing or invalid metadata
    Metadata,
    /// Data integrity problems
    DataIntegrity,
    /// RFC 6330 compliance issues
    RfcCompliance,
    /// Performance or size concerns
    Performance,
    /// Format version compatibility
    Compatibility,
}

/// Summary of file metadata
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct MetadataSummary {
    /// File size in bytes
    pub file_size: u64,
    /// Test case name
    pub test_name: String,
    /// RFC section references
    pub rfc_sections: Vec<String>,
    /// Last update timestamp
    pub last_updated: Option<chrono::DateTime<chrono::Utc>>,
    /// Git commit hash (if available)
    pub git_commit: Option<String>,
    /// Number of input parameters
    pub input_param_count: usize,
}

/// Data integrity validation status
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DataIntegrityStatus {
    /// Checksum validation passed
    pub checksum_valid: bool,
    /// JSON structure is well-formed
    pub json_valid: bool,
    /// Required fields are present
    pub required_fields_present: bool,
    /// Data types match expected schema
    pub types_valid: bool,
    /// Data sizes are reasonable
    pub sizes_reasonable: bool,
}

/// RFC 6330 compliance validation status
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct RfcComplianceStatus {
    /// Symbol sizes are valid per RFC 6330
    pub symbol_sizes_valid: bool,
    /// Source symbol count is within limits
    pub source_symbols_valid: bool,
    /// Repair symbol count is reasonable
    pub repair_symbols_valid: bool,
    /// Encoding parameters are valid
    pub parameters_valid: bool,
    /// Test configuration follows RFC guidelines
    pub config_compliant: bool,
}

/// Golden file format validator
#[allow(dead_code)]
pub struct FormatValidator {
    config: ValidationConfig,
}

#[allow(dead_code)]

impl FormatValidator {
    /// Creates a new format validator with default configuration
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self {
            config: ValidationConfig::default(),
        }
    }

    /// Creates a validator with custom configuration
    #[allow(dead_code)]
    pub fn with_config(config: ValidationConfig) -> Self {
        Self { config }
    }

    /// Validates a single golden file
    #[allow(dead_code)]
    pub fn validate_file<P: AsRef<Path>>(
        &self,
        file_path: P,
    ) -> Result<ValidationResult, ValidationError> {
        let path = file_path.as_ref();
        let file_size = fs::metadata(path)?.len();

        // Check file size limit
        if file_size > self.config.max_file_size {
            return Ok(ValidationResult {
                is_valid: false,
                issues: vec![ValidationIssue {
                    severity: IssueSeverity::Critical,
                    category: IssueCategory::Performance,
                    description: format!(
                        "File size {} bytes exceeds limit of {} bytes",
                        file_size, self.config.max_file_size
                    ),
                    suggested_fix: Some("Reduce test data size or increase size limit".to_string()),
                    location: None,
                }],
                metadata_summary: MetadataSummary {
                    file_size,
                    test_name: "unknown".to_string(),
                    rfc_sections: vec![],
                    last_updated: None,
                    git_commit: None,
                    input_param_count: 0,
                },
                data_integrity: DataIntegrityStatus {
                    checksum_valid: false,
                    json_valid: false,
                    required_fields_present: false,
                    types_valid: false,
                    sizes_reasonable: false,
                },
                rfc_compliance: RfcComplianceStatus {
                    symbol_sizes_valid: false,
                    source_symbols_valid: false,
                    repair_symbols_valid: false,
                    parameters_valid: false,
                    config_compliant: false,
                },
            });
        }

        // Read and parse file
        let content = fs::read_to_string(path)?;
        let json_value: Value = serde_json::from_str(&content)
            .map_err(|e| ValidationError::JsonParseError(e.to_string()))?;

        // Attempt to deserialize as golden file entry
        let golden_entry: GoldenFileEntry<RoundTripOutput> =
            serde_json::from_value(json_value.clone())
                .map_err(|e| ValidationError::StructureError(e.to_string()))?;

        // Perform comprehensive validation
        self.validate_golden_entry(&golden_entry, file_size, path)
    }

    /// Validates all golden files in a directory
    #[allow(dead_code)]
    pub fn validate_directory<P: AsRef<Path>>(
        &self,
        dir_path: P,
    ) -> Result<DirectoryValidationResult, ValidationError> {
        let mut results = Vec::new();
        let mut total_files = 0;
        let mut valid_files = 0;

        for entry in fs::read_dir(dir_path)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some("golden") {
                total_files += 1;

                match self.validate_file(&path) {
                    Ok(result) => {
                        if result.is_valid && !result.has_critical_issues() {
                            valid_files += 1;
                        }
                        results.push((path, Ok(result)));
                    }
                    Err(e) => {
                        results.push((path, Err(e)));
                    }
                }
            }
        }

        Ok(DirectoryValidationResult {
            total_files,
            valid_files,
            results,
        })
    }

    /// Validates a parsed golden file entry
    #[allow(dead_code)]
    fn validate_golden_entry(
        &self,
        entry: &GoldenFileEntry<RoundTripOutput>,
        file_size: u64,
        _file_path: &Path,
    ) -> Result<ValidationResult, ValidationError> {
        let mut issues = Vec::new();

        // Validate metadata
        let metadata_issues = self.validate_metadata(&entry.metadata);
        issues.extend(metadata_issues);

        // Validate data structure
        let data_issues = self.validate_round_trip_data(&entry.data);
        issues.extend(data_issues);

        // Validate RFC 6330 compliance if enabled
        let rfc_issues = if self.config.validate_rfc_compliance {
            self.validate_rfc_compliance(&entry.metadata, &entry.data)
        } else {
            Vec::new()
        };
        issues.extend(rfc_issues);

        // Build status summaries
        let metadata_summary = self.build_metadata_summary(&entry.metadata, file_size);
        let data_integrity = self.assess_data_integrity(entry, &issues);
        let rfc_compliance = self.assess_rfc_compliance(&entry.metadata, &entry.data, &issues);

        let is_valid = issues
            .iter()
            .all(|issue| issue.severity != IssueSeverity::Critical);

        Ok(ValidationResult {
            is_valid,
            issues,
            metadata_summary,
            data_integrity,
            rfc_compliance,
        })
    }

    /// Validates metadata fields and content
    #[allow(dead_code)]
    fn validate_metadata(&self, metadata: &GoldenMetadata) -> Vec<ValidationIssue> {
        let mut issues = Vec::new();

        // Check required fields
        for required_field in &self.config.required_metadata_fields {
            match required_field.as_str() {
                "test_name" if metadata.test_name.is_empty() => {
                    issues.push(ValidationIssue {
                        severity: IssueSeverity::Critical,
                        category: IssueCategory::Metadata,
                        description: "test_name is empty".to_string(),
                        suggested_fix: Some("Provide a descriptive test name".to_string()),
                        location: Some("metadata.test_name".to_string()),
                    });
                }
                "rfc_section" => {
                    if metadata.rfc_section.is_empty() {
                        issues.push(ValidationIssue {
                            severity: IssueSeverity::Warning,
                            category: IssueCategory::Metadata,
                            description: "rfc_section is empty".to_string(),
                            suggested_fix: Some("Specify relevant RFC 6330 section".to_string()),
                            location: Some("metadata.rfc_section".to_string()),
                        });
                    } else if !metadata.rfc_section.starts_with("5.")
                        && !metadata.rfc_section.starts_with("4.")
                    {
                        issues.push(ValidationIssue {
                            severity: IssueSeverity::Info,
                            category: IssueCategory::RfcCompliance,
                            description: "RFC section should typically reference sections 4 or 5"
                                .to_string(),
                            suggested_fix: None,
                            location: Some("metadata.rfc_section".to_string()),
                        });
                    }
                }
                "description" if metadata.description.is_empty() => {
                    issues.push(ValidationIssue {
                        severity: IssueSeverity::Warning,
                        category: IssueCategory::Metadata,
                        description: "description is empty".to_string(),
                        suggested_fix: Some("Provide test description".to_string()),
                        location: Some("metadata.description".to_string()),
                    });
                }
                "checksum" if self.config.validate_checksums && metadata.checksum.is_empty() => {
                    issues.push(ValidationIssue {
                        severity: IssueSeverity::Critical,
                        category: IssueCategory::DataIntegrity,
                        description: "checksum is missing".to_string(),
                        suggested_fix: Some(
                            "Regenerate golden file with valid checksum".to_string(),
                        ),
                        location: Some("metadata.checksum".to_string()),
                    });
                }
                _ => {}
            }
        }

        // Validate checksum format
        if !metadata.checksum.is_empty() && metadata.checksum.len() != 32 {
            issues.push(ValidationIssue {
                severity: IssueSeverity::Warning,
                category: IssueCategory::DataIntegrity,
                description: "checksum has unexpected length (expected 32 hex chars)".to_string(),
                suggested_fix: Some("Ensure MD5 checksum is properly formatted".to_string()),
                location: Some("metadata.checksum".to_string()),
            });
        }

        issues
    }

    /// Validates round-trip data structure and content
    #[allow(dead_code)]
    fn validate_round_trip_data(&self, data: &RoundTripOutput) -> Vec<ValidationIssue> {
        let mut issues = Vec::new();

        // Check for empty symbol data
        if data.encoded_symbols.is_empty() {
            issues.push(ValidationIssue {
                severity: IssueSeverity::Critical,
                category: IssueCategory::DataIntegrity,
                description: "encoded_symbols is empty".to_string(),
                suggested_fix: Some("Ensure test produces encoded symbols".to_string()),
                location: Some("data.encoded_symbols".to_string()),
            });
        }

        // Check symbol index consistency
        if data.encoded_symbols.len() != data.symbol_indices.len() {
            issues.push(ValidationIssue {
                severity: IssueSeverity::Critical,
                category: IssueCategory::DataIntegrity,
                description: "encoded_symbols and symbol_indices have different lengths"
                    .to_string(),
                suggested_fix: Some("Ensure one index per symbol".to_string()),
                location: Some("data".to_string()),
            });
        }

        // Check for duplicate indices
        let unique_indices: HashSet<_> = data.symbol_indices.iter().collect();
        if unique_indices.len() != data.symbol_indices.len() {
            issues.push(ValidationIssue {
                severity: IssueSeverity::Warning,
                category: IssueCategory::DataIntegrity,
                description: "duplicate symbol indices detected".to_string(),
                suggested_fix: Some("Ensure symbol indices are unique".to_string()),
                location: Some("data.symbol_indices".to_string()),
            });
        }

        // Check timing values
        if data.encode_time_us == 0 && data.decode_time_us == 0 {
            issues.push(ValidationIssue {
                severity: IssueSeverity::Info,
                category: IssueCategory::Performance,
                description: "timing measurements are zero".to_string(),
                suggested_fix: Some("Ensure timing is properly measured".to_string()),
                location: Some("data timing".to_string()),
            });
        }

        // Validate metrics
        if !data.validation_metrics.data_integrity && data.success {
            issues.push(ValidationIssue {
                severity: IssueSeverity::Critical,
                category: IssueCategory::DataIntegrity,
                description: "success=true but data_integrity=false".to_string(),
                suggested_fix: Some("Fix data integrity validation".to_string()),
                location: Some("data.validation_metrics".to_string()),
            });
        }

        issues
    }

    /// Validates RFC 6330 compliance
    #[allow(dead_code)]
    fn validate_rfc_compliance(
        &self,
        metadata: &GoldenMetadata,
        _data: &RoundTripOutput,
    ) -> Vec<ValidationIssue> {
        let mut issues = Vec::new();

        // Extract parameters from metadata
        if let (Some(source_symbols_str), Some(symbol_size_str)) = (
            metadata.input_params.get("source_symbols"),
            metadata.input_params.get("symbol_size"),
        ) {
            if let (Ok(source_symbols), Ok(symbol_size)) = (
                source_symbols_str.parse::<usize>(),
                symbol_size_str.parse::<usize>(),
            ) {
                // Check symbol count limits
                if source_symbols > self.config.max_source_symbols {
                    issues.push(ValidationIssue {
                        severity: IssueSeverity::Critical,
                        category: IssueCategory::RfcCompliance,
                        description: format!(
                            "source_symbols {} exceeds RFC 6330 limit of {}",
                            source_symbols, self.config.max_source_symbols
                        ),
                        suggested_fix: Some("Reduce source symbol count".to_string()),
                        location: Some("metadata.input_params.source_symbols".to_string()),
                    });
                }

                // Check symbol size validity
                if !self.config.allowed_symbol_sizes.contains(&symbol_size) {
                    issues.push(ValidationIssue {
                        severity: IssueSeverity::Warning,
                        category: IssueCategory::RfcCompliance,
                        description: format!(
                            "symbol_size {} is not a standard RFC 6330 value",
                            symbol_size
                        ),
                        suggested_fix: Some(
                            "Use standard symbol sizes (64, 128, 256, 512, 1024, etc.)".to_string(),
                        ),
                        location: Some("metadata.input_params.symbol_size".to_string()),
                    });
                }

                // Check repair symbol count
                if let Some(repair_symbols_str) = metadata.input_params.get("repair_symbols") {
                    if let Ok(repair_symbols) = repair_symbols_str.parse::<usize>() {
                        if repair_symbols > self.config.max_repair_symbols {
                            issues.push(ValidationIssue {
                                severity: IssueSeverity::Warning,
                                category: IssueCategory::RfcCompliance,
                                description: format!(
                                    "repair_symbols {} is very large",
                                    repair_symbols
                                ),
                                suggested_fix: Some(
                                    "Consider reducing repair symbol count".to_string(),
                                ),
                                location: Some("metadata.input_params.repair_symbols".to_string()),
                            });
                        }
                    }
                }
            }
        }

        issues
    }

    /// Builds metadata summary
    #[allow(dead_code)]
    fn build_metadata_summary(&self, metadata: &GoldenMetadata, file_size: u64) -> MetadataSummary {
        let last_updated = chrono::DateTime::from_timestamp(
            metadata
                .last_updated
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64,
            0,
        );

        MetadataSummary {
            file_size,
            test_name: metadata.test_name.clone(),
            rfc_sections: vec![metadata.rfc_section.clone()],
            last_updated,
            git_commit: metadata.git_commit.clone(),
            input_param_count: metadata.input_params.len(),
        }
    }

    /// Assesses data integrity status
    #[allow(dead_code)]
    fn assess_data_integrity(
        &self,
        entry: &GoldenFileEntry<RoundTripOutput>,
        issues: &[ValidationIssue],
    ) -> DataIntegrityStatus {
        let has_integrity_issues = issues
            .iter()
            .any(|issue| issue.category == IssueCategory::DataIntegrity);

        DataIntegrityStatus {
            checksum_valid: !entry.metadata.checksum.is_empty()
                && !issues
                    .iter()
                    .any(|i| i.location == Some("metadata.checksum".to_string())),
            json_valid: true, // If we got here, JSON parsing succeeded
            required_fields_present: !issues.iter().any(|i| {
                i.category == IssueCategory::Metadata && i.severity == IssueSeverity::Critical
            }),
            types_valid: !has_integrity_issues,
            sizes_reasonable: !issues.iter().any(|i| {
                i.category == IssueCategory::Performance && i.severity == IssueSeverity::Critical
            }),
        }
    }

    /// Assesses RFC compliance status
    #[allow(dead_code)]
    fn assess_rfc_compliance(
        &self,
        _metadata: &GoldenMetadata,
        _data: &RoundTripOutput,
        issues: &[ValidationIssue],
    ) -> RfcComplianceStatus {
        let has_rfc_issues = issues
            .iter()
            .any(|issue| issue.category == IssueCategory::RfcCompliance);

        RfcComplianceStatus {
            symbol_sizes_valid: !has_rfc_issues,
            source_symbols_valid: !has_rfc_issues,
            repair_symbols_valid: !has_rfc_issues,
            parameters_valid: !has_rfc_issues,
            config_compliant: !has_rfc_issues,
        }
    }
}

impl Default for FormatValidator {
    #[allow(dead_code)]
    fn default() -> Self {
        Self::new()
    }
}

/// Result of validating an entire directory
#[derive(Debug)]
#[allow(dead_code)]
pub struct DirectoryValidationResult {
    pub total_files: usize,
    pub valid_files: usize,
    pub results: Vec<(PathBuf, Result<ValidationResult, ValidationError>)>,
}

#[allow(dead_code)]

impl DirectoryValidationResult {
    #[allow(dead_code)]
    pub fn success_rate(&self) -> f64 {
        if self.total_files == 0 {
            1.0
        } else {
            self.valid_files as f64 / self.total_files as f64
        }
    }
}

/// Errors that can occur during validation
#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
pub enum ValidationError {
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("JSON parse error: {0}")]
    JsonParseError(String),

    #[error("Structure error: {0}")]
    StructureError(String),

    #[error("Validation configuration error: {0}")]
    ConfigError(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::golden_file_manager::create_metadata;
    use crate::round_trip_harness::{RoundTripOutput, ValidationMetrics};
    use std::collections::HashMap;

    #[allow(dead_code)]

    fn create_test_golden_file() -> GoldenFileEntry<RoundTripOutput> {
        let metadata = create_metadata("test_case", "5.3.1", "Test golden file", HashMap::new());

        let output = RoundTripOutput {
            encoded_symbols: vec![vec![1, 2, 3], vec![4, 5, 6]],
            symbol_indices: vec![0, 1],
            decoded_data: vec![1, 2, 3, 4, 5, 6],
            success: true,
            error_message: None,
            encode_time_us: 1000,
            decode_time_us: 500,
            validation_metrics: ValidationMetrics {
                data_integrity: true,
                symbol_count_valid: true,
                parameters_preserved: true,
                repair_symbols_valid: true,
                erasure_recovery_valid: None,
            },
        };

        GoldenFileEntry {
            metadata,
            data: output,
        }
    }

    #[test]
    #[allow(dead_code)]
    fn test_validation_config_default() {
        let config = ValidationConfig::default();
        assert!(config.required_metadata_fields.contains("test_name"));
        assert!(config.allowed_symbol_sizes.contains(&1024));
        assert_eq!(config.max_source_symbols, 8192);
    }

    #[test]
    #[allow(dead_code)]
    fn test_format_validator_creation() {
        let validator = FormatValidator::new();
        assert!(validator.config.validate_checksums);
        assert!(validator.config.validate_rfc_compliance);
    }

    #[test]
    #[allow(dead_code)]
    fn test_validate_golden_entry_success() {
        let validator = FormatValidator::new();
        let entry = create_test_golden_file();

        let result = validator
            .validate_golden_entry(&entry, 1024, Path::new("test.golden"))
            .unwrap();

        // Should have some issues but be generally valid
        assert!(result.data_integrity.json_valid);
        assert!(result.data_integrity.types_valid);
    }

    #[test]
    #[allow(dead_code)]
    fn test_validation_issue_severity() {
        let issue = ValidationIssue {
            severity: IssueSeverity::Critical,
            category: IssueCategory::DataIntegrity,
            description: "test issue".to_string(),
            suggested_fix: None,
            location: None,
        };

        assert_eq!(issue.severity, IssueSeverity::Critical);
    }

    #[test]
    #[allow(dead_code)]
    fn test_directory_validation_result() {
        let result = DirectoryValidationResult {
            total_files: 10,
            valid_files: 8,
            results: vec![],
        };

        assert_eq!(result.success_rate(), 0.8);
    }
}
