//! Golden File Management for RaptorQ RFC 6330 Conformance Testing
//!
//! Implements Pattern 2 (Golden File Testing) with UPDATE_GOLDENS workflow
//! for complex RaptorQ outputs that are correct once verified, then frozen
//! as regression tests.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Environment variable to enable golden file updates
pub const UPDATE_GOLDENS_ENV: &str = "UPDATE_GOLDENS";

/// Golden file metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct GoldenMetadata {
    /// Test case name
    pub test_name: String,
    /// RFC 6330 section reference
    pub rfc_section: String,
    /// Description of what this golden file contains
    pub description: String,
    /// When this golden file was last updated
    pub last_updated: SystemTime,
    /// Git commit hash when golden was created
    pub git_commit: Option<String>,
    /// Input parameters that generated this output
    pub input_params: HashMap<String, String>,
    /// Checksum for integrity verification
    pub checksum: String,
}

/// Golden file entry combining metadata and data
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct GoldenFileEntry<T> {
    /// Metadata about this golden file
    pub metadata: GoldenMetadata,
    /// The actual golden data
    pub data: T,
}

/// Manager for golden file operations
#[derive(Debug)]
#[allow(dead_code)]
pub struct GoldenFileManager {
    base_path: PathBuf,
    update_mode: bool,
}

#[allow(dead_code)]

impl GoldenFileManager {
    /// Creates a new golden file manager
    #[allow(dead_code)]
    pub fn new<P: AsRef<Path>>(base_path: P) -> Self {
        let update_mode = std::env::var(UPDATE_GOLDENS_ENV).is_ok();
        Self {
            base_path: base_path.as_ref().to_path_buf(),
            update_mode,
        }
    }

    /// Creates a new golden file manager with explicit update mode
    #[allow(dead_code)]
    pub fn with_update_mode<P: AsRef<Path>>(base_path: P, update_mode: bool) -> Self {
        Self {
            base_path: base_path.as_ref().to_path_buf(),
            update_mode,
        }
    }

    /// Saves or validates a golden file entry
    #[allow(dead_code)]
    pub fn assert_golden<T>(
        &self,
        filename: &str,
        data: &T,
        metadata: GoldenMetadata,
    ) -> Result<(), GoldenError>
    where
        T: Serialize + for<'de> Deserialize<'de> + PartialEq + std::fmt::Debug,
    {
        let file_path = self.base_path.join(filename);

        if self.update_mode {
            self.save_golden(&file_path, data, metadata)
        } else {
            self.validate_golden(&file_path, data)
        }
    }

    /// Saves a golden file (update mode)
    #[allow(dead_code)]
    fn save_golden<T>(
        &self,
        path: &Path,
        data: &T,
        metadata: GoldenMetadata,
    ) -> Result<(), GoldenError>
    where
        T: Serialize,
    {
        // Ensure directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| GoldenError::IoError {
                path: parent.to_path_buf(),
                error: e,
            })?;
        }

        let entry = GoldenFileEntry { metadata, data };

        let json = serde_json::to_string_pretty(&entry).map_err(GoldenError::SerializationError)?;
        fs::write(path, json).map_err(|e| GoldenError::IoError {
            path: path.to_path_buf(),
            error: e,
        })?;

        eprintln!("✅ Updated golden file: {}", path.display());
        Ok(())
    }

    /// Validates against existing golden file
    #[allow(dead_code)]
    fn validate_golden<T>(&self, path: &Path, data: &T) -> Result<(), GoldenError>
    where
        T: for<'de> Deserialize<'de> + PartialEq + std::fmt::Debug,
    {
        if !path.exists() {
            return Err(GoldenError::MissingGoldenFile {
                path: path.to_path_buf(),
                hint: format!("Run with {}=1 to create golden files", UPDATE_GOLDENS_ENV),
            });
        }

        let contents = fs::read_to_string(path).map_err(|e| GoldenError::IoError {
            path: path.to_path_buf(),
            error: e,
        })?;

        let entry: GoldenFileEntry<T> =
            serde_json::from_str(&contents).map_err(GoldenError::DeserializationError)?;

        if entry.data != *data {
            return Err(GoldenError::DataMismatch {
                path: path.to_path_buf(),
                expected: format!("{:#?}", entry.data),
                actual: format!("{:#?}", data),
            });
        }

        Ok(())
    }

    /// Lists all golden files in the base directory
    #[allow(dead_code)]
    pub fn list_golden_files(&self) -> Result<Vec<PathBuf>, GoldenError> {
        let mut files = Vec::new();
        self.collect_golden_files(&self.base_path, &mut files)?;
        Ok(files)
    }

    /// Recursively collects golden files
    #[allow(dead_code)]
    fn collect_golden_files(
        &self,
        dir: &Path,
        files: &mut Vec<PathBuf>,
    ) -> Result<(), GoldenError> {
        if !dir.exists() {
            return Ok(());
        }

        let entries = fs::read_dir(dir).map_err(|e| GoldenError::IoError {
            path: dir.to_path_buf(),
            error: e,
        })?;

        for entry in entries {
            let entry = entry.map_err(|e| GoldenError::IoError {
                path: dir.to_path_buf(),
                error: e,
            })?;

            let path = entry.path();
            if path.is_dir() {
                self.collect_golden_files(&path, files)?;
            } else if path.extension().and_then(|s| s.to_str()) == Some("golden") {
                files.push(path);
            }
        }

        Ok(())
    }

    /// Validates all golden files in the directory
    #[allow(dead_code)]
    pub fn validate_all(&self) -> Result<ValidationSummary, GoldenError> {
        let files = self.list_golden_files()?;
        let mut summary = ValidationSummary::default();

        for file in files {
            summary.total += 1;

            // For validation, we just check that the file is readable and well-formed
            let contents = fs::read_to_string(&file).map_err(|e| GoldenError::IoError {
                path: file.clone(),
                error: e,
            })?;

            match serde_json::from_str::<serde_json::Value>(&contents) {
                Ok(_) => {
                    summary.passed += 1;
                }
                Err(e) => {
                    summary.failed += 1;
                    summary.failures.push(format!("{}: {}", file.display(), e));
                }
            }
        }

        Ok(summary)
    }
}

/// Summary of golden file validation
#[derive(Debug, Default)]
#[allow(dead_code)]
pub struct ValidationSummary {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub failures: Vec<String>,
}

#[allow(dead_code)]

impl ValidationSummary {
    #[allow(dead_code)]
    pub fn is_success(&self) -> bool {
        self.failed == 0
    }
}

/// Golden file operation errors
#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
pub enum GoldenError {
    #[error("Missing golden file at {path}: {hint}")]
    MissingGoldenFile { path: PathBuf, hint: String },

    #[error("Data mismatch in {path}:\nExpected:\n{expected}\n\nActual:\n{actual}")]
    DataMismatch {
        path: PathBuf,
        expected: String,
        actual: String,
    },

    #[error("IO error for {path}: {error}")]
    IoError {
        path: PathBuf,
        error: std::io::Error,
    },

    #[error("Serialization error: {0}")]
    SerializationError(serde_json::Error),

    #[error("Deserialization error: {0}")]
    DeserializationError(serde_json::Error),
}

/// Helper macro for creating golden file assertions
#[macro_export]
macro_rules! assert_golden {
    ($manager:expr, $filename:expr, $data:expr, $metadata:expr) => {
        $manager
            .assert_golden($filename, &$data, $metadata)
            .unwrap_or_else(|e| panic!("Golden file assertion failed: {}", e))
    };
}

/// Helper function to create metadata
#[allow(dead_code)]
pub fn create_metadata(
    test_name: &str,
    rfc_section: &str,
    description: &str,
    input_params: HashMap<String, String>,
) -> GoldenMetadata {
    let data_str = format!(
        "{}{}{}{:?}",
        test_name, rfc_section, description, input_params
    );
    let checksum = format!("{:x}", md5::compute(data_str));

    GoldenMetadata {
        test_name: test_name.to_string(),
        rfc_section: rfc_section.to_string(),
        description: description.to_string(),
        last_updated: SystemTime::now(),
        git_commit: std::env::var("GIT_COMMIT").ok(),
        input_params,
        checksum,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    #[allow(dead_code)]
    struct TestData {
        values: Vec<u32>,
        name: String,
    }

    #[test]
    #[allow(dead_code)]
    fn test_golden_file_creation() {
        let temp_dir = TempDir::new().unwrap();
        let manager = GoldenFileManager::with_update_mode(temp_dir.path(), true);

        let data = TestData {
            values: vec![1, 2, 3, 4, 5],
            name: "test".to_string(),
        };

        let metadata = create_metadata(
            "test_case",
            "5.3.1",
            "Test data for golden file",
            HashMap::new(),
        );

        assert!(manager
            .assert_golden("test.golden", &data, metadata)
            .is_ok());
        assert!(temp_dir.path().join("test.golden").exists());
    }

    #[test]
    #[allow(dead_code)]
    fn test_golden_file_validation() {
        let temp_dir = TempDir::new().unwrap();
        let manager = GoldenFileManager::with_update_mode(temp_dir.path(), true);

        let data = TestData {
            values: vec![1, 2, 3, 4, 5],
            name: "test".to_string(),
        };

        let metadata = create_metadata(
            "test_case",
            "5.3.1",
            "Test data for golden file",
            HashMap::new(),
        );

        // Create golden file
        manager
            .assert_golden("test.golden", &data, metadata)
            .unwrap();

        // Switch to validation mode
        let validator = GoldenFileManager::with_update_mode(temp_dir.path(), false);

        // Should pass with same data
        assert!(validator
            .validate_golden(&temp_dir.path().join("test.golden"), &data)
            .is_ok());

        // Should fail with different data
        let wrong_data = TestData {
            values: vec![6, 7, 8],
            name: "wrong".to_string(),
        };
        assert!(validator
            .validate_golden(&temp_dir.path().join("test.golden"), &wrong_data)
            .is_err());
    }

    #[test]
    #[allow(dead_code)]
    fn test_missing_golden_file() {
        let temp_dir = TempDir::new().unwrap();
        let manager = GoldenFileManager::with_update_mode(temp_dir.path(), false);

        let data = TestData {
            values: vec![1, 2, 3],
            name: "test".to_string(),
        };

        let result = manager.validate_golden(&temp_dir.path().join("missing.golden"), &data);
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("Missing golden file"));
    }
}
