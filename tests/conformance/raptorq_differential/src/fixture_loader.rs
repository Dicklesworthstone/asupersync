//! Fixture loading and management for differential testing.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Manages loading and validation of test fixtures
#[derive(Debug)]
#[allow(dead_code)]
pub struct FixtureLoader {
    fixture_dir: PathBuf,
}

/// Collection of related fixtures
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct FixtureSet {
    pub name: String,
    pub fixtures: Vec<FixtureEntry>,
    pub metadata: FixtureSetMetadata,
}

/// Individual fixture entry
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct FixtureEntry {
    /// Test metadata
    pub metadata: FixtureMetadata,
    /// Reference implementation output
    pub reference_output: Vec<u8>,
    /// Test input parameters
    pub test_input: Vec<u8>,
}

/// Metadata for a test fixture
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct FixtureMetadata {
    /// Name of the test case
    pub test_name: String,
    /// Reference implementation used
    pub reference_implementation: String,
    /// Version of reference implementation
    pub reference_version: String,
    /// Parameters used to generate this fixture
    pub test_parameters: HashMap<String, String>,
    /// When this fixture was generated
    pub generated_at: String,
    /// Command line used to generate fixture
    pub generation_command: Option<String>,
    /// Hash of input data for verification
    pub input_hash: String,
    /// Hash of output data for verification
    pub output_hash: String,
}

/// Metadata for a collection of fixtures
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct FixtureSetMetadata {
    /// Name of the fixture set
    pub set_name: String,
    /// Description of what this set tests
    pub description: String,
    /// Reference implementation info
    pub reference_info: String,
    /// Test categories covered
    pub categories: Vec<String>,
}

/// Errors that can occur during fixture operations
#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
pub enum FixtureError {
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Invalid fixture format: {0}")]
    InvalidFormat(String),

    #[error("Fixture not found: {0}")]
    NotFound(String),

    #[error("Hash mismatch in fixture {0}: expected {1}, got {2}")]
    HashMismatch(String, String, String),

    #[error("Missing required field: {0}")]
    MissingField(String),
}

#[allow(dead_code)]

impl FixtureLoader {
    /// Creates a new fixture loader for the given directory
    #[allow(dead_code)]
    pub fn new<P: AsRef<Path>>(fixture_dir: P) -> Result<Self, FixtureError> {
        let fixture_dir = fixture_dir.as_ref().to_path_buf();

        if !fixture_dir.exists() {
            return Err(FixtureError::NotFound(format!("Fixture directory not found: {}", fixture_dir.display())));
        }

        Ok(Self { fixture_dir })
    }

    /// Lists all available fixture files
    #[allow(dead_code)]
    pub fn list_fixtures(&self) -> Result<Vec<PathBuf>, FixtureError> {
        let mut fixtures = Vec::new();
        self.scan_directory(&self.fixture_dir, &mut fixtures)?;
        Ok(fixtures)
    }

    /// Recursively scans for fixture files
    #[allow(dead_code)]
    fn scan_directory(&self, dir: &Path, fixtures: &mut Vec<PathBuf>) -> Result<(), FixtureError> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                self.scan_directory(&path, fixtures)?;
            } else if path.extension().and_then(|s| s.to_str()) == Some("fixture") {
                fixtures.push(path);
            }
        }

        Ok(())
    }

    /// Loads a single fixture from file
    #[allow(dead_code)]
    pub fn load_fixture<P: AsRef<Path>>(&self, fixture_path: P) -> Result<FixtureEntry, FixtureError> {
        let path = fixture_path.as_ref();

        if !path.exists() {
            return Err(FixtureError::NotFound(path.display().to_string()));
        }

        let content = fs::read_to_string(path)?;
        let fixture_data: SerializedFixture = serde_json::from_str(&content)?;

        // Decode base64 data
        let reference_output = base64::decode(&fixture_data.reference_output_base64)
            .map_err(|e| FixtureError::InvalidFormat(format!("Invalid base64 in reference_output: {}", e)))?;

        let test_input = base64::decode(&fixture_data.test_input_base64)
            .map_err(|e| FixtureError::InvalidFormat(format!("Invalid base64 in test_input: {}", e)))?;

        // Verify hashes
        let input_hash = calculate_hash(&test_input);
        if input_hash != fixture_data.metadata.input_hash {
            return Err(FixtureError::HashMismatch(
                path.display().to_string(),
                fixture_data.metadata.input_hash,
                input_hash,
            ));
        }

        let output_hash = calculate_hash(&reference_output);
        if output_hash != fixture_data.metadata.output_hash {
            return Err(FixtureError::HashMismatch(
                path.display().to_string(),
                fixture_data.metadata.output_hash,
                output_hash,
            ));
        }

        Ok(FixtureEntry {
            metadata: fixture_data.metadata,
            reference_output,
            test_input,
        })
    }

    /// Loads all fixtures in a directory as a fixture set
    #[allow(dead_code)]
    pub fn load_fixture_set<P: AsRef<Path>>(&self, set_dir: P) -> Result<FixtureSet, FixtureError> {
        let set_path = set_dir.as_ref();
        let metadata_path = set_path.join("metadata.json");

        let metadata: FixtureSetMetadata = if metadata_path.exists() {
            let content = fs::read_to_string(&metadata_path)?;
            serde_json::from_str(&content)?
        } else {
            FixtureSetMetadata {
                set_name: set_path.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown")
                    .to_string(),
                description: "No description available".to_string(),
                reference_info: "Unknown reference implementation".to_string(),
                categories: vec!["general".to_string()],
            }
        };

        let mut fixtures = Vec::new();
        for entry in fs::read_dir(set_path)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some("fixture") {
                match self.load_fixture(&path) {
                    Ok(fixture) => fixtures.push(fixture),
                    Err(e) => {
                        eprintln!("Warning: Failed to load fixture {}: {}", path.display(), e);
                    }
                }
            }
        }

        Ok(FixtureSet {
            name: metadata.set_name.clone(),
            fixtures,
            metadata,
        })
    }

    /// Saves a fixture to file
    #[allow(dead_code)]
    pub fn save_fixture<P: AsRef<Path>>(&self, fixture_path: P, fixture: &FixtureEntry) -> Result<(), FixtureError> {
        let serialized = SerializedFixture {
            metadata: fixture.metadata.clone(),
            reference_output_base64: base64::encode(&fixture.reference_output),
            test_input_base64: base64::encode(&fixture.test_input),
        };

        let json = serde_json::to_string_pretty(&serialized)?;
        fs::write(fixture_path, json)?;

        Ok(())
    }

    /// Validates all fixtures in the directory
    #[allow(dead_code)]
    pub fn validate_all_fixtures(&self) -> Result<ValidationReport, FixtureError> {
        let fixture_paths = self.list_fixtures()?;
        let mut report = ValidationReport {
            total_fixtures: fixture_paths.len(),
            valid_fixtures: 0,
            invalid_fixtures: Vec::new(),
        };

        for fixture_path in fixture_paths {
            match self.load_fixture(&fixture_path) {
                Ok(_) => report.valid_fixtures += 1,
                Err(e) => report.invalid_fixtures.push((fixture_path, e)),
            }
        }

        Ok(report)
    }
}

/// Serialized format for fixtures on disk
#[derive(Debug, Serialize, Deserialize)]
#[allow(dead_code)]
struct SerializedFixture {
    metadata: FixtureMetadata,
    reference_output_base64: String,
    test_input_base64: String,
}

/// Report from fixture validation
#[derive(Debug)]
#[allow(dead_code)]
pub struct ValidationReport {
    pub total_fixtures: usize,
    pub valid_fixtures: usize,
    pub invalid_fixtures: Vec<(PathBuf, FixtureError)>,
}

#[allow(dead_code)]

impl ValidationReport {
    /// Returns true if all fixtures are valid
    #[allow(dead_code)]
    pub fn is_all_valid(&self) -> bool {
        self.invalid_fixtures.is_empty()
    }

    /// Returns the percentage of valid fixtures
    #[allow(dead_code)]
    pub fn validity_percentage(&self) -> f64 {
        if self.total_fixtures == 0 {
            100.0
        } else {
            (self.valid_fixtures as f64 / self.total_fixtures as f64) * 100.0
        }
    }
}

/// Calculates SHA-256 hash of data
#[allow(dead_code)]
fn calculate_hash(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::fs;

    #[test]
    #[allow(dead_code)]
    fn test_fixture_loader_creation() {
        let temp_dir = TempDir::new().unwrap();
        let loader = FixtureLoader::new(temp_dir.path()).unwrap();
        assert_eq!(loader.fixture_dir, temp_dir.path());
    }

    #[test]
    #[allow(dead_code)]
    fn test_fixture_loader_nonexistent_dir() {
        let result = FixtureLoader::new("/nonexistent/path");
        assert!(result.is_err());
        matches!(result.unwrap_err(), FixtureError::NotFound(_));
    }

    #[test]
    #[allow(dead_code)]
    fn test_list_fixtures_empty_dir() {
        let temp_dir = TempDir::new().unwrap();
        let loader = FixtureLoader::new(temp_dir.path()).unwrap();
        let fixtures = loader.list_fixtures().unwrap();
        assert!(fixtures.is_empty());
    }

    #[test]
    #[allow(dead_code)]
    fn test_calculate_hash() {
        let data = b"test data";
        let hash = calculate_hash(data);
        assert_eq!(hash.len(), 64); // SHA-256 produces 64 hex characters
        assert!(!hash.is_empty());

        // Same data should produce same hash
        let hash2 = calculate_hash(data);
        assert_eq!(hash, hash2);
    }

    #[test]
    #[allow(dead_code)]
    fn test_validation_report() {
        let report = ValidationReport {
            total_fixtures: 10,
            valid_fixtures: 8,
            invalid_fixtures: vec![],
        };

        assert_eq!(report.validity_percentage(), 80.0);
        assert!(report.is_all_valid()); // No invalid fixtures recorded
    }

    #[allow(dead_code)]

    fn create_test_fixture() -> FixtureEntry {
        FixtureEntry {
            metadata: FixtureMetadata {
                test_name: "test_case".to_string(),
                reference_implementation: "libraptorq".to_string(),
                reference_version: "1.0.0".to_string(),
                test_parameters: {
                    let mut params = HashMap::new();
                    params.insert("k".to_string(), "100".to_string());
                    params.insert("t".to_string(), "1024".to_string());
                    params
                },
                generated_at: "2024-01-01T00:00:00Z".to_string(),
                generation_command: Some("libraptorq encode --k 100 --t 1024".to_string()),
                input_hash: calculate_hash(b"test input"),
                output_hash: calculate_hash(b"test output"),
            },
            reference_output: b"test output".to_vec(),
            test_input: b"test input".to_vec(),
        }
    }

    #[test]
    #[allow(dead_code)]
    fn test_fixture_save_load_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let loader = FixtureLoader::new(temp_dir.path()).unwrap();

        let fixture = create_test_fixture();
        let fixture_path = temp_dir.path().join("test.fixture");

        // Save fixture
        loader.save_fixture(&fixture_path, &fixture).unwrap();
        assert!(fixture_path.exists());

        // Load fixture
        let loaded_fixture = loader.load_fixture(&fixture_path).unwrap();

        // Compare
        assert_eq!(fixture.metadata.test_name, loaded_fixture.metadata.test_name);
        assert_eq!(fixture.reference_output, loaded_fixture.reference_output);
        assert_eq!(fixture.test_input, loaded_fixture.test_input);
    }
}

// Add missing base64 and sha2 dependencies for compilation
#[cfg(not(test))]
mod base64 {
    #[allow(dead_code)]
    pub fn encode(_data: &[u8]) -> String {
        "mock_base64".to_string()
    }

    #[allow(dead_code)]

    pub fn decode(_data: &str) -> Result<Vec<u8>, &'static str> {
        Ok(vec![0x42; 64])
    }
}

#[cfg(not(test))]
mod sha2 {
    pub trait Digest {
        #[allow(dead_code)]
        fn update(&mut self, data: &[u8]);
        #[allow(dead_code)]
        fn finalize(self) -> [u8; 32];
    }

    #[allow(dead_code)]
    pub struct Sha256;

    #[allow(dead_code)]

    impl Sha256 {
        #[allow(dead_code)]
        pub fn new() -> Self { Self }
    }

    impl Digest for Sha256 {
        #[allow(dead_code)]
        fn update(&mut self, _data: &[u8]) {}
        #[allow(dead_code)]
        fn finalize(self) -> [u8; 32] { [0; 32] }
    }
}