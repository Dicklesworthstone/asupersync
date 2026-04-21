#![allow(clippy::all)]
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Reference implementation language.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub enum ReferenceLanguage {
    C,
    Cpp,
    Go,
    Python,
    Rust,
    Other(String),
}

#[allow(dead_code)]

impl ReferenceLanguage {
    #[must_use]
    #[allow(dead_code)]
    pub fn as_str(&self) -> &str {
        match self {
            Self::C => "C",
            Self::Cpp => "C++",
            Self::Go => "Go",
            Self::Python => "Python",
            Self::Rust => "Rust",
            Self::Other(value) => value.as_str(),
        }
    }
}

/// Metadata describing the reference implementation used for a fixture set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct ReferenceImplementation {
    pub name: String,
    pub language: ReferenceLanguage,
    pub version: String,
    pub source: String,
    pub invocation: String,
    pub notes: Option<String>,
}

/// One generated fixture artifact produced by the reference implementation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct FixtureArtifact {
    pub relative_path: PathBuf,
    pub media_type: String,
    pub sha256: String,
    pub description: String,
}

/// Provenance record for one differential test case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct FixtureProvenanceRecord {
    pub case_id: String,
    pub rfc_section: String,
    pub generated_at: String,
    pub command: String,
    pub reference: ReferenceImplementation,
    pub artifacts: Vec<FixtureArtifact>,
}

/// Top-level catalog for differential fixtures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[allow(dead_code)]
pub struct DifferentialFixtureCatalog {
    pub records: Vec<FixtureProvenanceRecord>,
}

#[allow(dead_code)]

impl DifferentialFixtureCatalog {
    #[must_use]
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::default()
    }

    #[allow(dead_code)]

    pub fn add_record(&mut self, record: FixtureProvenanceRecord) {
        self.records.push(record);
        self.records.sort_by(|a, b| a.case_id.cmp(&b.case_id));
    }

    #[must_use]
    #[allow(dead_code)]
    pub fn summary(&self) -> CatalogSummary {
        let artifact_count = self.records.iter().map(|record| record.artifacts.len()).sum();
        CatalogSummary {
            case_count: self.records.len(),
            artifact_count,
        }
    }

    #[allow(dead_code)]

    pub fn save_json<P: AsRef<Path>>(&self, path: P) -> Result<(), DifferentialFixtureError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| DifferentialFixtureError::Io {
                path: parent.to_path_buf(),
                error,
            })?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(DifferentialFixtureError::Serialize)?;
        fs::write(path, json).map_err(|error| DifferentialFixtureError::Io {
            path: path.to_path_buf(),
            error,
        })
    }

    #[allow(dead_code)]

    pub fn load_json<P: AsRef<Path>>(path: P) -> Result<Self, DifferentialFixtureError> {
        let path = path.as_ref();
        let json = fs::read_to_string(path).map_err(|error| DifferentialFixtureError::Io {
            path: path.to_path_buf(),
            error,
        })?;
        serde_json::from_str(&json).map_err(DifferentialFixtureError::Deserialize)
    }

    #[must_use]
    #[allow(dead_code)]
    pub fn render_provenance_markdown(&self) -> String {
        let mut markdown = String::from(
            "# Differential Fixture Provenance\n\n\
             This file documents which reference implementation generated each\n\
             differential fixture set and how to reproduce it.\n\n",
        );

        for record in &self.records {
            markdown.push_str(&format!("## {}\n\n", record.case_id));
            markdown.push_str(&format!(
                "- RFC section: `{}`\n- Generated at: `{}`\n- Reference: `{}` ({}, version `{}`)\n\
                 - Source: {}\n- Invocation: `{}`\n- Command: `{}`\n",
                record.rfc_section,
                record.generated_at,
                record.reference.name,
                record.reference.language.as_str(),
                record.reference.version,
                record.reference.source,
                record.reference.invocation,
                record.command,
            ));

            if let Some(notes) = &record.reference.notes {
                markdown.push_str(&format!("- Notes: {}\n", notes));
            }

            markdown.push_str("- Artifacts:\n");
            for artifact in &record.artifacts {
                markdown.push_str(&format!(
                    "  - `{}` ({}, sha256 `{}`) - {}\n",
                    artifact.relative_path.display(),
                    artifact.media_type,
                    artifact.sha256,
                    artifact.description,
                ));
            }
            markdown.push('\n');
        }

        markdown
    }
}

/// Lightweight summary for reporting.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub struct CatalogSummary {
    pub case_count: usize,
    pub artifact_count: usize,
}

#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
pub enum DifferentialFixtureError {
    #[error("I/O error for {path}: {error}")]
    Io { path: PathBuf, error: std::io::Error },

    #[error("failed to serialize differential fixture catalog: {0}")]
    Serialize(serde_json::Error),

    #[error("failed to deserialize differential fixture catalog: {0}")]
    Deserialize(serde_json::Error),

    #[error("differential fixture catalog contains duplicate case id `{case_id}`")]
    DuplicateCaseId { case_id: String },

    #[error("differential fixture case `{case_id}` uses absolute artifact path `{path}`")]
    AbsoluteArtifactPath { case_id: String, path: PathBuf },

    #[error("differential fixture catalog is missing case id `{case_id}`")]
    MissingCaseId { case_id: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(dead_code)]

    fn sample_record() -> FixtureProvenanceRecord {
        FixtureProvenanceRecord {
            case_id: "encode_k40_systematic".to_string(),
            rfc_section: "5.3.3".to_string(),
            generated_at: "2026-04-16T16:00:00Z".to_string(),
            command: "python generate_fixture.py --case encode_k40_systematic".to_string(),
            reference: ReferenceImplementation {
                name: "raptorq-python".to_string(),
                language: ReferenceLanguage::Python,
                version: "1.2.3".to_string(),
                source: "https://example.invalid/raptorq-python".to_string(),
                invocation: "python -m raptorq".to_string(),
                notes: Some("Pinned in CI to avoid fixture drift".to_string()),
            },
            artifacts: vec![
                FixtureArtifact {
                    relative_path: PathBuf::from("fixtures/reference_outputs/encode_k40_systematic.bin"),
                    media_type: "application/octet-stream".to_string(),
                    sha256: "abc123".to_string(),
                    description: "Systematic symbols for the K=40 reference vector".to_string(),
                },
                FixtureArtifact {
                    relative_path: PathBuf::from("fixtures/test_cases/encode_k40_systematic.json"),
                    media_type: "application/json".to_string(),
                    sha256: "def456".to_string(),
                    description: "Fixture parameters for the systematic encoding case".to_string(),
                },
            ],
        }
    }

    #[test]
    #[allow(dead_code)]
    fn catalog_round_trips_through_json() {
        let mut catalog = DifferentialFixtureCatalog::new();
        catalog.add_record(sample_record());

        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("catalog.json");
        catalog.save_json(&path).expect("save catalog");

        let reloaded = DifferentialFixtureCatalog::load_json(&path).expect("load catalog");
        assert_eq!(reloaded, catalog);
    }

    #[test]
    #[allow(dead_code)]
    fn markdown_contains_reproduction_metadata() {
        let mut catalog = DifferentialFixtureCatalog::new();
        catalog.add_record(sample_record());

        let markdown = catalog.render_provenance_markdown();
        assert!(markdown.contains("# Differential Fixture Provenance"));
        assert!(markdown.contains("encode_k40_systematic"));
        assert!(markdown.contains("raptorq-python"));
        assert!(markdown.contains("python -m raptorq"));
        assert!(markdown.contains("fixtures/reference_outputs/encode_k40_systematic.bin"));
    }

    #[test]
    #[allow(dead_code)]
    fn summary_counts_cases_and_artifacts() {
        let mut catalog = DifferentialFixtureCatalog::new();
        catalog.add_record(sample_record());

        let summary = catalog.summary();
        assert_eq!(summary.case_count, 1);
        assert_eq!(summary.artifact_count, 2);
    }
}
