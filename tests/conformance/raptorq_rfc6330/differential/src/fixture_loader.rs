use crate::provenance::{
    DifferentialFixtureCatalog, DifferentialFixtureError, FixtureArtifact, FixtureProvenanceRecord,
};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Resolves differential fixture catalogs and artifact paths from a base
/// directory on disk.
#[derive(Debug, Clone)]
pub struct DifferentialFixtureLoader {
    base_path: PathBuf,
}

impl DifferentialFixtureLoader {
    #[must_use]
    pub fn new<P: AsRef<Path>>(base_path: P) -> Self {
        Self {
            base_path: base_path.as_ref().to_path_buf(),
        }
    }

    #[must_use]
    pub fn base_path(&self) -> &Path {
        &self.base_path
    }

    #[must_use]
    pub fn default_catalog_path(&self) -> PathBuf {
        self.base_path.join("fixtures").join("catalog.json")
    }

    #[must_use]
    pub fn default_provenance_path(&self) -> PathBuf {
        self.base_path.join("fixtures").join("PROVENANCE.md")
    }

    pub fn load_catalog(&self) -> Result<DifferentialFixtureCatalog, DifferentialFixtureError> {
        let catalog = DifferentialFixtureCatalog::load_json(self.default_catalog_path())?;
        self.validate_catalog(&catalog)?;
        Ok(catalog)
    }

    pub fn validate_catalog(
        &self,
        catalog: &DifferentialFixtureCatalog,
    ) -> Result<(), DifferentialFixtureError> {
        let mut seen_case_ids = BTreeSet::new();
        for record in &catalog.records {
            if !seen_case_ids.insert(record.case_id.clone()) {
                return Err(DifferentialFixtureError::DuplicateCaseId {
                    case_id: record.case_id.clone(),
                });
            }

            for artifact in &record.artifacts {
                if artifact.relative_path.is_absolute() {
                    return Err(DifferentialFixtureError::AbsoluteArtifactPath {
                        case_id: record.case_id.clone(),
                        path: artifact.relative_path.clone(),
                    });
                }
            }
        }
        Ok(())
    }

    pub fn load_case<'a>(
        &self,
        catalog: &'a DifferentialFixtureCatalog,
        case_id: &str,
    ) -> Result<FixtureCaseView<'a>, DifferentialFixtureError> {
        let record = catalog
            .records
            .iter()
            .find(|record| record.case_id == case_id)
            .ok_or_else(|| DifferentialFixtureError::MissingCaseId {
                case_id: case_id.to_string(),
            })?;

        let resolved_artifacts = record
            .artifacts
            .iter()
            .map(|artifact| self.resolve_artifact_path(artifact))
            .collect();

        Ok(FixtureCaseView {
            record,
            resolved_artifacts,
        })
    }

    #[must_use]
    pub fn resolve_artifact_path(&self, artifact: &FixtureArtifact) -> PathBuf {
        self.base_path.join(&artifact.relative_path)
    }

    pub fn write_provenance_markdown(
        &self,
        catalog: &DifferentialFixtureCatalog,
    ) -> Result<(), DifferentialFixtureError> {
        self.validate_catalog(catalog)?;
        let path = self.default_provenance_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| DifferentialFixtureError::Io {
                path: parent.to_path_buf(),
                error,
            })?;
        }
        fs::write(&path, catalog.render_provenance_markdown()).map_err(|error| {
            DifferentialFixtureError::Io {
                path: path.clone(),
                error,
            }
        })
    }
}

/// A catalog case plus its resolved artifact paths on disk.
#[derive(Debug, Clone)]
pub struct FixtureCaseView<'a> {
    pub record: &'a FixtureProvenanceRecord,
    pub resolved_artifacts: Vec<PathBuf>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provenance::{ReferenceImplementation, ReferenceLanguage};

    fn sample_catalog() -> DifferentialFixtureCatalog {
        DifferentialFixtureCatalog {
            records: vec![FixtureProvenanceRecord {
                case_id: "decode_erasure_pattern_1".to_string(),
                rfc_section: "5.4.4".to_string(),
                generated_at: "2026-04-16T17:00:00Z".to_string(),
                command: "python gen.py --case decode_erasure_pattern_1".to_string(),
                reference: ReferenceImplementation {
                    name: "raptorq-python".to_string(),
                    language: ReferenceLanguage::Python,
                    version: "1.2.3".to_string(),
                    source: "https://example.invalid/raptorq-python".to_string(),
                    invocation: "python -m raptorq".to_string(),
                    notes: None,
                },
                artifacts: vec![FixtureArtifact {
                    relative_path: PathBuf::from(
                        "fixtures/reference_outputs/decode_erasure_pattern_1.bin",
                    ),
                    media_type: "application/octet-stream".to_string(),
                    sha256: "abc123".to_string(),
                    description: "Recovered payload bytes".to_string(),
                }],
            }],
        }
    }

    #[test]
    fn loader_resolves_case_artifact_paths() {
        let loader = DifferentialFixtureLoader::new("/tmp/differential");
        let catalog = sample_catalog();

        let case = loader
            .load_case(&catalog, "decode_erasure_pattern_1")
            .expect("case should exist");

        assert_eq!(case.record.case_id, "decode_erasure_pattern_1");
        assert_eq!(
            case.resolved_artifacts,
            vec![PathBuf::from(
                "/tmp/differential/fixtures/reference_outputs/decode_erasure_pattern_1.bin"
            )]
        );
    }

    #[test]
    fn loader_rejects_duplicate_case_ids() {
        let loader = DifferentialFixtureLoader::new("/tmp/differential");
        let record = sample_catalog().records.into_iter().next().expect("record");
        let catalog = DifferentialFixtureCatalog {
            records: vec![record.clone(), record],
        };

        let err = loader.validate_catalog(&catalog).expect_err("duplicates rejected");
        assert!(matches!(
            err,
            DifferentialFixtureError::DuplicateCaseId { case_id }
            if case_id == "decode_erasure_pattern_1"
        ));
    }

    #[test]
    fn loader_rejects_absolute_artifact_paths() {
        let loader = DifferentialFixtureLoader::new("/tmp/differential");
        let mut catalog = sample_catalog();
        catalog.records[0].artifacts[0].relative_path =
            PathBuf::from("/tmp/escape/reference_output.bin");

        let err = loader.validate_catalog(&catalog).expect_err("absolute path rejected");
        assert!(matches!(
            err,
            DifferentialFixtureError::AbsoluteArtifactPath { case_id, .. }
            if case_id == "decode_erasure_pattern_1"
        ));
    }

    #[test]
    fn provenance_markdown_is_regenerated_from_catalog() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let loader = DifferentialFixtureLoader::new(tempdir.path());
        let catalog = sample_catalog();

        loader
            .write_provenance_markdown(&catalog)
            .expect("write provenance");

        let markdown = fs::read_to_string(loader.default_provenance_path()).expect("read file");
        assert!(markdown.contains("decode_erasure_pattern_1"));
        assert!(markdown.contains("raptorq-python"));
    }
}
