//! Explicit filesystem composition for scenario documents.

use super::{IncludeRef, SCENARIO_SCHEMA_VERSION, Scenario};
use serde_yaml::{Mapping, Value};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

/// Bounds on filesystem work performed by [`Scenario::load_resolved`].
///
/// These limits cover include expansion and bytes read, including the root.
/// They do not replace serde_yaml's parser recursion and alias protections or
/// impose a separate limit on the parser's in-memory representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScenarioLoadLimits {
    /// Maximum include edges from the root to a document; zero permits only
    /// the root document.
    pub max_include_depth: usize,
    /// Maximum document reads, counting repeated references separately.
    pub max_files: usize,
    /// Maximum bytes read from any one document.
    pub max_file_bytes: usize,
    /// Maximum bytes read across all documents, including repeated references.
    pub max_total_bytes: usize,
}

impl Default for ScenarioLoadLimits {
    fn default() -> Self {
        Self {
            max_include_depth: 16,
            max_files: 64,
            max_file_bytes: 1024 * 1024,
            max_total_bytes: 8 * 1024 * 1024,
        }
    }
}

/// Failure to read or compose a scenario and its explicitly requested includes.
#[derive(Debug)]
#[non_exhaustive]
pub enum ScenarioLoadError {
    /// A filesystem operation failed.
    Io {
        /// Document being accessed.
        path: PathBuf,
        /// Underlying filesystem error.
        source: io::Error,
    },
    /// YAML syntax or the composed typed scenario was invalid.
    Parse {
        /// Document being parsed; the root for final typed deserialization.
        path: PathBuf,
        /// Underlying YAML error, including a source location when available.
        source: serde_yaml::Error,
    },
    /// A document, schema version or include path was invalid.
    Invalid {
        /// Document containing the invalid declaration.
        path: PathBuf,
        /// Explanation of the invalid declaration.
        message: String,
    },
    /// A filesystem work limit would be exceeded.
    LimitExceeded {
        /// Document whose load would exceed the limit.
        path: PathBuf,
        /// Name of the exceeded [`ScenarioLoadLimits`] field.
        limit: &'static str,
        /// Configured maximum.
        maximum: usize,
    },
    /// An include resolves outside the root document's canonical directory.
    OutsideRoot {
        /// Canonical include target.
        path: PathBuf,
        /// Canonical directory containing the root document.
        root: PathBuf,
    },
    /// An include references a document already on the active include chain.
    IncludeCycle {
        /// Canonical paths from the root through the repeated document.
        chain: Vec<PathBuf>,
    },
}

impl std::fmt::Display for ScenarioLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "failed to read scenario {}: {source}", path.display())
            }
            Self::Parse { path, source } => {
                write!(f, "failed to parse scenario {}: {source}", path.display())?;
                if source.to_string().contains("expected a string") {
                    f.write_str(
                        ". Hint: quote numeric, boolean or null values used as strings in resolved scenarios",
                    )?;
                }
                Ok(())
            }
            Self::Invalid { path, message } => {
                write!(f, "invalid scenario {}: {message}", path.display())
            }
            Self::LimitExceeded {
                path,
                limit,
                maximum,
            } => write!(f, "scenario {} exceeds {limit} ({maximum})", path.display()),
            Self::OutsideRoot { path, root } => write!(
                f,
                "scenario include {} is outside root directory {}",
                path.display(),
                root.display()
            ),
            Self::IncludeCycle { chain } => {
                f.write_str("scenario include cycle: ")?;
                for (index, path) in chain.iter().enumerate() {
                    if index != 0 {
                        f.write_str(" -> ")?;
                    }
                    write!(f, "{}", path.display())?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for ScenarioLoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Parse { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl Scenario {
    /// Load YAML and explicitly resolve its include graph within the root
    /// document's canonical parent directory.
    ///
    /// Included files may be partial mappings without an `id`. Each include is
    /// relative to its containing file and is merged in declaration order;
    /// later includes override earlier ones, then local fields override them.
    /// Mappings merge recursively, while sequences, scalars and explicit nulls
    /// replace the inherited value. Thus a local empty list clears an inherited
    /// workload, and `cancellation: null` disables an inherited strategy.
    /// Missing fields receive typed defaults only after composition.
    ///
    /// Only the root's explicit `id` is used; ids on included full scenarios
    /// are ignored. Every declared schema version must be supported. Include
    /// directives are consumed, leaving a standalone scenario with no pending
    /// filesystem dependencies. YAML `<<` merge keys are not applied.
    /// Numeric, boolean and null scalars used as string fields must be quoted
    /// in this opt-in mode (for example, `metadata: {revision: "123"}`). Unlike
    /// direct YAML deserialization, composition preserves scalar types instead
    /// of coercing these values to strings or rewriting their spellings.
    ///
    /// This synchronous configuration loader performs no runtime work and
    /// does not call [`Scenario::validate`]. Existing deserialization APIs
    /// remain single-document operations without filesystem effects.
    ///
    /// Canonical paths reject cycles and symlink escapes before reading an
    /// include. Callers should keep the source tree stable while loading:
    /// filesystem path checks are not an operating-system sandbox against
    /// concurrent replacement of files or directories.
    ///
    /// # Errors
    ///
    /// Returns source-context errors for invalid declarations, unsupported
    /// versions, malformed YAML, missing files, cycles, escapes, or exceeded
    /// [`ScenarioLoadLimits`]. The root must declare its own `id`.
    pub fn load_resolved(
        path: impl AsRef<Path>,
        limits: ScenarioLoadLimits,
    ) -> Result<Self, ScenarioLoadError> {
        let source_path = path.as_ref();
        let path = fs::canonicalize(source_path).map_err(|source| ScenarioLoadError::Io {
            path: source_path.to_path_buf(),
            source,
        })?;
        let root = path
            .parent()
            .ok_or_else(|| ScenarioLoadError::Invalid {
                path: path.clone(),
                message: "root document must have a parent directory".into(),
            })?
            .to_path_buf();
        let mut loader = Loader {
            root,
            limits,
            active: Vec::new(),
            files_read: 0,
            bytes_read: 0,
        };
        let composed = loader.resolve(&path, 0)?;
        serde_yaml::from_value(composed).map_err(|source| ScenarioLoadError::Parse { path, source })
    }
}

struct Loader {
    root: PathBuf,
    limits: ScenarioLoadLimits,
    active: Vec<PathBuf>,
    files_read: usize,
    bytes_read: usize,
}

impl Loader {
    fn resolve(&mut self, path: &Path, depth: usize) -> Result<Value, ScenarioLoadError> {
        if !path.starts_with(&self.root) {
            return Err(ScenarioLoadError::OutsideRoot {
                path: path.to_path_buf(),
                root: self.root.clone(),
            });
        }
        if self.active.iter().any(|active| active == path) {
            let mut chain = self.active.clone();
            chain.push(path.to_path_buf());
            return Err(ScenarioLoadError::IncludeCycle { chain });
        }
        if depth > self.limits.max_include_depth {
            return Err(limit_error(
                path,
                "max_include_depth",
                self.limits.max_include_depth,
            ));
        }
        if self.files_read >= self.limits.max_files {
            return Err(limit_error(path, "max_files", self.limits.max_files));
        }
        self.files_read += 1;
        self.active.push(path.to_path_buf());
        let result = self.compose(path, depth);
        self.active.pop();
        result
    }

    fn compose(&mut self, path: &Path, depth: usize) -> Result<Value, ScenarioLoadError> {
        let raw = self.read_document(path)?;
        let value: Value =
            serde_yaml::from_slice(&raw).map_err(|source| ScenarioLoadError::Parse {
                path: path.to_path_buf(),
                source,
            })?;
        let Value::Mapping(mut local) = value else {
            return Err(ScenarioLoadError::Invalid {
                path: path.to_path_buf(),
                message: "scenario document must be a mapping".into(),
            });
        };

        let id = local.remove(Value::String("id".into()));
        if depth == 0 && id.is_none() {
            return Err(ScenarioLoadError::Invalid {
                path: path.to_path_buf(),
                message: "root scenario must declare its own id".into(),
            });
        }
        if let Some(version) = local.get(Value::String("schema_version".into())) {
            let version: u32 = serde_yaml::from_value(version.clone()).map_err(|source| {
                ScenarioLoadError::Parse {
                    path: path.to_path_buf(),
                    source,
                }
            })?;
            if version != SCENARIO_SCHEMA_VERSION {
                return Err(ScenarioLoadError::Invalid {
                    path: path.to_path_buf(),
                    message: format!(
                        "unsupported schema_version {version}, expected {SCENARIO_SCHEMA_VERSION}"
                    ),
                });
            }
        }

        let includes: Vec<IncludeRef> = match local.remove(Value::String("include".into())) {
            Some(value) => {
                serde_yaml::from_value(value).map_err(|source| ScenarioLoadError::Parse {
                    path: path.to_path_buf(),
                    source,
                })?
            }
            None => Vec::new(),
        };
        let declarations = Scenario {
            include: includes,
            ..Scenario::default()
        };
        let mut errors = Vec::new();
        declarations.validate_includes(&mut errors);
        if !errors.is_empty() {
            return Err(ScenarioLoadError::Invalid {
                path: path.to_path_buf(),
                message: errors
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; "),
            });
        }

        let mut merged = Value::Mapping(Mapping::new());
        // `path` was canonicalized and checked to be a regular file, so it
        // necessarily has a parent. Preserve declaration order even for a
        // diamond: repeated includes are applied and charged each time.
        let directory = path.parent().unwrap_or(&self.root).to_path_buf();
        for include in declarations.include {
            let requested = directory.join(include.path);
            let included =
                fs::canonicalize(&requested).map_err(|source| ScenarioLoadError::Io {
                    path: requested,
                    source,
                })?;
            merge(&mut merged, self.resolve(&included, depth + 1)?);
        }
        if depth == 0 {
            if let Some(id) = id {
                local.insert(Value::String("id".into()), id);
            }
        }
        merge(&mut merged, Value::Mapping(local));
        Ok(merged)
    }

    fn read_document(&mut self, path: &Path) -> Result<Vec<u8>, ScenarioLoadError> {
        let io_error = |source| ScenarioLoadError::Io {
            path: path.to_path_buf(),
            source,
        };
        let metadata = fs::metadata(path).map_err(io_error)?;
        if !metadata.is_file() {
            return Err(ScenarioLoadError::Invalid {
                path: path.to_path_buf(),
                message: "scenario document must be a regular file".into(),
            });
        }

        let remaining = self.limits.max_total_bytes.saturating_sub(self.bytes_read);
        let (read_limit, limit, maximum) = if self.limits.max_file_bytes <= remaining {
            (
                self.limits.max_file_bytes,
                "max_file_bytes",
                self.limits.max_file_bytes,
            )
        } else {
            (remaining, "max_total_bytes", self.limits.max_total_bytes)
        };
        let byte_limit = u64::try_from(read_limit).unwrap_or(u64::MAX);
        if metadata.len() > byte_limit {
            return Err(limit_error(path, limit, maximum));
        }
        let file = File::open(path).map_err(io_error)?;
        if !file.metadata().map_err(io_error)?.is_file() {
            return Err(ScenarioLoadError::Invalid {
                path: path.to_path_buf(),
                message: "scenario document must be a regular file".into(),
            });
        }
        let mut raw = Vec::new();
        // Read at most one excess byte, even if the file grows after metadata
        // was inspected. Never allocate from an unchecked advertised length.
        file.take(byte_limit.saturating_add(1))
            .read_to_end(&mut raw)
            .map_err(io_error)?;
        if raw.len() > read_limit {
            return Err(limit_error(path, limit, maximum));
        }
        self.bytes_read += raw.len();
        Ok(raw)
    }
}

fn limit_error(path: &Path, limit: &'static str, maximum: usize) -> ScenarioLoadError {
    ScenarioLoadError::LimitExceeded {
        path: path.to_path_buf(),
        limit,
        maximum,
    }
}

fn merge(inherited: &mut Value, local: Value) {
    match (inherited, local) {
        (Value::Mapping(inherited), Value::Mapping(local)) => {
            for (key, value) in local {
                if let Some(previous) = inherited.get_mut(&key) {
                    merge(previous, value);
                } else {
                    inherited.insert(key, value);
                }
            }
        }
        (inherited, local) => *inherited = local,
    }
}

#[cfg(test)]
#[path = "loader_tests.rs"]
mod tests;
