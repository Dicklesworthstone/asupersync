//! Fixture Maintenance CLI
//!
//! Maintains the live RFC 6330 conformance fixture surfaces without pretending
//! unsupported reference workflows are implemented.

use clap::{Arg, ArgAction, Command};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

#[allow(dead_code)]
#[path = "../src/maintenance_workflows.rs"]
mod maintenance_workflows;

use maintenance_workflows::ReferenceVersion;

type DynError = Box<dyn std::error::Error>;

#[derive(Debug, Clone)]
struct ReferencePlan {
    reference: ReferenceVersion,
    note: String,
    regeneration_supported: bool,
    validation_supported: bool,
}

#[derive(Debug, Deserialize, Default)]
struct MaintenanceCliConfig {
    #[serde(default)]
    references: Vec<ReferenceOverride>,
}

#[derive(Debug, Deserialize)]
struct ReferenceOverride {
    name: String,
    fixture_directory: PathBuf,
    #[serde(default)]
    generation_command: Option<String>,
    #[serde(default)]
    validation_command: Option<String>,
    #[serde(default)]
    note: Option<String>,
}

fn main() {
    if let Err(error) = real_main() {
        eprintln!("Error: {error}");
        std::process::exit(1);
    }
}

fn real_main() -> Result<(), DynError> {
    let matches = Command::new("maintain_fixtures")
        .version("1.1.0")
        .author("asupersync contributors")
        .about("Maintain RFC 6330 conformance fixtures with truthful reference workflows")
        .arg(
            Arg::new("check-versions")
                .long("check-versions")
                .action(ArgAction::SetTrue)
                .help("Report tracked fixture directories, ages, and supported workflows"),
        )
        .arg(
            Arg::new("regenerate")
                .short('r')
                .long("regenerate")
                .value_name("REFERENCE")
                .help("Regenerate fixtures for a supported reference (golden or all)"),
        )
        .arg(
            Arg::new("validate")
                .long("validate")
                .action(ArgAction::SetTrue)
                .help("Run configured validation commands for tracked references"),
        )
        .arg(
            Arg::new("dry-run")
                .long("dry-run")
                .action(ArgAction::SetTrue)
                .help("Print the commands that would run without executing them"),
        )
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Optional JSON file with reference-command overrides")
                .default_value("maintenance_config.json"),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(ArgAction::SetTrue)
                .help("Show command details and reference notes"),
        )
        .get_matches();

    let dry_run = matches.get_flag("dry-run");
    let verbose = matches.get_flag("verbose");
    let config_path = resolve_config_path(matches.get_one::<String>("config").unwrap());
    let references = build_reference_catalog(&config_path)?;

    let mut ran_action = false;

    if matches.get_flag("check-versions")
        || (matches.get_one::<String>("regenerate").is_none() && !matches.get_flag("validate"))
    {
        print_reference_report(&references, verbose)?;
        ran_action = true;
    }

    if let Some(reference_name) = matches.get_one::<String>("regenerate") {
        regenerate_references(&references, reference_name, dry_run, verbose)?;
        ran_action = true;

        if matches.get_flag("validate") {
            validate_references(&references, Some(reference_name.as_str()), dry_run, verbose)?;
        }
    } else if matches.get_flag("validate") {
        validate_references(&references, None, dry_run, verbose)?;
        ran_action = true;
    }

    if !ran_action {
        print_reference_report(&references, verbose)?;
    }

    Ok(())
}

fn resolve_config_path(raw: &str) -> PathBuf {
    let path = PathBuf::from(raw);
    if path.is_absolute() {
        path
    } else {
        project_root().join(path)
    }
}

fn project_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("conformance crate has a repo-root parent")
        .to_path_buf()
}

fn build_reference_catalog(
    config_path: &Path,
) -> Result<BTreeMap<String, ReferencePlan>, DynError> {
    let mut references = default_reference_catalog();

    if config_path.exists() {
        let config = load_cli_config(config_path)?;
        let config_dir = config_path.parent().unwrap_or_else(|| Path::new("."));
        for reference in config.references {
            let fixture_directory = if reference.fixture_directory.is_absolute() {
                reference.fixture_directory
            } else {
                config_dir.join(reference.fixture_directory)
            };

            let mut version = ReferenceVersion::new(reference.name.clone(), fixture_directory);
            version.generation_command = reference.generation_command.unwrap_or_else(|| {
                "printf 'No generation command configured\\n' >&2; exit 1".to_string()
            });
            version.validation_command = reference.validation_command;

            references.insert(
                reference.name.clone(),
                ReferencePlan {
                    regeneration_supported: !version
                        .generation_command
                        .contains("No generation command configured"),
                    validation_supported: version.validation_command.is_some(),
                    note: reference
                        .note
                        .unwrap_or_else(|| "Configured via maintenance_config.json".to_string()),
                    reference: version,
                },
            );
        }
    }

    Ok(references)
}

fn load_cli_config(path: &Path) -> Result<MaintenanceCliConfig, DynError> {
    let content = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&content)?)
}

fn default_reference_catalog() -> BTreeMap<String, ReferencePlan> {
    let root = project_root();
    let mut references = BTreeMap::new();

    let golden_dir = root.join("tests/conformance/raptorq_rfc6330/golden/fixtures");
    let mut golden = ReferenceVersion::new("golden".to_string(), golden_dir);
    golden.generation_command =
        "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_conformance_remaining_docs cargo run --manifest-path ../Cargo.toml --bin generate_goldens -- --output . --golden ."
            .to_string();
    golden.validation_command = Some(
        "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_conformance_remaining_docs cargo run --manifest-path ../Cargo.toml --bin validate_round_trips -- --golden . --validate-format"
            .to_string(),
    );
    references.insert(
        "golden".to_string(),
        ReferencePlan {
            reference: golden,
            note: "Uses the real golden-file generator and round-trip validator crate.".to_string(),
            regeneration_supported: true,
            validation_supported: true,
        },
    );

    let differential_dir = root.join("tests/conformance/raptorq_rfc6330/differential/fixtures");
    let mut differential = ReferenceVersion::new("differential".to_string(), differential_dir);
    differential.generation_command =
        "printf 'Differential fixtures are externally generated; no in-repo generator is configured.\\n' >&2; exit 1"
            .to_string();
    differential.validation_command = Some("test -f PROVENANCE.md".to_string());
    references.insert(
        "differential".to_string(),
        ReferencePlan {
            reference: differential,
            note: "The live differential surface is provenance-only today; regeneration remains manual until real reference-generated fixtures land.".to_string(),
            regeneration_supported: false,
            validation_supported: true,
        },
    );

    references
}

fn print_reference_report(
    references: &BTreeMap<String, ReferencePlan>,
    verbose: bool,
) -> Result<(), DynError> {
    println!("Tracked reference maintenance surfaces:");
    println!("Project root: {}", project_root().display());

    for (name, plan) in references {
        let file_count = fixture_file_count(&plan.reference.fixture_directory)?;
        let age_days = newest_fixture_age_days(&plan.reference.fixture_directory)?;
        let regen = if plan.regeneration_supported {
            "supported"
        } else {
            "manual-only"
        };
        let validate = if plan.validation_supported {
            "supported"
        } else {
            "unsupported"
        };

        println!(
            "- {}: {} files, age={}d, regenerate={}, validate={}",
            name, file_count, age_days, regen, validate
        );
        println!(
            "  fixture_dir={}",
            plan.reference.fixture_directory.display()
        );
        if verbose {
            println!("  note={}", plan.note);
            if plan.regeneration_supported {
                println!("  regenerate_cmd={}", plan.reference.generation_command);
            }
            if let Some(validation_command) = &plan.reference.validation_command {
                println!("  validate_cmd={validation_command}");
            }
        }
    }

    Ok(())
}

fn regenerate_references(
    references: &BTreeMap<String, ReferencePlan>,
    requested: &str,
    dry_run: bool,
    verbose: bool,
) -> Result<(), DynError> {
    let reference_names = expand_requested_references(references, requested, true)?;

    for name in reference_names {
        let plan = references
            .get(&name)
            .expect("expand_requested_references returned unknown reference");
        if !plan.regeneration_supported {
            return Err(format!(
                "Reference '{name}' does not support in-repo regeneration. {}",
                plan.note
            )
            .into());
        }

        println!("Regenerating fixtures for '{name}'...");
        let result = plan.reference.generate_fixtures(dry_run)?;
        if !result.success {
            return Err(format!(
                "Fixture regeneration failed for '{name}'. Command: {}\n{}",
                result.command, result.output
            )
            .into());
        }

        if dry_run {
            println!("  dry_run_command={}", result.command);
        } else {
            println!(
                "  generated_files={} duration_ms={}",
                result.files_generated.len(),
                result.duration.as_millis()
            );
        }
        if verbose && !result.output.trim().is_empty() {
            println!("  output:\n{}", result.output.trim());
        }
    }

    Ok(())
}

fn validate_references(
    references: &BTreeMap<String, ReferencePlan>,
    requested: Option<&str>,
    dry_run: bool,
    verbose: bool,
) -> Result<(), DynError> {
    let reference_names = match requested {
        Some(name) => expand_requested_references(references, name, false)?,
        None => references
            .iter()
            .filter_map(|(name, plan)| plan.validation_supported.then_some(name.clone()))
            .collect::<Vec<_>>(),
    };

    if reference_names.is_empty() {
        return Err("No references have a configured validation workflow".into());
    }

    for name in reference_names {
        let plan = references
            .get(&name)
            .expect("validate_references received unknown reference");
        let Some(validation_command) = &plan.reference.validation_command else {
            return Err(format!(
                "Reference '{name}' does not support validation. {}",
                plan.note
            )
            .into());
        };

        println!("Validating fixtures for '{name}'...");
        if dry_run {
            println!("  dry_run_command={validation_command}");
            continue;
        }

        let result = plan.reference.validate_fixtures()?;
        if !result.success {
            return Err(format!(
                "Fixture validation failed for '{name}'. Command: {}\n{}",
                result.command, result.output
            )
            .into());
        }

        println!("  validation=ok");
        if verbose && !result.output.trim().is_empty() {
            println!("  output:\n{}", result.output.trim());
        }
    }

    Ok(())
}

fn expand_requested_references(
    references: &BTreeMap<String, ReferencePlan>,
    requested: &str,
    regeneration_only: bool,
) -> Result<Vec<String>, DynError> {
    if requested == "all" {
        let names = references
            .iter()
            .filter_map(|(name, plan)| {
                if regeneration_only {
                    plan.regeneration_supported.then_some(name.clone())
                } else {
                    Some(name.clone())
                }
            })
            .collect::<Vec<_>>();
        if names.is_empty() {
            return Err("No matching references were configured".into());
        }
        return Ok(names);
    }

    if references.contains_key(requested) {
        Ok(vec![requested.to_string()])
    } else {
        Err(format!(
            "Unknown reference '{requested}'. Available references: {}",
            references.keys().cloned().collect::<Vec<_>>().join(", ")
        )
        .into())
    }
}

fn fixture_file_count(path: &Path) -> Result<usize, DynError> {
    if !path.exists() {
        return Ok(0);
    }
    Ok(fs::read_dir(path)?
        .filter_map(Result::ok)
        .filter(|entry| entry.path().is_file())
        .count())
}

fn newest_fixture_age_days(path: &Path) -> Result<u64, DynError> {
    if !path.exists() {
        return Ok(u64::MAX);
    }

    let mut newest = std::time::SystemTime::UNIX_EPOCH;
    let mut saw_file = false;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let metadata = entry.metadata()?;
        if !metadata.is_file() {
            continue;
        }
        saw_file = true;
        if let Ok(modified) = metadata.modified() {
            if modified > newest {
                newest = modified;
            }
        }
    }

    if !saw_file {
        return Ok(u64::MAX);
    }

    Ok(std::time::SystemTime::now()
        .duration_since(newest)?
        .as_secs()
        / 86_400)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn default_catalog_uses_real_golden_commands() {
        let catalog = default_reference_catalog();
        let golden = catalog.get("golden").expect("golden reference");

        assert!(golden.regeneration_supported);
        assert!(golden.validation_supported);
        assert!(
            golden
                .reference
                .generation_command
                .contains("generate_goldens")
        );
        assert!(
            golden
                .reference
                .validation_command
                .as_deref()
                .unwrap_or_default()
                .contains("validate_round_trips")
        );
    }

    #[test]
    fn default_catalog_marks_differential_manual_only() {
        let catalog = default_reference_catalog();
        let differential = catalog.get("differential").expect("differential reference");

        assert!(!differential.regeneration_supported);
        assert!(differential.validation_supported);
        assert!(differential.note.contains("provenance-only"));
    }

    #[test]
    fn config_override_adds_custom_reference() {
        let temp = TempDir::new().expect("tempdir");
        let config_path = temp.path().join("maintenance_config.json");
        fs::write(
            &config_path,
            r#"{
  "references": [
    {
      "name": "custom",
      "fixture_directory": "fixtures/custom",
      "generation_command": "printf custom",
      "validation_command": "test -f PROVENANCE.md",
      "note": "custom override"
    }
  ]
}"#,
        )
        .expect("write config");

        let catalog = build_reference_catalog(&config_path).expect("catalog");
        let custom = catalog.get("custom").expect("custom ref");

        assert!(
            custom
                .reference
                .fixture_directory
                .ends_with("fixtures/custom")
        );
        assert!(custom.regeneration_supported);
        assert_eq!(custom.note, "custom override");
    }
}
