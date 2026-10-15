use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const METADATA_PATH: &str = "examples/metadata.json";
const SCHEMA_VERSION: &str = "asupersync.examples.metadata.v1";
const BEAD_ID: &str = "asupersync-agent-native-dx-zxqaqs.4";
const SCENARIO_REGISTRY_BEAD_ID: &str = "asupersync-5z2scg.5.4";
const SCENARIO_ROOTS: &[&str] = &["examples/scenarios", "frankenlab/examples/scenarios"];
const MIN_FAILURE_DOCTESTS: usize = 5;
const CORE_API_SYMBOLS: &[&str] = &[
    "asupersync::Budget::meet",
    "asupersync::Cx",
    "asupersync::LabConfig",
    "asupersync::LabRuntime",
    "asupersync::Outcome::map",
    "asupersync::Scope",
    "asupersync::channel::broadcast",
    "asupersync::channel::mpsc",
    "asupersync::channel::oneshot",
    "asupersync::channel::watch",
    "asupersync::combinator::JoinSet",
    "asupersync::combinator::join2_outcomes",
    "asupersync::combinator::race2_outcomes",
    "asupersync::runtime::Runtime",
    "asupersync::runtime::RuntimeBuilder",
    "asupersync::runtime::TaskHandle",
    "asupersync::stream::StreamExt",
    "asupersync::supervision::SupervisionStrategy",
    "asupersync::sync::Mutex",
    "asupersync::sync::RwLock",
    "asupersync::sync::Semaphore",
    "asupersync::time::interval",
    "asupersync::time::sleep",
    "asupersync::time::timeout",
];

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

fn metadata() -> Value {
    serde_json::from_str(&read_repo_file(METADATA_PATH))
        .unwrap_or_else(|error| panic!("parse {METADATA_PATH}: {error}"))
}

fn object<'a>(value: &'a Value, key: &str) -> &'a serde_json::Map<String, Value> {
    value
        .get(key)
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("{key} must be an object"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    let text = value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"));
    assert!(!text.trim().is_empty(), "{key} must be nonempty");
    text
}

fn has_extension(path: &str, extension: &str) -> bool {
    Path::new(path)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case(extension))
}

fn bool_field(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("{key} must be a bool"))
}

fn usize_field(value: &Value, key: &str) -> usize {
    value
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("{key} must be a positive integer")) as usize
}

fn relative_slash_path(repo_root: &Path, path: &Path) -> String {
    path.strip_prefix(repo_root)
        .unwrap_or_else(|error| panic!("strip repo prefix from {path:?}: {error}"))
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn collect_example_files(repo_root: &Path, dir: &Path, files: &mut BTreeSet<String>) {
    let mut entries = fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("read dir {dir:?}: {error}"))
        .map(|entry| entry.expect("directory entry must be readable").path())
        .collect::<Vec<_>>();
    entries.sort();

    for path in entries {
        if path.is_dir() {
            collect_example_files(repo_root, &path, files);
            continue;
        }

        let relative = relative_slash_path(repo_root, &path);
        if relative != METADATA_PATH {
            files.insert(relative);
        }
    }
}

fn current_example_files() -> BTreeSet<String> {
    let repo_root = repo_path("");
    let mut files = BTreeSet::new();
    collect_example_files(&repo_root, &repo_path("examples"), &mut files);
    collect_example_files(
        &repo_root,
        &repo_path("frankenlab/examples/scenarios"),
        &mut files,
    );
    files
}

fn metadata_entries_by_file(metadata: &Value) -> BTreeMap<String, &Value> {
    let mut entries_by_file = BTreeMap::new();
    for entry in array(metadata, "examples") {
        let file = string(entry, "file").to_string();
        assert!(
            entries_by_file.insert(file.clone(), entry).is_none(),
            "duplicate metadata entry for {file}"
        );
    }
    entries_by_file
}

fn nonempty_string_set(value: &Value, key: &str) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    for entry in array(value, key) {
        let text = entry
            .as_str()
            .unwrap_or_else(|| panic!("{key} entries must be strings"));
        assert!(!text.trim().is_empty(), "{key} entries must be nonempty");
        assert!(set.insert(text.to_string()), "duplicate {key} entry {text}");
    }
    set
}

fn line_count(relative: &str) -> usize {
    read_repo_file(relative).lines().count()
}

fn file_stem(relative: &str) -> String {
    Path::new(relative)
        .file_stem()
        .unwrap_or_else(|| panic!("{relative} must have a file stem"))
        .to_string_lossy()
        .into_owned()
}

fn runnable_doctest_body<'a>(source: &'a str, marker: &str) -> &'a str {
    let marker_line = format!("//! <!-- {marker} -->");
    assert_eq!(
        source.matches(&marker_line).count(),
        1,
        "doctest marker must occur exactly once: {marker}"
    );
    let marker_end = source
        .find(&marker_line)
        .unwrap_or_else(|| panic!("missing doctest marker {marker}"))
        + marker_line.len();
    let after_marker = &source[marker_end..];
    const OPEN_FENCE: &str = "\n//! ```\n";
    assert!(
        after_marker.starts_with(OPEN_FENCE),
        "{marker} must be followed immediately by a runnable Rust fence"
    );
    let body = &after_marker[OPEN_FENCE.len()..];
    let close = body
        .find("\n//! ```")
        .unwrap_or_else(|| panic!("doctest marker {marker} has no closing fence"));
    let body = &body[..close];
    assert!(
        body.contains("Cx"),
        "{marker} must show where its capability context comes from"
    );
    body
}

#[test]
fn metadata_declares_schema_scope_and_owner() {
    let metadata = metadata();
    assert_eq!(metadata["schema_version"].as_str(), Some(SCHEMA_VERSION));
    assert_eq!(metadata["bead_id"].as_str(), Some(BEAD_ID));
    assert_eq!(metadata["generated_by"].as_str(), Some("SnowyFortress"));

    let scope = Value::Object(object(&metadata, "scope").clone());
    assert!(bool_field(&scope, "metadata_only"));
    assert!(!bool_field(&scope, "executes_examples"));

    let registry = metadata
        .get("scenario_registry")
        .unwrap_or_else(|| panic!("scenario_registry must be present"));
    assert_eq!(string(registry, "owner_bead"), SCENARIO_REGISTRY_BEAD_ID);
    assert_eq!(
        nonempty_string_set(registry, "roots"),
        SCENARIO_ROOTS
            .iter()
            .map(|root| (*root).to_string())
            .collect()
    );
    assert_eq!(string(registry, "source_state"), "SOURCE_ALIGNED_STATIC");
    assert_eq!(
        string(registry, "execution_state"),
        "NOT_RUN_BY_STATIC_LANE"
    );
    assert!(string(registry, "no_claim").contains("does not prove"));
}

#[test]
fn core_api_doctest_checklist_is_complete_and_runnable() {
    let metadata = metadata();
    let coverage = metadata
        .get("rustdoc_coverage")
        .unwrap_or_else(|| panic!("rustdoc_coverage must be present"));
    let mut symbols = BTreeSet::new();
    let mut failure_doctests = BTreeSet::new();

    for entry in array(coverage, "core_api") {
        let symbol = string(entry, "symbol");
        assert!(symbols.insert(symbol), "duplicate core API symbol {symbol}");

        let source_path = string(entry, "source");
        assert!(
            source_path.starts_with("src/") && has_extension(source_path, "rs"),
            "core API doctest source must be a Rust source file: {source_path}"
        );
        let source = read_repo_file(source_path);
        let marker = string(entry, "marker");
        let body = runnable_doctest_body(&source, marker);
        assert!(
            body.contains("assert"),
            "{marker} must assert its documented behavior"
        );

        if bool_field(entry, "failure_handling") {
            failure_doctests.insert((source_path.to_string(), marker.to_string()));
        }
    }

    assert_eq!(
        symbols,
        CORE_API_SYMBOLS.iter().copied().collect(),
        "the committed checklist must cover the complete core API set"
    );
    assert!(
        failure_doctests.len() >= MIN_FAILURE_DOCTESTS,
        "expected at least {MIN_FAILURE_DOCTESTS} distinct failure-handling doctests, found {}",
        failure_doctests.len()
    );
}

#[test]
fn unavailable_missing_doc_code_examples_lint_has_report_only_fallbacks() {
    let metadata = metadata();
    let coverage = metadata
        .get("rustdoc_coverage")
        .unwrap_or_else(|| panic!("rustdoc_coverage must be present"));
    let report = coverage
        .get("missing_doc_code_examples")
        .unwrap_or_else(|| panic!("missing_doc_code_examples report must be present"));

    assert_eq!(string(report, "lint"), "missing_doc_code_examples");
    assert_eq!(
        string(report, "availability"),
        "unavailable-on-pinned-toolchain"
    );
    assert_eq!(string(report, "policy"), "report-only");
    assert_eq!(string(report, "checked_command"), "rustc -W help");
    assert_eq!(
        nonempty_string_set(report, "observed_related_lints"),
        BTreeSet::from(["missing-docs".to_string()])
    );
    assert_eq!(
        nonempty_string_set(report, "replacement_gates"),
        BTreeSet::from([
            "cargo doc -p asupersync --no-deps".to_string(),
            "cargo test -p asupersync --doc".to_string(),
        ])
    );
}

#[test]
fn metadata_covers_every_file_in_the_declared_example_roots() {
    let metadata = metadata();
    let declared = metadata_entries_by_file(&metadata)
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let actual = current_example_files();
    assert_eq!(
        declared, actual,
        "examples/metadata.json must cover every file in the declared example roots"
    );
}

#[test]
fn scenario_registry_covers_the_exact_thirteen_typed_fixtures() {
    let metadata = metadata();
    let scenario_files = array(&metadata, "examples")
        .iter()
        .filter(|entry| entry.get("kind").and_then(Value::as_str) == Some("scenario-yaml"))
        .map(|entry| string(entry, "file").to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(scenario_files.len(), 13);

    let frankenlab_files = scenario_files
        .iter()
        .filter(|file| file.starts_with("frankenlab/examples/scenarios/"))
        .cloned()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        frankenlab_files,
        BTreeSet::from([
            "frankenlab/examples/scenarios/01_race_condition.yaml".to_string(),
            "frankenlab/examples/scenarios/02_obligation_leak.yaml".to_string(),
            "frankenlab/examples/scenarios/03_saga_partition.yaml".to_string(),
        ])
    );
}

#[test]
fn entries_have_unique_names_live_paths_and_line_spans() {
    let metadata = metadata();
    let mut names = BTreeSet::new();

    for entry in array(&metadata, "examples") {
        let name = string(entry, "name");
        assert!(
            name.bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'),
            "name must be lower snake case: {name}"
        );
        assert!(names.insert(name), "duplicate example name {name}");

        let file = string(entry, "file");
        assert!(
            repo_path(file).is_file(),
            "metadata file path must point to a live file: {file}"
        );
        assert!(!string(entry, "description").is_empty());
        assert!(
            !nonempty_string_set(entry, "demonstrates").is_empty(),
            "{file} must declare at least one demonstrated concept"
        );
        nonempty_string_set(entry, "feature_flags");

        let loc = Value::Object(object(entry, "loc").clone());
        let start = usize_field(&loc, "start");
        let end = usize_field(&loc, "end");
        assert_eq!(start, 1, "{file} metadata should cover the full file");
        assert_eq!(end, line_count(file), "{file} end line is stale");
    }
}

#[test]
fn commands_kinds_and_feature_flags_are_shape_checked() {
    let metadata = metadata();

    for entry in array(&metadata, "examples") {
        let file = string(entry, "file");
        let kind = string(entry, "kind");
        let run_command = string(entry, "run_command");
        let feature_flags = nonempty_string_set(entry, "feature_flags");

        match kind {
            "rust" => {
                assert!(
                    has_extension(file, "rs"),
                    "rust entry must point to .rs: {file}"
                );
                assert!(
                    run_command.starts_with("cargo run --example "),
                    "rust entry must expose a cargo example command: {file}"
                );
                let stem = file_stem(file);
                assert!(
                    run_command.contains(&stem),
                    "run command must name example target {stem}: {run_command}"
                );
                if feature_flags.is_empty() {
                    assert!(
                        !run_command.contains("--features"),
                        "{file} declares no feature flags but command enables features"
                    );
                } else {
                    assert!(
                        run_command.contains("--features"),
                        "{file} has feature flags but command omits --features"
                    );
                    for flag in feature_flags {
                        assert!(
                            run_command.contains(&flag),
                            "{file} run command must mention feature flag {flag}"
                        );
                    }
                }
            }
            "shell" => {
                assert!(
                    has_extension(file, "sh"),
                    "shell entry must point to .sh: {file}"
                );
                assert!(
                    run_command.starts_with("manual: bash "),
                    "shell entry must name manual bash invocation: {file}"
                );
            }
            "markdown" => {
                assert!(
                    has_extension(file, "md"),
                    "markdown entry must point to .md: {file}"
                );
                assert!(
                    run_command.starts_with("manual: "),
                    "markdown entry must be marked manual: {file}"
                );
            }
            "json" => {
                assert!(
                    has_extension(file, "json"),
                    "json entry must point to .json: {file}"
                );
                assert!(
                    run_command.starts_with("manual: "),
                    "json entry must be marked manual: {file}"
                );
            }
            "scenario-yaml" => {
                assert!(
                    SCENARIO_ROOTS.iter().any(|root| {
                        file.strip_prefix(*root)
                            .is_some_and(|suffix| suffix.starts_with('/'))
                    }) && has_extension(file, "yaml"),
                    "scenario-yaml entry must point below a declared scenario root: {file}"
                );
                assert!(
                    run_command.starts_with("scenario: "),
                    "scenario entry must be marked as scenario fixture: {file}"
                );
            }
            other => panic!("unknown example kind {other} for {file}"),
        }
    }
}
