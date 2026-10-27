use super::*;
use crate::lab::scenario_runner::ScenarioRunner;

fn write(root: &Path, name: &str, source: &str) -> PathBuf {
    let path = root.join(name);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, source).unwrap();
    path
}

fn load(path: &Path) -> Scenario {
    Scenario::load_resolved(path, ScenarioLoadLimits::default()).unwrap()
}

#[test]
fn nested_fragments_preserve_defaults_and_explicit_local_precedence() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "first.yaml",
        "id: base\nlab: {seed: 7, worker_count: 3}\nmetadata: {base: kept, winner: first}\n",
    );
    write(
        dir.path(),
        "config/common.yml",
        "lab: {seed: 9, trace_capacity: 2048}\nmetadata: {nested: kept}\n",
    );
    write(
        dir.path(),
        "config/later.yaml",
        "include: [{path: common.yml}]\nmetadata: {winner: later}\n",
    );
    let path = write(
        dir.path(),
        "root.yaml",
        "id: composed\ninclude: [{path: first.yaml}, {path: config/later.yaml}]\nlab: {worker_count: 2}\nmetadata: {winner: local}\n",
    );

    let scenario = load(&path);
    assert_eq!(scenario.id, "composed");
    assert_eq!(scenario.lab.seed, 9);
    assert_eq!(scenario.lab.worker_count, 2);
    assert_eq!(scenario.lab.trace_capacity, 2048);
    assert_eq!(scenario.lab.max_steps, Some(100_000));
    assert_eq!(scenario.metadata["base"], "kept");
    assert_eq!(scenario.metadata["nested"], "kept");
    assert_eq!(scenario.metadata["winner"], "local");
    assert!(scenario.include.is_empty());
    assert!(scenario.validate().is_empty());
}

#[test]
fn participant_fault_and_oracle_lists_replace_without_concatenation() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "base.yaml",
        "participants: [{name: inherited, role: sender}]\nfaults: [{at_ms: 1, action: disk_pressure}]\noracles: [all]\n",
    );
    let path = write(
        dir.path(),
        "root.yaml",
        "id: replacement\ninclude: [{path: base.yaml}]\nparticipants: [{name: local, role: receiver}]\nfaults: []\noracles: []\n",
    );
    let scenario = load(&path);
    assert_eq!(scenario.participants.len(), 1);
    assert_eq!(scenario.participants[0].name, "local");
    assert!(scenario.faults.is_empty());
    assert!(scenario.oracles.is_empty());

    let path = write(
        dir.path(),
        "empty.yaml",
        "id: cleared\ninclude: [{path: base.yaml}]\nparticipants: []\n",
    );
    assert!(load(&path).participants.is_empty());
}

#[test]
fn explicit_null_clears_options_and_never_restores_an_inherited_value() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "base.yaml",
        "lab: {max_steps: 800}\ncancellation: {strategy: all_points}\n",
    );
    let path = write(
        dir.path(),
        "root.yaml",
        "id: null-options\ninclude: [{path: base.yaml}]\nlab: {max_steps: null}\ncancellation: null\n",
    );
    let scenario = load(&path);
    assert_eq!(scenario.lab.max_steps, None);
    assert_eq!(scenario.cancellation, None);

    let invalid = write(
        dir.path(),
        "invalid.yaml",
        "id: invalid-null\ninclude: [{path: base.yaml}]\nlab: null\n",
    );
    assert!(matches!(
        Scenario::load_resolved(invalid, ScenarioLoadLimits::default()),
        Err(ScenarioLoadError::Parse { .. })
    ));
}

#[test]
fn identity_must_be_declared_by_the_root() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "base.yaml", "id: inherited-identity\n");
    let missing = write(dir.path(), "missing.yaml", "include: [{path: base.yaml}]\n");
    let error = Scenario::load_resolved(missing, ScenarioLoadLimits::default()).unwrap_err();
    assert!(error.to_string().contains("declare its own id"));
    let valid = write(
        dir.path(),
        "valid.yaml",
        "id: root-identity\ninclude: [{path: base.yaml}]\n",
    );
    assert_eq!(load(&valid).id, "root-identity");
}

#[test]
fn unsupported_version_in_a_base_cannot_be_hidden_by_a_local_version() {
    let dir = tempfile::tempdir().unwrap();
    let base = write(dir.path(), "future.yaml", "schema_version: 2\n");
    let path = write(
        dir.path(),
        "root.yaml",
        "id: wrong-version\nschema_version: 1\ninclude: [{path: future.yaml}]\n",
    );
    let error = Scenario::load_resolved(path, ScenarioLoadLimits::default()).unwrap_err();
    match error {
        ScenarioLoadError::Invalid { path, message } => {
            assert_eq!(path, fs::canonicalize(base).unwrap());
            assert!(message.contains("unsupported schema_version 2"));
        }
        other => panic!("expected an included version error, got {other}"),
    }
}

#[test]
fn repeated_diamond_includes_keep_declaration_order_and_count_occurrences() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "common.yaml", "lab: {seed: 7}\n");
    write(
        dir.path(),
        "left.yaml",
        "include: [{path: common.yaml}]\nlab: {seed: 11}\n",
    );
    write(dir.path(), "right.yaml", "include: [{path: common.yaml}]\n");
    let path = write(
        dir.path(),
        "root.yaml",
        "id: diamond\ninclude: [{path: left.yaml}, {path: right.yaml}]\n",
    );
    let mut limits = ScenarioLoadLimits {
        max_files: 5,
        ..ScenarioLoadLimits::default()
    };
    assert_eq!(Scenario::load_resolved(&path, limits).unwrap().lab.seed, 7);
    limits.max_files = 4;
    assert!(matches!(
        Scenario::load_resolved(path, limits),
        Err(ScenarioLoadError::LimitExceeded {
            limit: "max_files",
            maximum: 4,
            ..
        })
    ));
}

#[test]
fn cycle_error_contains_the_canonical_include_chain() {
    let dir = tempfile::tempdir().unwrap();
    let root = write(
        dir.path(),
        "root.yaml",
        "id: cycle\ninclude: [{path: second.yaml}]\n",
    );
    let second = write(dir.path(), "second.yaml", "include: [{path: root.yaml}]\n");
    let error = Scenario::load_resolved(&root, ScenarioLoadLimits::default()).unwrap_err();
    let ScenarioLoadError::IncludeCycle { chain } = error else {
        panic!("expected cycle error: {error}");
    };
    let root = fs::canonicalize(root).unwrap();
    assert_eq!(
        chain,
        [root.clone(), fs::canonicalize(second).unwrap(), root]
    );
}

#[cfg(unix)]
#[test]
fn symlink_escape_and_alias_cycle_are_rejected_by_canonical_identity() {
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let external = write(outside.path(), "base.yaml", "lab: {seed: 88}\n");
    std::os::unix::fs::symlink(external, dir.path().join("escape.yaml")).unwrap();
    let root = write(
        dir.path(),
        "root.yaml",
        "id: escape\ninclude: [{path: escape.yaml}]\n",
    );
    assert!(matches!(
        Scenario::load_resolved(&root, ScenarioLoadLimits::default()),
        Err(ScenarioLoadError::OutsideRoot { .. })
    ));

    std::os::unix::fs::symlink(&root, dir.path().join("alias.yaml")).unwrap();
    write(
        dir.path(),
        "root.yaml",
        "id: alias-cycle\ninclude: [{path: alias.yaml}]\n",
    );
    assert!(matches!(
        Scenario::load_resolved(root, ScenarioLoadLimits::default()),
        Err(ScenarioLoadError::IncludeCycle { .. })
    ));
}

#[test]
fn include_depth_and_zero_file_limit_fail_before_loading_children() {
    let dir = tempfile::tempdir().unwrap();
    let path = write(dir.path(), "root.yaml", "id: single\n");
    let mut limits = ScenarioLoadLimits {
        max_include_depth: 0,
        ..ScenarioLoadLimits::default()
    };
    assert_eq!(Scenario::load_resolved(&path, limits).unwrap().id, "single");
    write(dir.path(), "base.yaml", "lab: {seed: 7}\n");
    write(
        dir.path(),
        "root.yaml",
        "id: nested\ninclude: [{path: base.yaml}]\n",
    );
    assert!(matches!(
        Scenario::load_resolved(&path, limits),
        Err(ScenarioLoadError::LimitExceeded {
            limit: "max_include_depth",
            maximum: 0,
            ..
        })
    ));
    limits.max_files = 0;
    assert!(matches!(
        Scenario::load_resolved(path, limits),
        Err(ScenarioLoadError::LimitExceeded {
            limit: "max_files",
            maximum: 0,
            ..
        })
    ));
}

#[test]
fn byte_limits_accept_exact_boundaries_and_charge_repeated_documents() {
    let dir = tempfile::tempdir().unwrap();
    let base = "lab: {seed: 7}\n";
    let root = "id: bytes\ninclude: [{path: base.yaml}, {path: base.yaml}]\n";
    write(dir.path(), "base.yaml", base);
    let path = write(dir.path(), "root.yaml", root);
    let mut limits = ScenarioLoadLimits {
        max_file_bytes: root.len(),
        max_total_bytes: root.len() + 2 * base.len(),
        ..ScenarioLoadLimits::default()
    };
    assert_eq!(Scenario::load_resolved(&path, limits).unwrap().lab.seed, 7);
    limits.max_total_bytes -= 1;
    assert!(matches!(
        Scenario::load_resolved(&path, limits),
        Err(ScenarioLoadError::LimitExceeded {
            limit: "max_total_bytes",
            ..
        })
    ));
    limits.max_total_bytes += 1;
    limits.max_file_bytes -= 1;
    assert!(matches!(
        Scenario::load_resolved(path, limits),
        Err(ScenarioLoadError::LimitExceeded {
            limit: "max_file_bytes",
            ..
        })
    ));
}

#[test]
fn lexical_path_validation_precedes_file_access() {
    let dir = tempfile::tempdir().unwrap();
    for include in [
        "../escape.yaml",
        "/absolute.yaml",
        "wrong.json",
        "",
        "bad\\path.yaml",
    ] {
        let raw = serde_yaml::to_string(&Scenario {
            id: "invalid-path".into(),
            include: vec![IncludeRef {
                path: include.into(),
            }],
            ..Scenario::default()
        })
        .unwrap();
        let path = write(dir.path(), "root.yaml", &raw);
        let error = Scenario::load_resolved(path, ScenarioLoadLimits::default()).unwrap_err();
        assert!(
            matches!(error, ScenarioLoadError::Invalid { .. }),
            "{error}"
        );
        assert!(error.to_string().contains("include[0].path"));
    }
}

#[test]
fn missing_malformed_and_non_regular_sources_fail_with_their_path() {
    let dir = tempfile::tempdir().unwrap();
    let root = write(
        dir.path(),
        "root.yaml",
        "id: source-errors\ninclude: [{path: child.yaml}]\n",
    );
    assert!(matches!(
        Scenario::load_resolved(&root, ScenarioLoadLimits::default()),
        Err(ScenarioLoadError::Io { path, .. }) if path.ends_with("child.yaml")
    ));
    write(dir.path(), "child.yaml", "lab: [unterminated\n");
    assert!(matches!(
        Scenario::load_resolved(&root, ScenarioLoadLimits::default()),
        Err(ScenarioLoadError::Parse { path, .. }) if path.ends_with("child.yaml")
    ));
    fs::create_dir(dir.path().join("directory.yaml")).unwrap();
    write(
        dir.path(),
        "root.yaml",
        "id: source-errors\ninclude: [{path: directory.yaml}]\n",
    );
    let error = Scenario::load_resolved(root, ScenarioLoadLimits::default()).unwrap_err();
    assert!(error.to_string().contains("regular file"));
}

#[test]
fn raw_deserialization_remains_independent_of_include_files() {
    let raw = "id: raw\ninclude: [{path: missing.yaml}]\n";
    let parsed: Scenario = serde_yaml::from_str(raw).unwrap();
    assert_eq!(parsed.include[0].path, "missing.yaml");
    assert!(parsed.validate().is_empty());
    let dir = tempfile::tempdir().unwrap();
    let path = write(dir.path(), "root.yaml", raw);
    assert!(Scenario::load_resolved(path, ScenarioLoadLimits::default()).is_err());
}

#[test]
fn resolved_string_fields_require_quotes_without_changing_legacy_coercions() {
    let raw = "id: string-types\nmetadata: {revision: 123}\n";
    let legacy: Scenario = serde_yaml::from_str(raw).unwrap();
    assert_eq!(legacy.metadata["revision"], "123");
    let dir = tempfile::tempdir().unwrap();
    let path = write(dir.path(), "root.yaml", raw);
    let error = Scenario::load_resolved(&path, ScenarioLoadLimits::default()).unwrap_err();
    let message = error.to_string();
    assert!(message.contains("root.yaml"), "{message}");
    assert!(message.contains("123"), "{message}");
    assert!(message.contains("quote"), "{message}");

    write(
        dir.path(),
        "root.yaml",
        "id: string-types\nmetadata: {revision: \"123\"}\n",
    );
    assert_eq!(load(&path), legacy);
}

#[test]
fn yaml_aliases_and_string_tags_work_without_activating_merge_keys() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "base.yaml",
        "description: &description inherited\nmetadata: {alias: *description}\n",
    );
    let path = write(
        dir.path(),
        "root.yaml",
        "id: !scenario tagged\ninclude: [{path: base.yaml}]\nbase: &base {seed: 11}\nlab: {<<: *base}\n",
    );
    let scenario = load(&path);
    assert_eq!(scenario.id, "tagged");
    assert_eq!(scenario.description, "inherited");
    assert_eq!(scenario.metadata["alias"], "inherited");
    assert_eq!(scenario.lab.seed, 42);
}

#[test]
fn resolved_workload_replays_and_serializes_as_a_standalone_scenario() {
    let dir = tempfile::tempdir().unwrap();
    let base = write(
        dir.path(),
        "workload.yaml",
        "lab: {seed: 17, worker_count: 2}\nparticipants:\n  - {name: producer, role: sender, properties: {messages: 4}}\n  - {name: consumer, role: receiver, properties: {capacity: 1}}\n",
    );
    let path = write(
        dir.path(),
        "root.yaml",
        "id: composed-workload\ninclude: [{path: workload.yaml}]\n",
    );
    let scenario = load(&path);
    let result = ScenarioRunner::run(&scenario).unwrap();
    assert!(
        result.passed(),
        "{:?}",
        result.lab_report.invariant_violations
    );
    assert!(result.lab_report.steps_total > 0);
    assert_eq!(
        ScenarioRunner::participant_bindings(&scenario).bound.len(),
        2
    );
    let replay = ScenarioRunner::validate_replay(&scenario).unwrap();
    assert_eq!(result.certificate, replay.certificate);

    // After resolution, source changes cannot affect execution or saved output.
    fs::write(base, "not: [valid yaml\n").unwrap();
    let reparsed = Scenario::from_json(&scenario.to_json().unwrap()).unwrap();
    assert_eq!(reparsed, scenario);
    assert!(reparsed.include.is_empty());
    assert_eq!(
        ScenarioRunner::run(&reparsed).unwrap().certificate,
        result.certificate
    );
}
