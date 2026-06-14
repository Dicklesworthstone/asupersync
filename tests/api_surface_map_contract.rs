use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const ARTIFACT: &str = "artifacts/api_surface_map_v1.json";
const SOURCE: &str = "src/lib.rs";
const README: &str = "README.md";
const AGENTS: &str = "AGENTS.md";

fn repo_path(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn read(path: &str) -> String {
    fs::read_to_string(repo_path(path)).unwrap_or_else(|err| panic!("failed to read {path}: {err}"))
}

fn root_export_names_from_source(source: &str) -> BTreeSet<String> {
    let lines: Vec<&str> = source.lines().collect();
    let mut names = BTreeSet::new();
    let mut index = 0;
    let mut brace_depth = 0_i32;

    while index < lines.len() {
        if brace_depth > 0 {
            brace_depth += brace_delta(lines[index]);
            index += 1;
            continue;
        }

        let trimmed = lines[index].trim();
        if let Some(rest) = trimmed.strip_prefix("pub mod ") {
            let name = rest
                .trim_end_matches(';')
                .trim_end_matches('{')
                .trim()
                .to_string();
            names.insert(name);
            brace_depth += brace_delta(trimmed);
        } else if let Some(rest) = trimmed.strip_prefix("pub use ") {
            let mut use_lines = vec![rest.trim().to_string()];
            while !use_lines
                .last()
                .expect("use_lines is nonempty")
                .contains(';')
                && index + 1 < lines.len()
            {
                index += 1;
                use_lines.push(lines[index].trim().to_string());
            }
            for export in expand_pub_use(&use_lines.join(" ")) {
                names.insert(export);
            }
        } else {
            brace_depth += brace_delta(trimmed);
        }
        index += 1;
    }

    names
}

fn brace_delta(line: &str) -> i32 {
    let opens = line.matches('{').count();
    let closes = line.matches('}').count();

    if opens >= closes {
        i32::try_from(opens - closes).expect("brace delta must fit in i32")
    } else {
        -i32::try_from(closes - opens).expect("brace delta must fit in i32")
    }
}

fn expand_pub_use(raw: &str) -> Vec<String> {
    let cleaned = raw.trim().trim_end_matches(';').trim();
    if let Some((prefix, rest)) = cleaned.split_once("::{") {
        let names = rest.rsplit_once('}').map_or(rest, |(names, _)| names);
        return names
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(|name| format!("{prefix}::{name}"))
            .collect();
    }
    vec![cleaned.to_string()]
}

fn root_export_names_from_artifact(artifact: &Value) -> BTreeSet<String> {
    artifact["root_exports"]
        .as_array()
        .expect("root_exports must be an array")
        .iter()
        .map(|entry| {
            entry["name"]
                .as_str()
                .expect("root export name must be a string")
                .to_string()
        })
        .collect()
}

#[test]
fn api_surface_map_schema_and_size_are_stable() {
    let raw = read(ARTIFACT);
    assert!(
        raw.len() < 300 * 1024,
        "api surface map must stay under 300KB; got {} bytes",
        raw.len()
    );

    let artifact: Value = serde_json::from_str(&raw).expect("artifact must be valid JSON");
    assert_eq!(artifact["schema_version"], "api-surface-map-v1");
    assert_eq!(
        artifact["generated_by"],
        "scripts/generate_api_surface_map.py"
    );
    assert!(
        artifact["generation"]["command"]
            .as_str()
            .expect("generation command must be present")
            .contains("rch exec --"),
        "documented generator command must be RCH-wrapped"
    );
}

#[test]
fn api_surface_map_tracks_root_public_exports() {
    let source = read(SOURCE);
    let raw = read(ARTIFACT);
    let artifact: Value = serde_json::from_str(&raw).expect("artifact must be valid JSON");

    let from_source = root_export_names_from_source(&source);
    let from_artifact = root_export_names_from_artifact(&artifact);
    assert_eq!(
        from_source, from_artifact,
        "root public export drift requires regenerating {ARTIFACT}"
    );

    for entry in artifact["root_exports"]
        .as_array()
        .expect("root_exports must be an array")
    {
        assert!(
            entry["line"].as_u64().is_some(),
            "entry missing line: {entry}"
        );
        assert!(
            matches!(entry["kind"].as_str(), Some("module" | "reexport")),
            "entry has invalid kind: {entry}"
        );
        assert!(
            matches!(
                entry["stability"].as_str(),
                Some("core" | "preview" | "native-only" | "feature-gated" | "test-internals")
            ),
            "entry has invalid stability class: {entry}"
        );
    }
}

#[test]
fn api_surface_entry_points_are_actionable() {
    let raw = read(ARTIFACT);
    let artifact: Value = serde_json::from_str(&raw).expect("artifact must be valid JSON");
    let entry_points = artifact["entry_points"]
        .as_array()
        .expect("entry_points must be an array");
    assert!(
        entry_points.len() >= 10,
        "entry_points must cover at least 10 use cases"
    );

    let mut seen = BTreeSet::new();
    for entry in entry_points {
        let use_case = entry["use_case"]
            .as_str()
            .expect("entry point use_case must be a string");
        assert!(seen.insert(use_case), "duplicate use_case {use_case}");
        assert!(
            !entry["symbol"].as_str().unwrap_or_default().is_empty(),
            "entry point symbol missing for {use_case}"
        );
        let example_path = entry["example"]["path"]
            .as_str()
            .expect("entry point example path must be present");
        assert!(
            repo_path(example_path).exists(),
            "entry point {use_case} points at missing example {example_path}"
        );
        assert_eq!(
            entry["example"]["exists"], true,
            "entry point {use_case} must record existing example"
        );
    }

    let route_entry = entry_points
        .iter()
        .find(|entry| entry["use_case"] == "web_router_routes")
        .expect("web router route introspection must be a curated entry point");
    assert_eq!(
        route_entry["symbol"],
        "web::Router::routes + web::RouteInfo"
    );
    assert_eq!(
        route_entry["example"]["path"],
        "tests/web_router_dump_format.rs"
    );
}

#[test]
fn api_surface_map_is_discoverable_from_docs() {
    let readme = read(README);
    let agents = read(AGENTS);
    assert!(
        readme.contains(ARTIFACT),
        "README must link the API surface map artifact"
    );
    assert!(
        agents.contains(ARTIFACT),
        "AGENTS.md must link the API surface map artifact"
    );
}
