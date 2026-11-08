//! Feature membership contract for the `process` module gate and the slim runtime profile, plus two smoke checks.
//!
//! `process` is the host child-process module (`asupersync::process`): a real module gate, unlike the empty
//! `runtime-core` / `native-runtime` markers. The module is built on native targets when the explicit
//! `slim-runtime-profile` is not selected, or when `process` is selected as well. So the default, desktop and
//! cross-platform groups keep it, a bare `--no-default-features` consumer keeps it for compatibility, and only a
//! deliberate slim selection without `process` omits it. It is never part of a wasm profile (the module does not
//! exist there).
//!
//! These tests read the manifest's feature table and run in every feature selection. They are not the proof of what
//! the module's presence does; the compiler is, through the downstream consumer `tests/fixtures/process-gate-consumer`.
//! Its core library compiles in all three graphs, and its binary imports `asupersync::process` unconditionally: it
//! compiles and runs (spawning and reaping one bounded host child) in the bare graph and in the slim-plus-`process`
//! graph, and must fail with E0432 on that import in the slim-only graph.

use std::collections::BTreeMap;
use std::fs;

/// Every `[features]` row of the root manifest with its members.
fn feature_table() -> BTreeMap<String, Vec<String>> {
    let manifest = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
        .expect("read Cargo.toml");
    let parsed = toml::from_str::<toml::Value>(&manifest).expect("parse Cargo.toml");
    parsed
        .get("features")
        .and_then(toml::Value::as_table)
        .expect("Cargo.toml has a [features] table")
        .iter()
        .map(|(name, row)| {
            let members = row
                .as_array()
                .unwrap_or_else(|| panic!("feature `{name}` must be an array in [features]"))
                .iter()
                .filter_map(|member| member.as_str().map(str::to_string))
                .collect();
            (name.clone(), members)
        })
        .collect()
}

/// The members of one `[features]` row of the root manifest.
fn members(feature: &str) -> Vec<String> {
    feature_table()
        .remove(feature)
        .unwrap_or_else(|| panic!("feature `{feature}` must exist in [features]"))
}

fn enables(group: &str, feature: &str) -> bool {
    members(group).iter().any(|member| member == feature)
}

#[test]
fn process_is_a_plain_gate_that_the_default_desktop_and_ci_groups_keep() {
    assert!(
        members("process").is_empty(),
        "`process` must imply nothing"
    );
    for group in ["default", "desktop-runtime-profile", "ci-cross-platform"] {
        assert!(
            enables(group, "process"),
            "`{group}` must keep `process`, so default, desktop and cross-platform builds keep the module"
        );
    }
}

#[test]
fn the_slim_profile_is_an_explicit_opt_in_that_omits_process_and_no_group_acquires_it() {
    assert!(
        !enables("slim-runtime-profile", "process"),
        "the slim profile is the one selection that omits `process` unless it is also selected"
    );
    for marker in ["runtime-core", "native-runtime"] {
        assert!(
            enables("slim-runtime-profile", marker),
            "the slim profile is still a native runtime selection: it must keep `{marker}`"
        );
    }
    // Existing selections never acquire the reduction: nothing but the slim row itself may enable it.
    for (name, row) in feature_table() {
        if name != "slim-runtime-profile" {
            assert!(
                !row.iter().any(|member| member == "slim-runtime-profile"),
                "`{name}` must not enable `slim-runtime-profile`: it is an explicit opt-in"
            );
        }
    }
}

#[test]
fn no_wasm_profile_enables_process_and_the_two_markers_stay_empty() {
    for profile in [
        "wasm-browser-dev",
        "wasm-browser-prod",
        "wasm-browser-deterministic",
        "wasm-browser-minimal",
    ] {
        assert!(
            !enables(profile, "process"),
            "`{profile}` must not enable `process`: the module does not exist on wasm32"
        );
    }
    for marker in ["runtime-core", "native-runtime"] {
        assert!(members(marker).is_empty(), "`{marker}` is still a marker");
    }
}

#[cfg(any(not(feature = "slim-runtime-profile"), feature = "process"))]
#[test]
fn the_module_resolves_wherever_the_legacy_selection_or_process_applies() {
    // Building a command spawns nothing; this only proves the path exists in this selection.
    let _command = asupersync::process::Command::new("true");
}

#[cfg(all(feature = "slim-runtime-profile", not(feature = "process")))]
#[test]
fn this_contract_builds_and_runs_in_the_slim_profile_without_the_module() {
    // That the API is really absent here is shown by the compiler consumer, not by this test.
    assert!(enables("default", "process"));
    assert!(enables("slim-runtime-profile", "runtime-core"));
}
