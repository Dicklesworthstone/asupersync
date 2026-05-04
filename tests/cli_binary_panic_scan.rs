//! Structural regression test for production `asupersync` CLI panics.
//!
//! This intentionally scans the feature-gated binary source without enabling
//! the `cli` feature so the invariant stays covered even when the binary's
//! feature graph has a separate compile blocker.

fn production_source(source: &str) -> &str {
    source
        .split("#[cfg(test)]")
        .next()
        .expect("CLI binary source should contain production section")
}

#[test]
fn cli_binary_production_code_has_no_panic_macros() {
    let production = production_source(include_str!("../src/bin/asupersync.rs"));
    let panics: Vec<_> = production
        .lines()
        .enumerate()
        .filter_map(|(idx, line)| line.contains("panic!(").then_some((idx + 1, line.trim())))
        .collect();

    assert!(
        panics.is_empty(),
        "production CLI code must return structured CliError/results instead of panic!: {panics:?}"
    );
}
