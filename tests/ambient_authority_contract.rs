//! Ambient-authority scanner contract.
//!
//! This integration wrapper runs the scanner tests from `src/audit/ambient.rs`
//! without compiling the full lib-test frontier. The lib-test target currently
//! includes broad conformance/metamorphic modules; this contract keeps the
//! production capability gate focused on the ambient-authority scanner.

#[path = "../src/audit/ambient.rs"]
mod ambient;

#[test]
fn ambient_authority_catalog_has_no_unresolved_entries() {
    assert_eq!(ambient::unresolved_count(), 0);
}

#[test]
fn ambient_authority_scanner_allows_lab_provider_carveout() {
    let source = r#"
pub fn lab_probe() {
    let _ = std::env::var("ASUPERSYNC_LAB_TRACE");
    eprintln!("lab oracle transcript");
}
"#;

    let categories =
        ambient::scan_categories_for_contract_fixture("lab/oracle/ambient_authority.rs", source);

    assert!(
        categories.is_empty(),
        "lab provider carve-out should not count as production ambient authority: {categories:?}"
    );
}

#[test]
fn ambient_authority_scanner_rejects_production_env_and_output() {
    let source = r#"
pub fn production_probe() {
    let _ = std::env::var("ASUPERSYNC_RUNTIME_FLAG");
    eprintln!("bypasses structured tracing");
}
"#;

    let categories = ambient::scan_categories_for_contract_fixture("service/runtime.rs", source);

    assert!(
        categories.contains(&ambient::AmbientCategory::Env),
        "expected production env access to be rejected, got {categories:?}"
    );
    assert!(
        categories.contains(&ambient::AmbientCategory::Output),
        "expected production output macro to be rejected, got {categories:?}"
    );
}
