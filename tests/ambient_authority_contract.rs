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
