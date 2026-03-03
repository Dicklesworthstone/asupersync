//! Contract tests for Tokio ecosystem capability inventory baseline (2oh2u.1.1.*).

#![allow(missing_docs)]

use std::path::Path;

const INVENTORY_DOC_PATH: &str = "docs/tokio_ecosystem_capability_inventory.md";
const EVIDENCE_MAP_DOC_PATH: &str = "docs/tokio_capability_evidence_map.md";
const RISK_REGISTER_DOC_PATH: &str = "docs/tokio_capability_risk_register.md";
const CARGO_TOML_PATH: &str = "Cargo.toml";
const CARGO_TOML_PATH: &str = "Cargo.toml";
const NET_MOD_PATH: &str = "src/net/mod.rs";
const HTTP_MOD_PATH: &str = "src/http/mod.rs";
const NET_QUIC_TEST_PATH: &str = "tests/net_quic.rs";

fn load_doc(path: &str) -> String {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let path = Path::new(&manifest_dir).join(path);
    std::fs::read_to_string(path).expect("capability inventory document must exist")
}

fn load_inventory_doc() -> String {
    load_doc(INVENTORY_DOC_PATH)
}

fn load_evidence_map_doc() -> String {
    load_doc(EVIDENCE_MAP_DOC_PATH)
}

fn load_risk_register_doc() -> String {
    load_doc(RISK_REGISTER_DOC_PATH)
}

fn load_cargo_toml() -> String {
    load_doc(CARGO_TOML_PATH)
}

fn load_cargo_toml() -> String {
    load_doc(CARGO_TOML_PATH)
}

fn load_net_mod() -> String {
    load_doc(NET_MOD_PATH)
}

fn load_http_mod() -> String {
    load_doc(HTTP_MOD_PATH)
}

fn load_net_quic_test() -> String {
    load_doc(NET_QUIC_TEST_PATH)
}

#[test]
fn inventory_doc_exists_and_is_substantial() {
    let doc = load_inventory_doc();
    assert!(
        doc.len() > 20_000,
        "inventory doc should be substantial, got {} bytes",
        doc.len()
    );
}

#[test]
fn inventory_doc_references_t1_1_a_bead() {
    let doc = load_inventory_doc();
    assert!(
        doc.contains("asupersync-2oh2u.1.1.1"),
        "must reference bead 2oh2u.1.1.1"
    );
    assert!(doc.contains("[T1.1.a]"), "must reference T1.1.a");
}

#[test]
fn inventory_doc_lists_all_28_capability_families() {
    let doc = load_inventory_doc();
    let family_count = doc.matches("### F").count();
    assert_eq!(
        family_count, 28,
        "expected 28 capability family sections, found {family_count}"
    );
}

#[test]
fn inventory_doc_includes_ownership_boundary_taxonomy() {
    let doc = load_inventory_doc();
    for boundary in ["`core`", "`feature-gated`", "`companion`", "`out-of-scope`"] {
        assert!(
            doc.contains(boundary),
            "missing ownership boundary category: {boundary}"
        );
    }
}

#[test]
fn inventory_doc_includes_parity_status_taxonomy() {
    let doc = load_inventory_doc();
    for parity in [
        "`complete`",
        "`active`",
        "`partial`",
        "`early`",
        "`planned`",
        "`adapter`",
    ] {
        assert!(
            doc.contains(parity),
            "missing parity status category: {parity}"
        );
    }
}

#[test]
fn inventory_doc_includes_maturity_and_determinism_taxonomy() {
    let doc = load_inventory_doc();
    for maturity in ["`mature`", "`active`", "`early`", "`parked`"] {
        assert!(
            doc.contains(maturity),
            "missing maturity category token: {maturity}"
        );
    }
    for determinism in ["`strong`", "`mixed`", "`none`"] {
        assert!(
            doc.contains(determinism),
            "missing determinism category token: {determinism}"
        );
    }
}

#[test]
fn inventory_doc_has_mapping_evidence_columns() {
    let doc = load_inventory_doc();
    for row in [
        "| Ownership |",
        "| Parity |",
        "| Maturity |",
        "| Determinism |",
    ] {
        assert!(doc.contains(row), "missing capability mapping row: {row}");
    }

    let key_files_count = doc.matches("| Key files |").count();
    assert!(
        key_files_count >= 20,
        "expected >=20 key-files evidence rows, found {key_files_count}"
    );
}

#[test]
fn inventory_doc_has_gap_register_g1_to_g13() {
    let doc = load_inventory_doc();
    for gap in 1..=13 {
        let marker = format!("| G{gap} |");
        assert!(
            doc.contains(&marker),
            "missing gap register entry: {marker}"
        );
    }
}

#[test]
fn inventory_doc_includes_asupersync_only_capabilities_section() {
    let doc = load_inventory_doc();
    assert!(
        doc.contains("## 3. Asupersync-Only Capabilities"),
        "missing Asupersync-only capabilities section"
    );
    for family in ["X01", "X08", "X16"] {
        assert!(
            doc.contains(&format!("| {family} |")),
            "missing Asupersync-only family row for {family}"
        );
    }
}

#[test]
fn inventory_doc_includes_ownership_summary_diagram() {
    let doc = load_inventory_doc();
    assert!(
        doc.contains("## 5. Ownership Boundary Summary"),
        "missing ownership summary section"
    );
    for heading in [
        "CORE (always compiled)",
        "FEATURE-GATED (opt-in)",
        "COMPANION CRATES",
        "OUT OF SCOPE",
    ] {
        assert!(
            doc.contains(heading),
            "missing ownership summary heading: {heading}"
        );
    }
}

#[test]
fn inventory_doc_has_statistics_and_expected_totals() {
    let doc = load_inventory_doc();
    assert!(
        doc.contains("## 6. Statistics"),
        "missing statistics section"
    );
    assert!(
        doc.contains("| Total capability families | 28 |"),
        "statistics must report 28 capability families"
    );
    assert!(
        doc.contains("| Critical gaps blocking replacement claim | 4"),
        "statistics must report 4 critical gaps"
    );
}

#[test]
fn evidence_map_doc_exists_and_is_substantial() {
    let doc = load_evidence_map_doc();
    assert!(
        doc.len() > 15_000,
        "evidence-map doc should be substantial, got {} bytes",
        doc.len()
    );
}

#[test]
fn evidence_map_references_t1_1_b_and_parent_inventory() {
    let doc = load_evidence_map_doc();
    assert!(
        doc.contains("asupersync-2oh2u.1.1.2"),
        "must reference bead 2oh2u.1.1.2"
    );
    assert!(
        doc.contains("docs/tokio_ecosystem_capability_inventory.md"),
        "must reference parent inventory document"
    );
}

#[test]
fn evidence_map_covers_all_28_capability_families() {
    let doc = load_evidence_map_doc();
    let family_count = doc.matches("### F").count();
    assert_eq!(
        family_count, 28,
        "expected 28 capability family sections, found {family_count}"
    );
}

#[test]
fn evidence_map_has_required_evidence_axes() {
    let doc = load_evidence_map_doc();
    for token in [
        "| Src |",
        "| Features |",
        "| Tests (inline) |",
        "| Tests (integration) |",
        "| Docs |",
        "| Test count |",
    ] {
        assert!(doc.contains(token), "missing evidence axis token: {token}");
    }
}

#[test]
fn cargo_features_expose_native_quic_http3_surfaces() {
    let cargo = load_cargo_toml();
    assert!(
        cargo.contains("quic = []"),
        "Cargo features must expose native `quic` surface"
    );
    assert!(
        cargo.contains("http3 = [\"quic\"]"),
        "Cargo features must expose native `http3` surface tied to `quic`"
    );
}

#[test]
fn cargo_features_keep_compat_wrappers_explicitly_separate() {
    let cargo = load_cargo_toml();
    assert!(
        cargo.contains("quic-compat = []"),
        "Cargo features must keep legacy QUIC wrapper behind `quic-compat`"
    );
    assert!(
        cargo.contains("http3-compat = [\"quic-compat\"]"),
        "Cargo features must keep legacy HTTP/3 wrapper behind `http3-compat`"
    );
}

#[test]
fn risk_register_doc_exists_and_is_substantial() {
    let doc = load_risk_register_doc();
    assert!(
        doc.len() > 9_000,
        "risk-register doc should be substantial, got {} bytes",
        doc.len()
    );
}

#[test]
fn risk_register_references_t1_1_c_and_parent_artifacts() {
    let doc = load_risk_register_doc();
    for token in [
        "asupersync-2oh2u.1.1.3",
        "docs/tokio_ecosystem_capability_inventory.md",
        "docs/tokio_capability_evidence_map.md",
    ] {
        assert!(doc.contains(token), "missing risk-register token: {token}");
    }
}

#[test]
fn risk_register_has_28_capability_rows() {
    let doc = load_risk_register_doc();
    let row_count = doc.lines().filter(|line| line.starts_with("| F")).count();
    assert!(
        row_count >= 28,
        "expected at least 28 capability rows, found {row_count}"
    );
}

#[test]
fn risk_register_highlights_critical_blockers() {
    let doc = load_risk_register_doc();
    for token in [
        "F15",
        "F28",
        "Critical Path Analysis",
        "Critical risk (R4)",
        "Wave 1 — Critical blockers",
    ] {
        assert!(
            doc.contains(token),
            "missing critical-blocker token: {token}"
        );
    }
}

#[test]
fn quic_http3_features_are_exposed_in_cargo() {
    let cargo = load_cargo_toml();
    assert!(
        cargo.contains("quic = []"),
        "Cargo features must expose native quic surface"
    );
    assert!(
        cargo.contains("http3 = [\"quic\"]"),
        "Cargo features must expose http3 surface on top of quic"
    );
    assert!(
        cargo.contains("quic-compat = []"),
        "Cargo features must expose explicit compat-only quic gate"
    );
    assert!(
        cargo.contains("http3-compat = [\"quic-compat\"]"),
        "Cargo features must expose explicit compat-only http3 gate"
    );
}

#[test]
fn quic_http3_public_boundary_wiring_is_explicit() {
    let net_mod = load_net_mod();
    let http_mod = load_http_mod();
    let net_quic_test = load_net_quic_test();

    assert!(
        net_mod.contains("#[cfg(feature = \"quic-compat\")]")
            && net_mod.contains("pub mod quic;"),
        "net::quic module must be compat-gated explicitly"
    );
    assert!(
        !net_mod.contains("#[cfg(feature = \"quic\")]\npub mod quic;"),
        "net::quic module must not be wired directly to native quic feature"
    );

    assert!(
        http_mod.contains("#[cfg(feature = \"http3-compat\")]")
            && http_mod.contains("pub mod h3;"),
        "http::h3 module must be compat-gated explicitly"
    );
    assert!(
        !http_mod.contains("#[cfg(feature = \"http3\")]\npub mod h3;"),
        "http::h3 module must not be wired directly to native http3 feature"
    );

    assert!(
        net_quic_test.contains("#![cfg(feature = \"quic-compat\")]"),
        "compat integration test must follow compat feature gate"
    );
}

#[test]
fn f15_docs_reflect_unparked_feature_surface_and_compat_boundary() {
    let inventory = load_inventory_doc();
    let risk = load_risk_register_doc();

    for token in [
        "feature-gated** (`quic`, `http3`)",
        "compat-only** (`quic-compat`, `http3-compat`)",
        "feature surfaces are unparked",
    ] {
        assert!(
            inventory.contains(token),
            "inventory F15 section missing token: {token}"
        );
    }

    for token in [
        "Native `quic`/`http3` feature surfaces are now exposed",
        "compat-only and off by default",
    ] {
        assert!(
            risk.contains(token),
            "risk register F15 row missing token: {token}"
        );
    }
}
