//! T6.11 — Migration Packs for Database and Messaging Ecosystems
//!
//! Bead: `asupersync-2oh2u.6.11`
//! Track: T6 (Database and messaging ecosystem closure)
//!
//! Meta-test suite validating contract document completeness, JSON artifact
//! schema, migration pack coverage, and source module references.

use std::collections::HashSet;

// ─── Constants ───────────────────────────────────────────────────────────────

const CONTRACT_MD: &str = include_str!("../docs/tokio_db_messaging_migration_packs_contract.md");
const CONTRACT_JSON: &str =
    include_str!("../docs/tokio_db_messaging_migration_packs_contract.json");

fn parse_json() -> serde_json::Value {
    serde_json::from_str(CONTRACT_JSON).expect("T6.11 contract JSON must parse")
}

// ════════════════════════════════════════════════════════════════════════════
// Section 1: Document Structure
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn doc_has_required_sections() {
    let required = [
        "## 1. PostgreSQL Migration (MIG-PG)",
        "## 2. PostgreSQL Migration — tokio-postgres (MIG-PG-TOKIO)",
        "## 3. MySQL Migration (MIG-MY)",
        "## 4. MySQL Migration — mysql_async (MIG-MY-TOKIO)",
        "## 5. SQLite Migration (MIG-SQ)",
        "## 6. Connection Pool Migration (MIG-POOL)",
        "## 7. Redis Migration (MIG-RD)",
        "## 8. NATS and JetStream Migration (MIG-NT)",
        "## 9. Kafka Migration (MIG-KF)",
        "## 10. Cross-Cutting Differences",
        "## 11. Operational Caveats",
        "## 12. Implementation Status",
        "## 13. Contract Dependencies",
        "## 14. Source Module References",
    ];
    for section in &required {
        assert!(CONTRACT_MD.contains(section), "missing section: {section}");
    }
}

#[test]
fn doc_has_scope_table() {
    assert!(CONTRACT_MD.contains("| Source Crate |"));
    assert!(CONTRACT_MD.contains("| Migration Pack ID |"));
}

#[test]
fn doc_has_before_after_tables() {
    // All migration sections should have before/after comparison tables
    let packs = [
        "MIG-PG-01",
        "MIG-MY-01",
        "MIG-SQ-01",
        "MIG-POOL-01",
        "MIG-RD-01",
        "MIG-NT-01",
        "MIG-KF-01",
    ];
    for pack in &packs {
        assert!(
            CONTRACT_MD.contains(pack),
            "missing migration scenario: {pack}"
        );
    }
}

#[test]
fn doc_references_cx_context() {
    // Migration docs must explain the Cx requirement
    assert!(
        CONTRACT_MD.contains("&Cx"),
        "doc must reference Cx capability"
    );
    assert!(
        CONTRACT_MD.contains("Outcome<T, E>"),
        "doc must reference Outcome type"
    );
}

#[test]
fn doc_references_resolved() {
    // Migration docs must explain .resolved()? bridging pattern
    assert!(
        CONTRACT_MD.contains(".resolved()?"),
        "doc must reference .resolved()? pattern"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// Section 2: JSON Artifact Schema
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn json_has_schema_version() {
    let json = parse_json();
    let v = json["schema_version"].as_str().unwrap();
    assert!(!v.is_empty());
}

#[test]
fn json_has_bead_id() {
    let json = parse_json();
    assert_eq!(json["bead_id"].as_str().unwrap(), "asupersync-2oh2u.6.11");
}

#[test]
fn json_has_track() {
    let json = parse_json();
    assert_eq!(json["track"].as_str().unwrap(), "T6");
}

#[test]
fn json_has_upstream_dependencies() {
    let json = parse_json();
    let deps = json["upstream_dependencies"]
        .as_array()
        .expect("upstream_dependencies required");
    let found: HashSet<&str> = deps.iter().filter_map(|d| d["bead_id"].as_str()).collect();
    assert!(
        found.contains("asupersync-2oh2u.6.10"),
        "must reference T6.10"
    );
    assert!(
        found.contains("asupersync-2oh2u.6.12"),
        "must reference T6.12"
    );
}

#[test]
fn json_has_downstream_dependents() {
    let json = parse_json();
    let deps = json["downstream_dependents"]
        .as_array()
        .expect("downstream_dependents required");
    assert!(
        deps.iter()
            .filter_map(|d| d["bead_id"].as_str())
            .any(|x| x == "asupersync-2oh2u.11.2"),
        "must reference T9.2"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// Section 3: Migration Pack Coverage
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn json_has_migration_packs_array() {
    let json = parse_json();
    let packs = json["migration_packs"]
        .as_array()
        .expect("migration_packs required");
    assert!(
        packs.len() >= 9,
        "expected >= 9 migration packs, got {}",
        packs.len()
    );
}

#[test]
fn json_migration_packs_have_required_fields() {
    let json = parse_json();
    let packs = json["migration_packs"].as_array().unwrap();
    for (i, pack) in packs.iter().enumerate() {
        assert!(pack["id"].as_str().is_some(), "pack[{i}] missing 'id'");
        assert!(
            pack["source_crate"].as_str().is_some(),
            "pack[{i}] missing 'source_crate'"
        );
        assert!(
            pack["target_module"].as_str().is_some(),
            "pack[{i}] missing 'target_module'"
        );
        let empty = vec![];
        let scenarios = pack["scenarios"].as_array().unwrap_or(&empty);
        assert!(
            !scenarios.is_empty(),
            "pack[{i}] ({}) has no scenarios",
            pack["id"].as_str().unwrap_or("?")
        );
    }
}

#[test]
fn json_scenarios_have_required_fields() {
    let json = parse_json();
    let packs = json["migration_packs"].as_array().unwrap();
    for pack in packs {
        let scenarios = pack["scenarios"].as_array().unwrap();
        for (j, s) in scenarios.iter().enumerate() {
            let pack_id = pack["id"].as_str().unwrap_or("?");
            assert!(
                s["id"].as_str().is_some(),
                "{pack_id}:scenario[{j}] missing 'id'"
            );
            assert!(
                s["title"].as_str().is_some(),
                "{pack_id}:scenario[{j}] missing 'title'"
            );
            assert!(
                s["source_pattern"].as_str().is_some(),
                "{pack_id}:scenario[{j}] missing 'source_pattern'"
            );
            assert!(
                s["target_pattern"].as_str().is_some(),
                "{pack_id}:scenario[{j}] missing 'target_pattern'"
            );
        }
    }
}

#[test]
fn json_covers_all_pack_ids() {
    let json = parse_json();
    let packs = json["migration_packs"].as_array().unwrap();
    let ids: HashSet<&str> = packs.iter().filter_map(|p| p["id"].as_str()).collect();
    let required = [
        "MIG-PG",
        "MIG-PG-TOKIO",
        "MIG-MY",
        "MIG-MY-TOKIO",
        "MIG-SQ",
        "MIG-POOL",
        "MIG-RD",
        "MIG-NT",
        "MIG-KF",
    ];
    for pack_id in &required {
        assert!(ids.contains(pack_id), "missing migration pack: {pack_id}");
    }
}

#[test]
fn json_covers_all_source_crates() {
    let json = parse_json();
    let packs = json["migration_packs"].as_array().unwrap();
    let crates: HashSet<&str> = packs
        .iter()
        .filter_map(|p| p["source_crate"].as_str())
        .collect();
    let required = [
        "sqlx",
        "tokio-postgres",
        "mysql_async",
        "bb8/deadpool",
        "redis",
        "async-nats",
        "rdkafka",
    ];
    for c in &required {
        assert!(crates.contains(c), "missing source crate: {c}");
    }
}

#[test]
fn total_scenario_count() {
    let json = parse_json();
    let packs = json["migration_packs"].as_array().unwrap();
    let total: usize = packs
        .iter()
        .map(|p| p["scenarios"].as_array().map_or(0, Vec::len))
        .sum();
    assert!(total >= 40, "expected >= 40 total scenarios, got {total}");
}

// ════════════════════════════════════════════════════════════════════════════
// Section 4: Cross-Cutting and Caveats
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn json_has_cross_cutting_items() {
    let json = parse_json();
    let cc = json["cross_cutting"]
        .as_array()
        .expect("cross_cutting required");
    assert!(cc.len() >= 4, "expected >= 4 cross_cutting items");
    for (i, item) in cc.iter().enumerate() {
        assert!(
            item["id"].as_str().is_some(),
            "cross_cutting[{i}] missing 'id'"
        );
        assert!(
            item["title"].as_str().is_some(),
            "cross_cutting[{i}] missing 'title'"
        );
    }
}

#[test]
fn json_cross_cutting_covers_cx() {
    let json = parse_json();
    let cc = json["cross_cutting"].as_array().unwrap();
    assert!(
        cc.iter().any(|item| item["id"].as_str() == Some("CX-01")),
        "CX-01 (cancellation) missing"
    );
    assert!(
        cc.iter().any(|item| item["id"].as_str() == Some("CX-02")),
        "CX-02 (error classification) missing"
    );
}

#[test]
fn json_has_caveats() {
    let json = parse_json();
    let caveats = json["caveats"].as_array().expect("caveats required");
    assert!(caveats.len() >= 4, "expected >= 4 caveats");
    let ids: HashSet<&str> = caveats.iter().filter_map(|c| c["id"].as_str()).collect();
    assert!(ids.contains("CAV-01"), "missing CAV-01 (feature flags)");
    assert!(ids.contains("CAV-02"), "missing CAV-02 (Outcome vs Result)");
    assert!(ids.contains("CAV-03"), "missing CAV-03 (no global runtime)");
    assert!(ids.contains("CAV-04"), "missing CAV-04 (sync pool)");
}

// ════════════════════════════════════════════════════════════════════════════
// Section 5: Thresholds
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn json_thresholds_present() {
    let json = parse_json();
    let t = json["thresholds"].as_object().expect("thresholds required");
    assert_eq!(t["total_migration_packs"].as_u64().unwrap(), 9);
    assert!(t["total_scenarios"].as_u64().unwrap() >= 40);
    assert_eq!(t["cross_cutting_items"].as_u64().unwrap(), 4);
    assert_eq!(t["caveats"].as_u64().unwrap(), 4);
    assert!(t["source_crates_covered"].as_u64().unwrap() >= 7);
}

// ════════════════════════════════════════════════════════════════════════════
// Section 6: Source Module References
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn doc_references_all_source_modules() {
    let required = [
        "src/database/pool.rs",
        "src/database/transaction.rs",
        "src/database/postgres.rs",
        "src/database/mysql.rs",
        "src/database/sqlite.rs",
        "src/messaging/redis.rs",
        "src/messaging/nats.rs",
        "src/messaging/jetstream.rs",
        "src/messaging/kafka.rs",
        "src/messaging/kafka_consumer.rs",
    ];
    for module in &required {
        assert!(
            CONTRACT_MD.contains(module),
            "doc missing source module: {module}"
        );
    }
}

#[test]
fn json_references_all_source_modules() {
    let json = parse_json();
    let refs = json["source_module_references"]
        .as_array()
        .expect("source_module_references required");
    let modules: HashSet<&str> = refs.iter().filter_map(|r| r.as_str()).collect();
    let required = [
        "src/database/pool.rs",
        "src/database/transaction.rs",
        "src/database/postgres.rs",
        "src/database/mysql.rs",
        "src/database/sqlite.rs",
        "src/messaging/redis.rs",
        "src/messaging/nats.rs",
        "src/messaging/jetstream.rs",
        "src/messaging/kafka.rs",
        "src/messaging/kafka_consumer.rs",
    ];
    for module in &required {
        assert!(
            modules.contains(module),
            "JSON missing source module: {module}"
        );
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Section 7: JSON-to-Doc Consistency
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn json_pack_ids_appear_in_doc() {
    let json = parse_json();
    let packs = json["migration_packs"].as_array().unwrap();
    for pack in packs {
        let id = pack["id"].as_str().unwrap();
        assert!(
            CONTRACT_MD.contains(id),
            "pack {id} in JSON but not in contract doc"
        );
    }
}

#[test]
fn json_scenario_ids_appear_in_doc() {
    let json = parse_json();
    let packs = json["migration_packs"].as_array().unwrap();
    for pack in packs {
        let scenarios = pack["scenarios"].as_array().unwrap();
        for s in scenarios {
            let id = s["id"].as_str().unwrap();
            assert!(
                CONTRACT_MD.contains(id),
                "scenario {id} in JSON but not in contract doc"
            );
        }
    }
}

#[test]
fn json_cross_cutting_ids_appear_in_doc() {
    let json = parse_json();
    let cc = json["cross_cutting"].as_array().unwrap();
    for item in cc {
        let id = item["id"].as_str().unwrap();
        assert!(
            CONTRACT_MD.contains(id),
            "cross-cutting {id} in JSON but not in contract doc"
        );
    }
}

#[test]
fn json_caveat_ids_appear_in_doc() {
    let json = parse_json();
    let caveats = json["caveats"].as_array().unwrap();
    for item in caveats {
        let id = item["id"].as_str().unwrap();
        assert!(
            CONTRACT_MD.contains(id),
            "caveat {id} in JSON but not in contract doc"
        );
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Section 8: Database Backend Coverage
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn all_db_backends_have_connection_migration() {
    for pack in &["MIG-PG-01", "MIG-MY-01", "MIG-SQ-01"] {
        assert!(
            CONTRACT_MD.contains(pack),
            "missing DB connection migration: {pack}"
        );
    }
}

#[test]
fn all_db_backends_have_transaction_migration() {
    for pack in &["MIG-PG-04", "MIG-MY-03", "MIG-SQ-03"] {
        assert!(
            CONTRACT_MD.contains(pack),
            "missing DB transaction migration: {pack}"
        );
    }
}

#[test]
fn all_db_backends_have_error_handling_migration() {
    for pack in &["MIG-PG-06", "MIG-MY-04", "MIG-SQ-05"] {
        assert!(
            CONTRACT_MD.contains(pack),
            "missing DB error handling migration: {pack}"
        );
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Section 9: Messaging Backend Coverage
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn all_messaging_backends_have_connection_migration() {
    for pack in &["MIG-RD-01", "MIG-NT-01", "MIG-KF-01"] {
        assert!(
            CONTRACT_MD.contains(pack),
            "missing messaging connection migration: {pack}"
        );
    }
}

#[test]
fn all_messaging_backends_have_error_migration() {
    for pack in &["MIG-RD-05", "MIG-NT-04", "MIG-KF-06"] {
        assert!(
            CONTRACT_MD.contains(pack),
            "missing messaging error migration: {pack}"
        );
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Section 10: Dependency Graph
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn doc_has_dependency_diagram() {
    assert!(CONTRACT_MD.contains("T6.10"));
    assert!(CONTRACT_MD.contains("T6.12"));
    assert!(CONTRACT_MD.contains("T6.11"));
    assert!(CONTRACT_MD.contains("T9.2"));
}

#[test]
fn doc_states_bead_id() {
    assert!(CONTRACT_MD.contains("asupersync-2oh2u.6.11"));
}
