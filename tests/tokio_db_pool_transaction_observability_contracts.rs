//! Contract enforcement tests for T6.5: Pool, Transaction, and Observability
//! Contracts Across Databases.
//!
//! These tests validate the structure and completeness of the contract
//! documentation and JSON artifact, ensuring all declared contracts are
//! well-formed, cross-referenced, and aligned with source code.
//!
//! Bead: asupersync-2oh2u.6.5

use std::collections::{HashMap, HashSet};

// ─── Helpers ─────────────────────────────────────────────────────────────────

const CONTRACT_MD: &str =
    include_str!("../docs/tokio_db_pool_transaction_observability_contracts.md");
const CONTRACT_JSON: &str =
    include_str!("../docs/tokio_db_pool_transaction_observability_contracts.json");

fn parse_json() -> serde_json::Value {
    serde_json::from_str(CONTRACT_JSON).expect("contract JSON must parse")
}

fn contract_ids_from_json(json: &serde_json::Value) -> Vec<String> {
    let mut ids = Vec::new();
    let contracts = json.get("contracts").expect("contracts key");
    for (_domain, items) in contracts.as_object().unwrap() {
        for item in items.as_array().unwrap() {
            if let Some(id) = item.get("id").and_then(|v: &serde_json::Value| v.as_str()) {
                ids.push(id.to_string());
            }
        }
    }
    ids
}

// ─── Section 1: Document Structure ───────────────────────────────────────────

#[test]
fn contract_md_has_all_required_sections() {
    let required_sections = [
        "Pool Contracts",
        "Transaction Contracts",
        "Timeout Contracts",
        "Observability Contracts",
        "Error Normalization Contract",
        "Implementation Status",
        "Contract Dependencies",
    ];
    for section in &required_sections {
        assert!(
            CONTRACT_MD.contains(section),
            "missing required section: {section}"
        );
    }
}

#[test]
fn contract_md_references_all_three_backends() {
    let backends = ["PostgreSQL", "MySQL", "SQLite"];
    for backend in &backends {
        assert!(
            CONTRACT_MD.contains(backend),
            "missing backend reference: {backend}"
        );
    }
}

#[test]
fn contract_md_references_source_modules() {
    let modules = [
        "src/database/pool.rs",
        "src/sync/pool.rs",
        "src/database/transaction.rs",
        "src/database/postgres.rs",
        "src/database/mysql.rs",
        "src/database/sqlite.rs",
    ];
    for module in &modules {
        assert!(
            CONTRACT_MD.contains(module),
            "missing source module reference: {module}"
        );
    }
}

#[test]
fn contract_md_references_gap_baseline() {
    assert!(
        CONTRACT_MD.contains("tokio_db_messaging_gap_baseline"),
        "must reference T6.1 gap baseline"
    );
}

// ─── Section 2: JSON Artifact Structure ──────────────────────────────────────

#[test]
fn json_schema_version_is_present() {
    let json = parse_json();
    let version = json
        .get("schema_version")
        .and_then(|v: &serde_json::Value| v.as_str())
        .expect("schema_version");
    assert_eq!(version, "1.0.0");
}

#[test]
fn json_has_all_contract_domains() {
    let json = parse_json();
    let contracts = json.get("contracts").expect("contracts key");
    let domains: HashSet<&str> = contracts
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();

    let required = [
        "pool",
        "transaction",
        "timeout",
        "observability",
        "error_normalization",
    ];
    for domain in &required {
        assert!(domains.contains(domain), "missing domain: {domain}");
    }
}

#[test]
fn json_contract_ids_are_unique() {
    let json = parse_json();
    let ids = contract_ids_from_json(&json);
    let unique: HashSet<&str> = ids.iter().map(String::as_str).collect();
    assert_eq!(
        ids.len(),
        unique.len(),
        "duplicate contract IDs found: {ids:?}"
    );
}

#[test]
fn json_total_contracts_matches_count() {
    let json = parse_json();
    let ids = contract_ids_from_json(&json);
    let declared = json
        .get("summary")
        .and_then(|s: &serde_json::Value| s.get("total_contracts"))
        .and_then(serde_json::Value::as_u64)
        .expect("summary.total_contracts");
    assert_eq!(
        ids.len() as u64,
        declared,
        "actual contract count ({}) != declared ({})",
        ids.len(),
        declared
    );
}

// ─── Section 3: Pool Contracts ───────────────────────────────────────────────

#[test]
fn pool_contracts_cover_minimum_set() {
    let json = parse_json();
    let pool = json
        .get("contracts")
        .and_then(|c: &serde_json::Value| c.get("pool"))
        .and_then(|p: &serde_json::Value| p.as_array())
        .expect("contracts.pool array");

    let ids: HashSet<String> = pool
        .iter()
        .filter_map(|c: &serde_json::Value| {
            c.get("id")
                .and_then(|v: &serde_json::Value| v.as_str())
                .map(String::from)
        })
        .collect();

    let required = [
        "C-POOL-01", // Acquire/Release
        "C-POOL-02", // Configuration Parity
        "C-POOL-03", // Health Check
        "C-POOL-04", // Statistics
        "C-POOL-05", // Cancel-Safety
        "C-POOL-06", // Backpressure
        "C-POOL-07", // Graceful Drain
    ];
    for id in &required {
        assert!(ids.contains(*id), "missing pool contract: {id}");
    }
}

#[test]
fn pool_config_parameters_have_defaults() {
    let json = parse_json();
    let pool = json
        .get("contracts")
        .and_then(|c: &serde_json::Value| c.get("pool"))
        .and_then(|p: &serde_json::Value| p.as_array())
        .expect("contracts.pool");

    let config_contract = pool
        .iter()
        .find(|c: &&serde_json::Value| {
            c.get("id").and_then(|v: &serde_json::Value| v.as_str()) == Some("C-POOL-02")
        })
        .expect("C-POOL-02");

    let params = config_contract
        .get("parameters")
        .and_then(|p: &serde_json::Value| p.as_array())
        .expect("C-POOL-02 parameters");

    let param_names: HashSet<&str> = params
        .iter()
        .filter_map(|p: &serde_json::Value| {
            p.get("name").and_then(|n: &serde_json::Value| n.as_str())
        })
        .collect();

    let required_params = [
        "min_idle",
        "max_size",
        "connection_timeout",
        "idle_timeout",
        "max_lifetime",
        "validate_on_checkout",
    ];
    for param in &required_params {
        assert!(
            param_names.contains(param),
            "missing pool config parameter: {param}"
        );
    }

    // Verify each parameter has a default
    for param in params {
        let name = param
            .get("name")
            .and_then(|n: &serde_json::Value| n.as_str())
            .unwrap();
        let has_default = param.get("default").is_some() || param.get("default_secs").is_some();
        assert!(has_default, "pool parameter '{name}' missing default value");
    }
}

#[test]
fn pool_cancel_safety_covers_all_phases() {
    let json = parse_json();
    let pool = json
        .get("contracts")
        .and_then(|c: &serde_json::Value| c.get("pool"))
        .and_then(|p: &serde_json::Value| p.as_array())
        .expect("contracts.pool");

    let cancel_contract = pool
        .iter()
        .find(|c: &&serde_json::Value| {
            c.get("id").and_then(|v: &serde_json::Value| v.as_str()) == Some("C-POOL-05")
        })
        .expect("C-POOL-05");

    let phases: HashSet<&str> = cancel_contract
        .get("phases")
        .and_then(|p: &serde_json::Value| p.as_array())
        .expect("C-POOL-05 phases")
        .iter()
        .filter_map(|p: &serde_json::Value| {
            p.get("phase").and_then(|v: &serde_json::Value| v.as_str())
        })
        .collect();

    assert!(phases.contains("wait"), "missing wait-phase cancel-safety");
    assert!(phases.contains("hold"), "missing hold-phase cancel-safety");
    assert!(
        phases.contains("transaction"),
        "missing transaction-phase cancel-safety"
    );
}

#[test]
fn pool_stats_has_minimum_fields() {
    let json = parse_json();
    let pool = json
        .get("contracts")
        .and_then(|c: &serde_json::Value| c.get("pool"))
        .and_then(|p: &serde_json::Value| p.as_array())
        .expect("contracts.pool");

    let stats_contract = pool
        .iter()
        .find(|c: &&serde_json::Value| {
            c.get("id").and_then(|v: &serde_json::Value| v.as_str()) == Some("C-POOL-04")
        })
        .expect("C-POOL-04");

    let fields: HashSet<&str> = stats_contract
        .get("required_fields")
        .and_then(|f: &serde_json::Value| f.as_array())
        .expect("C-POOL-04 required_fields")
        .iter()
        .filter_map(|f: &serde_json::Value| {
            f.get("name").and_then(|n: &serde_json::Value| n.as_str())
        })
        .collect();

    let required = [
        "active",
        "idle",
        "total",
        "max_size",
        "waiters",
        "total_acquisitions",
        "total_timeouts",
        "total_validation_failures",
    ];
    for field in &required {
        assert!(fields.contains(field), "missing pool stat field: {field}");
    }
}

// ─── Section 4: Transaction Contracts ────────────────────────────────────────

#[test]
fn transaction_contracts_cover_minimum_set() {
    let json = parse_json();
    let txn = json
        .get("contracts")
        .and_then(|c: &serde_json::Value| c.get("transaction"))
        .and_then(|t: &serde_json::Value| t.as_array())
        .expect("contracts.transaction");

    let ids: HashSet<String> = txn
        .iter()
        .filter_map(|c: &serde_json::Value| {
            c.get("id")
                .and_then(|v: &serde_json::Value| v.as_str())
                .map(String::from)
        })
        .collect();

    let required = [
        "C-TXN-01", // Lifecycle
        "C-TXN-02", // Closure-Based Wrapper
        "C-TXN-03", // Savepoint Support
        "C-TXN-04", // Retry Policy
        "C-TXN-05", // Isolation Level
    ];
    for id in &required {
        assert!(ids.contains(*id), "missing transaction contract: {id}");
    }
}

#[test]
fn transaction_closure_wrapper_defines_outcome_mapping() {
    let json = parse_json();
    let txn = json
        .get("contracts")
        .and_then(|c: &serde_json::Value| c.get("transaction"))
        .and_then(|t: &serde_json::Value| t.as_array())
        .expect("contracts.transaction");

    let closure_contract = txn
        .iter()
        .find(|c: &&serde_json::Value| {
            c.get("id").and_then(|v: &serde_json::Value| v.as_str()) == Some("C-TXN-02")
        })
        .expect("C-TXN-02");

    let mapping = closure_contract
        .get("outcome_mapping")
        .expect("C-TXN-02 outcome_mapping");

    assert_eq!(
        mapping
            .get("Ok")
            .and_then(|v: &serde_json::Value| v.as_str()),
        Some("commit"),
        "Ok must map to commit"
    );
    assert_eq!(
        mapping
            .get("Err")
            .and_then(|v: &serde_json::Value| v.as_str()),
        Some("rollback"),
        "Err must map to rollback"
    );
    assert!(
        mapping
            .get("Cancelled")
            .and_then(|v: &serde_json::Value| v.as_str())
            .is_some_and(|s| s.contains("rollback")),
        "Cancelled must include rollback"
    );
}

#[test]
fn transaction_retry_defines_eligibility_per_backend() {
    let json = parse_json();
    let txn = json
        .get("contracts")
        .and_then(|c: &serde_json::Value| c.get("transaction"))
        .and_then(|t: &serde_json::Value| t.as_array())
        .expect("contracts.transaction");

    let retry_contract = txn
        .iter()
        .find(|c: &&serde_json::Value| {
            c.get("id").and_then(|v: &serde_json::Value| v.as_str()) == Some("C-TXN-04")
        })
        .expect("C-TXN-04");

    let eligibility = retry_contract
        .get("retry_eligibility")
        .expect("C-TXN-04 retry_eligibility");

    // Each backend must have an eligibility condition
    for backend in &["postgresql", "mysql", "sqlite"] {
        assert!(
            eligibility.get(*backend).is_some(),
            "missing retry eligibility for {backend}"
        );
    }

    // PostgreSQL must reference SQLSTATE 40001
    let pg = eligibility
        .get("postgresql")
        .and_then(|v: &serde_json::Value| v.as_str())
        .unwrap();
    assert!(
        pg.contains("40001"),
        "PostgreSQL retry must reference 40001"
    );
}

#[test]
fn transaction_savepoints_defined_for_all_backends() {
    let json = parse_json();
    let txn = json
        .get("contracts")
        .and_then(|c: &serde_json::Value| c.get("transaction"))
        .and_then(|t: &serde_json::Value| t.as_array())
        .expect("contracts.transaction");

    let savepoint_contract = txn
        .iter()
        .find(|c: &&serde_json::Value| {
            c.get("id").and_then(|v: &serde_json::Value| v.as_str()) == Some("C-TXN-03")
        })
        .expect("C-TXN-03");

    let patterns = savepoint_contract
        .get("sql_patterns")
        .expect("C-TXN-03 sql_patterns");

    for backend in &["postgresql", "mysql", "sqlite"] {
        let cmds = patterns
            .get(*backend)
            .and_then(|v: &serde_json::Value| v.as_array())
            .unwrap_or_else(|| panic!("missing sql_patterns for {backend}"));
        // Each backend must define at least 3 operations (create, release, rollback)
        assert!(
            cmds.len() >= 3,
            "{backend} must have >= 3 savepoint SQL patterns, found {}",
            cmds.len()
        );
    }
}

#[test]
fn isolation_levels_defined_for_all_backends() {
    let json = parse_json();
    let txn = json
        .get("contracts")
        .and_then(|c: &serde_json::Value| c.get("transaction"))
        .and_then(|t: &serde_json::Value| t.as_array())
        .expect("contracts.transaction");

    let isolation_contract = txn
        .iter()
        .find(|c: &&serde_json::Value| {
            c.get("id").and_then(|v: &serde_json::Value| v.as_str()) == Some("C-TXN-05")
        })
        .expect("C-TXN-05");

    let support = isolation_contract
        .get("isolation_support")
        .expect("C-TXN-05 isolation_support");

    for backend in &["postgresql", "mysql", "sqlite"] {
        let backend_support = support
            .get(*backend)
            .unwrap_or_else(|| panic!("missing isolation support for {backend}"));

        // Must specify default
        assert!(
            backend_support.get("default").is_some(),
            "{backend} must specify default isolation level"
        );

        // Must declare at least Serializable
        assert!(
            backend_support.get("Serializable").is_some(),
            "{backend} must declare Serializable support status"
        );
    }
}

// ─── Section 5: Timeout Contracts ────────────────────────────────────────────

#[test]
fn timeout_contracts_cover_minimum_set() {
    let json = parse_json();
    let tmo = json
        .get("contracts")
        .and_then(|c: &serde_json::Value| c.get("timeout"))
        .and_then(|t: &serde_json::Value| t.as_array())
        .expect("contracts.timeout");

    let ids: HashSet<String> = tmo
        .iter()
        .filter_map(|c: &serde_json::Value| {
            c.get("id")
                .and_then(|v: &serde_json::Value| v.as_str())
                .map(String::from)
        })
        .collect();

    let required = [
        "C-TMO-01", // Connection Timeout
        "C-TMO-02", // Query Timeout
        "C-TMO-03", // Idle Timeout
        "C-TMO-04", // Max Lifetime
    ];
    for id in &required {
        assert!(ids.contains(*id), "missing timeout contract: {id}");
    }
}

#[test]
fn connection_timeout_respects_cx_cancel() {
    let json = parse_json();
    let tmo = json
        .get("contracts")
        .and_then(|c: &serde_json::Value| c.get("timeout"))
        .and_then(|t: &serde_json::Value| t.as_array())
        .expect("contracts.timeout");

    let conn_timeout = tmo
        .iter()
        .find(|c: &&serde_json::Value| {
            c.get("id").and_then(|v: &serde_json::Value| v.as_str()) == Some("C-TMO-01")
        })
        .expect("C-TMO-01");

    let respects = conn_timeout
        .get("respects_cx_cancel")
        .and_then(serde_json::Value::as_bool)
        .expect("C-TMO-01 respects_cx_cancel");

    assert!(respects, "connection timeout must respect Cx cancellation");
}

#[test]
fn max_lifetime_uses_monotonic_clock() {
    let json = parse_json();
    let tmo = json
        .get("contracts")
        .and_then(|c: &serde_json::Value| c.get("timeout"))
        .and_then(|t: &serde_json::Value| t.as_array())
        .expect("contracts.timeout");

    let lifetime = tmo
        .iter()
        .find(|c: &&serde_json::Value| {
            c.get("id").and_then(|v: &serde_json::Value| v.as_str()) == Some("C-TMO-04")
        })
        .expect("C-TMO-04");

    let clock = lifetime
        .get("clock")
        .and_then(|v: &serde_json::Value| v.as_str())
        .expect("C-TMO-04 clock");

    assert!(
        clock.contains("monotonic") || clock.contains("Instant"),
        "max lifetime must use monotonic clock, found: {clock}"
    );
}

// ─── Section 6: Observability Contracts ──────────────────────────────────────

#[test]
fn observability_contracts_cover_minimum_set() {
    let json = parse_json();
    let obs = json
        .get("contracts")
        .and_then(|c: &serde_json::Value| c.get("observability"))
        .and_then(|o: &serde_json::Value| o.as_array())
        .expect("contracts.observability");

    let ids: HashSet<String> = obs
        .iter()
        .filter_map(|c: &serde_json::Value| {
            c.get("id")
                .and_then(|v: &serde_json::Value| v.as_str())
                .map(String::from)
        })
        .collect();

    let required = [
        "C-OBS-01", // Connection Events
        "C-OBS-02", // Transaction Events
        "C-OBS-03", // Pool Health Metrics
        "C-OBS-04", // Slow Query Detection
    ];
    for id in &required {
        assert!(ids.contains(*id), "missing observability contract: {id}");
    }
}

#[test]
fn connection_events_include_lifecycle_milestones() {
    let json = parse_json();
    let obs = json
        .get("contracts")
        .and_then(|c: &serde_json::Value| c.get("observability"))
        .and_then(|o: &serde_json::Value| o.as_array())
        .expect("contracts.observability");

    let conn_events = obs
        .iter()
        .find(|c: &&serde_json::Value| {
            c.get("id").and_then(|v: &serde_json::Value| v.as_str()) == Some("C-OBS-01")
        })
        .expect("C-OBS-01");

    let events: HashSet<&str> = conn_events
        .get("events")
        .and_then(|e: &serde_json::Value| e.as_array())
        .expect("C-OBS-01 events")
        .iter()
        .filter_map(|e: &serde_json::Value| {
            e.get("name").and_then(|n: &serde_json::Value| n.as_str())
        })
        .collect();

    let required_events = [
        "connection.created",
        "connection.acquired",
        "connection.released",
        "connection.evicted",
    ];
    for event in &required_events {
        assert!(events.contains(event), "missing connection event: {event}");
    }
}

#[test]
fn transaction_events_include_lifecycle_milestones() {
    let json = parse_json();
    let obs = json
        .get("contracts")
        .and_then(|c: &serde_json::Value| c.get("observability"))
        .and_then(|o: &serde_json::Value| o.as_array())
        .expect("contracts.observability");

    let txn_events = obs
        .iter()
        .find(|c: &&serde_json::Value| {
            c.get("id").and_then(|v: &serde_json::Value| v.as_str()) == Some("C-OBS-02")
        })
        .expect("C-OBS-02");

    let events: HashSet<&str> = txn_events
        .get("events")
        .and_then(|e: &serde_json::Value| e.as_array())
        .expect("C-OBS-02 events")
        .iter()
        .filter_map(|e: &serde_json::Value| {
            e.get("name").and_then(|n: &serde_json::Value| n.as_str())
        })
        .collect();

    let required_events = [
        "transaction.begin",
        "transaction.commit",
        "transaction.rollback",
    ];
    for event in &required_events {
        assert!(events.contains(event), "missing transaction event: {event}");
    }
}

#[test]
fn pool_health_metrics_include_utilization() {
    let json = parse_json();
    let obs = json
        .get("contracts")
        .and_then(|c: &serde_json::Value| c.get("observability"))
        .and_then(|o: &serde_json::Value| o.as_array())
        .expect("contracts.observability");

    let metrics = obs
        .iter()
        .find(|c: &&serde_json::Value| {
            c.get("id").and_then(|v: &serde_json::Value| v.as_str()) == Some("C-OBS-03")
        })
        .expect("C-OBS-03");

    let metric_names: HashSet<&str> = metrics
        .get("derived_metrics")
        .and_then(|m: &serde_json::Value| m.as_array())
        .expect("C-OBS-03 derived_metrics")
        .iter()
        .filter_map(|m: &serde_json::Value| {
            m.get("name").and_then(|n: &serde_json::Value| n.as_str())
        })
        .collect();

    assert!(
        metric_names.contains("pool_utilization"),
        "must include pool_utilization metric"
    );
    assert!(
        metric_names.contains("timeout_rate"),
        "must include timeout_rate metric"
    );
}

// ─── Section 7: Error Normalization ──────────────────────────────────────────

#[test]
fn error_categories_cover_common_failures() {
    let json = parse_json();
    let err = json
        .get("contracts")
        .and_then(|c: &serde_json::Value| c.get("error_normalization"))
        .and_then(|e: &serde_json::Value| e.as_array())
        .expect("contracts.error_normalization");

    let categories_contract = err
        .iter()
        .find(|c: &&serde_json::Value| {
            c.get("id").and_then(|v: &serde_json::Value| v.as_str()) == Some("C-ERR-01")
        })
        .expect("C-ERR-01");

    let categories: HashSet<&str> = categories_contract
        .get("categories")
        .and_then(|c: &serde_json::Value| c.as_array())
        .expect("C-ERR-01 categories")
        .iter()
        .filter_map(|c: &serde_json::Value| {
            c.get("category")
                .and_then(|v: &serde_json::Value| v.as_str())
        })
        .collect();

    let required = [
        "ConnectionFailed",
        "AuthenticationFailed",
        "QuerySyntax",
        "ConstraintViolation",
        "SerializationFailure",
        "DeadlockDetected",
        "Timeout",
        "PoolExhausted",
        "Cancelled",
    ];
    for cat in &required {
        assert!(categories.contains(cat), "missing error category: {cat}");
    }
}

#[test]
fn error_categories_cover_all_backends() {
    let json = parse_json();
    let err = json
        .get("contracts")
        .and_then(|c: &serde_json::Value| c.get("error_normalization"))
        .and_then(|e: &serde_json::Value| e.as_array())
        .expect("contracts.error_normalization");

    let categories_contract = err
        .iter()
        .find(|c: &&serde_json::Value| {
            c.get("id").and_then(|v: &serde_json::Value| v.as_str()) == Some("C-ERR-01")
        })
        .expect("C-ERR-01");

    let categories = categories_contract
        .get("categories")
        .and_then(|c: &serde_json::Value| c.as_array())
        .expect("C-ERR-01 categories");

    for cat in categories {
        let category_name = cat
            .get("category")
            .and_then(|v: &serde_json::Value| v.as_str())
            .unwrap();
        for backend in &["postgresql", "mysql", "sqlite"] {
            assert!(
                cat.get(*backend).is_some(),
                "error category '{category_name}' missing mapping for {backend}"
            );
        }
    }
}

#[test]
fn error_method_parity_defines_required_methods() {
    let json = parse_json();
    let err = json
        .get("contracts")
        .and_then(|c: &serde_json::Value| c.get("error_normalization"))
        .and_then(|e: &serde_json::Value| e.as_array())
        .expect("contracts.error_normalization");

    let methods_contract = err
        .iter()
        .find(|c: &&serde_json::Value| {
            c.get("id").and_then(|v: &serde_json::Value| v.as_str()) == Some("C-ERR-02")
        })
        .expect("C-ERR-02");

    let methods: HashSet<&str> = methods_contract
        .get("required_methods")
        .and_then(|m: &serde_json::Value| m.as_array())
        .expect("C-ERR-02 required_methods")
        .iter()
        .filter_map(|m: &serde_json::Value| m.as_str())
        .collect();

    let required = [
        "is_connection_error",
        "is_serialization_failure",
        "is_deadlock",
        "is_unique_violation",
        "is_constraint_violation",
        "is_retryable",
    ];
    for method in &required {
        assert!(methods.contains(method), "missing error method: {method}");
    }
}

// ─── Section 8: Summary and Cross-References ─────────────────────────────────

#[test]
fn summary_domain_counts_are_consistent() {
    let json = parse_json();
    let summary = json.get("summary").expect("summary");
    let domains = summary.get("domains").expect("summary.domains");

    let mut total_from_domains = 0u64;
    for (_name, domain) in domains.as_object().unwrap() {
        let count = domain
            .get("count")
            .and_then(serde_json::Value::as_u64)
            .expect("domain count");
        total_from_domains += count;
    }

    let declared_total = summary
        .get("total_contracts")
        .and_then(serde_json::Value::as_u64)
        .expect("total_contracts");

    assert_eq!(
        total_from_domains, declared_total,
        "sum of domain counts ({total_from_domains}) != total_contracts ({declared_total})"
    );
}

#[test]
fn summary_lists_all_three_backends() {
    let json = parse_json();
    let backends = json
        .get("summary")
        .and_then(|s: &serde_json::Value| s.get("backends"))
        .and_then(|b: &serde_json::Value| b.as_array())
        .expect("summary.backends");

    let backend_set: HashSet<&str> = backends
        .iter()
        .filter_map(|b: &serde_json::Value| b.as_str())
        .collect();

    assert!(backend_set.contains("postgresql"), "missing postgresql");
    assert!(backend_set.contains("mysql"), "missing mysql");
    assert!(backend_set.contains("sqlite"), "missing sqlite");
}

#[test]
fn summary_pool_integration_status_tracks_gaps() {
    let json = parse_json();
    let pool_status = json
        .get("summary")
        .and_then(|s: &serde_json::Value| s.get("pool_integration_status"))
        .expect("summary.pool_integration_status");

    // PostgreSQL and MySQL should be marked as not_wired (blocking gaps)
    let pg = pool_status
        .get("postgresql")
        .and_then(|v: &serde_json::Value| v.as_str())
        .expect("pg status");
    assert_eq!(pg, "not_wired", "PostgreSQL pool status must be not_wired");

    let mysql = pool_status
        .get("mysql")
        .and_then(|v: &serde_json::Value| v.as_str())
        .expect("mysql status");
    assert_eq!(mysql, "not_wired", "MySQL pool status must be not_wired");
}

#[test]
fn blocking_gaps_include_critical_pool_items() {
    let json = parse_json();
    let gaps = json
        .get("summary")
        .and_then(|s: &serde_json::Value| s.get("blocking_gaps"))
        .and_then(|g: &serde_json::Value| g.as_array())
        .expect("summary.blocking_gaps");

    let gap_ids: HashSet<&str> = gaps
        .iter()
        .filter_map(|g: &serde_json::Value| {
            g.get("id").and_then(|v: &serde_json::Value| v.as_str())
        })
        .collect();

    assert!(gap_ids.contains("PG-G4"), "must list PG-G4 as blocking gap");
    assert!(gap_ids.contains("MY-G3"), "must list MY-G3 as blocking gap");
}

#[test]
fn dependencies_reference_valid_beads() {
    let json = parse_json();
    let deps = json.get("dependencies").expect("dependencies");

    let blocked_by = deps
        .get("blocked_by")
        .and_then(|b: &serde_json::Value| b.as_array())
        .expect("dependencies.blocked_by");

    // Must reference T6.2 as a blocker
    let blocker_beads: HashSet<&str> = blocked_by
        .iter()
        .filter_map(|b: &serde_json::Value| {
            b.get("bead").and_then(|v: &serde_json::Value| v.as_str())
        })
        .collect();

    assert!(
        blocker_beads.contains("asupersync-2oh2u.6.2"),
        "must reference T6.2 as blocker"
    );

    let blocks = deps
        .get("blocks")
        .and_then(|b: &serde_json::Value| b.as_array())
        .expect("dependencies.blocks");

    let downstream_beads: HashSet<&str> = blocks
        .iter()
        .filter_map(|b: &serde_json::Value| {
            b.get("bead").and_then(|v: &serde_json::Value| v.as_str())
        })
        .collect();

    assert!(
        downstream_beads.contains("asupersync-2oh2u.6.9"),
        "must list T6.9 as downstream"
    );
    assert!(
        downstream_beads.contains("asupersync-2oh2u.6.12"),
        "must list T6.12 as downstream"
    );
}

// ─── Section 9: Source Module References ─────────────────────────────────────

#[test]
fn source_modules_reference_existing_files() {
    let json = parse_json();
    let modules = json.get("source_modules").expect("source_modules");

    let expected_paths = [
        ("pool_sync", "src/database/pool.rs"),
        ("pool_async", "src/sync/pool.rs"),
        ("transaction", "src/database/transaction.rs"),
        ("postgres", "src/database/postgres.rs"),
        ("mysql", "src/database/mysql.rs"),
        ("sqlite", "src/database/sqlite.rs"),
    ];

    for (key, expected) in &expected_paths {
        let path = modules
            .get(*key)
            .and_then(|v: &serde_json::Value| v.as_str())
            .unwrap_or_else(|| panic!("missing source_modules.{key}"));
        assert_eq!(
            path, *expected,
            "source_modules.{key} should be {expected}, found {path}"
        );
    }
}

// ─── Section 10: Markdown-JSON Consistency ───────────────────────────────────

#[test]
fn all_json_contract_ids_appear_in_markdown() {
    let json = parse_json();
    let ids = contract_ids_from_json(&json);

    for id in &ids {
        assert!(
            CONTRACT_MD.contains(id.as_str()),
            "contract {id} exists in JSON but not referenced in markdown"
        );
    }
}

#[test]
fn markdown_contract_headers_match_json_domains() {
    // Verify that each domain in JSON has corresponding markdown sections
    let domain_to_section: HashMap<&str, &str> = [
        ("pool", "Pool Contracts"),
        ("transaction", "Transaction Contracts"),
        ("timeout", "Timeout Contracts"),
        ("observability", "Observability Contracts"),
        ("error_normalization", "Error Normalization"),
    ]
    .into_iter()
    .collect();

    let json = parse_json();
    let contracts = json.get("contracts").expect("contracts");

    for (domain, _items) in contracts.as_object().unwrap() {
        let section = domain_to_section
            .get(domain.as_str())
            .unwrap_or_else(|| panic!("unmapped domain: {domain}"));
        assert!(
            CONTRACT_MD.contains(section),
            "domain '{domain}' maps to section '{section}' which is missing from markdown"
        );
    }
}

#[test]
fn bead_id_consistent_between_md_and_json() {
    let json = parse_json();
    let json_bead = json
        .get("bead_id")
        .and_then(|v: &serde_json::Value| v.as_str())
        .expect("bead_id in JSON");

    assert!(
        CONTRACT_MD.contains(json_bead),
        "bead_id '{json_bead}' from JSON not found in markdown"
    );
}
