//! T6.9 — Retry, Idempotency, and Failure Contract Enforcement Tests
//!
//! Validates that the contract documents (markdown + JSON) for retry,
//! idempotency, and failure handling across database and messaging paths
//! are internally consistent, reference real source modules, and satisfy
//! the structural requirements of the T6 track.

// ── Section 1: Document structure ───────────────────────────────────

#[test]
fn doc_contains_required_sections() {
    let md = include_str!("../docs/tokio_retry_idempotency_failure_contracts.md");
    let required = [
        "## 1. Retry Contracts",
        "## 2. Error Classification Contracts",
        "## 3. Idempotency Contracts",
        "## 4. Delivery Guarantee Contracts",
        "## 5. Failure Propagation Contracts",
        "## 6. Backpressure Contracts",
        "## 7. Implementation Status",
        "## 8. Contract Dependencies",
    ];
    for section in &required {
        assert!(md.contains(section), "missing section: {section}");
    }
}

#[test]
fn doc_references_all_systems() {
    let md = include_str!("../docs/tokio_retry_idempotency_failure_contracts.md");
    let systems = [
        "PostgreSQL",
        "MySQL",
        "SQLite",
        "Kafka",
        "JetStream",
        "NATS",
        "Redis",
    ];
    for sys in &systems {
        assert!(md.contains(sys), "missing system reference: {sys}");
    }
}

#[test]
fn doc_references_source_modules() {
    let md = include_str!("../docs/tokio_retry_idempotency_failure_contracts.md");
    let modules = [
        "src/combinator/retry.rs",
        "src/combinator/circuit_breaker.rs",
        "src/combinator/rate_limit.rs",
        "src/database/transaction.rs",
        "src/database/postgres.rs",
        "src/database/mysql.rs",
        "src/database/sqlite.rs",
        "src/messaging/kafka.rs",
        "src/messaging/jetstream.rs",
        "src/messaging/nats.rs",
        "src/messaging/redis.rs",
    ];
    for m in &modules {
        assert!(md.contains(m), "missing source module reference: {m}");
    }
}

#[test]
fn doc_references_t6_5_contracts() {
    let md = include_str!("../docs/tokio_retry_idempotency_failure_contracts.md");
    assert!(
        md.contains("tokio_db_pool_transaction_observability_contracts"),
        "must reference upstream T6.5 contract document"
    );
}

// ── Section 2: JSON structure ───────────────────────────────────────

#[test]
fn json_has_valid_schema_version() {
    let json: serde_json::Value = serde_json::from_str(include_str!(
        "../docs/tokio_retry_idempotency_failure_contracts.json"
    ))
    .expect("valid JSON");
    assert_eq!(json["schema_version"].as_str().unwrap(), "1.0.0");
    assert_eq!(json["bead_id"].as_str().unwrap(), "asupersync-2oh2u.6.9");
    assert_eq!(json["track"].as_str().unwrap(), "T6");
}

#[test]
fn json_has_all_contract_domains() {
    let json: serde_json::Value = serde_json::from_str(include_str!(
        "../docs/tokio_retry_idempotency_failure_contracts.json"
    ))
    .expect("valid JSON");
    let contracts = json["contracts"].as_object().expect("contracts object");
    let expected_domains = [
        "retry",
        "error_classification",
        "idempotency",
        "delivery",
        "failure_propagation",
        "backpressure",
    ];
    for domain in &expected_domains {
        assert!(contracts.contains_key(*domain), "missing domain: {domain}");
    }
}

#[test]
fn json_contract_ids_are_unique() {
    let json: serde_json::Value = serde_json::from_str(include_str!(
        "../docs/tokio_retry_idempotency_failure_contracts.json"
    ))
    .expect("valid JSON");
    let contracts = json["contracts"].as_object().unwrap();
    let mut ids = std::collections::HashSet::new();
    for (_domain, items) in contracts {
        for item in items.as_array().unwrap() {
            let id = item["id"].as_str().unwrap();
            assert!(ids.insert(id.to_string()), "duplicate contract ID: {id}");
        }
    }
}

#[test]
fn json_total_contracts_matches_actual_count() {
    let json: serde_json::Value = serde_json::from_str(include_str!(
        "../docs/tokio_retry_idempotency_failure_contracts.json"
    ))
    .expect("valid JSON");
    let contracts = json["contracts"].as_object().unwrap();
    let actual: usize = contracts
        .values()
        .map(|v: &serde_json::Value| v.as_array().unwrap().len())
        .sum();
    let declared = json["summary"]["total_contracts"].as_u64().unwrap() as usize;
    assert_eq!(actual, declared, "declared {declared} but found {actual}");
}

// ── Section 3: Retry contracts ──────────────────────────────────────

#[test]
fn retry_policy_defines_required_fields() {
    let json: serde_json::Value = serde_json::from_str(include_str!(
        "../docs/tokio_retry_idempotency_failure_contracts.json"
    ))
    .expect("valid JSON");
    let retry = &json["contracts"]["retry"];
    let rty01 = retry
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "C-RTY-01")
        .expect("C-RTY-01 must exist");

    let fields: Vec<&str> = rty01["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["name"].as_str().unwrap())
        .collect();

    assert!(fields.contains(&"max_attempts"));
    assert!(fields.contains(&"initial_delay"));
    assert!(fields.contains(&"max_delay"));
    assert!(fields.contains(&"multiplier"));
    assert!(fields.contains(&"jitter"));
}

#[test]
fn retry_policy_has_delay_formula() {
    let json: serde_json::Value = serde_json::from_str(include_str!(
        "../docs/tokio_retry_idempotency_failure_contracts.json"
    ))
    .expect("valid JSON");
    let rty01 = json["contracts"]["retry"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "C-RTY-01")
        .expect("C-RTY-01");
    let formula = rty01["delay_formula"].as_str().unwrap();
    assert!(
        formula.contains("multiplier"),
        "formula must use multiplier"
    );
    assert!(
        formula.contains("max_delay"),
        "formula must cap at max_delay"
    );
    assert!(formula.contains("jitter"), "formula must include jitter");
}

#[test]
fn transaction_retry_eligibility_covers_all_backends() {
    let json: serde_json::Value = serde_json::from_str(include_str!(
        "../docs/tokio_retry_idempotency_failure_contracts.json"
    ))
    .expect("valid JSON");
    let rty02 = json["contracts"]["retry"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "C-RTY-02")
        .expect("C-RTY-02");
    let eligibility = rty02["eligibility"].as_object().unwrap();
    assert!(eligibility.contains_key("postgresql"));
    assert!(eligibility.contains_key("mysql"));
    assert!(eligibility.contains_key("sqlite"));
}

#[test]
fn transaction_retry_defines_non_retryable_categories() {
    let json: serde_json::Value = serde_json::from_str(include_str!(
        "../docs/tokio_retry_idempotency_failure_contracts.json"
    ))
    .expect("valid JSON");
    let rty02 = json["contracts"]["retry"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "C-RTY-02")
        .expect("C-RTY-02");
    let non_retryable: Vec<&str> = rty02["non_retryable"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v: &serde_json::Value| v.as_str().unwrap())
        .collect();
    assert!(non_retryable.contains(&"constraint_violation"));
    assert!(non_retryable.contains(&"syntax_error"));
    assert!(non_retryable.contains(&"authentication_failure"));
}

#[test]
fn cancel_aware_retry_requirements_defined() {
    let json: serde_json::Value = serde_json::from_str(include_str!(
        "../docs/tokio_retry_idempotency_failure_contracts.json"
    ))
    .expect("valid JSON");
    let rty05 = json["contracts"]["retry"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "C-RTY-05")
        .expect("C-RTY-05");
    let reqs: Vec<&str> = rty05["requirements"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v: &serde_json::Value| v.as_str().unwrap())
        .collect();
    assert!(reqs.contains(&"check_cancel_before_attempt"));
    assert!(reqs.contains(&"propagate_cancelled_outcome"));
    assert!(reqs.contains(&"delays_count_against_cx_budget"));
}

// ── Section 4: Error classification contracts ───────────────────────

#[test]
fn transient_error_predicate_covers_all_systems() {
    let json: serde_json::Value = serde_json::from_str(include_str!(
        "../docs/tokio_retry_idempotency_failure_contracts.json"
    ))
    .expect("valid JSON");
    let err03 = json["contracts"]["error_classification"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "C-ERR-03")
        .expect("C-ERR-03");
    let conditions = err03["transient_conditions"].as_object().unwrap();
    let expected = [
        "postgresql",
        "mysql",
        "sqlite",
        "kafka",
        "jetstream",
        "nats",
        "redis",
    ];
    for sys in &expected {
        assert!(
            conditions.contains_key(*sys),
            "missing transient conditions for: {sys}"
        );
        assert!(
            !conditions[*sys].as_array().unwrap().is_empty(),
            "empty transient conditions for: {sys}"
        );
    }
}

#[test]
fn error_method_parity_tracks_backend_status() {
    let json: serde_json::Value = serde_json::from_str(include_str!(
        "../docs/tokio_retry_idempotency_failure_contracts.json"
    ))
    .expect("valid JSON");
    let err04 = json["contracts"]["error_classification"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "C-ERR-04")
        .expect("C-ERR-04");

    let methods = err04["required_methods"].as_array().unwrap();
    assert!(
        methods.len() >= 7,
        "need at least 7 error classification methods"
    );

    let backend_status = err04["backend_status"].as_object().unwrap();
    assert!(backend_status.contains_key("postgresql"));
    assert!(backend_status.contains_key("mysql"));
    assert!(backend_status.contains_key("sqlite"));
}

#[test]
fn postgresql_has_partial_error_methods() {
    let json: serde_json::Value = serde_json::from_str(include_str!(
        "../docs/tokio_retry_idempotency_failure_contracts.json"
    ))
    .expect("valid JSON");
    let err04 = json["contracts"]["error_classification"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "C-ERR-04")
        .expect("C-ERR-04");
    let pg = &err04["backend_status"]["postgresql"];
    assert_eq!(
        pg["is_serialization_failure"].as_str().unwrap(),
        "implemented"
    );
    assert_eq!(pg["is_deadlock"].as_str().unwrap(), "implemented");
    assert_eq!(pg["is_unique_violation"].as_str().unwrap(), "implemented");
    assert_eq!(
        pg["is_transient"].as_str().unwrap(),
        "implemented",
        "is_transient now implemented"
    );
}

#[test]
fn mysql_error_methods_document_gaps() {
    let json: serde_json::Value = serde_json::from_str(include_str!(
        "../docs/tokio_retry_idempotency_failure_contracts.json"
    ))
    .expect("valid JSON");
    let err04 = json["contracts"]["error_classification"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "C-ERR-04")
        .expect("C-ERR-04");
    let mysql = &err04["backend_status"]["mysql"];
    // MySQL now has all classification methods implemented
    let impl_count = mysql
        .as_object()
        .unwrap()
        .values()
        .filter(|v: &&serde_json::Value| v.as_str().unwrap() == "implemented")
        .count();
    assert!(
        impl_count >= 6,
        "MySQL should have most methods implemented, found {impl_count}"
    );
}

// ── Section 5: Idempotency contracts ────────────────────────────────

#[test]
fn producer_idempotency_covers_key_systems() {
    let json: serde_json::Value = serde_json::from_str(include_str!(
        "../docs/tokio_retry_idempotency_failure_contracts.json"
    ))
    .expect("valid JSON");
    let imp01 = json["contracts"]["idempotency"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "C-IMP-01")
        .expect("C-IMP-01");
    let systems = imp01["systems"].as_object().unwrap();
    assert!(systems.contains_key("kafka"));
    assert!(systems.contains_key("jetstream"));

    let kafka = &systems["kafka"];
    assert_eq!(kafka["mechanism"].as_str().unwrap(), "sequence_numbers");
    let js = &systems["jetstream"];
    assert_eq!(js["mechanism"].as_str().unwrap(), "duplicate_window");
}

#[test]
fn consumer_idempotency_defines_strategies() {
    let json: serde_json::Value = serde_json::from_str(include_str!(
        "../docs/tokio_retry_idempotency_failure_contracts.json"
    ))
    .expect("valid JSON");
    let imp02 = json["contracts"]["idempotency"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "C-IMP-02")
        .expect("C-IMP-02");
    let systems = imp02["systems"].as_object().unwrap();
    assert!(systems.contains_key("kafka"));
    assert!(systems.contains_key("jetstream"));
    assert!(systems.contains_key("database"));
}

#[test]
fn request_level_idempotency_key_contract_defined() {
    let json: serde_json::Value = serde_json::from_str(include_str!(
        "../docs/tokio_retry_idempotency_failure_contracts.json"
    ))
    .expect("valid JSON");
    let imp03 = json["contracts"]["idempotency"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "C-IMP-03")
        .expect("C-IMP-03");
    let fields: Vec<&str> = imp03["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["name"].as_str().unwrap())
        .collect();
    assert!(fields.contains(&"idempotency_key"));
    assert!(fields.contains(&"ttl"));
}

// ── Section 6: Delivery guarantee contracts ─────────────────────────

#[test]
fn delivery_semantics_matrix_covers_all_systems() {
    let json: serde_json::Value = serde_json::from_str(include_str!(
        "../docs/tokio_retry_idempotency_failure_contracts.json"
    ))
    .expect("valid JSON");
    let dlv01 = json["contracts"]["delivery"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "C-DLV-01")
        .expect("C-DLV-01");
    let systems = dlv01["systems"].as_object().unwrap();
    let expected = [
        "postgresql",
        "mysql",
        "sqlite",
        "kafka",
        "jetstream",
        "nats_core",
        "redis_pubsub",
    ];
    for sys in &expected {
        assert!(
            systems.contains_key(*sys),
            "missing delivery semantics for: {sys}"
        );
    }
}

#[test]
fn databases_have_exactly_once_delivery() {
    let json: serde_json::Value = serde_json::from_str(include_str!(
        "../docs/tokio_retry_idempotency_failure_contracts.json"
    ))
    .expect("valid JSON");
    let dlv01 = json["contracts"]["delivery"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "C-DLV-01")
        .expect("C-DLV-01");
    for db in &["postgresql", "mysql", "sqlite"] {
        let sys = &dlv01["systems"][db];
        assert_eq!(
            sys["default"].as_str().unwrap(),
            "exactly_once",
            "{db} default should be exactly_once"
        );
    }
}

#[test]
fn fire_and_forget_systems_are_at_most_once() {
    let json: serde_json::Value = serde_json::from_str(include_str!(
        "../docs/tokio_retry_idempotency_failure_contracts.json"
    ))
    .expect("valid JSON");
    let dlv01 = json["contracts"]["delivery"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "C-DLV-01")
        .expect("C-DLV-01");
    for sys_name in &["nats_core", "redis_pubsub"] {
        let sys = &dlv01["systems"][sys_name];
        assert_eq!(
            sys["default"].as_str().unwrap(),
            "at_most_once",
            "{sys_name} should be at_most_once"
        );
    }
}

#[test]
fn acknowledgement_contract_covers_ack_systems() {
    let json: serde_json::Value = serde_json::from_str(include_str!(
        "../docs/tokio_retry_idempotency_failure_contracts.json"
    ))
    .expect("valid JSON");
    let dlv02 = json["contracts"]["delivery"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "C-DLV-02")
        .expect("C-DLV-02");
    let systems = dlv02["systems"].as_object().unwrap();
    assert!(systems.contains_key("kafka"));
    assert!(systems.contains_key("jetstream"));
    assert!(systems.contains_key("database"));
}

// ── Section 7: Failure propagation contracts ────────────────────────

#[test]
fn circuit_breaker_integration_requirements_defined() {
    let json: serde_json::Value = serde_json::from_str(include_str!(
        "../docs/tokio_retry_idempotency_failure_contracts.json"
    ))
    .expect("valid JSON");
    let fpr01 = json["contracts"]["failure_propagation"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "C-FPR-01")
        .expect("C-FPR-01");
    let reqs: Vec<&str> = fpr01["requirements"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v: &serde_json::Value| v.as_str().unwrap())
        .collect();
    assert!(reqs.contains(&"open_circuit_stops_retry"));
    assert!(reqs.contains(&"half_open_probes_not_retry_attempts"));
    assert!(
        fpr01["reference"]
            .as_str()
            .unwrap()
            .contains("circuit_breaker"),
        "must reference circuit_breaker module"
    );
}

#[test]
fn rate_limiter_integration_requirements_defined() {
    let json: serde_json::Value = serde_json::from_str(include_str!(
        "../docs/tokio_retry_idempotency_failure_contracts.json"
    ))
    .expect("valid JSON");
    let fpr02 = json["contracts"]["failure_propagation"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "C-FPR-02")
        .expect("C-FPR-02");
    let reqs: Vec<&str> = fpr02["requirements"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v: &serde_json::Value| v.as_str().unwrap())
        .collect();
    assert!(reqs.contains(&"rate_limit_rejection_not_retryable"));
    assert!(reqs.contains(&"retry_delay_respects_token_availability"));
}

#[test]
fn failure_escalation_chain_preserves_errors() {
    let json: serde_json::Value = serde_json::from_str(include_str!(
        "../docs/tokio_retry_idempotency_failure_contracts.json"
    ))
    .expect("valid JSON");
    let fpr03 = json["contracts"]["failure_propagation"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "C-FPR-03")
        .expect("C-FPR-03");
    assert_eq!(
        fpr03["requirement"].as_str().unwrap(),
        "preserve_original_error"
    );
    let chain = fpr03["chain"].as_array().unwrap();
    assert!(chain.len() >= 4, "escalation chain needs at least 4 steps");
    assert_eq!(chain[0].as_str().unwrap(), "operation_error");
}

// ── Section 8: Backpressure contracts ───────────────────────────────

#[test]
fn queue_depth_signals_defined() {
    let json: serde_json::Value = serde_json::from_str(include_str!(
        "../docs/tokio_retry_idempotency_failure_contracts.json"
    ))
    .expect("valid JSON");
    let bpr01 = json["contracts"]["backpressure"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "C-BPR-01")
        .expect("C-BPR-01");
    let signals = bpr01["signals"].as_object().unwrap();
    assert!(signals.contains_key("connection_pool"));
    assert!(signals.contains_key("kafka_producer"));
    assert!(signals.contains_key("rate_limiter"));
}

#[test]
fn timeout_backpressure_requirements() {
    let json: serde_json::Value = serde_json::from_str(include_str!(
        "../docs/tokio_retry_idempotency_failure_contracts.json"
    ))
    .expect("valid JSON");
    let bpr02 = json["contracts"]["backpressure"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "C-BPR-02")
        .expect("C-BPR-02");
    let reqs: Vec<&str> = bpr02["requirements"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v: &serde_json::Value| v.as_str().unwrap())
        .collect();
    assert!(reqs.contains(&"connection_timeout_prevents_unbounded_wait"));
    assert!(reqs.contains(&"retry_budget_prevents_retry_storms"));
    assert!(reqs.contains(&"all_timeouts_respect_cx_cancellation"));
}

// ── Section 9: Summary consistency ──────────────────────────────────

#[test]
fn summary_domain_counts_match() {
    let json: serde_json::Value = serde_json::from_str(include_str!(
        "../docs/tokio_retry_idempotency_failure_contracts.json"
    ))
    .expect("valid JSON");
    let contracts = json["contracts"].as_object().unwrap();
    let summary = json["summary"]["domains"].as_object().unwrap();

    for (domain, items) in contracts {
        let actual_count = items.as_array().unwrap().len() as u64;
        let declared_count = summary[domain.as_str()]["count"].as_u64().unwrap();
        assert_eq!(
            actual_count, declared_count,
            "domain {domain}: declared {declared_count} but found {actual_count}"
        );
    }
}

#[test]
fn summary_status_counts_are_consistent() {
    let json: serde_json::Value = serde_json::from_str(include_str!(
        "../docs/tokio_retry_idempotency_failure_contracts.json"
    ))
    .expect("valid JSON");
    let contracts = json["contracts"].as_object().unwrap();
    let summary_domains = json["summary"]["domains"].as_object().unwrap();

    for (domain, items) in contracts {
        let items: &Vec<serde_json::Value> = items.as_array().unwrap();
        let mut implemented = 0u64;
        let mut partial = 0u64;
        let mut defined = 0u64;
        let mut not_implemented = 0u64;

        for item in items {
            match item["status"].as_str().unwrap() {
                "implemented" => implemented += 1,
                "partial" => partial += 1,
                "defined" => defined += 1,
                "not_implemented" => not_implemented += 1,
                other => {
                    assert!(
                        other.starts_with("delegates"),
                        "unknown status '{other}' in {domain}"
                    );
                }
            }
        }

        let s = &summary_domains[domain.as_str()];
        assert_eq!(
            s["implemented"].as_u64().unwrap(),
            implemented,
            "{domain}: implemented mismatch"
        );
        assert_eq!(
            s["partial"].as_u64().unwrap(),
            partial,
            "{domain}: partial mismatch"
        );
        assert_eq!(
            s["defined"].as_u64().unwrap(),
            defined,
            "{domain}: defined mismatch"
        );
        assert_eq!(
            s["not_implemented"].as_u64().unwrap(),
            not_implemented,
            "{domain}: not_implemented mismatch"
        );
    }
}

#[test]
fn summary_systems_list_complete() {
    let json: serde_json::Value = serde_json::from_str(include_str!(
        "../docs/tokio_retry_idempotency_failure_contracts.json"
    ))
    .expect("valid JSON");
    let systems: Vec<&str> = json["summary"]["systems"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v: &serde_json::Value| v.as_str().unwrap())
        .collect();
    assert!(systems.contains(&"postgresql"));
    assert!(systems.contains(&"mysql"));
    assert!(systems.contains(&"sqlite"));
    assert!(systems.contains(&"kafka"));
    assert!(systems.contains(&"jetstream"));
}

#[test]
fn summary_blocking_gaps_have_severity() {
    let json: serde_json::Value = serde_json::from_str(include_str!(
        "../docs/tokio_retry_idempotency_failure_contracts.json"
    ))
    .expect("valid JSON");
    let gaps = json["summary"]["blocking_gaps"].as_array().unwrap();
    assert!(!gaps.is_empty(), "must have blocking gaps");
    for gap in gaps {
        assert!(gap["id"].as_str().is_some(), "gap must have id");
        assert!(gap["severity"].as_str().is_some(), "gap must have severity");
        assert!(
            gap["description"].as_str().is_some(),
            "gap must have description"
        );
    }
}

// ── Section 10: Source module validation ─────────────────────────────

#[test]
fn source_modules_reference_real_paths() {
    let json: serde_json::Value = serde_json::from_str(include_str!(
        "../docs/tokio_retry_idempotency_failure_contracts.json"
    ))
    .expect("valid JSON");
    let modules = json["source_modules"].as_object().unwrap();
    let expected = [
        "retry_combinator",
        "circuit_breaker",
        "rate_limiter",
        "transaction",
        "postgres",
        "mysql",
        "sqlite",
        "kafka",
        "jetstream",
        "nats",
        "redis",
    ];
    for key in &expected {
        assert!(
            modules.contains_key(*key),
            "missing source module key: {key}"
        );
        let path = modules[*key].as_str().unwrap();
        assert!(
            path.starts_with("src/"),
            "path must start with src/: {path}"
        );
        assert!(
            std::path::Path::new(path)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("rs")),
            "path must end with .rs: {path}"
        );
    }
}

// ── Section 11: Dependency tracking ─────────────────────────────────

#[test]
fn dependencies_track_upstream_beads() {
    let json: serde_json::Value = serde_json::from_str(include_str!(
        "../docs/tokio_retry_idempotency_failure_contracts.json"
    ))
    .expect("valid JSON");
    let blocked_by = json["dependencies"]["blocked_by"].as_array().unwrap();
    assert!(
        blocked_by
            .iter()
            .map(|b| b["bead"].as_str().unwrap())
            .any(|x| x == "asupersync-2oh2u.6.5"),
        "must be blocked by T6.5"
    );
}

#[test]
fn dependencies_track_downstream_beads() {
    let json: serde_json::Value = serde_json::from_str(include_str!(
        "../docs/tokio_retry_idempotency_failure_contracts.json"
    ))
    .expect("valid JSON");
    let blocks = json["dependencies"]["blocks"].as_array().unwrap();
    assert!(
        blocks
            .iter()
            .map(|b| b["bead"].as_str().unwrap())
            .any(|x| x == "asupersync-2oh2u.6.12"),
        "must block T6.12"
    );
}

// ── Section 12: Markdown-JSON cross-reference ───────────────────────

#[test]
fn all_json_contract_ids_appear_in_markdown() {
    let md = include_str!("../docs/tokio_retry_idempotency_failure_contracts.md");
    let json: serde_json::Value = serde_json::from_str(include_str!(
        "../docs/tokio_retry_idempotency_failure_contracts.json"
    ))
    .expect("valid JSON");
    let contracts = json["contracts"].as_object().unwrap();
    for (_domain, items) in contracts {
        for item in items.as_array().unwrap() {
            let id = item["id"].as_str().unwrap();
            assert!(md.contains(id), "JSON contract {id} missing from markdown");
        }
    }
}

#[test]
fn all_json_source_modules_appear_in_markdown() {
    let md = include_str!("../docs/tokio_retry_idempotency_failure_contracts.md");
    let json: serde_json::Value = serde_json::from_str(include_str!(
        "../docs/tokio_retry_idempotency_failure_contracts.json"
    ))
    .expect("valid JSON");
    let modules = json["source_modules"].as_object().unwrap();
    for (_key, path) in modules {
        let path = path.as_str().unwrap();
        assert!(
            md.contains(path),
            "JSON source module {path} missing from markdown"
        );
    }
}

#[test]
fn markdown_retry_eligibility_matches_json() {
    let md = include_str!("../docs/tokio_retry_idempotency_failure_contracts.md");
    let json: serde_json::Value = serde_json::from_str(include_str!(
        "../docs/tokio_retry_idempotency_failure_contracts.json"
    ))
    .expect("valid JSON");
    let rty02 = json["contracts"]["retry"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "C-RTY-02")
        .expect("C-RTY-02");

    // PostgreSQL eligibility should mention 40001 in both
    let pg_eligible = &rty02["eligibility"]["postgresql"];
    for code in pg_eligible.as_array().unwrap() {
        let code_str = code.as_str().unwrap();
        // Extract the numeric part for checking markdown
        if code_str.contains("40001") {
            assert!(
                md.contains("40001"),
                "markdown must mention SQLSTATE 40001 for PostgreSQL"
            );
        }
    }
}

#[test]
fn markdown_delivery_semantics_consistent_with_json() {
    let md = include_str!("../docs/tokio_retry_idempotency_failure_contracts.md");

    // Verify key delivery semantics mentioned in markdown
    assert!(
        md.contains("At-most-once") || md.contains("at-most-once"),
        "must document at-most-once delivery"
    );
    assert!(
        md.contains("At-least-once") || md.contains("at-least-once"),
        "must document at-least-once delivery"
    );
    assert!(
        md.contains("Exactly-once") || md.contains("exactly-once"),
        "must document exactly-once delivery"
    );
}
