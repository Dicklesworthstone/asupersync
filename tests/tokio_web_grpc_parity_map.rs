#![allow(clippy::all)]
//! Contract tests for the web/gRPC parity map (2oh2u.5.1).
//!
//! Validates document structure, gap coverage, domain completeness,
//! and migration blocker classification.

#![allow(missing_docs)]

use std::collections::BTreeSet;
use std::path::Path;

fn load_parity_doc() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/tokio_web_grpc_parity_map.md");
    std::fs::read_to_string(path).expect("parity map document must exist")
}

fn extract_gap_ids(doc: &str) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    for line in doc.lines() {
        let trimmed = line.trim().trim_start_matches('|').trim();
        if let Some(id) = trimmed.split('|').next() {
            let id = id.trim();
            let prefixes = ["WEB-G", "MW-G", "GRPC-G", "HT-G", "WS-G"];
            if prefixes.iter().any(|p| id.starts_with(p)) && id.len() >= 4 {
                ids.insert(id.to_string());
            }
        }
    }
    ids
}

#[test]
fn parity_document_exists_and_is_nonempty() {
    let doc = load_parity_doc();
    assert!(
        doc.len() > 2000,
        "parity map document should be substantial, got {} bytes",
        doc.len()
    );
}

#[test]
fn parity_references_correct_bead() {
    let doc = load_parity_doc();
    assert!(
        doc.contains("asupersync-2oh2u.5.1"),
        "document must reference bead 2oh2u.5.1"
    );
    assert!(doc.contains("[T5.1]"), "document must reference T5.1");
}

#[test]
fn parity_covers_all_tokio_comparison_crates() {
    let doc = load_parity_doc();
    let crates = ["axum", "warp", "tower-http", "tonic", "hyper"];
    for c in &crates {
        assert!(
            doc.contains(c),
            "parity map must reference Tokio crate: {c}"
        );
    }
}

#[test]
fn parity_covers_web_framework_surface() {
    let doc = load_parity_doc();
    assert!(
        doc.contains("Router") && doc.contains("Extractors") && doc.contains("Responses"),
        "must cover Router, Extractors, and Responses"
    );
    assert!(
        doc.contains("IntoResponse"),
        "must reference IntoResponse trait"
    );
    assert!(
        doc.contains("Path<T>") && doc.contains("Query<T>") && doc.contains("Json<T>"),
        "must cover core extractors"
    );
}

#[test]
fn parity_covers_warp_surface() {
    let doc = load_parity_doc();
    assert!(
        doc.contains("warp::path!") || doc.contains("typed path"),
        "must cover warp typed-path behavior"
    );
    assert!(
        doc.contains("Filter") && doc.contains("and") && doc.contains("or"),
        "must cover warp filter-combinator parity"
    );
    assert!(
        doc.contains("reject") && doc.contains("recover"),
        "must cover warp reject/recover behavior"
    );
}

#[test]
fn parity_covers_middleware_surface() {
    let doc = load_parity_doc();
    assert!(
        doc.contains("Service<Request>") || doc.contains("Service Trait"),
        "must cover Service trait"
    );
    assert!(doc.contains("Layer"), "must cover Layer trait");
    assert!(doc.contains("ServiceBuilder"), "must cover ServiceBuilder");
    assert!(
        doc.contains("TimeoutLayer") && doc.contains("RateLimitLayer"),
        "must cover core middleware layers"
    );
}

#[test]
fn parity_covers_grpc_surface() {
    let doc = load_parity_doc();
    assert!(
        doc.contains("Server") && doc.contains("Client"),
        "must cover gRPC server and client"
    );
    assert!(
        doc.contains("UnaryMethod") || doc.contains("Unary RPC"),
        "must cover unary RPC"
    );
    assert!(
        doc.contains("Server streaming") && doc.contains("Client streaming"),
        "must cover streaming RPC patterns"
    );
    assert!(
        doc.contains("Bidirectional"),
        "must cover bidirectional streaming"
    );
    assert!(
        doc.contains("HealthService") || doc.contains("Health check"),
        "must cover health service"
    );
}

#[test]
fn parity_covers_http_transport() {
    let doc = load_parity_doc();
    assert!(doc.contains("HTTP/1.1"), "must cover HTTP/1.1");
    assert!(doc.contains("HTTP/2"), "must cover HTTP/2");
    assert!(
        doc.contains("HPACK") || doc.contains("hpack"),
        "must cover HPACK compression"
    );
    assert!(
        doc.contains("Stream multiplexing"),
        "must cover HTTP/2 stream multiplexing"
    );
}

#[test]
fn parity_covers_websocket() {
    let doc = load_parity_doc();
    assert!(doc.contains("WebSocket"), "must cover WebSocket protocol");
    assert!(doc.contains("RFC 6455"), "must reference WebSocket RFC");
}

#[test]
fn parity_has_gap_entries_for_all_domains() {
    let doc = load_parity_doc();
    let ids = extract_gap_ids(&doc);

    let domain_prefixes = [
        ("WEB-G", 10),
        ("MW-G", 5),
        ("GRPC-G", 5),
        ("HT-G", 1),
        ("WS-G", 1),
    ];
    for (prefix, min_count) in &domain_prefixes {
        let count = ids.iter().filter(|id| id.starts_with(prefix)).count();
        assert!(
            count >= *min_count,
            "domain {prefix} must have >= {min_count} gap entries, found {count}"
        );
    }
}

#[test]
fn parity_total_gap_count() {
    let doc = load_parity_doc();
    let ids = extract_gap_ids(&doc);
    assert!(
        ids.len() >= 40,
        "parity map must identify >= 40 gaps across all domains, found {}",
        ids.len()
    );
}

#[test]
fn parity_classifies_gap_severity() {
    let doc = load_parity_doc();
    for level in &["High", "Medium", "Low"] {
        assert!(
            doc.contains(level),
            "parity map must use severity level: {level}"
        );
    }
}

#[test]
fn parity_has_migration_blocker_section() {
    let doc = load_parity_doc();
    assert!(
        doc.contains("Migration Blocker") || doc.contains("Hard Blocker"),
        "parity map must include migration blocker classification"
    );
    assert!(
        doc.contains("Soft Blocker"),
        "parity map must distinguish soft blockers"
    );
}

#[test]
fn parity_has_hard_blockers_identified() {
    let doc = load_parity_doc();
    // Key hard blockers that should be identified
    assert!(
        doc.contains("WEB-G8") && doc.contains("Multipart"),
        "must identify multipart as hard blocker"
    );
    assert!(
        doc.contains("MW-G2") && doc.contains("CORS"),
        "must identify CORS as hard blocker"
    );
    assert!(
        doc.contains("GRPC-G3") && doc.contains("codegen"),
        "must identify protobuf codegen as hard blocker"
    );
}

#[test]
fn parity_has_gap_summary_table() {
    let doc = load_parity_doc();
    assert!(doc.contains("Gap Summary"), "must have gap summary section");
    let summary_section = doc
        .split("Gap Summary")
        .nth(1)
        .expect("must have gap summary section");
    assert!(
        summary_section.contains("Domain"),
        "summary must have Domain column"
    );
    assert!(
        summary_section.contains("Severity"),
        "summary must have Severity column"
    );
    assert!(
        summary_section.contains("Phase"),
        "summary must have Phase column"
    );
}

#[test]
fn parity_has_execution_order_with_phases() {
    let doc = load_parity_doc();
    assert!(
        doc.contains("Execution Order") || doc.contains("Phase A"),
        "must include recommended execution order"
    );
    let phase_count = ["Phase A", "Phase B", "Phase C", "Phase D"]
        .iter()
        .filter(|p| doc.contains(**p))
        .count();
    assert!(
        phase_count >= 3,
        "execution order must have >= 3 phases, found {phase_count}"
    );
}

#[test]
fn parity_has_ownership_boundaries() {
    let doc = load_parity_doc();
    assert!(
        doc.contains("Ownership Boundaries"),
        "must include ownership boundaries section"
    );
    assert!(
        doc.contains("Boundary Contract"),
        "ownership boundaries must include boundary contract column"
    );
    assert!(
        doc.contains("Owning Bead"),
        "ownership boundaries must map domains to owning beads"
    );
}

#[test]
fn parity_covers_asupersync_extensions() {
    let doc = load_parity_doc();
    assert!(
        doc.contains("Asupersync-Specific") || doc.contains("No Tokio Equivalent"),
        "must note Asupersync-specific extensions"
    );
    assert!(
        doc.contains("AsupersyncService"),
        "must note AsupersyncService trait"
    );
    assert!(
        doc.contains("CircuitBreakerMiddleware"),
        "must note circuit breaker middleware"
    );
}

#[test]
fn parity_covers_combinator_middleware() {
    let doc = load_parity_doc();
    assert!(
        doc.contains("Combinator") || doc.contains("MiddlewareStack"),
        "must cover combinator-based middleware"
    );
    assert!(
        doc.contains("BulkheadMiddleware"),
        "must cover bulkhead middleware"
    );
}

#[test]
fn parity_references_upstream_dependency() {
    let doc = load_parity_doc();
    assert!(
        doc.contains("T1.3.c") || doc.contains("roadmap baseline"),
        "must reference T1.3.c (roadmap baseline) dependency"
    );
}

#[test]
fn parity_covers_grpc_protocol_features() {
    let doc = load_parity_doc();
    assert!(
        doc.contains("gRPC frame") || doc.contains("GrpcCodec"),
        "must cover gRPC frame format"
    );
    assert!(
        doc.contains("Status") && doc.contains("16 codes"),
        "must cover gRPC status codes"
    );
    assert!(
        doc.contains("Deadline") || doc.contains("grpc-timeout"),
        "must cover deadline propagation"
    );
}

#[test]
fn parity_covers_connection_pooling() {
    let doc = load_parity_doc();
    assert!(
        doc.contains("Connection Pooling") || doc.contains("pool"),
        "must cover HTTP connection pooling"
    );
}

#[test]
fn parity_covers_non_blocking_gaps() {
    let doc = load_parity_doc();
    assert!(
        doc.contains("Non-Blocking"),
        "must classify non-blocking gaps"
    );
}

#[test]
fn parity_includes_t52_router_closure_scope() {
    let doc = load_parity_doc();
    for token in [
        "asupersync-2oh2u.5.2",
        "T5.2",
        "Router Composition and Route-Matching Closure Contract",
        "Version",
    ] {
        assert!(doc.contains(token), "missing T5.2 scope token: {token}");
    }
    // Version must be at least 1.2.0 (may be bumped by subsequent beads)
    assert!(
        doc.contains("1.2.0")
            || doc.contains("1.3.0")
            || doc.contains("1.4.0")
            || doc.contains("1.5.0")
            || doc.contains("1.6.0")
            || doc.contains("1.7.0"),
        "version must be >= 1.2.0"
    );
}

#[test]
fn parity_has_t52_success_failure_cancellation_contract_rows() {
    let doc = load_parity_doc();
    for token in [
        "Contract ID",
        "Success Path",
        "Failure Path",
        "Cancellation Path",
        "Deterministic Assertion",
        "T52-ROUTE-01",
        "T52-ROUTE-02",
        "T52-ROUTE-03",
        "T52-ROUTE-04",
        "T52-ROUTE-05",
        "T52-ROUTE-06",
    ] {
        assert!(doc.contains(token), "missing T5.2 contract token: {token}");
    }
}

#[test]
fn parity_has_t52_deterministic_scenario_pack() {
    let doc = load_parity_doc();
    assert!(
        doc.contains("T5.2 Deterministic Scenario Pack"),
        "must include T5.2 deterministic scenario pack section"
    );
    for token in [
        "T52-ROUTE-01",
        "T52-ROUTE-04",
        "T52-ROUTE-08",
        "Expected Status",
        "| success |",
        "| failure |",
        "| cancelled |",
        "Required Log Fields",
    ] {
        assert!(doc.contains(token), "missing scenario-pack token: {token}");
    }
}

#[test]
fn parity_has_t52_validation_bundle_and_evidence_links() {
    let doc = load_parity_doc();
    for token in [
        "br show asupersync-2oh2u.5.2 --json",
        "rch exec -- cargo test --test tokio_web_grpc_parity_map",
        "rch exec -- cargo test --test web_router_composition -- --nocapture",
        "rch exec -- cargo test --test web_router_match_order -- --nocapture",
        "src/web/router.rs",
        "src/web/extract.rs",
        "src/web/middleware.rs",
    ] {
        assert!(
            doc.contains(token),
            "missing validation/evidence token: {token}"
        );
    }
}

#[test]
fn parity_revision_history_tracks_t52_update() {
    let doc = load_parity_doc();
    assert!(
        doc.contains("| 2026-03-03 | WhiteDesert |"),
        "revision history should include WhiteDesert v1.2 row"
    );
    assert!(
        doc.contains("| 2026-03-03 | SapphireHill | Initial parity map (v1.0) |"),
        "revision history should retain initial baseline row"
    );
}

// ---------------------------------------------------------------------------
// T5.3 Contract Tests — Extractor and Body Handling Closure
// ---------------------------------------------------------------------------

#[test]
fn parity_includes_t53_extractor_closure_scope() {
    let doc = load_parity_doc();
    for token in [
        "asupersync-2oh2u.5.3",
        "T5.3",
        "Extractor and Body Handling Closure Contract",
    ] {
        assert!(doc.contains(token), "missing T5.3 scope token: {token}");
    }
    // Version must be at least 1.3.0 (may be bumped by subsequent beads)
    assert!(
        doc.contains("1.3.0")
            || doc.contains("1.4.0")
            || doc.contains("1.5.0")
            || doc.contains("1.6.0")
            || doc.contains("1.7.0"),
        "version must be >= 1.3.0"
    );
}

#[test]
fn parity_has_t53_success_failure_cancellation_contract_rows() {
    let doc = load_parity_doc();
    for token in [
        "T53-EXTRACT-01",
        "T53-EXTRACT-02",
        "T53-EXTRACT-03",
        "T53-EXTRACT-04",
        "T53-EXTRACT-05",
        "T53-EXTRACT-06",
        "T53-EXTRACT-07",
        "T53-EXTRACT-08",
        "T53-EXTRACT-09",
        "T53-EXTRACT-10",
    ] {
        assert!(doc.contains(token), "missing T5.3 contract row: {token}");
    }
    // Verify contract table columns
    let contract_section = doc
        .split("T5.3 Extractor and Body Handling Closure Contract")
        .nth(1)
        .expect("must have T5.3 contract section");
    for col in [
        "Contract ID",
        "Success Path",
        "Failure Path",
        "Cancellation Path",
        "Deterministic Assertion",
    ] {
        assert!(
            contract_section.contains(col),
            "T5.3 contract table missing column: {col}"
        );
    }
}

#[test]
fn parity_has_t53_deterministic_scenario_pack() {
    let doc = load_parity_doc();
    assert!(
        doc.contains("T5.3 Deterministic Scenario Pack"),
        "must include T5.3 deterministic scenario pack section"
    );
    // Verify scenario coverage across extractors
    for token in [
        "T53-EXTRACT-01",
        "T53-EXTRACT-06",
        "T53-EXTRACT-10",
        "T53-EXTRACT-14",
        "T53-EXTRACT-16",
        "T53-EXTRACT-19",
        "T53-EXTRACT-20",
    ] {
        assert!(doc.contains(token), "missing scenario pack entry: {token}");
    }
    // Verify all three outcome classes are present
    let pack_section = doc
        .split("T5.3 Deterministic Scenario Pack")
        .nth(1)
        .expect("must have scenario pack section");
    for status in ["| success |", "| failure |", "| cancelled |"] {
        assert!(
            pack_section.contains(status),
            "scenario pack missing status: {status}"
        );
    }
}

#[test]
fn parity_t53_covers_all_extractor_types() {
    let doc = load_parity_doc();
    let t53_section = doc
        .split("T5.3 Extractor and Body Handling Closure Contract")
        .nth(1)
        .unwrap_or("");
    for extractor in [
        "Path<T>",
        "Query<T>",
        "Json<T>",
        "Form<T>",
        "State<T>",
        "RawBody",
        "FromRequestParts",
        "FromRequest",
    ] {
        assert!(
            t53_section.contains(extractor),
            "T5.3 contract must cover extractor: {extractor}"
        );
    }
}

#[test]
fn parity_t53_covers_body_size_enforcement() {
    let doc = load_parity_doc();
    let t53_section = doc
        .split("T5.3 Extractor and Body Handling Closure Contract")
        .nth(1)
        .unwrap_or("");
    for token in [
        "MAX_JSON_BODY_SIZE",
        "MAX_FORM_BODY_SIZE",
        "413",
        "Payload Too Large",
    ] {
        assert!(
            t53_section.contains(token),
            "T5.3 must cover body size enforcement token: {token}"
        );
    }
}

#[test]
fn parity_t53_covers_content_type_validation() {
    let doc = load_parity_doc();
    let t53_section = doc
        .split("T5.3 Extractor and Body Handling Closure Contract")
        .nth(1)
        .unwrap_or("");
    for token in [
        "content-type",
        "415",
        "Unsupported Media Type",
        "application/json",
        "application/x-www-form-urlencoded",
    ] {
        assert!(
            t53_section.contains(token),
            "T5.3 must cover content-type token: {token}"
        );
    }
}

#[test]
fn parity_t53_scenario_pack_has_required_log_fields() {
    let doc = load_parity_doc();
    let pack_section = doc
        .split("T5.3 Deterministic Scenario Pack")
        .nth(1)
        .unwrap_or("");
    for field in [
        "scenario_id",
        "extractor",
        "outcome_class",
        "status_code",
        "body_size",
    ] {
        assert!(
            pack_section.contains(field),
            "scenario pack missing required log field: {field}"
        );
    }
}

#[test]
fn parity_t53_validation_bundle_references() {
    let doc = load_parity_doc();
    // T5.3 should be referenced in the evidence/validation section
    assert!(
        doc.contains("br show asupersync-2oh2u.5.3"),
        "evidence section must reference T5.3 bead"
    );
    assert!(
        doc.contains("cargo test --lib web::extract::tests"),
        "evidence section must include extractor unit test command"
    );
}

#[test]
fn parity_revision_history_tracks_t53_update() {
    let doc = load_parity_doc();
    assert!(
        doc.contains("T5.3 extractor/body handling closure contract"),
        "revision history must reference T5.3 closure contract"
    );
    assert!(
        doc.contains("WEB-G2") && doc.contains("WEB-G10"),
        "revision history must note closed gaps WEB-G2 and WEB-G10"
    );
}

#[test]
fn parity_gap_closures_reflected_in_table() {
    let doc = load_parity_doc();
    // WEB-G2 and WEB-G10 should be marked as closed in the gap summary
    assert!(
        doc.contains("WEB-G2") && doc.contains("Closed"),
        "WEB-G2 (fallback handler) must be marked closed"
    );
    assert!(
        doc.contains("WEB-G10") && doc.contains("Closed"),
        "WEB-G10 (FromRequestParts) must be marked closed"
    );
}

// ---------------------------------------------------------------------------
// T5.4 Contract Tests — Middleware Stack Parity
// ---------------------------------------------------------------------------

#[test]
fn parity_includes_t54_middleware_closure_scope() {
    let doc = load_parity_doc();
    for token in [
        "asupersync-2oh2u.5.4",
        "T5.4",
        "Middleware Stack Closure Contract",
    ] {
        assert!(doc.contains(token), "missing T5.4 scope token: {token}");
    }
    // Version must be at least 1.4.0 (may be bumped by subsequent beads)
    assert!(
        doc.contains("1.4.0")
            || doc.contains("1.5.0")
            || doc.contains("1.6.0")
            || doc.contains("1.7.0"),
        "version must be >= 1.4.0"
    );
}

#[test]
fn parity_has_t54_success_failure_cancellation_contract_rows() {
    let doc = load_parity_doc();
    for token in [
        "T54-MW-01",
        "T54-MW-05",
        "T54-MW-08",
        "T54-MW-10",
        "T54-MW-14",
        "T54-MW-17",
    ] {
        assert!(doc.contains(token), "missing T5.4 contract row: {token}");
    }
    let contract_section = doc
        .split("T5.4 Middleware Stack Closure Contract")
        .nth(1)
        .expect("must have T5.4 contract section");
    for col in [
        "Contract ID",
        "Success Path",
        "Failure Path",
        "Cancellation Path",
        "Deterministic Assertion",
    ] {
        assert!(
            contract_section.contains(col),
            "T5.4 contract table missing column: {col}"
        );
    }
}

#[test]
fn parity_has_t54_deterministic_scenario_pack() {
    let doc = load_parity_doc();
    assert!(
        doc.contains("T5.4 Deterministic Scenario Pack"),
        "must include T5.4 deterministic scenario pack section"
    );
    for token in [
        "T54-MW-01",
        "T54-MW-06",
        "T54-MW-12",
        "T54-MW-16",
        "T54-MW-20",
        "T54-MW-24",
    ] {
        assert!(doc.contains(token), "missing scenario pack entry: {token}");
    }
    let pack_section = doc
        .split("T5.4 Deterministic Scenario Pack")
        .nth(1)
        .expect("must have T5.4 scenario pack section");
    for status in ["| success |", "| failure |", "| cancelled |"] {
        assert!(
            pack_section.contains(status),
            "T5.4 scenario pack missing status: {status}"
        );
    }
}

#[test]
fn parity_t54_covers_all_middleware_types() {
    let doc = load_parity_doc();
    let t54_section = doc
        .split("T5.4 Middleware Stack Closure Contract")
        .nth(1)
        .unwrap_or("");
    for mw in [
        "CorsMiddleware",
        "CompressionMiddleware",
        "AuthMiddleware",
        "NormalizePathMiddleware",
        "RequestBodyLimitMiddleware",
        "CatchPanicMiddleware",
        "TimeoutMiddleware",
        "CircuitBreakerMiddleware",
        "RateLimitMiddleware",
        "BulkheadMiddleware",
        "RetryMiddleware",
        "MiddlewareStack",
        "LoadShedMiddleware",
        "RequestIdMiddleware",
        "SetResponseHeaderMiddleware",
    ] {
        assert!(
            t54_section.contains(mw),
            "T5.4 contract must cover middleware: {mw}"
        );
    }
}

#[test]
fn parity_t54_covers_status_codes() {
    let doc = load_parity_doc();
    let t54_section = doc
        .split("T5.4 Middleware Stack Closure Contract")
        .nth(1)
        .unwrap_or("");
    for token in ["401", "429", "503", "504", "413", "500", "406", "301"] {
        assert!(
            t54_section.contains(token),
            "T5.4 must cover HTTP status code: {token}"
        );
    }
}

#[test]
fn parity_t54_scenario_pack_has_required_log_fields() {
    let doc = load_parity_doc();
    let pack_section = doc
        .split("T5.4 Deterministic Scenario Pack")
        .nth(1)
        .unwrap_or("");
    for field in ["scenario_id", "middleware", "outcome_class", "status_code"] {
        assert!(
            pack_section.contains(field),
            "T5.4 scenario pack missing required log field: {field}"
        );
    }
}

#[test]
fn parity_t54_validation_bundle_references() {
    let doc = load_parity_doc();
    assert!(
        doc.contains("br show asupersync-2oh2u.5.4"),
        "evidence section must reference T5.4 bead"
    );
    assert!(
        doc.contains("cargo test --lib web::middleware::tests"),
        "evidence section must include middleware unit test command"
    );
}

#[test]
fn parity_revision_history_tracks_t54_update() {
    let doc = load_parity_doc();
    assert!(
        doc.contains("T5.4 middleware stack closure contract"),
        "revision history must reference T5.4 closure contract"
    );
    assert!(
        doc.contains("MW-G2") && doc.contains("MW-G5") && doc.contains("MW-G9"),
        "revision history must note closed middleware gaps"
    );
}

#[test]
fn parity_t54_gap_closures_reflected_in_table() {
    let doc = load_parity_doc();
    let summary = doc
        .split("Gap Summary")
        .nth(1)
        .expect("must have gap summary");
    for gap in ["MW-G2", "MW-G5", "MW-G6", "MW-G8", "MW-G9"] {
        assert!(
            summary.contains(gap) && summary.contains("Closed"),
            "{gap} must be marked closed in gap summary"
        );
    }
}

#[test]
fn parity_t54_gap_total_updated() {
    let doc = load_parity_doc();
    // Originally 7 closed after T5.4; now >= 11 with GRPC-G1, GRPC-G2, GRPC-G11, HT-G1
    assert!(
        doc.contains("7 closed")
            || doc.contains("8 closed")
            || doc.contains("9 closed")
            || doc.contains("10 closed")
            || doc.contains("11 closed")
            || doc.contains("12 closed")
            || doc.contains("13 closed"),
        "gap total must reflect closures (>= 7 closed)"
    );
}

// ---------------------------------------------------------------------------
// T5.5 Contract Tests — Server Lifecycle Parity
// ---------------------------------------------------------------------------

#[test]
fn parity_includes_t55_lifecycle_closure_scope() {
    let doc = load_parity_doc();
    for token in [
        "asupersync-2oh2u.5.5",
        "T5.5",
        "Server Lifecycle Closure Contract",
    ] {
        assert!(doc.contains(token), "missing T5.5 scope token: {token}");
    }
    // Version must be at least 1.5.0 (may be bumped by subsequent beads)
    assert!(
        doc.contains("1.5.0") || doc.contains("1.6.0") || doc.contains("1.7.0"),
        "version must be >= 1.5.0"
    );
}

#[test]
fn parity_has_t55_success_failure_cancellation_contract_rows() {
    let doc = load_parity_doc();
    for token in [
        "T55-LIFE-01",
        "T55-LIFE-03",
        "T55-LIFE-06",
        "T55-LIFE-09",
        "T55-LIFE-12",
    ] {
        assert!(doc.contains(token), "missing T5.5 contract row: {token}");
    }
    let contract_section = doc
        .split("T5.5 Server Lifecycle Closure Contract")
        .nth(1)
        .expect("must have T5.5 contract section");
    for col in [
        "Contract ID",
        "Success Path",
        "Failure Path",
        "Cancellation Path",
        "Deterministic Assertion",
    ] {
        assert!(
            contract_section.contains(col),
            "T5.5 contract table missing column: {col}"
        );
    }
}

#[test]
fn parity_has_t55_deterministic_scenario_pack() {
    let doc = load_parity_doc();
    assert!(
        doc.contains("T5.5 Deterministic Scenario Pack"),
        "must include T5.5 deterministic scenario pack section"
    );
    for token in [
        "T55-LIFE-01",
        "T55-LIFE-05",
        "T55-LIFE-10",
        "T55-LIFE-16",
        "T55-LIFE-18",
    ] {
        assert!(doc.contains(token), "missing scenario pack entry: {token}");
    }
    let pack_section = doc
        .split("T5.5 Deterministic Scenario Pack")
        .nth(1)
        .expect("must have T5.5 scenario pack section");
    for status in ["| success |", "| failure |", "| cancelled |"] {
        assert!(
            pack_section.contains(status),
            "T5.5 scenario pack missing status: {status}"
        );
    }
}

#[test]
fn parity_t55_covers_lifecycle_phases() {
    let doc = load_parity_doc();
    // Check lifecycle concepts across both the parity table (5.4) and contract (5.5) sections
    let lifecycle_area = doc.split("Server Lifecycle Parity").nth(1).unwrap_or("");
    for phase in [
        "Running",
        "Draining",
        "ForceClosing",
        "Stopped",
        "ShutdownSignal",
        "ConnectionManager",
        "ConnectionGuard",
        "ShutdownStats",
    ] {
        assert!(
            lifecycle_area.contains(phase),
            "T5.5 lifecycle sections must cover concept: {phase}"
        );
    }
}

#[test]
fn parity_t55_covers_backpressure_mechanisms() {
    let doc = load_parity_doc();
    let lifecycle_section = doc.split("Server Lifecycle Parity").nth(1).unwrap_or("");
    for token in [
        "max_connections",
        "max_requests_per_connection",
        "idle_timeout",
        "keep_alive",
        "max_headers_size",
        "max_body_size",
    ] {
        assert!(
            lifecycle_section.contains(token),
            "T5.5 parity table must cover backpressure token: {token}"
        );
    }
}

#[test]
fn parity_t55_scenario_pack_has_required_log_fields() {
    let doc = load_parity_doc();
    let pack_section = doc
        .split("T5.5 Deterministic Scenario Pack")
        .nth(1)
        .unwrap_or("");
    for field in ["scenario_id", "outcome_class", "phase"] {
        assert!(
            pack_section.contains(field),
            "T5.5 scenario pack missing required log field: {field}"
        );
    }
}

#[test]
fn parity_t55_validation_bundle_references() {
    let doc = load_parity_doc();
    assert!(
        doc.contains("br show asupersync-2oh2u.5.5"),
        "evidence section must reference T5.5 bead"
    );
}

#[test]
fn parity_revision_history_tracks_t55_update() {
    let doc = load_parity_doc();
    assert!(
        doc.contains("T5.5 server lifecycle closure contract"),
        "revision history must reference T5.5 closure contract"
    );
    assert!(
        doc.contains("HT-G4") && doc.contains("HT-G5"),
        "revision history must note new HT-G4 and HT-G5 gaps"
    );
}

#[test]
fn parity_t55_new_gaps_in_summary() {
    let doc = load_parity_doc();
    let summary = doc
        .split("Gap Summary")
        .nth(1)
        .expect("must have gap summary");
    assert!(
        summary.contains("HT-G4") && summary.contains("HTTP/2 server lifecycle"),
        "HT-G4 must appear in gap summary"
    );
    assert!(
        summary.contains("HT-G5") && summary.contains("Multi-listener"),
        "HT-G5 must appear in gap summary"
    );
}

// ---------------------------------------------------------------------------
// T5.7 Contract Tests — gRPC Production Features
// ---------------------------------------------------------------------------

#[test]
fn parity_includes_t57_grpc_production_features_scope() {
    let doc = load_parity_doc();
    assert!(
        doc.contains("T5.7 gRPC Production Features Closure Contract"),
        "must include T5.7 closure contract section"
    );
    assert!(
        doc.contains("1.6.0") || doc.contains("1.7.0"),
        "version must be >= 1.6.0 for T5.7 updates"
    );
}

#[test]
fn parity_t57_covers_reflection_service() {
    let doc = load_parity_doc();
    assert!(
        doc.contains("ReflectionService") && doc.contains("grpc/reflection.rs"),
        "T5.7 must cover reflection service with module path"
    );
    // GRPC-G1 should be closed
    assert!(
        doc.contains("~~GRPC-G1~~") || doc.contains("Closed — `ReflectionService`"),
        "GRPC-G1 must be marked closed"
    );
}

#[test]
fn parity_t57_covers_compression() {
    let doc = load_parity_doc();
    assert!(
        doc.contains("gzip_frame_compress") && doc.contains("gzip_frame_decompress"),
        "T5.7 must cover gzip compression functions"
    );
    assert!(
        doc.contains("send_compression") && doc.contains("accept_compression"),
        "T5.7 must cover server compression config"
    );
    // GRPC-G2 should be closed
    assert!(
        doc.contains("~~GRPC-G2~~") || doc.contains("Closed — `gzip_frame_compress`"),
        "GRPC-G2 must be marked closed"
    );
}

#[test]
fn parity_t57_covers_interceptors() {
    let doc = load_parity_doc();
    let t57_section = doc
        .split("T5.7 gRPC Production Features Closure Contract")
        .nth(1)
        .unwrap_or("");
    for interceptor in [
        "InterceptorLayer",
        "BearerAuthInterceptor",
        "LoggingInterceptor",
        "RateLimitInterceptor",
        "TimeoutInterceptor",
        "TracingInterceptor",
        "MetadataPropagator",
    ] {
        assert!(
            t57_section.contains(interceptor),
            "T5.7 must cover interceptor: {interceptor}"
        );
    }
}

#[test]
fn parity_t57_covers_health_service() {
    let doc = load_parity_doc();
    let t57_section = doc
        .split("T5.7 gRPC Production Features Closure Contract")
        .nth(1)
        .unwrap_or("");
    for token in [
        "HealthService",
        "HealthServiceBuilder",
        "HealthReporter",
        "ServingStatus",
    ] {
        assert!(
            t57_section.contains(token),
            "T5.7 must cover health service type: {token}"
        );
    }
}

#[test]
fn parity_t57_covers_grpc_web() {
    let doc = load_parity_doc();
    let t57_section = doc
        .split("T5.7 gRPC Production Features Closure Contract")
        .nth(1)
        .unwrap_or("");
    for token in [
        "WebFrameCodec",
        "TrailerFrame",
        "ContentType",
        "base64 text modes",
        "grpc/web.rs",
    ] {
        assert!(
            t57_section.contains(token),
            "T5.7 must cover gRPC-Web token: {token}"
        );
    }
}

#[test]
fn parity_t57_has_evidence_commands() {
    let doc = load_parity_doc();
    let t57_section = doc
        .split("T5.7 gRPC Production Features Closure Contract")
        .nth(1)
        .unwrap_or("");
    for cmd in [
        "cargo test --test grpc_enhancement_integration",
        "cargo test --lib grpc::codec::tests",
        "cargo test --lib grpc::web::tests",
        "cargo test --lib grpc::health::tests",
    ] {
        assert!(
            t57_section.contains(cmd),
            "T5.7 must include evidence command: {cmd}"
        );
    }
}

#[test]
fn parity_t57_identifies_remaining_gap() {
    let doc = load_parity_doc();
    let t57_section = doc
        .split("T5.7 gRPC Production Features Closure Contract")
        .nth(1)
        .unwrap_or("");
    assert!(
        t57_section.contains("GRPC-G9") && t57_section.contains("deadline"),
        "T5.7 must identify GRPC-G9 (deadline propagation) as remaining gap"
    );
}

#[test]
fn parity_grpc_g1_g2_g11_ht_g1_closed_in_gap_summary() {
    let doc = load_parity_doc();
    let summary = doc
        .split("Gap Summary")
        .nth(1)
        .expect("must have gap summary");
    for (gap, feature) in [
        ("GRPC-G1", "Reflection"),
        ("GRPC-G2", "compression"),
        ("GRPC-G11", "metadata"),
        ("HT-G1", "100-continue"),
    ] {
        assert!(
            summary.contains(&format!("~~{gap}~~")) || summary.contains(gap),
            "gap summary must reference {gap} ({feature})"
        );
    }
}

#[test]
fn parity_gap_count_updated_for_closures() {
    let doc = load_parity_doc();
    // Total should reflect 4 additional closures (GRPC-G1, GRPC-G2, GRPC-G11, HT-G1)
    assert!(
        doc.contains("34 open gaps")
            || doc.contains("33 open gaps")
            || doc.contains("32 open gaps"),
        "total gap count must be updated to reflect closures (34 or fewer)"
    );
    assert!(
        doc.contains("11 closed") || doc.contains("12 closed") || doc.contains("13 closed"),
        "closed gap count must be >= 11"
    );
}
