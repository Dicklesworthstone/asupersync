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
        "1.2.0",
    ] {
        assert!(doc.contains(token), "missing T5.2 scope token: {token}");
    }
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
