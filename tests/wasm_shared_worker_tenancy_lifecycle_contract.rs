//! Contract checks for the SharedWorker tenancy/lifecycle/downgrade policy and
//! bounded browser-run proof surface (`asupersync-n6kwt.6.3`).

use std::path::{Path, PathBuf};

const DOC_PATH: &str = "docs/wasm_shared_worker_tenancy_lifecycle_contract.md";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_file(path: &str) -> String {
    let path = repo_root().join(path);
    let content = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        !content.is_empty(),
        "expected non-empty contract file at {}",
        path.display()
    );
    content
}

#[test]
fn doc_exists_and_pins_bead_and_contract_id() {
    assert!(Path::new(DOC_PATH).exists(), "contract doc must exist");
    let doc = read_file(DOC_PATH);
    for marker in [
        "asupersync-n6kwt.6.1",
        "wasm-shared-worker-tenancy-lifecycle-v1",
        "Current Truthful Runtime Status",
        "src/runtime/builder.rs",
    ] {
        assert!(doc.contains(marker), "doc missing marker: {marker}");
    }
}

#[test]
fn doc_defines_tenancy_tuple_and_registration_identity() {
    let doc = read_file(DOC_PATH);
    for marker in [
        "(origin, app_namespace, app_version_major, coordinator_protocol_version, run_profile)",
        "same-origin multi-tab",
        "same-origin only",
        "client_instance_id",
        "client_epoch",
        "client_kind",
        "client_artifact_namespace",
        "client churn",
        "registration is explicit and idempotent",
    ] {
        assert!(doc.contains(marker), "doc missing tenancy marker: {marker}");
    }
}

#[test]
fn doc_distinguishes_ephemeral_and_durable_state() {
    let doc = read_file(DOC_PATH);
    for marker in [
        "Ephemeral coordinator state",
        "Durable state",
        "IndexedDB-backed artifacts",
        "live port registry",
        "artifact manifests and retained evidence indexes",
        "replay bundles and crashpack metadata",
        "The SharedWorker coordinator owns no irreplaceable authoritative state.",
    ] {
        assert!(doc.contains(marker), "doc missing state marker: {marker}");
    }
}

#[test]
fn doc_pins_lifecycle_quiescence_and_downgrade_rules() {
    let doc = read_file(DOC_PATH);
    for marker in [
        "1. `bootstrapping`",
        "2. `joining`",
        "3. `active`",
        "4. `draining`",
        "5. `quiescent`",
        "6. `terminated`",
        "coordinator loss is never treated as impossible or exceptional for semantic correctness",
        "shared_worker_api_missing",
        "coordinator_crash_or_browser_reclaim",
        "lane_health_demoted",
        "downgrade chooses the next truthful lower lane",
    ] {
        assert!(
            doc.contains(marker),
            "doc missing lifecycle marker: {marker}"
        );
    }
}

#[test]
fn runtime_builder_exposes_shared_worker_fail_closed_markers() {
    let builder = read_file("src/runtime/builder.rs");
    for marker in [
        "Some(\"SharedWorkerGlobalScope\") => BrowserExecutionHostRole::SharedWorker",
        "BrowserRuntimeSupportReason::SharedWorkerNotYetShipped",
        "BrowserExecutionReasonCode::SharedWorkerDirectRuntimeNotShipped",
        "\"shared_worker_direct_runtime_not_shipped\"",
        "Rust Browser Edition does not yet ship a shared-worker direct-runtime lane.",
    ] {
        assert!(
            builder.contains(marker),
            "runtime builder missing shared-worker fail-closed marker: {marker}"
        );
    }
}

#[test]
fn canonical_browser_docs_reference_the_contract() {
    let wasm = read_file("docs/WASM.md");
    let integration = read_file("docs/integration.md");

    assert!(
        wasm.contains("docs/wasm_shared_worker_tenancy_lifecycle_contract.md"),
        "WASM guide must reference the SharedWorker contract"
    );
    assert!(
        wasm.contains("shared_worker_direct_runtime_not_shipped"),
        "WASM guide must preserve the shared-worker fail-closed reason"
    );
    assert!(
        integration.contains("docs/wasm_shared_worker_tenancy_lifecycle_contract.md"),
        "integration guide must reference the SharedWorker contract"
    );
    assert!(
        integration.contains("Browser shared worker"),
        "integration guide must carry a dedicated shared-worker environment row"
    );
}

#[test]
fn browser_package_support_surface_pins_admission_and_recovery_guards() {
    let browser = read_file("packages/browser/src/index.ts");
    for marker in [
        "export interface BrowserSharedWorkerCoordinatorSupportDiagnostics",
        "\"shared_worker_api_missing\"",
        "\"origin_not_same_origin_or_opaque\"",
        "\"app_namespace_mismatch\"",
        "\"app_version_major_mismatch\"",
        "\"coordinator_protocol_version_mismatch\"",
        "\"durable_store_unavailable_for_recovery_required_profile\"",
        "\"registration_schema_mismatch\"",
        "\"coordinator_crash_or_browser_reclaim\"",
        "\"lane_health_demoted\"",
        "if (hostRole === \"shared_worker\") {",
        "return \"shared_worker\";",
        "const directRuntimeReason: BrowserRuntimeSupportReason =",
        "\"shared_worker_not_yet_shipped\"",
        "runProfile !== \"ephemeral\"",
        "scriptOrigin !== null && scriptOrigin !== origin",
        "@asupersync/browser shared-worker coordinator prerequisites are available; direct BrowserRuntime creation remains fail-closed inside the shared-worker host and attach must downgrade explicitly on denial or loss.",
    ] {
        assert!(
            browser.contains(marker),
            "browser package missing SharedWorker support marker: {marker}"
        );
    }
}

#[test]
fn browser_package_selection_demotes_explicit_attach_failures() {
    let browser = read_file("packages/browser/src/index.ts");
    for marker in [
        "selectedMode: \"shared_worker\"",
        "selectedMode: \"fallback\"",
        "return createBrowserSharedWorkerFallbackSelection(",
        "SharedWorker coordinator rejected attach with ${responseReason}.",
        "SharedWorker coordinator reported protocol ${response.coordinatorProtocolVersion}, expected ${admission.coordinatorProtocolVersion}.",
        "SharedWorker coordinator is missing required features:",
        "SharedWorker coordinator attach timed out after ${timeoutMs}ms.",
        "SharedWorker coordinator attach failed before the handshake could start:",
        "Downgrade immediately to the fallback lane whenever the coordinator denies attach, crashes, or is reclaimed by the browser.",
    ] {
        assert!(
            browser.contains(marker),
            "browser package missing SharedWorker fallback marker: {marker}"
        );
    }
}

#[test]
fn browser_package_client_close_preserves_detach_and_terminated_lifecycle() {
    let browser = read_file("packages/browser/src/index.ts");
    for marker in [
        "export class BrowserSharedWorkerCoordinatorClient {",
        "type: \"asupersync.browser.shared_worker.detach\"",
        "clientInstanceId: this.attachDiagnosticsSnapshot.client.clientInstanceId",
        "clientEpoch: this.attachDiagnosticsSnapshot.client.clientEpoch",
        "this.lifecycleStateValue = \"draining\";",
        "this.lifecycleStateValue = \"terminated\";",
        "Closing the client must stay best-effort because the browser may have",
    ] {
        assert!(
            browser.contains(marker),
            "browser package missing SharedWorker lifecycle marker: {marker}"
        );
    }
}

#[test]
fn release_and_readiness_docs_pin_guarded_shared_worker_evidence_story() {
    let release = read_file("docs/wasm_release_channel_strategy.md");
    let readiness = read_file("docs/wasm_ga_readiness_review_board_checklist.md");
    for marker in [
        "guarded canary-only",
        "preview_only",
        "shared_worker_direct_runtime_not_shipped",
        "docs/wasm_shared_worker_tenancy_lifecycle_contract.md",
    ] {
        assert!(
            release.contains(marker),
            "release strategy missing SharedWorker marker: {marker}"
        );
        assert!(
            readiness.contains(marker),
            "readiness checklist missing SharedWorker marker: {marker}"
        );
    }
}

#[test]
fn shared_worker_fixture_validator_preserves_fail_closed_direct_runtime_truth() {
    let fixture = read_file("tests/fixtures/shared-worker-consumer/src/main.ts");
    let browser_check =
        read_file("tests/fixtures/shared-worker-consumer/scripts/check-browser-run.mjs");
    let validator = read_file("scripts/validate_shared_worker_consumer.sh");

    assert!(
        fixture.contains("directExecutionReasonCode: support.directExecutionReasonCode"),
        "shared-worker fixture must surface the directExecutionReasonCode summary"
    );

    for marker in [
        "shared_worker_direct_runtime_not_shipped",
        "reuse_page_one_direct_execution_reason_code",
        "reuse_page_two_direct_execution_reason_code",
        "mismatch_direct_execution_reason_code",
        "crash_direct_execution_reason_code",
        "churn_direct_execution_reason_code",
        "recovery_direct_execution_reason_code",
        "shared_worker_client_churn_rejoin",
        "shared_worker_crash_recovery_reconnect",
    ] {
        assert!(
            browser_check.contains(marker) || validator.contains(marker),
            "shared-worker fixture validation surface missing marker: {marker}"
        );
    }
}

#[test]
fn shared_worker_fixture_docs_and_contract_doc_pin_churn_and_recovery_proof() {
    let fixture_readme = read_file("tests/fixtures/shared-worker-consumer/README.md");
    let contract_doc = read_file(DOC_PATH);

    for marker in [
        "asupersync-n6kwt.6.3",
        "shared_worker_client_churn_rejoin",
        "shared_worker_crash_recovery_reconnect",
        "scripts/validate_shared_worker_consumer.sh",
        "client churn",
        "crash-recovery reconnect",
    ] {
        assert!(
            fixture_readme.contains(marker) || contract_doc.contains(marker),
            "shared-worker proof docs missing marker: {marker}"
        );
    }
}
