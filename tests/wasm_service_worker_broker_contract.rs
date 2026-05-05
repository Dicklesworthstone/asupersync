//! Contract checks for the service-worker bounded broker policy
//! (`asupersync-n6kwt.7.1`).

use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

const DOC_PATH: &str = "docs/wasm_service_worker_broker_contract.md";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_file(path: &str) -> String {
    let path = repo_root().join(path);
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    assert!(
        !content.is_empty(),
        "expected non-empty contract file at {}",
        path.display()
    );
    content
}

fn run_node_json(script: &str, extra_env: &[(&str, &std::path::Path)]) -> Value {
    let repo_root = repo_root();
    let mut command = Command::new("node");
    command
        .arg("--input-type=module")
        .arg("--eval")
        .arg(script)
        .current_dir(&repo_root)
        .env("ASUPERSYNC_REPO_ROOT", &repo_root);
    for (key, value) in extra_env {
        command.env(key, value);
    }
    let output = command
        .output()
        .expect("failed to execute node ESM contract harness");

    let stdout = String::from_utf8(output.stdout).expect("node stdout must be valid UTF-8");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "node broker harness failed:\nstdout:\n{stdout}\n\nstderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("ExperimentalWarning"),
        "node import path must not require experimental JSON modules:\n{stderr}"
    );

    serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("failed to parse node JSON stdout: {error}\n{stdout}"))
}

fn write_stage_file(path: &std::path::Path, contents: &[u8]) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .unwrap_or_else(|error| panic!("failed to create {}: {error}", parent.display()));
    }
    std::fs::write(path, contents)
        .unwrap_or_else(|error| panic!("failed to write {}: {error}", path.display()));
}

fn stage_browser_node_fixture() -> Option<TempDir> {
    let repo_root = repo_root();
    let browser_package = repo_root.join("packages/browser/package.json");
    let browser_dist = repo_root.join("packages/browser/dist/index.js");
    let browser_core_package = repo_root.join("packages/browser-core/package.json");
    let browser_core_index = repo_root.join("packages/browser-core/index.js");
    let browser_core_wasm_bindings = repo_root.join("packages/browser-core/asupersync.js");
    let browser_core_abi_metadata = repo_root.join("packages/browser-core/abi-metadata.json");

    for path in [
        &browser_package,
        &browser_dist,
        &browser_core_package,
        &browser_core_index,
        &browser_core_wasm_bindings,
        &browser_core_abi_metadata,
    ] {
        if !path.exists() {
            eprintln!(
                "skipping staged Node broker proof because required package asset is unavailable: {}",
                path.display()
            );
            return None;
        }
    }

    let stage = tempfile::tempdir().expect("create staged node fixture directory");
    let root = stage.path();

    write_stage_file(
        &root.join("browser/package.json"),
        &std::fs::read(&browser_package).unwrap_or_else(|error| {
            panic!("failed to read {}: {error}", browser_package.display())
        }),
    );
    write_stage_file(
        &root.join("browser/dist/index.js"),
        &std::fs::read(&browser_dist)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", browser_dist.display())),
    );
    write_stage_file(
        &root.join("node_modules/@asupersync/browser-core/package.json"),
        &std::fs::read(&browser_core_package).unwrap_or_else(|error| {
            panic!("failed to read {}: {error}", browser_core_package.display())
        }),
    );
    write_stage_file(
        &root.join("node_modules/@asupersync/browser-core/index.js"),
        &std::fs::read(&browser_core_index).unwrap_or_else(|error| {
            panic!("failed to read {}: {error}", browser_core_index.display())
        }),
    );
    write_stage_file(
        &root.join("node_modules/@asupersync/browser-core/asupersync.js"),
        &std::fs::read(&browser_core_wasm_bindings).unwrap_or_else(|error| {
            panic!(
                "failed to read {}: {error}",
                browser_core_wasm_bindings.display()
            )
        }),
    );
    write_stage_file(
        &root.join("node_modules/@asupersync/browser-core/abi-metadata.json"),
        &std::fs::read(&browser_core_abi_metadata).unwrap_or_else(|error| {
            panic!(
                "failed to read {}: {error}",
                browser_core_abi_metadata.display()
            )
        }),
    );

    Some(stage)
}

const NODE_SERVICE_WORKER_BROKER_RESTART_FLOW_SCRIPT: &str = r#"
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function createLocalStorageHarness() {
  const backing = new Map();
  return {
    backing,
    localStorage: {
      get length() {
        return backing.size;
      },
      clear() {
        backing.clear();
      },
      getItem(key) {
        return backing.has(key) ? backing.get(key) : null;
      },
      key(index) {
        return Array.from(backing.keys())[index] ?? null;
      },
      removeItem(key) {
        backing.delete(key);
      },
      setItem(key, value) {
        backing.set(String(key), String(value));
      },
    },
  };
}

const repoRoot = process.env.ASUPERSYNC_REPO_ROOT;
assert(typeof repoRoot === "string" && repoRoot.length > 0, "ASUPERSYNC_REPO_ROOT must be set");
const stageRoot = process.env.ASUPERSYNC_BROWSER_STAGE_ROOT;
assert(
  typeof stageRoot === "string" && stageRoot.length > 0,
  "ASUPERSYNC_BROWSER_STAGE_ROOT must be set",
);

const browserEntryUrl = pathToFileURL(
  resolve(stageRoot, "browser/dist/index.js"),
).href;
const abiMetadataSidecar = JSON.parse(
  readFileSync(
    resolve(stageRoot, "node_modules/@asupersync/browser-core/abi-metadata.json"),
    "utf8",
  ),
);
const browser = await import(browserEntryUrl);
const {
  abiMetadata,
  BROWSER_BRIDGE_ONLY_FALLBACK_TARGET,
  BROWSER_DEDICATED_WORKER_DIRECT_RUNTIME_LANE,
  BROWSER_MAIN_THREAD_DIRECT_RUNTIME_LANE,
  BROWSER_SERVICE_WORKER_BROKER_CONTRACT_ID,
  BROWSER_SERVICE_WORKER_BROKER_LANE,
  createBrowserServiceWorkerBrokerStore,
  detectBrowserServiceWorkerBrokerSupport,
} = browser;

const { backing, localStorage } = createLocalStorageHarness();
const serviceWorkerGlobal = {
  TextEncoder,
  TextDecoder,
  atob: (value) => Buffer.from(value, "base64").toString("binary"),
  btoa: (value) => Buffer.from(value, "binary").toString("base64"),
  clients: {
    claim: async () => undefined,
    matchAll: async () => [],
    openWindow: async () => null,
  },
  localStorage,
  location: { origin: "https://example.test" },
  navigator: { serviceWorker: { controller: { id: "controller-1" } } },
  registration: { scope: "https://example.test/app/" },
  skipWaiting: async () => undefined,
};

let nowMs = 1_000;
const now = () => {
  nowMs += 100;
  return nowMs;
};

const support = detectBrowserServiceWorkerBrokerSupport({
  appNamespace: "browser.tests",
  appVersionMajor: 7,
  backend: "localstorage",
  brokerProtocolVersion: 3,
  expectedAppNamespace: "browser.tests",
  expectedAppVersionMajor: 7,
  expectedBrokerProtocolVersion: 3,
  expectedRegistrationScope: "https://example.test/app/",
  globalObject: serviceWorkerGlobal,
  requireController: true,
});
assert(support.supported, `expected broker support, got ${support.reason}`);

const store = createBrowserServiceWorkerBrokerStore({
  backend: "localstorage",
  globalObject: serviceWorkerGlobal,
  now,
});
const registration = await store.registerBroker({
  admission: {
    origin: "https://example.test",
    registrationScope: "https://example.test/app/",
    appNamespace: "browser.tests",
    appVersionMajor: 7,
    brokerProtocolVersion: 3,
    runProfile: "restartable",
  },
  capabilityManifestVersion: "caps-v1",
  controllerPresent: true,
  lifecycleState: "validating_scope",
});
const brokeringRegistration = await store.setLifecycleState("brokering");
const firstWork = await store.persistBrokerWork({
  artifactNamespace: "evidence.browser.tests",
  brokerWorkId: "work-1",
  capabilityManifestVersion: "caps-v1",
  idempotencyKey: "idem-1",
  leaseEpoch: 1,
  metadata: { route: "/broker/one" },
  sourceEventKind: "fetch",
});
const firstHandoff = await store.persistDurableHandoff({
  artifactNamespace: "evidence.browser.tests",
  brokerWorkId: "work-1",
  capabilityManifestVersion: "caps-v1",
  fallbackTarget: BROWSER_MAIN_THREAD_DIRECT_RUNTIME_LANE,
  idempotencyKey: "idem-1",
  leaseEpoch: 1,
  metadata: { destination: "window" },
  reason: support.directExecutionReasonCode,
  sourceEventKind: "fetch",
  targetLane: BROWSER_MAIN_THREAD_DIRECT_RUNTIME_LANE,
});

const preRestartPending = await store.listPendingWork();
const preRestartHandoffs = await store.listDurableHandoffs();

const restartedStore = createBrowserServiceWorkerBrokerStore({
  backend: "localstorage",
  globalObject: serviceWorkerGlobal,
  now,
});
const recoveredRegistration = await restartedStore.readRegistration();
const reconcilingRegistration =
  await restartedStore.setLifecycleState("reconciling_durable_state");
const recoveredPendingBeforeNewWrite = await restartedStore.listPendingWork();
const recoveredHandoffsBeforeNewWrite = await restartedStore.listDurableHandoffs();
const mismatch = restartedStore.diagnostics({
  expectedBrokerProtocolVersion: 99,
  expectedRegistrationScope: "https://example.test/app/",
});

const secondWork = await restartedStore.persistBrokerWork({
  artifactNamespace: "evidence.browser.tests",
  brokerWorkId: "work-2",
  capabilityManifestVersion: "caps-v1",
  fallbackTarget: BROWSER_DEDICATED_WORKER_DIRECT_RUNTIME_LANE,
  idempotencyKey: "idem-2",
  leaseEpoch: 2,
  metadata: { route: "/broker/two" },
  sourceEventKind: "push",
});
const secondHandoff = await restartedStore.persistDurableHandoff({
  artifactNamespace: "evidence.browser.tests",
  brokerWorkId: "work-2",
  capabilityManifestVersion: "caps-v1",
  fallbackTarget: BROWSER_DEDICATED_WORKER_DIRECT_RUNTIME_LANE,
  idempotencyKey: "idem-2",
  leaseEpoch: 2,
  metadata: { destination: "dedicated_worker" },
  reason: "worker_reclaimed_by_browser",
  sourceEventKind: "push",
  targetLane: BROWSER_DEDICATED_WORKER_DIRECT_RUNTIME_LANE,
});

const postRestartPending = await restartedStore.listPendingWork();
const postRestartHandoffs = await restartedStore.listDurableHandoffs();
const cleared = await restartedStore.clearBrokerState();
const postClearRegistration = await restartedStore.readRegistration();
const postClearPending = await restartedStore.listPendingWork();
const postClearHandoffs = await restartedStore.listDurableHandoffs();

console.log(
  JSON.stringify({
    abi_metadata_matches_sidecar:
      JSON.stringify(abiMetadata) === JSON.stringify(abiMetadataSidecar),
    abi_metadata_profile: abiMetadata.profile,
    abi_metadata_version_major: abiMetadata.abi_version.major,
    broker_contract_id: BROWSER_SERVICE_WORKER_BROKER_CONTRACT_ID,
    requested_lane: BROWSER_SERVICE_WORKER_BROKER_LANE,
    fallback_constants: [
      BROWSER_DEDICATED_WORKER_DIRECT_RUNTIME_LANE,
      BROWSER_MAIN_THREAD_DIRECT_RUNTIME_LANE,
      BROWSER_BRIDGE_ONLY_FALLBACK_TARGET,
    ],
    support: {
      controllerPresent: support.controllerPresent,
      directExecutionReasonCode: support.directExecutionReasonCode,
      downgradeOrder: support.downgradeOrder,
      fallbackLaneId: support.fallbackLaneId,
      fallbackTarget: support.fallbackTarget,
      hostRole: support.hostRole,
      reason: support.reason,
      registrationScope: support.registrationScope,
      runtimeContext: support.runtimeContext,
      supported: support.supported,
    },
    registration,
    brokering_lifecycle_state: brokeringRegistration?.lifecycleState ?? null,
    first_work: firstWork,
    first_handoff: firstHandoff,
    pre_restart_pending_ids: preRestartPending.map((item) => item.brokerWorkId),
    pre_restart_handoff_ids: preRestartHandoffs.map((item) => item.brokerWorkId),
    recovered_registration: recoveredRegistration,
    reconciling_lifecycle_state:
      reconcilingRegistration?.lifecycleState ?? null,
    recovered_pending_before_new_write:
      recoveredPendingBeforeNewWrite.map((item) => item.brokerWorkId),
    recovered_handoffs_before_new_write:
      recoveredHandoffsBeforeNewWrite.map((item) => item.brokerWorkId),
    mismatch: {
      directExecutionReasonCode: mismatch.directExecutionReasonCode,
      reason: mismatch.reason,
      supported: mismatch.supported,
    },
    second_work: secondWork,
    second_handoff: secondHandoff,
    post_restart_pending_ids: postRestartPending.map((item) => item.brokerWorkId),
    post_restart_handoff_ids:
      postRestartHandoffs.map((item) => item.brokerWorkId),
    cleared,
    post_clear_registration: postClearRegistration,
    post_clear_pending_count: postClearPending.length,
    post_clear_handoff_count: postClearHandoffs.length,
    post_clear_storage_keys: Array.from(backing.keys()).sort(),
  }),
);
"#;

fn staged_node_service_worker_broker_report(stage: &TempDir) -> Value {
    run_node_json(
        NODE_SERVICE_WORKER_BROKER_RESTART_FLOW_SCRIPT,
        &[("ASUPERSYNC_BROWSER_STAGE_ROOT", stage.path())],
    )
}

fn assert_node_broker_report_support(report: &Value) {
    assert_eq!(report["abi_metadata_matches_sidecar"], Value::Bool(true));
    assert_eq!(report["abi_metadata_profile"], Value::String("prod".into()));
    assert_eq!(report["abi_metadata_version_major"], Value::from(1));
    assert_eq!(
        report["broker_contract_id"],
        Value::String("wasm-service-worker-broker-contract-v1".into())
    );
    assert_eq!(
        report["requested_lane"],
        Value::String("lane.browser.service_worker.broker".into())
    );
    assert_eq!(
        report["fallback_constants"],
        serde_json::json!([
            "lane.browser.dedicated_worker.direct_runtime",
            "lane.browser.main_thread.direct_runtime",
            "bridge_fallback",
        ])
    );
    assert_eq!(report["support"]["supported"], Value::Bool(true));
    assert_eq!(
        report["support"]["reason"],
        Value::String("supported".into())
    );
    assert_eq!(
        report["support"]["hostRole"],
        Value::String("service_worker".into())
    );
    assert_eq!(
        report["support"]["runtimeContext"],
        Value::String("service_worker".into())
    );
    assert_eq!(
        report["support"]["directExecutionReasonCode"],
        Value::String("service_worker_direct_runtime_not_shipped".into())
    );
    assert_eq!(
        report["support"]["fallbackTarget"],
        Value::String("lane.browser.dedicated_worker.direct_runtime".into())
    );
    assert_eq!(
        report["support"]["fallbackLaneId"],
        Value::String("lane.browser.dedicated_worker.direct_runtime".into())
    );
    assert_eq!(
        report["support"]["downgradeOrder"],
        serde_json::json!([
            "lane.browser.dedicated_worker.direct_runtime",
            "lane.browser.main_thread.direct_runtime",
            "bridge_fallback",
        ])
    );
    assert_eq!(report["support"]["controllerPresent"], Value::Bool(true));
    assert_eq!(
        report["support"]["registrationScope"],
        Value::String("https://example.test/app/".into())
    );
}

fn assert_node_broker_report_initial_state(report: &Value) {
    assert_eq!(
        report["registration"]["contractId"],
        Value::String("wasm-service-worker-broker-contract-v1".into())
    );
    assert_eq!(
        report["registration"]["requestedLane"],
        Value::String("lane.browser.service_worker.broker".into())
    );
    assert_eq!(
        report["registration"]["fallbackTarget"],
        Value::String("lane.browser.dedicated_worker.direct_runtime".into())
    );
    assert_eq!(
        report["registration"]["directExecutionReasonCode"],
        Value::String("service_worker_direct_runtime_not_shipped".into())
    );
    assert_eq!(
        report["brokering_lifecycle_state"],
        Value::String("brokering".into())
    );
    assert_eq!(
        report["first_work"]["brokerWorkId"],
        Value::String("work-1".into())
    );
    assert_eq!(
        report["first_work"]["fallbackTarget"],
        Value::String("lane.browser.dedicated_worker.direct_runtime".into())
    );
    assert_eq!(
        report["first_handoff"]["targetLane"],
        Value::String("lane.browser.main_thread.direct_runtime".into())
    );
    assert_eq!(
        report["first_handoff"]["reason"],
        Value::String("service_worker_direct_runtime_not_shipped".into())
    );
    assert_eq!(
        report["pre_restart_pending_ids"],
        serde_json::json!(["work-1"])
    );
    assert_eq!(
        report["pre_restart_handoff_ids"],
        serde_json::json!(["work-1"])
    );
}

fn assert_node_broker_report_restart_state(report: &Value) {
    assert_eq!(
        report["recovered_registration"]["lifecycleState"],
        Value::String("brokering".into())
    );
    assert_eq!(
        report["reconciling_lifecycle_state"],
        Value::String("reconciling_durable_state".into())
    );
    assert_eq!(
        report["recovered_pending_before_new_write"],
        serde_json::json!(["work-1"])
    );
    assert_eq!(
        report["recovered_handoffs_before_new_write"],
        serde_json::json!(["work-1"])
    );
    assert_eq!(report["mismatch"]["supported"], Value::Bool(false));
    assert_eq!(
        report["mismatch"]["reason"],
        Value::String("broker_protocol_version_mismatch".into())
    );
    assert_eq!(
        report["mismatch"]["directExecutionReasonCode"],
        Value::String("service_worker_direct_runtime_not_shipped".into())
    );
    assert_eq!(
        report["second_work"]["brokerWorkId"],
        Value::String("work-2".into())
    );
    assert_eq!(
        report["second_handoff"]["targetLane"],
        Value::String("lane.browser.dedicated_worker.direct_runtime".into())
    );
}

fn assert_node_broker_report_cleanup(report: &Value) {
    assert_eq!(
        report["post_restart_pending_ids"],
        serde_json::json!(["work-2", "work-1"])
    );
    assert_eq!(
        report["post_restart_handoff_ids"],
        serde_json::json!(["work-2", "work-1"])
    );
    assert_eq!(report["cleared"], Value::from(5));
    assert_eq!(report["post_clear_registration"], Value::Null);
    assert_eq!(report["post_clear_pending_count"], Value::from(0));
    assert_eq!(report["post_clear_handoff_count"], Value::from(0));
    assert_eq!(report["post_clear_storage_keys"], serde_json::json!([]));
}

#[test]
fn doc_exists_and_pins_bead_and_contract_id() {
    assert!(
        repo_root().join(DOC_PATH).exists(),
        "contract doc must exist at repo-relative path"
    );
    let doc = read_file(DOC_PATH);
    for marker in [
        "asupersync-n6kwt.7.1",
        "wasm-service-worker-broker-contract-v1",
        "Current Truthful Runtime Status",
        "packages/browser/src/index.ts",
        "src/runtime/builder.rs",
    ] {
        assert!(doc.contains(marker), "doc missing marker: {marker}");
    }
}

#[test]
fn doc_scopes_bounded_broker_responsibilities() {
    let doc = read_file(DOC_PATH);
    for marker in [
        "Allowed broker responsibilities",
        "serialize fetch/push/sync/notification ingress",
        "explicit broker work",
        "persist durable broker manifests before claiming restartable progress",
        "hand work off to a dedicated worker, browser main thread, or explicit",
        "general-purpose always-alive runtime",
        "unbounded queue or broker-of-last-resort",
    ] {
        assert!(doc.contains(marker), "doc missing broker marker: {marker}");
    }
}

#[test]
fn doc_distinguishes_ephemeral_and_durable_state() {
    let doc = read_file(DOC_PATH);
    for marker in [
        "Ephemeral broker state",
        "Durable state",
        "IndexedDB-backed BrowserStorage / BrowserArtifactStore",
        "pending broker work descriptors and idempotency keys",
        "artifact manifests and retained evidence indexes",
        "restart reconciliation journal",
        "The service-worker broker owns no irreplaceable authoritative state.",
    ] {
        assert!(doc.contains(marker), "doc missing state marker: {marker}");
    }
}

#[test]
fn doc_pins_restart_reconciliation_and_capability_reestablishment() {
    let doc = read_file(DOC_PATH);
    for marker in [
        "1. `cold_start`",
        "2. `validating_scope`",
        "3. `reconciling_durable_state`",
        "4. `brokering`",
        "5. `draining`",
        "6. `quiescent`",
        "7. `terminated`",
        "capabilities are re-established explicitly",
        "resume is allowed only when the durable descriptor",
        "new capability",
        "snapshot still match",
        "downgrade_to_dedicated_worker",
        "downgrade_to_browser_main_thread",
        "downgrade_to_bridge_only",
        "capability_manifest_mismatch_on_restart",
    ] {
        assert!(
            doc.contains(marker),
            "doc missing reconciliation marker: {marker}"
        );
    }
}

#[test]
fn doc_and_browser_package_pin_bounded_broker_exports() {
    let doc = read_file(DOC_PATH);
    for marker in [
        "detectBrowserServiceWorkerBrokerSupport()",
        "BrowserServiceWorkerBrokerStore",
        "createBrowserServiceWorkerBrokerStore()",
        "registerBroker()",
        "persistBrokerWork()",
        "persistDurableHandoff()",
        "lane.browser.service_worker.broker",
    ] {
        assert!(
            doc.contains(marker),
            "doc missing broker API marker: {marker}"
        );
    }

    let browser = read_file("packages/browser/src/index.ts");
    for marker in [
        "BROWSER_SERVICE_WORKER_BROKER_CONTRACT_ID",
        "BROWSER_SERVICE_WORKER_BROKER_LANE",
        "export interface BrowserServiceWorkerBrokerAdmissionTuple",
        "export interface BrowserServiceWorkerBrokerSupportDiagnostics",
        "export function detectBrowserServiceWorkerBrokerSupport(",
        "export class BrowserServiceWorkerBrokerStore",
        "registerBroker(",
        "persistBrokerWork(",
        "persistDurableHandoff(",
        "createBrowserServiceWorkerBrokerStore(",
    ] {
        assert!(
            browser.contains(marker),
            "browser package missing bounded broker marker: {marker}"
        );
    }
}

#[test]
fn browser_package_and_runtime_builder_preserve_service_worker_fail_closed_markers() {
    let browser = read_file("packages/browser/src/index.ts");
    for marker in [
        "reason: \"service_worker_not_yet_shipped\"",
        "@asupersync/browser does not yet ship direct runtime APIs for service-worker hosts.",
        "Keep service-worker orchestration at the application boundary until this host is promoted.",
        "if (hostRole === \"service_worker\") {",
        "return \"service_worker\";",
    ] {
        assert!(
            browser.contains(marker),
            "browser package missing service-worker marker: {marker}"
        );
    }

    let builder = read_file("src/runtime/builder.rs");
    for marker in [
        "Some(\"ServiceWorkerGlobalScope\") => BrowserExecutionHostRole::ServiceWorker",
        "BrowserRuntimeSupportReason::ServiceWorkerNotYetShipped",
        "BrowserExecutionReasonCode::ServiceWorkerDirectRuntimeNotShipped",
        "\"service_worker_direct_runtime_not_shipped\"",
        "Rust Browser Edition does not yet ship a service-worker direct-runtime lane.",
    ] {
        assert!(
            builder.contains(marker),
            "runtime builder missing service-worker marker: {marker}"
        );
    }
}

#[test]
fn browser_package_source_avoids_json_sidecar_import_for_node_esm() {
    let browser = read_file("packages/browser/src/index.ts");
    assert!(
        !browser.contains("@asupersync/browser-core/abi-metadata.json"),
        "browser package source must not depend on the JSON sidecar import path"
    );

    let (browser_core_import, _) = browser
        .split_once("from \"@asupersync/browser-core\";")
        .expect("browser package must import from @asupersync/browser-core");
    assert!(
        browser_core_import.contains("abiMetadata,"),
        "browser package source must import abiMetadata from the browser-core root export"
    );
}

#[test]
fn doc_and_browser_package_pin_durable_handoff_listing_and_key_schema() {
    let doc = read_file(DOC_PATH);
    for marker in [
        "listDurableHandoffs()",
        "__service_worker_broker_registration__",
        "broker_work:<broker_work_id>",
        "broker_handoff:<broker_work_id>",
        "service_worker_broker_v1",
        "newest-first order",
    ] {
        assert!(
            doc.contains(marker),
            "doc missing durable handoff/key-schema marker: {marker}"
        );
    }

    let browser = read_file("packages/browser/src/index.ts");
    for marker in [
        "BROWSER_SERVICE_WORKER_BROKER_REGISTRATION_KEY",
        "BROWSER_SERVICE_WORKER_BROKER_WORK_PREFIX",
        "BROWSER_SERVICE_WORKER_BROKER_HANDOFF_PREFIX",
        "DEFAULT_BROWSER_SERVICE_WORKER_BROKER_NAMESPACE",
        "async listDurableHandoffs()",
        "right.recordedAtMs - left.recordedAtMs",
    ] {
        assert!(
            browser.contains(marker),
            "browser package missing durable handoff/key-schema marker: {marker}"
        );
    }
}

#[test]
fn browser_package_fail_closes_foreign_requested_lane_in_durable_broker_records() {
    let browser = read_file("packages/browser/src/index.ts");
    for marker in [
        "function parseBrowserServiceWorkerBrokerDescriptor(",
        "function parseBrowserServiceWorkerBrokerHandoffRecord(",
        "candidate.requestedLane !== BROWSER_SERVICE_WORKER_BROKER_LANE",
        "service-worker broker descriptor is missing required fields",
        "service-worker broker handoff record is missing required fields",
    ] {
        assert!(
            browser.contains(marker),
            "browser package missing requested-lane fail-closed marker: {marker}"
        );
    }
}

#[test]
fn canonical_browser_docs_reference_the_contract_and_current_reason_codes() {
    let wasm = read_file("docs/WASM.md");
    let integration = read_file("docs/integration.md");
    let troubleshooting = read_file("docs/wasm_troubleshooting_compendium.md");

    assert!(
        wasm.contains("docs/wasm_service_worker_broker_contract.md"),
        "WASM guide must reference the service-worker contract"
    );
    assert!(
        wasm.contains("service_worker_not_yet_shipped"),
        "WASM guide must preserve the package-level service-worker denial reason"
    );
    assert!(
        wasm.contains("service_worker_direct_runtime_not_shipped"),
        "WASM guide must preserve the ladder-level service-worker denial reason"
    );
    assert!(
        wasm.contains("detectBrowserServiceWorkerBrokerSupport()"),
        "WASM guide must reference the bounded broker support helper"
    );
    assert!(
        wasm.contains("BrowserServiceWorkerBrokerStore"),
        "WASM guide must reference the bounded broker store"
    );
    assert!(
        integration.contains("docs/wasm_service_worker_broker_contract.md"),
        "integration guide must reference the service-worker contract"
    );
    assert!(
        integration.contains("Browser service worker"),
        "integration guide must carry a dedicated service-worker environment row"
    );
    assert!(
        integration.contains("service_worker_not_yet_shipped"),
        "integration guide must use the current browser package reason code"
    );
    assert!(
        integration.contains("registerBroker()"),
        "integration guide must reference broker registration"
    );
    assert!(
        integration.contains("persistDurableHandoff()"),
        "integration guide must reference durable handoff"
    );
    assert!(
        troubleshooting.contains("service_worker_not_yet_shipped"),
        "troubleshooting guide must list the current service-worker reason"
    );
    assert!(
        troubleshooting.contains("shared_worker_not_yet_shipped"),
        "troubleshooting guide must list the current shared-worker reason"
    );
    assert!(
        !troubleshooting.contains("missing_browser_dom"),
        "troubleshooting guide must not mention the removed missing_browser_dom reason"
    );
}

#[test]
fn maintained_service_worker_broker_fixture_exists_with_required_files() {
    let fixture = repo_root().join("tests/fixtures/service-worker-broker-consumer");
    assert!(
        fixture.exists(),
        "service-worker broker fixture directory must exist"
    );

    for rel in [
        "README.md",
        "package.json",
        "index.html",
        "vite.config.ts",
        "src/main.ts",
        "src/service-worker.ts",
        "scripts/check-bundle.mjs",
        "scripts/check-browser-run.mjs",
    ] {
        let path = fixture.join(rel);
        assert!(path.exists(), "missing fixture file: {}", path.display());
    }
}

#[test]
fn maintained_service_worker_broker_validation_path_is_pinned() {
    let script = read_file("scripts/validate_service_worker_broker_consumer.sh");
    for marker in [
        "tests/fixtures/service-worker-broker-consumer",
        "target/e2e-results/service_worker_broker_consumer",
        "BROWSER_RUN_FILE",
        "npm run build",
        "npm run check:bundle",
        "npm run check:browser -- \"${BROWSER_RUN_FILE}\"",
        "\"real_browser_run_ok\": browser_run[\"status\"] == \"ok\"",
        "\"browser_broker_supported\": browser_run[\"broker_supported\"] is True",
        "\"browser_direct_execution_reason\": browser_run[\"direct_execution_reason_code\"]",
        "\"browser_handoff_target_lane_id\": browser_run[\"handoff_target_lane_id\"]",
        "\"browser_mismatch_reason\": browser_run[\"mismatch_reason\"]",
        "L6-SERVICE-WORKER-BROKER",
        "asupersync-n6kwt.7.2",
    ] {
        assert!(
            script.contains(marker),
            "validation script missing expected marker: {marker}"
        );
    }

    let fixture_readme = read_file("tests/fixtures/service-worker-broker-consumer/README.md");
    for marker in [
        "scripts/validate_service_worker_broker_consumer.sh",
        "detectBrowserServiceWorkerBrokerSupport()",
        "BrowserServiceWorkerBrokerStore",
        "registerBroker()",
        "persistBrokerWork()",
        "persistDurableHandoff()",
        "check-browser-run.mjs",
    ] {
        assert!(
            fixture_readme.contains(marker),
            "fixture readme missing expected marker: {marker}"
        );
    }

    let main = read_file("tests/fixtures/service-worker-broker-consumer/src/main.ts");
    for marker in [
        "navigator.serviceWorker.register",
        "service-worker-broker-ready",
        "\"cleanup_complete\"",
        "\"run-broker-demo\"",
    ] {
        assert!(
            main.contains(marker),
            "fixture main source missing expected marker: {marker}"
        );
    }

    let service_worker =
        read_file("tests/fixtures/service-worker-broker-consumer/src/service-worker.ts");
    for marker in [
        "detectBrowserServiceWorkerBrokerSupport",
        "createBrowserServiceWorkerBrokerStore",
        "registerBroker",
        "persistBrokerWork",
        "persistDurableHandoff",
        "listDurableHandoffs",
        "service-worker-broker-mismatch",
        "service_worker_direct_runtime_not_shipped",
    ] {
        assert!(
            service_worker.contains(marker),
            "fixture service-worker source missing expected marker: {marker}"
        );
    }

    let vite = read_file("tests/fixtures/service-worker-broker-consumer/vite.config.ts");
    for marker in ["base: \"./\"", "service-worker.js", "src/service-worker.ts"] {
        assert!(
            vite.contains(marker),
            "fixture vite config missing expected marker: {marker}"
        );
    }

    let browser_check =
        read_file("tests/fixtures/service-worker-broker-consumer/scripts/check-browser-run.mjs");
    for marker in [
        "import { chromium } from \"playwright-core\";",
        "SERVICE-WORKER-BROKER-CONSUMER",
        "service_worker_direct_runtime_not_shipped",
        "broker_protocol_version_mismatch",
        "cleanup_complete",
        "service-worker-broker-ready",
    ] {
        assert!(
            browser_check.contains(marker),
            "fixture browser-run checker missing expected marker: {marker}"
        );
    }
}

#[test]
fn node_executes_service_worker_broker_restart_flow_against_dist_bundle() {
    let Some(stage) = stage_browser_node_fixture() else {
        return;
    };
    let report = staged_node_service_worker_broker_report(&stage);

    assert_node_broker_report_support(&report);
    assert_node_broker_report_initial_state(&report);
    assert_node_broker_report_restart_state(&report);
    assert_node_broker_report_cleanup(&report);
}
