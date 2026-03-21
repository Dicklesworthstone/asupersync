#![deny(unsafe_code)]

use asupersync::runtime::builder::{
    BrowserCapabilitySnapshot, BrowserExecutionHostRole, BrowserExecutionLadderDiagnostics,
    BrowserExecutionLane, BrowserExecutionLaneCandidate, BrowserExecutionLaneKind,
    BrowserExecutionReasonCode, BrowserRuntimeContext, BrowserRuntimeSupportClass,
    BrowserRuntimeSupportReason, RuntimeBuilder,
};
use asupersync::types::{
    ReactProviderConfig, ReactProviderPhase, ReactProviderState, WasmAbiOutcomeEnvelope,
    WasmAbiSymbol, WasmAbiValue,
};
use js_sys::{Reflect, global};
use serde::Serialize;
use wasm_bindgen::JsValue;
use wasm_bindgen::prelude::wasm_bindgen;
use web_sys::window;

#[derive(Debug, Serialize)]
struct CapabilitySnapshot {
    has_window: bool,
    has_document: bool,
    has_webassembly: bool,
}

#[derive(Debug, Serialize)]
struct BrowserExecutionApiSnapshot {
    has_abort_controller: bool,
    has_fetch: bool,
    has_webassembly: bool,
}

#[derive(Debug, Serialize)]
struct BrowserDomSnapshot {
    has_document: bool,
    has_window: bool,
}

#[derive(Debug, Serialize)]
struct BrowserStorageSnapshot {
    has_indexed_db: bool,
    has_local_storage: bool,
}

#[derive(Debug, Serialize)]
struct BrowserTransportSnapshot {
    has_web_socket: bool,
    has_web_transport: bool,
}

#[derive(Debug, Serialize)]
struct BrowserCapabilitySummary {
    execution_api: BrowserExecutionApiSnapshot,
    dom: BrowserDomSnapshot,
    storage: BrowserStorageSnapshot,
    transport: BrowserTransportSnapshot,
}

#[derive(Debug, Serialize)]
struct BrowserLaneCandidateSummary {
    lane_id: &'static str,
    available: bool,
    selected: bool,
    reason_code: &'static str,
}

#[derive(Debug, Serialize)]
struct BrowserExecutionLadderSummary {
    supported: bool,
    preferred_lane: Option<&'static str>,
    selected_lane: &'static str,
    lane_kind: &'static str,
    host_role: &'static str,
    runtime_context: &'static str,
    support_class: &'static str,
    reason_code: &'static str,
    runtime_support_reason: &'static str,
    fallback_lane_id: Option<&'static str>,
    downgrade_order: Vec<&'static str>,
    repro_command: String,
    message: String,
    guidance: Vec<String>,
    candidates: Vec<BrowserLaneCandidateSummary>,
    capabilities: BrowserCapabilitySummary,
}

#[derive(Debug, Serialize)]
struct DemoSummary {
    scenario_id: &'static str,
    support_lane: &'static str,
    ready_phase: ReactProviderPhase,
    disposed_phase: ReactProviderPhase,
    child_scope_count_before_unmount: usize,
    active_task_count_before_unmount: usize,
    completed_task_outcome: &'static str,
    cancel_event_count: usize,
    dispatch_count: u64,
    event_symbols: Vec<String>,
    diagnostics_clean: bool,
    capabilities: CapabilitySnapshot,
}

fn js_error(message: impl Into<String>) -> JsValue {
    JsValue::from_str(&message.into())
}

fn capability_snapshot() -> CapabilitySnapshot {
    let has_window = window().is_some();
    let has_document = window().and_then(|win| win.document()).is_some();
    let has_webassembly =
        Reflect::has(&global(), &JsValue::from_str("WebAssembly")).unwrap_or(false);

    CapabilitySnapshot {
        has_window,
        has_document,
        has_webassembly,
    }
}

fn lane_kind_str(kind: BrowserExecutionLaneKind) -> &'static str {
    match kind {
        BrowserExecutionLaneKind::DirectRuntime => "direct_runtime",
        BrowserExecutionLaneKind::Unsupported => "unsupported",
    }
}

fn runtime_support_reason_str(reason: BrowserRuntimeSupportReason) -> &'static str {
    match reason {
        BrowserRuntimeSupportReason::MissingGlobalThis => "missing_global_this",
        BrowserRuntimeSupportReason::ServiceWorkerNotYetShipped => "service_worker_not_yet_shipped",
        BrowserRuntimeSupportReason::SharedWorkerNotYetShipped => "shared_worker_not_yet_shipped",
        BrowserRuntimeSupportReason::UnsupportedRuntimeContext => "unsupported_runtime_context",
        BrowserRuntimeSupportReason::MissingWebAssembly => "missing_webassembly",
        BrowserRuntimeSupportReason::Supported => "supported",
    }
}

fn reason_code_str(reason: BrowserExecutionReasonCode) -> &'static str {
    reason.as_str()
}

fn lane_str(lane: BrowserExecutionLane) -> &'static str {
    lane.as_str()
}

fn host_role_str(host_role: BrowserExecutionHostRole) -> &'static str {
    host_role.as_str()
}

fn runtime_context_str(runtime_context: BrowserRuntimeContext) -> &'static str {
    runtime_context.as_str()
}

fn support_class_str(support_class: BrowserRuntimeSupportClass) -> &'static str {
    support_class.as_str()
}

fn browser_capability_summary(snapshot: BrowserCapabilitySnapshot) -> BrowserCapabilitySummary {
    BrowserCapabilitySummary {
        execution_api: BrowserExecutionApiSnapshot {
            has_abort_controller: snapshot.execution_api.has_abort_controller,
            has_fetch: snapshot.execution_api.has_fetch,
            has_webassembly: snapshot.execution_api.has_webassembly,
        },
        dom: BrowserDomSnapshot {
            has_document: snapshot.dom.has_document,
            has_window: snapshot.dom.has_window,
        },
        storage: BrowserStorageSnapshot {
            has_indexed_db: snapshot.storage.has_indexed_db,
            has_local_storage: snapshot.storage.has_local_storage,
        },
        transport: BrowserTransportSnapshot {
            has_web_socket: snapshot.transport.has_web_socket,
            has_web_transport: snapshot.transport.has_web_transport,
        },
    }
}

fn browser_lane_candidate_summary(
    candidate: BrowserExecutionLaneCandidate,
) -> BrowserLaneCandidateSummary {
    BrowserLaneCandidateSummary {
        lane_id: lane_str(candidate.lane_id),
        available: candidate.available,
        selected: candidate.selected,
        reason_code: reason_code_str(candidate.reason_code),
    }
}

fn browser_execution_ladder_summary(
    ladder: BrowserExecutionLadderDiagnostics,
) -> BrowserExecutionLadderSummary {
    BrowserExecutionLadderSummary {
        supported: ladder.supported,
        preferred_lane: ladder.preferred_lane.map(lane_str),
        selected_lane: lane_str(ladder.selected_lane),
        lane_kind: lane_kind_str(ladder.lane_kind),
        host_role: host_role_str(ladder.host_role),
        runtime_context: runtime_context_str(ladder.runtime_context),
        support_class: support_class_str(ladder.support_class),
        reason_code: reason_code_str(ladder.reason_code),
        runtime_support_reason: runtime_support_reason_str(ladder.runtime_support.reason),
        fallback_lane_id: ladder.fallback_lane_id.map(lane_str),
        downgrade_order: ladder.downgrade_order.into_iter().map(lane_str).collect(),
        repro_command: ladder.repro_command,
        message: ladder.message,
        guidance: ladder.guidance,
        candidates: ladder
            .candidates
            .into_iter()
            .map(browser_lane_candidate_summary)
            .collect(),
        capabilities: browser_capability_summary(ladder.capabilities),
    }
}

fn inspect_execution_ladder(
    preferred_lane: Option<BrowserExecutionLane>,
) -> BrowserExecutionLadderSummary {
    let builder = RuntimeBuilder::new();
    let ladder = match preferred_lane {
        Some(preferred_lane) => {
            builder.inspect_browser_execution_ladder_with_preferred_lane(preferred_lane)
        }
        None => builder.inspect_browser_execution_ladder(),
    };
    browser_execution_ladder_summary(ladder)
}

#[wasm_bindgen]
pub fn run_rust_browser_consumer_demo() -> Result<JsValue, JsValue> {
    let mut provider = ReactProviderState::new(ReactProviderConfig {
        label: "rust-browser-consumer".to_string(),
        ..ReactProviderConfig::default()
    });

    provider
        .mount()
        .map_err(|err| js_error(format!("mount failed: {err}")))?;

    let child_scope = provider
        .create_child_scope(Some("rust-browser-child"))
        .map_err(|err| js_error(format!("create_child_scope failed: {err}")))?;

    let completed_task = provider
        .spawn_task(child_scope, Some("completed-task"))
        .map_err(|err| js_error(format!("spawn completed task failed: {err}")))?;

    let completed_outcome = provider
        .complete_task(
            &completed_task,
            WasmAbiOutcomeEnvelope::Ok {
                value: WasmAbiValue::String("rust-browser-consumer-ok".to_string()),
            },
        )
        .map_err(|err| js_error(format!("complete_task failed: {err}")))?;

    provider
        .spawn_task(child_scope, Some("cancel-on-unmount"))
        .map_err(|err| js_error(format!("spawn cancel-on-unmount task failed: {err}")))?;

    let ready_snapshot = provider.snapshot();

    provider
        .unmount()
        .map_err(|err| js_error(format!("unmount failed: {err}")))?;

    let disposed_snapshot = provider.snapshot();
    let event_symbols = provider
        .dispatcher()
        .event_log()
        .events()
        .iter()
        .map(|event| event.symbol.as_str().to_string())
        .collect::<Vec<_>>();
    let cancel_event_count = provider
        .dispatcher()
        .event_log()
        .events()
        .iter()
        .filter(|event| event.symbol == WasmAbiSymbol::TaskCancel)
        .count();

    let diagnostics = disposed_snapshot
        .dispatcher_diagnostics
        .ok_or_else(|| js_error("dispatcher diagnostics missing after unmount"))?;

    let completed_task_outcome = match completed_outcome {
        WasmAbiOutcomeEnvelope::Ok { .. } => "ok",
        WasmAbiOutcomeEnvelope::Err { .. } => "err",
        WasmAbiOutcomeEnvelope::Cancelled { .. } => "cancelled",
        WasmAbiOutcomeEnvelope::Panicked { .. } => "panicked",
    };

    let summary = DemoSummary {
        scenario_id: "RUST-BROWSER-CONSUMER",
        support_lane: "repository_maintained_rust_browser_fixture",
        ready_phase: ready_snapshot.phase,
        disposed_phase: disposed_snapshot.phase,
        child_scope_count_before_unmount: ready_snapshot.child_scope_count,
        active_task_count_before_unmount: ready_snapshot.active_task_count,
        completed_task_outcome,
        cancel_event_count,
        dispatch_count: diagnostics.dispatch_count,
        event_symbols,
        diagnostics_clean: diagnostics.is_clean(),
        capabilities: capability_snapshot(),
    };

    serde_wasm_bindgen::to_value(&summary)
        .map_err(|err| js_error(format!("failed to encode summary: {err}")))
}

#[wasm_bindgen]
pub fn inspect_rust_browser_execution_ladder() -> Result<JsValue, JsValue> {
    serde_wasm_bindgen::to_value(&inspect_execution_ladder(None))
        .map_err(|err| js_error(format!("failed to encode execution ladder: {err}")))
}

#[wasm_bindgen]
pub fn inspect_rust_browser_execution_ladder_preferred_main_thread() -> Result<JsValue, JsValue> {
    serde_wasm_bindgen::to_value(&inspect_execution_ladder(Some(
        BrowserExecutionLane::BrowserMainThreadDirectRuntime,
    )))
    .map_err(|err| {
        js_error(format!(
            "failed to encode preferred main-thread ladder: {err}"
        ))
    })
}

#[wasm_bindgen]
pub fn inspect_rust_browser_execution_ladder_preferred_dedicated_worker() -> Result<JsValue, JsValue>
{
    serde_wasm_bindgen::to_value(&inspect_execution_ladder(Some(
        BrowserExecutionLane::DedicatedWorkerDirectRuntime,
    )))
    .map_err(|err| {
        js_error(format!(
            "failed to encode preferred dedicated-worker ladder: {err}"
        ))
    })
}
