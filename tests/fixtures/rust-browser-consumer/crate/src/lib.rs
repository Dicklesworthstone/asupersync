#![allow(warnings)]
#![allow(clippy::all)]
#![deny(unsafe_code)]

use asupersync::runtime::builder::{
    BrowserCapabilitySnapshot, BrowserExecutionHostRole, BrowserExecutionLadderDiagnostics,
    BrowserExecutionLane, BrowserExecutionLaneCandidate, BrowserExecutionLaneKind,
    BrowserExecutionProbe, BrowserExecutionReasonCode, BrowserRuntimeContext,
    BrowserRuntimeSupportClass, BrowserRuntimeSupportReason,
    BrowserServiceWorkerBrokerSupportDiagnostics, BrowserServiceWorkerBrokerSupportReason,
    BrowserSharedWorkerCoordinatorSupportDiagnostics, BrowserSharedWorkerCoordinatorSupportReason,
    BrowserWorkerFallbackTarget, RuntimeBuilder,
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
struct BrowserRuntimeSelectionSummary {
    preferred_lane: Option<&'static str>,
    selected_lane: &'static str,
    supported: bool,
    reason_code: &'static str,
    runtime_available: bool,
    error_message: Option<String>,
    scope_close_outcome: Option<&'static str>,
    runtime_close_outcome: Option<&'static str>,
    dispatch_count: Option<u64>,
    diagnostics_clean: Option<bool>,
}

#[derive(Debug, Serialize)]
struct BrowserWorkerSupportSummary {
    supported: bool,
    contract_id: &'static str,
    requested_lane: &'static str,
    fallback_target: &'static str,
    fallback_lane_id: Option<&'static str>,
    host_role: &'static str,
    runtime_context: &'static str,
    reason: &'static str,
    direct_runtime_reason: &'static str,
    direct_execution_reason_code: &'static str,
    downgrade_order: Vec<&'static str>,
    message: String,
    guidance: Vec<String>,
    capabilities: BrowserCapabilitySummary,
}

#[derive(Debug, Serialize)]
struct UnsupportedWorkerLaddersSummary {
    service_worker: BrowserExecutionLadderSummary,
    shared_worker: BrowserExecutionLadderSummary,
    service_worker_broker: BrowserWorkerSupportSummary,
    shared_worker_coordinator_main_thread: BrowserWorkerSupportSummary,
    shared_worker_coordinator_dedicated_worker: BrowserWorkerSupportSummary,
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
    unsupported_worker_ladders: UnsupportedWorkerLaddersSummary,
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

fn worker_fallback_target_str(target: BrowserWorkerFallbackTarget) -> &'static str {
    target.as_str()
}

fn service_worker_broker_support_reason_str(
    reason: BrowserServiceWorkerBrokerSupportReason,
) -> &'static str {
    reason.as_str()
}

fn shared_worker_coordinator_support_reason_str(
    reason: BrowserSharedWorkerCoordinatorSupportReason,
) -> &'static str {
    reason.as_str()
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

fn browser_service_worker_broker_support_summary(
    diagnostics: BrowserServiceWorkerBrokerSupportDiagnostics,
) -> BrowserWorkerSupportSummary {
    BrowserWorkerSupportSummary {
        supported: diagnostics.supported,
        contract_id: diagnostics.contract_id,
        requested_lane: diagnostics.requested_lane,
        fallback_target: worker_fallback_target_str(diagnostics.fallback_target),
        fallback_lane_id: diagnostics.fallback_lane_id.map(lane_str),
        host_role: host_role_str(diagnostics.host_role),
        runtime_context: runtime_context_str(diagnostics.runtime_context),
        reason: service_worker_broker_support_reason_str(diagnostics.reason),
        direct_runtime_reason: runtime_support_reason_str(diagnostics.direct_runtime_reason),
        direct_execution_reason_code: reason_code_str(diagnostics.direct_execution_reason_code),
        downgrade_order: diagnostics
            .downgrade_order
            .into_iter()
            .map(worker_fallback_target_str)
            .collect(),
        message: diagnostics.message,
        guidance: diagnostics.guidance,
        capabilities: browser_capability_summary(diagnostics.capabilities),
    }
}

fn browser_shared_worker_coordinator_support_summary(
    diagnostics: BrowserSharedWorkerCoordinatorSupportDiagnostics,
) -> BrowserWorkerSupportSummary {
    BrowserWorkerSupportSummary {
        supported: diagnostics.supported,
        contract_id: diagnostics.contract_id,
        requested_lane: diagnostics.requested_lane,
        fallback_target: worker_fallback_target_str(diagnostics.fallback_target),
        fallback_lane_id: diagnostics.fallback_lane_id.map(lane_str),
        host_role: host_role_str(diagnostics.host_role),
        runtime_context: runtime_context_str(diagnostics.runtime_context),
        reason: shared_worker_coordinator_support_reason_str(diagnostics.reason),
        direct_runtime_reason: runtime_support_reason_str(diagnostics.direct_runtime_reason),
        direct_execution_reason_code: reason_code_str(diagnostics.direct_execution_reason_code),
        downgrade_order: diagnostics
            .downgrade_order
            .into_iter()
            .map(worker_fallback_target_str)
            .collect(),
        message: diagnostics.message,
        guidance: diagnostics.guidance,
        capabilities: browser_capability_summary(diagnostics.capabilities),
    }
}

fn unsupported_worker_ladders_summary() -> UnsupportedWorkerLaddersSummary {
    let builder = RuntimeBuilder::new();
    UnsupportedWorkerLaddersSummary {
        service_worker:
            browser_execution_ladder_summary(
                builder.inspect_browser_execution_ladder_for_probe(
                    BrowserExecutionProbe::service_worker(),
                ),
            ),
        shared_worker: browser_execution_ladder_summary(
            builder
                .inspect_browser_execution_ladder_for_probe(BrowserExecutionProbe::shared_worker()),
        ),
        service_worker_broker: browser_service_worker_broker_support_summary(
            builder.inspect_browser_service_worker_broker_support_for_probe(
                BrowserExecutionProbe::service_worker(),
            ),
        ),
        shared_worker_coordinator_main_thread: browser_shared_worker_coordinator_support_summary(
            builder.inspect_browser_shared_worker_coordinator_support_for_probe(
                BrowserExecutionProbe::browser_main_thread(),
            ),
        ),
        shared_worker_coordinator_dedicated_worker:
            browser_shared_worker_coordinator_support_summary(
                builder.inspect_browser_shared_worker_coordinator_support_for_probe(
                    BrowserExecutionProbe::dedicated_worker(),
                ),
            ),
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

fn outcome_envelope_str(outcome: &WasmAbiOutcomeEnvelope) -> &'static str {
    match outcome {
        WasmAbiOutcomeEnvelope::Ok { .. } => "ok",
        WasmAbiOutcomeEnvelope::Err { .. } => "err",
        WasmAbiOutcomeEnvelope::Cancelled { .. } => "cancelled",
        WasmAbiOutcomeEnvelope::Panicked { .. } => "panicked",
    }
}

fn select_browser_runtime(
    preferred_lane: Option<BrowserExecutionLane>,
) -> Result<BrowserRuntimeSelectionSummary, JsValue> {
    let builder = preferred_lane.map_or_else(RuntimeBuilder::browser, |lane| {
        RuntimeBuilder::browser().preferred_lane(lane)
    });
    let selection = builder.build_selection();
    let mut scope_close_outcome = None;
    let mut runtime_close_outcome = None;
    let mut dispatch_count = None;
    let mut diagnostics_clean = None;

    if let Some(runtime) = selection.runtime.clone() {
        let scope = runtime
            .enter_scope(Some("rust-browser-builder-smoke"))
            .map_err(|err| js_error(format!("browser builder enter_scope failed: {err}")))?;

        let scope_close = runtime
            .close_scope(&scope)
            .map_err(|err| js_error(format!("browser builder close_scope failed: {err}")))?;
        scope_close_outcome = Some(outcome_envelope_str(&scope_close));

        let runtime_close = runtime
            .close()
            .map_err(|err| js_error(format!("browser builder close failed: {err}")))?;
        runtime_close_outcome = Some(outcome_envelope_str(&runtime_close));

        let dispatcher_diagnostics = runtime.dispatcher_diagnostics();
        dispatch_count = Some(dispatcher_diagnostics.dispatch_count);
        diagnostics_clean = Some(dispatcher_diagnostics.is_clean());
    }

    Ok(BrowserRuntimeSelectionSummary {
        preferred_lane: preferred_lane.map(lane_str),
        selected_lane: lane_str(selection.execution_ladder.selected_lane),
        supported: selection.execution_ladder.supported,
        reason_code: reason_code_str(selection.execution_ladder.reason_code),
        runtime_available: selection.runtime_available(),
        error_message: selection.error.map(|error| error.to_string()),
        scope_close_outcome,
        runtime_close_outcome,
        dispatch_count,
        diagnostics_clean,
    })
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
        unsupported_worker_ladders: unsupported_worker_ladders_summary(),
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

#[wasm_bindgen]
pub fn select_rust_browser_runtime() -> Result<JsValue, JsValue> {
    serde_wasm_bindgen::to_value(&select_browser_runtime(None)?)
        .map_err(|err| js_error(format!("failed to encode browser runtime selection: {err}")))
}

#[wasm_bindgen]
pub fn select_rust_browser_runtime_preferred_main_thread() -> Result<JsValue, JsValue> {
    serde_wasm_bindgen::to_value(&select_browser_runtime(Some(
        BrowserExecutionLane::BrowserMainThreadDirectRuntime,
    ))?)
    .map_err(|err| {
        js_error(format!(
            "failed to encode preferred main-thread browser selection: {err}"
        ))
    })
}

#[wasm_bindgen]
pub fn select_rust_browser_runtime_preferred_dedicated_worker() -> Result<JsValue, JsValue> {
    serde_wasm_bindgen::to_value(&select_browser_runtime(Some(
        BrowserExecutionLane::DedicatedWorkerDirectRuntime,
    ))?)
    .map_err(|err| {
        js_error(format!(
            "failed to encode preferred dedicated-worker browser selection: {err}"
        ))
    })
}
