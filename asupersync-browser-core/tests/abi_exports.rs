use asupersync::types::{
    WASM_ABI_MAJOR_VERSION, WASM_ABI_MINOR_VERSION, WASM_ABI_SIGNATURE_FINGERPRINT_V1,
    WasmAbiErrorCode, WasmAbiFailure, WasmAbiOutcomeEnvelope, WasmAbiValue, WasmAbiVersion,
    WasmFetchRequest, WasmHandleKind, WasmHandleRef, WasmScopeEnterRequest, WasmTaskCancelRequest,
    WasmTaskSpawnRequest,
};
use asupersync_browser_core::types::{
    BROWSER_OPERATOR_SNAPSHOT_SCHEMA_VERSION, BrowserOperatorConsoleSnapshot,
    BrowserOperatorSnapshotKind,
};
use asupersync_browser_core::{
    abi_fingerprint, abi_version, browser_operator_snapshot, dispatcher_diagnostics_for_tests,
    fetch_request, reset_dispatcher_for_tests, runtime_close, runtime_create, scope_close,
    scope_enter, task_cancel, task_join, task_spawn, websocket_cancel, websocket_close,
    websocket_open, websocket_recv, websocket_send,
};

fn parse_json<T: serde::de::DeserializeOwned>(raw: &str) -> T {
    serde_json::from_str(raw).expect("valid JSON payload")
}

fn to_json<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string(value).expect("serialize JSON")
}

#[cfg(target_arch = "wasm32")]
fn error_message(err: wasm_bindgen::JsValue) -> String {
    err.as_string().unwrap_or_else(|| format!("{err:?}"))
}

#[cfg(not(target_arch = "wasm32"))]
const fn error_message(err: String) -> String {
    err
}

fn incompatible_consumer_version_json() -> String {
    to_json(&WasmAbiVersion {
        major: WASM_ABI_MAJOR_VERSION + 1,
        minor: WASM_ABI_MINOR_VERSION,
    })
}

fn backward_compatible_consumer_version_json() -> String {
    to_json(&WasmAbiVersion {
        major: WASM_ABI_MAJOR_VERSION,
        minor: WASM_ABI_MINOR_VERSION + 1,
    })
}

#[test]
fn runtime_create_and_close_round_trip() {
    reset_dispatcher_for_tests();

    let runtime_json = runtime_create(None).expect("runtime_create succeeds");
    let runtime: WasmHandleRef = parse_json(&runtime_json);
    assert_eq!(runtime.kind, WasmHandleKind::Runtime);

    let close_json = runtime_close(runtime_json.clone(), None).expect("runtime_close succeeds");
    let close: WasmAbiOutcomeEnvelope = parse_json(&close_json);
    assert!(matches!(
        close,
        WasmAbiOutcomeEnvelope::Ok {
            value: WasmAbiValue::Unit
        }
    ));

    let err = runtime_close(runtime_json, None).expect_err("double close must fail");
    let msg = error_message(err);
    if let Ok(failure) = serde_json::from_str::<WasmAbiFailure>(&msg) {
        assert_eq!(failure.code, WasmAbiErrorCode::InvalidHandle);
    } else {
        assert!(
            msg.contains("invalid handle") || msg.contains("released") || msg.contains("handle")
        );
    }
}

#[test]
fn browser_operator_snapshot_export_projects_live_dispatcher_diagnostics() {
    reset_dispatcher_for_tests();

    let empty_json = browser_operator_snapshot().expect("empty snapshot succeeds");
    let empty: BrowserOperatorConsoleSnapshot = parse_json(&empty_json);
    assert_eq!(
        empty.schema_version,
        BROWSER_OPERATOR_SNAPSHOT_SCHEMA_VERSION
    );
    assert_eq!(empty.kind, BrowserOperatorSnapshotKind::EmptyRuntime);
    assert_eq!(empty.runtime.logical_tick, 0);
    assert_eq!(empty.regions.total, 1);
    assert_eq!(empty.tasks.total, 0);
    assert!(empty.has_fail_closed_native_omissions());

    let runtime_json = runtime_create(None).expect("runtime_create succeeds");
    let runtime: WasmHandleRef = parse_json(&runtime_json);
    let scope_json = scope_enter(
        to_json(&WasmScopeEnterRequest {
            parent: runtime,
            label: Some("operator-snapshot".to_string()),
        }),
        None,
    )
    .expect("scope_enter succeeds");
    let scope: WasmHandleRef = parse_json(&scope_json);
    let task_json = task_spawn(
        to_json(&WasmTaskSpawnRequest {
            scope,
            label: Some("snapshot-worker".to_string()),
            cancel_kind: Some("operator".to_string()),
        }),
        None,
    )
    .expect("task_spawn succeeds");

    let live_json = browser_operator_snapshot().expect("live snapshot succeeds");
    let live: BrowserOperatorConsoleSnapshot = parse_json(&live_json);
    assert_eq!(live.kind, BrowserOperatorSnapshotKind::LoadedRuntime);
    assert_eq!(live.runtime.logical_tick, 3);
    assert_eq!(live.regions.total, 2);
    assert_eq!(live.tasks.total, 1);
    assert!(live.proof_status.proof_fresh);
    assert_eq!(
        live.proof_status.proof_lane.as_deref(),
        Some("browser_operator_snapshot_live_dispatcher")
    );
    assert!(live.has_fail_closed_native_omissions());

    let join_input = WasmAbiOutcomeEnvelope::Ok {
        value: WasmAbiValue::String("done".to_string()),
    };
    task_join(task_json, to_json(&join_input), None).expect("task_join succeeds");
    scope_close(scope_json, None).expect("scope_close succeeds");
    runtime_close(runtime_json, None).expect("runtime_close succeeds");

    let closed_json = browser_operator_snapshot().expect("closed snapshot succeeds");
    let closed: BrowserOperatorConsoleSnapshot = parse_json(&closed_json);
    assert_eq!(closed.kind, BrowserOperatorSnapshotKind::EmptyRuntime);
    assert_eq!(closed.runtime.logical_tick, 6);
    assert_eq!(closed.tasks.total, 0);
}

#[test]
fn scope_task_cancel_and_join_surface() {
    reset_dispatcher_for_tests();

    let runtime_json = runtime_create(None).expect("runtime_create succeeds");
    let runtime: WasmHandleRef = parse_json(&runtime_json);

    let scope_req = WasmScopeEnterRequest {
        parent: runtime,
        label: Some("integration".to_string()),
    };
    let scope_json = scope_enter(to_json(&scope_req), None).expect("scope_enter succeeds");
    let scope: WasmHandleRef = parse_json(&scope_json);
    assert_eq!(scope.kind, WasmHandleKind::Region);

    let spawn_req = WasmTaskSpawnRequest {
        scope,
        label: Some("worker".to_string()),
        cancel_kind: Some("user".to_string()),
    };
    let task_json = task_spawn(to_json(&spawn_req), None).expect("task_spawn succeeds");
    let task: WasmHandleRef = parse_json(&task_json);
    assert_eq!(task.kind, WasmHandleKind::Task);

    let cancel_req = WasmTaskCancelRequest {
        task,
        kind: "user".to_string(),
        message: Some("stop".to_string()),
    };
    let cancel_outcome_json =
        task_cancel(to_json(&cancel_req), None).expect("task_cancel succeeds");
    let cancel_outcome: WasmAbiOutcomeEnvelope = parse_json(&cancel_outcome_json);
    assert!(matches!(
        cancel_outcome,
        WasmAbiOutcomeEnvelope::Ok {
            value: WasmAbiValue::Unit
        }
    ));

    let join_input = WasmAbiOutcomeEnvelope::Ok {
        value: WasmAbiValue::String("done".to_string()),
    };
    let join_json = task_join(task_json, to_json(&join_input), None).expect("task_join succeeds");
    let join: WasmAbiOutcomeEnvelope = parse_json(&join_json);
    assert_eq!(join, join_input);

    let scope_close_json = scope_close(scope_json, None).expect("scope_close succeeds");
    let scope_close_outcome: WasmAbiOutcomeEnvelope = parse_json(&scope_close_json);
    assert!(matches!(
        scope_close_outcome,
        WasmAbiOutcomeEnvelope::Ok {
            value: WasmAbiValue::Unit
        }
    ));

    let rt_close_json = runtime_close(runtime_json, None).expect("runtime close succeeds");
    let rt_close: WasmAbiOutcomeEnvelope = parse_json(&rt_close_json);
    assert!(matches!(
        rt_close,
        WasmAbiOutcomeEnvelope::Ok {
            value: WasmAbiValue::Unit
        }
    ));
}

#[test]
fn fetch_request_surface_and_validation() {
    reset_dispatcher_for_tests();

    let runtime_json = runtime_create(None).expect("runtime_create succeeds");
    let runtime: WasmHandleRef = parse_json(&runtime_json);

    let scope_req = WasmScopeEnterRequest {
        parent: runtime,
        label: None,
    };
    let scope_json = scope_enter(to_json(&scope_req), None).expect("scope_enter succeeds");
    let scope: WasmHandleRef = parse_json(&scope_json);

    let request = WasmFetchRequest {
        scope,
        url: "https://example.com/data".to_string(),
        method: "GET".to_string(),
        body: None,
    };
    let fetch_json = fetch_request(to_json(&request), None).expect("fetch_request succeeds");
    let fetch_outcome: WasmAbiOutcomeEnvelope = parse_json(&fetch_json);
    let fetch = match fetch_outcome {
        WasmAbiOutcomeEnvelope::Ok {
            value: WasmAbiValue::Handle(handle),
        } => handle,
        other => panic!("expected fetch_request to return handle outcome, got {other:?}"),
    };
    assert_eq!(fetch.kind, WasmHandleKind::FetchRequest);

    let bad_request = WasmFetchRequest {
        scope,
        url: String::new(),
        method: "GET".to_string(),
        body: None,
    };
    let err = fetch_request(to_json(&bad_request), None).expect_err("empty URL must fail");
    let msg = error_message(err);
    assert!(msg.contains("must not be empty"));

    let bad_method = WasmFetchRequest {
        scope,
        url: "https://example.com/data".to_string(),
        method: "TRACE".to_string(),
        body: None,
    };
    let err = fetch_request(to_json(&bad_method), None).expect_err("unsupported method must fail");
    let err = error_message(err);
    assert!(err.contains("unsupported fetch method"));

    let body_on_get = WasmFetchRequest {
        scope,
        url: "https://example.com/data".to_string(),
        method: "GET".to_string(),
        body: Some(vec![1, 2, 3]),
    };
    let err = fetch_request(to_json(&body_on_get), None).expect_err("GET body must be rejected");
    let err = error_message(err);
    assert!(err.contains("does not permit a request body"));
}

#[test]
fn abi_metadata_exports_match_runtime_constants() {
    let version_json = abi_version().expect("abi_version succeeds");
    let version: WasmAbiVersion = parse_json(&version_json);

    assert_eq!(version.major, WASM_ABI_MAJOR_VERSION);
    assert_eq!(version.minor, WASM_ABI_MINOR_VERSION);
    assert_eq!(abi_fingerprint(), WASM_ABI_SIGNATURE_FINGERPRINT_V1);
}

#[test]
fn runtime_create_rejects_incompatible_consumer_version_at_adapter_boundary() {
    reset_dispatcher_for_tests();

    let err = runtime_create(Some(incompatible_consumer_version_json()))
        .expect_err("incompatible consumer version must fail");
    let err = error_message(err);
    let failure: WasmAbiFailure = parse_json(&err);
    assert_eq!(failure.code, WasmAbiErrorCode::CompatibilityRejected);
    assert!(failure.message.contains("ABI incompatible"));

    let diagnostics = dispatcher_diagnostics_for_tests();
    assert!(
        diagnostics.is_clean(),
        "compatibility rejection should not leak boundary state: {diagnostics:?}"
    );
}

#[test]
fn adapter_boundary_accepts_backward_compatible_consumer_minor() {
    reset_dispatcher_for_tests();

    let consumer_version_json = backward_compatible_consumer_version_json();
    let runtime_json =
        runtime_create(Some(consumer_version_json.clone())).expect("runtime_create succeeds");
    let runtime: WasmHandleRef = parse_json(&runtime_json);

    let scope_json = scope_enter(
        to_json(&WasmScopeEnterRequest {
            parent: runtime,
            label: Some("compat".to_string()),
        }),
        Some(consumer_version_json.clone()),
    )
    .expect("scope_enter succeeds");
    let scope: WasmHandleRef = parse_json(&scope_json);
    assert_eq!(scope.kind, WasmHandleKind::Region);

    let fetch_json = fetch_request(
        to_json(&WasmFetchRequest {
            scope,
            url: "https://example.com/compat".to_string(),
            method: "GET".to_string(),
            body: None,
        }),
        Some(consumer_version_json.clone()),
    )
    .expect("fetch_request succeeds");
    let fetch_outcome: WasmAbiOutcomeEnvelope = parse_json(&fetch_json);
    assert!(matches!(
        fetch_outcome,
        WasmAbiOutcomeEnvelope::Ok {
            value: WasmAbiValue::Handle(_)
        }
    ));

    let scope_close_json =
        scope_close(scope_json, Some(consumer_version_json.clone())).expect("scope_close succeeds");
    let scope_close_outcome: WasmAbiOutcomeEnvelope = parse_json(&scope_close_json);
    assert!(matches!(
        scope_close_outcome,
        WasmAbiOutcomeEnvelope::Ok {
            value: WasmAbiValue::Unit
        }
    ));

    let runtime_close_json =
        runtime_close(runtime_json, Some(consumer_version_json)).expect("runtime_close succeeds");
    let runtime_close_outcome: WasmAbiOutcomeEnvelope = parse_json(&runtime_close_json);
    assert!(matches!(
        runtime_close_outcome,
        WasmAbiOutcomeEnvelope::Ok {
            value: WasmAbiValue::Unit
        }
    ));

    let diagnostics = dispatcher_diagnostics_for_tests();
    assert!(
        diagnostics.is_clean(),
        "backward-compatible adapter flow should remain clean: {diagnostics:?}"
    );
}

#[test]
fn websocket_bridge_round_trip_and_cancel_surface() {
    reset_dispatcher_for_tests();

    let runtime_json = runtime_create(None).expect("runtime_create succeeds");
    let runtime: WasmHandleRef = parse_json(&runtime_json);
    let scope_req = WasmScopeEnterRequest {
        parent: runtime,
        label: Some("ws".to_string()),
    };
    let scope_json = scope_enter(to_json(&scope_req), None).expect("scope_enter succeeds");
    let scope: WasmHandleRef = parse_json(&scope_json);

    let open_json = websocket_open(
        serde_json::json!({
            "scope": scope,
            "url": "wss://example.com/socket",
            "protocols": ["chat.v1"]
        })
        .to_string(),
        None,
    )
    .expect("websocket_open succeeds");
    let open_outcome: WasmAbiOutcomeEnvelope = parse_json(&open_json);
    let socket = match open_outcome {
        WasmAbiOutcomeEnvelope::Ok {
            value: WasmAbiValue::Handle(handle),
        } => handle,
        other => panic!("expected websocket_open handle outcome, got {other:?}"),
    };

    let send_json = websocket_send(
        serde_json::json!({
            "socket": socket,
            "value": {"kind": "string", "value": "hello"}
        })
        .to_string(),
        None,
    )
    .expect("websocket_send succeeds");
    let send_outcome: WasmAbiOutcomeEnvelope = parse_json(&send_json);
    assert!(matches!(
        send_outcome,
        WasmAbiOutcomeEnvelope::Ok {
            value: WasmAbiValue::Unit
        }
    ));

    let recv_json = websocket_recv(serde_json::json!({"socket": socket}).to_string(), None)
        .expect("websocket_recv succeeds");
    let recv_outcome: WasmAbiOutcomeEnvelope = parse_json(&recv_json);
    assert!(matches!(
        recv_outcome,
        WasmAbiOutcomeEnvelope::Ok {
            value: WasmAbiValue::String(ref text)
        } if text == "hello"
    ));

    let cancel_json = websocket_cancel(
        serde_json::json!({
            "socket": socket,
            "kind": "user",
            "message": "stop"
        })
        .to_string(),
        None,
    )
    .expect("websocket_cancel succeeds");
    let cancel_outcome: WasmAbiOutcomeEnvelope = parse_json(&cancel_json);
    assert!(matches!(
        cancel_outcome,
        WasmAbiOutcomeEnvelope::Cancelled { .. }
    ));

    let scope_close_json = scope_close(scope_json, None).expect("scope_close succeeds");
    let scope_close_outcome: WasmAbiOutcomeEnvelope = parse_json(&scope_close_json);
    assert!(matches!(
        scope_close_outcome,
        WasmAbiOutcomeEnvelope::Ok {
            value: WasmAbiValue::Unit
        }
    ));

    let rt_close_json = runtime_close(runtime_json, None).expect("runtime_close succeeds");
    let rt_close: WasmAbiOutcomeEnvelope = parse_json(&rt_close_json);
    assert!(matches!(
        rt_close,
        WasmAbiOutcomeEnvelope::Ok {
            value: WasmAbiValue::Unit
        }
    ));
}

#[test]
fn websocket_bridge_close_and_validation_surface() {
    reset_dispatcher_for_tests();

    let runtime_json = runtime_create(None).expect("runtime_create succeeds");
    let runtime: WasmHandleRef = parse_json(&runtime_json);
    let scope_req = WasmScopeEnterRequest {
        parent: runtime,
        label: Some("ws-close".to_string()),
    };
    let scope_json = scope_enter(to_json(&scope_req), None).expect("scope_enter succeeds");
    let scope: WasmHandleRef = parse_json(&scope_json);

    let open_json = websocket_open(
        serde_json::json!({
            "scope": scope,
            "url": "wss://example.com/socket"
        })
        .to_string(),
        None,
    )
    .expect("websocket_open succeeds");
    let open_outcome: WasmAbiOutcomeEnvelope = parse_json(&open_json);
    let socket = match open_outcome {
        WasmAbiOutcomeEnvelope::Ok {
            value: WasmAbiValue::Handle(handle),
        } => handle,
        other => panic!("expected websocket_open handle outcome, got {other:?}"),
    };

    let close_json = websocket_close(
        serde_json::json!({
            "socket": socket,
            "reason": "test complete"
        })
        .to_string(),
        None,
    )
    .expect("websocket_close succeeds");
    let close_outcome: WasmAbiOutcomeEnvelope = parse_json(&close_json);
    assert!(matches!(
        close_outcome,
        WasmAbiOutcomeEnvelope::Cancelled { .. }
    ));

    let err = websocket_open(
        serde_json::json!({
            "scope": scope,
            "url": "https://example.com/socket"
        })
        .to_string(),
        None,
    )
    .expect_err("non-websocket scheme must fail");
    let err = error_message(err);
    assert!(err.contains("must start with ws:// or wss://"));

    let scope_close_json = scope_close(scope_json, None).expect("scope_close succeeds");
    let scope_close_outcome: WasmAbiOutcomeEnvelope = parse_json(&scope_close_json);
    assert!(matches!(
        scope_close_outcome,
        WasmAbiOutcomeEnvelope::Ok {
            value: WasmAbiValue::Unit
        }
    ));

    let rt_close_json = runtime_close(runtime_json, None).expect("runtime_close succeeds");
    let rt_close: WasmAbiOutcomeEnvelope = parse_json(&rt_close_json);
    assert!(matches!(
        rt_close,
        WasmAbiOutcomeEnvelope::Ok {
            value: WasmAbiValue::Unit
        }
    ));
}

#[test]
fn websocket_close_failure_preserves_host_state_for_retry() {
    reset_dispatcher_for_tests();

    let runtime_json = runtime_create(None).expect("runtime_create succeeds");
    let runtime: WasmHandleRef = parse_json(&runtime_json);
    let scope_json = scope_enter(
        to_json(&WasmScopeEnterRequest {
            parent: runtime,
            label: Some("ws-close-retry".to_string()),
        }),
        None,
    )
    .expect("scope_enter succeeds");
    let scope: WasmHandleRef = parse_json(&scope_json);

    let open_json = websocket_open(
        serde_json::json!({
            "scope": scope,
            "url": "wss://example.com/retry-close"
        })
        .to_string(),
        None,
    )
    .expect("websocket_open succeeds");
    let open_outcome: WasmAbiOutcomeEnvelope = parse_json(&open_json);
    let socket = match open_outcome {
        WasmAbiOutcomeEnvelope::Ok {
            value: WasmAbiValue::Handle(handle),
        } => handle,
        other => panic!("expected websocket_open handle outcome, got {other:?}"),
    };

    let err = websocket_close(
        serde_json::json!({
            "socket": socket,
            "reason": "x".repeat(124)
        })
        .to_string(),
        None,
    )
    .expect_err("oversized close reason must fail");
    let err = error_message(err);
    assert!(err.contains("exceeds 123 bytes"), "got: {err}");

    let diagnostics = dispatcher_diagnostics_for_tests();
    assert_eq!(diagnostics.memory_report.live_handles, 3);

    websocket_send(
        serde_json::json!({
            "socket": socket,
            "value": {"kind": "string", "value": "still-live"}
        })
        .to_string(),
        None,
    )
    .expect("send after failed close preserves websocket state");
    let recv_json = websocket_recv(serde_json::json!({"socket": socket}).to_string(), None)
        .expect("recv after failed close succeeds");
    let recv_outcome: WasmAbiOutcomeEnvelope = parse_json(&recv_json);
    assert!(matches!(
        recv_outcome,
        WasmAbiOutcomeEnvelope::Ok {
            value: WasmAbiValue::String(ref text)
        } if text == "still-live"
    ));

    let close_json = websocket_close(serde_json::json!({"socket": socket}).to_string(), None)
        .expect("retry close succeeds");
    let close_outcome: WasmAbiOutcomeEnvelope = parse_json(&close_json);
    assert!(matches!(
        close_outcome,
        WasmAbiOutcomeEnvelope::Ok {
            value: WasmAbiValue::Unit
        }
    ));

    scope_close(scope_json, None).expect("scope_close succeeds");
    runtime_close(runtime_json, None).expect("runtime_close succeeds");

    let diagnostics = dispatcher_diagnostics_for_tests();
    assert!(
        diagnostics.is_clean(),
        "expected clean diagnostics: {diagnostics:?}"
    );
}

#[test]
fn websocket_cancel_failure_preserves_host_state_for_cleanup() {
    reset_dispatcher_for_tests();

    let runtime_json = runtime_create(None).expect("runtime_create succeeds");
    let runtime: WasmHandleRef = parse_json(&runtime_json);
    let scope_json = scope_enter(
        to_json(&WasmScopeEnterRequest {
            parent: runtime,
            label: Some("ws-cancel-retry".to_string()),
        }),
        None,
    )
    .expect("scope_enter succeeds");
    let scope: WasmHandleRef = parse_json(&scope_json);

    let open_json = websocket_open(
        serde_json::json!({
            "scope": scope,
            "url": "wss://example.com/retry-cancel"
        })
        .to_string(),
        None,
    )
    .expect("websocket_open succeeds");
    let open_outcome: WasmAbiOutcomeEnvelope = parse_json(&open_json);
    let socket = match open_outcome {
        WasmAbiOutcomeEnvelope::Ok {
            value: WasmAbiValue::Handle(handle),
        } => handle,
        other => panic!("expected websocket_open handle outcome, got {other:?}"),
    };

    let err = websocket_cancel(
        serde_json::json!({
            "socket": socket,
            "kind": "user",
            "message": "x".repeat(124)
        })
        .to_string(),
        None,
    )
    .expect_err("oversized cancel message must fail");
    let err = error_message(err);
    assert!(err.contains("exceeds 123 bytes"), "got: {err}");

    let diagnostics = dispatcher_diagnostics_for_tests();
    assert_eq!(diagnostics.memory_report.live_handles, 3);

    let close_json = websocket_close(
        serde_json::json!({
            "socket": socket,
            "reason": "cleanup"
        })
        .to_string(),
        None,
    )
    .expect("close after failed cancel succeeds");
    let close_outcome: WasmAbiOutcomeEnvelope = parse_json(&close_json);
    assert!(matches!(
        close_outcome,
        WasmAbiOutcomeEnvelope::Cancelled { .. }
    ));

    scope_close(scope_json, None).expect("scope_close succeeds");
    runtime_close(runtime_json, None).expect("runtime_close succeeds");

    let diagnostics = dispatcher_diagnostics_for_tests();
    assert!(
        diagnostics.is_clean(),
        "expected clean diagnostics: {diagnostics:?}"
    );
}

#[test]
fn websocket_binary_message_round_trip() {
    reset_dispatcher_for_tests();

    let runtime_json = runtime_create(None).expect("runtime_create succeeds");
    let runtime: WasmHandleRef = parse_json(&runtime_json);
    let scope_req = WasmScopeEnterRequest {
        parent: runtime,
        label: Some("ws-binary".to_string()),
    };
    let scope_json = scope_enter(to_json(&scope_req), None).expect("scope_enter succeeds");
    let scope: WasmHandleRef = parse_json(&scope_json);

    let open_json = websocket_open(
        serde_json::json!({
            "scope": scope,
            "url": "wss://example.com/binary"
        })
        .to_string(),
        None,
    )
    .expect("websocket_open succeeds");
    let open_outcome: WasmAbiOutcomeEnvelope = parse_json(&open_json);
    let socket = match open_outcome {
        WasmAbiOutcomeEnvelope::Ok {
            value: WasmAbiValue::Handle(handle),
        } => handle,
        other => panic!("expected handle, got {other:?}"),
    };

    // Send binary message
    let send_json = websocket_send(
        serde_json::json!({
            "socket": socket,
            "value": {"kind": "bytes", "value": [72, 101, 108, 108, 111]}
        })
        .to_string(),
        None,
    )
    .expect("websocket_send binary succeeds");
    let send_outcome: WasmAbiOutcomeEnvelope = parse_json(&send_json);
    assert!(matches!(
        send_outcome,
        WasmAbiOutcomeEnvelope::Ok {
            value: WasmAbiValue::Unit
        }
    ));

    // Recv the binary message (host adapter echoes to inbox)
    let recv_json = websocket_recv(serde_json::json!({"socket": socket}).to_string(), None)
        .expect("websocket_recv succeeds");
    let recv_outcome: WasmAbiOutcomeEnvelope = parse_json(&recv_json);
    assert!(matches!(
        recv_outcome,
        WasmAbiOutcomeEnvelope::Ok {
            value: WasmAbiValue::Bytes(ref data)
        } if data == &[72, 101, 108, 108, 111]
    ));

    // Close and teardown
    websocket_close(serde_json::json!({"socket": socket}).to_string(), None)
        .expect("websocket_close succeeds");
    scope_close(scope_json, None).expect("scope_close succeeds");
    runtime_close(runtime_json, None).expect("runtime_close succeeds");
}

#[test]
fn websocket_recv_empty_returns_idle() {
    reset_dispatcher_for_tests();

    let runtime_json = runtime_create(None).expect("runtime_create succeeds");
    let runtime: WasmHandleRef = parse_json(&runtime_json);
    let scope_req = WasmScopeEnterRequest {
        parent: runtime,
        label: Some("ws-idle".to_string()),
    };
    let scope_json = scope_enter(to_json(&scope_req), None).expect("scope_enter succeeds");
    let scope: WasmHandleRef = parse_json(&scope_json);

    let open_json = websocket_open(
        serde_json::json!({
            "scope": scope,
            "url": "ws://example.com/idle"
        })
        .to_string(),
        None,
    )
    .expect("websocket_open succeeds");
    let open_outcome: WasmAbiOutcomeEnvelope = parse_json(&open_json);
    let socket = match open_outcome {
        WasmAbiOutcomeEnvelope::Ok {
            value: WasmAbiValue::Handle(handle),
        } => handle,
        other => panic!("expected handle, got {other:?}"),
    };

    // Recv from empty queue returns idle (Unit)
    let recv_json = websocket_recv(serde_json::json!({"socket": socket}).to_string(), None)
        .expect("websocket_recv succeeds");
    let recv_outcome: WasmAbiOutcomeEnvelope = parse_json(&recv_json);
    assert!(
        matches!(
            recv_outcome,
            WasmAbiOutcomeEnvelope::Ok {
                value: WasmAbiValue::Unit
            }
        ),
        "recv from empty queue should return Unit (idle), got {recv_outcome:?}"
    );

    // Teardown
    websocket_cancel(
        serde_json::json!({"socket": socket, "kind": "cleanup", "message": "test done"})
            .to_string(),
        None,
    )
    .expect("websocket_cancel succeeds");
    scope_close(scope_json, None).expect("scope_close succeeds");
    runtime_close(runtime_json, None).expect("runtime_close succeeds");
}

#[test]
fn websocket_multiple_handles_in_same_scope() {
    reset_dispatcher_for_tests();

    let runtime_json = runtime_create(None).expect("runtime_create succeeds");
    let runtime: WasmHandleRef = parse_json(&runtime_json);
    let scope_req = WasmScopeEnterRequest {
        parent: runtime,
        label: Some("ws-multi".to_string()),
    };
    let scope_json = scope_enter(to_json(&scope_req), None).expect("scope_enter succeeds");
    let scope: WasmHandleRef = parse_json(&scope_json);

    // Open two WebSocket connections in the same scope
    let open1_json = websocket_open(
        serde_json::json!({"scope": scope, "url": "wss://example.com/ws1"}).to_string(),
        None,
    )
    .expect("websocket_open 1 succeeds");
    let socket1 = match parse_json::<WasmAbiOutcomeEnvelope>(&open1_json) {
        WasmAbiOutcomeEnvelope::Ok {
            value: WasmAbiValue::Handle(h),
        } => h,
        other => panic!("expected handle, got {other:?}"),
    };

    let open2_json = websocket_open(
        serde_json::json!({"scope": scope, "url": "wss://example.com/ws2"}).to_string(),
        None,
    )
    .expect("websocket_open 2 succeeds");
    let socket2 = match parse_json::<WasmAbiOutcomeEnvelope>(&open2_json) {
        WasmAbiOutcomeEnvelope::Ok {
            value: WasmAbiValue::Handle(h),
        } => h,
        other => panic!("expected handle, got {other:?}"),
    };

    // Handles are distinct
    assert_ne!(
        socket1.slot, socket2.slot,
        "WebSocket handles must be distinct"
    );

    // Send on each, they don't interfere
    websocket_send(
        serde_json::json!({"socket": socket1, "value": {"kind": "string", "value": "msg1"}})
            .to_string(),
        None,
    )
    .expect("send on ws1");
    websocket_send(
        serde_json::json!({"socket": socket2, "value": {"kind": "string", "value": "msg2"}})
            .to_string(),
        None,
    )
    .expect("send on ws2");

    // Recv from each gets the right message
    let recv1: WasmAbiOutcomeEnvelope = parse_json(
        &websocket_recv(serde_json::json!({"socket": socket1}).to_string(), None).unwrap(),
    );
    assert!(
        matches!(
            recv1,
            WasmAbiOutcomeEnvelope::Ok { value: WasmAbiValue::String(ref s) } if s == "msg1"
        ),
        "ws1 recv should get msg1, got {recv1:?}"
    );

    let recv2: WasmAbiOutcomeEnvelope = parse_json(
        &websocket_recv(serde_json::json!({"socket": socket2}).to_string(), None).unwrap(),
    );
    assert!(
        matches!(
            recv2,
            WasmAbiOutcomeEnvelope::Ok { value: WasmAbiValue::String(ref s) } if s == "msg2"
        ),
        "ws2 recv should get msg2, got {recv2:?}"
    );

    // Close both and teardown
    websocket_cancel(
        serde_json::json!({"socket": socket1, "kind": "cleanup"}).to_string(),
        None,
    )
    .expect("cancel ws1");
    websocket_cancel(
        serde_json::json!({"socket": socket2, "kind": "cleanup"}).to_string(),
        None,
    )
    .expect("cancel ws2");
    scope_close(scope_json, None).expect("scope_close");
    runtime_close(runtime_json, None).expect("runtime_close");
}

#[test]
fn websocket_url_validation_rejects_empty_and_bad_schemes() {
    reset_dispatcher_for_tests();

    let runtime_json = runtime_create(None).expect("runtime_create succeeds");
    let runtime: WasmHandleRef = parse_json(&runtime_json);
    let scope_req = WasmScopeEnterRequest {
        parent: runtime,
        label: Some("ws-val".to_string()),
    };
    let scope_json = scope_enter(to_json(&scope_req), None).expect("scope_enter succeeds");
    let scope: WasmHandleRef = parse_json(&scope_json);

    // Empty URL
    let err = websocket_open(
        serde_json::json!({"scope": scope, "url": ""}).to_string(),
        None,
    )
    .expect_err("empty URL must fail");
    let err = error_message(err);
    assert!(err.contains("must not be empty"), "got: {err}");

    // HTTP scheme
    let err = websocket_open(
        serde_json::json!({"scope": scope, "url": "http://example.com/ws"}).to_string(),
        None,
    )
    .expect_err("http scheme must fail");
    let err = error_message(err);
    assert!(
        err.contains("must start with ws:// or wss://"),
        "got: {err}"
    );

    // HTTPS scheme
    let err = websocket_open(
        serde_json::json!({"scope": scope, "url": "https://example.com/ws"}).to_string(),
        None,
    )
    .expect_err("https scheme must fail");
    let err = error_message(err);
    assert!(
        err.contains("must start with ws:// or wss://"),
        "got: {err}"
    );

    // Teardown
    scope_close(scope_json, None).expect("scope_close");
    runtime_close(runtime_json, None).expect("runtime_close");
}

#[test]
fn websocket_url_validation_accepts_mixed_case_ws_schemes() {
    reset_dispatcher_for_tests();

    let runtime_json = runtime_create(None).expect("runtime_create succeeds");
    let runtime: WasmHandleRef = parse_json(&runtime_json);
    let scope_req = WasmScopeEnterRequest {
        parent: runtime,
        label: Some("ws-case-insensitive".to_string()),
    };
    let scope_json = scope_enter(to_json(&scope_req), None).expect("scope_enter succeeds");
    let scope: WasmHandleRef = parse_json(&scope_json);

    for url in ["WSS://example.com/ws", "Ws://example.com/ws"] {
        let open_json = websocket_open(
            serde_json::json!({"scope": scope, "url": url}).to_string(),
            None,
        )
        .expect("mixed-case websocket scheme should succeed");
        let open_outcome: WasmAbiOutcomeEnvelope = parse_json(&open_json);
        let socket = match open_outcome {
            WasmAbiOutcomeEnvelope::Ok {
                value: WasmAbiValue::Handle(handle),
            } => handle,
            other => panic!("expected handle outcome for {url}, got {other:?}"),
        };

        websocket_cancel(
            serde_json::json!({
                "socket": socket,
                "kind": "cleanup",
                "message": format!("closing {url}")
            })
            .to_string(),
            None,
        )
        .expect("cleanup cancel succeeds");
    }

    scope_close(scope_json, None).expect("scope_close");
    runtime_close(runtime_json, None).expect("runtime_close");

    let diagnostics = dispatcher_diagnostics_for_tests();
    assert!(
        diagnostics.is_clean(),
        "expected clean diagnostics after mixed-case websocket validation: {diagnostics:?}"
    );
}

#[test]
fn runtime_close_drains_open_scope_task_and_fetch_handles() {
    reset_dispatcher_for_tests();

    let runtime_json = runtime_create(None).expect("runtime_create succeeds");
    let runtime: WasmHandleRef = parse_json(&runtime_json);
    let scope_json = scope_enter(
        to_json(&WasmScopeEnterRequest {
            parent: runtime,
            label: Some("auto-drain".to_string()),
        }),
        None,
    )
    .expect("scope_enter succeeds");
    let scope: WasmHandleRef = parse_json(&scope_json);

    let task_json = task_spawn(
        to_json(&WasmTaskSpawnRequest {
            scope,
            label: Some("worker".to_string()),
            cancel_kind: Some("user".to_string()),
        }),
        None,
    )
    .expect("task_spawn succeeds");
    let task: WasmHandleRef = parse_json(&task_json);

    let fetch_json = fetch_request(
        to_json(&WasmFetchRequest {
            scope,
            url: "https://example.com/data".to_string(),
            method: "GET".to_string(),
            body: None,
        }),
        None,
    )
    .expect("fetch_request succeeds");
    let fetch_outcome: WasmAbiOutcomeEnvelope = parse_json(&fetch_json);
    let fetch = match fetch_outcome {
        WasmAbiOutcomeEnvelope::Ok {
            value: WasmAbiValue::Handle(handle),
        } => handle,
        other => panic!("expected fetch handle outcome, got {other:?}"),
    };

    let close_json = runtime_close(runtime_json, None).expect("runtime_close succeeds");
    let close: WasmAbiOutcomeEnvelope = parse_json(&close_json);
    assert!(matches!(
        close,
        WasmAbiOutcomeEnvelope::Ok {
            value: WasmAbiValue::Unit
        }
    ));

    let stale_scope = scope_close(scope_json, None).expect_err("scope handle should be stale");
    let stale_scope = error_message(stale_scope);
    assert!(stale_scope.contains("stale handle") || stale_scope.contains("released"));

    let stale_task = task_cancel(
        to_json(&WasmTaskCancelRequest {
            task,
            kind: "user".to_string(),
            message: Some("too late".to_string()),
        }),
        None,
    )
    .expect_err("task handle should be stale");
    let stale_task = error_message(stale_task);
    assert!(stale_task.contains("stale handle") || stale_task.contains("released"));

    let stale_fetch = task_join(
        to_json(&fetch),
        to_json(&WasmAbiOutcomeEnvelope::Ok {
            value: WasmAbiValue::Unit,
        }),
        None,
    )
    .expect_err("fetch handle should be invalid for task join");
    let stale_fetch = error_message(stale_fetch);
    assert!(stale_fetch.contains("stale handle") || stale_fetch.contains("released"));

    let diagnostics = dispatcher_diagnostics_for_tests();
    assert!(
        diagnostics.is_clean(),
        "expected clean diagnostics: {diagnostics:?}"
    );
}

#[test]
fn scope_close_drains_nested_task_and_preserves_runtime() {
    reset_dispatcher_for_tests();

    let runtime_json = runtime_create(None).expect("runtime_create succeeds");
    let runtime: WasmHandleRef = parse_json(&runtime_json);
    let outer_scope_json = scope_enter(
        to_json(&WasmScopeEnterRequest {
            parent: runtime,
            label: Some("outer".to_string()),
        }),
        None,
    )
    .expect("outer scope_enter succeeds");
    let outer_scope: WasmHandleRef = parse_json(&outer_scope_json);
    let inner_scope_json = scope_enter(
        to_json(&WasmScopeEnterRequest {
            parent: outer_scope,
            label: Some("inner".to_string()),
        }),
        None,
    )
    .expect("inner scope_enter succeeds");
    let inner_scope: WasmHandleRef = parse_json(&inner_scope_json);

    let nested_task_json = task_spawn(
        to_json(&WasmTaskSpawnRequest {
            scope: inner_scope,
            label: Some("nested".to_string()),
            cancel_kind: None,
        }),
        None,
    )
    .expect("task_spawn succeeds");
    let nested_task: WasmHandleRef = parse_json(&nested_task_json);

    let close_json = scope_close(outer_scope_json, None).expect("scope_close succeeds");
    let close: WasmAbiOutcomeEnvelope = parse_json(&close_json);
    assert!(matches!(
        close,
        WasmAbiOutcomeEnvelope::Ok {
            value: WasmAbiValue::Unit
        }
    ));

    let stale_inner = scope_close(inner_scope_json, None).expect_err("inner scope should be stale");
    let stale_inner = error_message(stale_inner);
    assert!(stale_inner.contains("stale handle") || stale_inner.contains("released"));

    let stale_nested = task_join(
        nested_task_json,
        to_json(&WasmAbiOutcomeEnvelope::Ok {
            value: WasmAbiValue::Unit,
        }),
        None,
    )
    .expect_err("nested task should be stale");
    let stale_nested = error_message(stale_nested);
    assert!(stale_nested.contains("stale handle") || stale_nested.contains("released"));

    let runtime_close_json = runtime_close(runtime_json, None).expect("runtime_close succeeds");
    let runtime_close_outcome: WasmAbiOutcomeEnvelope = parse_json(&runtime_close_json);
    assert!(matches!(
        runtime_close_outcome,
        WasmAbiOutcomeEnvelope::Ok {
            value: WasmAbiValue::Unit
        }
    ));

    let diagnostics = dispatcher_diagnostics_for_tests();
    assert!(
        diagnostics.is_clean(),
        "expected clean diagnostics: {diagnostics:?}"
    );
    let _ = nested_task;
}

#[test]
fn cancelled_task_join_preserves_cancellation_payload_and_invalidates_handle() {
    reset_dispatcher_for_tests();

    let runtime_json = runtime_create(None).expect("runtime_create succeeds");
    let runtime: WasmHandleRef = parse_json(&runtime_json);
    let scope_json = scope_enter(
        to_json(&WasmScopeEnterRequest {
            parent: runtime,
            label: Some("cancelled-join".to_string()),
        }),
        None,
    )
    .expect("scope_enter succeeds");
    let scope: WasmHandleRef = parse_json(&scope_json);

    let task_json = task_spawn(
        to_json(&WasmTaskSpawnRequest {
            scope,
            label: Some("worker".to_string()),
            cancel_kind: Some("timeout".to_string()),
        }),
        None,
    )
    .expect("task_spawn succeeds");
    let task: WasmHandleRef = parse_json(&task_json);

    let cancel_json = task_cancel(
        to_json(&WasmTaskCancelRequest {
            task,
            kind: "timeout".to_string(),
            message: Some("deadline exceeded".to_string()),
        }),
        None,
    )
    .expect("task_cancel succeeds");
    let cancel_outcome: WasmAbiOutcomeEnvelope = parse_json(&cancel_json);
    assert!(matches!(
        cancel_outcome,
        WasmAbiOutcomeEnvelope::Ok {
            value: WasmAbiValue::Unit
        }
    ));

    let cancelled = WasmAbiOutcomeEnvelope::Cancelled {
        cancellation: asupersync::types::WasmAbiCancellation {
            kind: "timeout".to_string(),
            phase: "completed".to_string(),
            origin_region: "browser".to_string(),
            origin_task: Some("task-1".to_string()),
            timestamp_nanos: 42,
            message: Some("deadline exceeded".to_string()),
            truncated: false,
        },
    };
    let join_json =
        task_join(task_json.clone(), to_json(&cancelled), None).expect("task_join succeeds");
    let joined: WasmAbiOutcomeEnvelope = parse_json(&join_json);
    assert_eq!(joined, cancelled);

    let stale_join = task_join(
        task_json,
        to_json(&WasmAbiOutcomeEnvelope::Ok {
            value: WasmAbiValue::Unit,
        }),
        None,
    )
    .expect_err("joined task handle should be stale");
    let stale_join = error_message(stale_join);
    assert!(stale_join.contains("stale handle") || stale_join.contains("released"));

    let stale_cancel = task_cancel(
        to_json(&WasmTaskCancelRequest {
            task,
            kind: "user".to_string(),
            message: Some("late cancel".to_string()),
        }),
        None,
    )
    .expect_err("joined task should not accept another cancel");
    let stale_cancel = error_message(stale_cancel);
    assert!(stale_cancel.contains("stale handle") || stale_cancel.contains("released"));

    scope_close(scope_json, None).expect("scope_close succeeds");
    runtime_close(runtime_json, None).expect("runtime_close succeeds");

    let diagnostics = dispatcher_diagnostics_for_tests();
    assert!(
        diagnostics.is_clean(),
        "expected clean diagnostics: {diagnostics:?}"
    );
}

#[cfg(target_arch = "wasm32")]
mod writable_stream_cancellation {
    use asupersync::io::{AsyncWrite, WasmWritableStreamSink};
    use js_sys::Promise;
    use std::future::poll_fn;
    use std::pin::Pin;
    use std::task::{Context, Poll, Waker};
    use wasm_bindgen::JsValue;
    use wasm_bindgen::prelude::wasm_bindgen;
    use wasm_bindgen_futures::JsFuture;
    use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};
    use web_sys::WritableStream;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen(inline_js = r#"
        export function makeControlledWritableHarness() {
            const writes = [];
            const pending = [];
            const stream = new WritableStream({
                write(chunk) {
                    writes.push(Array.from(chunk));
                    return new Promise((resolve, reject) => {
                        pending.push({ resolve, reject });
                    });
                }
            });
            return { stream, writes, pending };
        }

        export function controlledWritableStream(harness) {
            return harness.stream;
        }

        export function controlledWritableWritesJson(harness) {
            return JSON.stringify(harness.writes);
        }

        export function resolveNextControlledWrite(harness) {
            const next = harness.pending.shift();
            if (next === undefined) {
                throw new Error("no controlled WritableStream write is pending");
            }
            next.resolve();
        }
    "#)]
    extern "C" {
        #[wasm_bindgen(js_name = makeControlledWritableHarness)]
        fn make_controlled_writable_harness() -> JsValue;

        #[wasm_bindgen(js_name = controlledWritableStream)]
        fn controlled_writable_stream(harness: &JsValue) -> WritableStream;

        #[wasm_bindgen(js_name = controlledWritableWritesJson)]
        fn controlled_writable_writes_json(harness: &JsValue) -> String;

        #[wasm_bindgen(js_name = resolveNextControlledWrite)]
        fn resolve_next_controlled_write(harness: &JsValue);
    }

    fn writes(harness: &JsValue) -> Vec<Vec<u8>> {
        serde_json::from_str(&controlled_writable_writes_json(harness))
            .expect("controlled write log must be valid JSON")
    }

    fn poll_write_once(
        sink: &mut WasmWritableStreamSink,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        Pin::new(sink).poll_write(&mut cx, buf)
    }

    async fn yield_microtask() {
        JsFuture::from(Promise::resolve(&JsValue::UNDEFINED))
            .await
            .expect("microtask yield must resolve");
    }

    async fn wait_for_write_count(harness: &JsValue, expected: usize) {
        for _ in 0..16 {
            if writes(harness).len() == expected {
                return;
            }
            yield_microtask().await;
        }
        panic!("WritableStream did not observe {expected} queued writes");
    }

    async fn poll_until_first_chunk_is_accepted(
        sink: &mut WasmWritableStreamSink,
        first: &[u8],
    ) -> std::io::Result<usize> {
        for _ in 0..16 {
            if let Poll::Ready(result) = poll_write_once(sink, first) {
                return result;
            }
            yield_microtask().await;
        }
        panic!("WritableStream writer.ready did not accept the first chunk");
    }

    async fn assert_cancelled_write_does_not_credit_old_chunk(first: &[u8], second: &[u8]) {
        let harness = make_controlled_writable_harness();
        let stream = controlled_writable_stream(&harness);
        let mut sink = WasmWritableStreamSink::new(&stream).expect("getWriter succeeds");

        let first_written = poll_until_first_chunk_is_accepted(&mut sink, first)
            .await
            .expect("first write succeeds");
        assert_eq!(first_written, first.len());
        wait_for_write_count(&harness, 1).await;
        assert_eq!(writes(&harness), vec![first.to_vec()]);

        // Model a second write future that is polled and then dropped while
        // the first chunk is still completing. No part of `second` may be
        // accepted or credited yet.
        assert!(poll_write_once(&mut sink, second).is_pending());
        assert_eq!(writes(&harness), vec![first.to_vec()]);

        resolve_next_controlled_write(&harness);
        yield_microtask().await;

        let second_written = poll_fn(|cx| Pin::new(&mut sink).poll_write(cx, second))
            .await
            .expect("second write succeeds");
        assert_eq!(second_written, second.len());
        wait_for_write_count(&harness, 2).await;
        assert_eq!(writes(&harness), vec![first.to_vec(), second.to_vec()]);

        resolve_next_controlled_write(&harness);
        poll_fn(|cx| Pin::new(&mut sink).poll_shutdown(cx))
            .await
            .expect("controlled stream closes cleanly");
    }

    #[wasm_bindgen_test]
    async fn cancelled_pending_write_with_unequal_lengths_enqueues_new_buffer() {
        assert_cancelled_write_does_not_credit_old_chunk(b"old", b"new-buffer").await;
    }

    #[wasm_bindgen_test]
    async fn cancelled_pending_write_with_equal_lengths_enqueues_new_buffer() {
        assert_cancelled_write_does_not_credit_old_chunk(b"old!", b"new!").await;
    }
}
