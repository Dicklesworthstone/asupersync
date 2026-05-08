//! JS-visible type wrappers and serialization helpers.
//!
//! Bridges between core ABI types (`WasmAbiOutcomeEnvelope`, `WasmHandleRef`,
//! etc.) and `JsValue` representations using `serde-wasm-bindgen`.
//!
//! This module focuses on deterministic payload marshalling for bead
//! `asupersync-3qv04.2.3`.

use asupersync::types::WasmAbiVersion;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsValue;

/// Stable schema identifier for browser operator console snapshots.
pub const BROWSER_OPERATOR_SNAPSHOT_SCHEMA_VERSION: &str = "browser-operator-snapshot-v1";

/// Decode a JSON payload string into a typed ABI value.
pub fn decode_json_payload<T: DeserializeOwned>(raw: &str, field: &str) -> Result<T, String> {
    serde_json::from_str(raw)
        .map_err(|err| format!("failed to decode {field} JSON payload: {err}; payload={raw}"))
}

/// Encode a typed ABI value into a JSON payload string.
pub fn encode_json_payload<T: Serialize>(value: &T, field: &str) -> Result<String, String> {
    serde_json::to_string(value)
        .map_err(|err| format!("failed to encode {field} JSON payload: {err}"))
}

/// Decode optional consumer ABI version from an optional JSON payload.
pub fn decode_optional_consumer_version(
    raw: Option<String>,
) -> Result<Option<WasmAbiVersion>, String> {
    match raw {
        None => Ok(None),
        Some(version) if version.trim().is_empty() => Ok(None),
        Some(version) => decode_json_payload(&version, "consumer_version").map(Some),
    }
}

/// Decode a `JsValue` payload into a typed ABI value on wasm targets.
#[cfg(target_arch = "wasm32")]
pub fn decode_js_payload<T: DeserializeOwned>(value: JsValue, field: &str) -> Result<T, String> {
    serde_wasm_bindgen::from_value(value)
        .map_err(|err| format!("failed to decode {field} JsValue payload: {err}"))
}

/// Encode a typed ABI value into `JsValue` on wasm targets.
#[cfg(target_arch = "wasm32")]
pub fn encode_js_payload<T: Serialize>(value: &T, field: &str) -> Result<JsValue, String> {
    serde_wasm_bindgen::to_value(value)
        .map_err(|err| format!("failed to encode {field} JsValue payload: {err}"))
}

/// Browser-visible scenario represented by an operator console snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserOperatorSnapshotKind {
    /// Runtime has been created and has no user work.
    EmptyRuntime,
    /// Runtime has live regions, tasks, channels, and budget accounting.
    LoadedRuntime,
    /// Runtime is in cancellation cleanup with drain work visible.
    CancelledRuntime,
    /// Runtime is sampled while admission pressure is active.
    PressureGovernedRuntime,
}

impl BrowserOperatorSnapshotKind {
    /// Stable scenario identifier used by JSON artifacts and UI consumers.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EmptyRuntime => "empty_runtime",
            Self::LoadedRuntime => "loaded_runtime",
            Self::CancelledRuntime => "cancelled_runtime",
            Self::PressureGovernedRuntime => "pressure_governed_runtime",
        }
    }
}

/// Runtime state exposed to browser operator consoles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserOperatorRuntimeState {
    /// Runtime accepts work.
    Running,
    /// Runtime is draining after cancellation.
    Cancelling,
    /// Runtime is still observable but rejecting work due to pressure.
    Backpressured,
}

/// Browser-side pressure state used by compact snapshots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserOperatorPressureLevel {
    /// No pressure signal is active.
    None,
    /// Pressure is observable but not rejecting new work.
    Watch,
    /// Pressure is high enough to reject or delay admission.
    Shed,
}

/// Browser rendering status for native-only fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserOperatorFieldStatus {
    /// Field is available in the browser snapshot payload.
    Present,
    /// Field is native-only and intentionally omitted.
    UnsupportedNativeOnly,
}

/// Compact count block shared by regions, tasks, channels, and budgets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserOperatorCountSummary {
    /// Total visible records.
    pub total: u32,
    /// Records currently active.
    pub active: u32,
    /// Records that are cancelling or cancelled.
    pub cancelled: u32,
    /// Records waiting for cleanup or drain.
    pub cleanup_pending: u32,
}

impl BrowserOperatorCountSummary {
    /// Construct a compact count block.
    #[must_use]
    pub const fn new(total: u32, active: u32, cancelled: u32, cleanup_pending: u32) -> Self {
        Self {
            total,
            active,
            cancelled,
            cleanup_pending,
        }
    }
}

/// Browser-visible runtime summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserOperatorRuntimeSummary {
    /// Stable browser-local runtime identifier.
    pub runtime_id: String,
    /// Current runtime state.
    pub state: BrowserOperatorRuntimeState,
    /// Logical tick supplied by the deterministic producer.
    pub logical_tick: u64,
    /// Whether this snapshot came from a direct browser runtime lane.
    pub direct_runtime_supported: bool,
}

/// Browser-visible channel summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserOperatorChannelSummary {
    /// Aggregate channel record counts.
    pub counts: BrowserOperatorCountSummary,
    /// Queued messages visible to the browser data model.
    pub backlog: u32,
    /// Senders or receivers waiting on progress.
    pub waiters: u32,
    /// Reserved sends or leases that have not committed.
    pub reserved_uncommitted: u32,
}

/// Browser-visible budget summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserOperatorBudgetSummary {
    /// Aggregate budget record counts.
    pub counts: BrowserOperatorCountSummary,
    /// Browser-visible memory envelope.
    pub memory_limit_bytes: Option<u64>,
    /// Browser-visible memory use.
    pub memory_used_bytes: Option<u64>,
    /// Cleanup budget still available in logical milliseconds.
    pub cleanup_remaining_ms: Option<u64>,
}

/// Browser-visible proof status summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserOperatorProofSummary {
    /// Whether the snapshot producer had a fresh proof for this view.
    pub proof_fresh: bool,
    /// Deterministic proof lane identifier, if one is available.
    pub proof_lane: Option<String>,
    /// Fail-closed reason when proof is absent or blocked.
    pub blocked_reason: Option<String>,
}

/// Browser-visible pressure summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserOperatorPressureSummary {
    /// Pressure state shown by the console.
    pub level: BrowserOperatorPressureLevel,
    /// Number of deterministic pressure samples folded into this snapshot.
    pub sample_count: u32,
    /// Whether admission is currently accepting new work.
    pub admission_open: bool,
}

/// Native-only field omitted from a browser operator snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserOperatorUnsupportedField {
    /// Stable field identifier.
    pub field_id: String,
    /// Rendering status for the field.
    pub status: BrowserOperatorFieldStatus,
    /// Deterministic reason shown to tooling.
    pub omission_reason: String,
}

/// Compact browser operator console payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserOperatorConsoleSnapshot {
    /// Stable schema identifier.
    pub schema_version: String,
    /// Scenario represented by this payload.
    pub kind: BrowserOperatorSnapshotKind,
    /// Runtime summary.
    pub runtime: BrowserOperatorRuntimeSummary,
    /// Region counts.
    pub regions: BrowserOperatorCountSummary,
    /// Task counts.
    pub tasks: BrowserOperatorCountSummary,
    /// Channel summary.
    pub channels: BrowserOperatorChannelSummary,
    /// Budget summary.
    pub budgets: BrowserOperatorBudgetSummary,
    /// Pressure summary.
    pub pressure: BrowserOperatorPressureSummary,
    /// Proof status summary.
    pub proof_status: BrowserOperatorProofSummary,
    /// Native-only fields omitted from the browser payload.
    pub unsupported_native_fields: Vec<BrowserOperatorUnsupportedField>,
}

impl BrowserOperatorConsoleSnapshot {
    /// Returns true when every native-only omission is explicitly fail-closed.
    #[must_use]
    pub fn has_fail_closed_native_omissions(&self) -> bool {
        self.unsupported_native_fields.iter().all(|field| {
            field.status == BrowserOperatorFieldStatus::UnsupportedNativeOnly
                && !field.omission_reason.trim().is_empty()
        })
    }
}

/// Build a deterministic browser operator snapshot fixture.
#[must_use]
pub fn browser_operator_snapshot_fixture(
    kind: BrowserOperatorSnapshotKind,
) -> BrowserOperatorConsoleSnapshot {
    let unsupported_native_fields = vec![
        BrowserOperatorUnsupportedField {
            field_id: "native_thread_id".to_string(),
            status: BrowserOperatorFieldStatus::UnsupportedNativeOnly,
            omission_reason: "browser runtimes do not expose native OS thread identifiers"
                .to_string(),
        },
        BrowserOperatorUnsupportedField {
            field_id: "native_file_descriptor".to_string(),
            status: BrowserOperatorFieldStatus::UnsupportedNativeOnly,
            omission_reason: "browser runtimes do not expose process file descriptors".to_string(),
        },
        BrowserOperatorUnsupportedField {
            field_id: "host_filesystem_path".to_string(),
            status: BrowserOperatorFieldStatus::UnsupportedNativeOnly,
            omission_reason: "browser packages must not imply local filesystem access".to_string(),
        },
    ];

    match kind {
        BrowserOperatorSnapshotKind::EmptyRuntime => BrowserOperatorConsoleSnapshot {
            schema_version: BROWSER_OPERATOR_SNAPSHOT_SCHEMA_VERSION.to_string(),
            kind,
            runtime: BrowserOperatorRuntimeSummary {
                runtime_id: "browser-runtime-0".to_string(),
                state: BrowserOperatorRuntimeState::Running,
                logical_tick: 0,
                direct_runtime_supported: true,
            },
            regions: BrowserOperatorCountSummary::new(1, 1, 0, 0),
            tasks: BrowserOperatorCountSummary::new(0, 0, 0, 0),
            channels: BrowserOperatorChannelSummary {
                counts: BrowserOperatorCountSummary::new(0, 0, 0, 0),
                backlog: 0,
                waiters: 0,
                reserved_uncommitted: 0,
            },
            budgets: BrowserOperatorBudgetSummary {
                counts: BrowserOperatorCountSummary::new(1, 1, 0, 0),
                memory_limit_bytes: Some(64 * 1024 * 1024),
                memory_used_bytes: Some(0),
                cleanup_remaining_ms: Some(0),
            },
            pressure: BrowserOperatorPressureSummary {
                level: BrowserOperatorPressureLevel::None,
                sample_count: 0,
                admission_open: true,
            },
            proof_status: BrowserOperatorProofSummary {
                proof_fresh: true,
                proof_lane: Some("browser_operator_snapshot_empty".to_string()),
                blocked_reason: None,
            },
            unsupported_native_fields,
        },
        BrowserOperatorSnapshotKind::LoadedRuntime => BrowserOperatorConsoleSnapshot {
            schema_version: BROWSER_OPERATOR_SNAPSHOT_SCHEMA_VERSION.to_string(),
            kind,
            runtime: BrowserOperatorRuntimeSummary {
                runtime_id: "browser-runtime-loaded".to_string(),
                state: BrowserOperatorRuntimeState::Running,
                logical_tick: 12,
                direct_runtime_supported: true,
            },
            regions: BrowserOperatorCountSummary::new(4, 4, 0, 0),
            tasks: BrowserOperatorCountSummary::new(32, 29, 0, 0),
            channels: BrowserOperatorChannelSummary {
                counts: BrowserOperatorCountSummary::new(7, 7, 0, 0),
                backlog: 18,
                waiters: 5,
                reserved_uncommitted: 2,
            },
            budgets: BrowserOperatorBudgetSummary {
                counts: BrowserOperatorCountSummary::new(4, 4, 0, 0),
                memory_limit_bytes: Some(128 * 1024 * 1024),
                memory_used_bytes: Some(37 * 1024 * 1024),
                cleanup_remaining_ms: Some(250),
            },
            pressure: BrowserOperatorPressureSummary {
                level: BrowserOperatorPressureLevel::Watch,
                sample_count: 3,
                admission_open: true,
            },
            proof_status: BrowserOperatorProofSummary {
                proof_fresh: true,
                proof_lane: Some("browser_operator_snapshot_loaded".to_string()),
                blocked_reason: None,
            },
            unsupported_native_fields,
        },
        BrowserOperatorSnapshotKind::CancelledRuntime => BrowserOperatorConsoleSnapshot {
            schema_version: BROWSER_OPERATOR_SNAPSHOT_SCHEMA_VERSION.to_string(),
            kind,
            runtime: BrowserOperatorRuntimeSummary {
                runtime_id: "browser-runtime-cancelled".to_string(),
                state: BrowserOperatorRuntimeState::Cancelling,
                logical_tick: 24,
                direct_runtime_supported: true,
            },
            regions: BrowserOperatorCountSummary::new(4, 1, 3, 1),
            tasks: BrowserOperatorCountSummary::new(32, 0, 32, 4),
            channels: BrowserOperatorChannelSummary {
                counts: BrowserOperatorCountSummary::new(7, 1, 6, 1),
                backlog: 0,
                waiters: 0,
                reserved_uncommitted: 0,
            },
            budgets: BrowserOperatorBudgetSummary {
                counts: BrowserOperatorCountSummary::new(4, 1, 3, 1),
                memory_limit_bytes: Some(128 * 1024 * 1024),
                memory_used_bytes: Some(9 * 1024 * 1024),
                cleanup_remaining_ms: Some(75),
            },
            pressure: BrowserOperatorPressureSummary {
                level: BrowserOperatorPressureLevel::None,
                sample_count: 5,
                admission_open: false,
            },
            proof_status: BrowserOperatorProofSummary {
                proof_fresh: true,
                proof_lane: Some("browser_operator_snapshot_cancelled".to_string()),
                blocked_reason: None,
            },
            unsupported_native_fields,
        },
        BrowserOperatorSnapshotKind::PressureGovernedRuntime => BrowserOperatorConsoleSnapshot {
            schema_version: BROWSER_OPERATOR_SNAPSHOT_SCHEMA_VERSION.to_string(),
            kind,
            runtime: BrowserOperatorRuntimeSummary {
                runtime_id: "browser-runtime-pressure".to_string(),
                state: BrowserOperatorRuntimeState::Backpressured,
                logical_tick: 36,
                direct_runtime_supported: true,
            },
            regions: BrowserOperatorCountSummary::new(9, 9, 0, 0),
            tasks: BrowserOperatorCountSummary::new(128, 117, 0, 0),
            channels: BrowserOperatorChannelSummary {
                counts: BrowserOperatorCountSummary::new(19, 19, 0, 0),
                backlog: 512,
                waiters: 64,
                reserved_uncommitted: 21,
            },
            budgets: BrowserOperatorBudgetSummary {
                counts: BrowserOperatorCountSummary::new(9, 9, 0, 0),
                memory_limit_bytes: Some(256 * 1024 * 1024),
                memory_used_bytes: Some(221 * 1024 * 1024),
                cleanup_remaining_ms: Some(25),
            },
            pressure: BrowserOperatorPressureSummary {
                level: BrowserOperatorPressureLevel::Shed,
                sample_count: 8,
                admission_open: false,
            },
            proof_status: BrowserOperatorProofSummary {
                proof_fresh: false,
                proof_lane: None,
                blocked_reason: Some(
                    "pressure-governor proof unavailable in browser snapshot producer".to_string(),
                ),
            },
            unsupported_native_fields,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BrowserOperatorSnapshotKind, browser_operator_snapshot_fixture, decode_json_payload,
        decode_optional_consumer_version, encode_json_payload,
    };
    use asupersync::types::{
        WasmAbiOutcomeEnvelope, WasmAbiValue, WasmAbiVersion, WasmHandleKind, WasmHandleRef,
    };

    #[test]
    fn handle_ref_json_round_trip_holds() {
        let handle = WasmHandleRef {
            kind: WasmHandleKind::Task,
            slot: 7,
            generation: 3,
            owner_token: 0x1234_5678_9ABC_DEF0,
        };

        let encoded = encode_json_payload(&handle, "handle").expect("encode handle");
        let decoded: WasmHandleRef =
            decode_json_payload(&encoded, "handle").expect("decode handle");
        assert_eq!(decoded, handle);
    }

    #[test]
    fn outcome_envelope_json_round_trip_holds() {
        let outcome = WasmAbiOutcomeEnvelope::Ok {
            value: WasmAbiValue::String("ready".to_string()),
        };

        let encoded = encode_json_payload(&outcome, "outcome").expect("encode outcome");
        let decoded: WasmAbiOutcomeEnvelope =
            decode_json_payload(&encoded, "outcome").expect("decode outcome");
        assert_eq!(decoded, outcome);
    }

    #[test]
    fn consumer_version_decoding_handles_none_and_blank() {
        assert_eq!(decode_optional_consumer_version(None).expect("none"), None);
        assert_eq!(
            decode_optional_consumer_version(Some(String::new())).expect("blank"),
            None
        );
        assert_eq!(
            decode_optional_consumer_version(Some("   ".to_string())).expect("whitespace"),
            None
        );
    }

    #[test]
    fn consumer_version_decoding_parses_valid_json() {
        let version_json = r#"{"major":1,"minor":2}"#.to_string();
        let parsed = decode_optional_consumer_version(Some(version_json)).expect("parse version");
        assert_eq!(parsed, Some(WasmAbiVersion { major: 1, minor: 2 }));
    }

    #[test]
    fn browser_operator_snapshot_fixtures_round_trip_json() {
        for kind in [
            BrowserOperatorSnapshotKind::EmptyRuntime,
            BrowserOperatorSnapshotKind::LoadedRuntime,
            BrowserOperatorSnapshotKind::CancelledRuntime,
            BrowserOperatorSnapshotKind::PressureGovernedRuntime,
        ] {
            let snapshot = browser_operator_snapshot_fixture(kind);
            assert_eq!(snapshot.kind.as_str(), kind.as_str());
            assert!(snapshot.has_fail_closed_native_omissions());

            let encoded =
                encode_json_payload(&snapshot, "browser_operator_snapshot").expect("encode");
            let decoded = decode_json_payload(&encoded, "browser_operator_snapshot")
                .expect("decode browser snapshot");
            assert_eq!(snapshot, decoded);
        }
    }
}
