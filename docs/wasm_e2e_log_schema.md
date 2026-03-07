# WASM E2E Log Schema and Artifact Bundle Layout

Contract ID: `wasm-e2e-log-schema-v1`
Bead: `asupersync-3qv04.8.4.4`

## Purpose

Standardize the structured logging schema and artifact-bundle layout used by the
Browser Edition E2E system. Every failed E2E run must produce a predictable,
inspectable evidence bundle. Every passing run must produce enough metadata for
automated regression triage.

## Canonical Inputs

- Schema artifact: `artifacts/wasm_e2e_log_schema_v1.json`
- Contract tests: `tests/wasm_e2e_log_schema_contract.rs`

## Log Entry Schema

Every E2E log entry is a single JSON line (JSONL) with these fields:

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `ts` | string (ISO-8601) | Timestamp with millisecond precision |
| `level` | string | One of: `trace`, `debug`, `info`, `warn`, `error`, `fatal` |
| `scenario_id` | string | Unique identifier for the test scenario (e.g. `e2e-ws-open-close-001`) |
| `run_id` | string | UUID for the specific test run |
| `event` | string | Machine-readable event name (e.g. `wasm_load`, `bridge_call`, `assertion_fail`) |
| `msg` | string | Human-readable description |

### Optional Fields

| Field | Type | Description |
|-------|------|-------------|
| `abi_version` | object | `{ "major": u32, "minor": u32 }` |
| `abi_fingerprint` | u64 | `WASM_ABI_SIGNATURE_FINGERPRINT_V1` value |
| `browser` | object | `{ "name": string, "version": string, "os": string }` |
| `build` | object | `{ "profile": string, "commit": string, "wasm_size_bytes": u64 }` |
| `module_url` | string | URL or path of the loaded WASM module |
| `handle_ref` | u64 | Handle reference for lifecycle tracking |
| `duration_ms` | f64 | Duration of the timed operation |
| `stack_trace` | string | Stack trace (symbolized if source maps available) |
| `error_code` | string | Structured error code (e.g. `ABI_MISMATCH`, `BRIDGE_TIMEOUT`) |
| `evidence_ids` | array[string] | Evidence matrix IDs this entry satisfies |
| `screenshot_path` | string | Relative path within the artifact bundle |
| `extra` | object | Free-form key-value pairs for scenario-specific data |

### Log Levels

| Level | Usage |
|-------|-------|
| `trace` | Wasm function entry/exit, handle allocation/deallocation |
| `debug` | Bridge call parameters, intermediate state |
| `info` | Scenario start/end, assertion pass, milestone events |
| `warn` | Unexpected but recoverable conditions, deprecation notices |
| `error` | Assertion failures, bridge errors, timeout expiry |
| `fatal` | Unrecoverable: WASM trap, module load failure, OOM |

## Artifact Bundle Layout

Each E2E run produces a bundle directory with deterministic naming:

```
e2e-runs/
  {scenario_id}/
    {run_id}/
      run-metadata.json      # Run metadata (browser, build, timing, verdict)
      log.jsonl               # JSONL log entries
      screenshots/            # Optional: failure screenshots
        {step_name}.png
      traces/                 # Optional: browser performance traces
        {step_name}.json
      wasm-artifacts/         # Optional: WASM module + source maps used
        asupersync_bg.wasm
        asupersync.js.map
        asupersync_bg.wasm.map
```

### run-metadata.json Schema

```json
{
  "schema_version": "wasm-e2e-run-metadata-v1",
  "scenario_id": "e2e-ws-open-close-001",
  "run_id": "550e8400-e29b-41d4-a716-446655440000",
  "started_at": "2026-03-07T05:00:00.000Z",
  "finished_at": "2026-03-07T05:00:03.142Z",
  "duration_ms": 3142.0,
  "verdict": "pass",
  "browser": {
    "name": "chromium",
    "version": "124.0.6367.60",
    "os": "linux"
  },
  "build": {
    "profile": "prod",
    "commit": "35c7de44",
    "wasm_size_bytes": 245760
  },
  "abi_version": { "major": 1, "minor": 0 },
  "abi_fingerprint": 1234567890,
  "evidence_ids_covered": ["L4-FETCH-E2E", "L4-WS-E2E"],
  "failure_summary": null,
  "log_line_count": 47,
  "screenshot_count": 0
}
```

### Verdict Values

| Verdict | Meaning |
|---------|---------|
| `pass` | All assertions passed |
| `fail` | One or more assertions failed |
| `error` | Infrastructure error (module load failure, browser crash) |
| `timeout` | Run exceeded time limit |
| `skip` | Scenario skipped (missing prerequisite) |

## Artifact Naming Convention

Bundle directory: `{scenario_id}/{run_id}/`

- `scenario_id`: lowercase, hyphen-separated, prefixed with `e2e-` (e.g. `e2e-fetch-abort-002`)
- `run_id`: UUID v4, lowercase, hyphen-separated
- Screenshot names: `{step_name}.png` where step_name is the test step that captured it
- Trace names: `{step_name}.json` matching Chromium DevTools trace format

## Retention Policy

Retention classes align with the evidence matrix artifact (`wasm_qa_evidence_matrix_v1.json`):

| Class | Min Days | Criteria |
|-------|----------|----------|
| `hot` | 30 | verdict=fail or verdict=error |
| `warm` | 14 | verdict=pass in execute mode |
| `cold` | 7 | verdict=skip, dry-run, or low-signal |

Retention is advisory; CI systems apply these as default prune policies.
Bundles linked to open incident investigations are exempt from pruning.

## Error Code Taxonomy

| Code | Category | Description |
|------|----------|-------------|
| `ABI_MISMATCH` | Compatibility | WASM module ABI version does not match host expectation |
| `BRIDGE_TIMEOUT` | Bridge | Host bridge call exceeded deadline |
| `BRIDGE_ERROR` | Bridge | Host bridge call returned an error |
| `HANDLE_LEAK` | Lifecycle | Handle was not closed before scope exit |
| `HANDLE_DOUBLE_FREE` | Lifecycle | Handle closed more than once |
| `ASSERTION_FAIL` | Test | Test assertion did not hold |
| `MODULE_LOAD_FAIL` | Infrastructure | WASM module could not be loaded |
| `WASM_TRAP` | Infrastructure | WASM execution trap (unreachable, OOM) |
| `BROWSER_CRASH` | Infrastructure | Browser process terminated unexpectedly |
| `SCREENSHOT_FAIL` | Capture | Screenshot capture failed |
