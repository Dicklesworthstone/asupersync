# ATP Logging And Failure Artifact Schema

This document is the ATP-N6 contract for structured logging, redaction,
failure bundles, and replay artifacts. It applies to ATP unit, lab,
integration, end-to-end, benchmark, and release-proof lanes.

## Schema IDs

| Artifact | Schema ID |
| --- | --- |
| Structured event | `asupersync.atp.log.event.v1` |
| Failure bundle | `asupersync.atp.failure_bundle.v1` |
| Replay artifact | `asupersync.atp.replay_artifacts.v1` |

The code constants live in `src/atp/logging/mod.rs`,
`src/atp/logging/failure_bundle.rs`, and
`src/atp/logging/replay_artifacts.rs`.

## Structured Event Envelope

Every rendered ATP log event must include these fields:

| Field | Required | Meaning |
| --- | --- | --- |
| `schema_version` | yes | Stable event schema ID. |
| `timestamp` | yes | RFC3339 UTC timestamp. Tests use replayable time. |
| `level` | yes | Lowercase structured log level. |
| `subsystem` | yes | One ATP subsystem or test lane. |
| `event_type` | yes | Subsystem-specific event name. |
| `data` | yes | JSON object with event payload. |
| `context` | yes | Correlation IDs and optional transfer/peer/test IDs. |
| `redacted_fields` | yes | Sorted paths changed by redaction. |

The event context carries:

| Field | Required | Meaning |
| --- | --- | --- |
| `session_id` | yes | ATP session or test session ID. |
| `transfer_id` | optional | Transfer operation ID. |
| `connection_id` | optional | QUIC, relay, or stream connection ID. |
| `peer_id` | optional | Peer identity. Shareable output redacts this by default. |
| `test_case_id` | optional | ATP test case or bead lane ID. |
| `trace_id` | yes | Distributed trace correlation ID. |
| `span_id` | yes | Local span ID. |

## Subsystems And Test Lanes

The logger must register nonempty schemas for these production subsystems:

- `path`
- `quic`
- `transfer`
- `scheduler`
- `repair`
- `disk`
- `journal`
- `verifier`
- `daemon`
- `cli`
- `relay`
- `mailbox`
- `security`

The same contract also covers these ATP test lanes:

- `unit_test`
- `lab_test`
- `e2e_test`
- `benchmark_test`
- `release_proof_test`

Each lane must be able to emit `test_started`, `test_completed`,
`test_failed`, `seed_selected`, `fixture_loaded`, `oracle_checked`,
`artifact_written`, `failure_bundle_created`, `replay_command_created`, and
`snapshot_compared`.

## Redaction Rules

Shareable ATP logs and artifacts must not expose private keys, auth tokens,
capability secrets, peer identities, sensitive local paths, or content hashes
when the active policy says hashes are sensitive.

Default redaction replaces sensitive values with stable markers:

| Secret Class | Marker |
| --- | --- |
| Private key | `[REDACTED_PRIVATE_KEY]` |
| Auth token, bearer token, password | `[REDACTED_TOKEN]` |
| Capability secret | `[REDACTED_CAPABILITY]` |
| Peer identity | `[REDACTED_PEER_ID]` |
| Sensitive local path | `[REDACTED_PATH]` |
| Content hash | `[REDACTED_CONTENT_HASH]` |

Redaction must run before JSON or human rendering. `redacted_fields` must be
sorted for deterministic assertions and snapshot stability.

## Failure Bundle

The failure bundle is the complete shareable failure record. It must contain:

| Field | Required | Meaning |
| --- | --- | --- |
| `schema_version` | yes | `asupersync.atp.failure_bundle.v1`. |
| `metadata` | yes | Bundle ID, format version, ATP version, Rust version, platform, timestamp. |
| `command` | yes | Redacted command line, working directory summary, exit code, duration, parsed args. |
| `environment` | yes | Safe environment variables, OS/arch, resource limit summary. |
| `seed` | yes | Deterministic seed for replay. |
| `trace_data` | yes | Structured events, trace timeline, performance metrics, error chain. |
| `qlog_data` | optional | QUIC qlog-style evidence. |
| `path_log` | optional | Path discovery and relay evidence. |
| `repair_log` | optional | Repair and RaptorQ evidence. |
| `journal_digest` | optional | Journal offset/checksum summary. |
| `proof_bundle` | optional | Verification evidence. |
| `replay_command` | yes | Command or recipe that reproduces the failure. |
| `additional_data` | yes | Redacted caller-provided context. |

Failure bundles must redact caller-provided `additional_data`, command
arguments, and the primary error context before serialization.

## Replay Artifact

Replay artifacts are deterministic pointers that tell an operator or test
harness how to reproduce a failure without embedding raw private data.

Required fields:

- `schema_id`
- `schema_version`
- `session_id`
- `seed`
- `replay_command`
- `trace_artifact`
- `qlog_artifact`
- `pathlog_artifact`
- `repairlog_artifact`
- `journal_digest_artifact`
- `proof_bundle_artifact`
- `environment_summary`

`session_id` must be sanitized for path-safe artifact names. The replay command
must include the sanitized session and seed.

## Contract Tests

The source-level contract lives in `src/atp/logging/tests.rs`. The existing ATP
forensics test module also enforces that an ATP E2E test lane can emit a
redacted structured event, build a failure bundle, and generate replay
artifacts with the stable schema IDs.

Focused proof command:

```bash
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_p9 cargo test -p asupersync --test atp_e2e_proof_suite test_forensics_uses_logging_failure_bundle_replay_contract -- --nocapture
```
