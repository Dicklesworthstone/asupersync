# Asupersync Public API Audit (0.1)

This document audits the public API surface exported from `src/lib.rs` and
classifies each module/type as **core** (intended to stabilize early),
**experimental** (public but likely to change), or **internal** (public today but
candidate for `pub(crate)` once downstreams stabilize).

## Scope

- Sources: `src/lib.rs` re-exports + top-level `pub mod` list
- Version: 0.1 (early development, no semver guarantees)

## Core (Intended-to-Stabilize Early)

These items are the likely foundation for external consumers (e.g. fastapi_rust).
They are still **0.x** but should change more slowly than other modules.

- `cx`: `Cx`, `Scope`
- `types`: `Outcome`, `OutcomeError`, `PanicPayload`, `Severity`, `Budget`, `Time`,
  `CancelKind`, `CancelReason`, `RegionId`, `TaskId`, `ObligationId`, `Policy`
- `error`: `Error`, `ErrorKind`, `Recoverability`, `RecoveryAction`, `SendError`, `RecvError`
- `lab`: `LabConfig`, `LabRuntime`
- `combinator`: `join_outcomes` (re-exported from `types`)

## Experimental (Public but Expected to Evolve)

These modules are public today but still in flux. External users should expect
API churn and semantics changes until 1.0.

- `actor`, `bytes`, `cancel`, `channel`, `codec`, `combinator`, `conformance`
- `decoding`, `distributed`, `encoding`, `epoch`, `fs`, `grpc`, `http`
- `io`, `net`, `plan`, `process`, `raptorq`, `remote`, `server`, `service`
- `session`, `signal`, `stream`, `supervision`, `sync`, `time`, `trace`
- `tracing_compat`, `transport`, `web`

## Internal / Candidate for `pub(crate)`

These modules are primarily implementation details. They are currently public
for internal wiring or test usage but are not intended as stable external API.

- `record`, `runtime`, `obligation`, `observability`, `security`, `util`, `config`
- `migration`, `test_logging`, `test_utils` (feature gated)

## Notes

- **Documentation coverage**: `#![warn(missing_docs)]` is enabled. Some public
  items still lack module or item-level docs. This audit should be used to drive
  doc coverage improvements, starting with the **Core** list above.
- **Stability policy**: Until 1.0, breaking changes may occur in any 0.(x+1).0.
  See README “Semver Policy” for details.

## Action Items (Next Pass)

1. Review each **Internal** module for possible visibility reduction.
2. For **Core** APIs, ensure module-level and item-level docs include purpose,
   panics, and errors where relevant.
3. Update README exports list if public surface changes.
