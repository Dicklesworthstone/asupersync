# Integration Documentation: Architecture, API, Tutorials

This document consolidates the integration-facing documentation for Asupersync:
architecture overview, API reference orientation, and practical tutorials. It is
written for developers integrating the runtime or the RaptorQ stack into other
systems (including fastapi_rust).

## Quick Start (minimal)

```ignore
use asupersync::{Cx, Outcome};
use asupersync::proc_macros::scope;
use asupersync::runtime::RuntimeBuilder;

fn main() -> Result<(), asupersync::Error> {
    let rt = RuntimeBuilder::current_thread().build()?;

    rt.block_on(async {
        // Structured concurrency: a scope closes to quiescence.
        let cx = Cx::for_request();
        scope!(cx, {
            cx.trace("worker running");
            Outcome::ok(())
        });
    });

    Ok(())
}
```

Notes:
- The `scope!` macro requires the `proc-macros` feature.
- `Cx::for_request()` is convenient for integration testing and request-style entry points.
- Production code should receive `Cx` from runtime-managed tasks when available.
- Use `Cx` and `Scope` for all effects: no ambient authority.
- A region closes to quiescence: all children complete and all finalizers run.
- Cancellation is a protocol (request -> drain -> finalize), not a silent drop.

---

## Effect-Safe Context Wrappers

Framework integrations should wrap `Cx` to provide least-privilege access.

### HTTP (RequestRegion)

```ignore
use asupersync::cx::cap::CapSet;
use asupersync::web::request_region::RequestContext;

type RequestCaps = CapSet<true, true, false, false, false>;

async fn handler(ctx: &RequestContext<'_>) -> Response {
    let cx = ctx.cx_narrow::<RequestCaps>();
    cx.checkpoint()?;
    // spawn/time allowed; IO/remote not exposed
    todo!()
}
```

For fully read-only handlers, use `ctx.cx_readonly()` to remove all gated APIs.

### gRPC (CallContextWithCx)

```ignore
use asupersync::cx::cap::CapSet;
use asupersync::grpc::{CallContext, CallContextWithCx};

type GrpcCaps = CapSet<true, true, false, false, false>;

fn handle(call: &CallContext, cx: &asupersync::Cx) {
    let ctx = call.with_cx(cx);
    let cx = ctx.cx_narrow::<GrpcCaps>();
    cx.trace("handling request");
}
```

Use `CallContext::with_cx(&cx)` to construct the wrapper.

These wrappers are zero-cost type-level restrictions; they do not alter runtime
behavior, but they remove access to gated APIs at compile time.

---

## Architecture Overview

### Conceptual flow

```
User Future
    -> Scope / Region
        -> Scheduler
            -> Cancellation + Obligations
                -> Trace / Lab Runtime
```

### Core invariants (recap)

- Structured concurrency: every task is owned by exactly one region.
- Region close implies quiescence: no live children, all finalizers done.
- Cancellation is a protocol: request -> drain -> finalize (idempotent).
- Losers are drained after races.
- No obligation leaks: permits/acks/leases must resolve.
- No ambient authority: effects flow through `Cx` and explicit capabilities.

### Module map (Phase 0/1)

- `cx/`: capability context and `Scope` API (entry point for effects)
- `runtime/`: scheduler and runtime state (`RuntimeBuilder`, `Runtime`)
- `cancel/`: cancellation protocol and propagation
- `obligation/`: linear obligations (permits/acks/leases)
- `combinator/`: join/race/timeout combinators
- `lab/`: deterministic runtime, oracles, trace capture
- `trace/` + `record/`: trace events and runtime records
- `types/`: identifiers, outcomes, budgets, policies, time
- `channel/`, `stream/`, `sync/`: cancel-correct primitives
- `transport/`: symbol transport traits and helpers
- `encoding/`, `decoding/`, `raptorq/`: RaptorQ pipelines
- `security/`, `observability/`: auth and structured tracing

### Protocol stack overview

- HTTP/1.1: `src/http/h1/` (codec + client/server helpers)
  - Tests: `tests/http_verification.rs`, fuzz targets `fuzz_http1_request` / `fuzz_http1_response`
- HTTP/2: `src/http/h2/` (frames, HPACK, streams, connection)
  - Tests: `tests/http_verification.rs`, fuzz targets `fuzz_http2_frame` / `fuzz_hpack_decode`
- gRPC: `src/grpc/` (framing, client/server, interceptors)
  - Tests: `tests/grpc_verification.rs`
- WebSocket: `src/net/websocket/` (handshake, frames, client/server)
  - Tests: `tests/e2e_websocket.rs`

### Testing reference

See `TESTING.md` for test categories, logging conventions, conformance suite usage,
and fuzzing instructions.

### Examples

Examples live in `examples/` and cover:

- Structured concurrency macros: `examples/macros_*.rs`
- Cancellation injection: `examples/cancellation_injection.rs`
- Chaos testing: `examples/chaos_testing.rs`
- Metrics dashboards: `examples/prometheus_metrics.rs`, `examples/grafana_dashboard.json`

### Module dependency sketch (high level)

```
Cx/Scope
  -> runtime (scheduler, tasks)
  -> cancel + obligation (protocol + linear tokens)
  -> combinator (join/race/timeout)

lab
  -> runtime
  -> trace

raptorq
  -> encoding/decoding
  -> transport
  -> security
  -> observability
```

### Runtime data flow (high level)

```
Cx::scope or scope! macro
    -> Scope::spawn (wired through runtime state)
        -> Runtime scheduler
            -> Task polls
                -> cx.checkpoint() (cancellation observation)
                -> Effects via capabilities (channels, io, time)
            -> Outcome aggregation
            -> Region close = quiescence
```

### Cancellation state machine

```
Running
  -> CancelRequested
     -> Cancelling (drain)
        -> Finalizing (finalizers)
           -> Completed(Cancelled)
```

### Region lifecycle (conceptual)

```
Open
  -> Closing (cancel requested or scope exit)
     -> Draining (children finish)
        -> Finalizing (finalizers run)
           -> Quiescent
```

### RaptorQ pipeline data flow

```
RaptorQSender / RaptorQReceiver
    -> EncodingPipeline / DecodingPipeline
        -> SecurityContext (sign/verify)
            -> SymbolSink / SymbolStream (transport)
```

### RaptorQ configuration surface

`RaptorQConfig` is the top-level configuration for the RaptorQ pipeline. It
groups all tuning knobs and is validated via `RaptorQConfig::validate()` before
construction.

Key knobs by component:

- `EncodingConfig` (`RaptorQConfig::encoding`)
  - `repair_overhead`: repair factor (e.g., `1.05` = 5% extra symbols)
  - `max_block_size`: max bytes per source block
  - `symbol_size`: symbol size in bytes (typically 64–1024)
  - `encoding_parallelism` / `decoding_parallelism`
- `TransportConfig` (`RaptorQConfig::transport`)
  - `max_paths`, `health_check_interval`, `max_symbols_in_flight`
  - `path_strategy`: `RoundRobin | LatencyWeighted | Adaptive | Random`
- `ResourceConfig` (`RaptorQConfig::resources`)
  - `max_symbol_buffer_memory`, `symbol_pool_size`
  - `max_encoding_ops`, `max_decoding_ops`
- `TimeoutConfig` (`RaptorQConfig::timeouts`)
  - `default_timeout`, `encoding_timeout`, `decoding_timeout`
  - `path_timeout`, `quorum_timeout`
- `SecurityConfig` (`RaptorQConfig::security`)
  - `auth_mode`, `auth_key_seed`, `reject_unauthenticated`

`RuntimeProfile::to_config()` provides baseline presets (`Development`,
`Testing`, `Staging`, `Production`, `HighThroughput`, `LowLatency`).

Note: `RaptorQReceiver` derives a `DecodingConfig` from `RaptorQConfig::encoding`
and uses defaults for the remaining decode knobs (`min_overhead`,
`max_buffered_symbols`, `block_timeout`). For fine-grained decode tuning, use
`DecodingPipeline` directly.

### RaptorQ builder example

```ignore
use asupersync::config::{RaptorQConfig, RuntimeProfile};
use asupersync::raptorq::{RaptorQReceiverBuilder, RaptorQSenderBuilder};

let mut config = RuntimeProfile::Testing.to_config();
config.encoding.symbol_size = 512;
config.encoding.repair_overhead = 1.10;

let sender = RaptorQSenderBuilder::new()
    .config(config.clone())
    .transport(sink)
    .build()?;

let receiver = RaptorQReceiverBuilder::new()
    .config(config)
    .source(stream)
    .build()?;
```

### RaptorQ RFC-6330-grade scope + determinism contract (spec)

This section is the internal spec for the RaptorQ pipeline. It replaces the
current Phase 0 LT/XOR shortcut and defines what "RFC-6330-grade" means for
Asupersync. Implementations should not require constant re-reading of external
standards; where we diverge, we must document it explicitly.

Scope (non-negotiable in full mode):
- Systematic transmission (source symbols first).
- Robust soliton LT layer for repair symbols.
- Deterministic precode (LDPC/HDPC-style constraints or equivalent).
- Deterministic inactivation decoding (peeling + sparse elimination).
- Proof-carrying decode trace artifact (bounded, deterministic).

Divergence ledger (explicit design decisions):
- Determinism is stricter than RFC 6330: all randomness is derived from explicit
  seeds and stable hashing; no ambient RNG or wall-clock.
- Proof artifact emission is required (additional constraint, not in RFC 6330).
- Phase 0 may allow XOR-only test mode, but full mode must use GF(256).

#### Determinism contract

Given:
- input bytes
- `ObjectId`
- `EncodingConfig` / `DecodingConfig`
- explicit seed(s) and policy knobs

Then the following are deterministic and reproducible:
- emitted `SymbolId` and symbol bytes
- degree selection and neighbor sets for repair symbols
- decoding decisions (pivot selection, inactivation set, row-op order)
- proof artifact bytes and final outcome

No ambient randomness and no time-based choices.

#### Seed derivation (canonical)

All pseudo-random decisions are derived from a stable hash of:

```
seed = H(config_hash || object_id || sbn || esi || purpose_tag)
```

Where:
- `config_hash` is a stable hash of the encoding/decoding config
- `object_id`, `sbn`, `esi` are from `SymbolId`
- `purpose_tag` distinguishes degree selection vs neighbor selection vs pivoting

`H` is a fixed, documented hash function; changing it is a protocol-breaking change.

#### Encoder contract (per source block)

1. Segmentation + padding
   - Split bytes into `symbol_size` chunks.
   - Pad deterministically (zero pad + pad length recorded in `ObjectParams`).
   - Partition into source blocks with deterministic `K` per block.

2. Precode / intermediate symbols
   - Map `K` source symbols to `N >= K` intermediate symbols.
   - Precode structure is sparse, stable, and deterministic.
   - Precode parameters are explicit in config and recorded in proof metadata.

3. Systematic emission
   - Emit source symbols first (`ESI < K`), in deterministic order.

4. Repair symbol generation
   - Choose degree `d` via robust soliton distribution (configurable `c`, `delta`).
   - Select `d` neighbors deterministically using the derived seed.
   - Compute repair symbol as a linear combination over GF(256) (full mode).

Neighbor selection and equation construction must be reproducible given
`(object_id, sbn, esi, config_hash, seed)`.

#### Decoder contract (per source block)

1. Ingest
   - Track received symbols and IDs.
   - Reject duplicates deterministically with a precise `RejectReason`.

2. Peeling / belief propagation
   - Repeatedly solve degree-1 equations and substitute into others.
   - Deterministic processing order for the degree-1 queue.

3. Inactivation decoding
   - When peeling stalls, pick an inactivation set deterministically.
   - Perform deterministic elimination (stable row order + stable pivot choice).

4. Completion
   - Recover intermediate symbols, then source symbols.
   - Reassemble bytes and validate padding rule.

#### Proof-carrying decode trace artifact

For each decoded block, emit a compact artifact that allows offline verification:
- config hash + seeds + block sizing metadata
- equation inventory: symbol IDs + neighbor sets used
- elimination trace: pivots, inactivation choices, row ops (bounded)
- final outcome: success or `RejectReason`

The artifact must be:
- deterministic
- bounded in size (explicit caps)
- sufficient to reproduce decoder state transitions and explain failures

#### Proof Artifact Schema + Versioning + Bounds

Schema versioning:
- `PROOF_SCHEMA_VERSION` is a u8 on the artifact. A breaking schema change must bump it.
- Readers version-gate: unknown versions are rejected with a clear error.
- Forward-compat is allowed only for additive fields when the encoding supports it; unknown fields are ignored in that case.

Canonical serialization (for hashing):
- `DecodeProof::content_hash()` must use a deterministic hasher (`util::DetHasher`) and a fixed field order.

#### Proof artifact API surface

- `InactivationDecoder::decode_with_proof(...) -> Result<DecodeResultWithProof, (DecodeError, DecodeProof)>`
  returns a decode result plus a proof artifact (or a failure + proof).
- `DecodeProof::replay_and_verify(symbols)` replays and validates the artifact.
- `DecodeProof::content_hash()` provides a stable fingerprint for deduplication.

Example usage:

```ignore
use asupersync::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::DecodeProof;
use asupersync::types::ObjectId;

let decoder = InactivationDecoder::new(k, symbol_size, seed);
let object_id = ObjectId::new(42);
let sbn = 0u8;

match decoder.decode_with_proof(&symbols, object_id, sbn) {
    Ok(result) => {
        let proof: DecodeProof = result.proof;
        let _fingerprint = proof.content_hash();
        proof.replay_and_verify(&symbols)?;
    }
    Err((_err, proof)) => {
        let _fingerprint = proof.content_hash();
        proof.replay_and_verify(&symbols)?;
    }
}
```
- Integer fields are serialized in little-endian fixed-width form.
- Vectors are serialized in recorded order with a length prefix.

Deterministic ordering requirements:
- `received.esis`, `peeling.solved_indices`, `elimination.inactive_cols`, and `elimination.pivot_events` must be recorded in deterministic order.
- Recommended: sort `esis` by ESI; record peel/inactivation/pivot events in stable row/col order used by the decoder.

Size bounds + truncation:
- `MAX_RECEIVED_SYMBOLS` and `MAX_PIVOT_EVENTS` are hard caps.
- When limits are exceeded, the artifact keeps the first N entries in the deterministic order and sets `truncated = true`.
- Counts (`total`, `solved`, `pivots`, `row_ops`) always reflect the full execution, not just the recorded prefix.

Schema fields (v1):
- `version`: u8 (`PROOF_SCHEMA_VERSION`)
- `config`: { `object_id`, `sbn`, `k`, `s`, `h`, `l`, `symbol_size`, `seed` }
- `received`: { `total`, `source_count`, `repair_count`, `esis[]`, `truncated` }
- `peeling`: { `solved`, `solved_indices[]`, `truncated` }
- `elimination`: { `inactivated`, `inactive_cols[]`, `pivots`, `pivot_events[]`, `row_ops`, `truncated` }
- `outcome`: `Success { symbols_recovered }` | `Failure { reason }`
- `reason`: `InsufficientSymbols { received, required }` | `SingularMatrix { row, attempted_cols[] }` | `SymbolSizeMismatch { expected, actual }`

### Formal Semantics (v4.0.0)

The canonical small-step semantics live in `docs/asupersync_v4_formal_semantics.md`
and are tagged **v4.0.0**. This is the ground-truth model for regions, tasks,
obligations, cancellation, scheduler lanes, and trace equivalence. It is intended
to be mechanically translatable to TLA+/Lean/Coq without a rewrite.

---

## API Reference Orientation

Asupersync exposes a small, capability-focused public API. The canonical list of
public items lives in `src/lib.rs` re-exports. Use `cargo doc --no-deps` for full
rustdoc output.

### Core types

- `Cx`, `Scope`: capability context and region-scoped API
- `Outcome`, `OutcomeError`, `CancelKind`, `CancelReason`, `Severity`
- `Budget`, `Time`, `Policy`
- `RegionId`, `TaskId`, `ObligationId`

### Runtime

- `runtime::RuntimeBuilder`: build and configure runtimes
- `runtime::Runtime`: runtime handle (`block_on`)

### Cancellation + obligations

- `cancel/`: cancellation protocol and propagation
- `obligation/`: linear obligations (permits/acks/leases)

### Combinators

- `combinator/`: join, race, timeout, hedge, quorum, pipeline patterns

### Lab runtime + oracles

- `LabRuntime`, `LabConfig`: deterministic testing
- `lab` oracles: quiescence, obligation leak, trace checks

### RaptorQ integration

- `RaptorQConfig` + `EncodingConfig` + `DecodingConfig`
- `RaptorQSenderBuilder`, `RaptorQReceiverBuilder`
- `RaptorQSender`, `RaptorQReceiver`, `SendOutcome`, `ReceiveOutcome`

### Transport + security + observability

- `transport::SymbolSink` / `transport::SymbolStream`
- `security::SecurityContext` for signing/verifying symbols
- `Cx::trace` + `observability::Metrics` for structured telemetry

---

## Tutorials

### 1) Getting Started: Structured Concurrency

```ignore
use asupersync::{Cx, Outcome};
use asupersync::proc_macros::scope;

async fn worker(cx: &Cx) -> Outcome<(), asupersync::Error> {
    cx.trace("worker start");
    cx.checkpoint()?;
    // ... do work ...
    Outcome::ok(())
}

async fn root(cx: Cx) -> Outcome<(), asupersync::Error> {
    scope!(cx, {
        let _ = worker(&cx).await;
        Outcome::ok(())
    });

    Outcome::ok(())
}
```

Key points:
- Always observe cancellation via `cx.checkpoint()` in loops.
- Leaving a region means all children are complete and drained.

### 2) Reliable Transfer: RaptorQ Sender/Receiver

```ignore
use asupersync::config::RaptorQConfig;
use asupersync::raptorq::{RaptorQReceiverBuilder, RaptorQSenderBuilder};
use asupersync::transport::mock::mock_channel;
use asupersync::types::symbol::{ObjectId, ObjectParams};
use asupersync::Cx;

let cx = Cx::for_request();
let config = RaptorQConfig::default();
let (mut sink, mut stream) = mock_channel(1024, 64);

let mut sender = RaptorQSenderBuilder::new()
    .config(config.clone())
    .transport(sink)
    .build()?;
let mut receiver = RaptorQReceiverBuilder::new()
    .config(config)
    .source(stream)
    .build()?;

let object_id = ObjectId::new_random();
let data = b"hello raptorq";
let _outcome = sender.send_object(&cx, object_id, data)?;

// In real systems, transmit ObjectParams alongside the payload metadata.
let params = /* ObjectParams derived from sender metadata */;
let decoded = receiver.receive_object(&cx, &params)?;
assert_eq!(decoded.data, data);
```

Notes:
- `send_object` and `receive_object` use `Cx` for cancellation.
- For production, replace `mock_channel` with a real `SymbolSink`/`SymbolStream`.

### 3) Custom Transport: Implement SymbolSink / SymbolStream

Implement the transport traits to plug in a custom network backend.

```rust
use asupersync::transport::{SymbolSink, SymbolStream};

struct MySink { /* ... */ }
struct MyStream { /* ... */ }

impl SymbolSink for MySink {
    // implement poll_send, poll_flush, poll_close
}

impl SymbolStream for MyStream {
    // implement poll_next
}
```

Guidelines:
- Make cancellation checks explicit via `Cx` at symbol boundaries.
- Ensure `poll_close` drains buffers and releases resources.

### 4) Observability: Structured Tracing

```rust
cx.trace("request_start");
// ... work ...
cx.trace("request_done");
```

Use `Cx::trace` for deterministic lab traces and runtime logs. Avoid direct
stdout/stderr printing in core logic.

### Evidence Ledger (Galaxy-Brain Mode)

For explainability, the runtime can emit an **evidence ledger**: a compact,
deterministic record of *why* a cancellation/race/scheduler decision occurred.
This is trace-backed and safe for audit/debugging.

Conceptual schema (stable, deterministic):

```
EvidenceEntry = {
  decision_id: u64,
  kind: "cancel" | "race" | "scheduler",
  context: {
    task_id: TaskId,
    region_id: RegionId,
    lane: DispatchLane
  },
  candidates: [Candidate],
  constraints: [Constraint],
  chosen: CandidateId,
  rationale: [Reason],
  witnesses: [TraceEventId]
}

Candidate = {
  id: CandidateId,
  score: i64,
  delta_v: i64,
  invariants: [InvariantCheck]
}
```

Renderer guidelines:
- One-line summary (decision + top reason).
- Optional expanded view: candidate table + constraint violations.
- Deterministic ordering of fields and candidates.

Runtime hooks (non-exhaustive):
- Cancellation: record why a task was cancelled vs drained.
- Race: record winner selection and loser-drain reasoning.
- Scheduler: record why task X was chosen over task Y (lane + score).

This ledger should be bounded in size and emitted via tracing/trace events,
never stdout/stderr.

### 5) Distributed Regions (conceptual)

The distributed API is in-progress. The intent is to provide region-scoped
fault tolerance with explicit leases and idempotency. Use the `distributed/`
module as the primary entry point, and prefer `Cx`-threaded capabilities over
ambient globals.

---

## Configuration Reference (high level)

Asupersync centralizes configuration in `RaptorQConfig` and related structs.

- `RaptorQConfig`: master configuration facade
- `EncodingConfig`: symbol size, block size, repair overhead
- `DecodingConfig`: buffer caps, timeouts, verification flags
- `TransportConfig`: buffer sizes, multipath policy, routing
- `SecurityConfig`: authentication mode and keying
- `TimeoutConfig`: deadlines and time budgets
- `ResourceConfig`: pool sizes and backpressure limits

Use `ConfigLoader` for file/env based loading. Validate configs before use.

---

## Troubleshooting

### Obligation leak
A task completed while holding a permit/ack/lease.

- Ensure permits are always committed or aborted.
- Use lab runtime oracles to detect leaks deterministically.

### Region close timeout
A region is waiting on children that never reach a checkpoint.

- Add `cx.checkpoint()` in loops.
- Avoid holding obligations across blocking waits.

### Non-deterministic failures
Intermittent failures usually indicate schedule sensitivity.

- Prefer `LabRuntime` with a fixed seed for reproducibility.
- Capture traces and replay to isolate schedule-dependent bugs.
- Use `lab::assert_deterministic` to validate stable outcomes.

### Slow shutdown or hanging tests
If shutdown never completes or tests hang:

- Ensure request/connection loops call `cx.checkpoint()`.
- Propagate budgets to child regions and timeouts to I/O.
- Confirm finalizers release obligations and permits.
