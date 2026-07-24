# DEP-ADR-002: Preserve arbitrary downstream Protobuf messages and ergonomic authoring

- Status: accepted
- Date: 2026-07-24
- Owner: SapphireHill
- Program: `asupersync-ir2uf0` (dependency sovereignty)
- Bead: `asupersync-dep-p3-api-adrs-h3jspm.2`
- Capability: `CAP-PROTOBUF-GENERIC`
- Decision: `KEEP_UNTIL_PARITY` / `KEEP_INCUMBENT`
- Machine row: `artifacts/dependency_api_adr_registry_v1.json`
- Supersedes: `COMPREHENSIVE_DEPENDENCY_REPLACEMENT_PLAN.md` §7 item 3.2, §9.6,
  and the `prost` row in the §5 disposition table

## Context

The Rev-3 plan is unusually direct about this one. §7 item 3.2 says: *"owned
`ProtoMessage` trait over a finite message set; drop the public
arbitrary-`prost::Message` surface."* §9.6 elaborates it into a `codec/proto.rs`
holding a hand-written finite set covering gRPC health, reflection,
status-details, and an OTLP export subset. The §5 disposition table marks `prost`
as OWN (SAFE).

The bead rejects that outright — a finite hand-written set "would remove
functionality and is forbidden" — and the capability registry agrees, with
`KEEP_UNTIL_PARITY` and a no-claim boundary reading *"finite in-repo schemas or
OTLP messages cannot replace arbitrary downstream Protobuf capability."*

What the source read adds is the reason the plan's trade does not work.

**`ProstCodec` is an unrestricted generic surface.** The struct carries no bounds
at all — `pub struct ProstCodec<T, U>` with a `PhantomData<(T, U)>`. The bounds
appear only on the `Codec` impl: `T: prost::Message + Send + 'static` and
`U: prost::Message + Default + Send + 'static`. Nothing enumerates, matches on,
or registers a closed set of message types. `new`, `Default` and `Clone` are all
implemented without bounds, so a codec value exists for any pair of types.

**`prost` is not behind a feature.** `prost = "0.14"` is a plain, non-optional
entry in `[dependencies]`. Protobuf support ships unconditionally on non-wasm32
targets. There is no `dep:prost` anywhere in the feature table.

**And the decisive point: the finite sets the plan proposes to hand-write in
exchange for dropping prost already exist without it.** `src/grpc/health.rs` and
`src/grpc/reflection.rs` contain zero prost references today — they are already
hand-written and prost-free. The only closed prost message set in the crate,
`otlp_logs_proto` in `src/observability/otel.rs`, is module-private and does not
touch the generic codec.

So prost buys exactly one thing: the arbitrary downstream generic surface.
Building the finite sets would remove nothing, because they are already owned.
Trading the generic surface for them means surrendering the entire capability in
exchange for work that is already done.

The cost of doing it anyway is concrete. It would delete `ProstCodec<T, U>`,
`SymmetricProstCodec<T>`, and both prost-typed `ProtobufError` variants, and it
would break the executable downstream journey in
`tests/fixtures/dependency-capability-baseline-consumer` — a standalone
workspace that authors its own message with a map and a oneof and pins prost to
exactly `0.14.4` — plus six gRPC codec conformance tests and eight fuzz targets.

## Decision

`prost` **MUST** remain the public authoring and codec boundary, at
`KEEP_UNTIL_PARITY` with cutover state `KEEP_INCUMBENT`.

1. `ProstCodec<T, U>` **MUST** keep accepting arbitrary downstream
   `prost::Message` types in both parameters. Collapsing to a symmetric-only or
   finite form is generic-API narrowing.
2. `SymmetricProstCodec<T>` **MUST** be preserved, including its long module
   path — it is public API even though it is not re-exported at
   `asupersync::grpc`.
3. Protobuf support **MUST NOT** become feature-gated. It is unconditional today
   and gating it removes capability from every consumer who does not opt in.
4. The generic codec **MUST** stay usable in unary *and* streaming gRPC, through
   the `Codec`-generic client and server seams.
5. `ProtobufError` **MUST** keep three distinct variants, and the size-limit
   variant **MUST** keep reporting both the actual size and the configured limit.
6. The accepted data model — scalars, repeated, packed, maps, enums, oneofs,
   nested messages, and prost's unknown-field evolution behavior — **MUST** be
   preserved exactly, not approximately.
7. Wire-byte compatibility with other gRPC implementations **MUST** hold, as the
   repository's own conformance tests already claim.
8. Owning further finite internal message sets **MAY** continue. It adds
   capability and is not a step toward removing prost.
9. A replacement **MUST NOT** proceed until an owned implementation offers
   authoring ergonomics at least as usable as prost's derive, accepts arbitrary
   downstream schemas, and passes arbitrary-consumer compile and runtime
   fixtures, cross-language interop, malformed and resource tests, fuzzing and
   rollback. Manual trait implementation alone does not qualify unless the owner
   explicitly finds it better after consumer trials.

## Allowed tradeoffs

- prost is not re-exported, so downstream consumers depend on it directly and
  must resolve a compatible version themselves.
- `ProtobufError` exposes prost's error types; that coupling is accepted as the
  current contract.
- Protobuf remains unavailable on wasm32, since `pub mod grpc` is gated to
  non-wasm32. That exclusion is pre-existing.

## Forbidden compromises

- Replacing the generic codec with any closed message set.
- Collapsing `ProstCodec<T, U>` to a single type parameter.
- Putting `prost` behind a Cargo feature.
- Citing the `cfg(test)` varint helpers in `src/grpc/protobuf.rs` as a partial
  owned implementation — they are differential-oracle code, not production code.
- Citing the two undeclared `src/real_http_h2_*_e2e_tests.rs` files as coverage
  (PB-GAP-02), or the `ignore`-fenced doc example as an executed journey
  (PB-GAP-03).

## Known gaps

| ID | Gap | Owner |
|---|---|---|
| PB-GAP-01 | Registry `source_owners` for this capability names `src/encoding.rs` — the RaptorQ FEC pipeline, zero protobuf code — and omits `src/grpc/protobuf.rs`, which actually defines the capability. Second confirmed instance of this defect class. | `asupersync-dep-p1-foundations-upksjk.5.1` |
| PB-GAP-02 | Two `src/real_http_h2_*_e2e_tests.rs` files exercise `ProstCodec` over real HTTP/2 streaming but are declared as modules nowhere, so they never compile. | `asupersync-d24mms.12.1` |
| PB-GAP-03 | No gRPC or protobuf example under `examples/`, and the module doc example is in an `ignore` fence. | `asupersync-5z2scg.1.7` |
| PB-GAP-04 | `ProtobufError` wraps prost's encode and decode error types, so the public error surface is not prost-free. Any replacement is a breaking error-surface change. | `asupersync-5z2scg.1` |
| PB-GAP-05 | `ProstCodec` does not override `set_max_encode_message_size` / `set_max_decode_message_size` (default no-op bodies), so runtime limit renegotiation never reaches it. Only construction-time `with_max_size` has effect. | `asupersync-5z2scg.1.4` |
| PB-GAP-06 | The capability baseline is `EXECUTABLE_PARTIAL_BLOCKING`: positive, boundary, malformed and resource cases have evidence, but cancellation cleanup and recovery are blocked. | `asupersync-5z2scg.1.7` |

PB-GAP-01 belongs to the capability-registry owner and is filed as
`asupersync-dvgpji` together with the equivalent defect found in DEP-ADR-004.

## Invariant impact checklist

- [x] The arbitrary downstream generic surface is preserved.
- [x] Both type parameters remain independent.
- [x] Protobuf stays available at default features on supported targets.
- [x] Streaming and unary use of the generic codec are both preserved.
- [x] All three `ProtobufError` variants and their detail are preserved.
- [x] The accepted data model and unknown-field policy are preserved.
- [x] Wire-byte and framing compatibility are preserved.
- [x] Size limits are still enforced before allocation on decode.
- [x] No compatibility shim or deprecated alias is introduced.
- [x] No root export changes, so `artifacts/api_surface_map_v1.json` is untouched.

## Evidence

Evidence state is `BASELINE_PLANNED`: the corpus is specified, not executed.

- Baseline: `asupersync-5z2scg.1.1`
- Unit: `asupersync-5z2scg.1.4`
- No-mock E2E: `asupersync-5z2scg.1.7`
- Scenario IDs: `protobuf_generic_consumer`, `protobuf_cross_language`,
  `grpc_streaming`

The standalone consumer fixture is the load-bearing artifact: it builds outside
the workspace, without `test-internals`, authors its own message with map and
oneof fields, and asserts both the codec round-trip and the size-limit error.
Cross-language interop in both directions remains the gap that most needs
closing, and PB-GAP-06 records that cancellation and recovery are still blocked.

## Rollback

Triggered by any downstream crate that can no longer author or use its own
message type, any narrowing of the accepted data model, any lost error variant or
size detail, any wire-byte divergence, any streaming ordering change, or any
prost major bump that breaks the pinned consumer fixture. Because the decision is
KEEP, rollback means abandoning the replacement attempt rather than restoring a
deleted capability.

## Focused contract

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_dependency_api_adr_registry" cargo test -p asupersync --test dependency_api_adr_registry_contract -- --nocapture
```

## No-claim boundary

This ADR is a frozen decision and public-surface inventory only. It does not
prove that the planned evidence has run, that cross-language interoperability has
been demonstrated, that cancellation and recovery behavior is correct, that an
owned protobuf implementation could reach ergonomic or wire parity, that
performance is unchanged, or that `prost` may be removed. It also does not
certify the capability registry's source-owner rows, which PB-GAP-01 records as
incorrect for this capability.
