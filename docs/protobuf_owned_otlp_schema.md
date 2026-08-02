# Owned OTLP protobuf schema authority

<!-- BEGIN PROTOBUF OWNED OTLP SCHEMA -->

This document is the operator-readable companion to
`artifacts/protobuf_owned_otlp_schema_v1.json` for
`asupersync-5z2scg.1.3` and `CAP-PROTOBUF-GENERIC`. The machine artifact is
authoritative for exact messages, tags, wire kinds, cardinalities, oneofs,
reserved tags, enums, limits, ownership, and no-claim boundaries.

The packet is an authority and partial-source receipt, not a completion receipt.
The private common/resource/metrics/trace/logs slice, the three
metrics-collector messages, their unit-test bodies, and a terminal native
default-plus-metrics library check are present. The remaining 6 collector
messages and unit-test execution remain pending. The public arbitrary
`prost::Message` capability and every incumbent OTLP path stay intact.

## Outcome

The root workspace has enough local evidence to pin the exact wire schema:

- `opentelemetry-proto` Rust crate `0.32.0`, crates.io checksum
  `56d658ba1faf63f7b9c492cfbe6e0ec365440a16132d3270c1065f7b33f1b638`;
- wrapper repository commit
  `ec289cb3c6f8260951699c51df968560943c1451` in
  `open-telemetry/opentelemetry-rust`;
- OTLP proto release `v1.10.0`, dated 2026-03-09; and
- the exact bytes of eight vendored `.proto` sources and eight generated Rust
  oracle files, each pinned by SHA-256 in the artifact.

The wrapper commit is not called an upstream schema commit. The published crate
does not retain the upstream `open-telemetry/opentelemetry-proto` commit SHA, so
the binding schema authority is the named v1.10.0 release plus the eight source
digests.

The default semantic-conventions URL
`https://opentelemetry.io/schemas/1.37.0` is a separate contract. It describes
semantic conventions; it is not the OTLP wire-schema version.

## Root lock authority and stale fuzz lock

The root `Cargo.lock` resolves `opentelemetry-proto` `0.32.0`. The fuzz manifest
requests `0.32`, but `fuzz/Cargo.lock` still resolves `0.31.0`. That lock is
explicitly excluded from A3 authority. This packet does not refresh it, run it,
or treat it as v0.32 evidence.

Generated OTLP messages remain a test/fuzz differential oracle. They may not
enter the default or `metrics` production graphs, because their tonic path
carries Tokio. The owned finite types must compile without that edge.

## Exact source set

| Package | Path | SHA-256 |
| --- | --- | --- |
| common | `common/v1/common.proto` | `833db934b8b08be193940aa412f26a9ed8c564dfa8ea3517dc583f5064142731` |
| resource | `resource/v1/resource.proto` | `e0a7cdc0ffcfeffaa2606e8611839735ebffaa2d6acdf33e9356f2c48ae692d3` |
| metrics | `metrics/v1/metrics.proto` | `d0a53dda45ad100edbf25675f5b339ce8bf689bdc51816f8cf19b0d51464e1a4` |
| trace | `trace/v1/trace.proto` | `c3fb1385c90b8bc08a2a462e28b5d0c422c7b524a839f75f75e3cd9f64f36956` |
| logs | `logs/v1/logs.proto` | `6b2e1eba0c01ae2da47927c63eabfaf3f151ee7ad846f2cdf3b2b71fb61004fe` |
| metrics collector | `collector/metrics/v1/metrics_service.proto` | `2bb3c6adee5f7609c8a32c5e4b1ec57057320015e298e9cf136699a42abc24d7` |
| trace collector | `collector/trace/v1/trace_service.proto` | `03c8cc4e3e101087d884392d6eda32152ad5cd696e6344f50deaa59804a75c7a` |
| logs collector | `collector/logs/v1/logs_service.proto` | `0252687fc8f59d139ced709d383e83678e9bd4957bdbe76077242f1c32363fa5` |

Authority drift is fail-closed: refresh the inventory and retain the incumbent
before implementation or cutover claims continue.

## Finite schema inventory

The machine registry contains 8 families, 43 messages, 163 fields, 7 enum or
bitmask contracts, and 3 unary collector methods.

| Family | Included shape |
| --- | --- |
| common | recursive `AnyValue`, arrays, key/value lists, `KeyValue`, `InstrumentationScope`, `EntityRef` |
| resource | `Resource`, attributes, dropped count, entity references |
| metrics | resource/scope groups; gauge, sum, histogram, exponential histogram, summary; every point, bucket, quantile, exemplar, temporality, flag, and metadata field |
| traces | resource/scope groups; spans, events, links, status, kinds, flags, IDs, timestamps, and drop counts |
| logs | resource/scope groups; typed body, severity, attributes, flags, IDs, observed time, and event name |
| collectors | request, response, and partial-success message for metrics, traces, and logs |

The complete v1.10.0 finite family is inventoried even where current producer
adapters construct only a subset. That distinction prevents current mapping
coverage from being confused with wire-schema coverage. Signal adapters and
transport integration remain downstream work.

The implemented slice is exactly the six common messages (`AnyValue`,
`ArrayValue`, `KeyValueList`, `KeyValue`, `InstrumentationScope`, and
`EntityRef`), `Resource`, all 16 metrics messages, all seven trace messages,
all four logs messages, and the three metrics-collector request, response, and
partial-success messages. Its shared semantic budget, fallible owned storage,
deterministic known-field encoding, unknown-field preservation, oneof and
singular-message merge behavior, packed/unpacked scalar handling, metric
equations, trace ID/time/name/tracestate invariants, raw kind/status/flag
retention, logs severity and flag retention, exact-or-empty log IDs,
partial-success invariants, and local boundary/error test bodies are present in
`src/observability/otlp_proto.rs`. The aggregate collector submodule remains
pending because collector-trace and collector-logs messages are absent, so A3
remains open and A4/A7 remain blocked.

Every finite message must own an `UnknownFields` member. Enum-valued fields are
stored as raw numeric values with typed helpers for known values; unknown values
and unknown flag bits survive a decode/re-encode cycle.

## Deterministic wire and evolution policy

Known fields encode in ascending tag order. Repeated element order is retained.
Packable repeated scalars encode packed, while decoders accept both packed and
unpacked forms. Singular scalar duplicates use last-value-wins; singular
messages follow protobuf merge semantics. Repeated occurrences of the same
message-valued oneof member merge; a different member replaces it, while
scalar or different-member occurrences use the last recognized value.

Unknown fields, including complete groups, retain their exact raw bytes in
unknown-field encounter order. Re-encoding places canonical known fields first
and then raw unknown fields. That preserves unknown data but deliberately makes
no claim that an unknown field returns to its original position among known
fields.

Reserved tags are never emitted as known fields or reused. An incoming reserved
tag is retained as unknown data within the shared resource budget. A removed
known field must reserve both its number and name. A known tag with the wrong
wire kind is a typed error, not an unknown-field escape hatch.

## Resource policy

The generic wire envelope is the current owned default:

| Limit | Value |
| --- | ---: |
| top-level message bytes | 4,194,304 |
| one length-delimited field bytes | 4,194,304 |
| wire field records | 65,536 |
| combined wire depth | 100 |
| cumulative wire work bytes | 16,777,216 |

All nested finite messages must also share one semantic budget. The schema
layer checks each affected limit before its corresponding reserve, allocation,
push, or field mutation and returns no partial model from a fresh decode. A
merge API may claim all-or-nothing failure only if it stages and commits after
complete validation; an incremental in-place merge must instead document and
test partial-mutation-on-error behavior. The codec never silently truncates and
never interprets zero as unbounded.

Key semantic defaults are:

| Path | Maximum |
| --- | ---: |
| resource groups per request | 64 |
| scopes per resource group | 128 |
| metrics, spans, or log records per scope | 4,096 |
| data points per metric | 1,000 |
| attributes on any owner | 128 |
| recursive `AnyValue` depth | 16 |
| `AnyValue` array or key/value-list entries | 128 |
| total `AnyValue` nodes | 4,096 |
| events or links per span | 128 |
| exemplars per point | 128 |
| histogram bucket counts | 4,096 |
| histogram explicit bounds | 4,095 |
| exponential buckets per sign | 4,096 |
| summary quantiles | 1,024 |
| attribute key bytes | 1,024 |
| attribute string or bytes value | 4,096 |
| total owned string and bytes payload | 4,194,304 |

The generic-wire values are incumbent facts. Some producer limits are also
incumbent facts: logs already cap attributes at 128 and value bytes at 4,096;
metrics default to 4,096 names and 1,000 cardinality entries per metric. The
128 span-attribute and event values exist only in a conformance-test helper.
The simplified/testing `OtlpSpan` exporter instead has an unbounded attribute
vector, no events collection, and a distinct 255-character value truncation.
Resource/scope/record, recursive value, trace attribute/event/link, exemplar,
bucket, quantile, and several string-path caps are therefore new A3 policy
relative to the actual producers. They do not establish parity by themselves.
A downstream adapter must prove lossless chunking, typed rejection, or an
already-authorized counted-drop rule before migration.

Producer-side truncation remains separate. An adapter may apply a stricter
limit only where its existing contract defines the matching dropped counter.
The schema codec itself always returns a typed error.

The trace slice also enforces the pinned signal semantics: required nonzero
16-byte trace IDs and 8-byte span IDs, optional exact-width parent IDs,
exact-width nonempty link IDs, nonempty span and event names, nonzero ordered
span times, unique attributes, and W3C tracestate syntax for nonempty span/link values. Tracestate
validation retains the 512-byte aggregate bound, at most 32 unique members,
the W3C key/value component limits, and bounded duplicate-key work. Unknown
enum values and high flag bits are retained rather than rejected.

## Why the current derive is insufficient

The existing owned `ProtoMessage` and wire kernel provide the correct generic
starting point, including shared nested decode accounting and opt-in raw unknown
fields. The current derive path cannot yet make the A3 resource claim:

- nested and map encoding starts fresh default budgets rather than sharing the
  parent depth/work context;
- repeated, packed, and map decoding pushes or inserts without a semantic
  per-collection pre-allocation check;
- packed and map encoding can collect a whole source collection before a parent
  size rejection;
- oneof decoding replaces a repeated message-valued member instead of merging
  that same member as protobuf requires;
- `metrics` does not imply the optional proc-macro feature, and the required
  `--no-default-features --features metrics` cell cannot assume it; and
- compatibility `UnknownFields::record` and `record_raw` retain ordinary `Vec`
  growth; fallible alternatives now exist, but a safe downstream shared nested
  writer remains pending.

The common/resource/metrics/trace/logs/collector_metrics slice therefore uses
manual `ProtoMessage` implementations with one shared semantic budget plus
reviewed bounded nested/collection primitives in the authoring layer.
Remaining collector families must preserve that pattern. Deriving the messages and calling
`validate()` only after decode is explicitly forbidden as evidence for
pre-allocation bounds.

Fresh decode may use private staging state and return no partial model. Any
merge API must either stage then commit atomically or explicitly document and
test non-atomic partial mutation on error.

The recommended genuine private leaf is
`src/observability/otlp_proto.rs`, gated to native `metrics` builds. It must not
be publicly re-exported. Common/resource, metrics, trace, logs, collector, and
limits/error concerns should remain separately reviewable within that leaf.

## Feature and target contract

| Profile | Required outcome |
| --- | --- |
| default | additive source-compatible generic protobuf authoring errors and fallible methods; no generated OTLP dependency or public OTLP schema type |
| `metrics` | native private schema compiles without generated OTLP, tonic, or Tokio normal edges |
| `metrics,tracing-integration` | same owned schema; generated messages remain oracle-only |
| `--no-default-features --features metrics` | compiles without assuming proc macros |
| `fuzz` | generated oracle stays quarantined; stale lock cannot claim v0.32 authority |
| wasm32 | native schema integration remains excluded until separately designed and proved |

The additive generic authoring surface is explicit: `UnknownFields::try_record`
and `try_record_raw`, `ProtobufWireEncoder::remaining_work` and
`charge_schema_work`, plus the non-exhaustive `SchemaLimitExceeded`,
`AllocationFailed`, and `SchemaInvariant` wire-error variants. No public OTLP
schema type is added. `ProstCodec<T, U>`, `SymmetricProstCodec<T>`, and existing
downstream arbitrary-message capabilities are neither removed nor narrowed.

## Evidence ownership

| Owner | Evidence |
| --- | --- |
| Protobuf A3 `asupersync-5z2scg.1.3` | finite types, typed schema/resource errors, local happy/boundary/error tests, bounded shared-budget lifecycle and generic-codec consumer checks, and this authority packet |
| Protobuf A4 `asupersync-5z2scg.1.4` | independent bytes, full differential, malformed, property, minimized failure, and bounded fuzz evidence |
| Protobuf A7 `asupersync-5z2scg.1.7` | cross-language peers, downstream messages, schema evolution, gRPC shapes, cancellation, restart, and real journeys |
| OTLP A6 `asupersync-5z2scg.2.6` | request/response framing, partial-success behavior, transport integration, and production dependency-graph proof |

The registered A3 authority prefixes are retained in the machine packet.
`tests/protobuf_owned_otlp_schema_contract.rs` now uses recursive duplicate-key
rejection plus one reusable fail-closed validator. It freezes normalized exact
schema, enum, service, and authority-pin projections and includes negative
mutations for missing or duplicate families, tags, wrong wire/packed metadata,
missing unknown storage, all 45 numeric limits, stale-oracle promotion,
post-decode-only budgeting, and accidental public or cutover authority.

Within A3, `__lab_lifecycle` means deterministic shared-budget and fresh-decode
failure-state checks only; it proves no runtime task, cancellation, shutdown,
or transport behavior. `__downstream_consumer` reserves source-level
compile/use test bodies for the implemented finite metrics, traces, logs, and
metrics-export request/response shapes through the existing owned generic
codec. Those unit tests have not executed, and the scope does not cover signal
adapters, framing, collector contact, transport, or user journeys.

The semantic invariants in the artifact are a non-exhaustive minimum. The
implementation remains bound to every normative requirement in the pinned
v1.10.0 sources, including histogram count equality, nonnegative summary
quantile values, required trace identifiers/times/names, and W3C tracestate
format; the contract validator does not treat the listed examples as the
complete semantic specification.

## Current validation

This 37-message partial implementation slice has one terminal green compiler
receipt. Under an RCH clean overlay containing only the owned implementation
path, `cargo check --locked -p asupersync --lib --features metrics -j 4`
completed with exit code 0 and warnings denied on 2026-08-02 (`hz1`, RCH
execution `c894e4e10feeb685`). That receipt establishes a native
default-plus-metrics library typecheck for the
common/resource/metrics/trace/logs/collector_metrics source only; it does not
compile or run the unit-test bodies and is not a broad workspace or
feature-matrix result.

The artifact records 8 families, 43 unique message names, 163 fields with no
duplicate tag inside a message, 7 enum/bitmask rows, and 3 services. Independent
read-only review compares the registry against the vendored v1.10.0 sources.
The refreshed contract source and
common/resource/metrics/trace/logs/collector_metrics unit-test bodies are
present. Canonical unit-test execution remains pending. The remaining 6 finite
collector messages, reference vectors, feature matrix, and downstream journeys
are also pending.

## No-claim boundary

This packet records source, unit-test bodies, and a terminal native
default-plus-metrics library check for the private
common/resource/metrics/trace/logs/collector_metrics slice. It does not execute
the unit tests and does not implement collector_trace or collector_logs.
It proves no malformed/resource behavior, byte parity, collector contact,
signal wiring, or transport behavior and establishes no incumbent parity for
the new A3 caps. It adds no generated dependency, tonic, Tokio, or runtime to a
production graph.
Beyond the recorded source-compatible generic authoring methods and
non-exhaustive errors, it adds no public OTLP schema type and removes or narrows
no capability, feature, target, persisted format, or user journey. It
authorizes no dependency removal, production cutover, tracker closure,
performance claim, broad workspace-health claim, release-readiness claim,
local Cargo fallback, or file deletion.

<!-- END PROTOBUF OWNED OTLP SCHEMA -->
