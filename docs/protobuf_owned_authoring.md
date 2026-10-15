# Owned Protobuf authoring contract

Bead: `asupersync-5z2scg.1.6` (Protobuf A6)

Status: additive authoring surface shipped; incumbent decision remains
`KEEP_UNTIL_PARITY` / `KEEP_INCUMBENT`.

This contract freezes the Cargo-only derive grammar for the owned
`ProtoMessage` and `ProtoOneof` traits. It adds a reasonable inline-Rust
authoring path without narrowing `ProstCodec<T, U>`, changing the unconditional
`prost` feature graph, invoking `protoc`, or consulting an ambient schema
registry.

## Authoring grammar

Derive a named-field struct with `asupersync::ProtoMessage`. Every field has
exactly one `#[proto(...)]` attribute.

| Construct | Attribute and Rust type |
|---|---|
| scalar | `#[proto(uint64, tag = 1)] value: u64` |
| optional scalar | `#[proto(uint64, optional, tag = 2)] value: Option<u64>` |
| repeated scalar | `#[proto(string, repeated, tag = 3)] values: Vec<String>` |
| packed numeric | `#[proto(sint64, repeated, packed, tag = 4)] values: Vec<i64>` |
| nested message | `#[proto(message, optional, tag = 5)] child: Option<Child>` |
| map | `#[proto(map, key = "string", value = "uint64", tag = 6)] values: HashMap<String, u64>` |
| enumeration | `#[proto(enumeration = "Mode", tag = 7)] mode: i32` |
| oneof | `#[proto(oneof, tags = "8, 9")] payload: Option<Payload>` |
| unknown fields | `#[proto(unknown_fields)] unknown: UnknownFields` |

The scalar vocabulary is `double`, `float`, `int32`, `int64`, `uint32`,
`uint64`, `sint32`, `sint64`, `fixed32`, `fixed64`, `sfixed32`, `sfixed64`,
`bool`, `string`, and `bytes`. Repeated numeric, boolean, and enumeration fields
accept both packed and unpacked input; `packed` controls only the emitted form.

A oneof is an enum derived with `asupersync::ProtoOneof`. Every variant is a
one-value tuple variant with its own scalar, string, bytes, nested message, or
enumeration attribute and tag. The containing field repeats the sorted tag set.
Expansion compares that set with `ProtoOneof::FIELD_NUMBERS` in a const
assertion, so schema drift fails during compilation.

Maps accept `BTreeMap<K, V>` and `HashMap<K, V>`. Generated encoding sorts
entries by key before emission, so `HashMap` insertion order cannot affect wire
bytes. Map keys are restricted to the protobuf integer, boolean, and string
key types.

## Deterministic validation and diagnostics

The derive rejects these conditions before generated Rust is type-checked:

- missing or duplicate field attributes;
- field zero, values above `(1 << 29) - 1`, and the reserved
  `19000..=19999` range;
- duplicate ordinary, map, nested, or oneof tags in one message;
- `optional` on a non-`Option<T>` field and `repeated` on a non-`Vec<T>` field;
- `packed` on a non-repeated or non-packable type;
- unsupported map key kinds or malformed oneof variants.

The exact diagnostics are pinned by the four `proto_*.stderr` trybuild fixtures
under `asupersync-macros/tests/compile_fail/`. Expansion stability is pinned by
FNV-1a goldens in `asupersync-macros/src/proto.rs`: one representative message
and one representative oneof must produce identical token streams and the
committed hashes.

## Runtime semantics

- Known fields emit in ascending tag order regardless of Rust declaration
  order.
- Singular proto3 scalars omit defaults. `Option<T>` and oneof variants retain
  presence even when their active scalar value is the default.
- Repeated fields append in wire order. Singular scalars are last-one-wins.
  Nested messages merge through the parent decoder's shared resource budget.
- `#[proto(unknown_fields)]` captures unrecognized records verbatim and emits
  them after known fields. Without that member, unknown fields are skipped.
- All encoding and decoding uses the existing bounded owned wire kernel.
  The derive introduces no executor, build daemon, global registry, or
  non-Cargo package manager.

The runtime grammar is exercised in
`asupersync-macros/tests/proto_message.rs`. The public root re-export and this
document are checked by `tests/protobuf_owned_authoring_contract.rs`.

## Independent downstream journeys

Two standalone crates opt into only `proc-macros` and do not depend on `prost`:

- `tests/fixtures/protobuf-owned-unary` authors distinct request and response
  types and round-trips a realistic unary response through `ProtoCodec`.
- `tests/fixtures/protobuf-owned-streaming` authors packed values, a map, a
  nested cursor, and a three-variant oneof, then preserves message order through
  `FramedCodec`.

They are separate Cargo workspaces so workspace dev-dependencies cannot hide a
missing public export or an accidental reliance on test internals.

## Ergonomics and compile-impact review

The inline-Rust path is close to prost derive for scalar, optional, repeated,
packed, map, raw enumeration, oneof, and nested message declarations. It is
better for deterministic `HashMap` emission, explicit unknown-field retention,
and removal of an ambient `protoc` requirement. It adds no proc-macro
dependencies: `asupersync-macros` already depended on `syn`, `quote`, and
`proc-macro2`, and default builds already enabled that crate.

It is not comparable to the complete prost ecosystem:

- there is no `.proto` parser, package/import resolver, descriptor set, service
  generator, source-info retention, or generated accessor layer;
- enumeration storage deliberately remains raw `i32` to preserve unknown
  values, without prost's generated typed accessors;
- there is no generated cross-language schema artifact for another compiler to
  consume;
- compile cost has been bounded and observed in the focused RCH lanes, but no
  controlled same-schema prost-versus-owned benchmark has established SAME or
  BETTER compile time.

Diagnostic quality is directly reviewed by exact trybuild stderr, while the
compile graph comparison is structural: no new macro dependency edge was
introduced. Those remaining ecosystem and measurement gaps make the aggregate
authoring result WORSE for existing `.proto` consumers. Therefore this bead
ends in KEEP, not cutover.

## Proof commands

All Cargo commands require remote execution. In a peer-dirty shared checkout,
overlay only the reserved A6 paths on `HEAD`.

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_proto_authoring_macro" CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync-macros --test proto_message -- --nocapture
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_proto_authoring_trybuild" CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync-macros --test compile_fail_tests -- --nocapture
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_proto_authoring_contract" CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test protobuf_owned_authoring_contract -- --nocapture
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_proto_authoring_unary" CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test --manifest-path tests/fixtures/protobuf-owned-unary/Cargo.toml -- --nocapture
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_proto_authoring_streaming" CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test --manifest-path tests/fixtures/protobuf-owned-streaming/Cargo.toml -- --nocapture
```

## No-claim boundary

This additive derive does not authorize removing `prost`. It does not prove
cross-language interoperability, descriptor/reflection parity, `.proto`
code-generation parity, broad workspace health, release readiness, a compile
time improvement, or that every prost downstream schema can migrate. Those are
owned by Protobuf A4 and A7 plus the aggregate epic. `ProstCodec`,
`SymmetricProstCodec`, and the prost-backed error variants remain supported and
unchanged.
