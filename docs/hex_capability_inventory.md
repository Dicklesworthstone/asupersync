# Hex capability inventory

<!-- BEGIN HEX CAPABILITY INVENTORY -->

This is the operator-readable companion to
`artifacts/hex_capability_inventory_v1.json`. It freezes
`CAP-HEX-CODEC` for `asupersync-d24mms.9.1` at revision
`8793ef7097f23622b2bdea1cd9a60afbb11517f1`.

The disposition remains **KEEP_INCUMBENT** and cutover remains
`BLOCKED_PENDING_EVIDENCE`. This inventory authorizes no implementation,
migration, manifest edit, or dependency removal. It gives A2 through A5 an
exact, source-pinned baseline with zero `UNKNOWN` rows.

## Dependency and profile reachability

The root manifest declares unconditional `hex = "0.4"`; the root lockfile
resolves `hex 0.4.3` with checksum
`7f24254aa9a54b5c858eaee2f5bccdb46aaf0e486a595ed5fd8f86ba55232a70`.
The upstream default is `std`, which enables `alloc`.

The marginal ledger classifies this as `normal:hex`, with no target
condition, optional feature, build script, procedural macro, native code, or
unsafe implementation exposure. Each of the 48 synthesized-consumer cells
(12 profiles across four targets) loses exactly `hex@0.4.3` when this single
root edge is removed. The four full workspace dev/build cells lose zero
packages because `sqlx-macros-core` independently retains `hex`.
`const-hex`, reached through `opentelemetry-proto`, is a distinct engine
and is not this replacement edge.

Graph reachability is broader than direct source compilation:

| Direct surface | Requirement |
| --- | --- |
| portable library | root dependency; default and no-default builds |
| ATP library | native target, independent of an ATP feature |
| CLI workflows | `cli` and native target |
| ATP binary | `atp-cli` and native target |
| PostgreSQL | `postgres` and native target |
| root golden modules | `legacy-internal-test-harnesses` and/or `serialization-golden-harnesses` |
| observability audit modules | `cfg(test)` |
| test logging | `cfg(any(test, feature = "test-internals"))` |
| ordinary integration tests | auto-discovered target, empty manifest `required-features`, no crate/direct-occurrence cfg |
| ATP CLI loopback occurrence | auto target; crate requires `atp-cli` and `tls`; the direct occurrence is Windows-only |
| owned LZ4 contract occurrence | auto target; crate requires `test-internals` |
| Kafka broker occurrence | explicit target with empty manifest `required-features`; crate `cfg(test)`; source imports Kafka APIs |
| nested ATP object/journal modules | owned by `atp_object_journal_e2e_proof_suite` |
| nested ATP multi-peer module | owned by `atp_e2e_proof_suite` and `atp_multi_peer_integration` |
| compiled conformance package | direct call, but currently missing a direct manifest edge |
| nested RaptorQ simple golden source | lexical-only and unwired from its package crate root |

There are no direct path uses in examples, benches, or the separate robustness
workspace. Those zero rows are explicit rather than silently omitted. Native
ATP source is absent on wasm32 even though the unconditional dependency remains
graph-reachable there.

## Exact incumbent semantics

Only four upstream names are consumed:

| Name | Code/type references |
| --- | ---: |
| `encode` | 180 |
| `decode` | 33 |
| `decode_to_slice` | 11 |
| `FromHexError` | 4 |

`encode_upper`, `encode_to_slice`, `ToHex`, and `FromHex` have no
repository call site.

### Encoding

`encode` uses the exact lowercase alphabet `0123456789abcdef`, emits no
prefix or separators, maps empty input to an empty string, and emits exactly
two bytes per input byte. It returns an allocated `String` and has no
application-level input or allocation limit. It also computes the output length
with unchecked `2 * input.len()` arithmetic, so representation-limit overflow
or allocation failure is outside its `Result` contract because there is no
`Result` return.

### Allocating decode

`decode` accepts ASCII `0-9`, `a-f`, and `A-F`, including mixed case.
It accepts empty input and rejects whitespace and prefixes. Odd length is
checked before character validity, so a one-byte invalid input reports
`OddLength`. Even input is scanned left to right, high nibble before low
nibble, and the earliest invalid byte wins.

The error index is a raw byte index. An invalid byte is cast directly to
`char`; it is not decoded as a Unicode scalar. A partially built vector is
dropped on error and never returned. Successful output is half the input byte
length. The codec defines no application-level input or allocation cap.

### Slice decode

`decode_to_slice` checks odd input length first and exact destination length
second. Either preflight error leaves the destination unchanged. After
preflight, decoding proceeds left to right. If a later character is invalid,
completed prefix bytes remain overwritten, while the current byte and suffix
retain their prior values. There is no rollback or zeroization.

That partial-prefix behavior is incumbent truth, not a desired policy. A2 must
pin it before choosing and documenting any safer `BETTER` replacement
guarantee.

### Errors

The exact variants are:

- `InvalidHexCharacter { c: char, index: usize }`
- `OddLength`
- `InvalidStringLength`

The exact displays are:

- `Invalid character {:?} at position {}`
- `Odd number of digits`
- `Invalid string length`

The error derives `Debug`, `Clone`, `Copy`, and `PartialEq`, and
implements `std::error::Error` when upstream `std` is enabled. The
machine artifact contains a 12-case semantic corpus covering empty, mixed
case, odd-before-invalid precedence, byte indices, prefix rejection,
non-ASCII bytes, destination mismatch, partial-prefix mutation, and success.

## Complete call-site census

The source snapshot contains 90 Rust files and 230 literal path tokens. Of
those, 228 are code or type references, two are comments, and four code
references are disabled by `cfg(any())`. Another 25 references sit in
`cfg(test)` sections embedded in five otherwise production-owned files. Both
references in `src/test_logging.rs` are separately gated to tests or
`test-internals`. The test/conformance reservation group owns 102 references,
leaving 95 active production references after comment, disabled, and
non-production separation.

| Root | Files | Literal tokens |
| --- | ---: | ---: |
| `src` | 50 | 181 |
| `tests` | 39 | 47 |
| `conformance` | 1 | 2 |
| `examples` | 0 | 0 |
| `benches` | 0 | 0 |
| separate robustness workspace | 0 | 0 |

The two comment-only tokens are in
`src/database/postgres.rs:12714` and
`src/observability/w3c_trace_context.rs:576`. The four disabled references
are in `src/bin/atp.rs:7810,7992,8009` and
`src/net/atp/transport_tcp/mod.rs:569`.

The five mixed production/test files are `src/atp/cache/mod.rs` (one encode),
`src/atp/sync/mod.rs` (two encodes), `src/bin/atp.rs` (nine encodes),
`src/database/postgres.rs` (nine decodes), and
`src/net/atp/sdk/transfer.rs` (four encodes). Their test-only counts remain
part of each file reservation but not the active production behavior claim.

Every path and per-symbol count is recorded under `call_sites` in the
machine artifact. Its contract rescans the source and fails on a missing,
added, or recategorized path.

## Collision-free migration groups

The 90-path census is partitioned into four deterministic, non-overlapping
reservation groups. Digest input is byte-sorted
`path<TAB>literal_token_count\n`.

| Group | Files/tokens | Projection SHA-256 | Owner |
| --- | ---: | --- | --- |
| `HEX-A3-ATP-PROTOCOL-CLI` | 33/94 | `a1432140334c3763e9823e9ea06286a0308c618f03a13b08095d3a3bd5fc5a80` | A3 |
| `HEX-A3-SECURITY-OBSERVABILITY` | 9/21 | `3238b9a702154b696580eb534ac15bb3e5e10abb42e6769fa43ea54e3d2ce71a` | A3 |
| `HEX-A3-DATABASE` | 1/13 | `8b1b81a6b635c208085693fb6ed788bca8c50f08aecb8dac07aab0734acc5b0d` | A3 |
| `HEX-A3-TEST-CONFORMANCE` | 47/102 | `e766658ca7dd79e2439036e74a8b6e3222048f1c5f1e1a4088474968cff97fe2` | A3 |

A2 owns the scalar kernel and owned error. A3 migrates one reserved group at a
time without touching the manifest. A4 owns independent evidence and real
ATP, database, trace, and artifact journeys. A5 alone may reconcile graph
authority and conditionally serialize dependency cutover.

## Public API

Only one public signature directly exposes a third-party type:

`asupersync::net::atp::sdk::object::ObjectHash::from_hex(&str)
-> Result<ObjectHash, hex::FromHexError>`.

It is reachable through the native ATP SDK module. Syntax errors retain the
upstream variant and detail. A successfully decoded length other than 32 bytes
maps to `InvalidStringLength`. `ObjectHash::hex` returns 64 lowercase
digits. The only other function returning the upstream error is the private
`decode_hex_32` helper in `src/net/atp/sdk/transfer.rs`.

Owned public mappings also require exact preservation:

- `KeyFingerprint`: mixed-case input; syntax display embedded in
  `KeyStoreError::InvalidFingerprint`; exact 32-byte length; lowercase full
  and redacted output.
- `TranscriptHash`: syntax collapses to `invalid hex encoding`; wrong
  length reports the observed byte count; lowercase output.
- ATP peer IDs: syntax and length collapse to
  `DirectoryError::InvalidPeerIdHex`; lowercase output.
- W3C `TraceId` and `W3CSpanId`: exact widths, mixed-case input, fixed owned
  messages, all-zero rejection, lowercase output.
- `ContentId`, `ManifestId`, `ObjectId`, `MerkleRoot`, `CommitId`, and
  `ObjectDigest`: full forms are 64 lowercase digits. Displays are exactly
  `content:`+16, `manifest:`+16, delegated object display, `merkle:`+16,
  `commit:`+16, and `sha256:`+16; object-digest redaction is
  `sha256:`+12+`...`.
- Durable identity, repair, protocol, and consensus diagnostics: durable peer
  IDs use 64 lowercase digits; peer/session redactions use 16; repair peer
  strings use `socket#`+16; message digests use `digest:`+16.
- `SerializableContentId` Display emits 64 lowercase digits.
- `PeerInfo::auth_domain` emits `atp-repair:` followed by the first 12 digest
  bytes as exactly 24 lowercase digits.
- `BondedTransfer::auth_key_hex` trims whitespace, accepts an optional
  lowercase `0x`, then requires 64 mixed-case ASCII digits/32 bytes. Owned
  length, character, decode, and key-strength failures map to
  `RqError::Authentication`.

The root-only API map contains none of these nested types. That is an explicit
A3/A5 routing gap, not evidence that the public ATP error can change.

## Persisted, wire, and credential formats

The inventory names nineteen format families:

1. W3C `traceparent`: 128-byte header cap; four fields; version `00`;
   32-digit trace ID; 16-digit span ID; two-digit flags; mixed-case input;
   lowercase output; all-zero IDs rejected.
2. PostgreSQL `bytea`: binary format accepts arbitrary bytes. Text format
   rejects invalid UTF-8 first; lowercase `\\x` output accepts mixed-case
   prefixed payloads, while valid-UTF-8 unprefixed text becomes raw bytes.
3. Mailbox peer IDs: `peer-` followed by 16 lowercase digits.
4. Mailbox transfer IDs: lowercase UUID-shaped output; compact or canonical
   mixed-case input; source-byte error positions.
5. Mailbox SHA-256 metadata: lowercase digest and `sha256:` text; malformed
   or mismatched values become tamper evidence.
6. Detached ATP signatures: all three fields represent 32 bytes;
   `session_id_hex` must be canonical lowercase, while `hash_hex` and
   `signature_hex` accept mixed case at exactly 64 digits; failure is false.
7. Bonded auth descriptors: stored key text normalizes to 64 lowercase digits
   without a prefix; key IDs are `rq-auth-sha256:`+16.
8. ATP delta roots: QUIC and RQ require canonical lowercase; active TCP and
   channel bonding accept mixed case after exact 64-character checks.
9. ATP object, manifest, cache, proof, package, and state identifiers retain
   exact lowercase bytes, widths, prefixes, and separators. Cache storage uses
   a two-digit shard and 64-digit filename from SHA-256 of content-hash text.
10. Directory sync proofs: manifest/final roots are 64 lowercase digits;
    replay pointers are `directory-sync:`+64.
11. Stream consumer signatures: optional artifact text is lowercase and
    exactly twice the signature byte length.
12. Grant state: `grant-`+32, `paired-`+32, and persisted
    `grants/<sha256(grant-id) as 64 lowercase digits>.json`.
13. Session state: `atp-session-`+32; peer/session redactions are 16 digits;
    transcript redaction is 24.
14. Handshake trace JSON: connection IDs, CID fields, retry tokens, and
    transport-parameter values are lowercase variable-width hex.
15. Repair authentication domains: `atp-repair:` followed by exactly 24
    lowercase digits derived from the first 12 digest bytes.
16. ATP lab artifacts: replay fingerprints and attachment SHA-256 fields are
    64 lowercase digits; minimization keys are `atp-lab-<scenario>-` followed
    by the first 12 fingerprint digits.
17. CLI workflow artifacts: generated content hashes and checksums are raw 64
    lowercase digits. The current unit assertion's `sha256:` expectation is a
    routed contradiction, not the implemented grammar.
18. Keys and evidence: fingerprint full/redacted widths are 64/16;
    `AgentCredentials.signature` is `nkey_ed25519.` followed by a
    mixed-case-decodable signature whose bytes are verified; bearer tokens are
    `agent_token_v1.<agent_id>.<issued>.<expires>.<64-digit HMAC>`, with
    mixed-case digest input accepted during verification. Certificate hashes,
    handoff content hashes, and CrashPack checksums are 64; lab journal refs
    are `sha256:`+64.
19. Golden and evidence digests: snapshot bytes and lowercase fingerprints
   remain byte-identical.

These are preservation boundaries. A green scalar codec test alone cannot
establish their parity.

## Manual-codec collision surfaces

Several public/manual hex implementations do not use the dependency and must
not be swept into a mechanical migration:

- `PlanHash`, `ProofHash`, and distributed `DistTraceId`;
- `Color::from_hex`, whose whitespace and optional-`#` grammar differs;
- public `transport_common::hex_encode`;
- manual fixed ID encoders for `TransferId`, `DeltaChunkId`, and distributed
  `ContentHash` (the content/manifest/object APIs that call the dependency are
  public migration surfaces instead);
- TLS diagnostic `short_hex`;
- manual byte encoders in `examples/demo_benchmark.rs` and
  `benches/golden_output.rs`;
- no numeric-formatting syntax is treated as a byte-codec migration target.

`transport_common::hex_encode` is a candidate A2 must review, not an
already-approved kernel: it only encodes, uses unchecked capacity
multiplication, and provides no owned decode or error behavior.

## Routed gaps

| Gap | Finding | Owner |
| --- | --- | --- |
| `HEX-A1-GAP-01` | registry names unrelated `src/encoding.rs` as source owner | A5 |
| `HEX-A1-GAP-02` | registry feature list misses actual/unconditional profiles | A5 |
| `HEX-A1-GAP-03` | target resource/atomicity policy differs from incumbent truth | A2 |
| `HEX-A1-GAP-04` | `EVD-HEX-GOLDENS` overstates malformed/resource coverage | A4 |
| `HEX-A1-GAP-05` | no downstream profile or consumer fixture for public ObjectHash | A4 |
| `HEX-A1-GAP-06` | public upstream error and nested ATP surface are absent from API map | A3 |
| `HEX-A1-GAP-07` | registry aliases and matrix journeys are not runner-registered | A4 |
| `HEX-A1-GAP-08` | reachable conformance package calls lack a direct dependency | A5 |
| `HEX-A1-GAP-09` | four disabled references must remain separate from active parity | A3 |
| `HEX-A1-GAP-10` | manual collision surfaces need explicit disposition | A2 |
| `HEX-A1-GAP-11` | allocating APIs lack a cap and encode uses unchecked 2N length arithmetic | A2 |
| `HEX-A1-GAP-12` | A1 intentionally produced no live journey result | A4 |
| `HEX-A1-GAP-13` | nested simple golden source is lexical-only and unwired | A3 |
| `HEX-A1-GAP-14` | explicit Kafka test target omits required feature declaration | A5 |
| `HEX-A1-GAP-15` | CLI implementation emits raw 64-digit hashes while its unit assertion expects a `sha256:` prefix | A3 |

There are zero `UNKNOWN` rows. Missing runtime evidence is
`NOT_RUN_BY_A1`; the conformance manifest state is `BLOCKED`; the unwired
fixture is `OUT_OF_SCOPE` for compiled behavior; every discrepancy has an
owner.

## Downstream and evidence routing

The existing baseline remains `EXECUTABLE_PARTIAL_BLOCKING`. Its
`EVD-HEX-GOLDENS` fixtures contain valid and self-generated values but do
not substantiate their claimed malformed or oversized decode coverage. The
baseline downstream profile list is empty, and the consumer fixture does not
exercise `ObjectHash::from_hex` or the upstream error.

The registry aliases `hex_public_api`, `hex_protocol_artifact`, and
`hex_protocols` are planned but absent from the runner. The four hashed
matrix journey IDs for A1, A3, A4, and A5 remain planned routing metadata.
A4 owns registration and terminal evidence; this inventory does not fabricate
execution receipts.

## Validation boundary

`tests/hex_capability_inventory_contract.rs` is the focused static contract.
It checks identity, authority, zero-unknown policy, 81 unique source pins, all
20 compilation profiles, the complete path/symbol census, deterministic
reservation-group digests, eleven public/API rows, eight manual collision rows,
nineteen persisted-format rows, fifteen routed gaps, exact owner maps, the
canonical claims projection, documentation markers, and negative mutations.

This A1 pass ran no Cargo build, remote compilation, scenario, or robustness
lane. Static source pins do not prove compilation, runtime correctness,
performance, constant-time behavior, secret zeroization, broad workspace
health, release readiness, or permission to remove the incumbent.

<!-- END HEX CAPABILITY INVENTORY -->
