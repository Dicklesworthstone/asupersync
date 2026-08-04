# Base64 capability inventory

<!-- BEGIN BASE64 CAPABILITY INVENTORY -->

This is the operator-readable companion to
`artifacts/base64_capability_inventory_v1.json`. It freezes the direct and
colliding Base64 surfaces for `CAP-BASE64-CODEC` and
`asupersync-d24mms.10.1` at source revision
`7bb939ab2d18c1c102671809cf74b922d2ed0437`.

The disposition remains **KEEP_INCUMBENT** and dependency cutover remains
`BLOCKED_PENDING_EVIDENCE`. A1 is a static inventory: its execution state is
`NOT_RUN_BY_A1`. It authorizes no implementation, migration, manifest edit,
dependency removal, release claim, or tracker closure.

## Dependency and graph boundary

The root manifest selects `base64 = 0.23` with default features disabled and
only `std` enabled. The lockfile resolves `base64 0.23.0` at checksum
`b25655df2c3cdd83c5e5b293b88acd880332b2ddadd7c30ac43144fdc0033da9`.
This deliberately excludes upstream's default `simd-unsafe` feature and keeps
the safe scalar `GeneralPurpose` engine.

That is an unsafe-code boundary, not a timing guarantee. The incumbent scalar
engine explicitly makes no constant-time claim. Credential callers must retain
that no-claim boundary unless separate evidence establishes something stronger.

Three additional dependency/version boundaries are present:

- The root lock also retains transitive `base64 0.22.1` through
  `opentelemetry-proto 0.32.0`, `sqlx-core 0.9.0`, and `tonic 0.14.6`.
- The excluded fuzz workspace selects `0.22` and resolves `0.22.1`.
- The standalone RaptorQ differential workspace selects `0.22` but has no
  repository lockfile, so its exact patch is not pinned.

`base64ct 1.8.3` is a distinct dependency and is not this replacement edge.
Removing the direct root `base64 0.23` edge therefore would not remove every
Base64 package from the locked root graph.
The dependency marginal ledger covers 13 canonical profiles across four
targets, for 52 cells: 12 synthesized-consumer profiles plus one full-workspace
dev/build audit profile. Each root-edge removal cell loses exactly
`base64@0.23.0`.

## Four exact engines

All engines reject whitespace, the other alphabet's divergent symbols,
one-character tails, and non-zero trailing bits. Empty input maps to empty
output. Padded engines require canonical padding when a tail needs padding;
complete four-character groups need no `=`. No-pad engines reject `=` and
accept terminal lengths modulo four of 0, 2, or 3.

| Capability engine | Upstream name | Alphabet tail | Encode | Decode rule |
| --- | --- | --- | --- | --- |
| `B64-ENGINE-STANDARD-PAD` | `STANDARD` | `+/` | padded | canonical padding |
| `B64-ENGINE-STANDARD-NO-PAD` | `STANDARD_NO_PAD` | `+/` | unpadded | no padding |
| `B64-ENGINE-URL-SAFE-PAD` | `URL_SAFE` | `-_` | padded | canonical padding |
| `B64-ENGINE-URL-SAFE-NO-PAD` | `URL_SAFE_NO_PAD` | `-_` | unpadded | no padding |

Owned encode returns a newly allocated `String`. Owned decode returns a newly
allocated `Vec<u8>` and does not publish partial output on error. No direct
destination/slice API is used in the repository census. Encoded length is
`4 * ceil(input_len / 3)` before terminal padding is omitted by no-pad
engines. There is no application-level global input or allocation cap, and
allocation failure is outside the codec's `Result` contract.

The machine artifact freezes RFC 4648 empty, `f`, `fo`, `foo`, and divergent
alphabet vectors, plus whitespace, mixed alphabet, padding, length, and
trailing-bit failures.

## Error contract and version skew

The root `0.23` error variants are:

- `InvalidByte(usize, u8)`
- `InvalidLength(usize)`
- `InvalidLastSymbol { offset, symbol, symbol_value }`
- `InvalidPadding`

The `0.22` boundary represents the last-symbol variant as
`InvalidLastSymbol(usize, u8)`. A5 and A6 must not assume debug shape or display
text is identical across versions.

No public signature exposes `base64::DecodeError`. Callers translate failures
into owned boundaries:

- signed runtime profiles append a verification refusal reason;
- NATS uses `NatsError::InvalidAuth` with field context;
- PostgreSQL SCRAM uses `PgError::AuthenticationFailed`, with salt and server
  signature bounds layered over decode;
- certificate pins use `TlsError::Certificate` and require exactly 32 decoded
  bytes;
- gRPC-Web uses `GrpcError::protocol`; gRPC server metadata uses
  `Status::invalid_argument` with the metadata key;
- WebSocket handshake and extraction collapse syntax and decoded-length failure
  into `HandshakeError::InvalidKey` or a bad-request `ExtractionError`;
- browser storage key decode becomes `Option`, while value decode becomes an
  owned `String` error;
- ATP CLI surfaces command-context errors.

Those mappings are parity requirements. They are not endorsements of the
current wording or proof that every embedding is secure.

## Complete literal census

The pinned snapshot contains 36 Rust paths and 166 literal `base64::` tokens.
The contract rescans `src`, `tests`, `fuzz`, `examples`, `benches`, and
`conformance`, and fails on any path or per-path token-count drift.

| Root | Paths | Literal tokens |
| --- | ---: | ---: |
| `src` | 20 | 89 |
| `tests` | 9 | 19 |
| `fuzz` | 7 | 58 |
| `examples` | 0 | 0 |
| `benches` | 0 | 0 |
| `conformance` | 0 | 0 |

Literal tokens are not dynamic call counts: imports, fully qualified calls,
local modules, and comments produce different ratios. The independently
classified external call-expression census is:

| Class | Encode | Decode | Total |
| --- | ---: | ---: | ---: |
| active production | 23 | 20 | 43 |
| tests, fixtures, fuzz, and reference workspaces | 52 | 28 | 80 |
| all external call expressions | 75 | 48 | 123 |

The exact engine split is:

| Engine | Encode | Decode |
| --- | ---: | ---: |
| `STANDARD` | 57 | 35 |
| `STANDARD_NO_PAD` | 4 | 5 |
| `URL_SAFE` | 0 | 2 |
| `URL_SAFE_NO_PAD` | 14 | 6 |

Two paths named `base64` are local modules, not the dependency:

- `src/observability/otel_conformance_tests.rs` contains a hand-written
  standard encoder.
- `src/real_net_websocket_handshake_http_h1_server_integration_e2e_tests.rs`
  returns a `mock_base64_<len>` marker.

`tests/grpc_server_metadata_bin_encoding_audit.rs` contains one comment-only
token. All three paths stay in the literal census but contribute zero external
calls and cannot serve as parity oracles.

## Production roles

| Surface | Engines | Current acceptance and owned mapping |
| --- | --- | --- |
| signed runtime profile | `STANDARD_NO_PAD` | strict no-pad; decode failure becomes refusal; signature verification rejects empty material |
| NATS credentials | `URL_SAFE_NO_PAD`, then `URL_SAFE` | no-pad encode; decode tries no-pad before padded fallback; `NatsError::InvalidAuth` |
| PostgreSQL SCRAM | `STANDARD` | canonical padded; salt must be 1..=64 bytes and server signature exactly 32 bytes; `PgError::AuthenticationFailed` |
| certificate pins | `STANDARD` | canonical padded and exactly 32 bytes; `TlsError::Certificate` |
| HTTP Basic | `STANDARD` plus a manual encoder | canonical padded origin and proxy credentials |
| WebSocket | `STANDARD` | padded key and accept digest; public validation requires a 16-byte decoded key |
| debug WebSocket | `STANDARD` | padded accept digest, but the local path does not decode and length-check the supplied key |
| gRPC-Web | `STANDARD`, `STANDARD_NO_PAD` | padded one-shot; stream retains quartets and accepts a 2- or 3-character no-pad final tail; `GrpcError::protocol` |
| gRPC server | `STANDARD`, `STANDARD_NO_PAD` | metadata decode tries padded then no-pad; binary metadata/status details encode no-pad |
| browser storage | `URL_SAFE_NO_PAD` | LocalStorage persists namespace, key, and value as URL-safe no-pad text; IndexedDB uses it only for namespace/key and stores values as raw binary; decoded keys must also be UTF-8 |
| ATP CLI | `STANDARD` | delta target manifest and command transport |

The production URL-safe padded engine is decode-only: it is the NATS fallback.
A2 therefore needs an independent `URL_SAFE` encode corpus rather than deriving
parity from production traffic.

## Compilation profiles

The inventory assigns every call path to one of these explicit profiles:

- portable library;
- native messaging;
- native gRPC and gRPC-Web;
- native PostgreSQL;
- wasm32 browser;
- native `atp-cli`;
- embedded and root integration tests;
- legacy internal harnesses;
- feature-gated H3 WebSocket source;
- unwired legacy or nested source;
- standalone RaptorQ differential workspace;
- excluded fuzz workspace;
- local mock or comment-only text.

Unwired sources remain inventory obligations. They do not become executed or
compiled evidence merely because they are source-pinned. One unwired legacy
WebSocket source uses deprecated free functions that remain present in 0.23;
A5 owns its warning-policy and wiring disposition before any attempt to rewire
it.

## Collision-free reservation groups

Digest input is byte-sorted `path<TAB>literal_token_count\n`. Each literal
census path belongs to exactly one group.

| Group | Owner | Paths/tokens | Projection SHA-256 |
| --- | --- | ---: | --- |
| `B64-A3-AUTH` | `asupersync-d24mms.10.3` | 4/30 | `1e0520609721b817965200dd5ff2aa9638741031419bf69ca992af2000a86f7d` |
| `B64-A4-WEB-GRPC` | `asupersync-d24mms.10.4` | 8/41 | `e53d130f142c50c9680c6631f033f9cbc7829c64a93bb8f0c0133589713af824` |
| `B64-A5-REMAINING` | `asupersync-d24mms.10.5` | 24/95 | `c612bc272fed1ae20c15e850f615c54e3b28c8b8a58885f715107f31d4a0093b` |

A2 owns only the scalar kernel, checked sizing, owned error, and four-engine
semantics. A3 owns runtime profile, NATS, PostgreSQL, and TLS pin migration.
A4 owns HTTP, WebSocket, gRPC, and browser persistence migration. A5 owns CLI,
tests, fuzz/reference workspaces, local/mock/comment disposition, dependency
version skew, and authority reconciliation. A6 owns independent journeys and
terminal cutover evaluation.

## Manual and cross-runtime collisions

The literal Rust census is not the entire compatibility surface:

- `src/http/h1/types.rs` has a separate hand-written standard padded HTTP
  Basic encoder.
- `src/messaging/jetstream.rs` and `tests/tls_pin_mismatch_e2e.rs` contain
  hand-written test encoders.
- `packages/browser/src/index.ts` converts through host `btoa`/`atob` and
  URL-safe no-pad text. Host permissiveness is not a Rust parity authority;
  A6 must pin canonical re-encode behavior.
- `scripts/capture_baseline.sh` invokes a host decoder whose whitespace and
  trailing-data behavior is platform-defined for this purpose. It is an
  operational input, not parity evidence.

## Routed gaps

The machine artifact routes every observed gap; none is left unowned:

- A2: checked global sizing/allocation policy and the explicit no-constant-time
  boundary.
- A3: credential/certificate migration and the URL-safe padded decode-only
  production surface.
- A4: the duplicate HTTP encoder, gRPC stream buffering bound, and debug
  WebSocket key validation difference.
- A5: incomplete registry source/profile ownership, `0.22`/`0.23` skew, host
  tool semantics, unwired sources, and remaining fixtures.
- A6: the partial baseline, browser canonicalization, rejection of local mocks
  as oracles, independent protocol journeys, and cutover decision.

The existing registry baseline is `EXECUTABLE_PARTIAL_BLOCKING` and names only
the `consumer-default` downstream profile. It does not cover the complete
four-engine and protocol portfolio. The verification matrix remains
`BLOCKED_PENDING_EVIDENCE` for A1 through A6; this inventory does not promote
those rows.

## Static contract and no-claim boundary

`tests/base64_capability_inventory_contract.rs` is a fail-closed static
contract for artifact structure, zero `UNKNOWN` values, source hashes and line
counts, the literal census, call totals, engine/profile/group ownership,
governance-source state, documentation markers, and the `.gitignore`
exception. It deliberately performs no external process, network, timing, or
environment-dependent work.

For this A1 tranche, that contract was written but **not executed**. Static
JSON parsing, digest recomputation, literal recounting, and Git diff checks are
not behavioral execution evidence.

This packet does not prove compilation, runtime correctness, protocol or
authentication security, certificate or framing security, constant-time
behavior, bounded memory, denial-of-service resistance, throughput, wasm
parity, cross-version parity, release readiness, tracker closure, or permission
to remove the dependency. Only A6 may attach independently reproduced journey
evidence and evaluate cutover eligibility.

<!-- END BASE64 CAPABILITY INVENTORY -->
