# UTC and RFC3339 capability inventory

<!-- BEGIN TIME UTC CAPABILITY INVENTORY -->

This is the operator-readable companion to
`artifacts/time_utc_capability_inventory_v1.json`. It freezes the static A1
source inventory for `asupersync-5z2scg.6.1` and
`CAP-TIME-UTC-RFC3339` at revision
`1afde84d564bd8ea876459624116f90028b80835`.

The governing `DEP-ADR-011` decision remains additive coexistence:
`PRESERVE_AND_REPLACE_IF_PARITY`, `BLOCKED_PENDING_EVIDENCE`, and
`dependency_exit_allowed=false`. This inventory changes none of those states.
It classifies source and routes evidence work; it is not a cutover packet.
The A1 bead's full A1 acceptance remains unmet: the result is a
partial static inventory with seven behavioral evidence gaps and one bounded
derived-consumer remainder, and the bead must not be closed from this artifact.

## Pinned static result

Seven facts at the pinned revision supersede stale counts in the ADR and global
registry without mutating those shared authorities:

1. A bounded lexical scan of production source finds zero external
   `time`-crate imports or known `OffsetDateTime`/format-description call
   shapes. The CLI uses `asupersync::time::format_unix_nanos_rfc3339`; the
   remaining direct source use is the prior foundation contract's differential
   oracle. This is not compiler-resolved name analysis.
2. The root crate exposes 12 concrete Chrono UTC fields across nine
   serde-derived structs and three modules, not ten fields.
3. ATP workflows read and write four timestamp-bearing JSON families—CI,
   dataset, release, and archive metadata—not three.
4. The repository has three owned UTC emitters: the shared nonnegative-epoch
   formatter, ATP logging's seconds formatter, and JetStream's signed
   nanosecond formatter.
5. The release-proof aggregator also owns a private parser for Agent Mail
   timestamp strings, so the ADR's claim that nothing owned parses RFC3339 is
   no longer true.
6. Four files directly import Chrono symbols. Those bindings account for 32
   alias-bearing code lines and 45 imported-symbol occurrences. One line also
   contains a literal Chrono namespace reference; the other three formerly
   reported overlaps have their literal `chrono::Duration` call on the
   preceding line. The corrected literal-or-alias union is therefore 190
   unique lines.
7. Thirty-eight declared in-file consumer anchors across six categories link
   to 40 unique direct source anchors. Together with eight imported-alias
   anchors, the artifact freezes 46 derived anchors and 236 classified
   direct-plus-derived anchors. This is a source-linked static count, not
   runtime coverage.

The direct `time` edge remains present under `cli`, and Chrono remains present
under `cli`, `benchmark-adapters`, dev targets, the conformance member, and
separate test-tool workspaces. Static source absence is not permission to
remove either dependency.

## Cargo and crate profiles

The artifact separates direct manifest edges, transitive locked packages, and
source presence. Those are different claims.

| Profile | Chrono relationship | `time` relationship | Classification |
| --- | --- | --- | --- |
| root default | no | no | manifest-static default features |
| `cli` | yes | yes | opt-in production types plus prior oracle |
| `benchmark-adapters` | yes | no | opt-in public benchmark models |
| offline-tuner binary | yes | yes | explicit `cli` + `simd-intrinsics` target |
| `tls` | no | transitive | locked through X.509 crates |
| `tls-native-roots` | no | transitive | implies `tls` |
| `tls-webpki-roots` | no | transitive | implies `tls` |
| `atp-cli` | no | transitive | implies `tls`; distinct from `cli` |
| `atpd-daemon` | yes | yes | implies `cli` |
| `ci-cross-platform` | direct | direct + transitive | umbrella includes `cli` and `tls` |
| root dev targets | yes | no | library tests, integration tests, benches |
| root conformance member | yes | no | conformance library and binaries |
| excluded fuzz workspace root | transitively | transitively | through root `benchmark-adapters` and `tls` features |
| excluded conformance workspace | yes | no | separate workspace source |
| standalone golden workspace | yes | no | nested test tool |
| standalone reporting workspace | yes | no | nested test tool |

The root lock snapshot contains Chrono `0.4.45` and `time` `0.3.54`. Chrono's
direct locked dependers are the root crate and the conformance member. The
`time` package is directly retained by the root crate, `asn1-rs`, and
`x509-parser`. Lock membership does not prove activation of a profile.

The `cli` module is public only with the `cli` feature and that feature is
explicitly rejected for wasm. `atp::benchmark` is public only with
`benchmark-adapters`. The owned `asupersync::time` module is unconditional and
contains no external Chrono or `time` API.

## Literal and alias-aware Chrono source census

The workspace-filesystem census is 159 Rust source lines containing a literal
Chrono namespace reference across 71 paths. It recursively scans every Rust
file under its five roots, including untracked files. The machine artifact
freezes every matching path and per-path matching-line count.

| Classification | Paths | Matching lines | Later migration group |
| --- | ---: | ---: | --- |
| production CLI | 2 | 15 | CLI public and persisted |
| production benchmark module | 2 | 5 | benchmark reports |
| root benchmark | 1 | 2 | benchmark reports |
| database and messaging test regions | 2 | 8 | database/messaging oracles |
| root real-E2E source corpus | 21 | 51 | downstream corpus |
| root integration source corpus | 8 | 23 | downstream corpus |
| conformance workspace member | 22 | 31 | conformance tools |
| wired conformance RaptorQ reporting | 3 | 7 | conformance tools |
| excluded conformance workspace | 1 | 2 | conformance tools |
| standalone golden workspace | 2 | 4 | conformance tools |
| standalone reporting workspace | 7 | 11 | conformance tools |

The direct-import companion inventory finds four binding paths, 32
alias-bearing code lines, and 45 imported-symbol occurrences. Only workflow
line 236 contains both an imported `Utc` reference and a literal
`chrono::Duration` reference. The alias scan therefore exposes 31 additional
lines beyond the literal census and reconciles to 190 unique literal-or-alias
lines. Every direct import binding and direct imported-symbol reference is
enumerated with its profile, wiring, operation, exposure, association,
migration group, and owner. No `use chrono as ...`, `extern crate chrono`,
Chrono-backed type alias, or renamed Chrono import was found in the bounded
five-root scan.

The 159-line table remains a textual namespace projection, not a dynamic call
count or activated feature graph. Thirteen ordered literal-operation rules
classify every literal line with no remainder. Twenty-two exact path sets map
all 71 paths to a profile, migration group, wiring state, exposure, and owner;
36 line-specific overrides preserve composite operations, private `cfg(test)`
fixtures, public-field nuances, and database or wire associations. The four
direct bindings, 32 direct alias rows, one same-line overlap, and eight
imported-alias arithmetic, comparison, association, or ordering anchors are
also exact.

The declared downstream tranche now freezes 38 exact rows across CLI
cutoff/expiry handling, PostgreSQL and Kafka arithmetic, JetStream wire
insertion, real-E2E serialization/retention/return/embedding, conformance
field association and rendering, and standalone fixture serialization,
template association, and result retention. Every row names its direct source
anchor and stops at the declared first semantic boundary. The remaining static
gap is narrower but real: cross-file consumers outside Chrono-bearing paths,
external consumers absent from this snapshot, and later container or
arbitrary-byte propagation are not enumerated. A1's zero-unclassified-use
acceptance remains unmet and the bead stays open.

Most `src/real_*` files in the census are dormant source rather than declared
modules. The Chrono-bearing H3 server/websocket suite is feature-wired. In the
eight-path root integration group, only codec framing is dormant; HPACK,
gRPC/HTTP2, RFC6330, JetStream, and Kafka paths are statically wired as recorded
per path in the artifact. A filename or wiring marker is not execution
evidence.

## Root public API

At the pinned revision, the root Chrono-backed surface is 12 fields across nine
structs.

| Feature | Public struct | Fields | Exposure |
| --- | --- | --- | --- |
| `cli` | `AtpStatusOutput` | `timestamp` | public serde model; no in-tree producer found |
| `cli` | `AtpBenchSystemInfo` | `timestamp` | public serde model; no in-tree producer found |
| `cli` | `AtpCiArtifact` | `timestamp`, `expires_at` | re-exported and persisted |
| `cli` | `AtpDatasetInfo` | `updated_at` | re-exported and persisted |
| `cli` | `AtpReleaseInfo` | `published_at` | re-exported and persisted |
| `cli` | `AtpArchiveEntry` | `archived_at`, `expires_at`, `last_verified_at` | re-exported and persisted |
| `cli` | `AtpIntegrityStatus` | `last_check_at` | re-exported JSON output |
| `benchmark-adapters` | `BenchmarkEnvironment` | `timestamp` | public serde model |
| `benchmark-adapters` | `BenchmarkReport` | `timestamp` | public re-export and serde model |

All 12 are concrete Chrono UTC datetime fields in serde-derived containers.
Three are optional: CI `expires_at`, archive `expires_at`, and archive
`last_verified_at`. With no `skip_serializing_if`, `None` emits an explicit
JSON `null`; both an explicit `null` and a missing field deserialize to `None`.
Neither form may silently become an epoch sentinel.

The root API map is a crate-root export scan, not rustdoc output. Even a valid
semantic hash cannot make it see these nested fields or the nested owned
formatter. It is not completeness evidence for this surface.

## Conformance public reports

The root workspace's conformance member has a separate public Chrono-backed
timestamp surface:

- six serde report fields use concrete Chrono UTC datetime types;
- eleven serialized report fields use `String` populated by Chrono's RFC3339
  rendering;
- associated binaries pretty-serialize reports and may write them to files.

The six typed reports are data-end-stream, GOAWAY, PING, PRIORITY, SETTINGS,
and HPACK. Seven string reports are HTTP/1 expect-continue, HTTP/1 request,
HTTP/1 response, HTTP/2 ENABLE_PUSH, HTTP/2 CONNECT, HTTP/2 CONTINUATION, and
the HPACK encoder. Four more publicly wired RaptorQ reporting fields cover
reference-version update text, coverage generation, conformance-record time,
and history update time.

This yields 17 public Chrono-backed timestamp fields in addition to the root
crate's 12. The RaptorQ reporting subtree is publicly wired by the conformance
library; it is not legacy or dormant. A separate excluded conformance
workspace adds one public `ConformanceReport.timestamp` string generated by
Chrono, bringing the two primary arrays to 30 public Chrono-backed fields.

The first seven Chrono-generated string report types derive `Serialize` only.
The four wired RaptorQ models and the excluded PING report also derive
`Deserialize`; those five fields deserialize as plain, unvalidated `String`
values. The wired history store additionally compares record timestamps
lexicographically in `records_since`, not as parsed instants. Introducing
validation or instant ordering would therefore be a behavior change, not a
transparent dependency swap.

The conformance member also exposes non-Chrono temporal contracts:
`TestExecution.timestamp` and `CoverageMatrix.generated_at` use `SystemTime`,
while JSONL `ConformanceLogEntry.timestamp` is a decimal whole-second Unix
string with pre-epoch failure defaulted to zero. Those rows are inventoried as
distinct surfaces and are not included in the 17-field Chrono-backed subtotal.

Seven more concrete datetime fields belong to root or standalone test
profiles: five publicly reachable test-tool fields, one `pub` field inside a
private root integration-test module, and one private serialized golden-fixture
field. `MetadataSummary.last_updated` is optional. These are migration
obligations, not root library API.

## Persisted and output bytes

Seven of the root crate's 12 fields participate in four ATP workflow stores.

| Store | Path shape | Type | Timestamp fields | Read/write status |
| --- | --- | --- | --- | --- |
| CI | `ci/index/{build}-{hash}.json` | `AtpCiArtifact` | `timestamp`, `expires_at` | pretty JSON read/write |
| dataset | `datasets/{id}-{version}.json` | `AtpDatasetInfo` | `updated_at` | pretty JSON read/write |
| release | `releases/{channel}-{version}.json` | `AtpReleaseInfo` | `published_at` | pretty JSON read/write |
| archive | `archives/{id}/metadata.json` | `AtpArchiveEntry` | `archived_at`, `expires_at`, `last_verified_at` | pretty JSON read/write |

`AtpWorkflowCoordinator` is a public, re-exported library surface. Workflow
and dogfood tests exercise these families and inspect non-temporal fields, but
the static audit found no timestamp roundtrip assertion, historical readback
corpus, or timestamp-sensitive byte golden. The main binary also has a
separate private status model, so public library reachability must not be
misstated as proven binary reachability.

All four workflow records also flow through JSON, pretty, and stream CLI output
modes. Their human and TSV renderings omit timestamp fields. That output
surface is distinct from the four on-disk read/write families and inherits the
same missing timestamp-sensitive golden.

Of the remaining root fields, `AtpIntegrityStatus.last_check_at` is produced
inside archive output. No in-tree producer was found for `AtpStatusOutput` or
`AtpBenchSystemInfo`; they remain public serde models rather than proven output
journeys. `BenchmarkReport` is returned to callers and is serde-capable, but no
in-tree file writer for that type was found. Public serializability still makes
its representation a consumer contract.

The wired conformance RaptorQ reporter has a fifth explicit read/write store:
`ConformanceHistory::load_from_file` and `save_to_file` round-trip pretty JSON
containing `ConformanceHistory.last_updated` and nested
`ConformanceRecord.timestamp`. Deserialization accepts arbitrary strings and
`records_since` uses lexical comparison. Its accepted bytes remain unpinned.
`ReferenceVersion.last_updated` is a public serde field but the pinned private
fixture-version metadata deliberately excludes it.

Additional output and persistence consumers are separate from those five
pretty-JSON stores:

- trace files persist raw `recorded_at: u64` nanoseconds; CLI trace info maps
  nonzero values through the owned UTC formatter and maps zero to
  `created_at: null` in compact JSON while omitting the human `Created:` line;
- ATP event JSON uses an owned whole-second UTC string and has a pinned JSONL
  golden, though A1 did not execute it;
- JetStream writes caller-supplied signed `SystemTime` as the
  `opt_start_time` wire field with exactly nine fractional digits;
- RaptorQ benchmark stderr events use Chrono-rendered millisecond UTC text;
- offline tuning uses either `t_ns=<logical nanos>` from an injected/fallback
  `Time` or Debug-formatted ambient `SystemTime`, neither of which is RFC3339;
- the excluded conformance PING report serializes its public timestamp string
  to JSON or text without validating it on read.

Standalone golden/reporting tools add fixture and report metadata generated
from ambient UTC plus filesystem-modified-time conversion. Their source fields
are classified, but exact artifact bytes were not established by A1.

## Frozen operational semantics

The inventory records source behavior at the pinned revision without endorsing
it:

- ATP workflows acquire ambient `Utc::now()` directly.
- CI publish writes `expires_at: null` on retention parse failure, but maps
  failed standard-duration conversion to zero, so that expiry equals its
  acquisition instant.
- CI clean disables its age cutoff on parse or conversion failure and may
  select every otherwise-matching artifact; CI list similarly disables its
  recent cutoff.
- archive retention parse or standard-duration conversion failure writes
  `expires_at: null`.
- the four stores use generic whole-file serde JSON reads and direct pretty
  JSON writes.
- default archive IDs include Unix seconds from the ambient UTC clock.
- benchmark environment and report constructors acquire ambient UTC directly.
- public serde range, accepted offsets, fractional rendering, parse errors,
  and exact bytes are dependency-defined today and are not yet independently
  frozen.

The ADR says duration conversion failures should remain explicit. These
zero-default, cutoff-disable, and null policies do not prove that invariant;
A4 owns the decision and migration behavior.

## Owned time boundaries

`asupersync::time::format_unix_nanos_rfc3339(u64) -> String` is render-only. It
reads no clock, parses no text, and owns no scheduling behavior. Its prior
foundation artifact is limited to nonnegative Unix nanoseconds, years
1970–2554, uppercase `Z`, and trimmed nonzero fractional digits.

That prior artifact belongs to `asupersync-d24mms.4`. It does not cover
negative instants, numeric offsets, parsing, timezone rules, leap seconds,
serde, public Chrono fields, persisted documents, or dependency removal. No
prior receipt was treated as fresh A1 execution.

The release-proof aggregator has a separate private owned parser used for
Agent Mail reservation and evidence timestamps. It trims input; accepts `T`
with `Z` or signed `HH:MM` offsets; discards everything after the first dot in
the seconds component without validating that suffix; permits second 60;
bounds month/day independently rather than validating every calendar date;
rejects negative Unix results; and reports failure as `None`. Invalid
month/day combinations may normalize through its civil conversion. This is a
source-frozen compatibility obligation, not proof of RFC3339 conformance.

Two protocol-specific owned emitters remain separate:

- ATP logging takes `SystemTime`, clamps pre-epoch input to zero, and emits
  second precision.
- JetStream takes signed pre/post-epoch `SystemTime` and emits exactly nine
  fractional digits for its wire field.

Their differing semantics must be preserved or deliberately revised; “three
owned emitters” does not mean they are interchangeable.

Scheduling, monotone, virtual, and logical `Time` remain separate from UTC
calendar semantics. Likewise, the cross-referenced `SystemTime`, logical
`Time`, epoch-integer, and `Duration`/TTL schemas are illustrative boundaries,
not a repository-wide inventory of every temporal value. This is an explicit
scope boundary, not an unresolved detail in the dependency capability census.

The prior foundation doc also overstates zero-timestamp output. Human output
omits the `Created:` line, while compact JSON serializes `"created_at": null`.
A1 routes that documentation correction back to the foundation owner and does
not alter the earlier files.

## Database, Redis, and tests

Production PostgreSQL DATE, TIMESTAMP, and INTERVAL decoding is already owned.
Chrono independently constructs expected DATE and TIMESTAMP text in the test
region. The INTERVAL expected value reuses the same owned
`render_interval_text` helper, so it is not an independent Chrono oracle.
Removing the dev dependency would still discard the DATE/TIMESTAMP comparison
evidence and is not authorized.

Direct Chrono calls in the Redis module are also test-only diagnostics. The
simulated Redis durability source uses millisecond and string records; it is
not proof of real Redis or RDB temporal behavior.

The exact text of all 159 literal source lines, their operation projection,
path routing, line-specific overrides, direct alias binding/reference
discovery, eight imported-alias anchors, and 38 declared source-linked
downstream anchors are frozen in the artifact. The downstream boundary admits
the first semantic compare, arithmetic, format, serialization, persistence,
retention, return, extraction, or embedding consumer in a Chrono-bearing path.
Cross-file propagation, external consumers, and later container or
arbitrary-byte taint remain the declared static gap.
Later owners must prove each admitted profile separately rather than borrowing
a green result from another crate or feature set.

## Migration ownership

| Child | Frozen responsibility |
| --- | --- |
| A2 | owned UTC/calendar/duration/clock core, release-proof parser instant conversion, and leap-second no-claim |
| A3 | RFC3339 parse/format, release-proof parser grammar parity, offsets, fractions, serde, errors, optional absence, historical bytes |
| A4 | ten CLI fields, four workflow stores, arithmetic, fixed-clock journeys, migration reads |
| A5 | two Chrono-backed benchmark fields, stderr event text, report serialization, logical/SystemTime offline metadata |
| A6 | PostgreSQL oracle retention, Redis test-only disposition, and implementation ownership of the two database/messaging real-E2E source paths |
| A7 | aggregate evidence for those A6 paths plus other root tests, historical corpus, consumers, wired and standalone conformance surfaces, sparse profiles, and cross-platform evidence |
| A8 | locked graph, oracle disposition, rollback, and terminal keep-or-cutover decision |

Only A8 can authorize dependency exit. A1's path groups are collision-free
inputs to those later reservations; they are not edit authorization by
themselves.

## Reconciliation gaps

The artifact routes, without mutating shared authority files:

- incomplete registry source owners;
- the stale ten-field, three-store, one-call, and two-emitter counts;
- a missing `benchmark-adapters` capability mapping;
- a baseline whose named fixture and claims exceed its historical vector;
- a root-only API map used beyond its visibility;
- workflow tests that exist but omit temporal assertions;
- unregistered planned scenario identifiers;
- the foundation doc's JSON-null mismatch;
- the ADR's stale claim that no owned RFC3339-like parser exists.

Every reconciliation row has an explicit owner and
`ROUTED_NOT_MUTATED_BY_A1` state. There are no unclassified literal Chrono
paths or undiscovered direct Chrono import bindings in the pinned census, but
derived-consumer coverage beyond the 38 declared in-file rows remains partial.

## Validation and no-claim boundary

A1 used workspace-filesystem source search, direct-import reconciliation,
manifest and authority inspection, SHA-256 source pins, path/count and
literal-operation, literal-source, and derived-row projections, and independent
static cross-review. It did not execute the companion contract. This remains a
partial static inventory only; full A1
acceptance is unmet,
`bead_close_allowed=false`, and the bead must not be closed from this packet.

No compiler, formatter, test, benchmark, service, remote job, or runtime lane
was run. This inventory therefore does not prove runtime formatting or parsing,
calendar correctness, serde bytes, historical readback, database or messaging
behavior, deterministic clocks, malformed-input bounds, downstream builds,
cross-platform support, performance, broad workspace health, release
readiness, dependency removal, tracker closure, or permission to delete files.

<!-- END TIME UTC CAPABILITY INVENTORY -->
