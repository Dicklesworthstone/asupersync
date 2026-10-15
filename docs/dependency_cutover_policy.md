# Dependency cutover policy

Bead: `asupersync-dep-p1-foundations-upksjk.5.3`

Canonical artifact:
`artifacts/dependency_cutover_policy_v1.json`

Focused contract:
`tests/dependency_cutover_policy_contract.rs`

Replayable runner:
`scripts/run_dependency_cutover_policy.sh`

## Outcome

Dependency sovereignty may change how asupersync implements a capability. It
may not make asupersync a smaller, less interoperable, less portable, less
safe, less observable, or harder-to-use product.

The universal rule is:

> A dependency may exit only after every affected stable capability is
> demonstrably SAME or BETTER across its complete observable contract, the
> replacement has a rehearsed rollback, and the production switch follows the
> serialized state machine. Otherwise the incumbent stays.

Package exit and capability exit are different decisions. This program
authorizes only the former. An implementation campaign cannot manufacture
parity by deleting a feature, narrowing a generic API, rejecting an accepted
format, dropping a platform, removing an interoperability mode, hiding an
error, weakening cancellation or resource behavior, or declaring an
unavailable test green.

## Source contracts

CAP A3 joins, rather than duplicates, five already checked sources:

| Source | What it owns |
|---|---|
| `artifacts/dependency_safety_taxonomy_v1.json` | Replacement eligibility, unsafe category, review sensitivity, and exception gates. |
| `artifacts/dependency_marginal_ledger_v1.json` | Package-ID marginal cost, target/profile graphs, native evidence, and counterfactual method. |
| `artifacts/dependency_oracle_policy_v1.json` | Differential-oracle class, graph placement, reverse-cycle policy, native quarantine, expiry, and retirement. |
| `artifacts/dependency_capability_registry_v1.json` | The 50 stable capability IDs, current owners, public/user surface, scenarios, and no-loss boundaries. |
| `artifacts/dependency_capability_baseline_v1.json` | Incumbent evidence, required case classes, parity modes, standalone consumers, and typed gaps. |

The policy contract joins these artifacts by stable ID. Drift, a missing row,
or a cutover state that disagrees with the registry fails closed.

## Terminal verdicts

The campaign outcome is not forced to be `REPLACE`. That would reward
overclaiming and pressure agents to weaken acceptance criteria.

| Verdict | Campaign may close? | Production switch? | Incumbent |
|---|---:|---:|---|
| `REPLACE` | Yes | Only after every gate and the serialized transition | Leaves the production graph only after the observation and dependency-exit stages |
| `KEEP` | Yes | No | Remains because it is the best current safety, completeness, maintenance, performance, or interoperability choice |
| `DEFER` | Yes | No | Remains while named hardware, platform, service, upstream, or owner evidence is unavailable |
| `BLOCKED` | No | No | Remains while a required decision or contradiction is unresolved |

`KEEP` and `DEFER` are successful engineering outcomes. They protect users
from a replacement whose package-count story is better than its product
behavior. `BLOCKED` is an explicit non-green state and cannot be counted as
completion.

Every verdict records:

- the exact candidate and affected capability IDs;
- a substantive decision reason;
- the source revision and evidence timestamp;
- resume conditions for `DEFER`;
- blocking owners for `BLOCKED`;
- whether a production switch or campaign close was requested;
- the incumbent action; and
- at least three machine-readable no-claim boundaries.

## Parity and evidence are not interchangeable

Parity results describe the behavior being compared:

- `BETTER` and `SAME` may advance a replacement;
- `WORSE` and `UNKNOWN` block it; and
- `NOT_APPLICABLE` is permitted only for a property that genuinely has no
  operation and has a reviewed reason. It does not replace required evidence.

Evidence outcomes describe what happened when a gate ran:

- only `PASS` is green;
- `FAIL`, `BLOCKED_EXTERNAL`, `BLOCKED_PLATFORM`, `BLOCKED_OWNER`,
  `UNSUPPORTED`, and `NO_WIN` do not advance a required gate;
- zero tests, silent skips, local Cargo fallback in a remote-required lane, or
  stale evidence are not `PASS`; and
- `NO_WIN` on an evidence-gated performance candidate maps to `KEEP`.

CAP A2 defines ten separate parity modes. Exact wire or persisted bytes,
semantic behavior, downstream compilation, public errors, security policy,
resource envelopes, lifecycle, platform matrices, service interoperability,
and operator UX are never collapsed into a single “tests passed” flag.

## Gate stack

All replacement candidates pass twelve global gates:

1. `GATE-CAPABILITY-MAP`
2. `GATE-BASELINE-FRESHNESS`
3. `GATE-SAFETY`
4. `GATE-MARGINAL-GRAPH`
5. `GATE-UNIT-INVARIANTS`
6. `GATE-DOWNSTREAM`
7. `GATE-E2E`
8. `GATE-ORACLE`
9. `GATE-ROLLBACK`
10. `GATE-UX-DOCS`
11. `GATE-OWNER`
12. `GATE-FINAL-NO-LOSS`

The candidate's migration class then adds the relevant gates:

| Class | Additional gates |
|---|---|
| `GUARD_ONLY` | None; the guard is continuously enforced and cannot itself be cut over |
| `SOURCE_API` | Public compile and downstream generic behavior |
| `STATELESS_SEMANTIC` | The global differential, boundary, malformed, resource, and rollback gates |
| `STATEFUL_RUNTIME` | The global lifecycle, cancellation, recovery, leak, quiescence, and resource gates |
| `VERSIONED_DATA` | Migration and versioned compatibility |
| `CONFIG_LANGUAGE` | Public compile plus migration and data-preservation review |
| `WIRE_PROTOCOL` | Migration, negotiation, independent peers, and rollback decode |
| `SERVICE_INTEROP` | Pinned real-service matrix |
| `SECURITY_SENSITIVE` | Public compile plus independent security review |
| `CLI_OPERATOR` | Public/installed consumer behavior and complete operator UX |
| `DOWNSTREAM_RELOCATION` | Migration, real-service parity, and cycle-safe neutral/downstream harness |
| `PLATFORM_BOUNDARY` | Supported platform matrix |
| `CONCURRENCY_PERFORMANCE` | Platform/CPU matrix and complete performance envelope |
| `VERIFICATION_INFRASTRUCTURE` | Proof-integrity, failure-injection, replay, provenance, redaction, and cleanup |
| `OPERATOR_UX` | Stable diagnostics, structured fields, privacy, and recovery guidance |

Every required gate advances only on `PASS`. A class can add gates; it cannot
waive a global one.

### Required unit and risk-selected evidence

`GATE-UNIT-INVARIANTS` covers the smallest meaningful implementation surface
first:

- normal behavior;
- empty, minimum, maximum, Unicode, binary, overflow, and other boundaries;
- malformed input and stable public errors;
- panic containment where relevant;
- cancellation, race, shutdown, drain, leak, and quiescence;
- recovery, retry, reuse, restart, and rollback; and
- property, differential, fuzz, independent-vector, deterministic-lab, model,
  DPOR, or performance evidence selected by the safety and capability tags.

A source change without its narrow invariant proof is not ready for broader
E2E validation.

### Required downstream and UX evidence

Known in-repo call sites are not the boundary of a public library. The
downstream gate includes:

- the standalone exact-version consumers without `test-internals`;
- arbitrary downstream Serde, Protobuf, Stream, exporter/provider, Service,
  parser, and other generic implementations;
- sparse features and supported targets;
- the known `/dp` consumer portfolio when authoritative access exists;
- public names, bounds, traits, errors, and feature combinations;
- installation, help, examples, config, diagnostics, recovery, and rollback
  documentation; and
- typed `BLOCKED_EXTERNAL` evidence when a consumer cannot be accessed.

“No known consumer” never means “safe to delete.”

## Serialized state machine

The state machine deliberately separates implementation work, evidence,
production ownership, and package exit:

```text
INCUMBENT_PRIMARY
        |
        v
PROTOTYPE_ISOLATED -> SHADOW -> COEXISTENCE -> CUTOVER_CANDIDATE
                                                       |
                                                       v
                                             REPLACEMENT_PRIMARY
                                               |             |
                                      rollback |             | observation
                                               v             v
                                        ROLLBACK_ACTIVE  DEPENDENCY_EXIT_PENDING
                                               |             |
                                               v             v
                                      INCUMBENT_RESTORED  DEPENDENCY_EXITED
                                               |               |
                                               |               +----> ROLLBACK_ACTIVE
                                               +----> PROTOTYPE_ISOLATED
```

There is no direct transition from the incumbent, prototype, shadow, or
coexistence states to `REPLACEMENT_PRIMARY`. There is no direct transition
from `REPLACEMENT_PRIMARY` to `DEPENDENCY_EXITED`.

The production switch occurs only at:

- `CUTOVER_CANDIDATE -> REPLACEMENT_PRIMARY`; or
- `ROLLBACK_ACTIVE -> INCUMBENT_RESTORED`.

`REPLACEMENT_PRIMARY` is an observation state, not permission to remove the
package immediately. Dependency exit waits for a second graph, oracle,
rollback, and no-loss audit. Exit is not a point of no return:
`DEPENDENCY_EXITED -> ROLLBACK_ACTIVE` remains available if a post-exit
correctness, security, interoperability, data-integrity, resource, or
operator-UX trigger fires. The rollback then restores the exact recorded
incumbent revision and compatible state through the same verified
`ROLLBACK_ACTIVE -> INCUMBENT_RESTORED` path.

## Coexistence requirements

Every candidate decision records:

- coexistence mode;
- whether the incumbent remains primary;
- deterministic input selection;
- exact and semantic output comparison;
- side-effect isolation;
- resource budget;
- cancellation and cleanup behavior;
- observation window;
- promotion criteria; and
- rollback trigger.

The shape varies by migration class:

- stateless helpers run a differential corpus;
- runtime state uses deterministic model or shadow comparison with isolated
  ownership;
- persisted data dual-reads every accepted version;
- config migrations preserve originals and enumerate presentation and semantic
  effects;
- wire protocols negotiate or dual-decode;
- services shadow or dual-run against pinned real versions;
- platform backends remain independently selectable;
- concurrency/performance candidates remain non-default canaries;
- CLI parsers run old and candidate installed binaries over the same corpus;
  and
- reverse dependencies run only downstream or in a neutral consumer.

## Rollback is mandatory

Even a stateless manifest cutover needs rollback. Every `REPLACE` receipt
contains all of:

- exact pre-cutover 40-hex source revision;
- exact pre-cutover lockfile digest;
- correctness, security, compatibility, unsupported-surface, data-integrity,
  cancellation/leak, resource, tail-latency, and UX trigger thresholds;
- candidate-era artifact compatibility or a proven lossless reverse migrator;
- deterministic incumbent restoration steps;
- state reconciliation and drain;
- zero-residual task, process, handle, obligation, partial-write, and secret
  assertions;
- an RCH-wrapped verification command;
- operator owner and measured recovery-time bound; and
- a retained rehearsal receipt.

Rollback never deletes failed evidence or user data. A restored incumbent is
not considered healthy until its focused unit, downstream, lifecycle, and E2E
checks pass.

## Stateful and durable compatibility is not a shim

The project does not retain deprecated source-level compatibility wrappers.
That rule does not apply to product data:

- persisted traces and snapshots need versioned readers;
- candidate-era artifacts must survive rollback;
- TOML and YAML remain readable during migration;
- old user-authored files remain untouched;
- wire versions remain accepted for the declared protocol window;
- credentials and authentication forms remain valid;
- database state remains recoverable; and
- official downstream integration remains available.

A reader or reversible migrator for accepted durable inputs is real product
functionality, not technical debt.

## Special cases that must not regress

### Generic Serde, Protobuf, and regex surfaces

Arbitrary downstream types and accepted pattern syntax cannot be replaced by
a finite in-repo set. The incumbent stays until the generic surface is
preserved. A separate explicit product-scope decision may redesign an API, but
a dependency-removal bead cannot silently make that decision.

### TOML, YAML, and JSON

Migration is dual-read and non-destructive. Each affected file gets:

- semantic before/after goldens;
- comments, anchors, aliases, scalar distinctions, unknown fields, defaults,
  and precedence review;
- deterministic conversion output;
- preservation of the original;
- manual corpus review; and
- explicit written owner permission before any deletion.

### FrankenSQLite

FrankenSQLite already depends on asupersync, so adding it to this workspace
would create a reverse package cycle. Parity belongs in FrankenSQLite or a
neutral synthesized consumer with an independent lockfile.

The official downstream adapter, complete semantic parity, combined-graph
budget, documented user path, data compatibility, and rollback must exist
before asupersync's incumbent path changes. An unofficial workaround or a
smaller asupersync-only graph is not parity.

### Kafka

Kafka capability is retained regardless of whether the current downstream
inventory finds a consumer. `rdkafka` stays until the strictly safe native
client covers API negotiation, record batches, metadata, produce/fetch,
groups, rebalance, offsets, idempotence, transactions, isolation,
compression, TLS/SASL, faults, retry, cancellation, shutdown, performance,
pinned brokers, downstream consumers, and rollback.

### OTLP

The surface includes metrics, traces, logs, external SDK/provider/exporter
integration, collector interoperability, bounded `Cx` export, failures,
shutdown, backpressure, and the default/metrics no-Tokio guarantee. Implementing
only metrics or only owned internal types is not parity.

### Brotli and compression

Brotli is a current HTTP and ATP manifest capability. gzip or DEFLATE cannot
stand in for it. Negotiation, streaming, malformed input, bombs, cancellation,
cross-implementation bytes, and historical ATP artifacts remain gated.

### TLS and X.509

The strategy is delegate-first: rustls/webpki continues to own standard chain,
name, and EKU validation. Only demonstrably non-delegable residue may become
owned code. The security gate covers canonical DER, full input consumption,
ASN.1 time, KU/EKU, BasicConstraints, SAN, SPKI pinning, duplicate and critical
extensions, depth/resource caps, exact error mapping, independent vectors,
fuzzing, and real handshake behavior.

### Platforms

Linux evidence cannot stand in for macOS, Windows, BSD, browsers, kqueue,
IOCP, Windows control events, xattr namespaces, filesystem permission
semantics, containers/cgroups, or host metadata fields. Unsupported required
cells yield `BLOCKED_PLATFORM` or `DEFER`, never a reduced production feature.

### Concurrency and performance

Correctness alone does not justify replacing mature primitives. The complete
gate includes throughput, p50/p95/p99/p999, fairness and maximum starvation,
cancellation latency, allocations, RSS, cache traffic, compile time, binary
size, 1/8/32/64-core scaling, Apple Silicon, representative Intel and AMD
families, stable-lane behavior, weak-memory/model evidence, and deterministic
outputs. `NO_WIN` means `KEEP`.

### CLI and operator workflows

The parser surface is larger than argv tokenization. It includes all four
binaries, commands, aliases, options, environment variables, `OsString` and
invalid UTF-8, `--`, short clusters, negative values, custom parsers, defaults,
value delimiters/enums, help, errors, exit codes, config, traces, transfer,
daemon lifecycle, tuning reports, accessibility, pipes, terminal widths,
installation, interruption, partial-output rules, and recovery.

## Decision receipt

The machine contract requires a complete receipt with:

- candidate, capability IDs, verdict, reason, resume conditions, blockers,
  revision, and timestamp;
- parity results for every required mode;
- outcomes for all six CAP A2 case classes;
- exactly the global and class-specific gate results;
- explicit `feature_loss`, `api_narrowing`, and `format_rejection` booleans;
- unresolved regressions;
- downstream receipts;
- migration/coexistence and rollback plans;
- platform, service, security, performance, and oracle disposition;
- documentation and owner signoffs;
- state transition, production-switch request, campaign-close request, and
  incumbent action; and
- no-claim boundaries.

The focused contract includes a hypothetical structurally complete `REPLACE`
receipt only to test the evaluator. It is visibly fixture-only and grants no
real cutover authority.

Negative fixtures reject:

- unknown, duplicate, or guard-only capability targets;
- missing parity modes or case classes;
- `UNKNOWN`, `WORSE`, `NOT_APPLICABLE`, failed, blocked, unsupported, or
  no-win evidence used as green;
- missing downstream proof;
- feature loss, API narrowing, format rejection, or unresolved regression;
- stateful changes without migration and old-input preservation;
- missing rollback fields, even for a stateless helper;
- unsupported required platforms or missing service versions;
- incomplete independent security review;
- incomplete or regressed performance axes;
- unsafe, cyclic, expired, or unretired oracle placement;
- missing docs or owner signoff;
- state-machine bypass;
- malformed source/timestamp provenance; and
- policy mutations that omit a capability, drift a state, invent a class,
  authorize an early exit, broaden a gate, or enable a forbidden transition.

## Replay and detailed logging

Run:

```bash
RCH_REQUIRE_REMOTE=1 bash scripts/run_dependency_cutover_policy.sh contract
RCH_REQUIRE_REMOTE=1 bash scripts/run_dependency_cutover_policy.sh catalog
```

The runner refuses to overwrite an existing run directory and writes under:

```text
target/e2e-results/dependency-cutover-policy/<run_id>/
```

Every run retains:

- `summary.json`;
- `events.ndjson`;
- root and per-step stdout/stderr;
- `provenance.json`;
- `replay.sh`;
- exact command and scenario/step IDs;
- source revision and controller dirt;
- fixture ID, per-file SHA-256 manifest, and aggregate digest;
- Rust/Cargo version, target, host, feature profile, execution tree, and RCH
  worker;
- command exit, observed and minimum test count, normalized outcome, and
  duration;
- redaction self-test and retained-output scan;
- child cleanup and residual-child count;
- complete generated-path inventory; and
- the focused no-claim boundary.

The `contract` scenario runs Cargo only through RCH against clean committed
`HEAD` and requires at least 30 tests. The `catalog` scenario performs a static
cross-artifact assertion and requires one assertion. During implementation,
agents may use explicit clean-overlay paths; canonical receipts run after
commit.

If RCH is absent or local fallback occurs, the result is
`BLOCKED_EXTERNAL`, not green. `BLOCKED` and `UNSUPPORTED` are never counted as
passing. Failed receipts are retained and are not deleted.

The aggregate no-mock `dependency-sovereignty` suite, injected runner failures,
service lifecycle, platform matrix, and cross-scenario packaging remain owned
by VER A2/A3/A5 and the VER A6 negative-fixture signoff. This focused runner
does not overclaim those future surfaces.

## Generated summary

<!-- BEGIN GENERATED CUTOVER POLICY SUMMARY -->
- Artifact: `dependency-cutover-policy-v1` (schema 1)
- Coverage: 50 capabilities; 41 cutover targets; 9 cross-cutting guards.
- Policy: 4 terminal verdicts; 20 gates; 15 migration classes; 10 special-case contracts.
- Current registry states: BLOCKED_PENDING_EVIDENCE=18; KEEP_INCUMBENT=23; NOT_A_CUTOVER=9.
<!-- END GENERATED CUTOVER POLICY SUMMARY -->

## Focused contract

Run:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_dependency_cutover_policy" cargo test -p asupersync --test dependency_cutover_policy_contract -- --nocapture
```

The contract contains more than the 30-test fail-closed floor and checks the
canonical artifact, all 50 registry and baseline joins, live bead ownership,
state machine, verdict semantics, gate/class taxonomies, special cases,
hypothetical decision evaluator, negative mutations, documentation summary,
runner contract, and artifact-governance registration.

## No-claim boundary

Passing CAP A3 proves that the decision policy is complete, internally
consistent, joined to the current 50-capability registry/baseline, and
fail-closed against the encoded negative fixtures.

It does not prove that any replacement is correct, equivalent, faster, safer,
portable, interoperable, or ready. It does not authorize a production switch,
manifest cutover, feature removal, API narrowing, format rejection, platform
reduction, file deletion, or release. CAP A4, VER A1 through VER A6, and every
campaign-specific downstream, service, platform, security, performance,
migration, rollback, graph, and owner gate remain mandatory.
