# Dependency Phase-1 Aggregate Signoff

This is the operator guide for
`asupersync-dep-p1-foundations-upksjk.4`. The checked machine packet is
`artifacts/dependency_phase1_aggregate_signoff_v1.json`; its focused verifier
is `tests/dependency_phase1_aggregate_signoff_contract.rs`.

The terminal verdict is `PASS_SCOPED_FOUNDATIONS_ONLY`. It releases the later
Dependency Sovereignty evidence DAG to begin its already-scoped work. It is
not a dependency-exit, feature-cutover, performance, or release verdict.

## Reconciled foundation

The aggregate joins these checked authorities:

- the two-axis safety taxonomy;
- the Cargo-built marginal ledger;
- the differential-oracle lifecycle and quarantine policy;
- the capability registry, executable incumbent baseline, no-loss cutover
  state machine, and graph-wide CAP A4 signoff;
- the invariant-to-evidence matrix and VER A6 verification signoff.

All source contracts are content-pinned by SHA-256 in the aggregate artifact.
The reconciliation has 33 taxonomy candidates and 50 stable capability IDs.
Every taxonomy candidate is present in the capability crosswalk. The corrected
ledger projects 32 candidates through measured direct/marginal Cargo packages;
`simd-dispatch-boundary` is the sole implementation-only candidate with no
direct Cargo edge. Oracle coverage is an explicit partition: twelve
taxonomy candidates do not require an incumbent oracle, while the
`kafka-native-client` and `sqlite-cycle-safe-integration` IDs exist only to
govern native/reverse-dependency quarantine.

## Ledger correction found by the gate

The aggregate audit initially refused to sign off because the marginal ledger
projected only 23 of the 33 taxonomy candidates. The root cause was exact
comparison of manifest dependency keys against Cargo metadata dependency
identifiers: Cargo reports hyphenated keys with underscores. Consequently,
29 hyphenated direct edges were recorded as absent.

Commit `06a2ce21eb8bd609602f22865341cb8fb366d557` normalizes that comparison,
retains the original manifest spelling in the artifact, and projects taxonomy
references from the direct package plus packages actually removed by the
counterfactual. Unit regressions cover plain, empty, single-hyphen, and
multiple-hyphen names plus the transitive
`crossbeam-utils::CachePadded` surface. The canonical ledger was regenerated
from that exact clean commit.

## Frozen matrix and provenance

The ledger freezes 13 feature profiles:

- minimal and default;
- tls, sqlite, kafka, metrics, cli, compression, trace-compression, io-uring,
  and loom-tests;
- fuzz-quarantine;
- the full workspace dev/build audit.

Each profile is independently resolved for 4 target triples: Linux x86-64,
macOS arm64, Windows x86-64, and wasm32. The resulting 52 graph cells retain
the host triple, Cargo and rustc versions, baseline and counterfactual
manifest/lock hashes, exact `cargo metadata` commands, normalized upstream
identity, and active/declared-inactive/unknown/none native evidence.

Unknown native evidence remains `EXPLICITLY_BLOCKED_NOT_GREEN`. It is not
silently converted to safe, inactive, or absent.

## Oracle and cycle gate

Every oracle is forbidden from `workspace-release`. Native/C oracles may live
only in an external Cargo harness or frozen fixtures. The reverse-dependency
oracle may live only downstream, in a neutral synthesized consumer, or in
frozen fixtures. Ordinary workspace dev/build/normal/release and fuzz profiles
are forbidden for both classes.

Every registry row names a cycle-safe location, retirement bead, and expiry
disposition. A native oracle in a release lane, a reverse-dependency cycle, or
an expired active oracle fails the aggregate.

## Operator decision summary

Closing this gate authorizes downstream evidence work only:

- 104 later implementation rows remain evidence-gated through this node;
- 18 capabilities are `BLOCKED_PENDING_EVIDENCE`;
- 23 capabilities are `KEEP_INCUMBENT`;
- 9 cross-cutting capabilities are `NOT_A_CUTOVER`;
- 35 baseline cases remain `BLOCKED_OWNER`, assigned to 21 exact owner beads.

All 320 later non-Phase-1 matrix rows—architecture, decisions,
implementations, and verification—must transitively depend on this gate
through `blocks` and nested `parent-child` ancestry. Direct edges from later
work to the Phase-1 gate must be `blocks` edges. The contract recomputes that
direct edge count from the committed tracker and rejects any cycle in the
true `blocks` graph. Parent-child coordination loops are not dependency
cycles and match `br dep cycles` semantics.

## Fail-closed fixtures

The aggregate mutates one valid fixture at a time and requires exactly these
six failures:

1. missing taxonomy row;
2. stale ledger profile;
3. native oracle in a release lane;
4. reverse-dependency cycle;
5. unknown native evidence without an explicit blocked disposition;
6. expired active oracle.

The positive fixture deliberately contains an unknown native row with an
explicit blocked disposition. This proves that an honest blocker is accepted
as a blocker, never counted as green.

## Canonical commands

Regenerate the ledger from its pinned clean source commit using the exact
pipeline in `docs/dependency_marginal_ledger.md`. The aggregate artifact
retains the machine command under `canonical_commands.ledger_regeneration`.

Run the three foundation contracts plus this aggregate contract together:

```bash
RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- env \
  CARGO_INCREMENTAL=0 \
  CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-D warnings -C debuginfo=0' \
  CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_dependency_phase1_aggregate_signoff" \
  cargo test -p asupersync \
    --test dependency_safety_taxonomy_contract \
    --test dependency_marginal_ledger_contract \
    --test dependency_oracle_policy_contract \
    --test dependency_phase1_aggregate_signoff_contract -- --nocapture
```

Before closeout, audit the mutable tracker state separately:

```bash
br show \
  asupersync-dep-p1-foundations-upksjk.1 \
  asupersync-dep-p1-foundations-upksjk.2 \
  asupersync-dep-p1-foundations-upksjk.3 \
  asupersync-dep-p1-foundations-upksjk.5.4 \
  asupersync-dep-p1-foundations-upksjk.6.6 --json
br dep cycles
```

## No-claim boundary

This signoff proves content-pinned foundation agreement, stable-ID
reconciliation, matrix/provenance structure, oracle quarantine and lifecycle
policy, typed blocker preservation, fail-closed fixture behavior, and
transitive tracker gating.

It does not authorize dependency exit, cutover, feature/API/format/protocol/
platform/diagnostic/user-journey narrowing, or permission to delete files. It
does not prove implementation parity, runtime correctness, performance or no
regression, release readiness, broad workspace health, live RCH fleet
availability, unavailable platform/service execution, or downstream behavior
beyond the cited checked surfaces.
