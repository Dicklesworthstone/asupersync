# DEP-ADR-009: Preserve the complete Kafka client capability behind an already rdkafka-free public facade

- Status: accepted
- Date: 2026-07-24
- Owner: SapphireHill
- Program: `asupersync-ir2uf0` (dependency sovereignty)
- Bead: `asupersync-dep-p3-api-adrs-h3jspm.9`
- Capability: `CAP-KAFKA`
- Decision: `KEEP_UNTIL_PARITY` / `KEEP_INCUMBENT`
- Machine row: `artifacts/dependency_api_adr_registry_v1.json`
- Supersedes: `COMPREHENSIVE_DEPENDENCY_REPLACEMENT_PLAN.md` §5 `rdkafka` row and §9.3

## Context

**The public API is already completely free of rdkafka types.** This is the
strongest fact in the ADR and it is worth stating first. Every producer,
consumer, transaction, config, security and error type is first-party. The error
enum is hand-rolled, with the upstream error type imported *under an alias* and
mapped into the local taxonomy rather than re-exported — there is no `From` impl
bridging them. Every rdkafka value lives in a private field or a private
function, and the context type that would otherwise leak an associated type is
itself private. rdkafka is a swappable backend behind a facade the project
already owns.

**The module declarations are not feature-gated.** The types exist on every
build; the feature switches *behavior*. Without it, production paths fail closed
with a dedicated feature-disabled error and an actionable diagnostic, while a
cfg-gated deterministic in-process broker covers the state machines for tests
only. This is better than gating the module, and it is the part removal would
silently delete.

**The plan and the registry disagree.** §5/§9.3 say remove the feature once a
downstream inventory finds no consumer. The registry says `KEEP_UNTIL_PARITY`,
with a no-claim boundary that is direct: *"A wire codec or simple producer is not
a Kafka client; librdkafka stays until the complete campaign and real broker
matrix pass."* The registry governs. And the inventory that would gate removal
has not been run.

**Two capability gaps bound what parity means.** There is **no way to send
consumer offsets to a transaction**, so read-process-write exactly-once is not
achievable through this client — the registry's "transactional atomicity" claim
holds for the producer side only. And there is **no admin surface at all**: no
topic, partition, ACL, config or group administration.

**Compression is softer than the enum suggests.** Five codecs are declared in
first-party code, but rdkafka is taken with default features off and no
compression shim crates resolve — so which codecs the bundled C library can
actually use is decided by what its `configure` step autodetects **on the build
host**. Codec availability is a host property, not a declared Cargo feature.

The native build is `./configure` + `make` (mklove), **not cmake** — lockfile
verified: no `cmake` crate resolves anywhere, and the only build helper that does
is a `pkg-config` discovery shim. The plan already records this as a corrected
earlier error, and the standing rule that native attribution must be
lockfile-verified is what caught it.

## Decision

rdkafka and the `kafka` feature both stay, at `KEEP_UNTIL_PARITY` /
`KEEP_INCUMBENT`.

1. The rdkafka-free public facade **MUST** be preserved. No engine type may enter
   a public signature.
2. Module declarations **MUST** stay ungated and the no-feature lane **MUST**
   keep failing closed with its typed error and diagnostic.
3. The security posture is frozen in full: **SASL only over SSL**, non-loopback
   plaintext **refused** (including IPv4-mapped-IPv6 forms), credentials
   zeroized and redacted, the insecure opt-out **test-only**.
4. Idempotence **MUST** stay on by default and forced on for transactional
   producers; auto-commit **MUST** stay forced off in the real backend.
5. The caller-driven rebalance shape — generation, assigned, revoked — **MUST**
   be preserved.
6. The deterministic in-process broker **MUST NOT** become reachable from
   production.
7. rdkafka's `default-features = false` **MUST** hold; any change re-verifies the
   no-tokio production guarantee.
8. The feature **MUST NOT** be removed on a count. Removal additionally requires
   the downstream inventory, which has not been run.
9. The first-party RecordBatch v2 codec **MAY NOT** be counted as replacement
   progress. A codec is not a client.

## Allowed tradeoffs

- Adding the two missing capabilities (transactional consumer offsets, admin).
- Re-exporting currently unexported public types, as a reviewed change.
- Fixing the doc comment that names a method which does not exist.

## Forbidden compromises

- Removing the feature on a marginal package count.
- Exposing SASL over plaintext, or relaxing the plaintext refusal.
- Letting auto-commit default on, or idempotence off for transactional producers.
- Making the deterministic broker reachable from production.
- Counting the conformance codec as a native-client milestone.

## Known gaps

| ID | Gap | Owner |
|---|---|---|
| KFK-GAP-01 | Registry `source_owners` omits `src/messaging/kafka_consumer.rs`, which carries its own distinct rdkafka import set. Both listed entries are genuine, so this is wrong **by omission** — a baseline built from it would miss groups, rebalancing, commits, seek and isolation entirely. | `asupersync-dep-p1-foundations-upksjk.5.1` |
| KFK-GAP-02 | **No transactional consumer offsets** → no consume-process-produce exactly-once. The registry's atomicity claim covers the producer side only. | `asupersync-dep-p7-kafka-removal-sarszu.2.12.5` |
| KFK-GAP-03 | **No admin surface at all** — no topic, partition, ACL, config or group administration. | `asupersync-dep-p7-kafka-removal-sarszu.2.12.5` |
| KFK-GAP-04 | Compression codec availability is decided by the bundled library's `configure` autodetection on the build host, not by any Cargo feature. Same config can succeed on one host and fail on another. | `asupersync-dep-p7-kafka-removal-sarszu.1` |
| KFK-GAP-05 | Plan says REMOVE after a downstream inventory; registry says keep-until-parity. The inventory has not been run. | `asupersync-dep-p7-kafka-removal-sarszu` |
| KFK-GAP-06 | All four registry scenario ids and the baseline command are planned. The real-broker suite is opt-in via env var; several tests in that file run **without** a broker and emit proof rows only — not interoperability evidence. | `asupersync-dep-p7-kafka-removal-sarszu.2.13.6` |
| KFK-GAP-07 | `RebalanceResult`, the security config types, the client type and both backend traits are public but **not** re-exported from the `messaging` facade. | `asupersync-dep-p7-kafka-removal-sarszu.2.12.5` |
| KFK-GAP-08 | A consumer doc comment tells callers to call a singular commit method that does not exist; only the plural form is defined. | `asupersync-dep-p7-kafka-removal-sarszu.2.12.5` |

## Invariant impact checklist

- [x] rdkafka-free public facade preserved.
- [x] Ungated modules and the fail-closed no-feature lane preserved.
- [x] Full security posture preserved.
- [x] Idempotence and manual-commit defaults preserved.
- [x] Caller-driven rebalance shape preserved.
- [x] Deterministic broker stays test-scoped.
- [x] No-tokio production guarantee tied to the feature flag.
- [x] No compatibility shim introduced.
- [x] No root export changes.

## Evidence

Evidence state is `BASELINE_PLANNED`. Owners:
`asupersync-dep-p7-kafka-removal-sarszu.1` (baseline), `.2.12.5` (unit),
`.2.13.6` (E2E).

Real-broker evidence is the gate, and it is opt-in today. The four fuzz entry
points over response frames, metadata, error responses and delivery results are
genuinely wired and consumed by a fuzz target — that part is real. What is
missing is a multi-version broker matrix and a security fault matrix.

## Rollback

Triggered by any lost public symbol, error variant or config default; any
weakening of the security posture; auto-commit silently defaulting on;
idempotence no longer forced for transactional producers; the deterministic
broker becoming production-reachable; a real-broker regression; or a
reintroduced tokio edge from a changed feature flag.

## Focused contract

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_dependency_api_adr_registry" cargo test -p asupersync --test dependency_api_adr_registry_contract -- --nocapture
```

## No-claim boundary

This ADR is a frozen decision and public-surface inventory only. It does not
prove that the planned evidence has run, that the client interoperates with any
particular broker version or deployment, that transaction fencing or credential
zeroization behave as stated, that compression codecs are available on any given
build host, that a native client could reach protocol parity, that performance is
unchanged, or that rdkafka or the `kafka` feature may be removed. It also does
not certify the capability registry's source-owner row, which KFK-GAP-01 records
as omitting the consumer file.
