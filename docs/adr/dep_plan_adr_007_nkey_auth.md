# DEP-ADR-007: Preserve complete NKey credential, prefix, signing, verification and downstream API capability

- Status: accepted
- Date: 2026-07-24
- Owner: SapphireHill
- Program: `asupersync-ir2uf0` (dependency sovereignty)
- Bead: `asupersync-dep-p3-api-adrs-h3jspm.7`
- Capability: `CAP-NKEY-AUTH`
- Decision: `KEEP_UNTIL_PARITY` / `KEEP_INCUMBENT`
- Machine row: `artifacts/dependency_api_adr_registry_v1.json`
- Supersedes: `COMPREHENSIVE_DEPENDENCY_REPLACEMENT_PLAN.md` §5 `nkeys` row and §9.5

## Context

Three findings from the source read all point the same way.

**Scope.** The plan's design section sizes this at *"~200 lines SAFE-OWN codec
(base32 no-pad + CRC-16/XMODEM + prefixes)"* and frames it as NATS work. But
`nkeys` is load-bearing in **four independent subsystems**: NATS messaging, ATP
(peer identity *and* capability-token verification), agent-swarm credential
admission, and runtime signed-profile bundles — six production files in total.
Meanwhile the capability registry scopes it to *every* prefix form, Curve/X25519
keys, JWT signer policy and secret zeroization. Those two scopes differ by more
than an order of magnitude. The plan's file, `src/security/nkey.rs`, **does not
exist**; the real owned surface is `src/security/keys/mod.rs`.

**Direction of the trade.** `ed25519-dalek` is *not* a direct dependency — it
arrives transitively through `nkeys`, alongside `ed25519` and `data-encoding`.
The replacement therefore **adds** a direct cryptographic dependency and moves
base32 and CRC-16/XMODEM into first-party code, in exchange for removing one
crate. The program's own discipline says moving security-critical code from a
mature, widely-used dependency into fresh first-party code does not inherently
reduce risk without measured evidence and owner sign-off. That is exactly this
case, and it deserves stating plainly rather than being carried by a marginal
package count.

**Readiness.** The differential oracle that would prove parity does not exist:
the oracle policy names a harness directory that is absent from the tree, and
`nkeys` is a normal dependency rather than a dev-dependency, so the reference
implementation is not even wired for differential testing. The declared
independent security review has not happened. Existing tests generate their own
deterministic seeds, which proves self-consistency, not interoperability.

One thing is smaller than expected, and worth recording: the **public** blast
radius is a single function. `IdentityKeyStore::active_key_pair` returns
`Result<nkeys::KeyPair, KeyStoreError>` and is the only place an `nkeys` type
reaches asupersync's public API. Even the doc-hidden fuzz shims deliberately
return a `String` rather than a key pair.

## Decision

`nkeys` stays, at `KEEP_UNTIL_PARITY` / `KEEP_INCUMBENT`.

1. Every credential form, prefix handling, signing and verification operation,
   error class and downstream workflow **MUST** remain available.
2. Type names **MAY** change — permanent shims are unwanted — but the migration
   **MUST** be documented and direct.
3. The User-only production enforcement **MUST** remain fail-closed at all three
   sites, and public/seed/private type separation **MUST** hold.
4. Secret redaction, zeroization, seed-entropy validation, domain-separated
   fingerprints and the constant-time JWT subject comparison **MUST** be preserved.
5. Key rotation, revocation, generation history and the platform permission model
   **MUST** be preserved.
6. Algorithm pinning **MUST** stay fail-closed — an unexpected algorithm is
   rejected, never defaulted — and signer-authorization failures **MUST** stay
   distinct from signature failures and non-oracular.
7. A replacement **MUST NOT** begin before the differential oracle exists, with
   `nkeys` wired as a dev-dependency reference.
8. The owner **MUST** decide explicitly whether the target is **User-only actual
   capability** or **full upstream nominal capability** (eight kinds plus seed,
   private and curve encodings). That choice changes the scope enormously and
   this ADR records it rather than narrowing silently.
9. Cutover **MUST NOT** proceed without an independent security review.

## Allowed tradeoffs

- Owned wrapper types and ergonomic constructors may be added.
- The single public leak may be closed by wrapping the returned key pair — a
  breaking change, so it belongs with the replacement rather than ahead of it.
- The incumbent may serve as a quarantined oracle under the oracle policy.

## Forbidden compromises

- Losing any credential form, prefix handling, operation or error class.
- Weakening redaction, zeroization, entropy validation or the constant-time
  comparison.
- Defaulting an unexpected algorithm instead of rejecting it.
- Treating self-generated deterministic seeds as interoperability evidence.
- Beginning implementation on the "~200 line" estimate.

## Known gaps

| ID | Gap | Owner |
|---|---|---|
| NKY-GAP-01 | Registry `source_owners` names `src/messaging/nats.rs` and `Cargo.toml` — both genuine, so this is **not** a phantom-owner row — but is **wrong by omission**: five production files are missing, including `src/security/keys/mod.rs` which hosts the only public leak, plus `runtime/config.rs`, `atp/identity/mod.rs`, `atp/policy/verification.rs` and `agent_swarm/control_plane.rs`. | `asupersync-dep-p1-foundations-upksjk.5.1` |
| NKY-GAP-02 | `dependency_owners` lists **`base32` and `crc16` as if they were crates** — neither exists. Base32 is `data-encoding`; CRC-16 is inside `nkeys`. It also names `ed25519-dalek`, which is not a direct dependency. | `asupersync-dep-p1-foundations-upksjk.5.1` |
| NKY-GAP-03 | **The differential oracle does not exist.** Its harness directory is absent and `nkeys` is not a dev-dependency, so parity is unmeasurable. | `asupersync-dep-p4-nkeys-poc60v.1.1` |
| NKY-GAP-04 | No independent official NKey/NATS vectors. Tests generate their own seeds — self-consistency, not interoperability. | `asupersync-dep-p4-nkeys-poc60v.1.6` |
| NKY-GAP-05 | The declared independent security review **has not happened**. | `asupersync-dep-p4-nkeys-poc60v.5` |
| NKY-GAP-06 | Plan §9.5 sizes the work at ~200 lines, NATS-only; the real capability spans four subsystems and the registry demands full prefix, Curve, JWT-policy and zeroization coverage. | `asupersync-dep-p4-nkeys-poc60v.1.1` |
| NKY-GAP-07 | Production exercises **User only**; Cluster and Operator appear solely as test fixtures; Account, Server, Module, Service and Curve are referenced nowhere. Actual vs nominal capability is an unresolved owner decision. | `asupersync-dep-p4-nkeys-poc60v.1.1` |
| NKY-GAP-08 | The baseline records resource-limit evidence blocked on an owner, and cancellation-cleanup and recovery blocked externally. | `asupersync-dep-p4-nkeys-poc60v.5` |

## Invariant impact checklist

- [x] All credential forms and operations preserved.
- [x] User-only enforcement and type separation preserved, fail-closed.
- [x] Secret redaction, zeroization and entropy validation preserved.
- [x] Constant-time subject comparison preserved.
- [x] Rotation, revocation, history and permission model preserved.
- [x] Algorithm pinning stays fail-closed.
- [x] The single public leak is recorded, not widened.
- [x] Security review recorded as an unmet precondition.
- [x] No compatibility shim introduced.
- [x] No root export changes.

## Evidence

Evidence state is `BASELINE_PLANNED`. Owners: `asupersync-dep-p4-nkeys-poc60v.1.1`
(baseline), `.1.6` (unit), `.5` (E2E).

The ordering is forced by NKY-GAP-03: **the oracle comes first**, with `nkeys`
wired as a dev-dependency reference and a harness in place. Then official
vectors, a negative credential matrix, fuzzing, cross-implementation NATS E2E in
both directions, downstream fixtures, and an independent security review.

## Rollback

Triggered by any credential form that stops being accepted, any lost prefix
handling or error class, any weakened redaction or constant-time comparison, any
failure against a real NATS server, any downstream that can no longer obtain a
key pair, or any regression in rotation, revocation or permissions.

## Focused contract

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_dependency_api_adr_registry" cargo test -p asupersync --test dependency_api_adr_registry_contract -- --nocapture
```

## No-claim boundary

This ADR is a frozen decision and public-surface inventory only. It does not
prove that the planned evidence has run, that the current implementation
interoperates with any particular NATS deployment, that secret zeroization or
cancellation cleanup behave as stated, that an owned codec could reach byte or
security parity, that performance is unchanged, or that `nkeys` may be removed.
It also does not certify the capability registry's source-owner or
dependency-owner rows, which NKY-GAP-01 and NKY-GAP-02 record as incomplete and
incorrect.
