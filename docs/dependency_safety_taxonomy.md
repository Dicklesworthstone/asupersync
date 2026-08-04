# Dependency Replacement Safety Taxonomy

Bead: `asupersync-dep-p1-foundations-upksjk.1`

## Purpose and Scope

The canonical machine-readable policy is
`artifacts/dependency_safety_taxonomy_v1.json`. Its contract test is
`tests/dependency_safety_taxonomy_contract.rs`.

This taxonomy answers two orthogonal questions for the Dependency Sovereignty
Program:

1. What implementation-unsafety class does a proposed first-party replacement
   occupy?
2. Which review sensitivities apply even when the implementation is entirely
   safe Rust?

It governs prospective replacement approvals. It does not decide whether a
replacement is worthwhile on marginal dependency cost, performance,
interoperability, maintenance, portability, or product grounds. Those remain
separate gates in the owning bead and the marginal-cost ledger.

## Axis A: Implementation Unsafety

| Class | Meaning | Default safety eligibility |
| --- | --- | --- |
| `SAFE-OWN` | The complete first-party replacement surface is clean under `#![forbid(unsafe_code)]`; first-party unsafe helpers are not a loophole. | `eligible` |
| `BOUNDARY-UNSAFE` | Unsafe is confined to the narrowest practical OS/FFI or CPU-dispatch boundary. | `eligible_with_required_evidence` |
| `ALGORITHMIC-UNSAFE` | Unsafe encodes ownership, liveness, initialization, pinning, parking, reclamation, or weak-memory reasoning. | `prohibited` |

`SAFE-OWN` is the default. A downstream bead must still prove its semantics,
tests, differential oracle, interoperability, performance, and marginal-cost
claims. The class only says that the proposed first-party implementation does
not add an unsafe-code review boundary.

`BOUNDARY-UNSAFE` is conditional. Before approval, the implementation bead must
link all of the following:

1. Why safe Rust is insufficient at this boundary.
2. The narrowest practical item- or function-scoped
   `#[allow(unsafe_code)]`.
3. A matching row in `artifacts/unsafe_boundary_ledger_v1.json`.
4. Category-specific review evidence from
   `docs/unsafe_boundary_ledger.md`.
5. Miri coverage, or an explicit toolchain/platform limitation with an
   alternate focused proof.
6. UBS coverage for every owned boundary file.
7. Target-gated RCH evidence and an explicit list of hosts or architectures
   not exercised.

`ALGORITHMIC-UNSAFE` is prohibited by default. Loom does not prove liveness or
linearizability. Miri does not model weak memory. A 48-hour soak is not a
proof. Moving this unsafe class from a mature, widely-fuzzed crate into fresh
first-party code increases risk.

## Axis B: Review-Sensitivity Tags

Review sensitivity is multi-valued and independent of implementation
unsafety. A strict safe-Rust DER, protobuf, LZ4, or DEFLATE parser is
`SAFE-OWN`; the parser's security and wire obligations are represented by
tags, not by falsely labeling it `BOUNDARY-UNSAFE`.

| Tag | Additional evidence required |
| --- | --- |
| `ordinary` | Focused semantics and the owning bead's normal proof packet. This tag is exclusive. |
| `public-api-redesign` | Approved ADR, API-surface-map update, consumer migration, and no-shim decision. |
| `persistent-format` | Versioned schema, historical goldens, and an explicit migration, rejection, or retention policy. |
| `wire-format-parser` | Canonical and adversarial wire vectors, provenance, decoder fuzzing or exhaustive bounded-input strategy. |
| `security-sensitive-parser` | Independent security review, negative confusion/bypass/amplification fixtures, and fail-closed resource bounds. |
| `cryptographic-format` | Reference vectors, key-kind and canonicalization review, secret redaction/zeroization, and security sign-off. |
| `concurrency-liveness` | LabRuntime or DPOR schedules, leak/quiescence assertions, liveness argument, and bounded stress evidence. |
| `platform-boundary` | Target/host matrix, ABI references, and target-gated RCH evidence or an explicit no-host receipt. |
| `runtime-hot-path` | Real-workload performance evidence, appropriate resource metrics, and a rollback threshold. |

Every classification row lists at least one
`review_sensitivity_tags` value and a matching
`sensitivity_evidence_requirements` entry for each tag. Missing, unknown, or
duplicate tags fail the contract. `ordinary` cannot be combined with another
tag.

Parser safety and parser review are deliberately separate. For example:

- `x509-residual-parser` is `SAFE-OWN` plus `wire-format-parser` and
  `security-sensitive-parser`.
- `proto-codec` and `deflate-codec` are `SAFE-OWN` plus parser sensitivity
  tags.
- `nkey-codec` is `SAFE-OWN` plus `cryptographic-format`,
  `security-sensitive-parser`, `wire-format-parser`, and
  `persistent-format`.
- `signal-platform` and `extended-attributes` are
  `BOUNDARY-UNSAFE` plus `platform-boundary`.
- `safe-queue-prototype` is `SAFE-OWN` plus `concurrency-liveness` and
  `runtime-hot-path`.

## The Two Axes Are Not Program Approval

The taxonomy separates two decisions that must not be collapsed:

- Safety eligibility answers whether the implementation class is allowed and
  what safety evidence it requires.
- Program approval answers whether the replacement should happen at all.

For example, `polling-reactor` and `socket-platform` are classified
`BOUNDARY-UNSAFE` with `eligible_with_required_evidence`. Their program verdict
is still `KEEP_UNLESS_GATED`: each needs a measured defect or suite-wide
platform-boundary justification, cross-platform evidence, and explicit owner
sign-off. The class label is not permission to begin that work.

Likewise, `parking-lot-wrapper` is `SAFE-OWN`, but its implementation remains
blocked on the stable lane and the full-axis 1/8/32/64-core performance gate.
Its optional nightly nonpoison backend must remain safe. A future raw futex or
parking backend is a separate `ALGORITHMIC-UNSAFE` candidate and is prohibited
by default.

## Canonical Candidate IDs

Downstream beads cite the stable `candidate_id`, not a free-form paraphrase.
The artifact carries the complete row inventory. Important groups are:

- `SAFE-OWN`: `hex-codec`, `base64-codec`, `future-utilities`,
  `public-stream-migration`, `token-slab`, `visibility-attribute`,
  `atp-version-scanner`, `nkey-codec`, `proto-codec`,
  `typed-symbol-msgpack-codec`, `config-schema-migration`, `cli-parser`,
  `regex-scanners`, `parking-lot-wrapper`, `x509-residual-parser`,
  `safe-queue-prototype`, and `cache-padded-experiment`.
- `BOUNDARY-UNSAFE`: `polling-reactor`, `socket-platform`,
  `signal-platform`, `host-introspection`, `extended-attributes`,
  and `simd-dispatch-boundary`.
- `ALGORITHMIC-UNSAFE`: `lock-free-queue`, `inline-storage`,
  `pin-projection`, and `raw-lock-parking-protocol`.

The artifact also classifies the remaining owned surfaces from the Rev-3 plan,
including the timestamp, typed-symbol, metrics, and compression candidates.

## How an Implementation Bead Cites the Taxonomy

Before implementation:

1. Find the exact row in
   `artifacts/dependency_safety_taxonomy_v1.json`.
2. Copy its `candidate_id`, `class_id`, `eligibility`,
   `review_sensitivity_tags`, `sensitivity_evidence_requirements`, and
   `program_gates` into the bead plan.
3. Reserve the exact implementation, test, artifact, ledger, and documentation
   paths before editing.
4. If the row is `prohibited`, stop. Do not prototype first-party algorithmic
   unsafe unless the exception process has already reached
   `exception_approved`.

At closeout, add a machine-readable citation packet to the bead comment or its
owned evidence artifact:

```json
{
  "taxonomy_artifact": "artifacts/dependency_safety_taxonomy_v1.json",
  "candidate_id": "hex-codec",
  "class_id": "SAFE-OWN",
  "eligibility": "eligible",
  "review_sensitivity_tags": ["ordinary"],
  "evidence_refs": [
    "tests/example_hex_differential.rs",
    "bead-comment-with-rch-result"
  ],
  "sensitivity_evidence_refs": {
    "ordinary": ["tests/example_hex_differential.rs"]
  },
  "explicit_no_claims": [
    "This citation does not prove marginal dependency savings or broad workspace health."
  ]
}
```

Every key in that example is required. `evidence_refs` and every
`sensitivity_evidence_refs` entry must link actual terminal evidence, not
planned commands. The sensitivity evidence keys must exactly match the row's
tags. `explicit_no_claims` must name the important guarantees that the cited
evidence does not establish.

For a `BOUNDARY-UNSAFE` row, the references must also include the exact unsafe
ledger row, its documentation evidence, the Miri or explicit no-host result,
UBS output, and the target-gated RCH proof. A bare taxonomy citation is
incomplete.

## Algorithmic-Unsafe Exception Process

An `ALGORITHMIC-UNSAFE` row can move from `prohibited` to
`exception_approved` only when one decision record contains all four nonempty
fields:

1. `measured_incumbent_performance_defect` — a reproducible real-workload
   benchmark or production trace.
2. `safe_alternative_benchmark` — a `SAFE-OWN` alternative measured on the
   same workload and full gate axes.
3. `safe_alternative_rejection_rationale` — why that measured safe result is
   unacceptable and no narrower safe design works.
4. `owner_signoff` — explicit repository-owner approval after reviewing the
   defect and safe-alternative evidence.

Partial evidence fails closed. An open bead, prototype, benchmark plan, Loom
run, Miri run, fuzz result, soak, or taxonomy row is not implicit owner
sign-off.

## No-Claim Boundaries

This taxonomy governs prospective dependency-replacement approvals only. It
does not retroactively judge, revoke, certify, or reclassify existing ledgered
unsafe boundaries.

Passing the contract test proves only that:

- the three classes and their required evidence remain present;
- the nine review-sensitivity tags and their required evidence remain present;
- all 33 planned OWN, evidence-gated, and explanatory KEEP rows have exact
  class and sensitivity assignments;
- safe parsers are not mislabeled `BOUNDARY-UNSAFE`;
- every classification uses an eligibility state allowed by its class;
- prohibited rows cannot carry an implicit or partial exception;
- summary counts, citation fields, and documentation markers stay aligned.

It does not prove runtime correctness, performance parity, marginal dependency
savings, release readiness, broad workspace health, platform coverage, Miri
coverage, UBS cleanliness, or correctness of any unsafe boundary. Those claims
require their own terminal evidence.

## Validation

The focused contract is deterministic and reads only the checked artifact,
this guide, the Rev-3 source plan, and unsafe-ledger policy files.

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_dependency_safety_taxonomy" cargo test -p asupersync --test dependency_safety_taxonomy_contract -- --nocapture
```

Required test metadata:

- `scenario_id`: `dependency_safety_taxonomy_contract_v1`
- `seed_or_fixture`: `artifacts/dependency_safety_taxonomy_v1.json`
- `artifact_path`: `artifacts/dependency_safety_taxonomy_v1.json`
- `expected_outcome`: `pass`
