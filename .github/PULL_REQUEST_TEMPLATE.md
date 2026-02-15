## Summary

<!-- Brief description of changes -->

## Type of Change

- [ ] Bug fix (non-breaking change fixing an issue)
- [ ] New feature (non-breaking change adding functionality)
- [ ] Breaking change (fix or feature causing existing functionality to change)
- [ ] Performance optimization
- [ ] Refactoring (no functional changes)
- [ ] Documentation
- [ ] Tests

## Checklist

- [ ] Code compiles without errors (`cargo check --all-targets`)
- [ ] Clippy passes (`cargo clippy --all-targets -- -D warnings`)
- [ ] Formatting verified (`cargo fmt --check`)
- [ ] Tests pass (`cargo test`)
- [ ] Documentation updated (if applicable)
- [ ] Bead references included for any scope change (`bd-...` / `asupersync-...`)

## Proof + Conformance Impact Declaration

<!-- Required when touching runtime-critical modules:
src/runtime/, src/cx/, src/cancel/, src/channel/, src/obligation/, src/trace/, src/lab/, formal/lean/ -->

### Change Path Classification (choose one)

- [ ] Code-first repair (Rust implementation changed to match formal/declared behavior)
- [ ] Model-first repair (Lean/spec artifact changed to match implementation behavior)
- [ ] Assumption/harness-first repair (test/gate/assumption changed without direct code/model semantic change)

### Invariant and Theorem Impact

| Invariant ID | Impact (none/clarify/behavior) | Theorem / witness touched | Why unchanged or safe |
|--------------|--------------------------------|---------------------------|-----------------------|
| `inv.structured_concurrency.single_owner` | | | |
| `inv.region_close.quiescence` | | | |
| `inv.cancel.protocol` | | | |
| `inv.race.losers_drained` | | | |
| `inv.obligation.no_leaks` | | | |
| `inv.authority.no_ambient` | | | |

### Conformance Touchpoint Declaration

| Touchpoint Type | ID / Test / Profile | Result / Artifact |
|-----------------|----------------------|-------------------|
| Theorem touchpoints | theorem IDs / helper lemmas / witness names | |
| Refinement mapping touchpoints | `runtime_state_refinement_map` row IDs / constraint IDs | |
| Rust tests | | |
| Conformance checks | | |
| Lean coverage artifacts | | |
| CI verification profile (`smoke` / `frontier` / `full`) | | |

### Critical Module Scope Declaration

- [ ] This PR touches at least one runtime-critical path and the block below is complete
- [ ] This PR does not touch runtime-critical paths

| Critical Path Touched | Owner Group | Why This Change Is Needed |
|-----------------------|-------------|---------------------------|
| | | |

### Divergence Handling Declaration

If a model-code divergence was found, record the selected path and evidence:
- [ ] Divergence found and classified
- [ ] Required evidence attached (trace/log/theorem/test)
- [ ] Follow-up governance bead filed for any unresolved deviation
- Governance bead(s): <!-- bd-... -->

## Deterministic Review Rubric

Reviewer marks pass/fail per row. All rows must pass, or the PR must reference a governance bead.

| Rubric Check | Pass Criteria | Pass |
|--------------|---------------|------|
| Impact declaration complete | All touched invariants/theorems and touchpoints are filled | [ ] |
| Conformance linkage | At least one executable conformance/test link is present | [ ] |
| Determinism preserved | Seed, ordering, and tie-break behavior are unchanged or explicitly justified | [ ] |
| Cancellation semantics preserved | Request -> drain -> finalize semantics are unchanged or intentionally evolved with evidence | [ ] |
| Obligation safety preserved | No new leak path; obligations resolve commit/abort/nack correctly | [ ] |
| Governance tracking | Every unresolved exception has a governance bead with owner + closure path | [ ] |

---

## Performance Optimization Section

<!-- Required for PRs with "Performance optimization" checked above -->
<!-- Delete this section if not a performance change -->

### Opportunity Score

| Factor | Value | Rationale |
|--------|-------|-----------|
| Impact | <!-- 1-5 --> | <!-- Why this score --> |
| Confidence | <!-- 0.2-1.0 --> | <!-- Evidence: profile data, prototype, literature --> |
| Effort | <!-- 1-5 --> | <!-- Scope of change --> |
| **Score** | **<!-- Impact × Confidence / Effort -->** | Must be >= 2.0 |

### One Lever Rule

This change touches exactly one optimization lever:
- [ ] Allocation reduction
- [ ] Cache locality
- [ ] Algorithm complexity
- [ ] Parallelism
- [ ] Lock contention
- [ ] Other: <!-- specify -->

### Baseline Metrics

| Metric | Before | After | Delta |
|--------|--------|-------|-------|
| p50 latency | | | |
| p99 latency | | | |
| Allocations/op | | | |

### Isomorphism Proof

**Change summary:** <!-- What changed and why it should be behavior-preserving -->

**Semantic invariants (check all):**
- [ ] Outcomes unchanged (Ok/Err/Cancelled/Panicked)
- [ ] Cancellation protocol unchanged (request -> drain -> finalize)
- [ ] No task leaks / obligation leaks
- [ ] Losers drained after races
- [ ] Region close implies quiescence

**Determinism + ordering:**
- [ ] RNG: seed source unchanged
- [ ] Tie-breaks: unchanged or documented
- [ ] Iteration order: deterministic and stable

**Golden outputs:**
- [ ] `cargo test --test golden_outputs` passed
- [ ] No checksum changes (or changes documented)

---

## Bead Reference

<!-- Link to related beads if applicable -->
Closes: <!-- bd-XXXX -->
