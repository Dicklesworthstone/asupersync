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
