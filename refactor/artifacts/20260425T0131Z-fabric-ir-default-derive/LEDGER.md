# FABRIC IR Default Derive Isomorphic Simplification Ledger

Run: `20260425T0131Z-fabric-ir-default-derive`
Agent: `ProudLake`

## Rejected Shape

- `FabricIr` was rejected because `schema_version` defaults to `FABRIC_IR_SCHEMA_VERSION`, not `0`.
- Named/policy schema defaults such as `MorphismPlan`, `ServiceContract`, `SessionSchema`, `ConsumerPolicy`, and retention/privacy/branch policies were rejected because they contain non-empty names, seeded vectors, `true` booleans, non-zero durations, or non-zero probabilities.

## Accepted Passes

| Pass | File | Change | Isomorphism proof |
| --- | --- | --- | --- |
| 1 | `src/messaging/ir.rs` | Derive `Default` for `LatencyEstimate`; remove manual impl. | Manual `Self::zero()` sets all `Duration` fields to `Duration::ZERO`, matching `Duration::default()`. |
| 2 | `src/messaging/ir.rs` | Derive `Default` for `CpuEstimate`; remove manual impl. | Manual `Self::new(0, 0)` returns both `u64` fields as zero; derive produces the same values without changing constructor normalization for non-default callers. |
| 3 | `src/messaging/ir.rs` | Derive `Default` for `ByteEstimate`; remove manual impl. | Manual `Self::new(0, 0, 0)` returns all `u64` fields as zero; derive produces the same values. |
| 4 | `src/messaging/ir.rs` | Derive `Default` for `DurationEstimate`; remove manual impl. | Manual `Self::new(Duration::ZERO, Duration::ZERO, Duration::ZERO)` returns all zero durations; derive produces the same values. |
| 5 | `src/messaging/ir.rs` | Derive `Default` for `CostVector`; remove manual impl. | Manual `Self::zero()` is composed only from default cost estimates and zero `f64` fields, matching derived defaults after passes 1-4. |

## Verification Results

- Fresh-eyes diff review: only the accepted `Default` derive substitutions above are present; no generic trait-bound changes were introduced.
- `rustfmt --edition 2024 --check src/messaging/ir.rs`: pass.
- `git diff --check`: pass.
- `rch exec -- cargo check -p asupersync --all-targets`: pass.
- `rch exec -- cargo test -p asupersync --features messaging-fabric --lib messaging::ir --no-fail-fast`: pass, 24 passed.
- `rch exec -- cargo clippy -p asupersync --features messaging-fabric --all-targets -- -D warnings`: blocked by unrelated existing lints in `benches/bytes_allocation_profile.rs` (`criterion::black_box` deprecation, unused variables, useless conversion) and `src/messaging/control.rs` (`clippy::match_single_binding`).
- `rch exec -- cargo clippy -p asupersync --features messaging-fabric --lib -- -D warnings -A clippy::match-single-binding`: pass; the allow isolates the known unrelated `src/messaging/control.rs` blocker so the edited feature-gated library code is linted.
