# Repeat Isomorphic Simplification Ledger

Run: `20260424T2350Z-repeat-isomorphic-simplification`
Agent: `ProudLake`

## Rejected Candidate

- Generic combinator marker derives in `src/combinator/*`: rejected because Rust derives add extra public bounds such as `T: Copy` and `T: Default` for `PhantomData<T>` marker structs. That is not isomorphic.

## Accepted Passes

All accepted passes are single-file, compile-checked boilerplate collapses. They do not change ordering, error semantics, laziness, RNG, side effects, or async/cancellation behavior.

| Pass | File | Change | Isomorphism proof |
| --- | --- | --- | --- |
| 1 | `src/evidence.rs` | Derive `Eq` for `EvidenceDetail`; remove empty impl. | Existing `PartialEq` is structural; all variants contain `Eq` payloads. |
| 2 | `src/evidence.rs` | Derive `Eq` for `SupervisionDetail`; remove empty impl. | Existing `PartialEq` is structural; `String`, `Duration`, `u32`, and `Option<Duration>` are `Eq`. |
| 3 | `src/evidence.rs` | Derive `Eq` for `LinkDetail`; remove empty impl. | Existing `PartialEq` is structural; `TaskId`, `RegionId`, and `Outcome<(), ()>` are `Eq`. |
| 4 | `src/evidence.rs` | Derive `Eq` for `MonitorDetail`; remove empty impl. | Existing `PartialEq` is structural; `TaskId`, `RegionId`, `usize`, and `Outcome<(), ()>` are `Eq`. |
| 5 | `src/supervision.rs` | Derive `Eq` for `BudgetRefusal`; remove empty impl. | Existing `PartialEq` is structural; all fields are integers or `Duration`. |
| 6 | `src/supervision.rs` | Derive `Eq` for `RestartVerdict`; remove empty impl. | Existing `PartialEq` is structural; payloads are `u32`, `Option<Duration>`, and `BudgetRefusal`. |
| 7 | `src/supervision.rs` | Derive `Eq` for `BindingConstraint`; remove empty impl. | Existing `PartialEq` is structural; payloads are `&'static str`, integers, and `Duration`. |
| 8 | `src/trace/crashpack.rs` | Derive `PartialEq, Eq` for `FailureInfo`; remove manual impls. | Removed equality compared all fields exactly; derived equality does the same field-by-field comparison. |
| 9 | `src/types/task_context.rs` | Derive `Default` for `CheckpointState`; remove manual impl. | Manual default returned `last_checkpoint: None`, `last_message: None`, `checkpoint_count: 0`, identical to field defaults. |
| 10 | `src/service/load_balance.rs` | Derive `Default` for `RoundRobin`; remove manual impl. | Manual default returned `AtomicUsize::new(0)` through `new()`, identical to `AtomicUsize::default()`. |

## Verification Results

- `rustfmt --edition 2024 --check src/evidence.rs src/supervision.rs src/trace/crashpack.rs src/types/task_context.rs src/service/load_balance.rs`: pass.
- `git diff --check`: pass.
- `rch exec -- cargo check -p asupersync --all-targets`: remote exit 0; local artifact retrieval stalled after success and the local wrapper was stopped.
- `rch exec -- cargo test -p asupersync --lib evidence --no-fail-fast`: 146 passed, 0 failed.
- `rch exec -- cargo clippy -p asupersync --all-targets -- -D warnings`: pass.
