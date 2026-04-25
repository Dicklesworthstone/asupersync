# Default Derive Isomorphic Simplification Ledger

Run: `20260425T0002Z-default-derive-simplification`
Agent: `ProudLake`

## Rejected Shape

- Manual defaults with policy values like non-zero durations, `"idle"`, `true`, non-empty static strings, or generated timestamps were rejected. Derived `Default` would change their values.
- Generic marker defaults were rejected again because Rust derives add public type-parameter bounds.

## Accepted Passes

| Pass | File | Change | Isomorphism proof |
| --- | --- | --- | --- |
| 1 | `src/service/load_balance.rs` | Derive `Default` for `PowerOfTwoChoices`; remove manual impl. | Manual default returns `counter: AtomicUsize::new(0)` through `new()`, matching `AtomicUsize::default()`. |
| 2 | `src/channel/verification_suite.rs` | Derive `Default` for `CategoryResult`; remove manual impl. | All numeric fields default to zero and `Vec<String>` defaults to empty. |
| 3 | `src/monitor.rs` | Derive `Default` for `MonitorSet`; remove manual impl. | All three `BTreeMap` indexes default to empty, matching `new()`. |
| 4 | `src/monitor.rs` | Derive `Default` for `DownBatch`; remove manual impl. | The sole `Vec` field defaults to empty, matching `new()`. |
| 5 | `src/link.rs` | Derive `Default` for `LinkExitBatch`; remove manual impl. | The sole `Vec` field defaults to empty, matching `new()`. |
| 6 | `src/link.rs` | Derive `Default` for `LinkSet`; remove manual impl. | All `BTreeMap` indexes default to empty, matching `new()`. |
| 7 | `src/link.rs` | Derive `Default` for `ExitBatch`; remove manual impl. | The sole `Vec` field defaults to empty, matching `new()`. |
| 8 | `src/trace/distributed/crdt.rs` | Derive `Default` for `GCounter`; remove manual impl. | The `BTreeMap` counter map defaults to empty, matching `new()`. |
| 9 | `src/trace/distributed/crdt.rs` | Derive `Default` for `PNCounter`; remove manual impl. | Both component counters default to empty `GCounter`s, matching `new()`. |
| 10 | `src/trace/distributed/vclock.rs` | Derive `Default` for `VectorClock`; remove manual impl. | The `BTreeMap` entry map defaults to empty, matching `new()`. |

## Verification Results

- Fresh-eyes diff review: only the accepted `Default` derive substitutions above are present.
- `rustfmt --edition 2024 --check src/service/load_balance.rs src/channel/verification_suite.rs src/monitor.rs src/link.rs src/trace/distributed/crdt.rs src/trace/distributed/vclock.rs`: pass.
- `git diff --check`: pass.
- `rch exec -- cargo check -p asupersync --all-targets`: pass.
- `rch exec -- cargo test -p asupersync --lib link --no-fail-fast`: pass, 78 passed.
- `rch exec -- cargo test -p asupersync --lib trace::distributed --no-fail-fast`: failed on two pre-existing missing insta snapshot baselines, `canonical_trace_id_serialization_snapshot` and `canonical_vector_clock_serialization_snapshot`; the prior artifact `refactor/artifacts/20260424T2312Z-isomorphic-simplification/tests_before.txt` records the same two failures before this cycle.
- `rch exec -- cargo clippy -p asupersync --all-targets -- -D warnings`: pass.
