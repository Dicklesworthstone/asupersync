# Asupersync On-Ramp

This guide starts with a normal async entry point and adds one layer at a time.
Every level is a complete program under `examples/`; the commands below compile
and run those exact files.

| Level | Add these concepts | Example |
| --- | --- | --- |
| 0 | Attribute entry point; no runtime concepts yet | [`onramp_level0.rs`](../examples/onramp_level0.rs) |
| 1 | Prelude, `Cx`, `Outcome`, and `Budget` | [`onramp_level1.rs`](../examples/onramp_level1.rs) |
| 2 | Scope, region ownership, policy, and `JoinSet` | [`onramp_level2.rs`](../examples/onramp_level2.rs) |
| 3 | Obligations, two-phase effects, and deterministic lab oracles | [`onramp_level3.rs`](../examples/onramp_level3.rs) |

## Level 0: enter the runtime

Start with the attribute macro and one import:

```rust
use asupersync::main;

#[main]
async fn main() {
    println!("hello from asupersync");
}
```

`#[main]` builds and drives the production runtime. There is no builder,
executor handle, or capability to learn before the first program runs.

```bash
cargo run --example onramp_level0
```

## Level 1: name cancellation and resource bounds

Level 1 imports the curated prelude. `Cx` carries cancellation and runtime
capabilities. `Outcome<T, E>` preserves the difference between success,
ordinary failure, cancellation, and panic. `Budget` composes bounds with
`meet`, which keeps the tighter quota or deadline.

The complete program is
[`examples/onramp_level1.rs`](../examples/onramp_level1.rs):

```bash
cargo run --example onramp_level1
```

Keep ordinary domain errors in `Outcome::Err`. A cancellation request is
`Outcome::Cancelled`, not a made-up domain error, and a panic remains
`Outcome::Panicked`.

## Level 2: own fan-out

Tasks belong to regions. `cx.scope_with_budget(...)` returns a scope for the
current region with a budget no looser than its parent. `JoinSet::new(&scope)`
spawns every member through that scope and drains collected members:

```bash
cargo run --example onramp_level2
```

The default scope policy is `FailFast`. The policy controls how sibling
outcomes aggregate; it does not turn a task into detached work.

This API intentionally does not hide a new child-region allocation:
`cx.scope()` and `cx.scope_with_budget(...)` refer to the current region. Code
that needs a fresh child-region boundary uses the explicit `Scope::region`
state-threaded API. In both cases, the runtime owns every admitted task and
region close is the quiescence backstop.

Use `JoinSet::join_next` for completion order, `join_all` for spawn order, and
`cancel_all` when you want to request cancellation and drain the remaining
members explicitly.

## Level 3: prove the cleanup contract

The channel send in
[`examples/onramp_level3.rs`](../examples/onramp_level3.rs) is two-phase:
`reserve` waits cancel-safely, and `send` commits the reserved slot. Dropping an
uncommitted permit aborts it cleanly.

The same program then constructs a deterministic lab state whose completed task
still holds one deliberately unresolved `SendPermit` obligation. Panic-on-leak
is disabled so the example can inspect the report, and the `obligation_leak`
oracle must report failure:

```bash
cargo run --example onramp_level3
```

That failure is the lesson. Production code must resolve every obligation;
tests should make the lab prove the invariant instead of trusting cleanup
comments.

## Where to go next

- [`examples/README.md`](../examples/README.md) indexes every runnable example
  and scenario.
- [`TESTING_FOR_AGENTS.md`](../TESTING_FOR_AGENTS.md) chooses between unit,
  lab, exploration, and scenario tests.
- [`docs/macro-dsl.md`](macro-dsl.md) covers `scope!`, `spawn!`, `join!`, and
  `race!`.
- [`docs/cancellation-testing.md`](cancellation-testing.md) goes deeper on
  deterministic cancellation injection and cleanup oracles.
