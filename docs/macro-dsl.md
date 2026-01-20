# Structured Concurrency Macro DSL

This document describes the Asupersync macro DSL for structured concurrency:
`scope!`, `spawn!`, `join!`, `join_all!`, and `race!`.

The macros are designed to reduce boilerplate while preserving Asupersync
invariants: structured concurrency, cancellation correctness, and deterministic
testing.

## Enable Macros

Enable the `proc-macros` feature and import the macros you need.

```toml
[dependencies]
asupersync = { path = ".", features = ["proc-macros"] }
```

```rust
use asupersync::proc_macros::{scope, spawn, join, join_all, race};
```

## Quick Start (Runnable)

This snippet is fully runnable today because it only uses `join!`.

```rust
use asupersync::proc_macros::join;
use asupersync::runtime::RuntimeBuilder;

fn main() {
    let rt = RuntimeBuilder::current_thread()
        .build()
        .expect("runtime");

    let (a, b) = rt.block_on(async {
        join!(async { 1 }, async { 2 })
    });

    assert_eq!(a + b, 3);
}
```

## Phase 0 Status Notes

The macro DSL is usable in Phase 0, but some runtime wiring is still in
progress. Keep the following in mind:

- `scope!` currently calls `Cx::scope()` which binds to the existing region
  (child regions will be added in later phases).
- `spawn!` requires a `__state: &mut RuntimeState` variable to exist in scope.
  This is pending fuller runtime integration.
- `race!` expands to `Cx::race*` methods that are planned but not yet implemented.
- `join!` is sequential in Phase 0. Concurrency comes in later phases.

These are *phase limitations*, not permanent API choices.

## Macro Reference

### scope!

Create a structured concurrency scope. The macro binds a `scope` variable inside
the body.

**Syntax**

```rust
scope!(cx, { ... })
scope!(cx, "name", { ... })
scope!(cx, budget: Budget::INFINITE, { ... })
scope!(cx, "name", budget: Budget::INFINITE, { ... })
```

**Expansion (conceptual)**

```rust
{
    let __cx = &cx;
    let __scope = __cx.scope();
    async move {
        let scope = __scope;
        /* body */
    }.await
}
```

**Notes**

- `scope!` always inserts `.await`, so it must be invoked inside an async context.
- `return` is rejected inside the body. Use early-return patterns instead.

### spawn!

Spawn work inside the current `scope`.

**Syntax**

```rust
spawn!(future)
spawn!("name", future)
spawn!(scope, future)
spawn!(scope, "name", future)
```

**Expansion (conceptual)**

```rust
scope.spawn_registered(__state, __cx, |cx| async move { future.await })
```

**Notes**

- `spawn!` expects `__state: &mut RuntimeState` and `__cx: &Cx` to be in scope.
- The handle is returned immediately; scheduling is handled by the runtime.

### join!

Join multiple futures and return a tuple of results.

**Syntax**

```rust
join!(f1, f2, f3)
join!(cx; f1, f2, f3)
```

**Notes**

- Phase 0: sequential awaits (still correct, just not parallel).
- `cx;` is reserved for future cancellation propagation.

### join_all!

Join multiple futures and return an array.

**Syntax**

```rust
join_all!(f1, f2, f3)
```

**Notes**

- All futures must return the same type.
- Useful when you want to iterate results.

### race!

Race futures and return the first completion. Losers are cancelled and drained.

**Syntax**

```rust
race!(cx, { f1, f2 })
race!(cx, { "fast" => f1, "slow" => f2 })
race!(cx, timeout: Duration::from_secs(5), { f1, f2 })
```

**Notes**

- Requires `Cx::race*` methods (planned).
- Semantics: winners return first, losers are cancelled and drained.

## Patterns

### Fan-out / fan-in

```rust,ignore
scope!(cx, {
    let h1 = spawn!(async { fetch_a().await });
    let h2 = spawn!(async { fetch_b().await });
    let (a, b) = join!(h1, h2);
    (a, b)
})
```

### Timeout wrapper

```rust,ignore
let value = race!(cx, timeout: Duration::from_secs(2), {
    long_operation(),
    async { Err(TimeoutError) },
});
```

### Nested scopes with tighter budgets

```rust,ignore
scope!(cx, {
    scope!(cx, budget: Budget::deadline(Duration::from_secs(5)), {
        // inner work with tighter budget
    });
})
```

## Migration Guide

Manual API usage (today):

```rust,ignore
let scope = cx.scope();
let (handle, stored) = scope.spawn(&mut state, &cx, |cx| async move { work(cx).await })?;
state.store_spawned_task(handle.task_id(), stored);
let result = handle.join(&cx).await?;
```

Macro DSL (intended):

```rust,ignore
scope!(cx, {
    let handle = spawn!(async { work(cx).await });
    let result = handle.await;
    result
})
```

## Examples

Example binaries live in `examples/`:

- `examples/macros_basic.rs`
- `examples/macros_race.rs`
- `examples/macros_nested.rs`
- `examples/macros_error_handling.rs`

Run with:

```bash
cargo run --example macros_basic --features proc-macros
```
