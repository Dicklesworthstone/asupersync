# Deadline Propagation: Min-Plus Composition Across Hops

> br-asupersync-server-stack-hardening-eeexl1.1 (D1 chain). Server-hop
> install is D1.1 (`br-asupersync-server-stack-hardening-eeexl1.1.1`);
> database statement timeouts + wire-level cancel are D1.2
> (`br-asupersync-server-stack-hardening-eeexl1.1.2`); outbound forwarding
> is D1.3 (`br-asupersync-server-stack-hardening-eeexl1.1.3`).

Asupersync propagates request deadlines structurally, not by convention:
every hop **meets** the deadlines it knows about, and a meet can only
tighten. The composition law is the tropical ("min-plus") semiring already
used by [`Budget`](../src/types/budget.rs): deadlines compose with `min`,
elapsed time composes with `+`.

## The composition law

At any hop, the *effective* deadline is the meet of every bound in scope:

```text
effective = min(remaining_budget, configured_default, per_call_override)
```

where `remaining_budget = budget.deadline − now` is what is left of the
*caller's* budget. Two properties follow directly:

1. **No extension, ever.** `min` is monotone non-increasing in each
   argument: adding a source can only tighten. A client header, a config
   default, or a per-call override can never push a deadline past what an
   upstream hop already imposed (the security property tested at both the
   h1 server and client hops).
2. **Hop chaining is associative.** `min(a, min(b, c)) = min(min(a, b), c)`
   — it does not matter in which order hops observe bounds, the end-to-end
   deadline is the tightest bound along the path. Elapsed time at each hop
   shrinks `remaining_budget` before the next meet, which is the `+` of
   the min-plus algebra.

## The path of one deadline

```text
  client                 h1/h2 server hop                handler            outbound client hop
    │                          │                            │                        │
    │  Request-Timeout: 5s     │                            │                        │
    ├─────────────────────────▶│                            │                        │
    │                          │ effective = min(            │                        │
    │                          │   connection budget,        │                        │
    │                          │   config.request_timeout,   │                        │
    │                          │   min(header, header_cap))  │                        │
    │                          │                            │                        │
    │                          │ mint request Cx            │                        │
    │                          │  budget.deadline = now+eff │                        │
    │                          ├───────────────────────────▶│                        │
    │                          │   [server.budget_installed]│                        │
    │                          │                            │  cx.budget().deadline  │
    │                          │                            ├───────────────────────▶│
    │                          │                            │                        │ effective' = min(
    │                          │                            │                        │   remaining budget,   ← deadline − now
    │                          │                            │                        │   client config,
    │                          │                            │                        │   per-call override)
    │                          │                            │                        │
    │                          │                            │                        │ gRPC: grpc-timeout: <effective'>
    │                          │                            │                        │ HTTP: total-timeout race
    │                          │                            │                        │  [client.budget_forwarded]
    │                          │                            │                        ├──────────▶ downstream
    │                          │◀───────────────────────────┤                        │
    │◀─────────────────────────┤ [server.budget_consumed]   │                        │
```

Each hop reads `now` from its timer driver (exact under lab virtual time),
so the same algebra is deterministic in `LabRuntime` tests and wall-clock
bound in production.

## Opt-in deadline jitter for wake smoothing

The deadline propagation law above stays exact. `Budget` deadlines are still
the cancellation and admission boundary, and `sleep_until` / `Sleep` preserve
same-deadline ordering unless a caller explicitly applies a jitter policy.

For thundering-herd smoothing, use
`asupersync::time::DeadlineJitterPolicy` at the point where a task registers a
timer or timed-lane wakeup. The policy takes a maximum non-negative slack, a
deterministic seed, a stable policy id for observability, and a scope:

| Scope | Identity input | Use when |
|-------|----------------|----------|
| `Task` | task id | many tasks share a region but can be spread independently |
| `Region` | region id | a whole request or tenant region should share one offset |
| `TaskAndRegion` | task id plus region id | default per-task smoothing that remains region-distinct |

The policy returns a decision with `original_deadline`,
`jittered_deadline`, `jitter`, `policy_id`, `task_id`, and `region_id`, and
emits the same fields as structured tracing data. The jittered deadline is
always `>= original_deadline` and saturates at `Time::MAX`, so smoothing never
wakes work before its exact budget deadline. Under `LabRuntime`, replay uses
the same seed and task/region ids, so the same workload produces byte-identical
jittered wake schedules.

Use jitter for best-effort wake registration and background maintenance
storms, not for tightening or extending budget propagation. If a downstream
hop receives a budget deadline, it should meet it with local config first and
then, only if smoothing is desired, jitter the local wake used to check or
resume that work.

## Where each piece lives

| Hop | Mechanism | Code |
|-----|-----------|------|
| h1 server install | `derive_request_budget` meet of connection budget, `Http1Config::request_timeout`, cap-clamped `Request-Timeout` header; request Cx minted per request | `src/web/request_region.rs`, `src/http/h1/server.rs` |
| h2/gRPC server install | `CallContext` deadline (cap-clamped `grpc-timeout`) tightens the per-request Cx budget | `src/grpc/server.rs` |
| gRPC outbound | base = per-request `grpc-timeout` override or channel default, then meet with remaining ambient budget; encoded back onto the wire | `src/grpc/client.rs` (`apply_channel_metadata_defaults`) |
| HTTP outbound | total-timeout race = meet of remaining budget, `HttpClientConfig::request_timeout`, per-call override (`request_with_timeout`) | `src/http/h1/http_client.rs` (`drive_with_budget_deadline`) |
| PostgreSQL queries | `SET statement_timeout` reconciled per query to meet of remaining budget (50ms-bucketed) and `set_statement_timeout_override`; managed SET is pool-safe (no discard poisoning) | `src/database/postgres.rs` (`apply_statement_timeout`), `src/database/mod.rs` (`wire_statement_timeout_ms`) |
| MySQL queries | `SET SESSION max_execution_time` (ms, `SELECT`-only per server semantics) reconciled identically; servers without the variable (ER 1193, e.g. MariaDB) degrade gracefully to client-side enforcement | `src/database/mysql.rs` (`apply_statement_timeout`) |
| SQLite operations | deadline-checking progress handler armed around each blocking-pool op; abort surfaces as `SqliteError::StatementTimeout` | `src/database/sqlite.rs` (`run_connection_op`) |

## Database hop: wire-level cancel in the drain phase

Cancellation observed mid-query does not just abandon the socket — each
client delivers a protocol-level cancel **inside the drain phase** and only
resolves `Outcome::Cancelled` after delivery completed (or the
connection-close fallback was taken and logged distinctly):

| Backend | Wire cancel | Bounding |
|---------|-------------|----------|
| PostgreSQL | `CancelRequest` (16-byte frame with the BackendKeyData identity) on a fresh plain-TCP socket, awaited | connect bounded by the 500ms-clamped cancel target; the frame write is checkpoint-free so it completes under a cancelled Cx |
| MySQL | `KILL QUERY <connection_id>` on a fresh connection, run under `commit_section` per-poll cancel masking | killer connect clamped to 500ms; bounded masked-poll budget guarantees the drain step terminates |
| SQLite | `sqlite3_interrupt` via the handle captured at open, then a masked re-receive waits for the blocking job to acknowledge | interrupt aborts the statement within one progress-handler window; bounded masked-poll budget on the drain wait |

Transaction/session-control statements (`COMMIT`, `ROLLBACK`, `BEGIN`,
`SET`, …) are exempt from both timeout reconciliation and drain-phase
kills: cleanup must never be aborted server-side by an almost-exhausted
budget.

## Trace events at the hops

Budget flow is observable as structured trace events (currently emitted as
`user_trace` messages with stable prefixes; first-class kinds tracked by
`br-asupersync-x6wffh`):

- `server.budget_installed proto=<h1|h2-grpc|…> source=<inherited|config|header|config+header> deadline_ns=… poll_quota=… cost_quota=… priority=…`
- `server.budget_consumed proto=… outcome=<ok|cancelled|panicked|deadline_exceeded|connection_lost> elapsed_ns=… deadline_remaining_ns=…`
- `client.budget_forwarded proto=<grpc|h1> base=<override|channel|none> remaining_ns=… grpc_timeout=…` (gRPC)
- `client.budget_forwarded proto=h1 remaining_ns=… total_timeout_ns=…` (HTTP)
- `client.budget_forwarded proto=postgres base_ms=<ms|none> remaining_ns=… statement_timeout_ms=<ms|default>` (PostgreSQL)
- `client.budget_forwarded proto=mysql base_ms=<ms|none> remaining_ns=… max_execution_time_ms=<ms|default>` and `client.budget_forwarded proto=mysql outcome=unsupported err_code=1193 …` (MySQL)
- `client.budget_forwarded proto=sqlite base_ms=<ms|none> remaining_ns=… statement_timeout_ms=…` (SQLite)
- `client.wire_cancel proto=<postgres|mysql|sqlite> outcome=<sent|interrupt_sent|send_failed|skipped> …` with `fallback=connection_close` / `drain=<job_completed|job_not_started|…>` detail on the non-sent paths (drain-phase wire cancel)

## Failure mapping

| Condition | h1 server | gRPC client | HTTP client | DB clients |
|-----------|-----------|-------------|-------------|------------|
| Deadline already expired at hop entry | request rejected before handler | `Status::deadline_exceeded` (fail-fast, nothing sent) | `ClientError::DeadlineExceeded` (fail-fast) | entry checkpoint observes exhaustion → `Outcome::Cancelled`, nothing sent |
| Deadline fires mid-exchange | cancel → bounded drain → `503` | existing timeout race → `DEADLINE_EXCEEDED` (region cancelled first) | future dropped (pooled connection discarded) → `ClientError::DeadlineExceeded` | server-side statement timeout aborts the statement (PG `57014` / MySQL ER 3024 / SQLite `StatementTimeout`); on Cx cancel: drain-phase wire cancel, then `Outcome::Cancelled` |

## Proof artifacts

The chain above is checked across complementary tiers, each scoped to what it
can prove deterministically:

- **Hop-level, lab-virtual (oracle-clean)**: the D1.1 server-hop lab matrix in
  `src/web/request_region.rs` (`tests::server_hop`, deterministic seeds for
  the normal / timeout / **client-disconnect** cells) proves region cancel,
  drain grace, and quiescence under virtual time with the runtime oracles green.
- **Wire-cancel frame (unit, loopback)**: `cancel_in_flight_sends_cancel_request_before_resolving`
  in `src/database/postgres.rs` proves the PostgreSQL `CancelRequest` handshake
  on a second connection — exact `BackendKeyData` identity, sent before the
  cancellation resolves — and the connection-close fallback when the cancel
  target is unreachable.
- **Budget-derived statement timeout (unit, wire bytes)**:
  `statement_timeout_derived_from_budget_alone` in `src/database/postgres.rs`
  pins the `SET statement_timeout` value produced from a Cx budget.
- **Chain-level, loopback wire (showcase)**:
  [`tests/e2e_deadline_db_wire_cancel_showcase.rs`](../tests/e2e_deadline_db_wire_cancel_showcase.rs)
  composes a request region with a real `PgConnection` against a scripted
  PostgreSQL backend over loopback TCP, under the production asupersync runtime.
  It asserts that the request-region budget reaches the DB as a
  `SET statement_timeout = <budget-ms>` on the wire and that the request budget
  deadline resolves the handler to `Outcome::Cancelled` (committed by the hop,
  not wedged) (br-asupersync-server-stack-hardening-eeexl1.1, AC2 + the
  region→DB cancellation composition).

A fully-composed *live* showcase — the in-region query reaching the `SELECT`,
parking, and the drain dialing the `CancelRequest` over loopback in one flow —
is tracked by `br-asupersync-rr849p`: a request-region-wrapped `PgConnection`
currently parks on the read immediately after the budget-derived `SET` write
and is only re-woken by the budget timer, so the query never advances to the
`SELECT` whose drain would dial the cancel. The wire-cancel mechanism and the
region/drain/disconnect behavior are independently proven by the unit and
lab-virtual tiers above.
