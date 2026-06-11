# Deadline Propagation: Min-Plus Composition Across Hops

> br-asupersync-server-stack-hardening-eeexl1.1 (D1 chain). Server-hop
> install is D1.1 (`br-asupersync-server-stack-hardening-eeexl1.1.1`);
> outbound forwarding is D1.3
> (`br-asupersync-server-stack-hardening-eeexl1.1.3`).

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

## Where each piece lives

| Hop | Mechanism | Code |
|-----|-----------|------|
| h1 server install | `derive_request_budget` meet of connection budget, `Http1Config::request_timeout`, cap-clamped `Request-Timeout` header; request Cx minted per request | `src/web/request_region.rs`, `src/http/h1/server.rs` |
| h2/gRPC server install | `CallContext` deadline (cap-clamped `grpc-timeout`) tightens the per-request Cx budget | `src/grpc/server.rs` |
| gRPC outbound | base = per-request `grpc-timeout` override or channel default, then meet with remaining ambient budget; encoded back onto the wire | `src/grpc/client.rs` (`apply_channel_metadata_defaults`) |
| HTTP outbound | total-timeout race = meet of remaining budget, `HttpClientConfig::request_timeout`, per-call override (`request_with_timeout`) | `src/http/h1/http_client.rs` (`drive_with_budget_deadline`) |

## Trace events at the hops

Budget flow is observable as structured trace events (currently emitted as
`user_trace` messages with stable prefixes; first-class kinds tracked by
`br-asupersync-x6wffh`):

- `server.budget_installed proto=<h1|h2-grpc|…> source=<inherited|config|header|config+header> deadline_ns=… poll_quota=… cost_quota=… priority=…`
- `server.budget_consumed proto=… outcome=<ok|cancelled|panicked|deadline_exceeded|connection_lost> elapsed_ns=… deadline_remaining_ns=…`
- `client.budget_forwarded proto=<grpc|h1> base=<override|channel|none> remaining_ns=… grpc_timeout=…` (gRPC)
- `client.budget_forwarded proto=h1 remaining_ns=… total_timeout_ns=…` (HTTP)

## Failure mapping

| Condition | h1 server | gRPC client | HTTP client |
|-----------|-----------|-------------|-------------|
| Deadline already expired at hop entry | request rejected before handler | `Status::deadline_exceeded` (fail-fast, nothing sent) | `ClientError::DeadlineExceeded` (fail-fast) |
| Deadline fires mid-exchange | cancel → bounded drain → `503` | existing timeout race → `DEADLINE_EXCEEDED` (region cancelled first) | future dropped (pooled connection discarded) → `ClientError::DeadlineExceeded` |
