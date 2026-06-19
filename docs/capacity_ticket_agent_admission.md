# Capacity Ticket Agent Admission

Bead: `asupersync-capacity-ticket-agent-admission-od29tn`

## Purpose

The capacity-ticket API gives agent-swarm admission code an explicit value to
carry after a capability-budget check succeeds. A ticket records the owner
region, owner task, effective budget envelope, required dimensions, work kind,
and reason that justified admission.

The API is intentionally small. It does not schedule work, reserve remote
machines, or start background tasks. It turns an existing `Cx` budget or a
captured parent budget into a deterministic receipt-bearing ticket that can be
split, lent, released, revoked, or audited as unreleased.

## API

The public surface lives under `asupersync::cx::capacity_ticket` and is
re-exported from `asupersync::cx`:

- `CapacityTicketRequest`
- `CapacityTicketWorkKind`
- `CapacityTicket`
- `CapacityTicketId`
- `CapacityTicketReceipt`
- `CapacityTicketReceiptStatus`
- `CapacityTicketRefusal`
- `request_capacity_ticket`
- `request_capacity_ticket_from_budget`

`request_capacity_ticket(&Cx, admission_sequence, request)` reads only the
explicit context owner, a non-zero root-admission sequence, and the capability
budget planner. `request_capacity_ticket_from_budget(...)` is for operator
fixtures and contract tests that have already captured the parent budget, owner
IDs, and root-admission sequence and must not look up ambient runtime state.

## No Ambient Authority

Tickets are plain value objects. There is no global ticket registry, no
thread-local lookup, no environment read, and no runtime side effect. Owner
identity is copied from `Cx::region_id()` and `Cx::task_id()` or supplied
directly to the budget-only entry point.

Child tickets use `CapabilityBudget::plan_child`, so they can only inherit or
tighten the parent envelope. Lend operations require explicit borrower
`RegionId` and `TaskId`; they do not infer ownership from ambient context.

## Failure Policy

Required resource dimensions fail closed through
`CapabilityBudgetRequirements`. A missing required memory, CPU, I/O, cleanup, or
artifact envelope returns `CapacityTicketRefusal` with the underlying
`CapabilityBudgetRefusal`.

Release and revoke consume the ticket and return leak-free receipts. If an
active ticket reaches an audit boundary without either action,
`unreleased_receipt()` mutably marks that terminal audit observation and returns
a fail-closed receipt with `obligation_leak_free=false`. Debug builds assert if
a live ticket is dropped without release, revoke, or unreleased audit receipt.

## Scope Limits

This lane does not enable automatic scheduler admission, governor policy, host
throughput claims, latency claims, fairness claims, broad workspace health, or
RCH fleet availability. It only proves the source/API/contract behavior listed
in `artifacts/capacity_ticket_agent_admission_contract_v1.json`.

## Validation

Non-Rust syntax and contract checks may run locally:

```bash
jq empty artifacts/capacity_ticket_agent_admission_contract_v1.json
rustfmt --edition 2024 --check src/cx/capacity_ticket.rs src/cx/mod.rs tests/capacity_ticket_agent_admission_contract.rs
```

Cargo validation must go through remote-required RCH:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_capacity_ticket_agent_admission CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test capacity_ticket_agent_admission_contract -- --nocapture
```
