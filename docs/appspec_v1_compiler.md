# AppSpec v1 compiler — generated topology

> Bead: `asupersync-idea-wizard-fifth-wave-3gaiun.2.2` ([APPSPEC][A2]).
> Scope: how a validated [`AppSpecV1`](appspec_v1.md) manifest is lowered into
> explicit Asupersync runtime wiring. This document covers the compiler/lowering
> surface only and makes **no broad runtime-correctness claim**.

## Stages

The compiler is two pure, inspectable stages plus one runtime-bound lowering:

1. **Validate** — `AppSpecV1::validate()` enforces every cross-field invariant
   serde cannot express: schema discriminator, unique names, resolvable
   budget/resource/SLO/group references, absolute route paths, **no ambient
   authority** (every route/actor/job/sink declares its `Cx` capabilities), and
   the fail-closed compatibility policy.
2. **Plan** — `AppSpecV1::compiler_plan()` projects the manifest into an
   `AppSpecV1CompilerPlan`: the root group + restart policy, every supervision
   group, and one `AppSpecV1CompiledChild` per route/actor/background-job work
   unit (carrying effective budget, SLO hook, trigger, route binding, and
   authority requirements). The plan is **pure data** — it never resolves a
   handler string into a Rust function and never starts a task.
3. **Lower** — `AppSpecV1::compile_with_child_specs(children)` lowers the plan
   into the builder-style [`AppSpec`](../src/app.rs) by binding one explicit
   caller-supplied `ChildSpec` factory to each compiled work unit. Names and
   completeness are checked; task startup logic stays in the caller's factories,
   so there is **no hidden global wiring**.

The generated `AppSpec` then drives ordinary supervision: it is started under a
root region and stopped with the cancel-correct `close → drain → finalize →
quiescence` sequence.

## Generated topology report

`AppSpecV1CompilerPlan::topology_report()` (and the convenience
`AppSpecV1::topology_report()`) render the generated topology deterministically.
For the minimal `demo` fixture — one service with a route, an actor, and a
background job under a single `one_for_one` group — the report is:

```text
# AppSpec v1 generated topology
app: demo
root_group: core (one_for_one)
budgets: request, background

supervision:
  group core (one_for_one)
    service api
      route  api.route.ping  GET /ping -> demo::ping  budget=request  slo=ping_latency  caps=cx:net,trace|feat:native-runtime|res:public_socket
      actor  api.actor.warmer  -> demo::warmer  budget=background  caps=cx:spawn,time
      job    api.job.tick  trigger=interval(every_ms=1000) -> demo::tick  budget=background  slo=ping_latency  caps=cx:time|res:timer

observability:
  sink metrics (metrics)  caps=cx:trace|feat:metrics

no-claim boundaries:
  - Does not resolve handler symbols into Rust functions.
  - Does not start runtime tasks without caller-supplied ChildSpec factories.
  - Does not prove handler cancel-correctness or region quiescence.
```

Each work-unit line names the compiled child (`{service}.{kind}.{name}`), its
entrypoint, effective budget, optional SLO hook, the job trigger, and the
explicit authority block `cx:…|feat:…|res:…`. The same plan always renders
byte-identical text, so the report is usable as a documentation snapshot and as
an artifact row for the lab fixture/proof layer (A3).

## Fail-closed boundaries

- **Ambient authority** — a route/actor/job/sink with no declared `Cx`
  capabilities is rejected (`AmbientAuthority`); `pure` combined with any other
  authority is rejected (`PureAuthorityHasEffects`).
- **Unknown capability / feature tokens** — rejected at the serde boundary
  (`deny_unknown_fields` plus closed enums).
- **Multi-group runtime mapping** — `compiler_plan()` fully supports multiple
  supervision groups, but `compile_with_child_specs` lowers only a single group
  into the current builder `AppSpec`. A multi-group manifest fails closed with
  `UnsupportedRuntimeMapping` rather than silently flattening a restart
  boundary. Lowering nested sub-supervisors awaits a dedicated runtime
  sub-supervisor factory surface.
- **Stop-on-failure groups** — `restart_policy: stop` has no builder mapping yet
  and fails closed (`UnsupportedRuntimeMapping`).
- **Child-factory mismatch** — missing, duplicate, or unexpected factories all
  fail closed (`MissingChildSpec` / `DuplicateChildSpec` / `UnexpectedChildSpec`).

## Proof

`tests/appspec_v1_compiler.rs` proves the acceptance criteria as an integration
test (library linked in non-test mode):

- the minimal manifest lowers, starts under the lab runtime, and reaches
  **region-close quiescence with no orphan tasks** (`report.run.quiescent`,
  oracle report passes, no invariant violations);
- ambient-authority, unknown-token, and pure-with-effects manifests fail closed;
- the multi-group boundary is explicit and fail-closed;
- missing/duplicate/unexpected child factories fail closed;
- the topology report is byte-stable and complete.

## Reference journey & e2e ([APPSPEC][A4])

`examples/appspec_reference_journey.rs` is the runnable end-to-end journey a new
user can inspect: a single-service AppSpec (a `GET /health` + `POST /enqueue`
route surface, a startup worker, a bounded-queue drainer job, a public-socket
resource, per-unit/per-service budgets, a latency SLO hook, a trace
observability sink, and `one_for_one` supervision) declared as data, lowered
through the A2 compiler, and run on the lab runtime for seeds `1/2/3`. Each seed
reaches region-close quiescence with no orphan tasks, and replay reproduces an
identical Foata-canonical trace fingerprint — so determinism is demonstrated,
not asserted. The journey also rehearses failure: a multi-group manifest fails
closed at builder lowering rather than silently mis-wiring.

Child factories are caller-supplied `ChildSpec`s created via
`state.create_task(region, budget, …)`, so `Cx`/region semantics stay explicit —
the example shows why AppSpec beats ad hoc wiring **without** hiding the
capability and region plumbing.

`scripts/run_appspec_reference_journey_e2e.sh` runs the example through `rch`
(remote-required; no local cargo fallback) and persists its stdout into diffable
e2e artifacts under `target/e2e-results/appspec_reference_journey/run_<id>/`:

- `events.ndjson` — the structured lifecycle log (one JSON object per line);
- `summary.json` — the aggregate (`trace_fingerprints`, `deterministic_replay`,
  `orphan_tasks`, `failure_rehearsal`, and the line-count/ergonomics note);
- `topology.txt` — the byte-stable generated topology report;
- `run_report.json` — the validator verdict.

The script asserts the contract (every seed quiescent and orphan-free, replay
deterministic across all seeds, and the failure rehearsal fail-closed), exiting
non-zero on any drift. Re-validate a captured run offline with
`--from-output <example-stdout-file>`.
