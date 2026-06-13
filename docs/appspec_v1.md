# Declarative AppSpec v1

`AppSpecV1` is the versioned, serde-friendly application topology contract for
SPORK applications. It lives beside the builder-style `AppSpec` in `src/app.rs`:
v1 defines the checked manifest shape, while the follow-on compiler layer maps
that manifest into runtime regions, supervisors, and service wiring.

The canonical schema discriminator is:

```text
asupersync.appspec.v1
```

The checked JSON schema artifact is
`artifacts/appspec_v1_schema.json`.

## Model

An AppSpec v1 manifest declares:

- services, each with routes, actors, and background jobs;
- named resources such as sockets, timers, databases, message buses, remote
  nodes, or browser host bridges;
- named budgets for service roots and individual work units;
- SLO hooks for latency, error rate, throughput, and saturation policy;
- a supervision topology over declared services;
- observability sinks and the authority they need;
- an embedded compatibility policy that keeps v1 fail-closed.

The current A1 contract intentionally does not start tasks or allocate regions.
It gives the compiler a deterministic input shape with enough authority metadata
to reject hidden effects before runtime wiring exists.

## Compiler Plan

`AppSpecV1::compiler_plan()` lowers a validated manifest into a deterministic
plan for the runtime compiler. The plan contains:

- the application name and root supervision group;
- supervision groups and their restart policies;
- one child-factory requirement for every route, actor, and background job;
- route bindings, background-job triggers, budget names, SLO hook names, and
  required capability declarations;
- observability sink wiring requirements;
- no-claim boundaries for handler resolution and runtime correctness.

Child names are stable and explicit:

```text
<service>.route.<route>
<service>.actor.<actor>
<service>.job.<job>
```

For example, the `payments` sample route named `readiness` in service `api`
compiles to the child-factory key `api.route.readiness`.

`AppSpecV1::compile_with_child_specs(...)` is the first runtime bridge. It
accepts caller-supplied `ChildSpec` factories keyed by those compiled child
names, verifies that every required child is present and no extra child is
smuggled in, and then returns the existing builder-style `AppSpec`. The bridge
currently supports a single root supervision group; manifests with topology that
cannot be represented by the current builder fail closed instead of being
partially lowered.

The compiler does not resolve a string such as `crate::payments::ready` into a
function pointer. Rust code must provide the actual `ChildSpec` start factory,
which keeps runtime setup inspectable and prevents hidden global registries or
ambient handler lookup.

## No Ambient Authority

Every route, actor, background job, and observability sink has a required
`required_capabilities` object:

```json
{
  "cx_capabilities": ["net", "trace"],
  "feature_flags": ["native-runtime", "tracing-integration"],
  "resources": ["public_socket"]
}
```

The `cx_capabilities` list must be nonempty. Unknown capability strings fail
serde deserialization, and the Rust validator rejects empty declarations. A pure
entry point must say so explicitly with:

```json
{
  "cx_capabilities": ["pure"],
  "feature_flags": [],
  "resources": []
}
```

`pure` cannot be combined with any other capability, feature flag, or resource.
That rule keeps effect-free code explicit without leaving a place for unsupported
or ambient effects to hide.

## Validation

`AppSpecV1::validate()` checks the cross-field rules that JSON schema cannot
express cleanly:

- `schema_version` must equal `asupersync.appspec.v1`;
- names in each declared collection must be unique and nonempty;
- budget, resource, SLO hook, service, and supervision references must resolve;
- route paths must be absolute;
- budgets must contain at least one limiting dimension;
- supervision groups must supervise at least one declared service;
- the embedded compatibility policy must remain fail-closed.

Serde additionally rejects unknown fields through `deny_unknown_fields` on each
v1 struct and rejects unknown enum values for capabilities, feature flags,
resource kinds, route methods, triggers, SLO hooks, and sink kinds.

## Compatibility Policy

AppSpec v1 is a fail-closed contract. A manifest must carry:

```json
{
  "fail_closed_unknown_fields": true,
  "fail_closed_unknown_capabilities": true,
  "future_schema_requires_new_version": true
}
```

Future incompatible widening gets a new schema discriminator instead of a
compatibility shim. Additive fields are not accepted silently in v1 because
unknown fields are rejected; the compiler must know what authority and topology
every field means before it can safely run an application.

## No-Claim Boundaries

AppSpec v1 does not claim that:

- a manifest can compile into a running `AppSpec` without explicit child
  factories;
- handlers, actors, or jobs named in the manifest exist;
- any handler is cancel-correct;
- every possible runtime capability is represented forever;
- schema acceptance is a stability or backwards-compatibility promise.

Those claims need separate compiler, downstream-consumer, and runtime proof
lanes.
