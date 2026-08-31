# Compat Bridge

The canonical compatibility contract is `COMPAT-BOUNDARY.md`. Read it before
recommending a bridge.

In short, `asupersync-tokio-compat` supplies narrow, opt-in Tokio I/O,
hyper-trait, Tower-service, Asupersync-`Cx`, and cancellation adapters. It does
not start or install a Tokio runtime, does not satisfy
`tokio::runtime::Handle::current()`, and is not generic proof that reqwest,
axum, tonic, SQLx, or another Tokio-hosted stack can run on Asupersync.

Use a bridge only when:

1. the dependency's exact required traits match implemented adapter features,
2. Tokio types remain in one explicit boundary,
3. representative downstream compile and runtime tests cover cancellation,
   timers, ownership, and shutdown, and
4. the boundary has a removal plan.

Prefer native Asupersync surfaces whenever the migration is in scope.
