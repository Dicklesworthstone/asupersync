# Persistent membership fencing

`distributed::membership::durable` adds an optional disk-backed authority
lifecycle without changing existing volatile controllers or the V1 wire. It
preserves accepted incarnation/sequence/terminal decisions across process
restart. It does not restore old runtime obligations, leases, tasks or network
sessions, and it does not elect an authority or detect peer liveness.

## Provision and recover before serving

Create a `MembershipJournalConfig` from independent local authority: authority
identity and epoch, statement-verification key, a separate journal key, initial
member floors, controller bounds, and `max_journal_bytes`. The initial member
set/floors, epoch and both keys are bound into the authenticated header. Reopen
with that initial configuration; do not replace it with guessed current floors.
The log restores the accepted decisions, including terminal incarnations.

Pass an exclusively owned regular read/write `File` to `MembershipJournal::create`
(empty files only) or `open` (existing files only). Persist its directory linkage
as required by the filesystem before exposing the service. Paths, permissions,
directory syncing, encrypted storage and file lifecycle remain caller authority.
The store never opens a pathname, truncates, deletes, repairs, evicts or compacts.
Keep the descriptor exclusive: do not clone/inherit it, unlock it elsewhere, or
modify its bytes through noncooperating writers. Lock support and sync are
required; unsupported operations fail rather than falling back.

Each append reuses the existing membership policy before writing. Stale sequence,
old incarnation, same-incarnation resurrection, equivocation and forged updates
are rejected without changing disk or the current policy. A duplicate of the
latest accepted decision for that member is idempotent, including at capacity.
Only after the whole authenticated record is written and `sync_all` succeeds is
the new decision published. An uncertain write/sync poisons that journal owner;
a complete unacknowledged append may become visible after successful reopen.

The format authenticates lengths independently of record bodies and chains the
record number, previous tag and original signed decision. Reopening checks every
complete record and statement, replays the policy, and syncs before exposing it.
A partial final record preserves the complete prefix in `ReadOnlyTail`; no new
decisions can be appended there. Complete corruption rejects the open rather
than silently reverting to earlier acknowledged state. Retained memory contains
one bounded latest statement per member. Append validation work is proportional
to that configured member set; replay is also bounded by journal size. These are
logical/count bounds, not an exact RSS or power-failure guarantee.

Authentication does not encrypt the file or defeat rollback by an actor able to
replace the whole file with a previously valid prefix. Use an independently
trusted head/witness or protected storage when that threat matters. This API
never claims to establish the newest authority from disk contents alone.

## Connect durable decisions to running work

Consume the recovered journal in `PersistentMembershipController::new(journal,
clock)`, then share it through `Arc`. Construction projects all recovered latest
decisions into a private `OwnedMembershipController` before exposing grants. No
mutable volatile-controller escape is provided. The journal and live policy
cannot independently advance through this API.

`try_grant`, `expire`, `run`, and `run_scoped` retain the existing checked runtime
ownership and child-region drain contracts. Each guard stays in its admitting
task. Scoped work drives its finite lease deadline; bare guards require the
owned expiry driver or explicit expiry calls. Driver cancellation/drop and
explicit `close` close local admission; this local shutdown does not manufacture
or persist a new membership statement. A rejoined member still needs a strictly
newer authenticated incarnation. No pre-restart guard is recreated.

For direct local updates, `Arc<PersistentMembershipController>::apply_blocking`
accepts the locally authenticated peer and signed bytes. It is a synchronous
API for blocking workers. For network updates, register
`register_persistent_membership_service` instead of the volatile membership
registration, and use the existing `submit_membership_update` with V1. Build the
normal certificate-bound policy and grant only the intended authority. Both the
admitted peer identity and independent statement authentication are checked.

Configure a real context blocking pool. Missing pool or spawn authority refuses
before disk I/O; there is no inline executor fallback. One controller-wide update
slot is taken before request copying/spawn, shared across registrations and Arc
clones. Queued or running jobs own that slot. Dropping a not-yet-started job
returns the untouched journal. A running job retains ownership if its network
waiter is dropped; the owning runtime must drain it.

The file is removed from its short mutex slot while the worker runs, so neither
disk sync nor arbitrary lease notifications hold that mutex. Grant operations do
not block behind disk I/O. Reentrant updates see `Busy` instead of deadlocking or
overtaking the original update. A synced decision is projected through the normal
checked abort/commit machinery before the success echo. Any uncertain append or
failed/panicking projection closes grants and aborts existing local leases before
returning the file slot. Reopen is required to resume that controller lifecycle.

During an in-progress append, existing leases still follow the last published
decision. The new decision is not acknowledged until persistence and projection
complete. A rejected update is not applied, and callers must handle refusal;
capacity does not silently evict history to make it succeed. The ordinary V1 echo
does not negotiate durability with arbitrary third-party implementations: backend
selection is an operator responsibility. A receipt is not a remote-work drain or
rollback certificate. Once a disk syscall starts, cancellation cannot preempt it.

## Validation

```sh
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p asupersync --lib distributed::membership::durable::
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p asupersync --features tls,test-internals --test membership_persistent_native -- --nocapture
```

Unit regressions cover actual journal files plus fault injection into the same
journal engine, checked LabRuntime obligations, queue ownership and reentrant or
panicking wake callbacks. The native process test accepts Alive/Dead via the
actual mTLS service, terminates its owned process after acknowledgement, opens
the same file in a new process, rejects replay/resurrection, and allows fresh
scoped work only for the new incarnation. It uses the old backend's schema to
construct the client hello, testing wire compatibility. A missing-pool test must
reach application refusal without any append. Files are deliberately retained;
watchdog cleanup reaps only owned children and fails acceptance. Authored tests
are not execution evidence until the commands run. Process death is not proof of
power-loss behavior across all filesystems and devices.
