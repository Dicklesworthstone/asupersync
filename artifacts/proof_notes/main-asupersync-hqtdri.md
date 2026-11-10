# Phase 6 proof note: coherent tracked-name handoff

Bead: `asupersync-hqtdri`

Review base: `b3af21c01724cf9cfd3602dfe5200740596558a0`

## Defect and change

`TrackedNameLease::try_transfer` previously took its runtime token out of the
guard, invoked the consuming token transfer (including an arbitrary notifier),
and only then rebound the name and restored the token. A notifier panic aborted
the unreturned destination credit while leaving the guard with a live name and
no token. Its destructor then panicked at the missing-credit assertion, which
could abort the process during unwinding. A missing or replaced raw registry
entry could also be discovered only after an irreversible credit handoff.

The adapter now validates the complete registration identity before transferring
credit and holds the registry lock through name rebinding. A crate-private
deferred transfer returns the destination token and notification separately.
The guard installs that token and rebinds discovery using the token's actual
holder and region, then releases the lock before notifying. It also retains the
source gateway before acquiring the registry lock. Transfer preparation's
temporary gateway upgrade therefore cannot be the last owner that destroys
arbitrary notifier captures under that lock if the source context disappears
concurrently. Opaque admission-retention guards similarly pin both source and
destination region storage before the lock is acquired. Without those pins,
concurrent runtime teardown could make transfer's temporary region upgrades the
last owners of a region heap or descendant panic payload.

All three retainers are declared outside the registry lock's lexical block.
Consequently success, refusal, and unwinding release the registry lock before
gateway captures or retained region payloads can be destroyed. Retention only
upgrades weak ownership; the existing transfer protocol still authoritatively
checks runtime identity, cancellation, region state, holder liveness, and quota.
The pins last only for the transfer call and add no required public fields.

## Ownership and cancellation argument

- A registry refusal occurs before the original token is removed. Identity
  validation compares the holder, region, acquisition time, and unique
  registration incarnation; equal owner/time values cannot authorize an ABA
  replacement. A runtime transfer refusal returns the original token, which the
  guard restores before returning the error. No refused path rebinds the name.
- An accepted handoff uses the existing checked-credit transfer protocol. Its
  region admission gates, ordered by region identity for cross-region movement,
  protect destination admission, source credit release, and handoff publication.
  This change does not replace that protocol or alter its terminal decisions.
- Registry validation and rebinding share one exclusive lock. The deferred
  operation has no arbitrary notification callback. Consequently the registry
  cannot be replaced between validation and rebinding, and observers acquiring
  that lock see the old ownership before the operation or the new ownership
  after publication. Source quota is returned synchronously by the underlying
  checked transfer, without waiting for mailbox projection.
- Before a notifier can run, the surviving guard owns both the rebound raw lease
  and the destination runtime token. A notifier panic therefore leaves a
  committed handoff that can be released or aborted by that guard. Existing
  checked settlement suppresses secondary notifier callbacks during unwinding;
  guard cleanup removes discovery and returns quota under the registry lock.
- The public consuming `ObligationToken::try_transfer` retains its existing
  contract: if notification panics before the new token is returned, that
  unreturned destination credit aborts. It explicitly enables abort-on-drop
  around notification. Its existing panic regression remains applicable.

There is no new unsafe block, dependency, public method signature, required
field, or cancellation checkpoint. This is a local ownership/publication
argument, not a blanket proof of all scheduler interleavings or a performance
claim. Forgetting a guard still retains its documented runtime leak liability.

## Regression coverage supplied

All new tests are in `src/cx/tracked_registry_tests.rs`:

- `lease_transfer_refusals_preserve_ownership_and_cross_region_handoff_returns_quota`
  checks same-holder and destination-quota refusals preserve ticket and owner,
  then checks an accepted cross-region handoff and immediate source-quota reuse.
  It exercises both an already materialized reservation and one awaiting drain.
- `lease_transfer_validates_name_incarnation_before_moving_runtime_credit`
  injects a missing entry and a same-owner, same-time replacement into the
  private registry. Both must refuse without posting a handoff; later cleanup
  must not remove the replacement registration.
- `lease_transfer_notifier_panic_preserves_committed_owner_and_safe_cleanup`
  checks unlocked notification observes the new owner, the panicked operation
  retains its destination token, and ordinary Drop and unwind Drop remove the
  name without leaking credit or causing a secondary panic. It catches the old
  missing-token cleanup panic separately so a regression can fail diagnostically
  rather than aborting the whole test process.

- `lease_transfer_drops_source_gateway_captures_after_registry_unlock` holds
  the region admission gate while a transfer upgrades its source gateway, then
  drops the last external gateway owner. A destructor probe verifies notifier
  captures are destroyed only after the registry unlocks. The fixture uses a
  bounded rendezvous and no production hook or panicking destructor.

The existing
`checked_transfer_notify_unwind_aborts_destination_once_without_secondary_notify`
test must also pass to guard the public consuming-token contract. Shared test
cleanup checks balanced reservation/terminal counters, posted/applied receipts,
zero open tickets, zero runtime leaks, and the Lab invariant/oracle reports.

## Validation status and required receipts

**This code was not compiled or executed in this session.** RCH was unavailable
and the workspace execution service failed. No local Cargo fallback was used.
The files were recovered from the review base and assembled using exact,
unique-context manually authored hunks. Static inspection is not an
old-red/new-green receipt.

Run the following through RCH on the actual landed tree, retaining the worker
receipt and command output:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_hqtdri CARGO_INCREMENTAL=0 cargo check --all-targets --keep-going
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_hqtdri CARGO_INCREMENTAL=0 cargo clippy --all-targets -- -D warnings
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_hqtdri CARGO_INCREMENTAL=0 cargo test -p asupersync --features test-internals --lib cx::tracked_registry -- --nocapture
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_hqtdri CARGO_INCREMENTAL=0 cargo test -p asupersync --features test-internals --lib checked_transfer_notify_unwind_aborts_destination_once_without_secondary_notify -- --nocapture
```

Apply the repository's pinned formatting gate as well. Under `AGENTS.md`
Validation Path rule 3, an API landing without compilation must cite the bead
and the missing execution evidence. The watchdog must supply an RCH receipt
within two hours; a red receipt or no green receipt after six hours requires a
P0 bead naming the commit and a repair-forward owner. This note does not assert
that the watchdog ran, and the bead must not be closed on this static argument.
