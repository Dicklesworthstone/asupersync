# Revoke one resumable-transfer client without stopping every client

The shared native resume service now exposes `revoke_client`,
`is_client_revoked`, and `revoked_clients`. These methods live on
`ResumableService<W>` under
`asupersync::net::atp::sdk::native_auth::live::commit::resume::service`.
They apply to both ordinary sink factories and committed-receipt restoration.
The existing protocol and receiver APIs are unchanged.

## Authority removal versus task completion

A manager can revoke an explicitly selected full client-certificate fingerprint:

```rust,ignore
let change = service.revoke_client(
    compromised_certificate,
    CancelReason::user("operator revoked transfer authority"),
)?;
// change is a cancellation/admission observation, not a terminal receipt.
// Keep driving next/next_restoring to collect actual connection results.
```

The service installs a lifetime denial before signalling any routed worker for
that certificate. The check is in routing, after authentication is collected
but before key admission, sink creation, or restoration. A TLS handshake that
was already verified cannot slip through on its old authorization decision.
New nonces do not bypass a certificate denial. Refused routes consume no new
session key, resident sink, factory invocation, or application storage claim.

Only matching workers receive cancellation. The listener and unrelated client
workers remain available. Handshakes that have not yet supplied an authenticated
key remain under their existing operation timeout and connection budget; once
identified, they are refused at routing. Revocation does not prematurely drop
those sockets or claim their identity was known earlier.

The TLS allowlist is a separate, potentially shared policy. Also remove the
certificate using `NativeClientAuthorization::replace_allowed` when future TLS
handshakes should be rejected. Doing only that TLS replacement does not cancel
an already routed transfer. Doing only service revocation prevents routing but
does not save the cost of TLS handshakes. Apply both from the same managing
operation, without yielding admission between policy changes.

## Preserve outcomes and ownership

Cancellation is cooperative. A source/sink operation that already started may
complete, and an application commit is drained rather than abandoned. Its
actual result can be cancellation, failure, committed-without-Proof, or success
that finished before revocation. Do not rewrite it to fit the new policy.

`ResumeClientRevocation` separates `newly_revoked`,
`signalled_connections`, and `retained_sessions`. Signalling a handle does not
establish that a worker stopped; an uncollected terminal result is still counted
as an owned routed connection. Duplicate revocation is idempotent and does not
replace its first cancellation reason.

Revocation consumes no join and destroys no sink. `next`, `next_restoring`, or
`drain_next` still returns every canonical result. Until it is collected, the
session remains active and `retire` refuses it. Once idle, inspect
`session_snapshot` and call `retire` explicitly to release the sink while keeping
its refusal tombstone and last local publication observation. No file deletion,
storage refund, automatic receipt eviction, or rollback is implied.

The service's admission reservation remains alive through its ordinary lifetime;
revocation does not release capacity underneath a live child or pending commit.
A panic raised by an ordinary cancellation callback is rethrown only after the
other matching handles have also been signalled, with admission already denied.
Fatal process aborts and malicious panic-payload destructors are not recoverable
work-completion guarantees.

## Independent, bounded policy

A service retains at most `MAX_REVOKED_RESUME_CLIENTS` (1,024) distinct client
denials. This bound is independent of resident sessions and lifetime session
keys. Denials are never evicted when another client is revoked; duplicates use
no additional capacity. At the bound, `ResumeRevokeError::Capacity` means the
new requested revocation did **not** take effect. Stop admission/cancel the
service rather than interpreting an error as success.

After final drain, an already-recorded denial is still observable and duplicate
requests remain idempotent. A new denial on a drained service returns
`ResumeRevokeError::Drained`. The API cannot reopen a closed listener or restore
an identity during the same service lifetime.

This deny set is in memory. The application must durably record and reapply its
revocation policy on restart, and protect current client configuration and trust
roots. A checkpoint, committed receipt, session nonce, or prior TLS success does
not renew a revoked client's authority. This is not issuer-wide CRL/OCSP checking,
a global cross-service revocation authority, or a replacement for per-operation
capability grants. The foreground CLI does not gain a policy-reload command in
this change; applications call the new SDK control API explicitly.

## Tests and validation boundary

One bounded-policy unit test and eight native integration tests accompany the
implementation. Native tests cover two simultaneously parked clients with only
one revoked, a TLS connection predating revocation, a parked factory, draining
an in-flight application commit, preserving a previously successful uncollected
result, refusing access to saved receipts, and capacity/retirement boundaries.
The parked-write and parked-commit scenarios target current-thread and sharded
runtimes. Tests require exact cancellation reasons, sink byte counts, commit
counts, canonical joins, and native task/obligation quiescence. Public fixture
certificates are used; no production credentials are embedded.

These Rust tests have not been compiled or executed in the authoring environment.
Source preservation, patch application, and Git hashes do not establish runtime
correctness. Use the repository-authorized RCH validation route before deployment.
