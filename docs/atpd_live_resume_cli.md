# Retained-session recovery from the foreground command

`atpd-live send-resumable` and `atpd-live receive-resumable` connect the existing
`atp-live-resume/1` SDK sessions to independent foreground processes. They
recover a **connection while both processes remain alive**, not a process crash.
The existing `send`, `serve`, `atpd start`, JSON schemas, TLS policy, and wire
profiles are unchanged. This is one transfer per receiver process, not a shared
multi-client resume registry.

The implementation and its tests require the same native Unix `atp-cli` profile
as `atpd-live`. They have not been compiled or executed in the authoring
environment. Use the repository-authorized validation route before deployment.

## Running a transfer

Use the existing sender settings. For the receiver, use the existing receiver
settings with exactly one entry in `clients` and `max_connections` equal to one.
All existing trust, private-directory, input-size, and retained-inbox validation
continues to apply. The two command names explicitly opt into retry behavior;
no existing command silently starts retrying.

```sh
atpd-live receive-resumable \
  --config /srv/atp/receiver.json \
  --attempts 8 \
  --retry-delay-ms 250 \
  --proof-recovery-secs 30

atpd-live send-resumable \
  --config /srv/atp/sender.json \
  --input /srv/atp/input.bin \
  --attempts 4 \
  --retry-delay-ms 250
```

The receiver's `ready` record contains the address of its actual retained
listener; port zero is supported. Put that address in the sender settings.
Start the sender promptly: idle accept timeouts also consume the receiver's
attempt budget. For a receiver behind a TCP relay, use the relay address while
retaining the correct TLS server name and explicit trust roots.

`--attempts` is required and must be between 1 and 1,024. The retry delay defaults
to 250 milliseconds and is bounded to 1 through 60,000 milliseconds. It is a
constant backoff, not a randomized congestion-control or WAN-throughput policy.
The proof-recovery window defaults to 30 seconds and is bounded to 1 through
86,400 seconds. Exhausting attempts can end that window earlier.

## What is preserved

The source file is opened once, and the same SDK sender session is returned by
each joined child and moved into the next. The producer is never restarted or
rewound. Eligible network failures and timeouts can reconnect; identity,
certificate-validation, continuity, and terminal local failures do not grant
sender retry permission. The SDK still refuses an already failed local source,
including a source error with an otherwise network-like I/O category.

The receiver preallocates **one** locally selected staging sink and reserves its
worst-case retention charge once, before binding. Its readiness record marks
`session_preallocated: true`. This differs from the multi-client `serve` command's
after-authentication sink factory: an unauthenticated client can consume an
attempt, but cannot create another sink, select a path, or acquire new quota.
The expected certificate selector in readiness is configuration, not evidence
that a client has already authenticated.

Every connection performs fresh mutual TLS. The selected client certificate,
first verified server certificate, nonce, negotiated limits, running hashes,
partial-write position, and pending epoch remain under the existing SDK rules.
No transfer engine or wire decoder is duplicated in the command module.

The receiver does **not** exit immediately after writing its first final Proof.
It retains the committed session for the absolute proof-recovery window, so a
sender whose final Proof was lost can reconnect without another sink write,
application commit, or destination publication. The deadline is set once after
local completion is reported; later attempts cannot extend it. The receiver
cannot know whether a successful Proof write reached the sender.

## Signals, ownership, and completion

Every attempt runs in a scope-owned child. Signal polling uses the child's
persistent join handle; it does not drop or recreate the transfer future every
50 milliseconds. After an interruption the same source or sink is handed to
another child only after the preceding child joins.

For the receiver, the first SIGINT or SIGTERM stops admission of additional
attempts while allowing the current attempt its configured `shutdown_grace_secs`.
Another signal or expiration of that grace requests attributed cancellation.
The sender requests cancellation on its first shutdown signal. Started commits
are still drained, even after cancellation or an operation timeout. Neither the
signal grace nor proof-recovery window is a hard process-exit guarantee for
nonreturning code, blocked stdout, or a filesystem call that does not finish.

Cancellation of a child is requested only after its user future starts, so a
pre-start abort does not discard the session that must be returned. Scheduler
failure, task panic, or other join failure still ends the command with an error;
it never becomes a successful transfer result.

Each joined attempt emits `resume_attempt`. The record includes actual attempt
count, retained epoch size, complete-prefix bytes, successful sink-write bytes,
whole-stream outcome, and any separately retained completed receipt.
`retry_eligible` describes policy eligibility, not a promise that another
attempt occurred; a signal or exhausted attempt budget can still stop it.

The sender's `send_result` succeeds only on an exact received final Proof.
A receiver's `receive_result` reports **local application commit**, its final
publication state, and the reason recovery ended. `sender_receipt_observed` is
always false. Receiver exit success requires local commit and confirmed runtime
shutdown; it does not prove the sender observed delivery. `stopped` is emitted
only after successful runtime shutdown.

Files and aliases are retained on failure and success. Inbox locks retain the
existing process-lifetime ownership rule. Local crash inspection or restarting
with those files is not continuation of the lost in-memory session. There is no
cross-process exactly-once guarantee or automatic cleanup.

## Authored validation

The command unit tests cover option bounds, retry classifications, absolute
recovery deadlines, independent commit/Proof facts, and legacy command parsing.
The executable tests reuse the existing public TLS fixtures and process harness.
An independent, non-decrypting TCP relay discards an acknowledgment only after
observing a real staged prefix, or discards a Proof only after observing the
published file. They require two actual connections, matching final bytes/hash,
and exactly one staging/destination inode pair. The quota is sized for just one
transfer, so re-creating and charging a sink on reconnect cannot pass.

Other authored cases cover ordinary/empty transfers on both runtime shapes,
non-retried certificate refusal, SIGTERM between attempts, a silent peer with a
finite connection count, and refusal of multi-client settings before creation.
These are unexecuted tests, not runtime, power-loss, or throughput evidence.
