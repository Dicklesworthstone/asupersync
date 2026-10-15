# Shared-port resumable foreground receiver

`atpd-live serve-resumable` connects the existing authenticated shared resume
service to client-specific private file inboxes. Multiple clients and transfers
use one bound TCP port. Reconnecting a known session reuses its original sink,
partial-write cursor, integrity state, and application-commit observation.
There is no new wire protocol or second transfer implementation.

This is connection recovery while the receiver process remains alive, **not
process-crash recovery or exactly-once publication across restarts**. The source
and receiver registry must survive a reconnect. Existing `serve`, `send`,
`receive-resumable`, `send-resumable`, and legacy `atpd` behavior is unchanged.

The source-tree command uses the same native Unix `atp-cli` profile as the other
`atpd-live` commands. Compilation and the tests described below were unavailable
in the authoring environment. Use the repository-authorized RCH validation route
before deployment; this document is an interface contract, not execution evidence.

## Start the receiver

Use the unchanged receiver JSON described in `atpd_live.md`. Its `clients`
array may contain multiple explicitly authorized certificate fingerprints,
each mapped to a distinct existing private inbox. Its `max_connections` limits
simultaneous connections; retained sessions have a separate budget:

```sh
atpd-live serve-resumable \
  --config /srv/atp/receiver.json \
  --max-sessions 32 \
  --max-sessions-per-client 8 \
  --max-session-keys 4096 \
  --attempts-per-session 16 \
  --idle-retention-secs 300 \
  --proof-recovery-secs 60
```

The first four budget flags are required. Idle retention defaults to 300 seconds;
Proof recovery defaults to 30 seconds when its flag is omitted. Limits are checked
before acquiring inbox locks or binding. A `ready` JSON line reports the actual
address, `profile: "atp-live-resume/1"`, `mode: "shared"`,
`session_preallocated: false`, and all effective service budgets. Port zero is
supported. No transfer file is created merely to announce readiness.

The existing sender command can target this address:

```sh
atpd-live send-resumable \
  --config /srv/atp/sender.json \
  --input /srv/atp/source.bin \
  --attempts 4 \
  --retry-delay-ms 250
```

Provision that sender's server name, CA and client identity explicitly. An
unlisted certificate cannot create a registry key or a sink. On every connection,
the SDK authenticates mutual TLS and validates the resume hello before looking
up the `(verified client certificate, stream nonce)` key. The nonce is continuity
data, not a path or permission grant. Filenames are generated locally.

## Independent resource limits

| Setting | Bound |
| --- | --- |
| JSON `max_connections` | Active handshakes/transfers and uncollected worker results; 1 through `max_sessions`. |
| `--max-sessions` | Resident sinks, including disconnected and completed sessions; 1 through 1,024. This entire budget is reserved from SDK admission while serving. |
| `--max-sessions-per-client` | Resident sessions for one verified certificate; 1 through `max_sessions`. |
| `--max-session-keys` | Distinct admitted keys during this service lifetime, including refusal tombstones; between `max_sessions` and 65,536. |
| `--attempts-per-session` | Authenticated routed attempts per admitted session; 1 through 1,024. |
| Retention flags | Each 1 through 86,400 seconds. |
| Existing inbox limits | Retained logical file bytes and directory entries, independently enforced per client. |

The kernel backlog, TLS buffers, codec, and blocking pool retain their own resource
semantics. The per-client resident limit is not a guarantee of fair connection
scheduling against a client continuously occupying handshake slots.

The once-per-session sink factory reserves two entries and twice the configured
maximum transfer size before creating the staging file, preserving the existing
conservative storage policy. Reconnects do not run that factory again and do not
incur another reservation. Retirement does not refund charges, delete files, or
turn logical hard-link accounting into physical disk billing. Exclusive inbox
ownership lasts until process exit, including uncertain runtime teardown.

## Retention and refusal tombstones

An incomplete session receives an idle deadline after each actual routed attempt
returns its state. A successful subsequent attempt can renew incomplete idle
retention. Busy, capacity, and other routing refusals cannot refresh that timer.

The first collected report containing a successful local application commit
opens one absolute Proof recovery deadline. A cached-Proof replay cannot extend
that deadline or turn it back into incomplete retention. This deadline begins
when the manager collects the commit report, not at an independently observed
filesystem timestamp. An earlier exhausted attempt budget can end recovery first.

At expiry the command retires an idle sink through the SDK. Active owners are
never removed underneath their workers. If a Proof deadline expires while an
attempt owns the session, retirement waits for its canonical join. A terminal
local failure or exhausted attempt budget also retires the idle sink. Network
interruption alone is not treated as a terminal local failure.

Retirement preserves the SDK's refusal tombstone and last collected snapshot.
A late reconnect to that exact key is rejected, never interpreted as permission
to create another destination. A different key can use the released resident
slot, subject to per-client, lifetime-key and disk limits. The metadata/tombstone
budget is deliberately not recycled: exhausting it refuses new keys while
existing eligible sessions can still reconnect. The command does not restart
itself to erase that protection.

Completed and partial files remain in their private inboxes. Staging aliases
remain plaintext and can reference the published inode. Protect those aliases
and do not modify committed content. Operator file-retention decisions remain
separate from session retirement.

## Results and shutdown

The command emits one `resume_completion` record per collected connection result.
It includes the canonical connection number, diagnostic address, authenticated
session key when known, outcome category, transfer report, and publication state.
Busy/refused connections do not consume another worker's publication handle.

A successful receiver result sets `proof_write_confirmed: true`, but
`sender_receipt_observed` remains false. A locally committed transfer with lost
Proof retains its `completed_receipt` independently of the failed attempt. Only
the sender's validated Proof establishes sender success. Arbitrary peer, sink,
certificate and panic messages are not copied into these structured records.

A `session_retired` record preserves the reason, last collected snapshot, final
local publication observation, resident/key counts, and `tombstone_retained:
true`. Local file presence is not silently relabelled as peer receipt. The
command retains publication handles by certificate/nonce, not TCP address.

SIGINT or SIGTERM closes new admission and starts the configured shutdown grace.
A subsequent observed shutdown signal or grace expiration requests attributed
cancellation. The manager keeps collecting real child results through `drain_next`,
including started application commits, before reporting `stopped`. Idle sessions
are released on final service drain; shutdown does not wait out their recovery
windows. A broken output pipe requests cancellation and drain rather than leaving
workers detached.

The caller must drain stdout. A blocking stdout consumer can delay control-loop
progress. A started commit or user operation that never finishes cannot be safely
preempted; the grace period is not a hard process-exit guarantee. A `stopped`
record with `drained: true` is emitted only after service and runtime teardown
are confirmed by their existing APIs.

## Tests and remaining boundaries

Eight unit tests cover CLI selection, independent limits, exact/saturating
deadlines, non-renewable Proof windows and non-fabricated result projections.
Eight process tests are nested under `tests/atpd_live_cli/resume.rs` in
`shared_resume.rs`. They exercise the actual command, two explicitly provisioned
client identities, concurrent isolated inboxes, real files, and an opaque TCP
relay that drops a response only after observing staging progress or publication.
A separate synchronous mTLS peer exercises exact nonce reuse, tombstone refusal,
finite lifetime keys, cached Proof, and SIGTERM after a real acknowledged prefix.
Existing standalone tests and fixtures are preserved.

**These tests have not been compiled or executed in the authoring environment.**
Source-preservation, whitespace and Git-object checks are not runtime evidence.
No new dependencies, unsafe code, filesystem deletion, automatic retransmission
loop, hot-reload mechanism, legacy daemon RPC, or durable session journal is added.

Restart rescans retained storage but forgets in-memory session keys, partial
continuations and tombstones. A restarted receiver must not be represented as
continuing the old session. No-overwrite publication protects existing filenames;
it cannot prevent a new session from publishing a second independent file with
the same contents. Durable duplicate suppression and process-crash recovery remain
separate unfinished work.
