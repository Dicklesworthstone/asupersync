# Ordered journal resume decisions

`AppendJournal::get_resume_summary` authenticates its transfer records, then
interprets them in sequence order. It no longer treats Verified and Written as
unordered sets, or uses the last terminal record to override all earlier ones.
The public signature, record encoding, authentication tags, and on-disk format
are unchanged. Raw entry reads remain available even when a summary refuses.

## Reusable payload

A range is reusable only when a Written record follows verification in its
current payload attempt. A Written followed by Verified is not sufficient;
another Written must follow that verification. A later Received or RepairDecode
starts a new unverified attempt and removes the range's prior reusable credit.
Other, disjoint ranges keep their credit. An incomplete attempt contributes no
bytes rather than being retrospectively approved by a later hash.

Legacy Verified -> Written histories remain supported without requiring a
Received record. Identical repeated Verified/Written records do not double-count
bytes. Received is not a verification receipt. When present, its hash must match
subsequent verification; an already verified hash cannot be rebound to other
content under the same range. Before any verification, a replacement Received
may supersede an earlier unverified Received.

All recorded payload ranges must have nonzero size, checked endpoints and,
when an offer is present, fit its length. Overlapping or changed-size ranges
refuse, including transient ranges. Rechunking ambiguous old history is not an
automatic recovery operation. Work scales with recorded ranges, not the logical
size of a sparse file. The existing range projection computes the final sorted
receipts, byte total and contiguous prefix.

## Terminal history and identity

Repeated offers must agree on object identity, manifest root and length.
Commit intent must agree with an offered root when present. A pending intent
can be repeated identically or progress to completion; completion, cancellation
and rollback can only repeat their own matching observations. Changed completion
paths/sizes, cancellation reasons or rollback checkpoints refuse. An offer,
acceptance or payload event after a terminal decision also refuses. ProofDigest
records remain diagnostic and cannot reopen a transfer.

Standalone legacy completion/cancellation/rollback reports remain representable
as non-resumable observations. This does not invent a missing intent or prove
publication. Offerless legacy receipt summaries likewise remain representable;
physical writer restoration still requires a matching authenticated Offer and
checks the retained payload. Never use a summary alone as manifest authority,
a file-opening grant, or proof that the payload is currently durable and intact.

## Compatibility and validation

Malformed histories that previously returned a last-record-wins status can now
return JournalError::Deserialization. An unverified replacement receive now
reduces durable_bytes and contiguous_prefix_bytes. Callers must retain and
inspect that evidence instead of assuming the earlier prefix remains reusable.
No append, compaction, cleanup, publication or network behavior is added by the
summary query; existing restore/checkpoint/recovery callers use the stronger
shared query without another opt-in adapter.

A separately named opt-in summary would leave existing restoration callers
exposed to stale reusable credit. Instead, this shared query rejects the unsafe
interpretation while retaining valid legacy profiles and raw diagnostic reads.
Applications must handle refusal, inspect or quarantine inconsistent history,
and start a separately authorized transfer rather than edit old evidence into
apparent validity. No deployment or release compatibility claim is made here.

History errors can now be attributed to the shared summary before a caller's
own validator runs. For example, journaled cancellation retains its existing
`WriteFailed("cancellation journal: ...")` wrapper around a rejected journal
summary; it does not enter terminal persistence or cleanup. Tests require those
specific diagnostics as well as unchanged staging, lifecycle and journal sequence.
The error wrapper itself and all production cancellation code are unchanged.

Eight regression tests cover ordered receipt traces, independent sparse ranges,
legacy profiles, conflicting hashes and geometry, terminal transition matrices,
changed identity, signed append/compaction/reopen, and physical restoration after
a superseding receive followed by verified publication. Two existing recovery
and cancellation tests now require refusal or zero credit at the stronger shared
boundary. Their bitmap replay and no-cleanup assertions remain intact.

These Rust changes and tests were NOT compiled or executed in the authoring
environment. Rust, Cargo, rustfmt, RCH and UBS were unavailable; RCH and UBS
attempts returned command-not-found. Full-source hash and patch-application
checks and a separate Python ordering specification were checked, not native
runtime correctness or power-loss behavior. Run remote-required default/native
checks, append_journal::resume::tests, existing journal/bitmap/restore/checkpoint/
finalization/cancellation tests, formatting and clippy on the landed commit
before deployment.

Record authentication does not authenticate the outer sequence headers. These
checks are not an authenticated append-only chain, log-completeness proof,
physical payload verification, bounded total journal-memory claim, hostile
filesystem-race protection, or release qualification.
