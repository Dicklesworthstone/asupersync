# Journal recovery: evidence before reusable bitmap progress

`recover_journal_and_bitmap` now separates the diagnostic replay of journal
states from the narrower decision to reactivate bytes after a restart. It uses
the existing authenticated `AppendJournal::get_resume_summary`, the existing
state-transition replay, and the existing bitmap format. It does not introduce
a second journal, storage codec, runtime, or receive protocol.

## Exact coverage, not a larger chunk inferred from its starting offset

A journal can contain unequal chunk lengths. A fixed-grid bitmap must not turn
one short record into evidence for the rest of a larger cell. For example,
written intervals `[0, 2)` and `[4, 8)` do not authorize cell `[0, 4)`.

Replay now rejects zero-size, overflowing, overlapping and changed-size ranges
before advancing state or recording successful deduplication. Geometry uses an
ordered map for predecessor/successor checks. Finalization projects the retained
intervals onto a grid whose width is the largest retained chunk. Only complete
coverage creates a cell; mixed states use the least advanced constituent state.
Quarantined or invalidated bytes cannot produce an available cell. A partial
cell remains unknown even if some of its bytes were recorded successfully.

Every interval intersects at most two cells. Sparse gaps are skipped without
enumerating their bytes, and coprime chunk sizes cannot create a byte-sized GCD
grid. Projection work and output are proportional to recorded intervals, not
the logical length of a sparse object. Standard uniform chunks and their final
short tail keep their geometry. No constituent hash is misrepresented as a hash
of a differently sized projected cell; these bitmap hashes remain absent.

The public low-level `RecoveryContext::finalize` remains a diagnostic view,
including transient and terminal states. Its `chunks_recovered` count now counts
actual emitted cells rather than source interval records.

## Restart admission uses both forms of evidence

The disk recovery entry point authenticates every decoded record. It refuses an
invalid signature before any bitmap quarantine or replacement. It cannot ignore
a suspect cancellation or commit boundary and reactivate an earlier prefix.
Structural geometry errors and contradictory authenticated summaries also stop
recovery before bitmap mutation. Original journal evidence remains on disk.

An active bitmap requires a resumable summary and an offered total length.
Cancelled, rolled-back, completed and commit-intent-pending transfers are not
reactivated. Neither are transfers whose records lack an offer. Existing active
bitmap files for those IDs are handled by the established stale-quarantine path;
the returned journal still exposes their terminal state and history.

For an admitted transfer, a reusable interval needs matching verified/written
records in the authenticated summary AND an accepted `Written` state transition
in replay. Merely received, verified-in-memory or repair-derived data is not
credited after restart. Set membership alone cannot override invalid record
ordering. Offered transfers with no reusable intervals receive an empty bitmap
with the declared extent, so they can request the whole object again.

These are journal-evidence rules, not physical payload verification. The journal
producer remains responsible for ordering payload durability before recording
reusable progress. This path does not reopen or rehash chunk files, prove their
continued existence, authenticate a network peer, or replace final object
verification. The live scoped receiver's in-process restart API is unchanged.

## Safe bitmap publication

Transfer IDs are validated as filename components before any bitmap mutations.
Separators from either operating system, control characters, Windows stream
syntax and nonportable filename punctuation are rejected. ASCII case aliases
among recovered IDs are also refused before writing. Ordinary Unicode IDs
remain supported; this is not general Unicode/filesystem alias normalization
or protection against hostile parent-directory replacement.

A missing bitmap directory is created after validation. Replacements use the
existing `fs::write_atomic` staging, synchronization and rename implementation,
not an in-place truncating write. Publishing a new bitmap does not rewrite an
already-open old inode or a hard-link alias. On Unix a target symlink is replaced
as a directory entry, rather than writing through it to another file.

This is atomic replacement per file, not a transaction over the entire set.
Earlier quarantine or publication steps may have completed when a later I/O
operation fails. A directory-sync failure after rename is not rollback. The
historical recovery execution model is retained: journal parsing and final
rename/directory synchronization can still run synchronously on the caller.
No additional region-drain or syscall-cancellation bound is claimed.

## Compatibility and validation

Public signatures and journal/bitmap wire formats are unchanged. Callers must
use the returned journal's resume summary to inspect completion, cancellation
or unresolved publication, not membership in the active bitmap map. Consumers
that previously inferred data availability from transient states must request
those bytes again. This is a safety correction, not downstream release approval.

Fourteen authored Rust regression tests cover interval projection, mixed/error
states, malformed ranges, huge sparse layouts, signed journal reopen/reload,
transient and terminal exclusion, record ordering, authentication and summary
refusals before mutation, portable filename boundaries, repeated recovery and
atomic replacement of link aliases. Native integration scenarios use both
scheduler flavors; existing recovery tests remain unchanged.

Rust, Cargo, rustfmt and RCH are unavailable in the authoring environment.
The Rust tests have not been compiled or executed. An independent Python
projection model matched a per-byte oracle on 43,690 layouts and three large
boundary cases; the old aligned shortcut disagreed in 942 cases. Model checks,
source hashes and preserved test bodies are not native execution, clean clippy,
physical payload recovery, downstream compatibility or release-readiness proof.
