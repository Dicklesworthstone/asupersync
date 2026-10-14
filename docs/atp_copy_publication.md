# Verified copy publication without a partial destination

`SparseWriter` now implements `CommitPolicy::CopyAndVerify` as private-copy,
verify, sync, and rename. The non-Unix copy fallback for `LinkAndUnlink` uses
that same implementation. This applies automatically to historical writer
calls and the scoped write, finalization, fresh-receive and resumed-receive
APIs. No additional opt-in transfer API, pool, task or dependency is introduced.

This supersedes the **non-atomic copy visibility** caveats in the earlier
scoped-writer and receive documents for these copy-based operations. Other
pathname-race, external-mutation and cancellation limitations still apply.

## Ordering and ownership

The existing commit driver first seals the writer and applies the original
staging-file durability policy. It then acquires a separate, private file in
the destination directory using the existing path manager's exclusive creation
and collision handling. It copies at most the verified expected length and
checks both lengths and SHA-256 digests through the retained file descriptors.
The complete copy receives the original file's permissions. Unless the policy
is `FsyncPolicy::Never`, its own `sync_all` must succeed before it is renamed
over the destination. A sync of the original file alone is not sufficient.

The copy source is the owned staging descriptor. Copy-based verification also
uses that descriptor, rather than authorizing a replacement at the staging
pathname. Rename and native hard-link policies retain their existing
name-based verification behavior; they are not newly claimed to be confined.

Only the rename publishes the copy. The destination is not opened for writing
or truncated during preparation. On Unix a destination symlink is replaced as
a directory entry, not followed, and existing hard-link aliases or already-open
readers continue to refer to their old inode. This is a deliberate safety
change from an in-place copy; callers requiring writes through symlinks or
updates to all hard links must perform those operations explicitly elsewhere.
The rename's platform and filesystem restrictions still apply, and failure
never falls back to overwriting the visible destination in place.

After rename, the outer driver performs its existing Unix directory sync and
original staging-name cleanup. It does not reopen the published destination
for an inode barrier: the actual copied inode has already been synchronized.
Successful commit remains idempotent and returns the retained path on retry.

## Failures, cancellation and storage costs

Before rename, copy errors, digest or length mismatches, permission errors,
copy-inode sync errors and panics leave the destination unchanged by this
operation. The writer remains sealed. Original staging and any acquired copy
are retained rather than silently discarded; ordinary errors include the copy
path, and the writer retains that path and manager ownership for investigation.
A pre-allocation refusal naturally has no copy file to retain. No automatic
retry or cleanup of an uncertain publication is introduced.

Directory synchronization or original staging cleanup can fail **after** the
destination becomes visible. Such errors do not imply rollback. Cancellation
and dropped waits keep their existing region-owned drain semantics; a started
commit can still publish after cancellation. This is not a transaction over
multiple files or a universal power-loss guarantee.

The destination-side candidate needs space in addition to the original staging
file and any existing destination until rename. It can fail for insufficient
space without replacing the existing destination. Hashing uses the existing
bounded scratch buffer; this change makes no throughput or peak-disk reduction
claim. Existing temporary-file permissions remain subject to umask; Windows
ACL guarantees and hostile parent-directory replacement are not added.

## Validation

Eleven authored Rust tests cover empty and nonempty files across four fsync
policies; real partial-copy failure; bad lengths and bytes; copy-inode sync
failure and panic; rename failure; source growth; deceptive staging-name
replacement; Unix destination symlink and hard-link aliases; private/read-only
file modes; and public scoped finalization on both native scheduler flavors.
The failure injection points use real files and retain the canonical verifier,
sealing, rename, directory-sync and cleanup paths. Earlier writer tests remain
unchanged.

Rust, Cargo, rustfmt and RCH are unavailable in the authoring environment.
These Rust tests are **not compiled or executed** here. Exact source/blob and
whitespace checks are structural checks, not native-runtime or release proof.
Run the repository-authorized focused Rust and clippy lanes before deployment.
