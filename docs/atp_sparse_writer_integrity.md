# Sparse-writer content authentication

`SparseWriter` separates local write accounting from content authorization.
A hash of bytes received by this writer detects later local corruption; it does
not establish which bytes the sender was authorized to supply.

## Existing roots remain unchanged

The legacy `MerkleRoot::from_manifest_components` does not include per-object
chunk boundaries. Its format, `ManifestVersion`, and persisted roots remain
unchanged. Do not treat successful legacy manifest validation alone as proof
that a chunk ledger is authentic.

`atp::manifest_chunk_commitment::ManifestChunkCommitment` is an explicit,
versioned SHA-256 supplement. It binds the legacy root, manifest version,
ordered roots, namespaced object identities, kinds, optional sizes and content
hashes, and each chunk's index, offset, length, hash and strategy. Counts and
option-presence tags make the new framing explicit. Profile-only chunk metadata
and other fields omitted by the legacy root are outside this format's claim.
It is neither a signature nor a capability grant.

The trusted producer calls `ManifestChunkCommitment::from_manifest` after
finalizing its manifest, then exports `hash()` through an authenticated
application channel. A receiver imports those independently trusted 32 bytes
with `ManifestChunkCommitment::new`. Recomputing the expected commitment from
an untrusted received manifest is not authentication. Existing CLI and wire
profiles do not automatically transport or negotiate this supplement.

## Verification and migration

The existing `verify(&cx, &manifest)` signature is preserved. It requires a
trusted expected manifest and independently checks bytes against the selected
content-addressed object ID. A manifest-addressed file can continue to use a
whole-object content hash. Optional chunk hints may describe only part of a
file when a whole-object hash authenticates every byte.

**Security behavior change:** a manifest-addressed file with only chunk hashes
can no longer pass `verify` using a legacy root alone. Callers must either use
a trusted whole-object content hash or supply an independently authenticated
`ManifestChunkCommitment` to:

```text
writer.verify_with_chunk_commitment(&cx, &manifest, &expected).await
```

This routes through the same serialized verification and publication lifecycle,
not a separate writer. It checks the commitment before file I/O, including
creation of an empty staging inode. Chunk-only manifests must cover exactly
`[0, file_length)`: no gaps, overlaps, excess bytes, overflow, or zero-length
entries. A pinned empty ledger covers an empty file only. Selected content IDs
remain an independent check even when a manifest supplies a different hash.

A rejected commitment invalidates previous verification. It cannot be ignored
by retrying a chunk-only file through the unpinned method. Verification refusal
leaves staging bytes available for an explicitly authorized retry; successful
publication remains sealed and idempotent. No destination is published by a
verification operation.

## Validation and limits

Seven commitment tests and twelve writer tests cover tampering invisible to the
legacy root, object substitution, incomplete coverage, wrong-pin refusal before
empty-file staging, downgrade attempts, corrupt local bytes, and successful
publication under all three existing policies. Old inline writer tests and the
lifecycle and durability tests are retained unchanged.

These Rust tests were authored but not compiled or executed in the authoring
environment, which lacks Rust, Cargo, rustfmt and RCH. Complete source/blob hashes
and unchanged test bodies were checked. An independent finite-domain Python
coverage model matched a per-byte oracle in 287,934 cases; this is not execution
of the Rust implementation or native runtime proof. Run the focused commitment
and sparse-writer library tests through the repository-authorized RCH lane
before deployment.

Synchronous filesystem placement, host path-race confinement, and external
modification between verification and publication are not solved here.
`CopyAndVerify` retains its documented non-atomic destination visibility.
No universal power-loss guarantee, automatic protocol migration, complete
manifest authentication, or release-readiness claim is made.
