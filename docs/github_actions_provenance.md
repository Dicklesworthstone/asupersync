# GitHub Actions provenance and update contract

The canonical inventory for `asupersync-mnotoo.3.1` is
`artifacts/github_actions_provenance_v1.json`. Every external `uses:` reference
in `.github/workflows/` is selected by a lowercase 40-hex commit SHA and keeps
a readable tag or dated branch-snapshot comment on the same line.

## Selection policy

A major-version tag such as `@v4`, a branch such as `@main`, and a
tool-selecting alias are mutable references and are not admitted. A reviewer
must resolve the intended upstream reference, inspect the selected action
source, and write the immutable commit into both the workflow and inventory.
Annotated tags must be peeled to the commit object that GitHub Actions will
execute; the tag object's SHA is not an action-source pin.

The inventory currently has no exceptions. A future exception must identify
the exact reference, owner, narrow reason, and expiry date. Missing or expired
exceptions are policy failures. Local actions and reusable workflows must also
be inventoried deliberately rather than being silently skipped.

## Safe update procedure

1. Enumerate every `uses:` line under `.github/workflows/` and reconcile the
   result with the checked inventory before choosing an update.
2. Resolve the proposed tag in the upstream repository. For annotated tags,
   record the peeled commit. For versionless branch-only actions, record a
   dated snapshot and make any branch-selected behavior an explicit input.
3. Review release notes and the old-to-new source diff, including `action.yml`,
   bundled runtime changes, network or installation behavior, maintainer
   changes, and permissions used by the calling job.
4. Update the workflow SHA, its readable comment, the provenance URLs, and the
   exact occurrence count in one commit. No automated tag drift is allowed.
5. Run `github_actions_provenance_contract` and review the workflow diff before
   citing the inventory as green. An automated updater may propose a change,
   but it may not merge a tag-only or SHA-only change without this review.

Branch-selected actions need special care. Pinning
`dtolnay/rust-toolchain@nightly` or
`taiki-e/install-action@cargo-llvm-cov` changes the ref string that previously
selected behavior. The pinned workflows therefore provide `toolchain: nightly`
or `tool: cargo-llvm-cov` explicitly.

## Deterministic contract

`tests/github_actions_provenance_contract.rs` independently enumerates the
workflow directory. It requires every `uses:` reference to have a full
lowercase SHA and nonempty readable comment, compares exact occurrence counts
with the artifact, checks provenance URLs, and exercises rejection fixtures
for mutable tags, short SHAs, and missing comments.

## No-claim boundaries

SHA pinning prevents a moved tag from silently selecting different source. It
does not make an action trustworthy, authenticate a maintainer, prove the
upstream repository uncompromised, or establish that the code is defect-free.
This static inventory also does not prove least-privilege permissions, runner
isolation, secret safety, workflow execution success, release readiness,
broad workspace health, runtime correctness, performance, or live CI
availability.
