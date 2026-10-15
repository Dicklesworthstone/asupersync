# Release checklist (0.4.x)

Every release is a bead. Nothing on this list is optional; each line names
the receipt that goes into the release bead before `cargo publish`.

1. **Version and notes.** `Cargo.toml` version bumped (root and the satellite
   crates that ship), `CHANGELOG.md` has a dated `[vX.Y.Z]` section and a
   Version Timeline bullet, README's crates.io snippet shows the new version.
   Receipt: the commit hash.
2. **Compatibility floor.** Public surface compared against `v0.4.3`
   (`artifacts/api_surface_map_v1.json` regenerated and diffed); any removed
   or changed public item is a release hold unless the owner approved it in
   writing. Receipt: the diff summary in the bead.
3. **Gates on the exact commit.** `cargo check --all-targets --all-features
   --keep-going`, `cargo clippy --all-targets --all-features -- -D warnings`,
   `cargo fmt --check`, the native parked-task cancellation lane
   (`runtime_abort_vs_cancel_semantics_audit`), and `cargo test --lib
   --features test-internals`, all run through `rch` with clean overlay on
   the release commit. Receipt: rch summary lines with worker and duration.
4. **Downstream canary.** At least one opted-in consumer built against the
   release candidate (a `default-features = false` consumer and one with
   `tls`). Receipt: the consumer, commit, and `cargo check` result.
5. **Package.** `cargo package --list` reviewed for the 10 MiB crates.io cap
   and for files that must not ship; `cargo publish --dry-run` green.
   Receipt: package size.
6. **Publish, then tag the published sha.** After `cargo publish`, download
   the tarball, read `.cargo_vcs_info.json`, and tag exactly that sha
   (`git tag -a vX.Y.Z <sha>`; push the tag; sync `master`). Receipt: tag
   name and sha in the bead.
7. **Close the bead** with links to every receipt above.

History: v0.4.4 through v0.4.10 shipped without release beads; v0.4.10 was
tagged after the fact on 2026-09-02 at `997e8d116`, the sha recorded in the
published tarball.
