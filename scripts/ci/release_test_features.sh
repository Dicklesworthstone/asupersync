#!/usr/bin/env bash
# Prints the comma-separated feature list CI uses for the asupersync test
# suites.
#
#   scripts/ci/release_test_features.sh           # Unix: every feature except the harness features
#   scripts/ci/release_test_features.sh windows   # Windows: `ci-cross-platform` members minus the harness features
#
# Why not `--all-features`: `legacy-internal-test-harnesses` and
# `serialization-golden-harnesses` gate crate-root metamorphic / conformance /
# golden modules that Cargo.toml documents as "retained for audit history but
# not part of the default release compile gate". Their goldens under
# tests/golden/state were never committed and several harnesses unwrap on
# message shapes that have since changed, so enabling them makes the lib run
# red on any OS (2026-09-02: 93 failures on Linux with --all-features, the
# same modules that head the GitHub macOS runner's failure list).
# `ci-cross-platform` is excluded as a composite because it transitively
# enables both harness features; its other members are listed individually.
# Reading the list from `cargo metadata` keeps it in sync with Cargo.toml.
set -euo pipefail

HARNESS='^(legacy-internal-test-harnesses|serialization-golden-harnesses)$'
mode="${1:-unix}"

case "$mode" in
  unix)
    cargo metadata --no-deps --format-version 1 \
      | jq -r '.packages[] | select(.name == "asupersync") | .features | keys[]' \
      | grep -vE '^(default|ci-cross-platform)$' \
      | grep -vE "$HARNESS" \
      | paste -sd, -
    ;;
  windows)
    cargo metadata --no-deps --format-version 1 \
      | jq -r '.packages[] | select(.name == "asupersync") | .features["ci-cross-platform"][]' \
      | grep -vE "$HARNESS" \
      | paste -sd, -
    ;;
  *)
    echo "usage: $0 [unix|windows]" >&2
    exit 64
    ;;
esac
