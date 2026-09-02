#!/usr/bin/env bash
# Prints the comma-separated feature list CI uses for the asupersync test
# suites: every feature except the ones Cargo.toml documents as NOT part of
# the release gate.
#
# Why not `--all-features`: `legacy-internal-test-harnesses` gates crate-root
# metamorphic/conformance/golden modules "retained for audit history but not
# part of the default release compile gate" (Cargo.toml). Their goldens under
# tests/golden/state were never committed and several harnesses assert on
# message shapes that have since changed, so enabling them made every OS's
# lib run red (93 of the 235 "macOS" failures on 2026-09-02 reproduced on an
# Apple-silicon host were exactly these modules; none were platform bugs).
# Excluding one feature keeps the rest of `--all-features` coverage intact
# and keeps the list in sync with Cargo.toml automatically.
set -euo pipefail

EXCLUDE='^(default|legacy-internal-test-harnesses)$'

cargo metadata --no-deps --format-version 1 \
  | jq -r '.packages[] | select(.name == "asupersync") | .features | keys[]' \
  | grep -vE "$EXCLUDE" \
  | paste -sd, -
