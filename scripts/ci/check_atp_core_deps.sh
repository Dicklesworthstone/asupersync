#!/bin/bash
# ATP-M5: Core ATP Dependency Validation
#
# Validates that ATP core (without fuzz, test-internals, or dev features)
# contains no external QUIC stacks or Tokio runtime dependencies in the
# resolved normal dependency graph.

set -euo pipefail

echo "=== ATP Core Dependency Validation ==="

ARTIFACT_DIR="artifacts/audit"
mkdir -p "$ARTIFACT_DIR"

if [[ ! -f Cargo.toml ]]; then
    echo "ERROR: run from the asupersync project root" >&2
    exit 2
fi

audit_profile() {
    local profile="$1"
    local forbid_tokio="$2"
    shift 2

    local tree_file="$ARTIFACT_DIR/atp-core-tree-${profile}.txt"
    local violations_file="$ARTIFACT_DIR/atp-core-tree-${profile}.violations.json"

    echo "Checking resolved normal dependency graph: $profile"
    if ! cargo tree -e normal -p asupersync "$@" >"$tree_file"; then
        echo "ERROR: failed to generate cargo tree for $profile" >&2
        return 1
    fi

    if ! python3 - "$profile" "$tree_file" "$violations_file" "$forbid_tokio" <<'EOF'
import json
import re
import sys

profile, tree_path, violations_path, forbid_tokio_arg = sys.argv[1:5]
forbid_tokio = forbid_tokio_arg == "true"

forbidden_quic = {
    "quinn",
    "quinn-proto",
    "quinn-udp",
    "quiche",
    "s2n-quic",
    "s2n-quic-core",
    "s2n-quic-transport",
    "h3",
    "h3-quinn",
    "h3-quiche",
    "msquic",
    "msquic-sys",
    "cloudflare-quic",
    "neqo-transport",
    "neqo-http3",
    "lsquic",
    "lsquic-sys",
}

forbidden_tokio = {
    "tokio",
    "tokio-util",
    "tokio-stream",
    "tokio-tungstenite",
    "hyper",
    "reqwest",
    "axum",
    "tower-http",
    "async-std",
    "smol",
    "glommio",
}

tree_prefix = re.compile(r"^[\s│├└─]+")
package_line = re.compile(r"^([A-Za-z0-9_.-]+)\s+v[0-9]")
violations = []
seen = set()

with open(tree_path, "r", encoding="utf-8") as tree:
    for raw_line in tree:
        line = tree_prefix.sub("", raw_line).strip()
        match = package_line.match(line)
        if not match:
            continue
        crate = match.group(1)

        violation_class = None
        if crate in forbidden_quic:
            violation_class = "external-quic-stack"
        elif forbid_tokio and crate in forbidden_tokio:
            violation_class = "tokio-or-runtime-stack"

        if violation_class is None:
            continue

        key = (crate, violation_class)
        if key in seen:
            continue
        seen.add(key)
        violations.append(
            {
                "profile": profile,
                "crate": crate,
                "class": violation_class,
                "tree_file": tree_path,
            }
        )

with open(violations_path, "w", encoding="utf-8") as out:
    json.dump(
        {
            "profile": profile,
            "tree_file": tree_path,
            "forbid_tokio": forbid_tokio,
            "violations": violations,
        },
        out,
        indent=2,
        sort_keys=True,
    )
    out.write("\n")

if violations:
    print(f"  Found {len(violations)} forbidden dependencies:")
    for violation in violations:
        print(f"    {violation['class']}: {violation['crate']}")
    sys.exit(1)

print("  No forbidden dependencies found")
EOF
    then
        echo "ERROR: dependency violations in $profile" >&2
        return 1
    fi
}

assert_no_tokio_path() {
    local profile="$1"
    shift

    local invert_file="$ARTIFACT_DIR/atp-core-tokio-invert-${profile}.txt"

    echo "Checking Tokio inversion proof: $profile"
    if ! cargo tree -e normal -p asupersync "$@" -i tokio >"$invert_file" 2>&1; then
        echo "ERROR: failed to run Tokio inversion proof for $profile" >&2
        cat "$invert_file" >&2
        return 1
    fi

    if ! grep -q "nothing to print" "$invert_file"; then
        echo "ERROR: Tokio is present in production profile $profile" >&2
        cat "$invert_file" >&2
        return 1
    fi

    echo "  Tokio not present"
}

require_feature_build() {
    local label="$1"
    local primary_features="$2"
    local fallback_features="$3"

    local primary_log="$ARTIFACT_DIR/atp-core-build-${label}-primary.log"
    local fallback_log="$ARTIFACT_DIR/atp-core-build-${label}-fallback.log"

    echo "Checking feature build: $label"
    if cargo check --no-default-features --features "$primary_features" --lib >"$primary_log" 2>&1; then
        echo "  Builds with features: $primary_features"
        return 0
    fi

    if [[ -n "$fallback_features" ]] && cargo check --no-default-features --features "$fallback_features" --lib >"$fallback_log" 2>&1; then
        echo "  Builds with features: $fallback_features"
        return 0
    fi

    echo "ERROR: feature build failed for $label" >&2
    echo "  primary log: $primary_log" >&2
    if [[ -n "$fallback_features" ]]; then
        echo "  fallback log: $fallback_log" >&2
    fi
    return 1
}

failures=0

audit_profile "default-production" "true" || failures=$((failures + 1))
audit_profile "metrics-production" "true" --features metrics || failures=$((failures + 1))
audit_profile "quic-native" "false" --features quic || failures=$((failures + 1))
audit_profile "http3-native" "false" --features http3 || failures=$((failures + 1))

assert_no_tokio_path "default-production" || failures=$((failures + 1))
assert_no_tokio_path "metrics-production" --features metrics || failures=$((failures + 1))

require_feature_build \
    "core" \
    "quic,http3,tls,compression" \
    "proc-macros,quic,http3,tls,compression" || failures=$((failures + 1))
require_feature_build \
    "metrics" \
    "metrics" \
    "metrics,proc-macros" || failures=$((failures + 1))

echo ""
if [[ "$failures" -ne 0 ]]; then
    echo "ATP core dependency validation failed with $failures failure(s)" >&2
    exit 1
fi

echo "ATP core dependency validation passed"
echo "  - Resolved normal dependency graphs checked for default, metrics, quic, and http3 profiles"
echo "  - Default and metrics production profiles prove Tokio is absent"
echo "  - Core and metrics feature build checks fail closed"
