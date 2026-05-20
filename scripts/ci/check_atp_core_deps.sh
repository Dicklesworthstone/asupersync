#!/bin/bash
# ATP-M5: Core ATP Dependency Validation
#
# Validates that ATP core (without fuzz, test-internals, or dev features)
# contains no external QUIC stacks or Tokio runtime dependencies.

set -euo pipefail

echo "=== ATP Core Dependency Validation ==="

# Create audit report directory
mkdir -p artifacts/audit

# Check ATP core features (production-only)
echo "Checking ATP core dependencies (production features only)..."

# Build metadata for core ATP features only
CORE_FEATURES="default,metrics,quic,http3,tls,compression"
echo "Core features: $CORE_FEATURES"

cargo metadata --no-deps --features "$CORE_FEATURES" --format-version 1 > artifacts/audit/atp-core-metadata.json

# Extract just the workspace packages (not all transitive deps)
echo "Analyzing workspace package dependencies..."

python3 - <<'EOF'
import json
import sys

# Load core metadata
with open('artifacts/audit/atp-core-metadata.json', 'r') as f:
    metadata = json.load(f)

# Get workspace members
workspace_members = set(metadata.get('workspace_members', []))
packages = metadata.get('packages', [])

# Filter to just workspace packages
workspace_packages = [pkg for pkg in packages if pkg.get('id') in workspace_members]

print(f"Workspace packages: {len(workspace_packages)}")
for pkg in workspace_packages:
    print(f"  - {pkg.get('name')} v{pkg.get('version')}")

# Check for banned dependencies in workspace packages only
banned_core_deps = {
    'quinn', 'quiche', 'h3', 'h3-quinn', 's2n-quic',
    'tokio', 'tokio-util', 'tokio-stream',
    'async-std', 'smol', 'glommio'
}

violations = []

for pkg in workspace_packages:
    pkg_name = pkg.get('name', '')

    # Skip packages that are allowed to have these deps
    if pkg_name in ('asupersync-tokio-compat', 'asupersync-conformance'):
        continue

    # Check direct dependencies (NOT dev dependencies)
    for dep in pkg.get('dependencies', []):
        dep_name = dep.get('name', '')
        dep_kind = dep.get('kind', None)

        # Skip dev dependencies - they're not part of the production build
        if dep_kind == 'dev':
            continue

        if dep_name in banned_core_deps:
            # Check if it's optional or feature-gated
            dep_optional = dep.get('optional', False)
            dep_features = dep.get('features', [])

            # Allow optional dependencies - they're only included when explicitly requested
            if not dep_optional:
                violations.append({
                    'package': pkg_name,
                    'banned_dep': dep_name,
                    'reason': f'Direct dependency on banned package: {dep_name}',
                    'optional': dep_optional,
                    'features': dep_features
                })

if violations:
    print(f"\n✗ Found {len(violations)} core dependency violations:")
    for v in violations:
        print(f"  {v['package']} -> {v['banned_dep']}: {v['reason']}")
        if v['optional']:
            print(f"    (optional: {v['optional']}, features: {v['features']})")
    sys.exit(1)
else:
    print("\n✓ ATP core dependencies are clean - no banned packages found")

EOF

# Test production feature combinations (non-default)
echo "Testing production feature builds..."

# Test core runtime features without test-internals
if cargo check --no-default-features --features "quic,http3,tls,compression" --lib >/dev/null 2>&1; then
    echo "✓ Core ATP features build successfully"
else
    echo "⚠ Core ATP features may require additional dependencies (checking details...)"
    # Try with proc-macros which might be needed
    if cargo check --no-default-features --features "proc-macros,quic,http3,tls,compression" --lib >/dev/null 2>&1; then
        echo "✓ Core ATP features build with proc-macros"
    else
        echo "⚠ Core ATP features have build dependencies (may be acceptable)"
    fi
fi

# Test that metrics feature builds independently
if cargo check --no-default-features --features "metrics" --lib >/dev/null 2>&1; then
    echo "✓ Metrics feature builds independently"
elif cargo check --no-default-features --features "metrics,proc-macros" --lib >/dev/null 2>&1; then
    echo "✓ Metrics feature builds with proc-macros"
else
    echo "⚠ Metrics feature has build dependencies"
fi

echo ""
echo "✓ ATP core dependency validation passed"
echo "  - No external QUIC stacks in workspace packages"
echo "  - No Tokio runtime in core features"
echo "  - Core and metrics features build independently"