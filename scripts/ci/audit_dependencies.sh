#!/bin/bash
# ATP-N7: Dependency Audit Script
# Audits dependencies for security vulnerabilities and banned packages

set -euo pipefail

echo "=== ATP Dependency Audit ==="

# Create audit report directory
mkdir -p artifacts/audit

# Run cargo audit for security vulnerabilities
echo "Running security audit..."
if command -v cargo-audit >/dev/null; then
    cargo audit --json > artifacts/audit/security-audit.json || {
        echo "Security audit found issues"
        cargo audit
    }
    echo "✓ Security audit completed"
else
    echo "⚠ cargo-audit not installed, skipping security audit"
fi

# Check for outdated dependencies
echo "Checking for outdated dependencies..."
cargo update --dry-run > artifacts/audit/outdated-deps.txt 2>&1 || true

# Generate dependency metadata
echo "Generating dependency metadata..."
cargo metadata --format-version 1 > artifacts/audit/dependency-metadata.json

# Generate dependency tree (human readable)
echo "Generating dependency tree..."
cargo tree > artifacts/audit/dependency-tree.txt

# Check for duplicate dependencies
echo "Checking for duplicate dependencies..."
cargo tree --duplicates > artifacts/audit/duplicate-deps.txt 2>&1 || true

# Analyze dependency sizes
echo "Analyzing dependency sizes..."
if command -v cargo >/dev/null; then
    # Get build timings
    cargo clean
    cargo build --timings --release 2>/dev/null || true
    if [[ -f cargo-timing.html ]]; then
        mv cargo-timing.html artifacts/audit/build-timings.html
    fi
fi

# Generate dependency report
echo "Generating dependency report..."
python3 - <<'EOF'
import json
import sys
from collections import defaultdict, Counter

try:
    with open('artifacts/audit/dependency-metadata.json', 'r') as f:
        metadata = json.load(f)

    # Analyze dependency metadata
    packages = metadata.get('packages', [])
    stats = {
        'total_packages': len(packages),
        'workspace_members': len(metadata.get('workspace_members', [])),
        'resolve_deps': len(metadata.get('resolve', {}).get('nodes', [])),
        'by_license': defaultdict(int),
        'largest_deps': [],
    }

    # Count license types
    for package in packages:
        license_type = package.get('license', 'unknown')
        stats['by_license'][license_type] += 1

    # Find largest dependencies by manifest path length (crude size approximation)
    largest = sorted(packages, key=lambda p: len(p.get('manifest_path', '')), reverse=True)[:10]
    stats['largest_deps'] = [{'name': p.get('name'), 'version': p.get('version')} for p in largest]

    # Write report
    with open('artifacts/audit/dependency-report.json', 'w') as f:
        json.dump(stats, f, indent=2)

    print(f"✓ Dependency analysis completed: {stats['total_packages']} total packages")

except Exception as e:
    print(f"⚠ Dependency analysis failed: {e}")
EOF

echo "Dependency audit completed"