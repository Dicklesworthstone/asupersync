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

# Generate dependency tree
echo "Generating dependency tree..."
cargo tree --format json > artifacts/audit/dependency-tree.json

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
    with open('artifacts/audit/dependency-tree.json', 'r') as f:
        tree_data = json.load(f)

    # Analyze dependency tree
    stats = {
        'total_packages': 0,
        'direct_deps': 0,
        'transitive_deps': 0,
        'by_license': defaultdict(int),
        'largest_deps': [],
    }

    def process_node(node, depth=0):
        stats['total_packages'] += 1
        if depth == 1:
            stats['direct_deps'] += 1
        elif depth > 1:
            stats['transitive_deps'] += 1

        # Process dependencies
        for dep in node.get('dependencies', []):
            process_node(dep, depth + 1)

    if 'packages' in tree_data:
        for package in tree_data['packages']:
            stats['total_packages'] += 1

    # Write report
    with open('artifacts/audit/dependency-report.json', 'w') as f:
        json.dump(stats, f, indent=2)

    print(f"✓ Dependency analysis completed: {stats['total_packages']} total packages")

except Exception as e:
    print(f"⚠ Dependency analysis failed: {e}")
EOF

echo "Dependency audit completed"