#!/usr/bin/env python3
"""
ATP-N7: Banned Dependencies Checker

Checks dependency tree for prohibited packages that violate ATP's
no-external-QUIC and no-Tokio-in-core policies.
"""

import json
import sys
import re
from typing import List, Dict, Set

# Banned dependencies for ATP core
BANNED_DEPENDENCIES = {
    # External QUIC implementations
    'quinn': 'External QUIC stack prohibited in ATP core',
    'quiche': 'External QUIC stack prohibited in ATP core',
    'h3': 'External HTTP/3 implementation prohibited in ATP core',
    'h3-quinn': 'External QUIC-based HTTP/3 prohibited in ATP core',
    's2n-quic': 'External QUIC stack prohibited in ATP core',

    # Tokio runtime (prohibited in ATP core, allowed in compat layer)
    'tokio': 'Tokio runtime prohibited in ATP core modules',
    'tokio-util': 'Tokio utilities prohibited in ATP core',
    'tokio-stream': 'Tokio streams prohibited in ATP core',

    # Other async runtimes that conflict with ATP
    'async-std': 'Conflicting async runtime',
    'smol': 'Conflicting async runtime',
    'glommio': 'Conflicting async runtime',

    # Network libraries that bypass ATP abstractions
    'reqwest': 'High-level HTTP client bypasses ATP networking',
    'hyper': 'HTTP implementation should use ATP abstractions',
    'warp': 'Web framework bypasses ATP networking',
    'axum': 'Web framework bypasses ATP networking',
}

# Dependencies that are allowed in specific contexts
CONTEXT_ALLOWED = {
    'asupersync-tokio-compat': {
        'tokio', 'tokio-util', 'tokio-stream'
    },
    'examples/': {
        'tokio', 'reqwest', 'hyper'
    },
    'tests/': {
        'tokio'  # For compatibility testing
    },
    'benches/': {
        'tokio', 'hyper'  # For benchmark comparisons
    }
}

# Regex patterns for banned dependencies
BANNED_PATTERNS = [
    r'.*-tokio$',  # Tokio-specific variants
    r'^quic-.*',   # QUIC-prefixed packages
    r'.*-quic$',   # QUIC-suffixed packages
]

def load_dependency_tree() -> Dict:
    """Load dependency tree from stdin or file."""
    try:
        return json.load(sys.stdin)
    except json.JSONDecodeError as e:
        print(f"Error parsing dependency tree JSON: {e}", file=sys.stderr)
        sys.exit(1)

def get_package_context(package_name: str, tree: Dict) -> str:
    """Determine the context/module where a package is used."""
    # This is simplified - in practice would analyze the dependency path
    # to determine if it's used in core ATP modules or allowed contexts

    # Check if it's in a known allowed context
    for context, allowed_deps in CONTEXT_ALLOWED.items():
        if package_name in allowed_deps:
            return context

    return 'core'  # Default to core context (most restrictive)

def check_banned_dependencies(tree: Dict) -> List[Dict]:
    """Check for banned dependencies in the tree."""
    violations = []
    seen_packages = set()

    def process_package(package_info: Dict, path: List[str] = None):
        if path is None:
            path = []

        package_name = package_info.get('name', '')
        if not package_name:
            return

        # Skip if we've already processed this package
        if package_name in seen_packages:
            return
        seen_packages.add(package_name)

        current_path = path + [package_name]
        context = get_package_context(package_name, tree)

        # Check exact matches
        if package_name in BANNED_DEPENDENCIES:
            # Check if allowed in current context
            is_allowed = False
            for allowed_context, allowed_deps in CONTEXT_ALLOWED.items():
                if (allowed_context in context or
                    any(allowed_context in p for p in current_path)):
                    if package_name in allowed_deps:
                        is_allowed = True
                        break

            if not is_allowed:
                violations.append({
                    'package': package_name,
                    'reason': BANNED_DEPENDENCIES[package_name],
                    'context': context,
                    'dependency_path': current_path,
                    'violation_type': 'banned_package'
                })

        # Check pattern matches
        for pattern in BANNED_PATTERNS:
            if re.match(pattern, package_name):
                violations.append({
                    'package': package_name,
                    'reason': f'Matches banned pattern: {pattern}',
                    'context': context,
                    'dependency_path': current_path,
                    'violation_type': 'banned_pattern'
                })
                break

        # Process dependencies recursively
        for dep in package_info.get('dependencies', []):
            process_package(dep, current_path)

    # Process root packages
    if 'packages' in tree:
        for package in tree['packages']:
            process_package(package)
    elif 'nodes' in tree:
        for node in tree['nodes']:
            process_package(node)
    else:
        print("Warning: Unrecognized dependency tree format", file=sys.stderr)

    return violations

def generate_report(violations: List[Dict]) -> None:
    """Generate a report of dependency violations."""
    if not violations:
        print("✓ No banned dependencies found")
        return

    print(f"✗ Found {len(violations)} dependency violations:")
    print()

    by_type = {}
    for violation in violations:
        vtype = violation['violation_type']
        if vtype not in by_type:
            by_type[vtype] = []
        by_type[vtype].append(violation)

    for vtype, group_violations in by_type.items():
        print(f"{vtype.replace('_', ' ').title()}:")
        for v in group_violations:
            print(f"  - {v['package']}: {v['reason']}")
            print(f"    Context: {v['context']}")
            print(f"    Path: {' -> '.join(v['dependency_path'])}")
            print()

    # Write JSON report
    with open('artifacts/audit/banned-deps-report.json', 'w') as f:
        json.dump({
            'total_violations': len(violations),
            'violations': violations,
            'by_type': {
                vtype: len(group) for vtype, group in by_type.items()
            }
        }, f, indent=2)

def main():
    """Main entry point."""
    tree = load_dependency_tree()
    violations = check_banned_dependencies(tree)
    generate_report(violations)

    if violations:
        sys.exit(1)

if __name__ == '__main__':
    main()