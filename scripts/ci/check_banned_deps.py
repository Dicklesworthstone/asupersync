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
        'tokio', 'tokio-util', 'tokio-stream', 'axum', 'hyper'
    },
    'examples/': {
        'tokio', 'reqwest', 'hyper', 'axum'
    },
    'tests/': {
        'tokio', 'async-std', 'smol'  # For compatibility testing
    },
    'benches/': {
        'tokio', 'hyper'  # For benchmark comparisons
    },
    'dev-dependencies': {
        'tokio', 'tokio-util', 'tokio-stream', 'async-std', 'smol', 'axum', 'hyper', 'reqwest'  # Dev/test only
    },
    'fuzz-feature': {
        'tokio', 'axum', 'hyper'  # Fuzz feature intentionally includes tonic/tokio
    },
    'conformance': {
        'async-std'  # Conformance tests may use alternate runtimes
    }
}

# Regex patterns for banned dependencies
BANNED_PATTERNS = [
    r'.*-tokio$',  # Tokio-specific variants
    r'^quic-.*',   # QUIC-prefixed packages
    r'.*-quic$',   # QUIC-suffixed packages
]

def load_dependency_metadata() -> Dict:
    """Load dependency metadata from stdin or file."""
    try:
        return json.load(sys.stdin)
    except json.JSONDecodeError as e:
        print(f"Error parsing metadata JSON: {e}", file=sys.stderr)
        sys.exit(1)

def get_package_context(package_name: str, metadata: Dict, dependency_path: List[str]) -> str:
    """Determine the context/module where a package is used."""
    # Check the dependency path for context clues
    path_str = ' -> '.join(dependency_path)

    # Check if this comes through opentelemetry-proto (fuzz feature)
    if 'opentelemetry-proto' in dependency_path:
        return 'fuzz-feature'

    # Check if this comes through conformance dependencies
    if 'asupersync-conformance' in dependency_path or 'conformance' in dependency_path:
        return 'conformance'

    # Check if this is a very deep transitive dependency (likely dev/test)
    if len(dependency_path) > 10:
        return 'dev-dependencies'

    # Check the source/manifest path to determine context
    packages = metadata.get('packages', [])
    for package in packages:
        if package.get('name') == package_name:
            manifest_path = package.get('manifest_path', '')

            # Check if it's in a known allowed context based on path
            if 'asupersync-tokio-compat' in manifest_path:
                return 'asupersync-tokio-compat'
            elif '/examples/' in manifest_path:
                return 'examples/'
            elif '/tests/' in manifest_path:
                return 'tests/'
            elif '/benches/' in manifest_path:
                return 'benches/'

            break

    return 'core'  # Default to core context (most restrictive)

def check_banned_dependencies(metadata: Dict) -> List[Dict]:
    """Check for banned dependencies in the metadata."""
    violations = []
    seen_packages = set()

    # Get all packages from metadata
    packages = metadata.get('packages', [])

    # Build a map of package names for quick lookup
    package_map = {pkg.get('name'): pkg for pkg in packages}

    def check_package(package_name: str, path: List[str] = None):
        if path is None:
            path = []

        if not package_name or package_name in seen_packages:
            return

        seen_packages.add(package_name)
        current_path = path + [package_name]
        context = get_package_context(package_name, metadata, current_path)

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
                # Check if it's allowed in context
                is_allowed = False
                for allowed_context, allowed_deps in CONTEXT_ALLOWED.items():
                    if (allowed_context in context and
                        package_name in allowed_deps):
                        is_allowed = True
                        break

                if not is_allowed:
                    violations.append({
                        'package': package_name,
                        'reason': f'Matches banned pattern: {pattern}',
                        'context': context,
                        'dependency_path': current_path,
                        'violation_type': 'banned_pattern'
                    })
                break

        # Process dependencies recursively
        if package_name in package_map:
            package_info = package_map[package_name]
            for dep_info in package_info.get('dependencies', []):
                dep_name = dep_info.get('name')
                if dep_name:
                    check_package(dep_name, current_path)

    # Check all packages
    for package in packages:
        package_name = package.get('name')
        if package_name:
            check_package(package_name)

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
    metadata = load_dependency_metadata()
    violations = check_banned_dependencies(metadata)
    generate_report(violations)

    if violations:
        sys.exit(1)

if __name__ == '__main__':
    main()