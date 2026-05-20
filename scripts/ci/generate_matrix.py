#!/usr/bin/env python3
"""
ATP-N7: Proof Lane Matrix Generator

Generates the CI matrix configuration for ATP proof lanes based on:
- Proof mode (smoke, full, release)
- Target platforms (linux, macos, windows)
- Lane definitions and dependencies
"""

import argparse
import json
import sys
from typing import Dict, List, Any

# ATP Proof Lane Definitions
PROOF_LANES = {
    # Fast Smoke Lanes (< 10 minutes total)
    "compile": {
        "name": "Compile Check",
        "description": "Basic compilation check across platforms",
        "timeout": "5m",
        "platforms": ["linux", "macos", "windows"],
        "commands": ["cargo check --all-targets", "cargo clippy -- -D warnings"],
        "artifacts": ["compile-log.txt"],
        "smoke": True,
        "full": True,
        "release": True,
        "guarantees": ["code compiles", "no clippy warnings"],
    },

    "unit": {
        "name": "Unit Tests",
        "description": "Fast unit test suite",
        "timeout": "8m",
        "platforms": ["linux", "macos", "windows"],
        "commands": ["cargo test --lib --bins"],
        "artifacts": ["unit-test-results.xml", "coverage-report.json"],
        "smoke": True,
        "full": True,
        "release": True,
        "guarantees": ["core logic correctness", "API contracts"],
    },

    "fmt": {
        "name": "Format Check",
        "description": "Code formatting validation",
        "timeout": "2m",
        "platforms": ["linux"],
        "commands": ["cargo fmt --check"],
        "artifacts": ["fmt-check.txt"],
        "smoke": True,
        "full": True,
        "release": True,
        "guarantees": ["consistent code formatting"],
    },

    # Full Proof Lanes (comprehensive testing)
    "atp_conformance": {
        "name": "ATP Protocol Conformance",
        "description": "QUIC protocol conformance and frame validation tests",
        "timeout": "20m",
        "platforms": ["linux", "macos", "windows"],
        "commands": [
            "cargo test atp::quic::conformance",
            "cargo test --test atp_conformance_suite"
        ],
        "artifacts": [
            "conformance-results.json",
            "frame-roundtrip-tests.log",
            "protocol-validation.log"
        ],
        "dependencies": ["compile", "unit"],
        "smoke": False,
        "full": True,
        "release": True,
        "guarantees": ["QUIC protocol compliance", "frame codec correctness"],
        "features": ["quic-conformance"],
    },

    "atp_fuzz": {
        "name": "ATP Fuzz Testing",
        "description": "Fuzzing for QUIC frames and packet parsing",
        "timeout": "30m",
        "platforms": ["linux"],
        "commands": [
            "cargo test atp::quic::fuzz_harness",
            "scripts/ci/run_fuzz_suite.sh --duration 1800" # 30 min
        ],
        "artifacts": [
            "fuzz-results.json",
            "fuzz-coverage.log",
            "crash-reports/"
        ],
        "dependencies": ["compile", "atp_conformance"],
        "smoke": False,
        "full": True,
        "release": True,
        "guarantees": ["protocol robustness", "no parser crashes"],
        "features": ["fuzz-testing"],
    },

    "atp_e2e": {
        "name": "ATP E2E Proof Suite",
        "description": "End-to-end crash-resume and object transfer tests",
        "timeout": "45m",
        "platforms": ["linux", "macos"],
        "commands": [
            "cargo test atp::e2e_proof_suite",
            "scripts/ci/run_e2e_scenarios.sh"
        ],
        "artifacts": [
            "e2e-results.json",
            "crash-recovery-logs/",
            "obligation-leak-report.json",
            "failure-artifacts/"
        ],
        "dependencies": ["compile", "unit", "atp_conformance"],
        "smoke": False,
        "full": True,
        "release": True,
        "guarantees": [
            "crash-safe recovery",
            "no obligation leaks",
            "object transfer integrity"
        ],
        "features": ["crash-injection", "forensics"],
    },

    "atp_packet_lab": {
        "name": "ATP Packet Laboratory",
        "description": "Deterministic network scenario testing",
        "timeout": "25m",
        "platforms": ["linux"],
        "commands": [
            "cargo test atp::quic::packet_lab",
            "scripts/ci/run_network_scenarios.sh"
        ],
        "artifacts": [
            "packet-lab-results.json",
            "network-scenario-logs/",
            "loss-recovery-stats.json"
        ],
        "dependencies": ["compile", "atp_conformance"],
        "smoke": False,
        "full": True,
        "release": True,
        "guarantees": ["network resilience", "loss recovery correctness"],
        "features": ["packet-simulation"],
    },

    "dependency_audit": {
        "name": "Dependency Audit",
        "description": "Audit for prohibited external dependencies",
        "timeout": "10m",
        "platforms": ["linux"],
        "commands": [
            "scripts/ci/audit_dependencies.sh",
            "cargo tree --format json | scripts/ci/check_banned_deps.py"
        ],
        "artifacts": [
            "dependency-report.json",
            "banned-deps-check.log"
        ],
        "dependencies": [],
        "smoke": False,
        "full": True,
        "release": True,
        "guarantees": [
            "no external QUIC stacks",
            "no Tokio runtime in ATP core",
            "allowed dependency versions"
        ],
        "features": [],
    },

    "platform_caps": {
        "name": "Platform Capabilities",
        "description": "Platform-specific feature and capability validation",
        "timeout": "15m",
        "platforms": ["linux", "macos", "windows"],
        "commands": [
            "cargo test platform_capabilities",
            "scripts/ci/test_platform_features.sh"
        ],
        "artifacts": [
            "platform-report.json",
            "capability-matrix.json"
        ],
        "dependencies": ["compile", "unit"],
        "smoke": False,
        "full": True,
        "release": True,
        "guarantees": ["cross-platform compatibility", "feature detection"],
        "features": ["platform-specific"],
    },

    # Release Proof Lanes (extended/stress testing)
    "atp_stress": {
        "name": "ATP Stress Testing",
        "description": "Extended stress and load testing",
        "timeout": "90m",
        "platforms": ["linux"],
        "commands": [
            "scripts/ci/run_stress_tests.sh",
            "scripts/ci/run_load_tests.sh"
        ],
        "artifacts": [
            "stress-test-results.json",
            "performance-metrics.json",
            "memory-usage-report.json"
        ],
        "dependencies": ["atp_e2e", "atp_packet_lab"],
        "smoke": False,
        "full": False,
        "release": True,
        "guarantees": ["performance under load", "memory stability"],
        "features": ["stress-testing"],
    },

    "atp_security": {
        "name": "ATP Security Testing",
        "description": "Security and adversarial testing",
        "timeout": "60m",
        "platforms": ["linux"],
        "commands": [
            "cargo test atp_security_tests",
            "scripts/ci/run_security_audit.sh"
        ],
        "artifacts": [
            "security-report.json",
            "vulnerability-scan.json"
        ],
        "dependencies": ["atp_e2e", "atp_fuzz"],
        "smoke": False,
        "full": False,
        "release": True,
        "guarantees": ["security properties", "no known vulnerabilities"],
        "features": ["security-testing"],
    },

    "atp_benchmarks": {
        "name": "ATP Benchmarks",
        "description": "Performance benchmarking and regression detection",
        "timeout": "45m",
        "platforms": ["linux"],
        "commands": [
            "cargo bench --bench atp_benchmarks",
            "scripts/ci/run_comparison_benchmarks.sh"
        ],
        "artifacts": [
            "benchmark-results.json",
            "performance-comparison.json",
            "regression-report.json"
        ],
        "dependencies": ["atp_e2e"],
        "smoke": False,
        "full": False,
        "release": True,
        "guarantees": ["performance baseline", "no regressions"],
        "features": ["benchmarking"],
    },
}

# Platform configurations
PLATFORM_CONFIG = {
    "linux": {
        "runner": "ubuntu-latest",
        "platform_script": "linux",
        "features": ["io-uring", "epoll", "native-sockets"],
    },
    "macos": {
        "runner": "macos-latest",
        "platform_script": "macos",
        "features": ["kqueue", "native-sockets"],
    },
    "windows": {
        "runner": "windows-latest",
        "platform_script": "windows",
        "features": ["iocp", "winsock"],
    },
}

def generate_matrix(mode: str, platforms: List[str]) -> Dict[str, Any]:
    """Generate the CI matrix for the given mode and platforms."""

    matrix = {
        "smoke": [],
        "full": [],
        "release": []
    }

    target_platforms = platforms if platforms else ["linux", "macos", "windows"]

    for lane_id, lane_config in PROOF_LANES.items():
        # Check if lane should run in the requested mode
        if mode == "smoke" and not lane_config.get("smoke", False):
            continue
        if mode == "full" and not lane_config.get("full", False):
            continue
        if mode == "release" and not lane_config.get("release", False):
            continue

        # Generate matrix entries for applicable platforms
        for platform in target_platforms:
            if platform not in lane_config["platforms"]:
                continue

            if platform not in PLATFORM_CONFIG:
                continue

            platform_config = PLATFORM_CONFIG[platform]

            matrix_entry = {
                "lane": {
                    "id": lane_id,
                    "name": lane_config["name"],
                    "description": lane_config["description"],
                    "timeout": lane_config["timeout"],
                    "commands": lane_config["commands"],
                    "artifacts": lane_config["artifacts"],
                    "guarantees": lane_config["guarantees"],
                },
                "platform": platform_config["runner"],
                "platform_script": platform_config["platform_script"],
                "features": platform_config["features"] + lane_config.get("features", []),
                "dependencies": lane_config.get("dependencies", []),
            }

            # Add to appropriate mode matrix
            if lane_config.get("smoke", False):
                matrix["smoke"].append(matrix_entry.copy())
            if lane_config.get("full", False):
                matrix["full"].append(matrix_entry.copy())
            if lane_config.get("release", False):
                matrix["release"].append(matrix_entry.copy())

    return matrix

def main():
    parser = argparse.ArgumentParser(description="Generate ATP proof lane matrix")
    parser.add_argument("--mode", choices=["smoke", "full", "release"],
                      default="smoke", help="Proof mode")
    parser.add_argument("--platforms", default="linux,macos,windows",
                      help="Comma-separated list of platforms")
    parser.add_argument("--output", default="matrix.json",
                      help="Output file for matrix JSON")

    args = parser.parse_args()

    platforms = [p.strip() for p in args.platforms.split(",")]
    matrix = generate_matrix(args.mode, platforms)

    with open(args.output, 'w') as f:
        json.dump(matrix, f, indent=2)

    print(f"Generated {args.mode} matrix with {len(matrix[args.mode])} entries")
    print(f"Matrix written to {args.output}")

if __name__ == "__main__":
    main()