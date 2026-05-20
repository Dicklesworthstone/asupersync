#!/usr/bin/env bash
#
# ATP Coverage Report Generator
#
# Analyzes ATP modules and generates coverage reports for the test ledger.
# Safe to run even when main crate has compilation issues.

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$REPO_ROOT"

echo -e "${CYAN}ATP Coverage Report Generator${NC}"
echo "======================================"

# Function to count files in a directory
count_files() {
    local dir="$1"
    local pattern="${2:-*.rs}"
    if [[ -d "$dir" ]]; then
        find "$dir" -name "$pattern" | wc -l
    else
        echo "0"
    fi
}

# Function to list files in a directory
list_files() {
    local dir="$1"
    local pattern="${2:-*.rs}"
    if [[ -d "$dir" ]]; then
        find "$dir" -name "$pattern" | sort
    fi
}

# Discover ATP modules
echo -e "\n${BLUE}Discovering ATP Modules${NC}"
echo "------------------------"

# Core ATP modules
ATP_CORE_COUNT=$(count_files "src/atp")
ATP_CORE_FILES=($(list_files "src/atp"))

echo -e "Core ATP modules (src/atp/): ${GREEN}$ATP_CORE_COUNT${NC} files"
for file in "${ATP_CORE_FILES[@]}"; do
    echo "  📄 $file"
done

# Network ATP modules
ATP_NET_COUNT=$(count_files "src/net/atp")
ATP_NET_FILES=($(list_files "src/net/atp"))

echo -e "\nNetwork ATP modules (src/net/atp/): ${GREEN}$ATP_NET_COUNT${NC} files"
for file in "${ATP_NET_FILES[@]}"; do
    echo "  🌐 $file"
done

# CLI ATP modules
ATP_CLI_FILES=($(find src/cli -name "atp_*.rs" 2>/dev/null | sort || true))
ATP_CLI_COUNT=${#ATP_CLI_FILES[@]}

echo -e "\nCLI ATP modules (src/cli/atp_*): ${GREEN}$ATP_CLI_COUNT${NC} files"
for file in "${ATP_CLI_FILES[@]}"; do
    echo "  🖥️  $file"
done

TOTAL_MODULES=$((ATP_CORE_COUNT + ATP_NET_COUNT + ATP_CLI_COUNT))
echo -e "\n${PURPLE}Total ATP modules: $TOTAL_MODULES${NC}"

# Check if ledger exists
echo -e "\n${BLUE}Checking Coverage Ledger${NC}"
echo "-------------------------"

LEDGER_FILE="docs/atp_coverage_ledger.md"
CONTRACT_FILE="docs/atp_test_contract.md"

if [[ -f "$LEDGER_FILE" ]]; then
    echo -e "✅ Coverage ledger exists: ${GREEN}$LEDGER_FILE${NC}"

    # Count modules tracked in ledger
    LEDGER_MODULES=$(grep -E '^\|.*src/(atp|net/atp|cli/atp_)' "$LEDGER_FILE" | wc -l || echo "0")
    echo -e "📊 Modules tracked in ledger: ${GREEN}$LEDGER_MODULES${NC}"

    # Check coverage by status
    TESTED_COUNT=$(grep -E '^\|.*\|\s*TESTED' "$LEDGER_FILE" | wc -l || echo "0")
    PARTIAL_COUNT=$(grep -E '^\|.*\|\s*PARTIAL' "$LEDGER_FILE" | wc -l || echo "0")
    PLANNED_COUNT=$(grep -E '^\|.*\|\s*PLANNED' "$LEDGER_FILE" | wc -l || echo "0")
    MISSING_COUNT=$(grep -E '^\|.*\|\s*MISSING' "$LEDGER_FILE" | wc -l || echo "0")

    echo "  📗 TESTED: $TESTED_COUNT"
    echo "  📙 PARTIAL: $PARTIAL_COUNT"
    echo "  📘 PLANNED: $PLANNED_COUNT"
    echo "  📕 MISSING: $MISSING_COUNT"

    if [[ $LEDGER_MODULES -eq $TOTAL_MODULES ]]; then
        echo -e "✅ ${GREEN}All modules are tracked in ledger${NC}"
    else
        echo -e "⚠️  ${YELLOW}Ledger tracking mismatch: found $TOTAL_MODULES modules, ledger has $LEDGER_MODULES${NC}"
    fi
else
    echo -e "❌ Coverage ledger missing: ${RED}$LEDGER_FILE${NC}"
fi

if [[ -f "$CONTRACT_FILE" ]]; then
    echo -e "✅ Test contract exists: ${GREEN}$CONTRACT_FILE${NC}"
else
    echo -e "❌ Test contract missing: ${RED}$CONTRACT_FILE${NC}"
fi

# Check for existing test files
echo -e "\n${BLUE}Checking Existing Tests${NC}"
echo "-----------------------"

TEST_FILES=($(find tests -name "*atp*" 2>/dev/null | sort || true))
TEST_COUNT=${#TEST_FILES[@]}

echo -e "ATP test files found: ${GREEN}$TEST_COUNT${NC}"
for file in "${TEST_FILES[@]}"; do
    echo "  🧪 $file"
done

# Check for unit tests in modules
echo -e "\n${BLUE}Checking Unit Tests in Modules${NC}"
echo "-------------------------------"

MODULES_WITH_TESTS=0
ALL_ATP_FILES=("${ATP_CORE_FILES[@]}" "${ATP_NET_FILES[@]}" "${ATP_CLI_FILES[@]}")

for module in "${ALL_ATP_FILES[@]}"; do
    if [[ -f "$module" ]]; then
        # Check for test module or #[test] attributes
        if grep -q "#\[test\]" "$module" || grep -q "#\[cfg(test)\]" "$module"; then
            echo -e "  ✅ $module has tests"
            ((MODULES_WITH_TESTS++))
        fi
    fi
done

echo -e "\n📊 Modules with unit tests: ${GREEN}$MODULES_WITH_TESTS${NC} / $TOTAL_MODULES"

# Generate missing modules report
echo -e "\n${BLUE}Missing Test Coverage Analysis${NC}"
echo "--------------------------------"

if [[ -f "$LEDGER_FILE" ]]; then
    echo "Modules not yet tested:"

    for module in "${ALL_ATP_FILES[@]}"; do
        if ! grep -q "$module" "$LEDGER_FILE"; then
            echo -e "  📋 ${YELLOW}$module${NC} - not tracked in ledger"
        elif grep -A1 "$module" "$LEDGER_FILE" | grep -q "PLANNED\|MISSING"; then
            STATUS=$(grep -A1 "$module" "$LEDGER_FILE" | grep -o "PLANNED\|MISSING" || echo "UNKNOWN")
            case $STATUS in
                "PLANNED")
                    echo -e "  📘 ${BLUE}$module${NC} - planned but not implemented"
                    ;;
                "MISSING")
                    echo -e "  📕 ${RED}$module${NC} - missing implementation"
                    ;;
            esac
        fi
    done
fi

# Generate summary
echo -e "\n${PURPLE}Summary${NC}"
echo "======="
echo -e "Total ATP modules: ${GREEN}$TOTAL_MODULES${NC}"
echo -e "Test files: ${GREEN}$TEST_COUNT${NC}"
echo -e "Modules with unit tests: ${GREEN}$MODULES_WITH_TESTS${NC}"
echo -e "Coverage ledger tracking: ${GREEN}$LEDGER_MODULES${NC} modules"

if [[ $TOTAL_MODULES -gt 0 ]]; then
    TEST_PERCENTAGE=$((MODULES_WITH_TESTS * 100 / TOTAL_MODULES))
    echo -e "Unit test coverage: ${GREEN}$TEST_PERCENTAGE%${NC}"

    if [[ $TEST_PERCENTAGE -ge 95 ]]; then
        echo -e "🎉 ${GREEN}Excellent test coverage!${NC}"
    elif [[ $TEST_PERCENTAGE -ge 80 ]]; then
        echo -e "👍 ${YELLOW}Good test coverage, room for improvement${NC}"
    elif [[ $TEST_PERCENTAGE -ge 50 ]]; then
        echo -e "⚠️  ${YELLOW}Moderate test coverage, more tests needed${NC}"
    else
        echo -e "🚨 ${RED}Low test coverage, significant testing work needed${NC}"
    fi
fi

# Recommendations
echo -e "\n${BLUE}Recommendations${NC}"
echo "---------------"

if [[ $MODULES_WITH_TESTS -lt $TOTAL_MODULES ]]; then
    echo -e "📝 Add unit tests to ${RED}$((TOTAL_MODULES - MODULES_WITH_TESTS))${NC} modules without tests"
fi

if [[ $TESTED_COUNT -eq 0 ]]; then
    echo "📊 Begin implementing tests for critical path modules:"
    echo "   - src/atp/object.rs (data model)"
    echo "   - src/atp/manifest.rs (integrity)"
    echo "   - src/atp/verifier.rs (security)"
    echo "   - src/net/atp/protocol.rs (protocol)"
    echo "   - src/atp/sdk.rs (public API)"
fi

if [[ $TEST_COUNT -eq 0 ]]; then
    echo "🧪 Create integration test files for end-to-end scenarios"
fi

echo -e "\n${GREEN}Report complete!${NC}"
echo "Run with: scripts/atp_coverage_report.sh"