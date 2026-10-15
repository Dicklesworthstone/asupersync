# ATP-J5 CLI Workflow Examples

This document provides comprehensive examples of using ATP-J5 logistics workflows for CI artifacts, dataset distribution, fuzz corpus synchronization, release bundle management, and proof bundle archival.

## CI Artifact Management

### Basic CI Artifact Workflows

```bash
# Push build artifacts to cache with deduplication
atp ci push \
  --build-id "build-2024-05-25-1234" \
  --tag linux --tag x86_64 \
  --retention 30d \
  --compression 6 \
  --dedupe \
  --scope "ci:artifacts" \
  target/release/asupersync \
  target/release/docs.tar.gz

# Pull artifacts from previous build
atp ci pull \
  --build-id "build-2024-05-25-1234" \
  --tag linux \
  --dest ./cached-artifacts \
  --if-newer \
  --verify

# List cached artifacts by tag
atp ci list \
  --tag linux \
  --recent 7d \
  --verbose

# Show cache health and usage
atp ci status \
  --stats \
  --health

# Clean up old artifacts
atp ci clean \
  --older-than 30d \
  --build-pattern "build-2024-04-*" \
  --dry-run
```

### Advanced CI Integration

```bash
# CI pipeline with scoped access
export CI_BUILD_ID=$(git rev-parse HEAD | cut -c1-8)
export CI_SCOPE="ci:project-$(basename $PWD)"

# Push artifacts with metadata
atp ci push \
  --build-id "$CI_BUILD_ID" \
  --tag "$(uname -s)" \
  --tag "$(uname -m)" \
  --tag "$CI_BRANCH" \
  --retention "permanent" \
  --compression 9 \
  --dedupe \
  --scope "$CI_SCOPE" \
  dist/*

# Conditional pull in CI
if atp ci list --build-id "$CI_BUILD_ID" --format json | jq -r '.artifacts | length' -gt 0; then
  echo "Artifacts found in cache"
  atp ci pull --build-id "$CI_BUILD_ID" --dest ./artifacts --verify
else
  echo "Building from source"
  make build
fi
```

## Dataset Distribution and Seeding

### Dataset Seeding Workflows

```bash
# Seed a large ML dataset
atp dataset seed \
  --id "imagenet-2024" \
  --metadata '{"type": "image-classification", "classes": 1000, "format": "jpg"}' \
  --chunk-size 10MB \
  --version "2024.1" \
  --replication 3 \
  --access-scope "research:vision" \
  ./datasets/imagenet

# Seed genomics dataset with versioning
atp dataset seed \
  --id "human-genome-reference" \
  --metadata '{"organism": "homo_sapiens", "build": "GRCh38", "format": "fasta"}' \
  --chunk-size 50MB \
  --version "38.p14" \
  --replication 5 \
  --access-scope "research:genomics" \
  ./data/GRCh38

# Get dataset with pattern matching
atp dataset get \
  --dataset-id "imagenet-2024" \
  --version "2024.1" \
  --pattern "train/*.jpg" \
  --dest ./local-datasets \
  --resume

# List available datasets
atp dataset list \
  --pattern "imagenet-*" \
  --local \
  --metadata

# Pin critical datasets locally
atp dataset pin "human-genome-reference" --version "38.p14"

# Show swarm health for dataset distribution
atp dataset status \
  --dataset-id "imagenet-2024" \
  --swarm
```

### Research Data Pipeline

```bash
# Scientific data workflow
DATASET_ID="climate-data-$(date +%Y%m)"
EXPERIMENT_SCOPE="research:climate:$(whoami)"

# Seed experimental dataset
atp dataset seed \
  --id "$DATASET_ID" \
  --metadata "$(cat experiment-metadata.json)" \
  --chunk-size 100MB \
  --version "experimental" \
  --replication 2 \
  --access-scope "$EXPERIMENT_SCOPE" \
  ./raw-climate-data

# Collaborators can retrieve the dataset
atp dataset get \
  --dataset-id "$DATASET_ID" \
  --version "experimental" \
  --dest ./shared-data \
  --resume

# Pin for long-term experiments
atp dataset pin "$DATASET_ID" --version "experimental"
```

## Fuzz Corpus Synchronization

### Basic Fuzz Corpus Operations

```bash
# Bidirectional corpus synchronization
atp fuzz sync \
  --target "http-parser" \
  --strategy bidirectional \
  --exclude "*.tmp" "*.log" \
  ./corpus/http-parser

# Push new test cases to shared corpus
atp fuzz push \
  --target "json-parser" \
  --incremental \
  ./corpus/json-parser

# Pull latest test cases
atp fuzz pull \
  --target "xml-parser" \
  --since "2024-05-20T00:00:00Z" \
  ./corpus/xml-parser

# Merge multiple corpora
atp fuzz merge \
  --output ./merged-corpus \
  --dedupe content-hash \
  ./corpus/parser1 ./corpus/parser2 ./corpus/parser3

# Minimize corpus while preserving coverage
atp fuzz minimize \
  --target "crypto-parser" \
  --coverage-threshold 0.95 \
  ./corpus/crypto-parser

# Show corpus statistics
atp fuzz stats \
  --per-target \
  --coverage \
  ./corpus
```

### Continuous Fuzzing Pipeline

```bash
# Real-time corpus synchronization
atp fuzz sync \
  --target "network-protocol-fuzzer" \
  --strategy bidirectional \
  --watch \
  ./fuzzing/corpus &

# Weekly corpus cleanup
atp fuzz minimize \
  --target "network-protocol-fuzzer" \
  --coverage-threshold 0.90 \
  ./fuzzing/corpus

# Corpus health monitoring
atp fuzz stats \
  --target "network-protocol-fuzzer" \
  --coverage \
  --format json | jq '.corpus_stats.growth_rate'
```

## Release Bundle Distribution

### Software Release Workflows

```bash
# Publish a stable release
atp release publish \
  --version "1.2.0" \
  --channel stable \
  --metadata ./release-metadata.json \
  --sign-cert ./signing.pem \
  --platform linux-x86_64 darwin-arm64 windows-x64 \
  --min-client "1.1.0" \
  ./dist/v1.2.0

# Create differential update package
atp release diff \
  --from ./dist/v1.1.0 \
  --to ./dist/v1.2.0 \
  --output ./updates/v1.1.0-to-v1.2.0.diff \
  --algorithm bsdiff

# Install latest stable release
atp release install \
  --release-id "asupersync" \
  --version latest \
  --dest /opt/asupersync \
  --verify

# List available releases
atp release list \
  --pattern "asupersync-*" \
  --channel stable \
  --latest

# Show release information
atp release info \
  --release-id "asupersync-v1.2.0" \
  --manifest

# Verify release integrity
atp release verify \
  --ca-cert ./ca-certificates.pem \
  --strict \
  ./downloads/asupersync-v1.2.0.bundle
```

### Beta Release Pipeline

```bash
# Automated beta publishing
VERSION="1.3.0-beta.$(git rev-parse --short HEAD)"

atp release publish \
  --version "$VERSION" \
  --channel beta \
  --metadata <(echo '{"commit": "'$(git rev-parse HEAD)'", "branch": "'$(git branch --show-current)'"}') \
  --platform linux-x86_64 \
  --min-client "1.2.0" \
  ./target/release

# Beta testers can install
atp release install \
  --release-id "asupersync" \
  --version "$VERSION" \
  --dest /opt/asupersync-beta \
  --force \
  --verify
```

## Proof Bundle Archival

### Long-term Proof Storage

```bash
# Archive ATP proof bundles
atp archive store \
  --id "transfer-proof-$(date +%Y%m%d-%H%M%S)" \
  --retention 7y \
  --tier warm \
  --tag verification --tag production \
  ./proofs/transfer-12345.atp

# Store critical verification proofs
atp archive store \
  --retention permanent \
  --tier hot \
  --tag critical --tag compliance \
  ./proofs/compliance-audit-2024.atp

# Retrieve archived proofs
atp archive retrieve \
  --archive-id "transfer-proof-20240525-143022" \
  --dest ./retrieved-proofs

# List archived proofs by criteria
atp archive list \
  --tag verification \
  --since "2024-01-01" \
  --tier warm

# Verify archived bundle integrity
atp archive verify \
  --archive-id "transfer-proof-20240525-143022" \
  --deep

# Compact storage to save space
atp archive compact \
  --tier cold \
  --dry-run

# Export proofs for external audit
atp archive export \
  --dest ./audit-export \
  --format tar.gz \
  transfer-proof-20240525-143022 \
  compliance-audit-2024
```

### Compliance and Audit Workflows

```bash
# Automated proof archival in CI
if [[ -f "./atp-proof-bundle.atp" ]]; then
  PROOF_ID="ci-$(basename $PWD)-$(git rev-parse --short HEAD)"
  
  atp archive store \
    --id "$PROOF_ID" \
    --retention 5y \
    --tier warm \
    --tag "ci" --tag "$(basename $PWD)" --tag "$CI_BRANCH" \
    ./atp-proof-bundle.atp
  
  echo "Proof archived with ID: $PROOF_ID"
fi

# Quarterly audit export
QUARTER="Q$((($(date +%-m)-1)/3+1))-$(date +%Y)"
atp archive export \
  --dest "./audit-$QUARTER" \
  --format tar.gz \
  $(atp archive list --tag compliance --since "$(date -d '3 months ago' +%Y-%m-%d)" --format json | jq -r '.archives[].id')
```

## Integrated Workflow Examples

### Complete CI/CD Pipeline

```bash
#!/bin/bash
# Complete ATP-J5 CI/CD pipeline

set -euo pipefail

BUILD_ID="$(git rev-parse HEAD | cut -c1-8)"
PROJECT_SCOPE="ci:$(basename $PWD)"

echo "=== ATP-J5 CI/CD Pipeline ==="
echo "Build ID: $BUILD_ID"
echo "Scope: $PROJECT_SCOPE"

# Step 1: Check for cached artifacts
echo "Checking artifact cache..."
if atp ci list --build-id "$BUILD_ID" --format json | jq -e '.artifacts | length > 0' >/dev/null; then
  echo "Found cached artifacts, pulling..."
  atp ci pull --build-id "$BUILD_ID" --dest ./artifacts --verify
  CACHED_BUILD=true
else
  echo "No cached artifacts, building from source..."
  CACHED_BUILD=false
fi

# Step 2: Build if not cached
if [[ "$CACHED_BUILD" == "false" ]]; then
  echo "Building project..."
  cargo build --release
  cargo test --release
  
  echo "Packaging artifacts..."
  tar -czf "./dist/release-$BUILD_ID.tar.gz" -C target/release .
  
  echo "Pushing artifacts to cache..."
  atp ci push \
    --build-id "$BUILD_ID" \
    --tag "$(uname -s)" --tag "$(uname -m)" \
    --retention 30d \
    --compression 6 \
    --dedupe \
    --scope "$PROJECT_SCOPE" \
    "./dist/release-$BUILD_ID.tar.gz"
fi

# Step 3: Update fuzz corpus if test cases changed
if [[ -d "./fuzz/corpus" ]] && git diff --name-only HEAD~1 | grep -q "fuzz/"; then
  echo "Synchronizing fuzz corpus..."
  atp fuzz sync \
    --target "$(basename $PWD)-fuzzer" \
    --strategy push \
    ./fuzz/corpus
fi

# Step 4: Archive proof bundle if generated
if [[ -f "./atp-proof.bundle" ]]; then
  echo "Archiving proof bundle..."
  atp archive store \
    --id "ci-proof-$BUILD_ID" \
    --retention 1y \
    --tier warm \
    --tag ci --tag "$(git branch --show-current)" \
    ./atp-proof.bundle
fi

# Step 5: Publish release if on main branch
if [[ "$(git branch --show-current)" == "main" ]] && [[ "$CACHED_BUILD" == "false" ]]; then
  VERSION=$(grep '^version = ' Cargo.toml | sed 's/version = "\(.*\)"/\1/')
  
  if ! atp release list --pattern "$(basename $PWD)-v$VERSION" --format json | jq -e '.releases | length > 0' >/dev/null; then
    echo "Publishing release v$VERSION..."
    atp release publish \
      --version "$VERSION" \
      --channel stable \
      --platform "$(uname -s)-$(uname -m)" \
      --min-client "$(grep '^version = ' Cargo.toml | sed 's/version = "\(.*\)"/\1/' | sed 's/\.[0-9]*$//')" \
      "./dist/release-$BUILD_ID.tar.gz"
  fi
fi

echo "=== Pipeline Complete ==="
```

### Research Data Management

```bash
#!/bin/bash
# Research data management workflow

EXPERIMENT_ID="exp-$(date +%Y%m%d)-$(whoami)"
SCOPE="research:$(basename $PWD)"

echo "=== Research Data Pipeline ==="
echo "Experiment: $EXPERIMENT_ID"

# Prepare experiment dataset
echo "Seeding experiment dataset..."
atp dataset seed \
  --id "$EXPERIMENT_ID-input" \
  --metadata "$(jq -n --arg exp "$EXPERIMENT_ID" --arg desc "Input dataset for $EXPERIMENT_ID" '{experiment: $exp, description: $desc, type: "input"}')" \
  --version "1.0" \
  --replication 2 \
  --access-scope "$SCOPE" \
  ./input-data

# Run experiment
echo "Running experiment..."
python run_experiment.py --input ./input-data --output ./results

# Store results
echo "Archiving experiment results..."
tar -czf "./$EXPERIMENT_ID-results.tar.gz" ./results

atp dataset seed \
  --id "$EXPERIMENT_ID-results" \
  --metadata "$(jq -n --arg exp "$EXPERIMENT_ID" --arg desc "Results from $EXPERIMENT_ID" '{experiment: $exp, description: $desc, type: "results"}')" \
  --version "1.0" \
  --replication 3 \
  --access-scope "$SCOPE" \
  ./"$EXPERIMENT_ID-results.tar.gz"

# Pin for collaboration
atp dataset pin "$EXPERIMENT_ID-input" --version "1.0"
atp dataset pin "$EXPERIMENT_ID-results" --version "1.0"

echo "Experiment complete. Collaborators can access:"
echo "  Input:   atp dataset get --dataset-id '$EXPERIMENT_ID-input' --version 1.0"
echo "  Results: atp dataset get --dataset-id '$EXPERIMENT_ID-results' --version 1.0"
```

## JSON Output Examples

All commands support `--format json` for machine-readable output:

```bash
# Get CI cache statistics as JSON
atp ci status --stats --format json | jq '.cache_stats'
```

```json
{
  "total_size_bytes": 1073741824,
  "artifact_count": 100,
  "hit_ratio": 0.85,
  "dedup_savings_bytes": 268435456,
  "available_space_bytes": 9663676416
}
```

```bash
# List datasets with metadata
atp dataset list --metadata --format json | jq '.datasets[]'
```

```json
{
  "id": "imagenet-2024",
  "version": "2024.1",
  "size_bytes": 150000000000,
  "file_count": 14197122,
  "metadata": {
    "type": "image-classification",
    "classes": 1000,
    "format": "jpg"
  },
  "availability": 0.98,
  "replication_factor": 3,
  "health_score": 0.95,
  "updated_at": "2024-05-25T10:30:00Z",
  "pinned": true
}
```

## Configuration and Profiles

Configure ATP profiles for optimized workflows:

```bash
# Set default profile for CI artifacts
atp config set --scope user profile artifact

# Configure dataset chunking
atp config set --scope local dataset.chunk_size 100MB
atp config set --scope local dataset.replication_factor 3

# Show current configuration
atp config show --format json
```

These examples demonstrate the comprehensive capabilities of ATP-J5 workflows for managing CI artifacts, distributing datasets, synchronizing fuzz corpora, managing releases, and archiving proof bundles with cache/swarm integration and capability scoping.