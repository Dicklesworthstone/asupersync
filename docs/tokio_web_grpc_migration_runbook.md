# Web/gRPC/Middleware Migration Runbook and Operator Guide

**Bead**: `asupersync-2oh2u.5.10` ([T5.10])
**Program**: `asupersync-2oh2u` ([TOKIO-REPLACE])
**Date**: 2026-03-04
**Purpose**: Provide end-to-end migration workflows, operator runbooks, and
decision guides for replacing Tokio-dependent web framework, middleware, and
gRPC stacks with asupersync equivalents.

---

## 1. Scope

This runbook covers migration of:
- HTTP server routing (axum-equivalent patterns)
- REST middleware chains (compression, path normalization, CORS, auth)
- gRPC service definitions and interceptors
- gRPC-web protocol bridging
- Service composition and tower-like middleware patterns
- Connection pooling and load balancing for app-level services

Prerequisites:
- `asupersync-2oh2u.5.9` (reference services)
- `asupersync-2oh2u.5.11` (exhaustive unit tests)
- `asupersync-2oh2u.5.12` (e2e service scripts)

---

## 2. Migration Decision Framework

### 2.1 Migration Readiness Checklist

| Check | Description | Pass Criteria |
|-------|-------------|---------------|
| MR-01 | Service inventory complete | all HTTP/gRPC endpoints catalogued |
| MR-02 | Dependency audit | no direct tokio runtime spawns in app code |
| MR-03 | Middleware compatibility | all middleware patterns have asupersync equivalents |
| MR-04 | Test coverage | >= 80% line coverage on service handlers |
| MR-05 | Observability | structured logging with correlation IDs enabled |

### 2.2 Migration Path Selection

| Pattern | From (Tokio) | To (asupersync) | Complexity |
|---------|-------------|-----------------|------------|
| HTTP routing | axum::Router | asupersync::web::Router | Low |
| JSON extraction | axum::extract::Json | asupersync::web::Json | Low |
| Path params | axum::extract::Path | asupersync::web::Path | Low |
| Query params | axum::extract::Query | asupersync::web::Query | Low |
| Middleware | tower::Layer | asupersync::service::Layer | Medium |
| gRPC service | tonic::Service | asupersync::grpc::Service | Medium |
| gRPC codec | tonic::codec | asupersync::grpc::codec | Medium |
| gRPC-web | tonic-web | asupersync::grpc::web | Medium |
| Compression | tower-http::compression | asupersync::web::CompressionMiddleware | Low |
| CORS | tower-http::cors | asupersync::web::CorsMiddleware | Low |
| Connection pool | deadpool/bb8 | asupersync::service::pool | Medium |

---

## 3. Step-by-Step Migration Workflows

### 3.1 HTTP Server Migration

```
Phase 1: Inventory
  - Catalogue all routes, extractors, and response types
  - Map middleware chain order

Phase 2: Adapter Bridge
  - Add asupersync-tokio-compat dependency
  - Wrap tokio::spawn calls with compat bridge
  - Run existing tests through adapter

Phase 3: Direct Replacement
  - Replace axum::Router with asupersync::web::Router
  - Replace extractors (Json, Path, Query, State)
  - Replace middleware layers
  - Remove compat bridge

Phase 4: Verification
  - Run e2e service scripts (T5.12)
  - Verify structured logging output
  - Confirm no performance regression
```

### 3.2 gRPC Service Migration

```
Phase 1: Service Definition
  - Keep .proto files unchanged
  - Map tonic::Request/Response to asupersync equivalents

Phase 2: Interceptor Chain
  - Replace tonic interceptors with asupersync::grpc interceptors
  - Migrate compression (gzip via flate2)
  - Migrate reflection service

Phase 3: gRPC-web Bridge
  - Replace tonic-web with asupersync::grpc::web module
  - Verify Content-Type negotiation (application/grpc-web)

Phase 4: Verification
  - Run gRPC e2e scripts
  - Verify health check endpoints
  - Confirm streaming RPCs work
```

---

## 4. Operator Runbooks

### 4.1 Rollback Procedure

**Trigger**: Migration causes service degradation (latency p99 > 2x baseline,
error rate > 1%, health check failures).

```
1. Revert deployment to last-known-good version
2. Restore tokio runtime configuration
3. Collect diagnostic logs with correlation IDs
4. File incident report with:
   - Timeline of degradation
   - Affected endpoints
   - Log correlation IDs for root cause analysis
5. Re-evaluate migration readiness (MR-01..MR-05)
```

### 4.2 Health Check Verification

**Frequency**: Post-migration, every deployment.

```
1. GET /health returns 200 with valid JSON body
2. gRPC health service returns SERVING for all services
3. Structured log output includes schema_version field
4. No redaction violations in log output
5. Correlation IDs present in all request traces
```

### 4.3 Performance Monitoring

| Metric | Threshold | Action |
|--------|-----------|--------|
| p50 latency | < 10ms (REST), < 5ms (gRPC) | nominal |
| p99 latency | < 100ms (REST), < 50ms (gRPC) | investigate if exceeded |
| Error rate | < 0.1% | investigate if exceeded |
| Connection pool utilization | < 80% | scale if exceeded |
| Memory usage | < 2x baseline | investigate if exceeded |

### 4.4 Incident Escalation

| Severity | Criteria | Response Time | Escalation |
|----------|----------|---------------|------------|
| P0 | Service down | 15 min | On-call + team lead |
| P1 | Degraded performance | 1 hour | On-call |
| P2 | Non-critical regression | 24 hours | Sprint backlog |
| P3 | Documentation gap | Next sprint | Backlog |

---

## 5. Anti-Patterns and Failure Modes

### 5.1 Common Anti-Patterns

| Anti-Pattern | Description | Mitigation |
|-------------|-------------|------------|
| AP-01 | Direct tokio::spawn in handlers | Use structured concurrency via regions |
| AP-02 | Unbounded middleware chains | Limit chain depth, use composition |
| AP-03 | Missing correlation IDs | Inject at edge, propagate via context |
| AP-04 | Silent error swallowing | Return structured errors, log all failures |
| AP-05 | Blocking in async handlers | Use spawn_blocking or dedicated thread pool |

### 5.2 Known Failure Modes

| Mode | Symptom | Root Cause | Resolution |
|------|---------|------------|------------|
| FM-01 | gRPC deadline exceeded | Missing timeout propagation | Set grpc-timeout header |
| FM-02 | Connection pool exhaustion | Leak in acquire/release cycle | Implement drain on shutdown |
| FM-03 | Middleware ordering error | Auth after compression | Ensure auth runs first |
| FM-04 | Memory growth | Unbounded request body | Set max_body_size limit |
| FM-05 | TLS handshake failure | Certificate mismatch | Verify cert chain |

---

## 6. Evidence Links

| Artifact | Location | Purpose |
|----------|----------|---------|
| Parity map | docs/tokio_web_grpc_parity_map.md | Feature-level coverage |
| E2E scripts | tests/web_grpc_e2e_service_scripts.rs | End-to-end verification |
| Unit tests | tests/web_grpc_exhaustive_unit.rs | Contract verification |
| Reference services | docs/tokio_reference_service_* | Working examples |
| Golden corpus | tests/fixtures/logging_golden_corpus/ | Log schema fixtures |

---

## 7. CI Verification Commands

```
rch exec -- cargo test --test tokio_web_grpc_migration_runbook_enforcement -- --nocapture
rch exec -- cargo test --test web_grpc_e2e_service_scripts -- --nocapture
rch exec -- cargo test --test web_grpc_exhaustive_unit -- --nocapture
```

---

## 8. Downstream Dependencies

This runbook is a prerequisite for:
- `asupersync-2oh2u.11.2` (T9.2: domain-specific migration cookbooks)
- `asupersync-2oh2u.10.9` (T8.9: replacement-readiness gate aggregator)
