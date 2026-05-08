# Database Testing Migration: make_test_connection → Real Database Integration

**Bead**: br-asupersync-qr9j1k  
**Methodology**: testing-perfect-e2e  

## Overview

This migration replaces mock `make_test_connection()` calls with real PostgreSQL and MySQL database integration tests following the testing-perfect-e2e methodology. The goal is to improve test coverage by validating behavior against actual database servers while preserving the existing mock tests where they provide better value.

## Migration Strategy

### Test Categories and Priorities

**HIGH PRIORITY (Migrated to Real Database):**
- **Cancellation handling tests** (22 tests) - Complex state interactions with cancellation at protocol boundaries  
- **Query execution & error handling** (7 tests) - Real server error responses and state transitions
- **Transaction isolation** (1 test) - Isolation levels must be verified against real server
- **Deallocate retry logic** (1 test) - Real backend failures improve coverage

**KEPT AS MOCKS (Not Migrated):**
- **Wire protocol parsing** (18 tests) - Deterministic message injection is superior for these
- **Type conversion** (19 tests) - Pure deserialization, no state changes needed  
- **Utility tests** - URL parsing, Display implementations, etc.

### Files Created

1. **`tests/postgres_make_test_connection_migration.rs`** - Real PostgreSQL integration tests
2. **`tests/mysql_make_test_connection_migration.rs`** - Real MySQL integration tests  
3. **`DATABASE_TESTING_MIGRATION.md`** - This documentation

## Running the Tests

### PostgreSQL Real Database Tests

```bash
# Start local PostgreSQL server (Docker recommended)
docker run -d --name postgres-test \
  -e POSTGRES_PASSWORD=postgres \
  -p 5432:5432 \
  postgres:15

# Run the migration tests
rch exec -- env REAL_PG_TESTS=true POSTGRES_URL=postgres://postgres:postgres@localhost:5432/postgres CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_database_testing_migration_docs cargo test --features postgres --test postgres_make_test_connection_migration
```

### MySQL Real Database Tests

```bash  
# Start local MySQL server (Docker recommended)
docker run -d --name mysql-test \
  -e MYSQL_ROOT_PASSWORD=password \
  -p 3306:3306 \
  mysql:8.0

# Run the migration tests
rch exec -- env REAL_MYSQL_TESTS=true MYSQL_URL=mysql://root:password@localhost:3306/mysql CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_database_testing_migration_docs cargo test --features mysql --test mysql_make_test_connection_migration
```

## Production Safety Guards

Both test suites include hard production guards:

- **`NODE_ENV=production`** - Tests are blocked completely
- **Production URLs** - URLs containing "prod" or "production" are rejected
- **Remote hosts** - Non-localhost URLs require explicit `ALLOW_NON_LOCALHOST_POSTGRES=true` / `ALLOW_NON_LOCALHOST_MYSQL=true`
- **Environment gates** - Tests only run when `REAL_PG_TESTS=true` / `REAL_MYSQL_TESTS=true`
- **Redacted skip logs** - Blocked `POSTGRES_URL` / `MYSQL_URL` values are never printed to CI logs

## Test Structure and Logging

All tests follow structured JSON logging for CI integration:

```json
{"ts":1698765432123,"suite":"postgres_migration","test":"real_pg_cancelled_commit_marks_connection_for_rollback","event":"test_start"}
{"ts":1698765432124,"suite":"postgres_migration","test":"real_pg_cancelled_commit_marks_connection_for_rollback","event":"phase","phase":"connect","phase_num":"0","elapsed_ms":"1"}
{"ts":1698765432200,"suite":"postgres_migration","test":"real_pg_cancelled_commit_marks_connection_for_rollback","event":"test_end","result":"pass","duration_ms":"77"}
```

## Key Test Cases Migrated

### PostgreSQL

1. **`real_pg_cancelled_commit_marks_connection_for_rollback`** - Verifies transaction state tracking under commit cancellation
2. **`real_pg_cancelled_rollback_marks_connection_for_rollback`** - Verifies rollback cancellation handling
3. **`real_pg_deallocate_caller_cancellation_vs_backend_failure`** - Tests prepared statement cleanup distinction between caller cancellation and backend failures
4. **`real_pg_begin_with_isolation_rollback_on_cancel`** - Transaction isolation level setup under cancellation  
5. **`real_pg_query_execution_error_handling`** - Real PostgreSQL error responses and session recovery

### MySQL

1. **`real_mysql_cancelled_commit_marks_connection_for_rollback`** - MySQL transaction cancellation handling
2. **`real_mysql_cancelled_rollback_marks_connection_for_rollback`** - MySQL rollback cancellation
3. **`real_mysql_query_execution_error_handling`** - MySQL-specific error codes and session recovery

## Differences from Mock Tests

### Real Database Value-Add

- **Actual server error codes**: PostgreSQL SQLSTATE codes, MySQL error numbers
- **Real transaction state transitions**: Server-driven transaction status bytes
- **Protocol compliance verification**: Actual server responses vs. hand-crafted messages
- **Connection health tracking**: Real backend failure scenarios for pool management
- **Session recovery**: Verification that connections remain usable after errors

### When Mocks are Superior

- **Wire protocol parsing**: Need to inject malformed/edge-case messages that rarely occur in production
- **Type conversion**: Deterministic deserialization testing doesn't need server state
- **Error message parsing**: Hand-crafted error responses test parsing edge cases

## Integration with Existing Tests

- **Mock tests remain**: `make_test_connection()` and `make_test_connection_with_peer()` tests are preserved
- **No test duplication**: Real database tests focus on server-behavior validation  
- **Complementary coverage**: Mocks test protocol compliance, real databases test integration behavior

## CI/CD Integration

Tests should be integrated into CI pipelines with:

1. **Docker services** for PostgreSQL and MySQL test databases
2. **Environment variable gates** to enable real database tests only in appropriate environments
3. **Structured logging ingestion** for test metrics and failure analysis
4. **Parallel execution** where real database tests can run alongside existing unit tests

## Future Considerations

- **Test containers**: Consider using testcontainers-rs for automatic test database lifecycle management
- **Database state isolation**: Each test uses transactions with rollback to avoid state leakage
- **Performance**: Real database tests are slower than mocks - consider running them in separate CI stages
- **Coverage expansion**: Additional high-value scenarios can be migrated as they're identified

## References

- **Original bead**: br-asupersync-qr9j1k  
- **Methodology**: /testing-perfect-e2e in AGENTS.md
- **Existing pattern**: `tests/postgres_real_server.rs` and `tests/integration/mysql_real_server.rs`
- **Mock test locations**: `src/database/postgres.rs` (lines 5904+), `src/database/mysql.rs` (lines 4324+)
