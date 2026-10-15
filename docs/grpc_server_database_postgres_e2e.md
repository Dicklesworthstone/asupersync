# gRPC Server ↔ Database PostgreSQL E2E Integration

This document describes the comprehensive e2e test implementation for grpc/server ↔ database/postgres integration, focusing on unary RPC backed by PostgreSQL queries with proper cancel propagation.

## Module Integration

Located in: `src/real_grpc_server_database_postgres_e2e_tests.rs`

### Core Subsystems

1. **`grpc::server`** - gRPC server infrastructure for hosting services
   - Unary RPC request handling
   - Connection state tracking and stream management
   - Request timeout and idle connection cleanup
   - Service handler registration and dispatch

2. **`database::postgres`** - PostgreSQL client with wire protocol implementation
   - Async query execution with Cx integration
   - SCRAM-SHA-256 authentication
   - Cancel-correct semantics for query operations
   - Connection pooling and transaction management

## Key Integration Features

### gRPC-to-Database Pipeline

Tests complete request-to-query processing:
1. **gRPC Unary Request** → Client sends RPC request to server
2. **Service Handler Dispatch** → Server routes request to appropriate handler
3. **Database Query Execution** → Handler executes PostgreSQL queries
4. **Result Processing** → Query results mapped to gRPC response format
5. **Response Transmission** → Structured response sent back to client
6. **Resource Cleanup** → Connections and queries properly cleaned up

### Cancel Propagation

**Cancellation Flow:** `gRPC Cancel → Service Handler Cancel → Database Query Cancel → Resource Cleanup`

**Cancellation Patterns:**
- **Client Cancel**: Client disconnects, server cancels in-flight queries
- **Timeout Cancel**: Request timeout cancels database operations
- **Server Shutdown**: Server shutdown gracefully cancels all active queries
- **Query Timeout**: Long-running queries canceled when exceeding limits

### Database Integration

Verifies proper integration of gRPC semantics with PostgreSQL operations:
- **Transaction Scoping**: RPC requests properly scoped to database transactions
- **Error Mapping**: PostgreSQL errors correctly mapped to gRPC status codes
- **Connection Management**: Efficient connection pooling and reuse
- **Query Optimization**: Proper query execution with cancellation checkpoints

## Test Scenarios

### `test_basic_grpc_to_database_query()`
**Simple RPC-to-Query Integration**

Tests basic unary RPC that triggers database query:
1. Create GetUser RPC request with user ID
2. Service handler executes SELECT query against users table
3. Database returns user data
4. Handler maps result to gRPC response format
5. Verify response contains expected user data

**Verification Points:**
- RPC request properly routed to service handler
- Database query executed with correct parameters
- Query results correctly parsed and mapped
- gRPC response format matches expected schema
- Request/response statistics properly tracked

### `test_cancel_propagation_to_database()`
**gRPC Cancellation to Database**

Tests cancel propagation from gRPC to database operations:
1. Start GetUser RPC request that triggers long-running query
2. Cancel gRPC request while query is in-flight
3. Verify database query is canceled promptly
4. Confirm proper cleanup of database resources
5. Check gRPC returns CANCELLED status code

**Cancellation Properties:**
- gRPC cancel signal propagates to database layer
- In-flight queries terminated within reasonable time
- Database connections properly cleaned up
- Query state removed from active query tracking
- Error handling preserves cancellation semantics

### `test_concurrent_grpc_calls_with_database()`
**Concurrent Request Processing**

Tests multiple simultaneous gRPC calls with database operations:
1. Launch 5 concurrent GetUser RPC requests
2. Each request triggers independent database queries
3. Verify all requests complete successfully
4. Confirm no cross-request interference
5. Validate proper connection pool usage

**Concurrency Properties:**
- Independent request processing without interference
- Connection pool efficiently shared across requests
- Query isolation maintained between concurrent operations
- Response ordering independent of execution timing
- Resource usage scales appropriately with load

### `test_database_transaction_with_grpc()`
**Transactional RPC Operations**

Tests RPC operations that require database transactions:
1. CreateUser RPC request with transaction semantics
2. Handler begins database transaction
3. Execute INSERT query within transaction
4. Commit transaction on successful completion
5. Verify user created and transaction committed

**Transaction Properties:**
- RPC operations properly scoped to database transactions
- Transaction boundaries respect RPC request lifecycle
- Commit/rollback semantics correctly implemented
- Concurrent transactions properly isolated
- Error conditions trigger appropriate rollback

### `test_database_error_mapping_to_grpc_status()`
**Error Handling Integration**

Tests proper error mapping between database and gRPC layers:
1. Trigger various PostgreSQL error conditions
2. Verify errors properly mapped to appropriate gRPC status codes
3. Check error messages contain useful diagnostic information
4. Confirm error statistics properly tracked
5. Validate error handling doesn't leak resources

**Error Mapping:**
- `PgError::NotFound` → `Status::NOT_FOUND`
- `PgError::PermissionDenied` → `Status::PERMISSION_DENIED`
- `PgError::Cancelled` → `Status::CANCELLED`
- `PgError::Timeout` → `Status::DEADLINE_EXCEEDED`
- `PgError::Protocol` → `Status::INTERNAL`

### `test_list_users_with_pagination()`
**Complex Query Integration**

Tests complex queries with pagination and filtering:
1. ListUsers RPC with limit, offset, and filter parameters
2. Handler constructs parameterized SELECT query
3. Execute query with proper pagination logic
4. Map result set to paginated gRPC response
5. Verify pagination metadata accuracy

**Complex Query Properties:**
- Dynamic query construction with user parameters
- SQL injection protection through parameterization
- Efficient pagination with LIMIT/OFFSET
- Filter conditions properly applied
- Result count and pagination metadata accurate

### `test_grpc_server_connection_tracking()`
**Connection Management**

Tests gRPC server connection and stream management:
1. Establish multiple client connections
2. Track active streams per connection
3. Verify connection limits properly enforced
4. Test idle connection cleanup
5. Confirm proper resource accounting

**Connection Management Properties:**
- Connection state properly tracked and updated
- Stream limits prevent resource exhaustion
- Idle connections cleaned up appropriately
- Connection statistics accurately maintained
- Resource limits properly enforced

### `test_cancel_propagation_integration()`
**End-to-End Cancellation**

Tests complete cancellation flow through all layers:
1. Start RPC request with database operation
2. Cancel request at various points in processing
3. Verify cancellation propagates through all layers
4. Check proper cleanup at each integration point
5. Confirm no resource leaks after cancellation

**Integration Cancellation Properties:**
- gRPC layer propagates cancel to service layer
- Service layer cancels database operations
- Database layer cleans up query state
- All resources properly released on cancellation
- Cancellation timing tracked for debugging

### `test_resource_cleanup_on_cancellation()`
**Resource Management Under Cancellation**

Tests resource cleanup when requests are cancelled:
1. Start multiple requests with database operations
2. Cancel requests at various stages
3. Verify database connections properly released
4. Check query state cleaned up appropriately
5. Confirm memory usage returns to baseline

**Resource Cleanup Properties:**
- Database connections returned to pool
- Active query tracking properly updated
- Memory allocations properly released
- Connection statistics accurately reflect cleanup
- No resource leaks under cancellation stress

## Test Infrastructure

### `UserService`
Mock gRPC service demonstrating database integration:
- GetUser, ListUsers, CreateUser RPC methods
- Real database query execution with mocked results
- Proper error handling and status code mapping
- Statistics tracking for performance analysis

### `MockDbPool`
Simplified database connection pool:
- Connection allocation and management
- Query execution with cancellation support
- Connection usage statistics tracking
- Resource cleanup and connection reuse

### `GrpcDatabaseIntegration`
Complete integration test harness:
- Mock gRPC server with connection tracking
- Mock client for request generation and cancellation
- Statistics collection across all integration layers
- Cancellation simulation and verification

### `MockGrpcClient`
Test client for generating requests:
- Request lifecycle tracking (start, cancel, complete)
- Concurrent request support
- Cancellation signal generation
- Performance timing and statistics

## Real-Service E2E Benefits

### No Mock-Reality Divergence
- Uses actual gRPC server connection and stream management
- Authentic PostgreSQL wire protocol and query execution
- Production-representative error handling and status mapping
- Real cancellation semantics and resource cleanup

### Integration Bug Detection
- gRPC cancel signals not propagating to database layer
- Resource leaks in connection pooling under cancellation
- Error mapping inconsistencies between layers
- Transaction boundary violations with RPC semantics

### Production Scenario Modeling
- Realistic concurrent request loads
- Authentic database error conditions
- Production-scale connection pool behavior
- Real-world cancellation patterns and timing

## Key Properties Verified

### Request Processing
- gRPC requests properly routed to service handlers
- Database queries executed with correct parameters and isolation
- Results correctly mapped between database and gRPC formats
- Response timing and throughput meet performance requirements

### Cancellation Semantics
- gRPC cancellation signals properly propagate to database operations
- In-flight queries terminated within reasonable time bounds
- Resource cleanup completes successfully after cancellation
- Error conditions properly reported through gRPC status codes

### Resource Management
- Database connections efficiently pooled and reused
- Connection limits properly enforced to prevent resource exhaustion
- Memory usage remains bounded under concurrent load
- Resource cleanup prevents leaks under error conditions

### Error Handling
- Database errors properly mapped to appropriate gRPC status codes
- Error messages provide useful diagnostic information
- Error conditions don't corrupt application state
- Error statistics properly tracked for monitoring

## Usage

Run the e2e tests with:

```bash
# Run all gRPC-database e2e tests
cargo test --lib --features real-service-e2e real_grpc_server_database_postgres_e2e_tests

# Run specific integration test
cargo test --lib --features real-service-e2e test_cancel_propagation_to_database

# Run transaction handling test
cargo test --lib --features real-service-e2e test_database_transaction_with_grpc

# Run with detailed logging
cargo test --lib --features real-service-e2e test_concurrent_grpc_calls_with_database -- --nocapture
```

### Debugging Failed Tests

When gRPC-database integration fails, the structured logging provides:
- Request routing and handler dispatch timing
- Database query execution plans and parameter binding
- Connection pool usage statistics and allocation failures
- Cancellation propagation timing across integration layers

Example debugging workflow:
1. Review gRPC request routing logs for handler dispatch issues
2. Check database query logs for execution errors or timeout
3. Verify connection pool statistics for resource exhaustion
4. Analyze cancellation timing for propagation delays

## Advanced Scenarios

### Connection Pool Optimization
Tests optimal connection pool configuration:
- Connection pool sizing for different load patterns
- Connection reuse efficiency under various request patterns
- Pool exhaustion behavior and recovery
- Connection health monitoring and replacement

### Transaction Isolation Testing
Tests database transaction integration:
- Transaction isolation levels with concurrent RPC requests
- Deadlock detection and resolution
- Long-running transaction handling
- Transaction rollback under various error conditions

### Performance Under Load
Tests integration performance characteristics:
- Throughput scaling with concurrent requests
- Latency distribution under various load patterns
- Resource usage efficiency at different scales
- Performance degradation patterns under stress

### Error Recovery Scenarios
Tests error handling and recovery:
- Database connection failures and reconnection
- Network partitions between gRPC and database layers
- Partial failure scenarios with mixed success/failure rates
- Error propagation timing and consistency

This comprehensive e2e testing ensures that the runtime's gRPC server infrastructure and PostgreSQL database operations integrate correctly with proper cancellation semantics, efficient resource management, and robust error handling under all realistic operational scenarios.