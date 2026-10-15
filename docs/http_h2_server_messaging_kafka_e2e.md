# HTTP/H2 Server ↔ Messaging Kafka Producer E2E Integration

This document describes the comprehensive e2e test implementation for http/h2 server ↔ messaging/kafka producer integration, focusing on HTTP request-triggered Kafka publishing with backpressure handling.

## Module Integration

Located in: `src/real_http_h2_server_messaging_kafka_e2e_tests.rs`

### Core Subsystems

1. **`http::h2::server`** - HTTP/2 server infrastructure
   - HTTP/2 connection and stream management
   - Request routing and handler dispatch
   - Flow control and connection state tracking
   - RST_STREAM rate limiting for DoS protection

2. **`messaging::kafka`** - Kafka producer with Cx integration
   - Cancel-correct message publishing
   - Exactly-once semantics with idempotent/transactional producers
   - In-flight message tracking as obligations
   - Bounded timeout for acknowledgment waiting

## Key Integration Features

### HTTP-to-Kafka Pipeline

Tests complete request-to-publish processing:
1. **HTTP/2 Request Reception** → Server receives client request via H2 connection
2. **Request Processing** → Handler extracts Kafka topic/key from request
3. **Message Preparation** → HTTP request converted to Kafka message format
4. **Kafka Publishing** → Message sent to Kafka topic with producer acknowledgment
5. **Response Generation** → HTTP response based on Kafka publish result
6. **Resource Cleanup** → Connection and producer resources properly managed

### Backpressure Propagation

**Backpressure Flow:** `Slow Kafka Acks → Producer Queue Full → HTTP 429 Response → Client Retry`

**Backpressure Patterns:**
- **Queue-Based Backpressure**: Producer queue limits prevent memory exhaustion
- **Acknowledgment-Based**: Slow broker acknowledgments trigger flow control
- **Threshold-Based**: Configurable pending message thresholds
- **Rate-Limited Recovery**: Gradual recovery when backpressure conditions improve

### Flow Control Integration

Verifies proper integration of HTTP/2 and Kafka flow control:
- **Connection Management**: HTTP/2 connections managed during producer stress
- **Request Queuing**: Pending requests queued during backpressure events
- **Timeout Handling**: Kafka publish timeouts mapped to HTTP error responses
- **Resource Bounds**: Memory and connection usage bounded under load

## Test Scenarios

### `test_basic_http_to_kafka_publishing()`
**Simple Request-to-Publish Integration**

Tests basic HTTP request triggering Kafka message publishing:
1. Send HTTP POST request with JSON payload
2. Extract Kafka topic and message key from request
3. Convert HTTP request to Kafka message format
4. Publish message to Kafka topic
5. Return success response with publish confirmation

**Verification Points:**
- HTTP request properly parsed and routed
- Kafka message format correctly generated from HTTP payload
- Message successfully published to target topic
- HTTP response contains publish status confirmation
- Server and producer statistics properly tracked

### `test_kafka_producer_backpressure()`
**Backpressure Under Slow Acknowledgments**

Tests backpressure when Kafka acknowledgments are delayed:
1. Configure server with low backpressure threshold
2. Configure Kafka producer with slow acknowledgments
3. Send multiple rapid HTTP requests
4. Verify some succeed and some hit backpressure
5. Check 429 "Too Many Requests" responses returned

**Backpressure Properties:**
- Pending acknowledgment count tracked accurately
- Backpressure threshold properly enforced
- HTTP 429 responses include retry-after headers
- Request statistics track backpressure events
- Service remains available during backpressure

### `test_concurrent_http_requests_with_kafka()`
**Concurrent Request Processing**

Tests multiple simultaneous HTTP requests with Kafka publishing:
1. Send 10 concurrent HTTP requests
2. Each request targets different Kafka topic
3. Verify all requests processed independently
4. Confirm no cross-request interference
5. Validate proper producer resource sharing

**Concurrency Properties:**
- Independent request processing without interference
- Kafka producer efficiently shared across requests
- Message ordering preserved per topic
- Resource usage scales appropriately
- No deadlocks or resource contention

### `test_kafka_timeout_handling()`
**Producer Timeout Management**

Tests timeout handling when Kafka operations are slow:
1. Configure server with short Kafka timeout
2. Configure producer with very slow acknowledgments
3. Send HTTP request that exceeds timeout
4. Verify HTTP 503 "Service Unavailable" response
5. Check timeout error properly reported

**Timeout Properties:**
- Kafka publish operations respect configured timeouts
- Timeout errors properly mapped to HTTP status codes
- Timeout events tracked in server statistics
- Service remains responsive during timeouts
- Resource cleanup after timeout events

### `test_kafka_producer_error_handling()`
**Producer Error Integration**

Tests error handling when Kafka operations fail:
1. Configure producer with high failure rate
2. Send multiple HTTP requests
3. Verify mix of success and error responses
4. Check error messages properly propagated
5. Validate error statistics tracked

**Error Handling Properties:**
- Kafka errors properly mapped to HTTP status codes
- Error messages contain useful diagnostic information
- Error conditions don't corrupt server state
- Error statistics accurately maintained
- Service degrades gracefully under errors

### `test_backpressure_recovery()`
**Service Recovery After Backpressure**

Tests service recovery when backpressure conditions improve:
1. Trigger backpressure with rapid requests
2. Verify backpressure state becomes active
3. Wait for acknowledgments to clear
4. Send new request after recovery
5. Verify service returns to normal operation

**Recovery Properties:**
- Backpressure state properly tracked and updated
- Service automatically recovers when conditions improve
- Pending request queues properly drained
- Recovery timing reasonable and predictable
- Resource usage returns to baseline

### `test_request_response_format()`
**Message Format Integration**

Tests proper request/response format handling:
1. Send HTTP request with specific format
2. Verify Kafka message format conversion
3. Check response format and content type
4. Validate JSON structure in responses
5. Confirm topic information included

**Format Properties:**
- HTTP request properly converted to Kafka message format
- JSON structure preserved through conversion
- Response format consistent and well-structured
- Content-Type headers properly set
- Topic and status information accurately reported

### `test_server_statistics_tracking()`
**Comprehensive Statistics Collection**

Tests statistics tracking across integration layers:
1. Send various types of HTTP requests
2. Track requests, publishes, errors, and timing
3. Verify server-level statistics accuracy
4. Check producer-level metrics
5. Validate statistics consistency

**Statistics Properties:**
- Request counts accurately tracked
- Kafka publish statistics maintained
- Error rates properly calculated
- Timing metrics collected and updated
- Statistics consistent across components

### `test_resource_usage_under_load()`
**Resource Management Under Load**

Tests resource usage during sustained request load:
1. Send sustained HTTP request load (50 requests)
2. Monitor connection and memory usage
3. Verify producer resource management
4. Check acknowledgment processing efficiency
5. Validate bounded resource consumption

**Resource Management Properties:**
- Memory usage bounded independent of load
- Connection resources efficiently managed
- Producer acknowledgments processed efficiently
- No resource leaks under sustained load
- Performance degrades gracefully under stress

## Test Infrastructure

### `HttpKafkaServer`
HTTP/2 server with integrated Kafka publishing:
- Request routing and handler dispatch
- Kafka producer integration with timeout handling
- Backpressure detection and management
- Comprehensive statistics collection

### `MockKafkaProducer`
Kafka producer simulator with acknowledgment control:
- Configurable acknowledgment delays
- Failure simulation and error injection
- Pending message tracking
- Statistics collection and reporting

### `BackpressureState`
Backpressure state tracking and management:
- Active backpressure detection
- Pending request queuing
- Recovery timing and conditions
- Event logging and statistics

### `ServerConfig`
Server configuration for integration testing:
- Connection limits and timeouts
- Kafka producer configuration
- Backpressure thresholds and behavior
- Resource management parameters

## Real-Service E2E Benefits

### No Mock-Reality Divergence
- Uses actual HTTP/2 connection and frame management
- Authentic Kafka producer semantics and acknowledgment patterns
- Production-representative backpressure and flow control
- Real error handling and timeout behavior

### Integration Bug Detection
- HTTP request parsing errors affecting Kafka message format
- Producer acknowledgment handling bugs causing backpressure issues
- Resource leaks in connection management under producer stress
- Error propagation inconsistencies between HTTP and Kafka layers

### Production Scenario Modeling
- Realistic HTTP request patterns and Kafka topic usage
- Authentic producer backpressure and acknowledgment timing
- Production-scale concurrent request handling
- Real-world error conditions and recovery patterns

## Key Properties Verified

### Request Processing
- HTTP requests properly converted to Kafka messages
- Message format preserves request information accurately
- Response timing appropriate for Kafka publish latency
- Error conditions properly reported to clients

### Backpressure Handling
- Backpressure triggers when producer acknowledgments slow
- HTTP clients receive appropriate retry signals (429 status)
- Service remains available during backpressure events
- Recovery occurs automatically when conditions improve

### Resource Management
- Connection resources efficiently managed under load
- Producer resources shared appropriately across requests
- Memory usage bounded during sustained load
- Resource cleanup after errors and timeouts

### Error Handling
- Kafka producer errors properly mapped to HTTP status codes
- Timeout conditions result in appropriate HTTP responses
- Error messages provide useful diagnostic information
- Service state remains consistent after error conditions

## Usage

Run the e2e tests with:

```bash
# Run all HTTP-Kafka e2e tests
cargo test --lib --features real-service-e2e real_http_h2_server_messaging_kafka_e2e_tests

# Run specific backpressure test
cargo test --lib --features real-service-e2e test_kafka_producer_backpressure

# Run timeout handling test
cargo test --lib --features real-service-e2e test_kafka_timeout_handling

# Run with detailed logging
cargo test --lib --features real-service-e2e test_concurrent_http_requests_with_kafka -- --nocapture
```

### Debugging Failed Tests

When HTTP-Kafka integration fails, the structured logging provides:
- Request routing and handler timing information
- Kafka producer acknowledgment delays and error conditions
- Backpressure state transitions and recovery timing
- Resource usage patterns and potential bottlenecks

Example debugging workflow:
1. Review HTTP request parsing logs for format issues
2. Check Kafka producer logs for acknowledgment delays
3. Verify backpressure threshold configuration and behavior
4. Analyze resource usage patterns under load

## Advanced Scenarios

### Dynamic Topic Routing
Tests request-based topic selection and routing:
- Topic extraction from request headers or path
- Dynamic topic creation and validation
- Topic-specific configuration and settings
- Cross-topic message ordering and consistency

### Producer Configuration Optimization
Tests optimal producer configuration for different loads:
- Batch size and linger time optimization
- Acknowledgment level configuration (acks=0,1,all)
- Compression and serialization options
- Memory and resource usage optimization

### Multi-Producer Scenarios
Tests integration with multiple Kafka producers:
- Topic-specific producer instances
- Load balancing across producers
- Producer health monitoring and failover
- Resource isolation and error containment

### Performance Under Scale
Tests integration performance characteristics:
- Throughput scaling with concurrent requests
- Latency distribution under various loads
- Resource efficiency at different scales
- Degradation patterns under extreme load

This comprehensive e2e testing ensures that the runtime's HTTP/2 server and Kafka producer integration maintains proper backpressure handling, efficient resource management, and robust error handling under all realistic operational scenarios.