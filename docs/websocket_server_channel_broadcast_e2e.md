# WebSocket Server ↔ Channel Broadcast E2E Integration

This document describes the comprehensive e2e test implementation for websocket/server ↔ channel/broadcast integration, focusing on multi-subscriber broadcasts with per-client backpressure isolation.

## Module Integration

Located in: `src/real_websocket_server_channel_broadcast_e2e_tests.rs`

### Core Subsystems

1. **`websocket::server`** - WebSocket server infrastructure
   - WebSocket connection management and handshaking
   - Per-client message queuing and flow control
   - Connection state tracking and health monitoring
   - Graceful disconnect handling and resource cleanup

2. **`channel::broadcast`** - Broadcast channel with backpressure
   - One-to-many message distribution
   - Per-subscriber backpressure detection and isolation
   - Priority-based message delivery and dropping
   - Memory-bounded operation with configurable limits

## Key Integration Features

### WebSocket-to-Broadcast Pipeline

Tests complete connection-to-broadcast message flow:
1. **Client Connection** → WebSocket clients connect to server
2. **Subscription Management** → Clients subscribe to broadcast channel
3. **Message Broadcasting** → Server broadcasts messages to all subscribers
4. **Per-Client Delivery** → Messages delivered respecting individual client speeds
5. **Backpressure Isolation** → Slow clients don't block fast clients
6. **Resource Cleanup** → Connections and channels properly cleaned up

### Per-Client Backpressure Isolation

**Isolation Flow:** `Fast Client Queue ⊥ Slow Client Queue → Independent Processing`

**Backpressure Patterns:**
- **Individual Client Queues**: Each client gets separate message queue
- **Backpressure Detection**: Queue size monitoring triggers backpressure state
- **Priority-Based Dropping**: Low priority messages dropped for slow clients
- **Resource Protection**: Memory limits prevent one client from exhausting resources

### Message Delivery Integration

Verifies proper integration of WebSocket and broadcast channel semantics:
- **Connection Management**: WebSocket connections properly tracked and managed
- **Message Ordering**: Broadcast order preserved for each individual client
- **Error Handling**: Network errors and disconnects handled gracefully
- **Statistics Collection**: Per-client and server-wide metrics maintained

## Test Scenarios

### `test_basic_websocket_broadcast_to_multiple_clients()`
**Simple Multi-Client Broadcast**

Tests basic broadcast functionality with multiple WebSocket clients:
1. Connect 5 fast WebSocket clients to server
2. Broadcast 20 messages to all connected clients
3. Verify all clients receive all messages
4. Check message ordering preserved per client
5. Confirm proper resource usage and cleanup

**Verification Points:**
- All clients receive broadcasted messages
- Message order preserved for each client
- No message duplication or loss
- WebSocket connections remain stable throughout
- Server statistics accurately track message delivery

### `test_per_client_backpressure_isolation()`
**Backpressure Isolation Verification**

Tests the core requirement: slow clients don't block fast clients:
1. Connect 2 fast clients and 2 slow clients
2. Configure low queue limits to trigger backpressure quickly
3. Broadcast messages at high rate (20 msg/sec)
4. Verify fast clients receive significantly more messages
5. Confirm slow clients experience backpressure without affecting others

**Backpressure Properties:**
- Fast clients process messages without delay
- Slow clients trigger backpressure detection
- Message delivery isolated between client types
- Fast-to-slow message ratio > 1.5x
- Backpressure statistics properly tracked

### `test_client_disconnect_during_broadcast()`
**Dynamic Connection Management**

Tests server resilience during client disconnections:
1. Connect 4 clients with one configured to disconnect mid-test
2. Start broadcasting messages to all clients
3. Trigger disconnect after 10 messages
4. Verify remaining clients continue receiving messages
5. Confirm proper cleanup of disconnected client resources

**Disconnect Properties:**
- Remaining clients unaffected by disconnect
- Server continues broadcasting to active clients
- Disconnected client resources properly cleaned up
- No memory leaks or connection state corruption
- Connection count statistics accurately updated

### `test_large_message_broadcast_memory_management()`
**Memory Management Under Load**

Tests memory management with large messages and backpressure:
1. Configure 2MB total memory limit for client queues
2. Broadcast 15 large messages (64KB each) to 5 clients
3. Mix fast and slow clients to trigger memory pressure
4. Verify memory limits respected and backpressure applied
5. Confirm large message delivery correctness

**Memory Management Properties:**
- Total memory usage stays within configured limits
- Slow clients experience backpressure with large messages
- Fast clients continue receiving messages efficiently
- Memory allocation and cleanup properly managed
- No out-of-memory conditions under memory pressure

### `test_concurrent_client_subscription_unsubscription()`
**Dynamic Subscription Changes**

Tests handling of clients joining and leaving during broadcasts:
1. Start with 3 initial clients
2. Begin broadcasting messages
3. Add and remove clients dynamically during broadcast
4. Verify message delivery adapts to changing client set
5. Confirm no race conditions or state corruption

**Subscription Properties:**
- New clients receive subsequent messages after joining
- Departed clients don't receive messages after leaving
- Message delivery continues smoothly during client changes
- No race conditions in subscription state management
- Connection tracking remains accurate throughout changes

### `test_priority_message_handling_under_backpressure()`
**Priority-Based Message Delivery**

Tests priority message handling when clients are backpressured:
1. Configure aggressive backpressure limits
2. Connect slow clients that will trigger backpressure quickly
3. Broadcast mix of critical, high, normal, and low priority messages
4. Verify critical messages always delivered
5. Confirm low priority messages dropped for slow clients

**Priority Handling Properties:**
- Critical priority messages never dropped
- Low priority messages dropped under backpressure
- Priority ordering respected in delivery
- Fast clients receive all priority levels
- Backpressure policy enforced per message priority

### `test_broadcast_error_recovery()`
**Error Handling and Recovery**

Tests server resilience under various error conditions:
1. Connect clients with some configured to disconnect unexpectedly
2. Simulate various network error conditions
3. Verify server continues functioning despite errors
4. Check error propagation and logging
5. Confirm graceful degradation and recovery

**Error Recovery Properties:**
- Server continues broadcasting despite individual client errors
- Error conditions properly detected and logged
- Failed operations don't corrupt server state
- Graceful degradation under error conditions
- Recovery after transient error conditions

### `test_resource_cleanup_after_mass_disconnect()`
**Resource Management Under Stress**

Tests resource cleanup when many clients disconnect simultaneously:
1. Connect 8 clients with staggered disconnect times
2. Begin broadcasting to all clients
3. Trigger mass disconnection over time
4. Verify proper resource cleanup for each disconnect
5. Confirm no resource leaks or memory bloat

**Resource Cleanup Properties:**
- Client connection maps properly cleaned up
- Message queues deallocated on disconnect
- Memory usage returns to baseline after disconnects
- No file descriptor or connection leaks
- Statistics accurately reflect remaining active clients

## Test Infrastructure

### `WebSocketBroadcastServer`
WebSocket server with integrated broadcast channel:
- Multi-client connection management
- Per-client message queuing with backpressure detection
- Broadcast channel integration for one-to-many messaging
- Statistics collection and performance monitoring

### `TestWebSocketClient`
Mock WebSocket client with configurable behaviors:
- Fast processing (immediate message consumption)
- Slow processing (artificial delays)
- Intermittent processing (probabilistic delays)
- Backpressured behavior (limited queue consumption)
- Disconnecting behavior (disconnect after N messages)

### `WebSocketBroadcastHarness`
Complete integration test harness:
- Server and client lifecycle management
- Test scenario orchestration and timing
- Statistics collection across all integration layers
- Verification of backpressure isolation properties

### `BackpressureState`
Per-client backpressure tracking and management:
- Queue size monitoring and threshold detection
- Backpressure timing and duration tracking
- Message drop counting and statistics
- Recovery detection and state management

## Real-Service E2E Benefits

### No Mock-Reality Divergence
- Uses actual WebSocket connection management and framing
- Authentic broadcast channel semantics with real backpressure
- Production-representative memory management and resource limits
- Real network-level timing and error conditions

### Integration Bug Detection
- WebSocket frame processing affecting broadcast delivery timing
- Channel backpressure not properly isolated between clients
- Memory leaks in per-client queue management under load
- Race conditions in connection state during concurrent operations

### Production Scenario Modeling
- Realistic client connection patterns and behaviors
- Authentic message sizes and broadcast rates
- Production-scale concurrent connection loads
- Real-world network error conditions and recovery patterns

## Key Properties Verified

### Backpressure Isolation
- Slow clients experience backpressure without affecting fast clients
- Per-client message queues properly isolated and managed
- Fast-to-slow client message delivery ratio demonstrates isolation
- Resource usage bounded per client and globally

### Message Delivery Guarantees
- Broadcast messages delivered to all active clients
- Message ordering preserved for each individual client
- Priority-based delivery and dropping policies enforced
- No message duplication or corruption during delivery

### Resource Management
- Memory usage bounded by configuration limits
- WebSocket connections efficiently managed and cleaned up
- Client queues properly allocated and deallocated
- No resource leaks under error or disconnect conditions

### Error Handling
- Client disconnections handled gracefully without server impact
- Network errors properly detected and isolated
- Server continues functioning despite individual client failures
- Graceful degradation and recovery under stress conditions

## Usage

Run the e2e tests with:

```bash
# Run all WebSocket-broadcast e2e tests
cargo test --lib --features real-service-e2e real_websocket_server_channel_broadcast_e2e_tests

# Run specific backpressure isolation test
cargo test --lib --features real-service-e2e test_per_client_backpressure_isolation

# Run large message memory management test
cargo test --lib --features real-service-e2e test_large_message_broadcast_memory_management

# Run with detailed logging
cargo test --lib --features real-service-e2e test_client_disconnect_during_broadcast -- --nocapture
```

### Debugging Failed Tests

When WebSocket-broadcast integration fails, the structured logging provides:
- Per-client connection state and queue statistics
- Message delivery timing and backpressure detection events
- Memory usage patterns and allocation/deallocation tracking
- Broadcast delivery success rates and error conditions

Example debugging workflow:
1. Review per-client statistics for queue sizes and delivery rates
2. Check backpressure detection logs for timing and thresholds
3. Verify memory usage patterns for leaks or excessive allocation
4. Analyze broadcast delivery logs for ordering or correctness issues

## Advanced Scenarios

### Dynamic Load Balancing
Tests adaptive behavior under varying client loads:
- Client connection rates varying over time
- Message broadcast rates adapted to client capacity
- Dynamic queue size adjustment based on client behavior
- Load shedding and priority-based client service

### High-Throughput Scenarios
Tests performance under extreme message rates:
- Thousands of messages per second broadcast rates
- Hundreds of concurrent client connections
- Large message payloads (MB-scale broadcasts)
- Sustained high-throughput operation with backpressure

### Network Partition Simulation
Tests resilience under network conditions:
- Partial client connectivity during broadcasts
- Network delays affecting delivery timing
- Packet loss and connection instability
- Recovery behavior after network partition resolution

### Priority Queue Optimization
Tests advanced priority-based message delivery:
- Multiple priority levels with complex policies
- Dynamic priority adjustment based on client behavior
- Priority inheritance and escalation policies
- Fairness guarantees across priority levels

This comprehensive e2e testing ensures that the runtime's WebSocket server and broadcast channel integration maintains proper per-client backpressure isolation, efficient resource management, and robust error handling under all realistic operational scenarios.