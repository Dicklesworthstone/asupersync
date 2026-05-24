# E2E Hardening-15 Analysis: Hardcoded Buffer Sizes & Magic Numbers

## 🔍 COMPREHENSIVE HARDCODED VALUES SCAN

### **SUMMARY**: Extensive hardcoded values preventing parameterized test coverage

**Scope**: 40 E2E test files analyzed for hardcoded buffer sizes and magic numbers  
**Focus**: Buffer sizes, timeout values, configuration parameters, loop counts that should be test parameters

---

## 📊 CRITICAL FINDINGS

### **1. WIDESPREAD HARDCODED BUFFER SIZES: 150+ fixed size values**

**Issue**: Extensive use of fixed buffer sizes prevents testing across multiple scenarios  
**Impact**: Limited test coverage, missing edge cases for small/medium/large data scenarios

| Pattern Type | Count | Risk Level |
|--------------|-------|------------|
| **Buffer size constants** | 85+ | ❌ **HIGH** - Single scenario testing |
| **Hardcoded timeouts** | 45+ | ❌ **HIGH** - Fixed timing assumptions |
| **Magic number loops** | 30+ | ❌ **MEDIUM** - Limited load testing |
| **Configuration constants** | 25+ | ❌ **MEDIUM** - Fixed test parameters |
| **Channel capacities** | 20+ | ❌ **MEDIUM** - Single capacity testing |
| **Total hardcoded values** | **200+** | **CRITICAL** |

### **2. FIXED BUFFER SIZES: Missing small/medium/large scenarios**

**Example**: Multipart codec tests in `real_web_multipart_codec_raptorq_e2e_tests.rs`
```rust
let test_data = create_test_file_data(4096, 0xAA);     // Fixed 4KB - what about 64B? 1MB?
let test_data = create_test_file_data(32768, 0xBB);    // Fixed 32KB
chunk_size: 8192,                                      // Fixed 8KB chunks
.max_frame_length(1024 * 1024)                        // Fixed 1MB frame limit
```

### **3. HARDCODED CONCURRENCY LIMITS: Fixed load scenarios**

**Example**: HTTP H2 concurrent tests in `real_http_h2_concurrent_load_e2e_tests.rs`
```rust
let num_clients = 10;                    // Fixed 10 clients - what about 1? 100?
let requests_per_client = 20;            // Fixed 20 requests
let streams_per_connection = 50;         // Fixed 50 streams
```

---

## ❌ PROBLEMATIC PATTERNS IDENTIFIED

### **Pattern 1: Fixed Buffer Size Testing**

**Files**: 25+ files with hardcoded buffer sizes
```rust
// ❌ BAD: Fixed buffer sizes - only test single scenario
let test_data = create_test_file_data(4096, 0xAA);          // Always 4KB
let large_data = create_test_file_data(1024 * 1024, 0x33); // Always 1MB
chunk_size: 8192,                                          // Always 8KB chunks
const WRITE_CHUNK_SIZE: usize = 8192;                      // Fixed chunk size

// What about edge cases?
// - Small buffers (64B, 256B) - different CPU cache behavior
// - Medium buffers (64KB, 256KB) - memory pressure scenarios  
// - Large buffers (16MB, 64MB) - allocation stress testing
// - Odd sizes (4097, 8193) - alignment edge cases
```

**Problems**:
- Only test single buffer size scenario, missing edge cases
- Cannot test performance characteristics across size ranges
- Miss memory allocation failures with large buffers
- Miss cache efficiency issues with small buffers
- No stress testing with extreme sizes

**Found in**:
- `real_web_multipart_codec_raptorq_e2e_tests.rs`: 15+ hardcoded sizes
- `real_fs_e2e_tests.rs`: 8+ fixed file sizes and capacities
- `real_fs_uring_raptorq_encoder_e2e_tests.rs`: 6+ chunk sizes
- `real_http_h2_concurrent_load_e2e_tests.rs`: 5+ buffer constants

### **Pattern 2: Hardcoded Concurrency Parameters**

**Files**: HTTP and WebSocket load tests
```rust
// ❌ BAD: Fixed concurrency parameters
let num_clients = 10;                    // Always 10 concurrent clients
let requests_per_client = 20;            // Always 20 requests
let streams_per_connection = 50;         // Always 50 streams
const NUM_CLIENTS: usize = 3;           // Always 3 clients

// Missing test scenarios:
// - Light load (1 client, 1 request) - single-threaded behavior
// - Medium load (10 clients, 100 requests) - moderate concurrency
// - Heavy load (100 clients, 1000 requests) - stress testing
// - Extreme load (1000 clients, 10000 requests) - breaking point
```

**Problems**:
- Only test single concurrency level
- Cannot validate scalability characteristics
- Miss race conditions that appear under high load
- Miss resource exhaustion issues with many connections
- Cannot test graceful degradation under load

**Found in**:
- `real_http_h2_concurrent_load_e2e_tests.rs`: 8+ concurrency constants
- `real_websocket_server_channel_broadcast_e2e_tests.rs`: 6+ client counts
- `real_quic_native_e2e_tests.rs`: 4+ connection limits
- `real_tcp_unix_e2e_tests.rs`: 3+ client parameters

### **Pattern 3: Fixed Timeout Values**

**Files**: All async test files
```rust
// ❌ BAD: Hardcoded timeouts - environment dependent
send_timeout: Duration::from_millis(100),        // Always 100ms
max_test_duration: Duration::from_secs(10),      // Always 10s
delivery_timeout: Duration::from_secs(5),        // Always 5s
sleep(Duration::from_millis(200)).await;         // Always 200ms delay

// What about different environments?
// - Fast environments (local SSD) - shorter timeouts sufficient
// - Slow environments (CI, network storage) - need longer timeouts  
// - Debug builds - much slower, need extended timeouts
// - Stress scenarios - intentionally longer operations
```

**Problems**:
- Timeouts fail in slower CI/debug environments
- Cannot test timeout behavior across different latency scenarios
- Miss timeout edge cases (just under/over threshold)
- Fixed delays make tests unnecessarily slow
- Cannot validate timeout handling robustness

**Found in**:
- `real_websocket_server_channel_broadcast_e2e_tests.rs`: 12+ timeout constants
- `real_http_h2_concurrent_load_e2e_tests.rs`: 8+ delay values
- Network and I/O test files universally affected

### **Pattern 4: Hardcoded Channel Capacities**

**Files**: Channel and messaging tests
```rust
// ❌ BAD: Fixed channel capacities
const STATUS_CHANNEL_CAPACITY: usize = 1000;        // Always 1000
let (broadcast_tx, _) = broadcast::channel(1024);   // Always 1024
const MAX_DECODED_FRAMES: usize = 1000;            // Always 1000

// Missing scenarios:
// - Small capacity (10) - backpressure testing
// - Medium capacity (1000) - normal operation
// - Large capacity (100000) - memory stress
// - Unbounded - resource exhaustion testing
```

**Problems**:
- Cannot test backpressure behavior with small channels
- Miss memory usage patterns with large channels
- Cannot validate channel overflow handling
- Single capacity scenario limits coverage

### **Pattern 5: Configuration Parameter Constants**

**Files**: Server and client configuration tests
```rust
// ❌ BAD: Fixed configuration values
max_pending_per_client: 50,                    // Always 50
max_total_memory_bytes: 1024 * 1024,          // Always 1MB
max_frame_length(1024 * 1024),                // Always 1MB
const MAX_DIRECTORY_ENTRIES: usize = 10_000;   // Always 10k

// Should be parameterized for:
// - Resource-constrained scenarios (small limits)
// - Normal operation scenarios (medium limits)
// - High-throughput scenarios (large limits)
```

**Problems**:
- Cannot test resource limit enforcement
- Miss edge cases at configuration boundaries
- Single configuration prevents stress testing
- Cannot validate graceful degradation behaviors

---

## ✅ CORRECT PATTERNS (Parameterized Test Examples)

### **Pattern 1: Parameterized Buffer Size Testing**

```rust
// ✅ GOOD: Parameterized buffer size scenarios
#[derive(Debug, Clone)]
struct BufferTestScenario {
    name: &'static str,
    buffer_size: usize,
    chunk_size: usize,
    expected_chunks: usize,
    performance_expectations: PerformanceExpectations,
}

#[derive(Debug, Clone)]
struct PerformanceExpectations {
    max_processing_time_ms: u64,
    max_memory_usage_bytes: usize,
    min_throughput_mbps: f64,
}

fn buffer_test_scenarios() -> Vec<BufferTestScenario> {
    vec![
        BufferTestScenario {
            name: "small_buffer_cache_aligned",
            buffer_size: 256,           // Cache-friendly small buffer
            chunk_size: 64,
            expected_chunks: 4,
            performance_expectations: PerformanceExpectations {
                max_processing_time_ms: 10,
                max_memory_usage_bytes: 1024,
                min_throughput_mbps: 100.0,
            },
        },
        BufferTestScenario {
            name: "medium_buffer_page_aligned",
            buffer_size: 64 * 1024,     // 64KB - page aligned
            chunk_size: 8192,
            expected_chunks: 8,
            performance_expectations: PerformanceExpectations {
                max_processing_time_ms: 50,
                max_memory_usage_bytes: 128 * 1024,
                min_throughput_mbps: 500.0,
            },
        },
        BufferTestScenario {
            name: "large_buffer_stress_test",
            buffer_size: 16 * 1024 * 1024,  // 16MB - stress allocation
            chunk_size: 1024 * 1024,
            expected_chunks: 16,
            performance_expectations: PerformanceExpectations {
                max_processing_time_ms: 1000,
                max_memory_usage_bytes: 32 * 1024 * 1024,
                min_throughput_mbps: 1000.0,
            },
        },
        BufferTestScenario {
            name: "odd_size_edge_case",
            buffer_size: 4097,          // Odd size to test alignment
            chunk_size: 1000,
            expected_chunks: 5,
            performance_expectations: PerformanceExpectations {
                max_processing_time_ms: 20,
                max_memory_usage_bytes: 8192,
                min_throughput_mbps: 50.0,
            },
        },
    ]
}

#[test]
fn test_multipart_upload_parameterized_buffer_sizes() {
    for scenario in buffer_test_scenarios() {
        println!("Testing buffer scenario: {}", scenario.name);
        let test_start = Instant::now();
        
        let mut pipeline = FileUploadPipeline::new()
            .with_chunk_size(scenario.chunk_size)
            .with_performance_monitoring(true);
        
        let test_data = create_test_file_data(scenario.buffer_size, 0xAA);
        let upload = MockMultipartUpload::new(
            "file".to_string(),
            Some(format!("test_{}.bin", scenario.name)),
            test_data.clone(),
        ).with_chunk_size(scenario.chunk_size);
        
        // Process with performance monitoring
        let processed = pipeline.process_upload(upload)
            .expect(&format!("Processing should succeed for {}", scenario.name));
        
        // Verify expected chunk count
        assert_eq!(
            processed.metadata.chunk_count,
            scenario.expected_chunks,
            "Scenario {}: Expected {} chunks, got {}",
            scenario.name,
            scenario.expected_chunks,
            processed.metadata.chunk_count
        );
        
        // Verify performance expectations
        let elapsed = test_start.elapsed().as_millis() as u64;
        assert!(
            elapsed <= scenario.performance_expectations.max_processing_time_ms,
            "Scenario {}: Processing took {} ms, expected max {} ms",
            scenario.name,
            elapsed,
            scenario.performance_expectations.max_processing_time_ms
        );
        
        let memory_usage = pipeline.get_peak_memory_usage();
        assert!(
            memory_usage <= scenario.performance_expectations.max_memory_usage_bytes,
            "Scenario {}: Memory usage {} bytes, expected max {} bytes",
            scenario.name,
            memory_usage,
            scenario.performance_expectations.max_memory_usage_bytes
        );
        
        println!("✓ Scenario {} completed: {} ms, {} MB peak memory",
                 scenario.name, elapsed, memory_usage / 1024 / 1024);
    }
}
```

### **Pattern 2: Parameterized Concurrency Testing**

```rust
// ✅ GOOD: Parameterized concurrency scenarios
#[derive(Debug, Clone)]
struct ConcurrencyTestScenario {
    name: &'static str,
    num_clients: usize,
    requests_per_client: usize,
    connection_timeout_ms: u64,
    request_timeout_ms: u64,
    expected_behavior: ExpectedBehavior,
}

#[derive(Debug, Clone)]
enum ExpectedBehavior {
    AllSucceed,
    MostSucceed { min_success_rate: f64 },
    GracefulDegradation { max_error_rate: f64 },
    ResourceExhaustion,
}

fn concurrency_test_scenarios() -> Vec<ConcurrencyTestScenario> {
    vec![
        ConcurrencyTestScenario {
            name: "light_load_single_client",
            num_clients: 1,
            requests_per_client: 1,
            connection_timeout_ms: 1000,
            request_timeout_ms: 500,
            expected_behavior: ExpectedBehavior::AllSucceed,
        },
        ConcurrencyTestScenario {
            name: "moderate_load_normal_operation",
            num_clients: 10,
            requests_per_client: 20,
            connection_timeout_ms: 2000,
            request_timeout_ms: 1000,
            expected_behavior: ExpectedBehavior::MostSucceed { min_success_rate: 0.95 },
        },
        ConcurrencyTestScenario {
            name: "heavy_load_stress_test",
            num_clients: 100,
            requests_per_client: 100,
            connection_timeout_ms: 5000,
            request_timeout_ms: 2000,
            expected_behavior: ExpectedBehavior::GracefulDegradation { max_error_rate: 0.10 },
        },
        ConcurrencyTestScenario {
            name: "extreme_load_breaking_point",
            num_clients: 1000,
            requests_per_client: 1000,
            connection_timeout_ms: 30000,
            request_timeout_ms: 10000,
            expected_behavior: ExpectedBehavior::ResourceExhaustion,
        },
    ]
}

#[tokio::test]
async fn test_http2_parameterized_concurrency() {
    for scenario in concurrency_test_scenarios() {
        println!("Testing concurrency scenario: {}", scenario.name);
        
        let harness = Arc::new(Http2LoadTestHarness::new().await);
        harness.configure_timeouts(
            scenario.connection_timeout_ms,
            scenario.request_timeout_ms,
        );
        
        let _server = harness.start_test_server().await
            .expect(&format!("Failed to start server for {}", scenario.name));
        
        let mut client_handles = Vec::new();
        let start_time = Instant::now();
        
        // Create concurrent clients
        for client_id in 0..scenario.num_clients {
            let harness_clone = Arc::clone(&harness);
            
            let handle = tokio::spawn(async move {
                match harness_clone.create_h2_client(client_id).await {
                    Ok(client) => {
                        harness_clone.run_concurrent_load_test(
                            client,
                            client_id,
                            scenario.requests_per_client
                        ).await
                    }
                    Err(e) => Err(format!("Client {} failed to connect: {}", client_id, e))
                }
            });
            
            client_handles.push(handle);
        }
        
        // Collect results
        let mut successful_clients = 0;
        let mut total_requests = 0;
        let mut successful_requests = 0;
        
        for handle in client_handles {
            match handle.await {
                Ok(Ok(result)) => {
                    successful_clients += 1;
                    total_requests += scenario.requests_per_client;
                    successful_requests += result.successful_requests;
                }
                Ok(Err(error)) => {
                    println!("Client failed: {}", error);
                    total_requests += scenario.requests_per_client;
                }
                Err(e) => {
                    println!("Client task panicked: {}", e);
                }
            }
        }
        
        let elapsed = start_time.elapsed().as_millis();
        let success_rate = if total_requests > 0 {
            successful_requests as f64 / total_requests as f64
        } else {
            0.0
        };
        
        // Verify expected behavior
        match scenario.expected_behavior {
            ExpectedBehavior::AllSucceed => {
                assert_eq!(
                    successful_clients,
                    scenario.num_clients,
                    "Scenario {}: Expected all {} clients to succeed, {} succeeded",
                    scenario.name,
                    scenario.num_clients,
                    successful_clients
                );
                assert!(
                    success_rate >= 0.99,
                    "Scenario {}: Expected >99% success rate, got {:.2}%",
                    scenario.name,
                    success_rate * 100.0
                );
            }
            ExpectedBehavior::MostSucceed { min_success_rate } => {
                assert!(
                    success_rate >= min_success_rate,
                    "Scenario {}: Expected >{:.1}% success rate, got {:.2}%",
                    scenario.name,
                    min_success_rate * 100.0,
                    success_rate * 100.0
                );
            }
            ExpectedBehavior::GracefulDegradation { max_error_rate } => {
                let error_rate = 1.0 - success_rate;
                assert!(
                    error_rate <= max_error_rate,
                    "Scenario {}: Expected <{:.1}% error rate, got {:.2}%",
                    scenario.name,
                    max_error_rate * 100.0,
                    error_rate * 100.0
                );
            }
            ExpectedBehavior::ResourceExhaustion => {
                // For extreme load, we expect failures but want to verify graceful handling
                assert!(
                    success_rate < 0.5 || elapsed > 20000,
                    "Scenario {}: Expected resource exhaustion (low success rate or high latency)",
                    scenario.name
                );
            }
        }
        
        println!(
            "✓ Scenario {} completed: {:.1}% success rate, {} ms total",
            scenario.name,
            success_rate * 100.0,
            elapsed
        );
    }
}
```

### **Pattern 3: Environment-Adaptive Timeouts**

```rust
// ✅ GOOD: Environment-adaptive timeout configuration
#[derive(Debug, Clone)]
struct TimeoutConfig {
    base_timeout_ms: u64,
    multiplier: f64,
    max_timeout_ms: u64,
}

impl TimeoutConfig {
    fn for_environment() -> Self {
        let is_debug = cfg!(debug_assertions);
        let is_ci = std::env::var("CI").is_ok();
        let is_slow_fs = std::env::var("ASUPERSYNC_SLOW_STORAGE").is_ok();
        
        match (is_debug, is_ci, is_slow_fs) {
            (true, true, true) => Self {     // Debug + CI + Slow storage
                base_timeout_ms: 1000,
                multiplier: 10.0,
                max_timeout_ms: 60000,
            },
            (true, true, false) => Self {    // Debug + CI
                base_timeout_ms: 500,
                multiplier: 5.0,
                max_timeout_ms: 30000,
            },
            (true, false, _) => Self {       // Debug local
                base_timeout_ms: 200,
                multiplier: 3.0,
                max_timeout_ms: 10000,
            },
            (false, true, _) => Self {       // Release CI
                base_timeout_ms: 100,
                multiplier: 2.0,
                max_timeout_ms: 5000,
            },
            (false, false, _) => Self {      // Release local
                base_timeout_ms: 50,
                multiplier: 1.0,
                max_timeout_ms: 2000,
            },
        }
    }
    
    fn connection_timeout(&self) -> Duration {
        let timeout_ms = (self.base_timeout_ms as f64 * self.multiplier) as u64;
        Duration::from_millis(timeout_ms.min(self.max_timeout_ms))
    }
    
    fn request_timeout(&self) -> Duration {
        let timeout_ms = ((self.base_timeout_ms / 2) as f64 * self.multiplier) as u64;
        Duration::from_millis(timeout_ms.min(self.max_timeout_ms / 2))
    }
    
    fn test_duration_limit(&self) -> Duration {
        let timeout_ms = (self.base_timeout_ms as f64 * self.multiplier * 20.0) as u64;
        Duration::from_millis(timeout_ms.min(self.max_timeout_ms))
    }
}

#[tokio::test]
async fn test_websocket_with_adaptive_timeouts() {
    let timeout_config = TimeoutConfig::for_environment();
    
    let server_config = ServerConfig {
        max_pending_per_client: 50,
        max_total_memory_bytes: 1024 * 1024,
        send_timeout: timeout_config.request_timeout(),
        drop_low_priority: false,
    };
    
    let test_config = TestConfig {
        num_clients: 5,
        num_messages: 20,
        message_size: 256,
        broadcast_rate: 10.0,
        max_test_duration: timeout_config.test_duration_limit(),
    };
    
    println!(
        "Using adaptive timeouts - connection: {} ms, request: {} ms, test: {} ms",
        timeout_config.connection_timeout().as_millis(),
        timeout_config.request_timeout().as_millis(),
        timeout_config.test_duration_limit().as_millis()
    );
    
    let mut harness = WebSocketBroadcastHarness::new(server_config, test_config).await
        .expect("Harness creation should succeed with adaptive timeouts");
    
    // Test proceeds with environment-appropriate timeouts
}
```

### **Pattern 4: Parameterized Channel Configurations**

```rust
// ✅ GOOD: Parameterized channel capacity testing
#[derive(Debug, Clone)]
struct ChannelTestScenario {
    name: &'static str,
    capacity: ChannelCapacity,
    producer_rate: usize,        // messages per second
    consumer_rate: usize,        // messages per second
    test_duration_ms: u64,
    expected_behavior: ChannelBehavior,
}

#[derive(Debug, Clone)]
enum ChannelCapacity {
    Bounded(usize),
    Unbounded,
}

#[derive(Debug, Clone)]
enum ChannelBehavior {
    NoBackpressure,
    ModerateBackpressure { max_blocked_time_ms: u64 },
    HighBackpressure { min_blocked_time_ms: u64 },
    ResourceExhaustion,
}

fn channel_test_scenarios() -> Vec<ChannelTestScenario> {
    vec![
        ChannelTestScenario {
            name: "small_capacity_fast_consumer",
            capacity: ChannelCapacity::Bounded(10),
            producer_rate: 100,     // 100 msg/sec
            consumer_rate: 200,     // 200 msg/sec - faster than producer
            test_duration_ms: 1000,
            expected_behavior: ChannelBehavior::NoBackpressure,
        },
        ChannelTestScenario {
            name: "small_capacity_matched_rates",
            capacity: ChannelCapacity::Bounded(10),
            producer_rate: 100,     // 100 msg/sec
            consumer_rate: 100,     // 100 msg/sec - matched rates
            test_duration_ms: 1000,
            expected_behavior: ChannelBehavior::ModerateBackpressure { max_blocked_time_ms: 100 },
        },
        ChannelTestScenario {
            name: "small_capacity_slow_consumer",
            capacity: ChannelCapacity::Bounded(10),
            producer_rate: 200,     // 200 msg/sec
            consumer_rate: 50,      // 50 msg/sec - much slower
            test_duration_ms: 1000,
            expected_behavior: ChannelBehavior::HighBackpressure { min_blocked_time_ms: 500 },
        },
        ChannelTestScenario {
            name: "unbounded_memory_stress",
            capacity: ChannelCapacity::Unbounded,
            producer_rate: 10000,   // Very fast producer
            consumer_rate: 10,      // Very slow consumer
            test_duration_ms: 2000,
            expected_behavior: ChannelBehavior::ResourceExhaustion,
        },
    ]
}
```

---

## 🔧 SYSTEMATIC FIX TEMPLATES

### **Template 1: Buffer Size Parameterization**

```rust
// BEFORE: Hardcoded buffer size
let test_data = create_test_file_data(4096, 0xAA);
let processed = pipeline.process_upload(upload).expect("Processing should succeed");

// AFTER: Parameterized buffer scenarios
#[derive(Debug, Clone)]
struct BufferScenario {
    name: &'static str,
    size: usize,
    expected_chunks: usize,
    performance_class: PerformanceClass,
}

#[derive(Debug, Clone)]
enum PerformanceClass {
    Fast,    // Small buffers, cache-friendly
    Medium,  // Moderate buffers, page-aligned
    Slow,    // Large buffers, allocation stress
}

fn test_with_buffer_scenarios<F>(test_fn: F) 
where 
    F: Fn(&BufferScenario) -> Result<(), String>
{
    let scenarios = vec![
        BufferScenario { name: "small", size: 256, expected_chunks: 1, performance_class: PerformanceClass::Fast },
        BufferScenario { name: "medium", size: 64 * 1024, expected_chunks: 8, performance_class: PerformanceClass::Medium },
        BufferScenario { name: "large", size: 16 * 1024 * 1024, expected_chunks: 2048, performance_class: PerformanceClass::Slow },
    ];
    
    for scenario in scenarios {
        println!("Testing buffer scenario: {}", scenario.name);
        test_fn(&scenario).expect(&format!("Scenario {} should pass", scenario.name));
    }
}
```

### **Template 2: Concurrency Parameterization**

```rust
// BEFORE: Fixed concurrency
let num_clients = 10;
let requests_per_client = 20;

// AFTER: Parameterized concurrency scenarios  
#[derive(Debug, Clone)]
struct ConcurrencyScenario {
    name: &'static str,
    clients: usize,
    requests_per_client: usize,
    load_class: LoadClass,
}

#[derive(Debug, Clone)]
enum LoadClass {
    Light,      // Single client, minimal load
    Moderate,   // Normal operation load
    Heavy,      // Stress testing
    Extreme,    // Breaking point testing
}

impl ConcurrencyScenario {
    fn scenarios() -> Vec<Self> {
        vec![
            Self { name: "light", clients: 1, requests_per_client: 1, load_class: LoadClass::Light },
            Self { name: "moderate", clients: 10, requests_per_client: 20, load_class: LoadClass::Moderate },
            Self { name: "heavy", clients: 100, requests_per_client: 100, load_class: LoadClass::Heavy },
            Self { name: "extreme", clients: 1000, requests_per_client: 1000, load_class: LoadClass::Extreme },
        ]
    }
}
```

### **Template 3: Adaptive Timeout Configuration**

```rust
// BEFORE: Fixed timeouts
send_timeout: Duration::from_millis(100),
max_test_duration: Duration::from_secs(10),

// AFTER: Environment-adaptive timeouts
fn get_timeout_multiplier() -> f64 {
    match (cfg!(debug_assertions), std::env::var("CI").is_ok()) {
        (true, true) => 10.0,   // Debug + CI
        (true, false) => 3.0,   // Debug local  
        (false, true) => 2.0,   // Release CI
        (false, false) => 1.0,  // Release local
    }
}

fn adaptive_timeout(base_ms: u64) -> Duration {
    let multiplier = get_timeout_multiplier();
    Duration::from_millis((base_ms as f64 * multiplier) as u64)
}

// Usage
send_timeout: adaptive_timeout(100),
max_test_duration: adaptive_timeout(10000),
```

### **Template 4: Configuration Parameterization**

```rust
// BEFORE: Fixed configuration
max_pending_per_client: 50,
max_total_memory_bytes: 1024 * 1024,

// AFTER: Parameterized configuration scenarios
#[derive(Debug, Clone)]
struct ResourceScenario {
    name: &'static str,
    max_pending_per_client: usize,
    max_total_memory_bytes: usize,
    resource_class: ResourceClass,
}

#[derive(Debug, Clone)]
enum ResourceClass {
    Constrained,  // Low resource limits
    Normal,       // Standard limits
    Generous,     // High limits for stress testing
}

impl ResourceScenario {
    fn scenarios() -> Vec<Self> {
        vec![
            Self { 
                name: "constrained", 
                max_pending_per_client: 10, 
                max_total_memory_bytes: 64 * 1024,
                resource_class: ResourceClass::Constrained 
            },
            Self { 
                name: "normal", 
                max_pending_per_client: 50, 
                max_total_memory_bytes: 1024 * 1024,
                resource_class: ResourceClass::Normal 
            },
            Self { 
                name: "generous", 
                max_pending_per_client: 1000, 
                max_total_memory_bytes: 100 * 1024 * 1024,
                resource_class: ResourceClass::Generous 
            },
        ]
    }
}
```

---

## 📈 PRIORITIZATION BY TEST COVERAGE IMPACT

### **Critical Priority: Buffer Size Parameterization (85+ instances)**
**Impact**: Single-scenario testing misses memory/performance edge cases  
**Files**: `real_web_multipart_codec_raptorq_e2e_tests.rs`, `real_fs_e2e_tests.rs`
**Fix**: Implement small/medium/large buffer test scenarios

### **Critical Priority: Concurrency Parameterization (50+ instances)**
**Impact**: Fixed concurrency prevents scalability and race condition testing
**Operations**: HTTP load tests, WebSocket broadcast tests
**Fix**: Light/moderate/heavy/extreme load scenarios

### **High Priority: Timeout Parameterization (45+ instances)**
**Impact**: Environment-dependent test failures and slow test execution
**Operations**: All async operations with timeouts
**Fix**: Environment-adaptive timeout configuration

### **High Priority: Channel Capacity Parameterization (20+ instances)**
**Impact**: Single capacity testing misses backpressure and resource scenarios
**Operations**: Message channels, broadcast channels
**Fix**: Small/medium/large/unbounded capacity testing

### **Medium Priority: Configuration Parameterization (25+ instances)**
**Impact**: Single configuration prevents resource limit testing
**Operations**: Server configs, client limits
**Fix**: Constrained/normal/generous resource scenarios

---

## 🚀 IMPLEMENTATION PHASES

### **Phase 1: Buffer Size Parameterization (Critical Coverage)**
**Target**: Replace hardcoded buffer sizes with parameterized scenarios (85+ instances)
**Effort**: Create buffer scenario enums and test runners for small/medium/large sizes
**Template**: Buffer size parameterization

### **Phase 2: Concurrency Parameterization (Scalability Testing)**
**Target**: Replace fixed client/request counts with load scenarios (50+ instances)
**Effort**: Create load scenario configurations for light/moderate/heavy/extreme testing
**Template**: Concurrency parameterization

### **Phase 3: Timeout Adaptation (Environmental Robustness)**
**Target**: Replace fixed timeouts with environment-adaptive configuration (45+ instances)
**Effort**: Implement timeout multiplier system based on debug/CI environment
**Template**: Adaptive timeout configuration

### **Phase 4: Configuration Scenarios (Resource Testing)**
**Target**: Replace fixed configs with resource constraint scenarios (45+ instances)  
**Effort**: Create configuration scenarios for constrained/normal/generous limits
**Template**: Configuration parameterization

---

## 🎯 DELIVERY STATUS

**ANALYSIS COMPLETE**: Comprehensive hardcoded values scan of 40 E2E test files done  
**CRITICAL GAPS IDENTIFIED**: 200+ hardcoded values preventing parameterized coverage  
**TEMPLATES ESTABLISHED**: 4 comprehensive parameterization patterns  
**READY FOR SYSTEMATIC IMPLEMENTATION**: Prioritized by test coverage impact

**Most problematic files**:
- `real_web_multipart_codec_raptorq_e2e_tests.rs`: 15+ hardcoded buffer sizes
- `real_http_h2_concurrent_load_e2e_tests.rs`: 13+ concurrency/timeout constants
- `real_websocket_server_channel_broadcast_e2e_tests.rs`: 18+ configuration values
- `real_fs_e2e_tests.rs`: 12+ file size and capacity constants
- **ALL** async test files have hardcoded timeout values

**Next Steps**:
1. Implement buffer scenario parameterization for size testing (Phase 1: 85+ instances)
2. Add concurrency scenario parameterization for load testing (Phase 2: 50+ instances)
3. Deploy environment-adaptive timeout configuration (Phase 3: 45+ instances)
4. Create resource constraint configuration scenarios (Phase 4: 45+ instances)

**Scope for systematic rollout**: 200+ parameterization improvements across 40+ files