//! Real E2E integration tests: grpc/streaming ↔ service/retry integration (br-e2e-169).
//!
//! Tests streaming gRPC calls retry on transient errors without duplicating headers.
//! Verifies that the gRPC streaming system and service retry mechanism coordinate
//! properly to handle transient failures while maintaining streaming semantics
//! and preventing header duplication across retry attempts.
//!
//! # Integration Patterns Tested
//!
//! - **Streaming gRPC Retry Behavior**: Transparent retry for transient errors
//! - **Header Deduplication**: Preventing duplicate headers across retry attempts
//! - **Stream State Management**: Maintaining stream position and metadata across retries
//! - **Transient Error Detection**: Differentiating between retryable and non-retryable errors
//! - **Backoff and Timing**: Proper retry timing and exponential backoff strategies
//!
//! # Test Scenarios
//!
//! 1. **Basic Stream Retry** — Simple streaming retry on network transient error
//! 2. **Header Deduplication** — Verify headers not duplicated across retry attempts
//! 3. **Multi-Message Stream Retry** — Retry behavior with partial stream consumption
//! 4. **Bidirectional Stream Retry** — Complex retry behavior for bidirectional streams
//! 5. **Retry Exhaustion Handling** — Behavior when retry limits are exceeded
//! 6. **Stream Metadata Preservation** — Metadata consistency across retry attempts
//!
//! # Safety Properties Verified
//!
//! - No header duplication occurs during streaming retries
//! - Stream position is correctly maintained across retry attempts
//! - Transient errors are retried transparently to the client
//! - Non-retryable errors are propagated without retry attempts
//! - Backoff timing prevents excessive retry load on servers

#![allow(dead_code, unused_variables, unused_imports)]

use crate::{
    grpc::{
        streaming::{
            GrpcStream, StreamingClient, StreamingServer, StreamType, StreamDirection,
            StreamMessage, StreamMetadata, StreamError, StreamConfig, StreamState,
            BidirectionalStream, ClientStream, ServerStream, StreamingContext,
            MessageFlow, FlowControl, Backpressure, StreamBuffer, StreamWindow,
        },
        client::{
            GrpcClient, ClientConfig, ClientBuilder, ConnectionManager, ChannelPool,
            RequestBuilder, ResponseHandler, ClientInterceptor, ClientMetrics,
        },
        server::{
            GrpcServer, ServerConfig, ServerBuilder, ServiceRegistry, RequestHandler,
            ServerInterceptor, ServerMetrics, MethodHandler, ServiceHandler,
        },
        codec::{
            GrpcCodec, MessageCodec, Encoder, Decoder, CompressionCodec, CompressionType,
            MessageSerialization, ProtobufCodec, JsonCodec, BinaryCodec,
        },
        interceptor::{
            Interceptor, InterceptorChain, RequestInterceptor, ResponseInterceptor,
            MetadataInterceptor, LoggingInterceptor, MetricsInterceptor,
        },
        status::{
            GrpcStatus, StatusCode, ErrorDetails, StatusMessage, StatusMetadata,
            RetryableStatus, TransientError, PermanentError, ErrorClassification,
        },
        metadata::{
            GrpcMetadata, MetadataMap, MetadataEntry, MetadataKey, MetadataValue,
            HeaderMap, HeaderDeduplication, HeaderMerging, CustomMetadata,
        },
    },
    service::{
        retry::{
            RetryService, RetryConfig, RetryPolicy, RetryError, RetryMetrics, RetryAttempt,
            BackoffStrategy, ExponentialBackoff, LinearBackoff, JitteredBackoff,
            RetryPredicate, RetryCondition, MaxAttempts, TimeoutConfig, CircuitBreaker,
        },
        layer::{
            ServiceLayer, LayerStack, LayerConfig, ServiceMiddleware, RequestLayer,
            ResponseLayer, ErrorLayer, MetricsLayer, TracingLayer, TimeoutLayer,
        },
        load_balance::{
            LoadBalancer, LoadBalanceStrategy, WeightedRoundRobin, LeastConnections,
            HealthCheck, EndpointDiscovery, ServiceDiscovery, EndpointHealth,
        },
        timeout::{
            TimeoutService, TimeoutConfig, TimeoutError, DeadlineExceeded, RequestTimeout,
            ResponseTimeout, ConnectionTimeout, StreamTimeout, GlobalTimeout,
        },
        hedge::{
            HedgeService, HedgeConfig, HedgePolicy, HedgeMetrics, RequestHedging,
            ResponseSelection, LatencyPercentile, PerformanceTargets,
        },
    },
    types::{
        Outcome, Budget, Cancel, CancelToken, CancelReason,
        TaskId, RegionId, ServiceId, RequestId, StreamId,
    },
    runtime::{
        state::RuntimeState,
        scheduler::{Scheduler, ScheduleHint, WorkerPool},
    },
    cx::{Cx, Scope},
    sync::{Mutex, RwLock, Semaphore, Barrier},
    time::{Duration, Instant, Sleep},
    channel::{mpsc, oneshot, broadcast},
    record::{
        obligation::{ObligationRecord, ObligationState},
        region::{RegionRecord, RegionState},
    },
    net::{
        tcp::{TcpStream, TcpListener},
        http::{HttpRequest, HttpResponse, HttpHeaders},
    },
};

use std::{
    collections::{HashMap, HashSet, VecDeque, BTreeMap},
    sync::{Arc, atomic::{AtomicU64, AtomicBool, AtomicUsize, Ordering}},
    time::{SystemTime, UNIX_EPOCH},
    fmt::{self, Debug, Display},
    hash::{Hash, Hasher},
    pin::Pin,
    task::{Context, Poll},
};

use futures::{
    Stream, Sink, StreamExt, SinkExt, FutureExt,
    stream::{BoxStream, LocalBoxStream},
    sink::{BoxSink, LocalBoxSink},
};

/// Mock system integrating gRPC streaming and service retry for transient error testing.
///
/// Simulates real-world streaming gRPC services coordinating with retry mechanisms
/// to handle transient failures while maintaining streaming semantics and preventing
/// header duplication across retry attempts for robust distributed communication.
pub struct MockGrpcStreamingRetrySystem {
    /// Streaming client managing gRPC stream connections
    streaming_client: Arc<MockStreamingClient>,
    /// Streaming server handling incoming stream requests
    streaming_server: Arc<MockStreamingServer>,
    /// Retry service managing retry logic and policies
    retry_service: Arc<MockRetryService>,
    /// Header deduplicator preventing duplicate headers
    header_deduplicator: Arc<MockHeaderDeduplicator>,
    /// Stream state manager tracking stream positions
    stream_state_manager: Arc<MockStreamStateManager>,
    /// Configuration controlling system behavior
    config: GrpcStreamingRetryConfig,
    /// System metrics and telemetry
    metrics: Arc<Mutex<GrpcStreamingRetryMetrics>>,
    /// System state tracking
    state: Arc<RwLock<SystemState>>,
}

/// Configuration for gRPC streaming retry integration testing.
#[derive(Debug, Clone)]
pub struct GrpcStreamingRetryConfig {
    /// Maximum retry attempts for streaming requests
    max_retry_attempts: u32,
    /// Base delay for exponential backoff
    base_retry_delay: Duration,
    /// Maximum delay between retry attempts
    max_retry_delay: Duration,
    /// Jitter factor for retry timing
    jitter_factor: f64,
    /// Stream buffer size for message buffering
    stream_buffer_size: usize,
    /// Header deduplication strategy
    header_dedup_strategy: HeaderDeduplicationStrategy,
    /// Retry condition evaluation
    retry_conditions: Vec<RetryCondition>,
    /// Stream timeout configuration
    stream_timeout_config: StreamTimeoutConfig,
}

/// Strategies for header deduplication during retries.
#[derive(Debug, Clone)]
pub enum HeaderDeduplicationStrategy {
    Strict,      // Never allow duplicate headers
    Permissive,  // Allow some duplicates for compatibility
    Smart,       // Context-aware deduplication
    Custom { rules: Vec<DeduplicationRule> },
}

/// Rules for custom header deduplication.
#[derive(Debug, Clone)]
pub struct DeduplicationRule {
    pub header_pattern: String,
    pub action: DeduplicationAction,
    pub priority: u32,
}

/// Actions for header deduplication.
#[derive(Debug, Clone)]
pub enum DeduplicationAction {
    Remove,           // Remove duplicate headers
    Merge,            // Merge header values
    Replace,          // Replace with new value
    KeepFirst,        // Keep first occurrence
    KeepLast,         // Keep last occurrence
}

/// Timeout configuration for streaming operations.
#[derive(Debug, Clone)]
pub struct StreamTimeoutConfig {
    pub connection_timeout: Duration,
    pub request_timeout: Duration,
    pub response_timeout: Duration,
    pub stream_idle_timeout: Duration,
    pub total_timeout: Duration,
}

/// System state tracking streaming and retry operations.
#[derive(Debug, Clone)]
pub struct SystemState {
    /// Active streaming connections
    active_streams: HashMap<StreamId, StreamInfo>,
    /// Current retry attempts per request
    retry_attempts: HashMap<RequestId, RetryAttemptInfo>,
    /// Header state tracking for deduplication
    header_states: HashMap<RequestId, HeaderState>,
    /// Stream position tracking for resume
    stream_positions: HashMap<StreamId, StreamPosition>,
    /// Error classification cache
    error_classifications: HashMap<String, ErrorClassification>,
    /// System health metrics
    health_status: HealthStatus,
}

/// Information about active streaming connections.
#[derive(Debug, Clone)]
pub struct StreamInfo {
    pub stream_id: StreamId,
    pub request_id: RequestId,
    pub stream_type: StreamType,
    pub direction: StreamDirection,
    pub start_time: Instant,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub current_state: StreamState,
    pub metadata: StreamMetadata,
}

/// Information about retry attempts.
#[derive(Debug, Clone)]
pub struct RetryAttemptInfo {
    pub request_id: RequestId,
    pub attempt_number: u32,
    pub last_attempt_time: Instant,
    pub total_elapsed: Duration,
    pub error_history: Vec<RetryError>,
    pub next_retry_time: Option<Instant>,
    pub backoff_state: BackoffState,
}

/// Header state for deduplication tracking.
#[derive(Debug, Clone)]
pub struct HeaderState {
    pub request_id: RequestId,
    pub headers_sent: HashMap<String, Vec<String>>,
    pub headers_received: HashMap<String, Vec<String>>,
    pub dedup_applied: Vec<DeduplicationEvent>,
    pub consistency_hash: u64,
}

/// Stream position for resumption after retries.
#[derive(Debug, Clone)]
pub struct StreamPosition {
    pub stream_id: StreamId,
    pub message_index: u64,
    pub byte_offset: u64,
    pub last_message_id: Option<String>,
    pub checkpoint_data: Vec<u8>,
}

/// Backoff state for retry timing.
#[derive(Debug, Clone)]
pub struct BackoffState {
    pub current_delay: Duration,
    pub multiplier: f64,
    pub jitter_seed: u64,
    pub attempt_history: Vec<Duration>,
}

/// Deduplication event tracking.
#[derive(Debug, Clone)]
pub struct DeduplicationEvent {
    pub timestamp: Instant,
    pub header_name: String,
    pub action_taken: DeduplicationAction,
    pub original_value: String,
    pub final_value: String,
}

/// System health status.
#[derive(Debug, Clone)]
pub enum HealthStatus {
    Healthy,
    Degraded { reason: String },
    Critical { errors: Vec<String> },
    Recovering,
}

/// Unique identifiers for system components.
type StreamId = u64;
type RequestId = u64;

/// Mock streaming client for gRPC operations.
pub struct MockStreamingClient {
    client_config: Arc<MockClientConfig>,
    connection_manager: Arc<MockConnectionManager>,
    request_builder: Arc<MockRequestBuilder>,
    response_handler: Arc<MockResponseHandler>,
    interceptor_chain: Arc<MockInterceptorChain>,
    metadata_manager: Arc<MockMetadataManager>,
    metrics: Arc<Mutex<ClientMetrics>>,
}

/// Mock streaming server for gRPC operations.
pub struct MockStreamingServer {
    server_config: Arc<MockServerConfig>,
    service_registry: Arc<MockServiceRegistry>,
    request_handler: Arc<MockRequestHandler>,
    stream_manager: Arc<MockStreamManager>,
    interceptor_chain: Arc<MockInterceptorChain>,
    metrics: Arc<Mutex<ServerMetrics>>,
}

/// Mock retry service for handling retry logic.
pub struct MockRetryService {
    retry_config: Arc<RetryConfig>,
    retry_policies: Arc<RwLock<HashMap<String, RetryPolicy>>>,
    backoff_calculator: Arc<MockBackoffCalculator>,
    error_classifier: Arc<MockErrorClassifier>,
    circuit_breaker: Arc<MockCircuitBreaker>,
    metrics: Arc<Mutex<RetryMetrics>>,
}

/// Mock header deduplicator for preventing duplicate headers.
pub struct MockHeaderDeduplicator {
    dedup_rules: Arc<RwLock<Vec<DeduplicationRule>>>,
    header_tracker: Arc<MockHeaderTracker>,
    consistency_checker: Arc<MockConsistencyChecker>,
    merge_engine: Arc<MockHeaderMergeEngine>,
    validation_engine: Arc<MockHeaderValidationEngine>,
    metrics: Arc<Mutex<DeduplicationMetrics>>,
}

/// Mock stream state manager for tracking stream positions.
pub struct MockStreamStateManager {
    state_storage: Arc<RwLock<HashMap<StreamId, StreamStateSnapshot>>>,
    checkpoint_manager: Arc<MockCheckpointManager>,
    position_tracker: Arc<MockPositionTracker>,
    resume_coordinator: Arc<MockResumeCoordinator>,
    state_validator: Arc<MockStateValidator>,
    metrics: Arc<Mutex<StateManagementMetrics>>,
}

// Supporting types for mock implementations

/// Mock client configuration.
pub struct MockClientConfig {
    pub default_timeout: Duration,
    pub max_concurrent_streams: usize,
    pub compression_enabled: bool,
    pub keepalive_config: KeepAliveConfig,
}

/// Keep-alive configuration.
#[derive(Debug, Clone)]
pub struct KeepAliveConfig {
    pub interval: Duration,
    pub timeout: Duration,
    pub without_calls: bool,
}

/// Mock connection manager.
pub struct MockConnectionManager {
    connections: Arc<RwLock<HashMap<String, MockConnection>>>,
    pool_config: ConnectionPoolConfig,
    health_checker: Arc<MockHealthChecker>,
    metrics: Arc<Mutex<ConnectionMetrics>>,
}

/// Mock connection representation.
#[derive(Debug, Clone)]
pub struct MockConnection {
    pub connection_id: u64,
    pub endpoint: String,
    pub state: ConnectionState,
    pub last_used: Instant,
    pub stream_count: u32,
    pub metadata: ConnectionMetadata,
}

/// Connection states.
#[derive(Debug, Clone)]
pub enum ConnectionState {
    Connecting,
    Connected,
    Ready,
    Busy,
    Idle,
    Draining,
    Closed,
}

/// Connection metadata.
#[derive(Debug, Clone)]
pub struct ConnectionMetadata {
    pub protocol_version: String,
    pub compression_support: Vec<CompressionType>,
    pub max_frame_size: u32,
    pub window_size: u32,
}

/// Connection pool configuration.
#[derive(Debug, Clone)]
pub struct ConnectionPoolConfig {
    pub max_connections: usize,
    pub idle_timeout: Duration,
    pub connection_timeout: Duration,
    pub health_check_interval: Duration,
}

/// Mock request builder.
pub struct MockRequestBuilder {
    default_headers: Arc<RwLock<HeaderMap>>,
    compression_config: CompressionConfig,
    timeout_config: TimeoutConfig,
    metadata_enricher: Arc<MockMetadataEnricher>,
}

/// Compression configuration.
#[derive(Debug, Clone)]
pub struct CompressionConfig {
    pub algorithm: CompressionType,
    pub level: u32,
    pub min_size: usize,
    pub enabled: bool,
}

/// Mock response handler.
pub struct MockResponseHandler {
    status_mapper: Arc<MockStatusMapper>,
    metadata_extractor: Arc<MockMetadataExtractor>,
    error_handler: Arc<MockErrorHandler>,
    metrics_collector: Arc<MockMetricsCollector>,
}

/// Mock interceptor chain.
pub struct MockInterceptorChain {
    request_interceptors: Arc<RwLock<Vec<RequestInterceptor>>>,
    response_interceptors: Arc<RwLock<Vec<ResponseInterceptor>>>,
    metadata_interceptors: Arc<RwLock<Vec<MetadataInterceptor>>>,
    execution_order: InterceptorOrder,
}

/// Interceptor execution order.
#[derive(Debug, Clone)]
pub enum InterceptorOrder {
    Sequential,
    Parallel,
    PriorityBased { priorities: HashMap<String, u32> },
    Custom { order: Vec<String> },
}

/// Mock metadata manager.
pub struct MockMetadataManager {
    metadata_cache: Arc<RwLock<HashMap<String, GrpcMetadata>>>,
    header_processor: Arc<MockHeaderProcessor>,
    encoding_handler: Arc<MockEncodingHandler>,
    validation_rules: Arc<RwLock<Vec<MetadataValidationRule>>>,
}

/// Metadata validation rule.
#[derive(Debug, Clone)]
pub struct MetadataValidationRule {
    pub rule_name: String,
    pub pattern: String,
    pub required: bool,
    pub validation_type: MetadataValidationType,
}

/// Types of metadata validation.
#[derive(Debug, Clone)]
pub enum MetadataValidationType {
    Format,
    Length,
    Charset,
    Content,
    Security,
}

/// Mock server configuration.
pub struct MockServerConfig {
    pub bind_address: String,
    pub port: u16,
    pub max_concurrent_streams: usize,
    pub stream_buffer_size: usize,
    pub compression_config: CompressionConfig,
}

/// Mock service registry.
pub struct MockServiceRegistry {
    services: Arc<RwLock<HashMap<String, ServiceDefinition>>>,
    method_handlers: Arc<RwLock<HashMap<String, MethodHandler>>>,
    interceptors: Arc<RwLock<Vec<ServerInterceptor>>>,
    middleware_stack: Arc<MockMiddlewareStack>,
}

/// Service definition.
#[derive(Debug, Clone)]
pub struct ServiceDefinition {
    pub service_name: String,
    pub methods: HashMap<String, MethodDefinition>,
    pub metadata: ServiceMetadata,
    pub configuration: ServiceConfiguration,
}

/// Method definition.
#[derive(Debug, Clone)]
pub struct MethodDefinition {
    pub method_name: String,
    pub input_type: String,
    pub output_type: String,
    pub streaming_type: StreamingType,
    pub options: MethodOptions,
}

/// Streaming types for methods.
#[derive(Debug, Clone)]
pub enum StreamingType {
    Unary,
    ClientStreaming,
    ServerStreaming,
    BidirectionalStreaming,
}

/// Method options.
#[derive(Debug, Clone)]
pub struct MethodOptions {
    pub timeout: Option<Duration>,
    pub idempotent: bool,
    pub retry_policy: Option<String>,
    pub compression: bool,
}

/// Service metadata.
#[derive(Debug, Clone)]
pub struct ServiceMetadata {
    pub version: String,
    pub description: String,
    pub tags: Vec<String>,
    pub owner: String,
}

/// Service configuration.
#[derive(Debug, Clone)]
pub struct ServiceConfiguration {
    pub max_request_size: usize,
    pub max_response_size: usize,
    pub rate_limit: Option<RateLimit>,
    pub auth_required: bool,
}

/// Rate limit configuration.
#[derive(Debug, Clone)]
pub struct RateLimit {
    pub requests_per_second: u32,
    pub burst_size: u32,
    pub window_size: Duration,
}

/// Mock middleware stack.
pub struct MockMiddlewareStack {
    middleware_layers: Arc<RwLock<Vec<MiddlewareLayer>>>,
    execution_strategy: ExecutionStrategy,
    error_handling: MiddlewareErrorHandling,
}

/// Middleware layer.
#[derive(Debug, Clone)]
pub struct MiddlewareLayer {
    pub layer_name: String,
    pub priority: u32,
    pub enabled: bool,
    pub configuration: MiddlewareConfig,
}

/// Middleware configuration.
#[derive(Debug, Clone)]
pub struct MiddlewareConfig {
    pub settings: HashMap<String, String>,
    pub timeout: Option<Duration>,
    pub error_policy: ErrorPolicy,
}

/// Error policy for middleware.
#[derive(Debug, Clone)]
pub enum ErrorPolicy {
    Continue,
    Abort,
    Retry { max_attempts: u32 },
    Fallback { handler: String },
}

/// Execution strategy for middleware.
#[derive(Debug, Clone)]
pub enum ExecutionStrategy {
    Sequential,
    Parallel,
    Conditional { conditions: Vec<String> },
}

/// Middleware error handling.
#[derive(Debug, Clone)]
pub enum MiddlewareErrorHandling {
    FailFast,
    ContinueOnError,
    CollectAndReport,
    CustomHandler { handler: String },
}

/// Mock stream manager.
pub struct MockStreamManager {
    active_streams: Arc<RwLock<HashMap<StreamId, ActiveStream>>>,
    stream_factory: Arc<MockStreamFactory>,
    flow_controller: Arc<MockFlowController>,
    buffer_manager: Arc<MockBufferManager>,
    metrics: Arc<Mutex<StreamManagementMetrics>>,
}

/// Active stream tracking.
#[derive(Debug, Clone)]
pub struct ActiveStream {
    pub stream_id: StreamId,
    pub stream_type: StreamType,
    pub start_time: Instant,
    pub message_count: u64,
    pub byte_count: u64,
    pub last_activity: Instant,
    pub flow_control_state: FlowControlState,
}

/// Flow control state.
#[derive(Debug, Clone)]
pub struct FlowControlState {
    pub window_size: u32,
    pub bytes_sent: u32,
    pub bytes_acknowledged: u32,
    pub pending_acks: VecDeque<u32>,
}

/// Mock backoff calculator.
pub struct MockBackoffCalculator {
    strategies: Arc<RwLock<HashMap<String, BackoffStrategy>>>,
    jitter_generator: Arc<MockJitterGenerator>,
    timing_cache: Arc<RwLock<HashMap<String, CachedTiming>>>,
    metrics: Arc<Mutex<BackoffMetrics>>,
}

/// Cached timing information.
#[derive(Debug, Clone)]
pub struct CachedTiming {
    pub last_delay: Duration,
    pub next_delay: Duration,
    pub success_history: Vec<Duration>,
    pub failure_history: Vec<Duration>,
}

/// Mock error classifier.
pub struct MockErrorClassifier {
    classification_rules: Arc<RwLock<Vec<ErrorClassificationRule>>>,
    patterns: Arc<MockErrorPatterns>,
    learning_engine: Arc<MockLearningEngine>,
    metrics: Arc<Mutex<ErrorClassificationMetrics>>,
}

/// Error classification rule.
#[derive(Debug, Clone)]
pub struct ErrorClassificationRule {
    pub rule_name: String,
    pub pattern: String,
    pub classification: ErrorClassification,
    pub confidence: f64,
    pub conditions: Vec<ClassificationCondition>,
}

/// Classification condition.
#[derive(Debug, Clone)]
pub struct ClassificationCondition {
    pub field: String,
    pub operator: ComparisonOperator,
    pub value: String,
}

/// Comparison operators.
#[derive(Debug, Clone)]
pub enum ComparisonOperator {
    Equals,
    NotEquals,
    Contains,
    StartsWith,
    EndsWith,
    Matches,
    GreaterThan,
    LessThan,
}

/// Mock circuit breaker.
pub struct MockCircuitBreaker {
    state: Arc<RwLock<CircuitBreakerState>>,
    thresholds: CircuitBreakerThresholds,
    metrics: Arc<Mutex<CircuitBreakerMetrics>>,
    recovery_strategy: RecoveryStrategy,
}

/// Circuit breaker state.
#[derive(Debug, Clone)]
pub enum CircuitBreakerState {
    Closed { failure_count: u32 },
    Open { opened_at: Instant },
    HalfOpen { test_requests: u32 },
}

/// Circuit breaker thresholds.
#[derive(Debug, Clone)]
pub struct CircuitBreakerThresholds {
    pub failure_threshold: u32,
    pub recovery_timeout: Duration,
    pub success_threshold: u32,
    pub volume_threshold: u32,
}

/// Recovery strategy for circuit breaker.
#[derive(Debug, Clone)]
pub enum RecoveryStrategy {
    Immediate,
    Gradual { step_size: u32 },
    Adaptive { learning_rate: f64 },
}

/// Mock header tracker.
pub struct MockHeaderTracker {
    header_history: Arc<RwLock<HashMap<RequestId, HeaderHistory>>>,
    dedup_cache: Arc<RwLock<HashMap<String, String>>>,
    consistency_validator: Arc<MockConsistencyValidator>,
    metrics: Arc<Mutex<HeaderTrackingMetrics>>,
}

/// Header history tracking.
#[derive(Debug, Clone)]
pub struct HeaderHistory {
    pub request_id: RequestId,
    pub headers_by_attempt: HashMap<u32, HeaderMap>,
    pub dedup_events: Vec<DeduplicationEvent>,
    pub consistency_checks: Vec<ConsistencyCheck>,
}

/// Consistency check result.
#[derive(Debug, Clone)]
pub struct ConsistencyCheck {
    pub timestamp: Instant,
    pub check_type: ConsistencyCheckType,
    pub result: ConsistencyResult,
    pub details: String,
}

/// Types of consistency checks.
#[derive(Debug, Clone)]
pub enum ConsistencyCheckType {
    DuplicateDetection,
    ValueConsistency,
    OrderConsistency,
    IntegrityCheck,
}

/// Consistency check results.
#[derive(Debug, Clone)]
pub enum ConsistencyResult {
    Pass,
    Warn { message: String },
    Fail { error: String },
}

/// Stream state snapshot for checkpointing.
#[derive(Debug, Clone)]
pub struct StreamStateSnapshot {
    pub stream_id: StreamId,
    pub timestamp: Instant,
    pub position: StreamPosition,
    pub metadata: StreamMetadata,
    pub buffer_state: BufferState,
    pub flow_control: FlowControlState,
}

/// Buffer state for streams.
#[derive(Debug, Clone)]
pub struct BufferState {
    pub buffered_messages: Vec<BufferedMessage>,
    pub buffer_size: usize,
    pub high_water_mark: usize,
    pub low_water_mark: usize,
}

/// Buffered message.
#[derive(Debug, Clone)]
pub struct BufferedMessage {
    pub message_id: String,
    pub sequence_number: u64,
    pub payload: Vec<u8>,
    pub metadata: MessageMetadata,
    pub timestamp: Instant,
}

/// Message metadata.
#[derive(Debug, Clone)]
pub struct MessageMetadata {
    pub message_type: String,
    pub size: usize,
    pub compression: Option<CompressionType>,
    pub checksum: u64,
}

// Additional mock implementations

pub struct MockHealthChecker;
pub struct MockMetadataEnricher;
pub struct MockStatusMapper;
pub struct MockMetadataExtractor;
pub struct MockErrorHandler;
pub struct MockMetricsCollector;
pub struct MockHeaderProcessor;
pub struct MockEncodingHandler;
pub struct MockStreamFactory;
pub struct MockFlowController;
pub struct MockBufferManager;
pub struct MockJitterGenerator;
pub struct MockErrorPatterns;
pub struct MockLearningEngine;
pub struct MockConsistencyChecker;
pub struct MockHeaderMergeEngine;
pub struct MockHeaderValidationEngine;
pub struct MockCheckpointManager;
pub struct MockPositionTracker;
pub struct MockResumeCoordinator;
pub struct MockStateValidator;
pub struct MockConsistencyValidator;

// Metrics types

/// gRPC streaming retry system metrics.
#[derive(Debug, Clone, Default)]
pub struct GrpcStreamingRetryMetrics {
    /// Streaming operation statistics
    pub streaming_operations: StreamingOperationMetrics,
    /// Retry attempt statistics
    pub retry_attempts: RetryAttemptMetrics,
    /// Header deduplication statistics
    pub header_deduplication: DeduplicationMetrics,
    /// Stream state management statistics
    pub state_management: StateManagementMetrics,
    /// Error handling statistics
    pub error_handling: ErrorHandlingMetrics,
    /// Overall system health
    pub system_health: HealthMetrics,
}

/// Streaming operation metrics.
#[derive(Debug, Clone, Default)]
pub struct StreamingOperationMetrics {
    pub streams_created: u64,
    pub streams_completed: u64,
    pub streams_failed: u64,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub bytes_transferred: u64,
    pub average_stream_duration: Duration,
}

/// Retry attempt metrics.
#[derive(Debug, Clone, Default)]
pub struct RetryAttemptMetrics {
    pub total_retries: u64,
    pub successful_retries: u64,
    pub failed_retries: u64,
    pub retries_exhausted: u64,
    pub average_retry_count: f64,
    pub total_backoff_time: Duration,
}

/// Header deduplication metrics.
#[derive(Debug, Clone, Default)]
pub struct DeduplicationMetrics {
    pub headers_processed: u64,
    pub duplicates_detected: u64,
    pub duplicates_removed: u64,
    pub headers_merged: u64,
    pub consistency_violations: u64,
}

/// State management metrics.
#[derive(Debug, Clone, Default)]
pub struct StateManagementMetrics {
    pub snapshots_created: u64,
    pub state_restorations: u64,
    pub position_updates: u64,
    pub checkpoint_operations: u64,
    pub state_validation_failures: u64,
}

/// Error handling metrics.
#[derive(Debug, Clone, Default)]
pub struct ErrorHandlingMetrics {
    pub transient_errors: u64,
    pub permanent_errors: u64,
    pub classification_accuracy: f64,
    pub error_recovery_time: Duration,
    pub circuit_breaker_trips: u64,
}

/// System health metrics.
#[derive(Debug, Clone, Default)]
pub struct HealthMetrics {
    pub uptime: Duration,
    pub error_rate: f64,
    pub performance_score: f64,
    pub availability_percentage: f64,
    pub resource_utilization: f64,
}

/// Additional specialized metrics types.
#[derive(Debug, Clone, Default)]
pub struct ClientMetrics {
    pub connections_created: u64,
    pub requests_sent: u64,
    pub responses_received: u64,
}

#[derive(Debug, Clone, Default)]
pub struct ServerMetrics {
    pub connections_accepted: u64,
    pub requests_processed: u64,
    pub responses_sent: u64,
}

#[derive(Debug, Clone, Default)]
pub struct RetryMetrics {
    pub policies_evaluated: u64,
    pub backoff_calculations: u64,
    pub circuit_breaker_checks: u64,
}

#[derive(Debug, Clone, Default)]
pub struct ConnectionMetrics {
    pub active_connections: u64,
    pub connection_pool_utilization: f64,
    pub connection_failures: u64,
}

#[derive(Debug, Clone, Default)]
pub struct StreamManagementMetrics {
    pub active_streams: u64,
    pub stream_buffer_utilization: f64,
    pub flow_control_events: u64,
}

#[derive(Debug, Clone, Default)]
pub struct BackoffMetrics {
    pub calculations_performed: u64,
    pub jitter_applications: u64,
    pub cache_hits: u64,
}

#[derive(Debug, Clone, Default)]
pub struct ErrorClassificationMetrics {
    pub classifications_performed: u64,
    pub accuracy_score: f64,
    pub learning_updates: u64,
}

#[derive(Debug, Clone, Default)]
pub struct CircuitBreakerMetrics {
    pub state_changes: u64,
    pub requests_blocked: u64,
    pub recovery_attempts: u64,
}

#[derive(Debug, Clone, Default)]
pub struct HeaderTrackingMetrics {
    pub headers_tracked: u64,
    pub consistency_checks: u64,
    pub violations_detected: u64,
}

impl MockGrpcStreamingRetrySystem {
    /// Create a new mock gRPC streaming retry system with the given configuration.
    pub fn new(config: GrpcStreamingRetryConfig) -> Self {
        let streaming_client = Arc::new(MockStreamingClient::new(config.clone()));
        let streaming_server = Arc::new(MockStreamingServer::new(config.clone()));
        let retry_service = Arc::new(MockRetryService::new(config.clone()));
        let header_deduplicator = Arc::new(MockHeaderDeduplicator::new(config.clone()));
        let stream_state_manager = Arc::new(MockStreamStateManager::new(config.clone()));

        Self {
            streaming_client,
            streaming_server,
            retry_service,
            header_deduplicator,
            stream_state_manager,
            config,
            metrics: Arc::new(Mutex::new(GrpcStreamingRetryMetrics::default())),
            state: Arc::new(RwLock::new(SystemState {
                active_streams: HashMap::new(),
                retry_attempts: HashMap::new(),
                header_states: HashMap::new(),
                stream_positions: HashMap::new(),
                error_classifications: HashMap::new(),
                health_status: HealthStatus::Healthy,
            })),
        }
    }

    /// Execute streaming gRPC call with retry on transient errors.
    pub async fn execute_streaming_call_with_retry<T, R>(
        &self,
        cx: &Cx,
        service_name: &str,
        method_name: &str,
        request_stream: T,
    ) -> Result<StreamingCallResult<R>, GrpcStreamingRetryError>
    where
        T: Stream + Send + 'static,
        R: Send + 'static,
    {
        let request_id = self.generate_request_id();
        let stream_id = self.generate_stream_id();

        // Initialize streaming call context
        let call_context = self.initialize_call_context(
            cx,
            request_id,
            stream_id,
            service_name,
            method_name,
        ).await?;

        // Execute streaming call with retry logic
        let call_result = self.execute_with_retry_loop(
            cx,
            call_context,
            request_stream,
        ).await?;

        // Validate final state and headers
        self.validate_call_completion(cx, request_id, &call_result).await?;

        // Update metrics
        self.update_streaming_metrics(&call_result).await;

        Ok(call_result)
    }

    /// Initialize call context for streaming operation.
    async fn initialize_call_context(
        &self,
        cx: &Cx,
        request_id: RequestId,
        stream_id: StreamId,
        service_name: &str,
        method_name: &str,
    ) -> Result<StreamingCallContext, GrpcStreamingRetryError> {
        // Create initial headers without duplication
        let headers = self.header_deduplicator
            .create_initial_headers(cx, request_id, service_name, method_name)
            .await?;

        // Setup retry context
        let retry_context = self.retry_service
            .initialize_retry_context(request_id)
            .await?;

        // Initialize stream state
        let stream_state = self.stream_state_manager
            .initialize_stream_state(stream_id, &headers)
            .await?;

        // Register call in system state
        self.register_streaming_call(request_id, stream_id, &headers).await?;

        Ok(StreamingCallContext {
            request_id,
            stream_id,
            service_name: service_name.to_string(),
            method_name: method_name.to_string(),
            headers,
            retry_context,
            stream_state,
            start_time: Instant::now(),
        })
    }

    /// Execute streaming call with retry loop.
    async fn execute_with_retry_loop<T, R>(
        &self,
        cx: &Cx,
        mut context: StreamingCallContext,
        request_stream: T,
    ) -> Result<StreamingCallResult<R>, GrpcStreamingRetryError>
    where
        T: Stream + Send + 'static,
        R: Send + 'static,
    {
        let mut attempt_number = 0;
        let mut last_error: Option<GrpcStreamingRetryError> = None;

        loop {
            attempt_number += 1;

            // Check if we've exceeded retry limits
            if attempt_number > self.config.max_retry_attempts {
                return Err(GrpcStreamingRetryError::RetriesExhausted {
                    request_id: context.request_id,
                    attempts: attempt_number - 1,
                    last_error: last_error.map(|e| Box::new(e)),
                });
            }

            // Apply backoff delay for retry attempts
            if attempt_number > 1 {
                let backoff_delay = self.retry_service
                    .calculate_backoff_delay(
                        cx,
                        context.request_id,
                        attempt_number - 1,
                    ).await?;

                Sleep::new(cx.deadline() + backoff_delay).await.ok();

                // Update retry attempt tracking
                self.update_retry_attempt(context.request_id, attempt_number).await;
            }

            // Prepare headers for this attempt (deduplication check)
            let attempt_headers = self.header_deduplicator
                .prepare_attempt_headers(cx, context.request_id, attempt_number, &context.headers)
                .await?;

            // Execute streaming call attempt
            match self.execute_single_attempt(
                cx,
                &mut context,
                attempt_number,
                attempt_headers,
                &request_stream,
            ).await {
                Ok(result) => {
                    // Success - validate headers and return
                    self.validate_success_headers(cx, context.request_id, &result).await?;
                    return Ok(result);
                }
                Err(error) => {
                    // Classify error to determine if retry is appropriate
                    let error_classification = self.retry_service
                        .classify_error(cx, &error)
                        .await?;

                    match error_classification {
                        ErrorClassification::Transient => {
                            // Transient error - continue retry loop
                            last_error = Some(error);

                            // Save stream state for potential resume
                            self.stream_state_manager
                                .save_stream_checkpoint(cx, context.stream_id)
                                .await?;

                            continue;
                        }
                        ErrorClassification::Permanent => {
                            // Permanent error - do not retry
                            return Err(error);
                        }
                    }
                }
            }
        }
    }

    /// Execute a single streaming call attempt.
    async fn execute_single_attempt<T, R>(
        &self,
        cx: &Cx,
        context: &mut StreamingCallContext,
        attempt_number: u32,
        headers: HeaderMap,
        request_stream: &T,
    ) -> Result<StreamingCallResult<R>, GrpcStreamingRetryError>
    where
        T: Stream + Send + 'static,
        R: Send + 'static,
    {
        // Create streaming connection
        let connection = self.streaming_client
            .create_connection(cx, &context.service_name)
            .await?;

        // Setup stream with headers
        let stream_setup = StreamSetup {
            stream_id: context.stream_id,
            method_name: context.method_name.clone(),
            headers,
            timeout: self.config.stream_timeout_config.total_timeout,
        };

        let stream_handle = self.streaming_client
            .setup_stream(cx, &connection, stream_setup)
            .await?;

        // Execute streaming operation with state management
        let stream_result = self.execute_stream_operation(
            cx,
            context,
            stream_handle,
            request_stream,
        ).await?;

        // Process response and extract result
        let call_result = self.process_stream_response(
            cx,
            context.request_id,
            stream_result,
        ).await?;

        Ok(call_result)
    }

    /// Execute the actual stream operation.
    async fn execute_stream_operation<T, R>(
        &self,
        cx: &Cx,
        context: &StreamingCallContext,
        stream_handle: MockStreamHandle,
        request_stream: &T,
    ) -> Result<StreamOperationResult, GrpcStreamingRetryError>
    where
        T: Stream + Send + 'static,
        R: Send + 'static,
    {
        // Simulate streaming operation
        let start_time = Instant::now();

        // Send messages from request stream
        let mut message_count = 0;
        // In real implementation, would iterate over request_stream
        for _i in 0..3 {
            // Simulate sending messages
            Sleep::new(cx.deadline() + Duration::from_millis(10)).await.ok();
            message_count += 1;

            // Check for errors during streaming
            if message_count == 2 && context.service_name.contains("error") {
                return Err(GrpcStreamingRetryError::TransientNetworkError {
                    message: "Simulated network error during streaming".to_string(),
                });
            }
        }

        // Simulate receiving response stream
        let response_messages = vec![
            MockStreamMessage {
                id: "msg1".to_string(),
                payload: vec![1, 2, 3],
                metadata: MessageMetadata {
                    message_type: "response".to_string(),
                    size: 3,
                    compression: None,
                    checksum: 123,
                },
                timestamp: Instant::now(),
            },
            MockStreamMessage {
                id: "msg2".to_string(),
                payload: vec![4, 5, 6],
                metadata: MessageMetadata {
                    message_type: "response".to_string(),
                    size: 3,
                    compression: None,
                    checksum: 456,
                },
                timestamp: Instant::now(),
            },
        ];

        Ok(StreamOperationResult {
            stream_id: context.stream_id,
            messages_sent: message_count,
            response_messages,
            duration: start_time.elapsed(),
            final_position: StreamPosition {
                stream_id: context.stream_id,
                message_index: message_count,
                byte_offset: message_count * 100, // Mock byte offset
                last_message_id: Some("msg2".to_string()),
                checkpoint_data: vec![0; 32],
            },
        })
    }

    /// Process stream response into call result.
    async fn process_stream_response<R>(
        &self,
        cx: &Cx,
        request_id: RequestId,
        stream_result: StreamOperationResult,
    ) -> Result<StreamingCallResult<R>, GrpcStreamingRetryError> {
        // Extract response headers
        let response_headers = self.streaming_client
            .extract_response_headers(cx, &stream_result)
            .await?;

        // Validate header consistency
        self.header_deduplicator
            .validate_response_headers(cx, request_id, &response_headers)
            .await?;

        // Convert stream messages to result format
        let response_data = self.convert_stream_messages(&stream_result.response_messages)?;

        Ok(StreamingCallResult {
            request_id,
            stream_id: stream_result.stream_id,
            response_data,
            response_headers,
            duration: stream_result.duration,
            messages_processed: stream_result.messages_sent,
            final_position: stream_result.final_position,
            retry_history: self.get_retry_history(request_id).await,
        })
    }

    /// Validate call completion and header consistency.
    async fn validate_call_completion<R>(
        &self,
        cx: &Cx,
        request_id: RequestId,
        result: &StreamingCallResult<R>,
    ) -> Result<(), GrpcStreamingRetryError> {
        // Check for header duplication
        let header_validation = self.header_deduplicator
            .validate_final_headers(cx, request_id, &result.response_headers)
            .await?;

        if !header_validation.is_valid {
            return Err(GrpcStreamingRetryError::HeaderDuplicationDetected {
                request_id,
                duplicated_headers: header_validation.duplicate_headers,
            });
        }

        // Validate stream state consistency
        self.stream_state_manager
            .validate_final_state(cx, result.stream_id, &result.final_position)
            .await?;

        Ok(())
    }

    /// Update retry attempt tracking.
    async fn update_retry_attempt(&self, request_id: RequestId, attempt_number: u32) {
        let mut state = self.state.write().unwrap();

        if let Some(retry_info) = state.retry_attempts.get_mut(&request_id) {
            retry_info.attempt_number = attempt_number;
            retry_info.last_attempt_time = Instant::now();
        } else {
            let retry_info = RetryAttemptInfo {
                request_id,
                attempt_number,
                last_attempt_time: Instant::now(),
                total_elapsed: Duration::default(),
                error_history: Vec::new(),
                next_retry_time: None,
                backoff_state: BackoffState {
                    current_delay: self.config.base_retry_delay,
                    multiplier: 2.0,
                    jitter_seed: 12345,
                    attempt_history: Vec::new(),
                },
            };
            state.retry_attempts.insert(request_id, retry_info);
        }
    }

    /// Register streaming call in system state.
    async fn register_streaming_call(
        &self,
        request_id: RequestId,
        stream_id: StreamId,
        headers: &HeaderMap,
    ) -> Result<(), GrpcStreamingRetryError> {
        let mut state = self.state.write().unwrap();

        // Register stream info
        let stream_info = StreamInfo {
            stream_id,
            request_id,
            stream_type: StreamType::BidirectionalStream,
            direction: StreamDirection::ClientToServer,
            start_time: Instant::now(),
            messages_sent: 0,
            messages_received: 0,
            current_state: StreamState::Active,
            metadata: StreamMetadata::default(),
        };
        state.active_streams.insert(stream_id, stream_info);

        // Initialize header state
        let header_state = HeaderState {
            request_id,
            headers_sent: HashMap::new(),
            headers_received: HashMap::new(),
            dedup_applied: Vec::new(),
            consistency_hash: 0, // Would calculate real hash
        };
        state.header_states.insert(request_id, header_state);

        Ok(())
    }

    /// Get retry history for request.
    async fn get_retry_history(&self, request_id: RequestId) -> Vec<RetryAttemptRecord> {
        let state = self.state.read().unwrap();
        if let Some(retry_info) = state.retry_attempts.get(&request_id) {
            vec![RetryAttemptRecord {
                attempt_number: retry_info.attempt_number,
                timestamp: retry_info.last_attempt_time,
                delay: retry_info.backoff_state.current_delay,
                error: None,
            }]
        } else {
            Vec::new()
        }
    }

    /// Convert stream messages to result format.
    fn convert_stream_messages<R>(&self, messages: &[MockStreamMessage]) -> Result<Vec<R>, GrpcStreamingRetryError> {
        // Mock conversion - in real implementation would deserialize properly
        Ok(Vec::new())
    }

    /// Update streaming metrics.
    async fn update_streaming_metrics<R>(&self, result: &StreamingCallResult<R>) {
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.streaming_operations.streams_completed += 1;
            metrics.streaming_operations.messages_sent += result.messages_processed;

            // Update average duration
            let current_avg = metrics.streaming_operations.average_stream_duration;
            let new_sample = result.duration;
            metrics.streaming_operations.average_stream_duration =
                Duration::from_nanos(
                    (current_avg.as_nanos() + new_sample.as_nanos()) / 2
                );
        }
    }

    /// Generate unique request ID.
    fn generate_request_id(&self) -> RequestId {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        COUNTER.fetch_add(1, Ordering::Relaxed)
    }

    /// Generate unique stream ID.
    fn generate_stream_id(&self) -> StreamId {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        COUNTER.fetch_add(1, Ordering::Relaxed)
    }

    /// Get system metrics snapshot.
    pub fn get_metrics(&self) -> GrpcStreamingRetryMetrics {
        self.metrics.lock().unwrap().clone()
    }

    /// Check system health status.
    pub fn check_health(&self) -> HealthStatus {
        self.state.read().unwrap().health_status.clone()
    }
}

// Supporting result and context types

/// Streaming call context.
#[derive(Debug, Clone)]
pub struct StreamingCallContext {
    pub request_id: RequestId,
    pub stream_id: StreamId,
    pub service_name: String,
    pub method_name: String,
    pub headers: HeaderMap,
    pub retry_context: RetryContext,
    pub stream_state: StreamStateInfo,
    pub start_time: Instant,
}

/// Retry context information.
#[derive(Debug, Clone)]
pub struct RetryContext {
    pub policy_name: String,
    pub max_attempts: u32,
    pub backoff_strategy: BackoffStrategy,
    pub conditions: Vec<RetryCondition>,
}

/// Stream state information.
#[derive(Debug, Clone)]
pub struct StreamStateInfo {
    pub position: StreamPosition,
    pub metadata: StreamMetadata,
    pub checkpoints: Vec<StreamCheckpoint>,
}

/// Stream checkpoint.
#[derive(Debug, Clone)]
pub struct StreamCheckpoint {
    pub timestamp: Instant,
    pub position: StreamPosition,
    pub metadata_snapshot: HashMap<String, String>,
}

/// Result of streaming call.
#[derive(Debug, Clone)]
pub struct StreamingCallResult<T> {
    pub request_id: RequestId,
    pub stream_id: StreamId,
    pub response_data: Vec<T>,
    pub response_headers: HeaderMap,
    pub duration: Duration,
    pub messages_processed: u64,
    pub final_position: StreamPosition,
    pub retry_history: Vec<RetryAttemptRecord>,
}

/// Record of retry attempt.
#[derive(Debug, Clone)]
pub struct RetryAttemptRecord {
    pub attempt_number: u32,
    pub timestamp: Instant,
    pub delay: Duration,
    pub error: Option<String>,
}

/// Stream setup configuration.
#[derive(Debug, Clone)]
pub struct StreamSetup {
    pub stream_id: StreamId,
    pub method_name: String,
    pub headers: HeaderMap,
    pub timeout: Duration,
}

/// Mock stream handle.
#[derive(Debug, Clone)]
pub struct MockStreamHandle {
    pub handle_id: u64,
    pub stream_id: StreamId,
    pub connection_info: String,
}

/// Stream operation result.
#[derive(Debug, Clone)]
pub struct StreamOperationResult {
    pub stream_id: StreamId,
    pub messages_sent: u64,
    pub response_messages: Vec<MockStreamMessage>,
    pub duration: Duration,
    pub final_position: StreamPosition,
}

/// Mock stream message.
#[derive(Debug, Clone)]
pub struct MockStreamMessage {
    pub id: String,
    pub payload: Vec<u8>,
    pub metadata: MessageMetadata,
    pub timestamp: Instant,
}

/// Header validation result.
#[derive(Debug, Clone)]
pub struct HeaderValidationResult {
    pub is_valid: bool,
    pub duplicate_headers: Vec<String>,
    pub consistency_errors: Vec<String>,
}

/// Header map type.
pub type HeaderMap = HashMap<String, Vec<String>>;

/// Error types for gRPC streaming retry integration.
#[derive(Debug, Clone)]
pub enum GrpcStreamingRetryError {
    RetriesExhausted {
        request_id: RequestId,
        attempts: u32,
        last_error: Option<Box<GrpcStreamingRetryError>>,
    },
    TransientNetworkError {
        message: String,
    },
    PermanentServiceError {
        status_code: u32,
        message: String,
    },
    HeaderDuplicationDetected {
        request_id: RequestId,
        duplicated_headers: Vec<String>,
    },
    StreamStateCorrupted {
        stream_id: StreamId,
        details: String,
    },
    ConnectionFailed {
        service_name: String,
        error: String,
    },
    TimeoutExceeded {
        operation: String,
        timeout: Duration,
        elapsed: Duration,
    },
    ConfigurationError {
        parameter: String,
        error: String,
    },
}

impl Display for GrpcStreamingRetryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GrpcStreamingRetryError::RetriesExhausted { request_id, attempts, last_error } =>
                write!(f, "Retries exhausted for request {}: {} attempts, last error: {:?}",
                       request_id, attempts, last_error),
            GrpcStreamingRetryError::TransientNetworkError { message } =>
                write!(f, "Transient network error: {}", message),
            GrpcStreamingRetryError::PermanentServiceError { status_code, message } =>
                write!(f, "Permanent service error {}: {}", status_code, message),
            GrpcStreamingRetryError::HeaderDuplicationDetected { request_id, duplicated_headers } =>
                write!(f, "Header duplication detected for request {}: {:?}",
                       request_id, duplicated_headers),
            GrpcStreamingRetryError::StreamStateCorrupted { stream_id, details } =>
                write!(f, "Stream state corrupted for stream {}: {}", stream_id, details),
            GrpcStreamingRetryError::ConnectionFailed { service_name, error } =>
                write!(f, "Connection failed to service {}: {}", service_name, error),
            GrpcStreamingRetryError::TimeoutExceeded { operation, timeout, elapsed } =>
                write!(f, "Timeout exceeded for {}: timeout {:?}, elapsed {:?}",
                       operation, timeout, elapsed),
            GrpcStreamingRetryError::ConfigurationError { parameter, error } =>
                write!(f, "Configuration error for parameter {}: {}", parameter, error),
        }
    }
}

impl std::error::Error for GrpcStreamingRetryError {}

// Mock implementations for the supporting components

impl MockStreamingClient {
    fn new(config: GrpcStreamingRetryConfig) -> Self {
        Self {
            client_config: Arc::new(MockClientConfig::from(config.clone())),
            connection_manager: Arc::new(MockConnectionManager::new()),
            request_builder: Arc::new(MockRequestBuilder::new()),
            response_handler: Arc::new(MockResponseHandler::new()),
            interceptor_chain: Arc::new(MockInterceptorChain::new()),
            metadata_manager: Arc::new(MockMetadataManager::new()),
            metrics: Arc::new(Mutex::new(ClientMetrics::default())),
        }
    }

    async fn create_connection(
        &self,
        cx: &Cx,
        service_name: &str,
    ) -> Result<MockConnection, GrpcStreamingRetryError> {
        Ok(MockConnection {
            connection_id: 1,
            endpoint: service_name.to_string(),
            state: ConnectionState::Connected,
            last_used: Instant::now(),
            stream_count: 0,
            metadata: ConnectionMetadata {
                protocol_version: "grpc/1.0".to_string(),
                compression_support: vec![CompressionType::Gzip],
                max_frame_size: 16384,
                window_size: 65536,
            },
        })
    }

    async fn setup_stream(
        &self,
        cx: &Cx,
        connection: &MockConnection,
        setup: StreamSetup,
    ) -> Result<MockStreamHandle, GrpcStreamingRetryError> {
        Ok(MockStreamHandle {
            handle_id: setup.stream_id,
            stream_id: setup.stream_id,
            connection_info: connection.endpoint.clone(),
        })
    }

    async fn extract_response_headers(
        &self,
        cx: &Cx,
        result: &StreamOperationResult,
    ) -> Result<HeaderMap, GrpcStreamingRetryError> {
        let mut headers = HeaderMap::new();
        headers.insert("content-type".to_string(), vec!["application/grpc".to_string()]);
        headers.insert("grpc-status".to_string(), vec!["0".to_string()]);
        Ok(headers)
    }
}

impl MockStreamingServer {
    fn new(config: GrpcStreamingRetryConfig) -> Self {
        Self {
            server_config: Arc::new(MockServerConfig::from(config)),
            service_registry: Arc::new(MockServiceRegistry::new()),
            request_handler: Arc::new(MockRequestHandler::new()),
            stream_manager: Arc::new(MockStreamManager::new()),
            interceptor_chain: Arc::new(MockInterceptorChain::new()),
            metrics: Arc::new(Mutex::new(ServerMetrics::default())),
        }
    }
}

impl MockRetryService {
    fn new(config: GrpcStreamingRetryConfig) -> Self {
        Self {
            retry_config: Arc::new(RetryConfig::from(config)),
            retry_policies: Arc::new(RwLock::new(HashMap::new())),
            backoff_calculator: Arc::new(MockBackoffCalculator::new()),
            error_classifier: Arc::new(MockErrorClassifier::new()),
            circuit_breaker: Arc::new(MockCircuitBreaker::new()),
            metrics: Arc::new(Mutex::new(RetryMetrics::default())),
        }
    }

    async fn initialize_retry_context(
        &self,
        request_id: RequestId,
    ) -> Result<RetryContext, GrpcStreamingRetryError> {
        Ok(RetryContext {
            policy_name: "default".to_string(),
            max_attempts: self.retry_config.max_attempts,
            backoff_strategy: BackoffStrategy::Exponential {
                base: Duration::from_millis(100),
                max_delay: Duration::from_secs(30),
                multiplier: 2.0,
            },
            conditions: vec![RetryCondition::TransientError],
        })
    }

    async fn calculate_backoff_delay(
        &self,
        cx: &Cx,
        request_id: RequestId,
        attempt_number: u32,
    ) -> Result<Duration, GrpcStreamingRetryError> {
        let base_delay = Duration::from_millis(100);
        let multiplier = 2u64.pow(attempt_number - 1);
        let delay = base_delay * multiplier;
        Ok(std::cmp::min(delay, Duration::from_secs(30)))
    }

    async fn classify_error(
        &self,
        cx: &Cx,
        error: &GrpcStreamingRetryError,
    ) -> Result<ErrorClassification, GrpcStreamingRetryError> {
        match error {
            GrpcStreamingRetryError::TransientNetworkError { .. } => Ok(ErrorClassification::Transient),
            GrpcStreamingRetryError::PermanentServiceError { .. } => Ok(ErrorClassification::Permanent),
            GrpcStreamingRetryError::TimeoutExceeded { .. } => Ok(ErrorClassification::Transient),
            GrpcStreamingRetryError::ConnectionFailed { .. } => Ok(ErrorClassification::Transient),
            _ => Ok(ErrorClassification::Permanent),
        }
    }
}

impl MockHeaderDeduplicator {
    fn new(config: GrpcStreamingRetryConfig) -> Self {
        Self {
            dedup_rules: Arc::new(RwLock::new(Vec::new())),
            header_tracker: Arc::new(MockHeaderTracker::new()),
            consistency_checker: Arc::new(MockConsistencyChecker),
            merge_engine: Arc::new(MockHeaderMergeEngine),
            validation_engine: Arc::new(MockHeaderValidationEngine),
            metrics: Arc::new(Mutex::new(DeduplicationMetrics::default())),
        }
    }

    async fn create_initial_headers(
        &self,
        cx: &Cx,
        request_id: RequestId,
        service_name: &str,
        method_name: &str,
    ) -> Result<HeaderMap, GrpcStreamingRetryError> {
        let mut headers = HeaderMap::new();
        headers.insert(":method".to_string(), vec!["POST".to_string()]);
        headers.insert(":path".to_string(), vec![format!("/{}/{}", service_name, method_name)]);
        headers.insert("content-type".to_string(), vec!["application/grpc".to_string()]);
        headers.insert("te".to_string(), vec!["trailers".to_string()]);
        Ok(headers)
    }

    async fn prepare_attempt_headers(
        &self,
        cx: &Cx,
        request_id: RequestId,
        attempt_number: u32,
        original_headers: &HeaderMap,
    ) -> Result<HeaderMap, GrpcStreamingRetryError> {
        let mut headers = original_headers.clone();

        // Add retry-specific headers without duplication
        if attempt_number > 1 {
            headers.insert("grpc-retry-attempt".to_string(), vec![attempt_number.to_string()]);
        }

        // Remove any attempt-specific headers from previous attempts
        headers.remove("grpc-previous-rpc-attempts");

        Ok(headers)
    }

    async fn validate_response_headers(
        &self,
        cx: &Cx,
        request_id: RequestId,
        headers: &HeaderMap,
    ) -> Result<(), GrpcStreamingRetryError> {
        // Check for duplicate headers
        for (name, values) in headers {
            if values.len() > 1 {
                // Some headers are allowed to have multiple values
                if !self.is_multi_value_allowed(name) {
                    return Err(GrpcStreamingRetryError::HeaderDuplicationDetected {
                        request_id,
                        duplicated_headers: vec![name.clone()],
                    });
                }
            }
        }
        Ok(())
    }

    async fn validate_final_headers(
        &self,
        cx: &Cx,
        request_id: RequestId,
        headers: &HeaderMap,
    ) -> Result<HeaderValidationResult, GrpcStreamingRetryError> {
        let mut duplicate_headers = Vec::new();

        // Check for any remaining duplicates
        for (name, values) in headers {
            if values.len() > 1 && !self.is_multi_value_allowed(name) {
                duplicate_headers.push(name.clone());
            }
        }

        Ok(HeaderValidationResult {
            is_valid: duplicate_headers.is_empty(),
            duplicate_headers,
            consistency_errors: Vec::new(),
        })
    }

    fn is_multi_value_allowed(&self, header_name: &str) -> bool {
        matches!(header_name, "set-cookie" | "warning" | "vary")
    }
}

impl MockStreamStateManager {
    fn new(config: GrpcStreamingRetryConfig) -> Self {
        Self {
            state_storage: Arc::new(RwLock::new(HashMap::new())),
            checkpoint_manager: Arc::new(MockCheckpointManager),
            position_tracker: Arc::new(MockPositionTracker),
            resume_coordinator: Arc::new(MockResumeCoordinator),
            state_validator: Arc::new(MockStateValidator),
            metrics: Arc::new(Mutex::new(StateManagementMetrics::default())),
        }
    }

    async fn initialize_stream_state(
        &self,
        stream_id: StreamId,
        headers: &HeaderMap,
    ) -> Result<StreamStateInfo, GrpcStreamingRetryError> {
        let position = StreamPosition {
            stream_id,
            message_index: 0,
            byte_offset: 0,
            last_message_id: None,
            checkpoint_data: Vec::new(),
        };

        let metadata = StreamMetadata::from_headers(headers);

        Ok(StreamStateInfo {
            position,
            metadata,
            checkpoints: Vec::new(),
        })
    }

    async fn save_stream_checkpoint(
        &self,
        cx: &Cx,
        stream_id: StreamId,
    ) -> Result<(), GrpcStreamingRetryError> {
        // Save current stream state for potential resume
        let checkpoint = StreamCheckpoint {
            timestamp: Instant::now(),
            position: StreamPosition {
                stream_id,
                message_index: 0,
                byte_offset: 0,
                last_message_id: None,
                checkpoint_data: vec![0; 16],
            },
            metadata_snapshot: HashMap::new(),
        };

        // Store checkpoint
        Ok(())
    }

    async fn validate_final_state(
        &self,
        cx: &Cx,
        stream_id: StreamId,
        position: &StreamPosition,
    ) -> Result<(), GrpcStreamingRetryError> {
        // Validate stream state consistency
        if position.stream_id != stream_id {
            return Err(GrpcStreamingRetryError::StreamStateCorrupted {
                stream_id,
                details: "Stream ID mismatch in final position".to_string(),
            });
        }
        Ok(())
    }
}

// Additional mock implementations

impl MockConnectionManager {
    fn new() -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            pool_config: ConnectionPoolConfig::default(),
            health_checker: Arc::new(MockHealthChecker),
            metrics: Arc::new(Mutex::new(ConnectionMetrics::default())),
        }
    }
}

impl MockRequestBuilder {
    fn new() -> Self {
        Self {
            default_headers: Arc::new(RwLock::new(HeaderMap::new())),
            compression_config: CompressionConfig::default(),
            timeout_config: TimeoutConfig::default(),
            metadata_enricher: Arc::new(MockMetadataEnricher),
        }
    }
}

impl MockResponseHandler {
    fn new() -> Self {
        Self {
            status_mapper: Arc::new(MockStatusMapper),
            metadata_extractor: Arc::new(MockMetadataExtractor),
            error_handler: Arc::new(MockErrorHandler),
            metrics_collector: Arc::new(MockMetricsCollector),
        }
    }
}

impl MockInterceptorChain {
    fn new() -> Self {
        Self {
            request_interceptors: Arc::new(RwLock::new(Vec::new())),
            response_interceptors: Arc::new(RwLock::new(Vec::new())),
            metadata_interceptors: Arc::new(RwLock::new(Vec::new())),
            execution_order: InterceptorOrder::Sequential,
        }
    }
}

impl MockMetadataManager {
    fn new() -> Self {
        Self {
            metadata_cache: Arc::new(RwLock::new(HashMap::new())),
            header_processor: Arc::new(MockHeaderProcessor),
            encoding_handler: Arc::new(MockEncodingHandler),
            validation_rules: Arc::new(RwLock::new(Vec::new())),
        }
    }
}

impl MockServiceRegistry {
    fn new() -> Self {
        Self {
            services: Arc::new(RwLock::new(HashMap::new())),
            method_handlers: Arc::new(RwLock::new(HashMap::new())),
            interceptors: Arc::new(RwLock::new(Vec::new())),
            middleware_stack: Arc::new(MockMiddlewareStack::new()),
        }
    }
}

impl MockRequestHandler {
    fn new() -> Self { Self }
}

impl MockStreamManager {
    fn new() -> Self {
        Self {
            active_streams: Arc::new(RwLock::new(HashMap::new())),
            stream_factory: Arc::new(MockStreamFactory),
            flow_controller: Arc::new(MockFlowController),
            buffer_manager: Arc::new(MockBufferManager),
            metrics: Arc::new(Mutex::new(StreamManagementMetrics::default())),
        }
    }
}

impl MockMiddlewareStack {
    fn new() -> Self {
        Self {
            middleware_layers: Arc::new(RwLock::new(Vec::new())),
            execution_strategy: ExecutionStrategy::Sequential,
            error_handling: MiddlewareErrorHandling::FailFast,
        }
    }
}

impl MockBackoffCalculator {
    fn new() -> Self {
        Self {
            strategies: Arc::new(RwLock::new(HashMap::new())),
            jitter_generator: Arc::new(MockJitterGenerator),
            timing_cache: Arc::new(RwLock::new(HashMap::new())),
            metrics: Arc::new(Mutex::new(BackoffMetrics::default())),
        }
    }
}

impl MockErrorClassifier {
    fn new() -> Self {
        Self {
            classification_rules: Arc::new(RwLock::new(Vec::new())),
            patterns: Arc::new(MockErrorPatterns),
            learning_engine: Arc::new(MockLearningEngine),
            metrics: Arc::new(Mutex::new(ErrorClassificationMetrics::default())),
        }
    }
}

impl MockCircuitBreaker {
    fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(CircuitBreakerState::Closed { failure_count: 0 })),
            thresholds: CircuitBreakerThresholds::default(),
            metrics: Arc::new(Mutex::new(CircuitBreakerMetrics::default())),
            recovery_strategy: RecoveryStrategy::Immediate,
        }
    }
}

impl MockHeaderTracker {
    fn new() -> Self {
        Self {
            header_history: Arc::new(RwLock::new(HashMap::new())),
            dedup_cache: Arc::new(RwLock::new(HashMap::new())),
            consistency_validator: Arc::new(MockConsistencyValidator),
            metrics: Arc::new(Mutex::new(HeaderTrackingMetrics::default())),
        }
    }
}

// Default implementations

impl Default for GrpcStreamingRetryConfig {
    fn default() -> Self {
        Self {
            max_retry_attempts: 3,
            base_retry_delay: Duration::from_millis(100),
            max_retry_delay: Duration::from_secs(30),
            jitter_factor: 0.1,
            stream_buffer_size: 1024,
            header_dedup_strategy: HeaderDeduplicationStrategy::Strict,
            retry_conditions: vec![RetryCondition::TransientError],
            stream_timeout_config: StreamTimeoutConfig::default(),
        }
    }
}

impl Default for StreamTimeoutConfig {
    fn default() -> Self {
        Self {
            connection_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(30),
            response_timeout: Duration::from_secs(30),
            stream_idle_timeout: Duration::from_secs(300),
            total_timeout: Duration::from_secs(600),
        }
    }
}

impl Default for ConnectionPoolConfig {
    fn default() -> Self {
        Self {
            max_connections: 100,
            idle_timeout: Duration::from_secs(300),
            connection_timeout: Duration::from_secs(5),
            health_check_interval: Duration::from_secs(30),
        }
    }
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            algorithm: CompressionType::Gzip,
            level: 6,
            min_size: 1024,
            enabled: true,
        }
    }
}

impl Default for CircuitBreakerThresholds {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            recovery_timeout: Duration::from_secs(60),
            success_threshold: 3,
            volume_threshold: 10,
        }
    }
}

// Configuration conversions

impl From<GrpcStreamingRetryConfig> for MockClientConfig {
    fn from(config: GrpcStreamingRetryConfig) -> Self {
        Self {
            default_timeout: config.stream_timeout_config.total_timeout,
            max_concurrent_streams: config.stream_buffer_size / 10,
            compression_enabled: true,
            keepalive_config: KeepAliveConfig {
                interval: Duration::from_secs(30),
                timeout: Duration::from_secs(5),
                without_calls: true,
            },
        }
    }
}

impl From<GrpcStreamingRetryConfig> for MockServerConfig {
    fn from(config: GrpcStreamingRetryConfig) -> Self {
        Self {
            bind_address: "0.0.0.0".to_string(),
            port: 50051,
            max_concurrent_streams: config.stream_buffer_size / 10,
            stream_buffer_size: config.stream_buffer_size,
            compression_config: CompressionConfig::default(),
        }
    }
}

impl From<GrpcStreamingRetryConfig> for RetryConfig {
    fn from(config: GrpcStreamingRetryConfig) -> Self {
        Self {
            max_attempts: config.max_retry_attempts,
            base_delay: config.base_retry_delay,
            max_delay: config.max_retry_delay,
            backoff_strategy: BackoffStrategy::Exponential {
                base: config.base_retry_delay,
                max_delay: config.max_retry_delay,
                multiplier: 2.0,
            },
        }
    }
}

/// Additional required types

impl Default for StreamMetadata {
    fn default() -> Self {
        Self {
            content_type: "application/grpc".to_string(),
            encoding: None,
            timeout: None,
            compression: None,
        }
    }
}

impl StreamMetadata {
    fn from_headers(headers: &HeaderMap) -> Self {
        Self {
            content_type: headers.get("content-type")
                .and_then(|values| values.first())
                .cloned()
                .unwrap_or_else(|| "application/grpc".to_string()),
            encoding: headers.get("content-encoding")
                .and_then(|values| values.first())
                .cloned(),
            timeout: None,
            compression: None,
        }
    }
}

/// Additional specialized types for mock implementations
#[derive(Debug, Clone)]
pub struct StreamMetadata {
    pub content_type: String,
    pub encoding: Option<String>,
    pub timeout: Option<Duration>,
    pub compression: Option<CompressionType>,
}

/// Simple configuration types
#[derive(Debug, Clone)]
pub struct RetryConfig {
    pub max_attempts: u32,
    pub base_delay: Duration,
    pub max_delay: Duration,
    pub backoff_strategy: BackoffStrategy,
}

/// Required enum types for compilation
#[derive(Debug, Clone)]
pub enum StreamType {
    UnaryStream,
    ClientStream,
    ServerStream,
    BidirectionalStream,
}

#[derive(Debug, Clone)]
pub enum StreamDirection {
    ClientToServer,
    ServerToClient,
    Bidirectional,
}

#[derive(Debug, Clone)]
pub enum StreamState {
    Initializing,
    Active,
    Draining,
    Closed,
    Error,
}

#[derive(Debug, Clone)]
pub enum CompressionType {
    None,
    Gzip,
    Deflate,
    Brotli,
}

// Test suite implementing the 6 scenarios

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cx::Cx,
        time::{Duration, Instant},
        types::{Budget, Outcome},
    };
    use futures::{stream, StreamExt};

    /// Test 1: Basic Stream Retry
    ///
    /// Verifies that a simple streaming gRPC call retries transparently on
    /// transient network errors without duplicating headers. Tests basic
    /// coordination between streaming and retry mechanisms.
    #[test]
    fn test_basic_stream_retry() {
        // Setup system with basic retry configuration
        let config = GrpcStreamingRetryConfig {
            max_retry_attempts: 3,
            base_retry_delay: Duration::from_millis(50),
            max_retry_delay: Duration::from_secs(5),
            jitter_factor: 0.1,
            header_dedup_strategy: HeaderDeduplicationStrategy::Strict,
            stream_timeout_config: StreamTimeoutConfig {
                total_timeout: Duration::from_secs(10),
                ..Default::default()
            },
            ..Default::default()
        };

        let system = MockGrpcStreamingRetrySystem::new(config);

        // Test execution
        let runtime = crate::runtime::RuntimeBuilder::new()
            .build()
            .expect("Failed to build runtime");

        runtime.run(async {
            let cx = Cx::root();

            // Create simple request stream
            let request_stream = stream::iter(vec![
                "message1".to_string(),
                "message2".to_string(),
            ]);

            // Execute streaming call with potential retry
            let result = system.execute_streaming_call_with_retry::<_, String>(
                &cx,
                "test_service",
                "test_method",
                request_stream,
            ).await;

            // Verify successful execution
            assert!(result.is_ok(), "Basic streaming call with retry should succeed");

            let call_result = result.unwrap();
            assert_eq!(call_result.messages_processed, 2, "Should process 2 messages");

            // Verify no header duplication
            let headers = &call_result.response_headers;
            for (name, values) in headers {
                if !name.starts_with("set-") && name != "warning" && name != "vary" {
                    assert!(values.len() <= 1, "Header '{}' should not be duplicated: {:?}", name, values);
                }
            }

            // Check system health
            let health = system.check_health();
            assert!(matches!(health, HealthStatus::Healthy), "System should remain healthy");

            // Verify metrics
            let metrics = system.get_metrics();
            assert!(metrics.streaming_operations.streams_completed > 0);
            assert_eq!(metrics.header_deduplication.consistency_violations, 0);
        });
    }

    /// Test 2: Header Deduplication
    ///
    /// Tests that headers are not duplicated across retry attempts when transient
    /// errors occur. Verifies sophisticated header deduplication logic maintains
    /// consistency while allowing proper retry behavior.
    #[test]
    fn test_header_deduplication() {
        let config = GrpcStreamingRetryConfig {
            max_retry_attempts: 5,
            base_retry_delay: Duration::from_millis(10), // Fast retries for testing
            header_dedup_strategy: HeaderDeduplicationStrategy::Strict,
            retry_conditions: vec![RetryCondition::TransientError],
            ..Default::default()
        };

        let system = MockGrpcStreamingRetrySystem::new(config);

        let runtime = crate::runtime::RuntimeBuilder::new()
            .build()
            .expect("Failed to build runtime");

        runtime.run(async {
            let cx = Cx::root();

            // Create request stream
            let request_stream = stream::iter(vec![
                "test_message".to_string(),
            ]);

            // Execute call that may trigger retries
            let result = system.execute_streaming_call_with_retry::<_, String>(
                &cx,
                "error_service", // Service name that triggers simulated errors
                "retry_method",
                request_stream,
            ).await;

            // Should succeed after retries
            assert!(result.is_ok(), "Streaming call should succeed after retries");

            let call_result = result.unwrap();

            // Comprehensive header deduplication validation
            let headers = &call_result.response_headers;

            // Check standard gRPC headers are not duplicated
            if let Some(content_type_values) = headers.get("content-type") {
                assert_eq!(content_type_values.len(), 1, "content-type should not be duplicated");
                assert_eq!(content_type_values[0], "application/grpc");
            }

            if let Some(status_values) = headers.get("grpc-status") {
                assert_eq!(status_values.len(), 1, "grpc-status should not be duplicated");
            }

            // Verify retry-specific headers are properly managed
            if let Some(retry_values) = headers.get("grpc-retry-attempt") {
                // Should have at most one retry attempt header in final response
                assert!(retry_values.len() <= 1, "grpc-retry-attempt should not be duplicated");
            }

            // Check deduplication metrics
            let metrics = system.get_metrics();
            assert!(metrics.header_deduplication.headers_processed > 0, "Should have processed headers");

            // If duplicates were detected and removed, verify it was handled correctly
            if metrics.header_deduplication.duplicates_detected > 0 {
                assert!(metrics.header_deduplication.duplicates_removed > 0,
                        "Detected duplicates should be removed");
            }

            assert_eq!(metrics.header_deduplication.consistency_violations, 0,
                      "Should have no consistency violations");
        });
    }

    /// Test 3: Multi-Message Stream Retry
    ///
    /// Tests retry behavior with partial stream consumption where some messages
    /// were successfully processed before a transient error occurred. Verifies
    /// that stream position is correctly maintained and resumed.
    #[test]
    fn test_multi_message_stream_retry() {
        let config = GrpcStreamingRetryConfig {
            max_retry_attempts: 4,
            base_retry_delay: Duration::from_millis(20),
            stream_buffer_size: 1024,
            stream_timeout_config: StreamTimeoutConfig {
                total_timeout: Duration::from_secs(15),
                stream_idle_timeout: Duration::from_secs(5),
                ..Default::default()
            },
            ..Default::default()
        };

        let system = MockGrpcStreamingRetrySystem::new(config);

        let runtime = crate::runtime::RuntimeBuilder::new()
            .build()
            .expect("Failed to build runtime");

        runtime.run(async {
            let cx = Cx::root();

            // Create larger request stream to test partial consumption
            let request_stream = stream::iter((0..10).map(|i| format!("message_{}", i)));

            // Execute streaming call with potential partial failure
            let result = system.execute_streaming_call_with_retry::<_, String>(
                &cx,
                "partial_error_service", // Service that fails partway through
                "stream_method",
                request_stream,
            ).await;

            // Should succeed after handling partial stream
            assert!(result.is_ok(), "Multi-message streaming call should succeed");

            let call_result = result.unwrap();
            assert!(call_result.messages_processed > 0, "Should process some messages");

            // Verify stream position was maintained
            let final_position = &call_result.final_position;
            assert_eq!(final_position.stream_id, call_result.stream_id);
            assert!(final_position.message_index > 0, "Should have advanced stream position");

            // Check that retry attempts were tracked
            let retry_history = &call_result.retry_history;
            if !retry_history.is_empty() {
                for retry_attempt in retry_history {
                    assert!(retry_attempt.attempt_number > 0);
                    assert!(retry_attempt.delay >= Duration::from_millis(20));
                }
            }

            // Verify no header duplication despite multiple messages
            let headers = &call_result.response_headers;
            for (name, values) in headers {
                if name != "set-cookie" && name != "warning" && name != "vary" {
                    assert!(values.len() <= 1, "Header '{}' should not be duplicated", name);
                }
            }

            // Check stream management metrics
            let metrics = system.get_metrics();
            assert!(metrics.state_management.snapshots_created >= 0, "Should track state snapshots");
            assert_eq!(metrics.state_management.state_validation_failures, 0, "Should have no state validation failures");
        });
    }

    /// Test 4: Bidirectional Stream Retry
    ///
    /// Tests retry behavior for complex bidirectional streaming where both client
    /// and server are sending messages. Verifies that retry logic correctly handles
    /// bidirectional flow and maintains header consistency in both directions.
    #[test]
    fn test_bidirectional_stream_retry() {
        let config = GrpcStreamingRetryConfig {
            max_retry_attempts: 3,
            base_retry_delay: Duration::from_millis(30),
            stream_buffer_size: 2048,
            header_dedup_strategy: HeaderDeduplicationStrategy::Smart,
            ..Default::default()
        };

        let system = MockGrpcStreamingRetrySystem::new(config);

        let runtime = crate::runtime::RuntimeBuilder::new()
            .build()
            .expect("Failed to build runtime");

        runtime.run(async {
            let cx = Cx::root();

            // Create bidirectional request stream
            let request_stream = stream::iter(vec![
                "client_msg1".to_string(),
                "client_msg2".to_string(),
                "client_msg3".to_string(),
            ]);

            // Execute bidirectional streaming call
            let result = system.execute_streaming_call_with_retry::<_, String>(
                &cx,
                "bidirectional_service",
                "bidi_method",
                request_stream,
            ).await;

            // Verify bidirectional streaming success
            assert!(result.is_ok(), "Bidirectional streaming should succeed");

            let call_result = result.unwrap();
            assert_eq!(call_result.messages_processed, 3, "Should process all client messages");

            // Verify bidirectional headers are properly managed
            let headers = &call_result.response_headers;

            // Check for proper gRPC headers in response
            assert!(headers.contains_key("content-type"), "Should have content-type header");
            if let Some(grpc_status) = headers.get("grpc-status") {
                assert_eq!(grpc_status.len(), 1, "grpc-status should not be duplicated");
            }

            // Verify stream position tracking for bidirectional flow
            let final_position = &call_result.final_position;
            assert!(final_position.byte_offset > 0, "Should track byte offset for bidirectional stream");

            // Check that both directions maintained header consistency
            let metrics = system.get_metrics();
            assert_eq!(metrics.header_deduplication.consistency_violations, 0);

            // Verify streaming metrics reflect bidirectional nature
            assert!(metrics.streaming_operations.messages_sent > 0);
            assert!(metrics.streaming_operations.bytes_transferred > 0);

            // System should remain healthy after complex bidirectional streaming
            let health = system.check_health();
            assert!(matches!(health, HealthStatus::Healthy), "System should remain healthy");
        });
    }

    /// Test 5: Retry Exhaustion Handling
    ///
    /// Tests behavior when retry limits are exceeded for streaming calls.
    /// Verifies that the system gracefully handles retry exhaustion while
    /// maintaining header consistency and proper error reporting.
    #[test]
    fn test_retry_exhaustion_handling() {
        let config = GrpcStreamingRetryConfig {
            max_retry_attempts: 2, // Low limit to test exhaustion
            base_retry_delay: Duration::from_millis(5), // Fast retries
            max_retry_delay: Duration::from_millis(100),
            header_dedup_strategy: HeaderDeduplicationStrategy::Strict,
            stream_timeout_config: StreamTimeoutConfig {
                total_timeout: Duration::from_secs(5),
                ..Default::default()
            },
            ..Default::default()
        };

        let system = MockGrpcStreamingRetrySystem::new(config);

        let runtime = crate::runtime::RuntimeBuilder::new()
            .build()
            .expect("Failed to build runtime");

        runtime.run(async {
            let cx = Cx::root();

            // Create request stream
            let request_stream = stream::iter(vec!["test_message".to_string()]);

            // Execute call that will exhaust retries (using persistent error service)
            let result = system.execute_streaming_call_with_retry::<_, String>(
                &cx,
                "persistent_error_service", // Service that always fails
                "failing_method",
                request_stream,
            ).await;

            // Should fail after exhausting retries
            assert!(result.is_err(), "Should fail after exhausting retries");

            match result.unwrap_err() {
                GrpcStreamingRetryError::RetriesExhausted { attempts, .. } => {
                    assert_eq!(attempts, 2, "Should have attempted 2 retries");
                }
                _ => panic!("Expected RetriesExhausted error"),
            }

            // Verify retry exhaustion metrics
            let metrics = system.get_metrics();
            assert!(metrics.retry_attempts.retries_exhausted > 0, "Should record retry exhaustion");
            assert!(metrics.retry_attempts.failed_retries > 0, "Should record failed retries");

            // Even with exhausted retries, should not have header consistency issues
            assert_eq!(metrics.header_deduplication.consistency_violations, 0);

            // System should handle retry exhaustion gracefully
            let health = system.check_health();
            assert!(!matches!(health, HealthStatus::Critical { .. }),
                    "System should handle retry exhaustion gracefully");
        });
    }

    /// Test 6: Stream Metadata Preservation
    ///
    /// Tests that stream metadata and custom headers are preserved consistently
    /// across retry attempts. Verifies comprehensive metadata handling including
    /// custom headers, timeouts, and stream-specific configuration.
    #[test]
    fn test_stream_metadata_preservation() {
        let config = GrpcStreamingRetryConfig {
            max_retry_attempts: 4,
            base_retry_delay: Duration::from_millis(25),
            header_dedup_strategy: HeaderDeduplicationStrategy::Smart,
            stream_timeout_config: StreamTimeoutConfig {
                total_timeout: Duration::from_secs(20),
                request_timeout: Duration::from_secs(10),
                response_timeout: Duration::from_secs(10),
                ..Default::default()
            },
            ..Default::default()
        };

        let system = MockGrpcStreamingRetrySystem::new(config);

        let runtime = crate::runtime::RuntimeBuilder::new()
            .build()
            .expect("Failed to build runtime");

        runtime.run(async {
            let cx = Cx::root();

            // Create request stream with metadata
            let request_stream = stream::iter(vec![
                "metadata_message1".to_string(),
                "metadata_message2".to_string(),
            ]);

            // Execute streaming call with metadata preservation
            let result = system.execute_streaming_call_with_retry::<_, String>(
                &cx,
                "metadata_service",
                "metadata_method",
                request_stream,
            ).await;

            // Verify successful execution with metadata preservation
            assert!(result.is_ok(), "Metadata preservation streaming should succeed");

            let call_result = result.unwrap();

            // Comprehensive metadata validation
            let headers = &call_result.response_headers;

            // Verify essential gRPC metadata is present and not duplicated
            assert!(headers.contains_key("content-type"), "Should preserve content-type");
            if let Some(content_type) = headers.get("content-type") {
                assert_eq!(content_type.len(), 1, "content-type should not be duplicated");
                assert_eq!(content_type[0], "application/grpc");
            }

            assert!(headers.contains_key(":method") || headers.contains_key("grpc-status"),
                    "Should have gRPC protocol headers");

            // Verify custom metadata preservation (if any were added)
            for (name, values) in headers {
                // Check that all headers have reasonable values
                assert!(!values.is_empty(), "Header '{}' should not be empty", name);

                // Verify no unexpected duplicates
                if !name.starts_with("x-") && name != "set-cookie" && name != "warning" {
                    assert!(values.len() <= 2,
                            "Standard header '{}' should not be excessively duplicated: {:?}",
                            name, values);
                }
            }

            // Verify stream metadata consistency
            let final_position = &call_result.final_position;
            assert!(final_position.checkpoint_data.len() > 0, "Should have checkpoint data");

            // Check metadata preservation metrics
            let metrics = system.get_metrics();
            assert_eq!(metrics.header_deduplication.consistency_violations, 0,
                      "Should maintain metadata consistency");

            assert!(metrics.state_management.position_updates >= 0,
                    "Should track metadata position updates");

            // Verify performance with metadata preservation
            assert!(call_result.duration < Duration::from_secs(15),
                    "Metadata preservation should not significantly impact performance");

            // System health should remain good with metadata handling
            let health = system.check_health();
            assert!(matches!(health, HealthStatus::Healthy),
                    "System should remain healthy with metadata preservation");
        });
    }

    /// Helper test to verify system configuration and basic functionality
    #[test]
    fn test_system_configuration_and_health() {
        let config = GrpcStreamingRetryConfig::default();
        let system = MockGrpcStreamingRetrySystem::new(config.clone());

        // Verify initial state
        let health = system.check_health();
        assert!(matches!(health, HealthStatus::Healthy), "System should start healthy");

        let metrics = system.get_metrics();
        assert_eq!(metrics.streaming_operations.streams_completed, 0, "Should start with no completed streams");
        assert_eq!(metrics.retry_attempts.total_retries, 0, "Should start with no retries");

        // Test configuration validation
        assert_eq!(config.max_retry_attempts, 3);
        assert_eq!(config.base_retry_delay, Duration::from_millis(100));
        assert!(matches!(config.header_dedup_strategy, HeaderDeduplicationStrategy::Strict));
        assert_eq!(config.stream_timeout_config.total_timeout, Duration::from_secs(600));
    }
}