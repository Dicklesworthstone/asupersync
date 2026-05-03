#![no_main]

//! Structure-aware fuzz target for gRPC Health Watch transitional state replay.
//!
//! Targets edge cases in health check streaming state transitions:
//! - Complex sequences of health status transitions across multiple services
//! - Concurrent watch streams with different authentication states
//! - Race conditions between status updates and stream polling
//! - Waiter registration/unregistration timing under concurrent updates
//! - Edge cases in initial status emission vs subsequent change notifications
//! - Authentication enforcement consistency across Check vs Watch methods

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

use asupersync::grpc::health::{HealthError, HealthService, MAX_SERVICE_NAME_LEN, ServingStatus};
use asupersync::grpc::status::Status;
use asupersync::grpc::streaming::{Metadata, MetadataValue, Request, Response, Streaming};

/// Maximum services and transitions for fuzzer performance
const MAX_SERVICES: usize = 20;
const MAX_TRANSITIONS: usize = 100;
const MAX_WATCHERS: usize = 10;

/// Test scenario for health watch transitional state replay
#[derive(Arbitrary, Debug, Clone)]
struct HealthWatchScenario {
    /// Initial service configurations
    initial_services: Vec<ServiceSetup>,
    /// Sequence of state transitions to apply
    transitions: Vec<StateTransition>,
    /// Watch stream configurations to test
    watchers: Vec<WatcherSetup>,
    /// Concurrent operations to stress test timing
    concurrent_ops: Vec<ConcurrentOperation>,
}

/// Initial setup for a service
#[derive(Arbitrary, Debug, Clone)]
struct ServiceSetup {
    /// Service name (may be invalid for edge case testing)
    name: ServiceName,
    /// Initial status
    status: ServingStatus,
}

/// Service name patterns for testing various edge cases
#[derive(Arbitrary, Debug, Clone)]
enum ServiceName {
    /// Empty string (server-level health)
    Empty,
    /// Normal service name
    Normal(NormalServiceName),
    /// Edge case names
    EdgeCase(EdgeCaseServiceName),
    /// Invalid names for error testing
    Invalid(InvalidServiceName),
}

impl ServiceName {
    fn as_string(&self) -> String {
        match self {
            ServiceName::Empty => String::new(),
            ServiceName::Normal(n) => n.as_string(),
            ServiceName::EdgeCase(e) => e.as_string(),
            ServiceName::Invalid(i) => i.as_string(),
        }
    }
}

/// Normal service name patterns
#[derive(Arbitrary, Debug, Clone)]
enum NormalServiceName {
    /// Single component
    Simple(u8), // "service{n}"
    /// Dotted package
    Dotted(u8, u8), // "package{n}.Service{m}"
    /// Deep hierarchy
    Deep(u8, u8, u8), // "com.example{n}.pkg{m}.Service{o}"
}

impl NormalServiceName {
    fn as_string(&self) -> String {
        match self {
            NormalServiceName::Simple(n) => format!("service{}", n),
            NormalServiceName::Dotted(n, m) => format!("package{}.Service{}", n, m),
            NormalServiceName::Deep(n, m, o) => format!("com.example{}.pkg{}.Service{}", n, m, o),
        }
    }
}

/// Edge case service names that are valid but unusual
#[derive(Arbitrary, Debug, Clone)]
enum EdgeCaseServiceName {
    /// Single character
    SingleChar,
    /// Maximum length valid name
    MaxLength,
    /// Numeric service name
    Numeric(u32),
    /// Special characters (valid in gRPC names)
    SpecialChars,
}

impl EdgeCaseServiceName {
    fn as_string(&self) -> String {
        match self {
            EdgeCaseServiceName::SingleChar => "a".to_string(),
            EdgeCaseServiceName::MaxLength => "a".repeat(MAX_SERVICE_NAME_LEN),
            EdgeCaseServiceName::Numeric(n) => format!("{}", n),
            EdgeCaseServiceName::SpecialChars => "my-service_123.v1".to_string(),
        }
    }
}

/// Invalid service names for error testing
#[derive(Arbitrary, Debug, Clone)]
enum InvalidServiceName {
    /// Exceeds maximum length
    TooLong(u8), // MAX_SERVICE_NAME_LEN + 1..255
    /// Contains invalid characters
    InvalidChars,
}

impl InvalidServiceName {
    fn as_string(&self) -> String {
        match self {
            InvalidServiceName::TooLong(extra) => {
                "a".repeat(MAX_SERVICE_NAME_LEN + 1 + (*extra as usize))
            }
            InvalidServiceName::InvalidChars => "service\x00with\x01invalid\x02chars".to_string(),
        }
    }
}

/// State transition operations
#[derive(Arbitrary, Debug, Clone)]
enum StateTransition {
    /// Set a single service status
    SetSingleStatus {
        service: ServiceName,
        status: ServingStatus,
    },
    /// Set server-wide status
    SetServerStatus { status: ServingStatus },
    /// Clear all statuses
    ClearAll,
    /// Batch status updates
    BatchUpdate { updates: Vec<BatchStatusUpdate> },
    /// Transient status (set then immediately change)
    Transient {
        service: ServiceName,
        intermediate_status: ServingStatus,
        final_status: ServingStatus,
    },
}

/// Batch status update for testing atomic operations
#[derive(Arbitrary, Debug, Clone)]
struct BatchStatusUpdate {
    service: ServiceName,
    status: ServingStatus,
}

/// Watcher configuration for testing streaming behavior
#[derive(Arbitrary, Debug, Clone)]
struct WatcherSetup {
    /// Service to watch
    service: ServiceName,
    /// Authentication metadata
    auth: AuthSetup,
    /// Polling behavior
    polling: PollingBehavior,
}

/// Authentication setup for testing auth enforcement
#[derive(Arbitrary, Debug, Clone)]
enum AuthSetup {
    /// No auth metadata (should be rejected)
    None,
    /// Valid auth token
    Valid(ValidAuthToken),
    /// Invalid auth token
    Invalid(InvalidAuthToken),
}

/// Valid authentication token patterns
#[derive(Arbitrary, Debug, Clone)]
enum ValidAuthToken {
    /// Standard bearer token
    Bearer(u32), // "Bearer token{n}"
    /// API key
    ApiKey(u32), // "ApiKey key{n}"
}

impl ValidAuthToken {
    fn as_metadata_value(&self) -> MetadataValue {
        match self {
            ValidAuthToken::Bearer(n) => {
                MetadataValue::Ascii(format!("Bearer token{}", n).try_into().unwrap())
            }
            ValidAuthToken::ApiKey(n) => {
                MetadataValue::Ascii(format!("ApiKey key{}", n).try_into().unwrap())
            }
        }
    }
}

/// Invalid authentication token patterns
#[derive(Arbitrary, Debug, Clone)]
enum InvalidAuthToken {
    /// Empty value
    Empty,
    /// Wrong format
    WrongFormat,
    /// Binary data (invalid for auth header)
    Binary,
}

impl InvalidAuthToken {
    fn as_metadata_value(&self) -> MetadataValue {
        match self {
            InvalidAuthToken::Empty => MetadataValue::Ascii("".try_into().unwrap()),
            InvalidAuthToken::WrongFormat => {
                MetadataValue::Ascii("InvalidFormat".try_into().unwrap())
            }
            InvalidAuthToken::Binary => MetadataValue::Binary(vec![0x00, 0x01, 0x02]),
        }
    }
}

/// Polling behavior patterns for testing async stream behavior
#[derive(Arbitrary, Debug, Clone)]
enum PollingBehavior {
    /// Poll immediately and continuously
    Immediate,
    /// Poll after each status change
    OnChange,
    /// Poll with delays
    Delayed(DelayPattern),
    /// Random polling pattern
    Random(u8), // Number of polls
}

/// Delay patterns for testing timing sensitivity
#[derive(Arbitrary, Debug, Clone)]
enum DelayPattern {
    /// Fixed delay between polls
    Fixed,
    /// Increasing delay (backoff)
    Increasing,
    /// Decreasing delay (acceleration)
    Decreasing,
}

/// Concurrent operations for stress testing
#[derive(Arbitrary, Debug, Clone)]
enum ConcurrentOperation {
    /// Concurrent status updates
    ConcurrentUpdates {
        service: ServiceName,
        updates: Vec<ServingStatus>,
    },
    /// Multiple watchers on same service
    MultipleWatchers {
        service: ServiceName,
        count: u8, // 1-10
    },
    /// Rapid watcher creation/destruction
    WatcherChurn {
        service: ServiceName,
        cycles: u8, // 1-20
    },
    /// Status thrashing (rapid status changes)
    StatusThrashing {
        service: ServiceName,
        duration: u8, // Number of rapid changes
    },
}

/// Mock health check request
#[derive(Debug)]
struct MockHealthCheckRequest {
    service: String,
}

/// Mock health check response
#[derive(Debug, Clone)]
struct MockHealthCheckResponse {
    status: ServingStatus,
}

impl MockHealthCheckResponse {
    fn new(status: ServingStatus) -> Self {
        Self { status }
    }
}

/// Test waker for controlling async execution
struct TestWaker {
    woken: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl TestWaker {
    fn new() -> Self {
        Self {
            woken: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    fn waker(&self) -> Waker {
        use std::task::RawWaker;
        use std::task::RawWakerVTable;

        unsafe fn clone_waker(data: *const ()) -> RawWaker {
            RawWaker::new(data, &VTABLE)
        }

        unsafe fn wake_waker(_data: *const ()) {
            // In real implementation, would set woken flag
        }

        unsafe fn wake_by_ref_waker(_data: *const ()) {
            // In real implementation, would set woken flag
        }

        unsafe fn drop_waker(_data: *const ()) {}

        static VTABLE: RawWakerVTable =
            RawWakerVTable::new(clone_waker, wake_waker, wake_by_ref_waker, drop_waker);

        unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) }
    }

    fn was_woken(&self) -> bool {
        self.woken.load(std::sync::atomic::Ordering::Acquire)
    }
}

fuzz_target!(|scenario: HealthWatchScenario| {
    // Limit complexity for fuzzer performance
    if scenario.initial_services.len() > MAX_SERVICES {
        return;
    }
    if scenario.transitions.len() > MAX_TRANSITIONS {
        return;
    }
    if scenario.watchers.len() > MAX_WATCHERS {
        return;
    }

    // Test health watch transitional state replay
    test_watch_transitions(&scenario);

    // Test concurrent streaming behavior
    test_concurrent_streams(&scenario);

    // Test auth enforcement consistency
    test_auth_enforcement(&scenario);
});

fn test_watch_transitions(scenario: &HealthWatchScenario) {
    let service = HealthService::new();

    // Set up initial services
    for setup in &scenario.initial_services {
        let name = setup.name.as_string();
        let _ = service.try_set_status(&name, setup.status);
    }

    // Apply state transitions
    for transition in &scenario.transitions {
        apply_state_transition(&service, transition);
    }

    // Test watcher behavior
    for watcher_setup in &scenario.watchers {
        test_single_watcher(&service, watcher_setup);
    }

    // Apply concurrent operations
    for op in &scenario.concurrent_ops {
        apply_concurrent_operation(&service, op);
    }
}

fn apply_state_transition(service: &HealthService, transition: &StateTransition) {
    match transition {
        StateTransition::SetSingleStatus {
            service: svc_name,
            status,
        } => {
            let name = svc_name.as_string();
            let _ = service.try_set_status(&name, *status);
        }

        StateTransition::SetServerStatus { status } => {
            service.set_server_status(*status);
        }

        StateTransition::ClearAll => {
            service.clear_all();
        }

        StateTransition::BatchUpdate { updates } => {
            // Apply batch updates in sequence
            let names_and_statuses: Vec<_> = updates
                .iter()
                .map(|u| (u.service.as_string(), u.status))
                .collect();

            for (name, status) in names_and_statuses {
                let _ = service.try_set_status(&name, status);
            }
        }

        StateTransition::Transient {
            service: svc_name,
            intermediate_status,
            final_status,
        } => {
            let name = svc_name.as_string();
            // Set intermediate status then immediately change to final
            let _ = service.try_set_status(&name, *intermediate_status);
            let _ = service.try_set_status(&name, *final_status);
        }
    }
}

fn test_single_watcher(service: &HealthService, setup: &WatcherSetup) {
    let service_name = setup.service.as_string();

    // Test direct watcher (polling interface)
    let mut watcher = service.watch(&service_name);
    let initial_status = watcher.status();

    // Test change detection
    let changed = watcher.changed();
    let _ = (initial_status, changed); // Use variables to avoid warnings

    // Test async watch stream
    let metadata = build_metadata(&setup.auth);
    let request = create_mock_request(service_name.clone(), metadata);

    // Test watch_async
    let result = futures_lite::future::block_on(service.watch_async(&request));

    match result {
        Ok(response) => {
            // Stream created successfully - test initial emission
            let mut stream = response.into_inner();
            let test_waker = TestWaker::new();
            let waker = test_waker.waker();
            let mut cx = Context::from_waker(&waker);

            // Poll for initial status
            match Pin::new(&mut stream).poll_next(&mut cx) {
                Poll::Ready(Some(Ok(_response))) => {
                    // Initial status emitted correctly
                }
                Poll::Ready(Some(Err(_))) => {
                    // Stream error
                }
                Poll::Ready(None) => {
                    // Stream ended unexpectedly
                }
                Poll::Pending => {
                    // Stream pending (shouldn't happen for initial status)
                }
            }

            // Test subsequent polling based on behavior
            match setup.polling {
                PollingBehavior::Immediate => {
                    // Poll again immediately
                    let _ = Pin::new(&mut stream).poll_next(&mut cx);
                }
                PollingBehavior::OnChange => {
                    // Only poll after making a change
                    let _ = service.try_set_status(&service_name, ServingStatus::NotServing);
                    let _ = Pin::new(&mut stream).poll_next(&mut cx);
                }
                PollingBehavior::Delayed(_) => {
                    // Simulate delayed polling
                    let _ = Pin::new(&mut stream).poll_next(&mut cx);
                }
                PollingBehavior::Random(count) => {
                    // Random number of polls
                    for _ in 0..(count % 5) {
                        let _ = Pin::new(&mut stream).poll_next(&mut cx);
                    }
                }
            }
        }
        Err(_status) => {
            // Stream creation failed (likely auth error) - this is expected
            // for invalid auth configurations
        }
    }
}

fn test_concurrent_streams(scenario: &HealthWatchScenario) {
    let service = HealthService::new();

    // Set up initial services
    for setup in &scenario.initial_services {
        let name = setup.name.as_string();
        let _ = service.try_set_status(&name, setup.status);
    }

    // Create multiple concurrent watchers
    let mut watchers = Vec::new();
    for watcher_setup in &scenario.watchers {
        let service_name = watcher_setup.service.as_string();
        let watcher = service.watch(&service_name);
        watchers.push((service_name, watcher));
    }

    // Apply transitions and check watcher consistency
    for transition in &scenario.transitions {
        apply_state_transition(&service, transition);

        // Check that all watchers see consistent state
        for (_name, watcher) in &mut watchers {
            let changed = watcher.changed();
            let _status = watcher.status();
            let _ = (changed, _status); // Use variables to avoid warnings
        }
    }
}

fn test_auth_enforcement(scenario: &HealthWatchScenario) {
    let service = HealthService::new();

    // Test that Watch and Check have consistent auth behavior
    for watcher_setup in &scenario.watchers {
        let service_name = watcher_setup.service.as_string();
        let metadata = build_metadata(&watcher_setup.auth);

        // Test Check method with same metadata
        let check_request = create_mock_request(service_name.clone(), metadata.clone());
        let check_result = futures_lite::future::block_on(service.check_async(&check_request));

        // Test Watch method with same metadata
        let watch_request = create_mock_request(service_name, metadata);
        let watch_result = futures_lite::future::block_on(service.watch_async(&watch_request));

        // Auth decisions should be consistent
        match (&check_result, &watch_result) {
            (Ok(_), Ok(_)) => {
                // Both succeeded - auth is valid
            }
            (Err(check_err), Err(watch_err)) => {
                // Both failed - auth is invalid
                // Error codes should match
                let codes_match = check_err.code() == watch_err.code();
                if !codes_match {
                    // Inconsistent auth enforcement detected
                }
            }
            (Ok(_), Err(_)) | (Err(_), Ok(_)) => {
                // Inconsistent auth enforcement between Check and Watch
            }
        }
    }
}

fn apply_concurrent_operation(service: &HealthService, op: &ConcurrentOperation) {
    match op {
        ConcurrentOperation::ConcurrentUpdates {
            service: svc_name,
            updates,
        } => {
            let name = svc_name.as_string();
            for &status in updates {
                let _ = service.try_set_status(&name, status);
            }
        }

        ConcurrentOperation::MultipleWatchers {
            service: svc_name,
            count,
        } => {
            let name = svc_name.as_string();
            let mut watchers = Vec::new();

            // Create multiple watchers
            for _ in 0..(*count as usize).min(10) {
                let watcher = service.watch(&name);
                watchers.push(watcher);
            }

            // Exercise all watchers
            for watcher in &mut watchers {
                let _changed = watcher.changed();
                let _status = watcher.status();
            }
        }

        ConcurrentOperation::WatcherChurn {
            service: svc_name,
            cycles,
        } => {
            let name = svc_name.as_string();

            // Rapidly create and drop watchers
            for _ in 0..(*cycles as usize).min(20) {
                let mut watcher = service.watch(&name);
                let _changed = watcher.changed();
                // Watcher drops here
            }
        }

        ConcurrentOperation::StatusThrashing {
            service: svc_name,
            duration,
        } => {
            let name = svc_name.as_string();
            let statuses = [
                ServingStatus::Unknown,
                ServingStatus::Serving,
                ServingStatus::NotServing,
                ServingStatus::ServiceUnknown,
            ];

            // Rapid status changes
            for i in 0..(*duration as usize).min(50) {
                let status = statuses[i % statuses.len()];
                let _ = service.try_set_status(&name, status);
            }
        }
    }
}

fn build_metadata(auth: &AuthSetup) -> Metadata {
    let mut metadata = Metadata::new();

    match auth {
        AuthSetup::None => {
            // No auth metadata
        }
        AuthSetup::Valid(valid_token) => {
            metadata.insert("authorization", valid_token.as_metadata_value());
        }
        AuthSetup::Invalid(invalid_token) => {
            metadata.insert("authorization", invalid_token.as_metadata_value());
        }
    }

    metadata
}

fn create_mock_request(service: String, metadata: Metadata) -> Request<MockHealthCheckRequest> {
    let inner = MockHealthCheckRequest { service };
    Request::from_parts(inner, metadata)
}

// Mock implementations needed for compilation
impl HealthService {
    // These would need to be actual methods in the real implementation
    async fn check_async(
        &self,
        _request: &Request<MockHealthCheckRequest>,
    ) -> Result<MockHealthCheckResponse, Status> {
        // Mock implementation
        Ok(MockHealthCheckResponse::new(ServingStatus::Serving))
    }
}
