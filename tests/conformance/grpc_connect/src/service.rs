//! Conformance test service implementation
//!
//! This module implements the test service that serves as the target for
//! conformance testing. It provides all RPC patterns and edge cases needed
//! to verify gRPC protocol compliance.

use anyhow::Result;
use asupersync::cx::Cx;
use asupersync::grpc::{
    Code, Request, Response, Status,
    service::{NamedService, ServiceDescriptor, UnaryMethod, ServerStreamingMethod,
              ClientStreamingMethod, BidiStreamingMethod},
    streaming::{RequestStream, ResponseSink},
};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::{TestRequest, TestResponse, StreamingTestRequest, StreamingTestResponse, AuthContext};

/// Conformance test service implementation
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ConformanceTestService {
    server_id: String,
    request_counter: Arc<AtomicU32>,
}

#[allow(dead_code)]

impl ConformanceTestService {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self {
            server_id: Uuid::new_v4().to_string(),
            request_counter: Arc::new(AtomicU32::new(0)),
        }
    }

    /// Unary call - single request, single response
    pub async fn unary_call(
        &self,
        cx: &Cx,
        request: Request<Bytes>
    ) -> Result<Response<Bytes>, Status> {
        let request_id = self.request_counter.fetch_add(1, Ordering::SeqCst);
        debug!("Processing unary call #{}", request_id);

        // Parse request
        let test_request: TestRequest = serde_json::from_slice(request.get_ref())
            .map_err(|e| Status::new(Code::InvalidArgument, &format!("Invalid request JSON: {}", e)))?;

        // Simulate processing time for large messages
        if test_request.message.len() > 1024 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        // Check for maximum message size
        if test_request.message.len() > 4 * 1024 * 1024 {
            return Err(Status::new(Code::ResourceExhausted, "Message too large"));
        }

        // Build response
        let mut response = TestResponse {
            message: if test_request.message.is_empty() {
                "Empty message received".to_string()
            } else {
                format!("Echo: {}", test_request.message)
            },
            server_id: if test_request.fill_server_id {
                Some(self.server_id.clone())
            } else {
                None
            },
            client_compressed: false, // TODO: Check compression header
            server_compressed: false, // TODO: Check compression settings
            auth_context: if test_request.check_auth_context {
                Some(AuthContext {
                    peer_identity: Some("test-client".to_string()),
                    peer_identity_property_name: Some("peer".to_string()),
                })
            } else {
                None
            },
        };

        // Apply response size if specified
        if let Some(target_size) = test_request.response_size {
            let current_size = serde_json::to_vec(&response).unwrap().len();
            if target_size as usize > current_size {
                let padding_size = target_size as usize - current_size;
                response.message.push_str(&"x".repeat(padding_size));
            }
        }

        let response_bytes = serde_json::to_vec(&response)
            .map_err(|e| Status::new(Code::Internal, &format!("Serialization error: {}", e)))?;

        let mut grpc_response = Response::new(Bytes::from(response_bytes));

        // Echo metadata if requested
        if test_request.echo_metadata {
            for (key, value) in request.metadata() {
                if key.as_str().starts_with("test-") {
                    grpc_response.metadata_mut().insert(key.clone(), value.clone());
                }
            }
        }

        // Echo deadline if requested
        if test_request.echo_deadline {
            if let Some(deadline) = request.metadata().get("grpc-timeout") {
                grpc_response.metadata_mut().insert("echo-deadline", deadline.clone());
            }
        }

        debug!("Completed unary call #{} successfully", request_id);
        Ok(grpc_response)
    }

    /// Server streaming - single request, multiple responses
    pub async fn server_streaming_call(
        &self,
        cx: &Cx,
        request: Request<Bytes>,
        mut response_sink: ResponseSink<Bytes>
    ) -> Result<(), Status> {
        let request_id = self.request_counter.fetch_add(1, Ordering::SeqCst);
        debug!("Processing server streaming call #{}", request_id);

        let test_request: StreamingTestRequest = serde_json::from_slice(request.get_ref())
            .map_err(|e| Status::new(Code::InvalidArgument, &format!("Invalid request JSON: {}", e)))?;

        // Send multiple responses
        for i in 0..5 {
            if cx.is_cancelled() {
                debug!("Server streaming call #{} cancelled", request_id);
                return Err(Status::new(Code::Cancelled, "Request cancelled"));
            }

            let response = StreamingTestResponse {
                message: format!("{} - Response #{}", test_request.message, i),
                sequence_number: i,
                server_timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64,
            };

            let response_bytes = serde_json::to_vec(&response)
                .map_err(|e| Status::new(Code::Internal, &format!("Serialization error: {}", e)))?;

            response_sink.send(Bytes::from(response_bytes)).await
                .map_err(|e| Status::new(Code::Internal, &format!("Send error: {}", e)))?;

            // Small delay between responses
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        debug!("Completed server streaming call #{} successfully", request_id);
        Ok(())
    }

    /// Client streaming - multiple requests, single response
    pub async fn client_streaming_call(
        &self,
        cx: &Cx,
        mut request_stream: RequestStream<Bytes>
    ) -> Result<Response<Bytes>, Status> {
        let request_id = self.request_counter.fetch_add(1, Ordering::SeqCst);
        debug!("Processing client streaming call #{}", request_id);

        let mut request_count = 0;
        let mut total_message_length = 0;
        let mut last_sequence = 0;

        while let Some(request_bytes) = request_stream.next().await {
            if cx.is_cancelled() {
                debug!("Client streaming call #{} cancelled", request_id);
                return Err(Status::new(Code::Cancelled, "Request cancelled"));
            }

            let streaming_request: StreamingTestRequest = serde_json::from_slice(&request_bytes)
                .map_err(|e| Status::new(Code::InvalidArgument, &format!("Invalid request JSON: {}", e)))?;

            request_count += 1;
            total_message_length += streaming_request.message.len();
            last_sequence = streaming_request.sequence_number;

            debug!("Received streaming request #{} with sequence {}",
                   request_count, streaming_request.sequence_number);

            if streaming_request.end_stream {
                debug!("End stream marker received");
                break;
            }
        }

        let response = TestResponse {
            message: format!("Processed {} requests, total {} bytes", request_count, total_message_length),
            server_id: Some(self.server_id.clone()),
            client_compressed: false,
            server_compressed: false,
            auth_context: None,
        };

        let response_bytes = serde_json::to_vec(&response)
            .map_err(|e| Status::new(Code::Internal, &format!("Serialization error: {}", e)))?;

        debug!("Completed client streaming call #{} successfully", request_id);
        Ok(Response::new(Bytes::from(response_bytes)))
    }

    /// Bidirectional streaming - multiple requests, multiple responses
    pub async fn bidirectional_streaming_call(
        &self,
        cx: &Cx,
        mut request_stream: RequestStream<Bytes>,
        mut response_sink: ResponseSink<Bytes>
    ) -> Result<(), Status> {
        let request_id = self.request_counter.fetch_add(1, Ordering::SeqCst);
        debug!("Processing bidirectional streaming call #{}", request_id);

        // Echo each request as a response with server timestamp
        while let Some(request_bytes) = request_stream.next().await {
            if cx.is_cancelled() {
                debug!("Bidirectional streaming call #{} cancelled", request_id);
                return Err(Status::new(Code::Cancelled, "Request cancelled"));
            }

            let streaming_request: StreamingTestRequest = serde_json::from_slice(&request_bytes)
                .map_err(|e| Status::new(Code::InvalidArgument, &format!("Invalid request JSON: {}", e)))?;

            let response = StreamingTestResponse {
                message: format!("Echo: {}", streaming_request.message),
                sequence_number: streaming_request.sequence_number,
                server_timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64,
            };

            let response_bytes = serde_json::to_vec(&response)
                .map_err(|e| Status::new(Code::Internal, &format!("Serialization error: {}", e)))?;

            response_sink.send(Bytes::from(response_bytes)).await
                .map_err(|e| Status::new(Code::Internal, &format!("Send error: {}", e)))?;

            debug!("Echoed request #{} with sequence {}",
                   request_id, streaming_request.sequence_number);

            if streaming_request.end_stream {
                debug!("End stream marker received, closing bidirectional stream");
                break;
            }

            // Small processing delay
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }

        debug!("Completed bidirectional streaming call #{} successfully", request_id);
        Ok(())
    }

    /// Test method that always returns an error for error handling tests
    pub async fn error_test_call(
        &self,
        cx: &Cx,
        request: Request<Bytes>
    ) -> Result<Response<Bytes>, Status> {
        let request_id = self.request_counter.fetch_add(1, Ordering::SeqCst);
        debug!("Processing error test call #{} (will fail intentionally)", request_id);

        // Parse request to determine which error to return
        let test_request: TestRequest = serde_json::from_slice(request.get_ref())
            .map_err(|e| Status::new(Code::InvalidArgument, &format!("Invalid request JSON: {}", e)))?;

        let error_type = test_request.message.as_str();
        match error_type {
            "UNIMPLEMENTED" => Err(Status::new(Code::Unimplemented, "Method not implemented")),
            "INVALID_ARGUMENT" => Err(Status::new(Code::InvalidArgument, "Invalid request parameter")),
            "PERMISSION_DENIED" => Err(Status::new(Code::PermissionDenied, "Access denied")),
            "NOT_FOUND" => Err(Status::new(Code::NotFound, "Resource not found")),
            "DEADLINE_EXCEEDED" => {
                // Simulate a long operation that times out
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                Err(Status::new(Code::DeadlineExceeded, "Operation timed out"))
            }
            "RESOURCE_EXHAUSTED" => Err(Status::new(Code::ResourceExhausted, "Resource limit exceeded")),
            "INTERNAL" => Err(Status::new(Code::Internal, "Internal server error")),
            "UNAVAILABLE" => Err(Status::new(Code::Unavailable, "Service temporarily unavailable")),
            _ => Err(Status::new(Code::Unknown, "Unknown error type requested")),
        }
    }
}

impl Default for ConformanceTestService {
    #[allow(dead_code)]
    fn default() -> Self {
        Self::new()
    }
}

/// Create and configure the conformance test service with all required methods
#[allow(dead_code)]
pub fn create_conformance_test_service() -> impl NamedService {
    ConformanceTestServiceWrapper::new()
}

/// Wrapper struct to implement the gRPC service traits
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct ConformanceTestServiceWrapper {
    inner: ConformanceTestService,
}

#[allow(dead_code)]

impl ConformanceTestServiceWrapper {
    #[allow(dead_code)]
    fn new() -> Self {
        Self {
            inner: ConformanceTestService::new(),
        }
    }
}

impl NamedService for ConformanceTestServiceWrapper {
    const NAME: &'static str = "conformance.TestService";

    #[allow(dead_code)]

    fn descriptor() -> ServiceDescriptor {
        ServiceDescriptor::new(Self::NAME)
            .with_method(UnaryMethod::new("UnaryCall"))
            .with_method(ServerStreamingMethod::new("ServerStreamingCall"))
            .with_method(ClientStreamingMethod::new("ClientStreamingCall"))
            .with_method(BidiStreamingMethod::new("BidirectionalStreamingCall"))
            .with_method(UnaryMethod::new("ErrorTestCall"))
    }
}

// TODO: Implement the actual service handler traits
// This would require implementing the specific service traits for each method type
// For now, this provides the structure and the core service logic

#[cfg(test)]
mod tests {
    use super::*;
    use asupersync::cx::Cx;

    #[tokio::test]
    async fn test_service_creation() {
        let service = ConformanceTestService::new();
        assert!(!service.server_id.is_empty());
        assert_eq!(service.request_counter.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn test_unary_call_basic() {
        let service = ConformanceTestService::new();
        let cx = Cx::root();

        let test_request = TestRequest {
            message: "Hello, world!".to_string(),
            echo_metadata: false,
            echo_deadline: false,
            check_auth_context: false,
            response_size: None,
            fill_server_id: false,
        };

        let request_bytes = serde_json::to_vec(&test_request).unwrap();
        let request = Request::new(Bytes::from(request_bytes));

        let result = service.unary_call(&cx, request).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        let response_data: TestResponse = serde_json::from_slice(response.get_ref()).unwrap();
        assert!(response_data.message.contains("Echo: Hello, world!"));
    }

    #[tokio::test]
    async fn test_error_handling() {
        let service = ConformanceTestService::new();
        let cx = Cx::root();

        let test_request = TestRequest {
            message: "UNIMPLEMENTED".to_string(),
            echo_metadata: false,
            echo_deadline: false,
            check_auth_context: false,
            response_size: None,
            fill_server_id: false,
        };

        let request_bytes = serde_json::to_vec(&test_request).unwrap();
        let request = Request::new(Bytes::from(request_bytes));

        let result = service.error_test_call(&cx, request).await;
        assert!(result.is_err());

        let status = result.unwrap_err();
        assert_eq!(status.code(), Code::Unimplemented);
    }
}