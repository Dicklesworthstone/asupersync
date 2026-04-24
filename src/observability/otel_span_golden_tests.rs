//! Golden artifact tests for OpenTelemetry span serialization.
//!
//! Comprehensive golden artifact testing for OTEL span serialization formats.
//! Uses the existing span infrastructure with insta snapshots.

use crate::observability::otel::span_semantics::*;
use opentelemetry::trace::{SpanKind, Status};
use std::collections::HashMap;
use serde_json::json;

// Use the existing test_span_snapshot function from the parent module
use super::test_span_snapshot;

/// Comprehensive golden artifact tests for OpenTelemetry span serialization.
/// Tests ensure span serialization remains stable and catches format regressions.
#[cfg(test)]
mod tests {
    #![allow(clippy::pedantic, clippy::nursery, clippy::expect_fun_call, clippy::map_unwrap_or, clippy::cast_possible_wrap, clippy::future_not_send)]
    use super::*;

    #[test]
    fn span_golden_basic_server_span() {
        let config = SpanConformanceConfig::default();
        let mut span = TestSpan::new_with_config("http.request", SpanKind::Server, &config);
        span.set_attribute("service.name", "checkout");
        span.set_attribute("http.method", "POST");
        span.set_attribute("http.url", "https://api.example.com/v1/orders");
        span.set_status(Status::Ok);
        span.end();

        insta::with_settings!({
            snapshot_path => "../../tests/golden/otel",
        }, {
            insta::assert_json_snapshot!("basic_server_span", test_span_snapshot(&span));
        });
    }

    #[test]
    fn span_golden_client_with_events() {
        let config = SpanConformanceConfig::default();
        let mut span = TestSpan::new_with_config("db.query", SpanKind::Client, &config);
        span.set_attribute("db.system", "postgresql");
        span.set_attribute("db.operation", "select");
        span.add_event("query.start", HashMap::from([
            ("query_id".to_string(), "q-12345".to_string()),
        ]));
        span.add_event("query.result", HashMap::from([
            ("rows_affected".to_string(), "150".to_string()),
        ]));
        span.set_status(Status::Ok);
        span.end();

        insta::with_settings!({
            snapshot_path => "../../tests/golden/otel",
        }, {
            insta::assert_json_snapshot!("client_with_events", test_span_snapshot(&span));
        });
    }

    #[test]
    fn span_golden_error_status() {
        let config = SpanConformanceConfig::default();
        let mut span = TestSpan::new_with_config("payment.process", SpanKind::Internal, &config);
        span.set_attribute("payment.provider", "stripe");
        span.add_event("payment.decline", HashMap::from([
            ("decline_code".to_string(), "insufficient_funds".to_string()),
        ]));
        span.set_status(Status::Error {
            description: "Payment declined by processor".into()
        });
        span.end();

        insta::with_settings!({
            snapshot_path => "../../tests/golden/otel",
        }, {
            insta::assert_json_snapshot!("error_status_span", test_span_snapshot(&span));
        });
    }

    #[test]
    fn span_golden_hierarchy() {
        let config = SpanConformanceConfig::default();

        let mut parent = TestSpan::new_with_config("order.process", SpanKind::Server, &config);
        parent.set_attribute("service.name", "order-service");
        parent.set_baggage_item("tenant", "acme-corp");

        let mut child = parent.new_child("inventory.check", SpanKind::Client);
        child.set_attribute("inventory.item", "widget-123");
        child.set_status(Status::Ok);
        child.end();

        parent.set_status(Status::Ok);
        parent.end();

        insta::with_settings!({
            snapshot_path => "../../tests/golden/otel",
        }, {
            insta::assert_json_snapshot!("span_hierarchy", json!({
                "parent": test_span_snapshot(&parent),
                "child": test_span_snapshot(&child),
            }));
        });
    }

    #[test]
    fn span_golden_attribute_limits() {
        let config = SpanConformanceConfig {
            max_attributes: 2,
            max_events: 1,
            max_attribute_length: Some(10),
            test_sampling: false,
            test_context_propagation: false,
        };

        let mut span = TestSpan::new_with_config("limited.span", SpanKind::Internal, &config);
        span.set_attribute("attr1", "value1");
        span.set_attribute("attr2", "value2");
        span.set_attribute("attr3", "value3"); // Should be dropped
        span.set_attribute("long_attr", "this_is_very_long_and_should_be_truncated");

        span.add_event("event1", HashMap::new());
        span.add_event("event2", HashMap::new()); // Should be dropped

        span.end();

        insta::with_settings!({
            snapshot_path => "../../tests/golden/otel",
        }, {
            insta::assert_json_snapshot!("attribute_limits", test_span_snapshot(&span));
        });
    }

    #[test]
    fn span_golden_baggage_propagation() {
        let config = SpanConformanceConfig::default();

        // Simulate remote parent context
        let remote_baggage = HashMap::from([
            ("tenant".to_string(), "acme-corp".to_string()),
            ("correlation.id".to_string(), "corr-789".to_string()),
        ]);

        let parent_context = opentelemetry::trace::SpanContext::new(
            opentelemetry::trace::TraceId::from_u128(0x1234567890abcdef),
            opentelemetry::trace::SpanId::from_u64(0x9876543210fedcba),
            opentelemetry::trace::TraceFlags::SAMPLED,
            true, // is_remote
            opentelemetry::trace::TraceState::default(),
        );

        let mut child = TestSpan::child_from_remote_parent(
            parent_context,
            remote_baggage,
            "downstream.service",
            SpanKind::Server,
            &config,
        );

        child.set_attribute("service.name", "downstream");
        child.set_baggage_item("downstream.region", "us-west-2");
        child.set_status(Status::Ok);
        child.end();

        insta::with_settings!({
            snapshot_path => "../../tests/golden/otel",
        }, {
            insta::assert_json_snapshot!("baggage_propagation", test_span_snapshot(&child));
        });
    }

    #[test]
    fn span_golden_unended_span() {
        let config = SpanConformanceConfig::default();
        let mut span = TestSpan::new_with_config("long.running", SpanKind::Consumer, &config);
        span.set_attribute("consumer.group", "analytics");
        span.add_event("message.received", HashMap::from([
            ("message.size_bytes".to_string(), "1024".to_string()),
        ]));
        // Don't end the span - test serialization of active spans

        insta::with_settings!({
            snapshot_path => "../../tests/golden/otel",
        }, {
            insta::assert_json_snapshot!("unended_span", test_span_snapshot(&span));
        });
    }

    #[test]
    fn span_golden_empty_minimal_span() {
        let config = SpanConformanceConfig::default();
        let mut span = TestSpan::new_with_config("minimal", SpanKind::Internal, &config);
        span.end();

        insta::with_settings!({
            snapshot_path => "../../tests/golden/otel",
        }, {
            insta::assert_json_snapshot!("empty_minimal_span", test_span_snapshot(&span));
        });
    }
}