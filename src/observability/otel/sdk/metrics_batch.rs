//! Pack independently bounded scope groups without multiplying native RPCs.

use super::{
    ExportMetricsServiceRequest, MAX_REQUESTS, MAX_SCOPES, Metric, OtlpSdkMetricsConfig,
    OtlpSdkMetricsError, ProtoMessage, Resource, ResourceMetrics, ScopeMetrics, attribute_nodes,
    compare_metric, compare_scope,
};
use std::cmp::Ordering;

const MAX_VALUE_NODES: usize = 4096;
const MAX_REPEATED_ITEMS: usize = 65_536;

pub(super) struct MetricsRequests<'a> {
    resource: &'a Resource,
    resource_schema: &'a str,
    config: &'a OtlpSdkMetricsConfig,
    base_bytes: usize,
    base_nodes: usize,
    base_items: usize,
    scopes: Vec<ScopeMetrics>,
    bytes: usize,
    nodes: usize,
    items: usize,
    requests: Vec<Vec<u8>>,
    encoded_bytes: usize,
}

impl<'a> MetricsRequests<'a> {
    pub(super) fn new(
        resource: &'a Resource,
        resource_schema: &'a str,
        config: &'a OtlpSdkMetricsConfig,
        resource_bytes: usize,
    ) -> Self {
        // Each bounded nested field needs at most six tag/length bytes. This
        // covers the outer request, resource, and resource schema envelopes.
        let base_bytes = resource_bytes
            .saturating_add(resource_schema.len())
            .saturating_add(32);
        let base_nodes = attribute_nodes(&resource.attributes);
        // Two repeated items per value node conservatively cover both the
        // attribute entry and any array element; add the resource group itself.
        let base_items = base_nodes.saturating_mul(2).saturating_add(1);
        Self {
            resource,
            resource_schema,
            config,
            base_bytes,
            base_nodes,
            base_items,
            scopes: Vec::new(),
            bytes: base_bytes,
            nodes: base_nodes,
            items: base_items,
            requests: Vec::new(),
            encoded_bytes: 0,
        }
    }

    /// The caller includes the scope header and metric field envelopes in the
    /// supplied footprint. Metric descriptors are already sorted and unique.
    pub(super) fn push(
        &mut self,
        scope: &ScopeMetrics,
        metrics: Vec<Metric>,
        bytes: usize,
        nodes: usize,
        items: usize,
    ) -> Result<(), OtlpSdkMetricsError> {
        if metrics.is_empty() {
            return Ok(());
        }
        if self.base_bytes.saturating_add(bytes) > self.config.max_request_bytes
            || self.base_nodes.saturating_add(nodes) > MAX_VALUE_NODES
            || self.base_items.saturating_add(items) > MAX_REPEATED_ITEMS
        {
            return Err(OtlpSdkMetricsError::WireEnvelopeExceeded);
        }
        // A large metric can produce several groups with the same scope.
        // Keep its descriptor in only one group per request, including scopes
        // whose original identities became equal under explicit caller policy.
        let repeated_descriptor = self.scopes.iter().any(|prior| {
            compare_scope(prior, scope).is_eq() && descriptors_overlap(&prior.metrics, &metrics)
        });
        if !self.scopes.is_empty()
            && (self.scopes.len() == MAX_SCOPES
                || self.bytes.saturating_add(bytes) > self.config.max_request_bytes
                || self.nodes.saturating_add(nodes) > MAX_VALUE_NODES
                || self.items.saturating_add(items) > MAX_REPEATED_ITEMS
                || repeated_descriptor)
        {
            self.flush()?;
        }
        self.bytes = self.bytes.saturating_add(bytes);
        self.nodes = self.nodes.saturating_add(nodes);
        self.items = self.items.saturating_add(items);
        self.scopes.push(ScopeMetrics {
            scope: scope.scope.clone(),
            schema_url: scope.schema_url.clone(),
            metrics,
            ..ScopeMetrics::default()
        });
        Ok(())
    }

    fn flush(&mut self) -> Result<(), OtlpSdkMetricsError> {
        if self.scopes.is_empty() {
            return Ok(());
        }
        if self.requests.len() == MAX_REQUESTS {
            return Err(OtlpSdkMetricsError::LimitExceeded);
        }
        let request = ExportMetricsServiceRequest {
            resource_metrics: vec![ResourceMetrics {
                resource: Some(self.resource.clone()),
                schema_url: self.resource_schema.to_owned(),
                scope_metrics: std::mem::take(&mut self.scopes),
                ..ResourceMetrics::default()
            }],
            ..ExportMetricsServiceRequest::default()
        };
        // Recheck the entire owned schema and actual encoded size. A failure
        // here still precedes atomic queue admission of the whole collection.
        let encoded = request
            .encode_to_bytes(crate::observability::otel::otlp_request_limits(
                self.config.max_request_bytes,
            ))
            .map_err(|_| OtlpSdkMetricsError::WireEnvelopeExceeded)?;
        self.encoded_bytes = self
            .encoded_bytes
            .checked_add(encoded.len())
            .filter(|bytes| *bytes <= self.config.max_collection_bytes)
            .ok_or(OtlpSdkMetricsError::LimitExceeded)?;
        self.requests.push(encoded.to_vec());
        self.bytes = self.base_bytes;
        self.nodes = self.base_nodes;
        self.items = self.base_items;
        Ok(())
    }

    pub(super) fn finish(mut self) -> Result<Vec<Vec<u8>>, OtlpSdkMetricsError> {
        self.flush()?;
        Ok(self.requests)
    }
}

fn descriptors_overlap(left: &[Metric], right: &[Metric]) -> bool {
    // Both inputs follow the mapper's sorted descriptor order. A merge walk
    // needs no allocation and avoids a quadratic comparison of large scopes.
    let mut left = left.iter().peekable();
    let mut right = right.iter().peekable();
    while let (Some(a), Some(b)) = (left.peek(), right.peek()) {
        match compare_metric(a, b) {
            Ordering::Less => {
                left.next();
            }
            Ordering::Greater => {
                right.next();
            }
            Ordering::Equal => return true,
        }
    }
    false
}
