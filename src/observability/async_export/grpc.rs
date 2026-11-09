//! Native OTLP/gRPC integration for the existing snapshot exporter interface.

use super::{
    AsyncMetricsExporter, ExportError, MetricsExportBatch, MetricsExportFuture, checkpoint,
    encode_snapshot,
};
use crate::cx::Cx;
use crate::observability::otel::{OtlpGrpcExporter, OtlpGrpcResponse, OtlpGrpcSignal};

/// Export existing cumulative metric snapshots over native OTLP/gRPC.
///
/// This adapter uses the same bounded, deterministic snapshot encoder as
/// [`super::OtlpSnapshotExporter`]. Counter, gauge, histogram, resource, and
/// explicit Unix timestamp semantics are unchanged. The complete snapshot is
/// validated before any network write, and an empty snapshot makes no request.
///
/// The supplied transport retains its caller-owned channel, TLS policy,
/// admission limits, connection reuse, metadata, and deadline bounds. Each
/// export invokes one logical unary call, with no exporter-level retry loop.
/// The channel retains its existing recovery of calls proven unprocessed on
/// reused connections. This adapter never starts a runtime or exporter task.
/// A cancelled or failed operation may already have reached the collector.
///
/// The [`AsyncMetricsExporter`] interface cannot retain collector diagnostics.
/// Its result reports positive partial rejection as an error; a zero-rejected
/// warning is successful and must not trigger a retry. Use
/// [`Self::export_with_response`] to inspect the complete collector receipt.
///
/// ```no_run
/// use asupersync::Cx;
/// use asupersync::observability::async_export::{
///     AsyncMultiExporter, MetricsExportBatch, OtlpGrpcSnapshotExporter,
/// };
/// use asupersync::observability::otel::{
///     ExportError, InMemoryExporter, MetricsSnapshot, OtlpGrpcExporter,
/// };
/// use std::sync::Arc;
///
/// async fn publish(
///     cx: &Cx,
///     transport: OtlpGrpcExporter,
///     snapshot: &MetricsSnapshot,
///     epoch_unix_nano: u64,
///     collection_unix_nano: u64,
/// ) -> Result<(), ExportError> {
///     let memory = Arc::new(InMemoryExporter::new());
///     let exporters = AsyncMultiExporter::try_new(vec![
///         Box::new(memory),
///         Box::new(OtlpGrpcSnapshotExporter::new(transport)),
///     ])?;
///     let batch = MetricsExportBatch::new(snapshot, epoch_unix_nano, collection_unix_nano)?;
///     exporters.export_all(cx, batch).await.into_result()
/// }
/// ```
pub struct OtlpGrpcSnapshotExporter {
    grpc: OtlpGrpcExporter,
    resource_attributes: Vec<(String, String)>,
}

impl std::fmt::Debug for OtlpGrpcSnapshotExporter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OtlpGrpcSnapshotExporter")
            .field("resource_attribute_count", &self.resource_attributes.len())
            .finish_non_exhaustive()
    }
}

impl OtlpGrpcSnapshotExporter {
    /// Adapt an already-validated transport without reading environment
    /// variables, changing its authority, or creating a runtime.
    #[must_use]
    pub fn new(grpc: OtlpGrpcExporter) -> Self {
        let resource_attributes = grpc
            .resource_attributes()
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .collect();
        Self {
            grpc,
            resource_attributes,
        }
    }

    /// Validate and send one snapshot, retaining the collector's response.
    ///
    /// `None` means an empty snapshot required no network request. `Some`
    /// includes full success, partial rejection, and collector warnings. A
    /// partial-success response must never cause the batch to be retried.
    /// Collector diagnostic text is available through the receipt's explicit
    /// accessor; it is not copied into this adapter's errors or debug output.
    pub async fn export_with_response(
        &self,
        cx: &Cx,
        batch: MetricsExportBatch<'_>,
    ) -> Result<Option<OtlpGrpcResponse>, ExportError> {
        checkpoint(cx)?;
        let Some(bytes) = encode_snapshot(batch, &self.resource_attributes)? else {
            return Ok(None);
        };
        checkpoint(cx)?;
        self.grpc
            .send_once(cx, OtlpGrpcSignal::Metrics, bytes)
            .await
            .map(Some)
            .map_err(|error| ExportError::new(error.to_string()))
    }

    /// Export through the existing metrics result contract.
    ///
    /// Positive partial rejection is an error, without replaying accepted
    /// points or exposing the collector's diagnostic. A zero-rejected warning
    /// remains successful. Call [`Self::export_with_response`] when an
    /// inspectable partial-success receipt is needed.
    pub async fn export(&self, cx: &Cx, batch: MetricsExportBatch<'_>) -> Result<(), ExportError> {
        if let Some(response) = self.export_with_response(cx, batch).await?
            && response.rejected_items() != 0
        {
            return Err(ExportError::new(format!(
                "otlp.grpc.snapshot.partial_success: collector rejected {} telemetry items; do not retry this batch",
                response.rejected_items()
            )));
        }
        Ok(())
    }
}

impl AsyncMetricsExporter for OtlpGrpcSnapshotExporter {
    fn export<'a>(&'a self, cx: &'a Cx, batch: MetricsExportBatch<'a>) -> MetricsExportFuture<'a> {
        Box::pin(Self::export(self, cx, batch))
    }
}

#[cfg(test)]
#[path = "grpc_tests.rs"]
mod tests;
