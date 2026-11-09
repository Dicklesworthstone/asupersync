//! Policy-aware owned collection over the existing native transport.

use super::{
    Cx, OtlpGrpcError, OtlpGrpcExportReport, OtlpGrpcExporter, OtlpGrpcSignal,
    OtlpLogKeyValueInput, OtlpLogRecordInput, OtlpTraceSpanInput, OwnedOtlpLogs, OwnedOtlpMetrics,
    OwnedOtlpPolicyReport, OwnedOtlpTraces, checkpoint,
};
use crate::observability::otel::{OwnedOtlpExportPolicy, OwnedOtlpPolicyOutput};

impl OtlpGrpcExporter {
    /// Collect owned metrics with explicit scope, resource, and privacy policy,
    /// then send the complete validated collection through the native channel.
    ///
    /// Policy resource attributes override equally named transport attributes.
    /// Local filtering finishes before any network operation. A collision
    /// between metric series after filtering refuses the whole collection.
    /// Existing mapper limits, channel limits, timestamps, and one-call delivery
    /// defaults remain in effect. The returned policy report counts local
    /// filtering separately from the collector's per-request receipts.
    pub async fn send_owned_metrics_with_policy(
        &self,
        cx: &Cx,
        metrics: &OwnedOtlpMetrics,
        point_time_unix_nano: u64,
        policy: &OwnedOtlpExportPolicy,
    ) -> Result<OwnedOtlpPolicyOutput<OtlpGrpcExportReport>, OtlpGrpcError> {
        checkpoint(cx)?;
        let attributes: Vec<_> = self.resource_attributes().collect();
        let (requests, report) = metrics
            .collect_with_policy(point_time_unix_nano, &attributes, policy)
            .map_err(|error| OtlpGrpcError::mapping(error.code()))?
            .into_parts();
        self.send_policy_requests(cx, OtlpGrpcSignal::Metrics, requests, report)
            .await
    }

    /// Apply shared resource/scope/privacy policy to owned trace spans before
    /// transmission. Sampling, identifiers, timestamps and lineage remain the
    /// mapper's responsibility. An entirely unsampled collection performs no I/O.
    ///
    /// Every successful response, including partial rejection, is terminal.
    /// A later failure retains earlier receipts and completed local filtering
    /// in [`OtlpGrpcError`]; it does not authorize replaying the collection.
    pub async fn send_owned_traces_with_policy(
        &self,
        cx: &Cx,
        traces: &OwnedOtlpTraces,
        spans: &[OtlpTraceSpanInput<'_>],
        policy: &OwnedOtlpExportPolicy,
    ) -> Result<OwnedOtlpPolicyOutput<OtlpGrpcExportReport>, OtlpGrpcError> {
        checkpoint(cx)?;
        let attributes: Vec<_> = self.resource_attributes().collect();
        let (collection, report) = traces
            .collect_with_policy(spans, &attributes, policy)
            .map_err(|error| OtlpGrpcError::mapping(error.code()))?
            .into_parts();
        self.send_policy_requests(
            cx,
            OtlpGrpcSignal::Traces,
            collection.into_requests(),
            report,
        )
        .await
    }

    /// Apply shared resource/scope/privacy policy to structured owned logs and
    /// send the complete validated collection. Original record order, typed
    /// values and producer timestamps are preserved by the mapper.
    ///
    /// Filtering and the smaller channel request limit are checked for every
    /// batch before the first send. Empty input performs no I/O. Policy counts
    /// describe local filtering; collector rejections remain separate receipts.
    pub async fn send_owned_logs_with_policy(
        &self,
        cx: &Cx,
        logs: &OwnedOtlpLogs,
        records: &[OtlpLogRecordInput<'_>],
        policy: &OwnedOtlpExportPolicy,
    ) -> Result<OwnedOtlpPolicyOutput<OtlpGrpcExportReport>, OtlpGrpcError> {
        checkpoint(cx)?;
        let attributes: Vec<_> = self
            .resource_attributes()
            .map(|(key, value)| OtlpLogKeyValueInput::string(key, value))
            .collect();
        let (collection, report) = logs
            .collect_with_policy(records, &attributes, policy)
            .map_err(|error| OtlpGrpcError::mapping(error.code()))?
            .into_parts();
        self.send_policy_requests(cx, OtlpGrpcSignal::Logs, collection.into_requests(), report)
            .await
    }

    async fn send_policy_requests(
        &self,
        cx: &Cx,
        signal: OtlpGrpcSignal,
        requests: Vec<Vec<u8>>,
        policy_report: OwnedOtlpPolicyReport,
    ) -> Result<OwnedOtlpPolicyOutput<OtlpGrpcExportReport>, OtlpGrpcError> {
        match self.send_collection(cx, signal, requests).await {
            Ok(receipts) => Ok(OwnedOtlpPolicyOutput::new(receipts, policy_report)),
            Err(mut error) => {
                error.policy_report = Some(policy_report);
                Err(error)
            }
        }
    }
}
