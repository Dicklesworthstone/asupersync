//! Shared SDK admission, acknowledgement and lifecycle for native transports.

use crate::cx::Cx;
use crate::observability::otel::{
    ExportError, OtlpQueueReceipt, OtlpSignal, QueuedOtlpGrpcExporter, QueuedOtlpHttpExporter,
};
use opentelemetry_sdk::error::{OTelSdkError, OTelSdkResult};
use std::time::Duration;

/// Private transport seam. Mapping remains signal-specific and transport-neutral.
pub(super) trait SdkQueue: Sync {
    fn ensure_ready(&self) -> Result<(), ExportError>;
    fn admit(
        &self,
        signal: OtlpSignal,
        requests: Vec<Vec<u8>>,
    ) -> Result<OtlpQueueReceipt, ExportError>;
    fn flush(&self, timeout: Duration) -> Result<(), ExportError>;
    fn shutdown(&self, timeout: Duration) -> Result<(), ExportError>;
}

impl SdkQueue for QueuedOtlpGrpcExporter {
    fn ensure_ready(&self) -> Result<(), ExportError> {
        self.ensure_managed_active()
    }

    fn admit(
        &self,
        signal: OtlpSignal,
        requests: Vec<Vec<u8>>,
    ) -> Result<OtlpQueueReceipt, ExportError> {
        self.enqueue_encoded_with_receipt(signal, requests)
    }

    fn flush(&self, timeout: Duration) -> Result<(), ExportError> {
        self.force_flush_blocking(timeout)
    }

    fn shutdown(&self, timeout: Duration) -> Result<(), ExportError> {
        self.shutdown_blocking(timeout)
    }
}

impl SdkQueue for QueuedOtlpHttpExporter {
    fn ensure_ready(&self) -> Result<(), ExportError> {
        self.ensure_managed_active()
    }

    fn admit(
        &self,
        signal: OtlpSignal,
        requests: Vec<Vec<u8>>,
    ) -> Result<OtlpQueueReceipt, ExportError> {
        self.enqueue_encoded_with_receipt(signal, requests)
    }

    fn flush(&self, timeout: Duration) -> Result<(), ExportError> {
        self.force_flush_blocking(timeout)
    }

    fn shutdown(&self, timeout: Duration) -> Result<(), ExportError> {
        self.shutdown_blocking(timeout)
    }
}

struct Codes {
    native_context: Option<&'static str>,
    owner_unavailable: &'static str,
    admission_refused: &'static str,
    flush_incomplete: &'static str,
    shutdown_incomplete: &'static str,
}

fn codes(signal: OtlpSignal) -> Codes {
    match signal {
        OtlpSignal::Metrics => Codes {
            native_context: None,
            owner_unavailable: "otlp.sdk.metrics.owner_unavailable",
            admission_refused: "otlp.sdk.metrics.admission_refused",
            flush_incomplete: "otlp.sdk.metrics.flush_incomplete",
            shutdown_incomplete: "otlp.sdk.metrics.shutdown_incomplete",
        },
        OtlpSignal::Traces => Codes {
            native_context: Some("otlp.sdk.traces.native_context"),
            owner_unavailable: "otlp.sdk.traces.owner_unavailable",
            admission_refused: "otlp.sdk.traces.admission_refused",
            flush_incomplete: "otlp.sdk.traces.flush_incomplete",
            shutdown_incomplete: "otlp.sdk.traces.shutdown_incomplete",
        },
        OtlpSignal::Logs => Codes {
            native_context: Some("otlp.sdk.logs.native_context"),
            owner_unavailable: "otlp.sdk.logs.owner_unavailable",
            admission_refused: "otlp.sdk.logs.admission_refused",
            flush_incomplete: "otlp.sdk.logs.flush_incomplete",
            shutdown_incomplete: "otlp.sdk.logs.shutdown_incomplete",
        },
    }
}

fn sdk_error(code: &'static str) -> OTelSdkError {
    OTelSdkError::InternalFailure(code.to_owned())
}

/// Guard before mapping, atomically admit the whole collection, then await
/// terminal collector responses. A consumed mapping closure drops its owned
/// source captures before any transport wait; only admitted bytes remain.
pub(super) async fn export(
    queue: &impl SdkQueue,
    signal: OtlpSignal,
    map: impl FnOnce() -> Result<Vec<Vec<u8>>, &'static str> + Send,
) -> OTelSdkResult {
    let codes = codes(signal);
    if let Some(code) = codes.native_context {
        if Cx::current().is_some() {
            return Err(sdk_error(code));
        }
    }
    queue
        .ensure_ready()
        .map_err(|_| sdk_error(codes.owner_unavailable))?;
    let requests = map().map_err(sdk_error)?;
    queue
        .admit(signal, requests)
        .map_err(|_| sdk_error(codes.admission_refused))?
        .await
        .map(|_| ())
        .map_err(|error| sdk_error(error.code()))
}

pub(super) fn force_flush(
    queue: &impl SdkQueue,
    signal: OtlpSignal,
    timeout: Duration,
) -> OTelSdkResult {
    queue
        .flush(timeout)
        .map_err(|_| sdk_error(codes(signal).flush_incomplete))
}

pub(super) fn shutdown(
    queue: &impl SdkQueue,
    signal: OtlpSignal,
    timeout: Duration,
) -> OTelSdkResult {
    queue
        .shutdown(timeout)
        .map_err(|_| sdk_error(codes(signal).shutdown_incomplete))
}
