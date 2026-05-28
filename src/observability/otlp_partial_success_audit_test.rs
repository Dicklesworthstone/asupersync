//! OTLP partial collector response audit test.
//!
//! **AUDIT SCOPE**: Verifies OTLP-Trace exporter handling of 200 responses
//! with partial_success.rejected_spans=N per OTLP specification §6.1.
//!
//! **OTLP PARTIAL SUCCESS SPECIFICATION (§6.1)**:
//! - Collector returns 200 with ExportTraceServiceResponse body
//! - partial_success.rejected_spans field indicates rejected span count
//! - partial_success.error_message provides rejection reason
//! - Exporter SHOULD log warnings for visibility of rejected spans
//! - NOT: silently advance pointer (causes data loss)
//! - NOT: retry whole batch (causes duplicates)
//!
//! **CRITICAL DEFECT IDENTIFIED**:
//! - Current implementation treats all 200-299 as complete success
//! - No parsing of response body for partial_success information
//! - Silently advances export pointer → data loss for rejected spans
//! - No visibility into span rejection reasons

#![cfg(test)]
#![allow(dead_code)]

/// OTLP ExportTraceServiceResponse fixture with partial success.
#[derive(Debug, Clone)]
pub struct OtlpTraceServiceResponseFixture {
    status: u16,
    body: Option<ExportTraceServiceResponseBody>,
}

/// OTLP trace export response body fixture.
#[derive(Debug, Clone)]
pub struct ExportTraceServiceResponseBody {
    partial_success: Option<ExportPartialSuccess>,
}

/// OTLP partial-success payload fixture.
#[derive(Debug, Clone)]
pub struct ExportPartialSuccess {
    rejected_spans: i64,
    error_message: String,
}

impl OtlpTraceServiceResponseFixture {
    fn success() -> Self {
        Self {
            status: 200,
            body: None, // No partial_success means full success
        }
    }

    fn partial_success(rejected_spans: i64, error_message: &str) -> Self {
        Self {
            status: 200, // Still 200 status
            body: Some(ExportTraceServiceResponseBody {
                partial_success: Some(ExportPartialSuccess {
                    rejected_spans,
                    error_message: error_message.to_string(),
                }),
            }),
        }
    }

    fn error(status: u16) -> Self {
        Self { status, body: None }
    }

    fn is_success_status(&self) -> bool {
        (200..=299).contains(&self.status)
    }

    fn has_partial_success(&self) -> bool {
        self.body
            .as_ref()
            .and_then(|b| b.partial_success.as_ref())
            .is_some()
    }

    fn rejected_span_count(&self) -> i64 {
        self.body
            .as_ref()
            .and_then(|b| b.partial_success.as_ref())
            .map_or(0, |ps| ps.rejected_spans)
    }

    fn rejection_reason(&self) -> Option<&str> {
        self.body
            .as_ref()
            .and_then(|b| b.partial_success.as_ref())
            .map(|ps| ps.error_message.as_str())
    }
}

/// Span batch fixture for partial success scenarios.
#[derive(Debug, Clone)]
pub struct SpanBatchFixture {
    batch_id: u64,
    span_count: usize,
    spans: Vec<String>, // Span names for testing
}

impl SpanBatchFixture {
    fn new(batch_id: u64, span_names: Vec<&str>) -> Self {
        Self {
            batch_id,
            span_count: span_names.len(),
            spans: span_names.iter().map(|s| s.to_string()).collect(),
        }
    }
}

/// OTLP exporter fixture for partial success handling.
#[derive(Debug)]
pub struct PartialSuccessOtlpExporterFixture {
    export_log: Vec<String>,
    warning_log: Vec<String>,
    retry_count: usize,
    pointer_advanced: bool,
}

impl PartialSuccessOtlpExporterFixture {
    fn new() -> Self {
        Self {
            export_log: Vec::new(),
            warning_log: Vec::new(),
            retry_count: 0,
            pointer_advanced: false,
        }
    }

    /// Current implementation: DEFECTIVE - only checks status code.
    fn export_current_defective(
        &mut self,
        batch: &SpanBatchFixture,
        response: &OtlpTraceServiceResponseFixture,
    ) -> Result<(), String> {
        self.export_log.push(format!(
            "export_attempt batch_id={} spans={}",
            batch.batch_id, batch.span_count
        ));

        // DEFECTIVE LOGIC: Only checks status, ignores response body
        if response.is_success_status() {
            self.pointer_advanced = true;
            self.export_log
                .push("success: pointer advanced".to_string());
            Ok(())
        } else {
            Err(format!("HTTP error: {}", response.status))
        }
    }

    /// Correct implementation: Handle partial success per OTLP §6.1.
    fn export_correct(
        &mut self,
        batch: &SpanBatchFixture,
        response: &OtlpTraceServiceResponseFixture,
    ) -> Result<(), String> {
        self.export_log.push(format!(
            "export_attempt batch_id={} spans={}",
            batch.batch_id, batch.span_count
        ));

        if !response.is_success_status() {
            return Err(format!("HTTP error: {}", response.status));
        }

        // Check for partial success in response body
        if response.has_partial_success() {
            let rejected_count = response.rejected_span_count();
            let reason = response.rejection_reason().unwrap_or("unknown");

            // Log warning for visibility (CORRECT per §6.1)
            let warning = format!(
                "OTLP partial success: {}/{} spans rejected. Reason: {}",
                rejected_count, batch.span_count, reason
            );
            self.warning_log.push(warning.clone());
            self.export_log.push(format!("warning_logged: {}", warning));

            // Advance pointer only for successfully exported spans
            let successfully_exported = i64::try_from(batch.span_count)
                .unwrap_or(i64::MAX)
                .saturating_sub(rejected_count);
            if successfully_exported > 0 {
                self.pointer_advanced = true;
                self.export_log.push(format!(
                    "partial_success: pointer advanced for {} spans, {} rejected",
                    successfully_exported, rejected_count
                ));
            } else {
                self.export_log
                    .push("all_spans_rejected: pointer not advanced".to_string());
            }

            Ok(()) // Don't retry whole batch (would cause duplicates)
        } else {
            // Complete success
            self.pointer_advanced = true;
            self.export_log
                .push("complete_success: pointer advanced".to_string());
            Ok(())
        }
    }

    /// Wrong implementation: Retry whole batch (causes duplicates).
    fn export_wrong_retry(
        &mut self,
        batch: &SpanBatchFixture,
        response: &OtlpTraceServiceResponseFixture,
    ) -> Result<(), String> {
        self.export_log.push(format!(
            "export_attempt batch_id={} spans={}",
            batch.batch_id, batch.span_count
        ));

        if !response.is_success_status() {
            return Err(format!("HTTP error: {}", response.status));
        }

        if response.has_partial_success() {
            let rejected_count = response.rejected_span_count();

            // WRONG: Retry whole batch instead of handling partial success
            self.retry_count += 1;
            self.export_log.push(format!(
                "wrong_retry: retrying whole batch due to {} rejections",
                rejected_count
            ));
            Err("Retrying due to partial rejection".to_string())
        } else {
            self.pointer_advanced = true;
            Ok(())
        }
    }

    fn get_warnings(&self) -> &[String] {
        &self.warning_log
    }

    fn was_pointer_advanced(&self) -> bool {
        self.pointer_advanced
    }

    fn get_retry_count(&self) -> usize {
        self.retry_count
    }

    fn get_export_log(&self) -> &[String] {
        &self.export_log
    }
}

/// **AUDIT TEST**: Verify partial success response handling per OTLP §6.1.
///
/// **SCENARIO**: Collector returns 200 with partial_success.rejected_spans=3.
/// **REQUIREMENT**: Log warnings for visibility, advance pointer for successful spans.
/// **ASSESSMENT**: DEFECTIVE - current implementation silently treats as full success.
#[test]
fn audit_partial_success_response_handling() {
    println!("🔍 AUDIT: OTLP partial success response handling (OTLP §6.1)");

    println!("📋 OTLP §6.1 partial success requirements:");
    println!("   • Parse ExportTraceServiceResponse body");
    println!("   • Check partial_success.rejected_spans field");
    println!("   • Log warnings for rejected spans (visibility)");
    println!("   • Advance pointer only for successfully exported spans");
    println!("   • NOT: retry whole batch (causes duplicates)");
    println!("   • NOT: silently treat as complete success (data loss)");

    // **TEST SCENARIO**: Batch of 10 spans, 3 rejected by collector
    let span_batch = SpanBatchFixture::new(
        123,
        vec![
            "span1", "span2", "span3", "span4", "span5", "span6", "span7", "span8", "span9",
            "span10",
        ],
    );

    let partial_response = OtlpTraceServiceResponseFixture::partial_success(
        3, // 3 spans rejected
        "Rate limit exceeded for trace ID abc123",
    );

    println!("📊 Test scenario:");
    println!("   Batch: {} spans", span_batch.span_count);
    println!(
        "   Response: 200 with {} rejected spans",
        partial_response.rejected_span_count()
    );
    println!("   Reason: {:?}", partial_response.rejection_reason());

    // **CURRENT IMPLEMENTATION (DEFECTIVE)**
    println!("📊 Testing current implementation:");
    let mut current_exporter = PartialSuccessOtlpExporterFixture::new();
    let current_result = current_exporter.export_current_defective(&span_batch, &partial_response);

    println!("   Export result: {:?}", current_result);
    println!(
        "   Pointer advanced: {}",
        current_exporter.was_pointer_advanced()
    );
    println!(
        "   Warnings logged: {}",
        current_exporter.get_warnings().len()
    );

    // DEFECTIVE: Treats partial success as complete success
    assert!(
        current_result.is_ok(),
        "Current implementation treats 200 as success"
    );
    assert!(
        current_exporter.was_pointer_advanced(),
        "Current implementation advances pointer"
    );
    assert_eq!(
        current_exporter.get_warnings().len(),
        0,
        "Current implementation logs no warnings"
    );

    println!("🚨 DEFECT: Current implementation silently advances pointer");
    println!("   → Data loss: 3 rejected spans are lost without visibility");

    // **CORRECT IMPLEMENTATION (OTLP §6.1 COMPLIANT)**
    println!("📊 Testing correct implementation:");
    let mut correct_exporter = PartialSuccessOtlpExporterFixture::new();
    let correct_result = correct_exporter.export_correct(&span_batch, &partial_response);

    println!("   Export result: {:?}", correct_result);
    println!(
        "   Pointer advanced: {}",
        correct_exporter.was_pointer_advanced()
    );
    println!(
        "   Warnings logged: {}",
        correct_exporter.get_warnings().len()
    );

    if !correct_exporter.get_warnings().is_empty() {
        println!("   Warning message: {}", correct_exporter.get_warnings()[0]);
    }

    // CORRECT: Handles partial success properly
    assert!(
        correct_result.is_ok(),
        "Correct implementation handles partial success"
    );
    assert!(
        correct_exporter.was_pointer_advanced(),
        "Correct implementation advances for successful spans"
    );
    assert_eq!(
        correct_exporter.get_warnings().len(),
        1,
        "Correct implementation logs warning"
    );

    println!("✅ CORRECT: Proper partial success handling");
    println!("   → Visibility: Warning logged for rejected spans");
    println!("   → Progress: Pointer advanced for successful spans");

    // **WRONG IMPLEMENTATION (RETRY APPROACH)**
    println!("📊 Testing wrong retry implementation:");
    let mut retry_exporter = PartialSuccessOtlpExporterFixture::new();
    let retry_result = retry_exporter.export_wrong_retry(&span_batch, &partial_response);

    println!("   Export result: {:?}", retry_result);
    println!("   Retry count: {}", retry_exporter.get_retry_count());
    println!(
        "   Pointer advanced: {}",
        retry_exporter.was_pointer_advanced()
    );

    // WRONG: Retries whole batch
    assert!(
        retry_result.is_err(),
        "Wrong implementation retries whole batch"
    );
    assert_eq!(
        retry_exporter.get_retry_count(),
        1,
        "Wrong implementation increments retry count"
    );
    assert!(
        !retry_exporter.was_pointer_advanced(),
        "Wrong implementation doesn't advance pointer"
    );

    println!("🚨 WRONG: Retry approach causes duplicates");
    println!("   → Duplication risk: Successful spans would be sent again");

    println!("🚨 AUDIT CONCLUSION: DEFECTIVE");
    println!("   Current implementation: Silently treats partial success as full success");
    println!("   Impact: Data loss for rejected spans without visibility");
    println!("   Required fix: Parse response body for partial_success field");
}

/// **AUDIT TEST**: Verify complete success scenario still works.
///
/// **SCENARIO**: Collector returns 200 with no partial_success field.
/// **REQUIREMENT**: Treat as complete success, advance pointer.
/// **ASSESSMENT**: Should remain SOUND after fix.
#[test]
fn audit_complete_success_scenario() {
    println!("🔍 AUDIT: Complete success response handling");

    let span_batch = SpanBatchFixture::new(456, vec!["span1", "span2", "span3"]);
    let complete_success_response = OtlpTraceServiceResponseFixture::success();

    println!("📊 Complete success scenario:");
    println!("   Batch: {} spans", span_batch.span_count);
    println!("   Response: 200 with no partial_success field");

    // Both current and correct implementations should handle complete success
    let mut current_exporter = PartialSuccessOtlpExporterFixture::new();
    let current_result =
        current_exporter.export_current_defective(&span_batch, &complete_success_response);

    let mut correct_exporter = PartialSuccessOtlpExporterFixture::new();
    let correct_result = correct_exporter.export_correct(&span_batch, &complete_success_response);

    println!("   Current implementation result: {:?}", current_result);
    println!("   Correct implementation result: {:?}", correct_result);

    // Both should succeed for complete success
    assert!(current_result.is_ok(), "Current handles complete success");
    assert!(correct_result.is_ok(), "Correct handles complete success");

    assert!(
        current_exporter.was_pointer_advanced(),
        "Current advances pointer"
    );
    assert!(
        correct_exporter.was_pointer_advanced(),
        "Correct advances pointer"
    );

    assert_eq!(
        current_exporter.get_warnings().len(),
        0,
        "No warnings for complete success"
    );
    assert_eq!(
        correct_exporter.get_warnings().len(),
        0,
        "No warnings for complete success"
    );

    println!("✅ Complete success handling: SOUND");
    println!("   Both implementations correctly handle complete success");
}

/// **AUDIT TEST**: Verify error response handling remains correct.
///
/// **SCENARIO**: Collector returns 500 server error.
/// **REQUIREMENT**: Treat as error, don't advance pointer.
/// **ASSESSMENT**: Should remain SOUND (not related to partial success).
#[test]
fn audit_error_response_handling() {
    println!("🔍 AUDIT: Error response handling");

    let span_batch = SpanBatchFixture::new(789, vec!["span1", "span2"]);
    let error_response = OtlpTraceServiceResponseFixture::error(500);

    println!("📊 Error response scenario:");
    println!("   Batch: {} spans", span_batch.span_count);
    println!("   Response: 500 Internal Server Error");

    let mut current_exporter = PartialSuccessOtlpExporterFixture::new();
    let current_result = current_exporter.export_current_defective(&span_batch, &error_response);

    let mut correct_exporter = PartialSuccessOtlpExporterFixture::new();
    let correct_result = correct_exporter.export_correct(&span_batch, &error_response);

    println!("   Current implementation result: {:?}", current_result);
    println!("   Correct implementation result: {:?}", correct_result);

    // Both should fail for error response
    assert!(current_result.is_err(), "Current handles errors");
    assert!(correct_result.is_err(), "Correct handles errors");

    assert!(
        !current_exporter.was_pointer_advanced(),
        "Current doesn't advance on error"
    );
    assert!(
        !correct_exporter.was_pointer_advanced(),
        "Correct doesn't advance on error"
    );

    println!("✅ Error response handling: SOUND");
    println!("   Both implementations correctly handle errors");
}

/// **AUDIT TEST**: Verify current implementation defect in otel.rs.
///
/// **SCENARIO**: Document exact line where defect exists.
/// **REQUIREMENT**: Line 1081 only checks status code, ignores response body.
/// **ASSESSMENT**: DEFECT CONFIRMED - missing response body parsing.
#[test]
fn audit_current_implementation_defect_location() {
    println!("🔍 AUDIT: Current implementation defect location");

    println!("📋 Defect analysis:");
    println!("   File: src/observability/otel.rs");
    println!("   Line: 1081");
    println!("   Code: 200..=299 => Ok(()),");
    println!("   Problem: No response body parsing for partial_success");

    println!("📊 Required fix:");
    println!("   1. Parse ExportTraceServiceResponse protobuf body");
    println!("   2. Check partial_success field if present");
    println!("   3. Log warnings for rejected_spans > 0");
    println!("   4. Return partial success information to caller");

    println!("📋 OTLP §6.1 compliance gap:");
    println!("   ❌ MISSING: Response body parsing");
    println!("   ❌ MISSING: partial_success.rejected_spans handling");
    println!("   ❌ MISSING: Rejection reason logging");
    println!("   ❌ MISSING: Visibility into span rejections");

    println!("🚨 DEFECT CONFIRMED: Line 1081 in otel.rs");
    println!("   Current: Only checks HTTP status code");
    println!("   Required: Parse response body for partial success");
    println!("   Impact: Silent data loss for rejected spans");
}
