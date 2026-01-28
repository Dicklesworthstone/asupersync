//! Report generation for conformance test results.

use crate::runner::SuiteResult;
use serde::Serialize;
use std::fs;
use std::io;
use std::path::Path;

/// Render a console-friendly summary string.
pub fn render_console_summary(summary: &SuiteResult) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "Conformance summary for {}\n",
        summary.runtime_name
    ));
    out.push_str(&format!(
        "Total: {}  Passed: {}  Failed: {}  Duration: {}ms\n",
        summary.total, summary.passed, summary.failed, summary.duration_ms
    ));

    for result in &summary.results {
        let status = if result.result.passed { "OK" } else { "FAILED" };
        let duration = result
            .result
            .duration_ms
            .map(|ms| format!("{ms}ms"))
            .unwrap_or_else(|| "n/a".to_string());
        out.push_str(&format!(
            "- {} ({}) [{}] {}\n",
            result.test_id, result.test_name, status, duration
        ));
    }

    out
}

/// Write a JSON report for any serializable summary.
pub fn write_json_report<T: Serialize>(summary: &T, path: &Path) -> io::Result<()> {
    let data = serde_json::to_vec_pretty(summary)
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
    fs::write(path, data)
}
