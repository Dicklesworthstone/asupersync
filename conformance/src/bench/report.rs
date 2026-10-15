//! Report generation for benchmark results.

use crate::bench::runner::{BenchComparisonSummary, BenchRunSummary};
use serde::Serialize;
use std::fs;
use std::io;
use std::path::Path;
use std::time::Duration;

/// Render a console-friendly summary string.
pub fn render_console_summary(summary: &BenchRunSummary) -> String {
    let mut out = String::new();
    out.push_str(&format!("Benchmark summary for {}\n", summary.runtime_name));
    out.push_str(&format!(
        "Total: {}  Completed: {}  Failed: {}  Duration: {}ms\n",
        summary.total, summary.completed, summary.failed, summary.duration_ms
    ));

    for result in &summary.results {
        if let Some(stats) = &result.stats {
            let alloc = format_alloc_summary(result.alloc_stats.as_ref());
            out.push_str(&format!(
                "- {}: mean={} p50={} p95={} p99={} samples={}{}\n",
                result.benchmark_id,
                format_duration(stats.mean),
                format_duration(stats.p50),
                format_duration(stats.p95),
                format_duration(stats.p99),
                stats.sample_count,
                alloc
            ));
        } else if let Some(error) = &result.error {
            out.push_str(&format!("- {}: ERROR: {}\n", result.benchmark_id, error));
        }
    }

    out
}

/// Write a JSON report for any serializable summary.
pub fn write_json_report<T: Serialize>(summary: &T, path: &Path) -> io::Result<()> {
    let data =
        serde_json::to_vec_pretty(summary).map_err(|err| io::Error::other(err.to_string()))?;
    fs::write(path, data)
}

/// Write an HTML report for a single-runtime benchmark run.
pub fn write_html_report(summary: &BenchRunSummary, path: &Path) -> io::Result<()> {
    let mut html = String::new();

    html.push_str("<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\">\n");
    html.push_str("<title>Asupersync Benchmark Report</title>\n");
    html.push_str("<style>");
    html.push_str("body{font-family:Arial,sans-serif;margin:40px;}");
    html.push_str("table{border-collapse:collapse;width:100%;}");
    html.push_str("th,td{border:1px solid #ddd;padding:8px;text-align:left;}");
    html.push_str("th{background-color:#4CAF50;color:white;}");
    html.push_str("tr:nth-child(even){background-color:#f2f2f2;}");
    html.push_str(".error{color:#b00020;font-weight:bold;}");
    html.push_str("</style></head><body>\n");

    html.push_str(&format!(
        "<h1>Benchmark Report: {}</h1>",
        summary.runtime_name
    ));
    html.push_str(&format!(
        "<p>Total: {} | Completed: {} | Failed: {} | Duration: {}ms</p>",
        summary.total, summary.completed, summary.failed, summary.duration_ms
    ));

    html.push_str("<table><tr>");
    html.push_str(
        "<th>Benchmark</th><th>Mean</th><th>P50</th><th>P95</th><th>P99</th><th>Std Dev</th><th>Samples</th><th>Alloc Avg</th><th>Bytes Avg</th><th>Status</th></tr>",
    );

    for result in &summary.results {
        if let Some(stats) = &result.stats {
            let (alloc_avg, bytes_avg) = format_alloc_columns(result.alloc_stats.as_ref());
            html.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>OK</td></tr>",
                result.benchmark_name,
                format_duration(stats.mean),
                format_duration(stats.p50),
                format_duration(stats.p95),
                format_duration(stats.p99),
                format_duration(stats.std_dev),
                stats.sample_count,
                alloc_avg,
                bytes_avg
            ));
        } else {
            let error = result.error.as_deref().unwrap_or("Unknown error");
            html.push_str(&format!(
                "<tr><td>{}</td><td colspan=\"8\"></td><td class=\"error\">{}</td></tr>",
                result.benchmark_name, error
            ));
        }
    }

    html.push_str("</table></body></html>");

    fs::write(path, html)
}

/// Write an HTML report for a comparison run.
pub fn write_html_comparison_report(
    summary: &BenchComparisonSummary,
    path: &Path,
) -> io::Result<()> {
    let mut html = String::new();

    html.push_str("<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\">\n");
    html.push_str("<title>Asupersync Benchmark Comparison</title>\n");
    html.push_str("<style>");
    html.push_str("body{font-family:Arial,sans-serif;margin:40px;}");
    html.push_str("table{border-collapse:collapse;width:100%;}");
    html.push_str("th,td{border:1px solid #ddd;padding:8px;text-align:left;}");
    html.push_str("th{background-color:#4CAF50;color:white;}");
    html.push_str("tr:nth-child(even){background-color:#f2f2f2;}");
    html.push_str(".faster{color:#0a7b34;font-weight:bold;}");
    html.push_str(".slower{color:#b00020;font-weight:bold;}");
    html.push_str(".neutral{color:#555;}");
    html.push_str(".error{color:#b00020;font-weight:bold;}");
    html.push_str("</style></head><body>\n");

    html.push_str(&format!(
        "<h1>Benchmark Comparison: {} vs {}</h1>",
        summary.runtime_a_name, summary.runtime_b_name
    ));
    html.push_str(&format!(
        "<p>Total: {} | Compared: {} | Failed: {} | Duration: {}ms</p>",
        summary.total, summary.compared, summary.failed, summary.duration_ms
    ));

    html.push_str("<table><tr>");
    html.push_str(&format!(
        "<th>Benchmark</th><th>{} Mean</th><th>{} Mean</th><th>Speedup</th><th>Confidence</th><th>Status</th></tr>",
        summary.runtime_a_name, summary.runtime_b_name
    ));

    for result in &summary.results {
        if let Some(comparison) = &result.comparison {
            let speedup = comparison.speedup;
            let class = if speedup > 1.05 {
                "faster"
            } else if speedup < 0.95 {
                "slower"
            } else {
                "neutral"
            };
            html.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td class=\"{}\">{:.2}x</td><td>{:?}</td><td>OK</td></tr>",
                result.benchmark_name,
                format_duration(comparison.a.mean),
                format_duration(comparison.b.mean),
                class,
                speedup,
                comparison.confidence
            ));
        } else {
            let error = result
                .runtime_a
                .error
                .as_ref()
                .or(result.runtime_b.error.as_ref())
                .map(String::as_str)
                .unwrap_or("Missing stats");
            html.push_str(&format!(
                "<tr><td>{}</td><td colspan=\"4\"></td><td class=\"error\">{}</td></tr>",
                result.benchmark_name, error
            ));
        }
    }

    html.push_str("</table></body></html>");

    fs::write(path, html)
}

fn format_duration(duration: Duration) -> String {
    let nanos = duration.as_nanos();
    if nanos < 1_000 {
        format!("{}ns", nanos)
    } else if nanos < 1_000_000 {
        format!("{}us", duration.as_micros())
    } else if nanos < 1_000_000_000 {
        format!("{}ms", duration.as_millis())
    } else {
        format!("{:.2}s", duration.as_secs_f64())
    }
}

fn format_alloc_summary(stats: Option<&crate::bench::runner::BenchAllocStats>) -> String {
    match stats {
        Some(stats) => format!(
            " alloc_avg={:.1} bytes_avg={}",
            stats.avg_allocations,
            format_bytes(stats.avg_bytes_allocated)
        ),
        None => String::new(),
    }
}

fn format_alloc_columns(stats: Option<&crate::bench::runner::BenchAllocStats>) -> (String, String) {
    match stats {
        Some(stats) => (
            format!("{:.1}", stats.avg_allocations),
            format_bytes(stats.avg_bytes_allocated),
        ),
        None => ("-".to_string(), "-".to_string()),
    }
}

fn format_bytes(bytes: f64) -> String {
    if !bytes.is_finite() || bytes <= 0.0 {
        return "0B".to_string();
    }
    if bytes < 1024.0 {
        format!("{:.0}B", bytes)
    } else if bytes < 1024.0 * 1024.0 {
        format!("{:.1}KB", bytes / 1024.0)
    } else if bytes < 1024.0 * 1024.0 * 1024.0 {
        format!("{:.1}MB", bytes / (1024.0 * 1024.0))
    } else {
        format!("{:.1}GB", bytes / (1024.0 * 1024.0 * 1024.0))
    }
}
