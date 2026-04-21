import os

replacements = {
    "src/observability/cancellation_analyzer.rs": [
        (
            "            let timing_ms: Vec<f64> = times.iter().map(|d| d.as_secs_f64() * 1000.0).collect();\n\n            let processing_stats = self.calculate_distribution_stats(&timing_ms);\n            let anomaly_count = entity_anomalies.get(&entity_id).copied().unwrap_or(0);\n            let anomaly_rate = anomaly_count as f64 / times.len() as f64;",
            "            if times.is_empty() {\n                continue;\n            }\n            let timing_ms: Vec<f64> = times.iter().map(|d| d.as_secs_f64() * 1000.0).collect();\n\n            let processing_stats = self.calculate_distribution_stats(&timing_ms);\n            let anomaly_count = entity_anomalies.get(&entity_id).copied().unwrap_or(0);\n            let anomaly_rate = anomaly_count as f64 / times.len() as f64;"
        ),
        (
            "            let total_anomalies: usize = trace.events.iter().filter(|e| e.is_anomaly).count();",
            "            if entity_traces.is_empty() {\n                continue;\n            }\n            let total_anomalies: usize = trace.events.iter().filter(|e| e.is_anomaly).count();"
        )
    ],
    "src/observability/structured_cancellation_analyzer.rs": [
        (
            "        real_time_stats.memory_usage_percentage =\n            (memory_mb as f64 / self.config.max_memory_usage_mb as f64 * 100.0).min(100.0);",
            "        real_time_stats.memory_usage_percentage = if self.config.max_memory_usage_mb > 0 {\n            (memory_mb as f64 / self.config.max_memory_usage_mb as f64 * 100.0).min(100.0)\n        } else {\n            100.0\n        };"
        ),
        (
            "                metric_value: slow_count as f64 / entity_traces.len() as f64 * 100.0,",
            "                metric_value: if entity_traces.is_empty() { 0.0 } else { slow_count as f64 / entity_traces.len() as f64 * 100.0 },"
        ),
        (
            "                metric_value: total_anomalies as f64 / entity_traces.len() as f64,",
            "                metric_value: if entity_traces.is_empty() { 0.0 } else { total_anomalies as f64 / entity_traces.len() as f64 },"
        )
    ],
    "src/raptorq/gf256_tests/gf256_validation_tests.rs": [
        (
            "    let throughput_gbps = (size * iterations) as f64 / duration.as_secs_f64() / 1e9;",
            "    let secs = duration.as_secs_f64().max(f64::MIN_POSITIVE);\n    let throughput_gbps = (size * iterations) as f64 / secs / 1e9;"
        )
    ]
}

for file_path, reps in replacements.items():
    if not os.path.exists(file_path):
        print(f"Skipping {file_path}")
        continue
    with open(file_path, "r") as f:
        content = f.read()
    for old, new in reps:
        if old in content:
            content = content.replace(old, new)
        else:
            print(f"Pattern not found in {file_path}")
    with open(file_path, "w") as f:
        f.write(content)
print("Replacements done.")
