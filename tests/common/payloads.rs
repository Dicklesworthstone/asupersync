#![allow(clippy::all)]
//! Realistic payload generators for E2E tests.
//!
//! Generate realistic data instead of synthetic/mock BS:
//! JSON user profiles, HTTP request batches, region snapshots, SQL result sets.

/// Generate a realistic JSON user profile (~500 bytes).
pub fn json_user_profile(id: u64) -> String {
    format!(
        r#"{{"id":{id},"username":"user_{id:04x}","email":"user_{id:04x}@example.com","display_name":"Test User {id}","created_at":"2026-01-15T08:30:00Z","roles":["viewer","editor"],"preferences":{{"theme":"dark","locale":"en-US","notifications":true,"timezone":"America/New_York"}},"last_login":"2026-03-15T14:22:00Z","metadata":{{"login_count":42,"storage_used_bytes":1048576,"plan":"professional"}}}}"#,
    )
}

/// Generate a batch of realistic JSON user profiles.
pub fn json_user_profile_batch(count: usize) -> Vec<String> {
    (0..count).map(|i| json_user_profile(i as u64)).collect()
}

/// Generate a realistic HTTP request body for a TODO item.
pub fn todo_create_body(title: &str) -> Vec<u8> {
    format!(
        r#"{{"title":"{title}","description":"Detailed description for: {title}","priority":"medium","due_date":"2026-04-01T00:00:00Z","tags":["work","urgent"],"assignee":"user_0001"}}"#,
    )
    .into_bytes()
}

/// Generate a realistic TODO update body.
pub fn todo_update_body(title: &str, completed: bool) -> Vec<u8> {
    format!(r#"{{"title":"{title}","completed":{completed},"updated_at":"2026-03-16T10:00:00Z"}}"#)
        .into_bytes()
}

/// Generate a realistic JSON log event.
pub fn json_log_event(seq: u64, level: &str, message: &str) -> String {
    format!(
        r#"{{"seq":{},"timestamp":"2026-03-16T10:00:{:02}.{:03}Z","level":"{}","service":"api-gateway","host":"prod-web-03","trace_id":"{:016x}","span_id":"{:08x}","message":"{}","metadata":{{"request_id":"req-{:08x}","user_agent":"Mozilla/5.0","latency_ms":{}}}}}"#,
        seq,
        seq % 60,
        (seq * 7) % 1000,
        level,
        0xCAFE_0000 + seq,
        0xBEEF_0000 + seq,
        message,
        seq,
        (seq * 13) % 500
    )
}

/// Generate a batch of realistic log events with realistic level distribution.
pub fn json_log_event_batch(count: usize) -> Vec<String> {
    (0..count)
        .map(|i| {
            let (level, msg) = match i % 20 {
                0 => ("ERROR", "connection refused to upstream service"),
                1 => ("WARN", "request latency exceeded 200ms threshold"),
                2 => ("WARN", "retry attempt 2/3 for database query"),
                3 => ("ERROR", "timeout waiting for response from auth-service"),
                _ => ("INFO", "request processed successfully"),
            };
            json_log_event(i as u64, level, msg)
        })
        .collect()
}

/// Generate a realistic config update message.
pub fn config_update_message(version: u32) -> String {
    format!(
        r#"{{"version":{},"features":{{"rate_limit_rps":1000,"max_connections":5000,"circuit_breaker_threshold":5,"retry_max_attempts":3}},"updated_by":"deploy-bot","updated_at":"2026-03-16T09:{}:00Z"}}"#,
        version,
        version % 60
    )
}

/// Generate a realistic server-state enum value for watch channel testing.
pub fn server_state_json(state: &str, connections: u32, uptime_secs: u64) -> String {
    format!(
        r#"{{"state":"{state}","connections":{connections},"uptime_secs":{uptime_secs},"version":"1.2.3","healthy":true}}"#,
    )
}

/// Generate large payload of specified size (for body size tests).
pub fn large_payload(size: usize) -> Vec<u8> {
    // Realistic-ish: repeating JSON-like content
    let pattern = br#"{"data":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","idx":000000},"#;
    let mut buf = Vec::with_capacity(size);
    while buf.len() < size {
        let remaining = size - buf.len();
        let chunk = &pattern[..remaining.min(pattern.len())];
        buf.extend_from_slice(chunk);
    }
    buf.truncate(size);
    buf
}

/// Generate a SQL-like result set as JSON.
pub fn sql_result_set(rows: usize, cols: usize) -> String {
    let col_names: Vec<String> = (0..cols).map(|c| format!("col_{c}")).collect();
    let row_data: Vec<String> = (0..rows)
        .map(|r| {
            let values: Vec<String> = (0..cols)
                .map(|c| format!(r#""{}":"val_{}_{}"#, col_names[c], r, c))
                .collect();
            format!("{{{}}}", values.join(","))
        })
        .collect();
    format!(
        r#"{{"columns":[{}],"rows":[{}],"row_count":{}}}"#,
        col_names
            .iter()
            .map(|c| format!(r#""{c}""#))
            .collect::<Vec<_>>()
            .join(","),
        row_data.join(","),
        rows
    )
}
