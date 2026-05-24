//! ATP Trace Redaction
//!
//! Implements secure redaction of sensitive data in ATP logs and traces.

use super::{AtpEvent, RedactionRule, RedactionType};
use serde_json::Value;
use std::collections::HashSet;

/// Apply redaction rules to an ATP event
pub fn apply_redaction(event: &mut AtpEvent, rules: &[RedactionRule]) {
    let mut redacted_fields = HashSet::new();

    // Redact the data field recursively
    redact_value(&mut event.data, rules, &mut redacted_fields, "data");

    // Redact context fields that might contain sensitive data
    redact_context_fields(event, rules, &mut redacted_fields);

    // Update the redacted_fields list
    event.redacted_fields = redacted_fields.into_iter().collect();
    event.redacted_fields.sort(); // For deterministic output
}

/// Redact sensitive values in an arbitrary JSON value and return stable paths
/// that were changed.
pub fn redact_json_value(
    value: &mut Value,
    rules: &[RedactionRule],
    root_path: &str,
) -> Vec<String> {
    let mut redacted_fields = HashSet::new();
    redact_value(value, rules, &mut redacted_fields, root_path);
    let mut fields = redacted_fields.into_iter().collect::<Vec<_>>();
    fields.sort();
    fields
}

/// Recursively redact sensitive values in JSON data
fn redact_value(
    value: &mut Value,
    rules: &[RedactionRule],
    redacted_fields: &mut HashSet<String>,
    field_path: &str,
) {
    match value {
        Value::Object(obj) => {
            for (key, val) in obj.iter_mut() {
                let current_path = if field_path.is_empty() {
                    key.clone()
                } else {
                    format!("{}.{}", field_path, key)
                };

                // Check if this field should be redacted
                if should_redact_field(&current_path, rules) {
                    let replacement = get_redaction_replacement(&current_path, rules);
                    *val = Value::String(replacement);
                    redacted_fields.insert(current_path.clone());
                } else {
                    // Recursively process nested objects/arrays
                    redact_value(val, rules, redacted_fields, &current_path);
                }
            }
        }
        Value::Array(arr) => {
            for (idx, val) in arr.iter_mut().enumerate() {
                let current_path = format!("{}[{}]", field_path, idx);
                redact_value(val, rules, redacted_fields, &current_path);
            }
        }
        Value::String(s) => {
            // Check for patterns within string values
            if let Some(redacted) = redact_string_patterns(s, rules, field_path) {
                *value = Value::String(redacted);
                redacted_fields.insert(field_path.to_string());
            }
        }
        _ => {
            // Numbers, bools, null - no redaction needed
        }
    }
}

/// Redact sensitive fields in event context
fn redact_context_fields(
    event: &mut AtpEvent,
    rules: &[RedactionRule],
    redacted_fields: &mut HashSet<String>,
) {
    // Check session_id for sensitive patterns
    if should_redact_field("context.session_id", rules) {
        event.context.session_id = get_redaction_replacement("context.session_id", rules);
        redacted_fields.insert("context.session_id".to_string());
    }

    // Check transfer_id
    if let Some(ref mut transfer_id) = event.context.transfer_id {
        if should_redact_field("context.transfer_id", rules) {
            *transfer_id = get_redaction_replacement("context.transfer_id", rules);
            redacted_fields.insert("context.transfer_id".to_string());
        }
    }

    // Check connection_id
    if let Some(ref mut connection_id) = event.context.connection_id {
        if should_redact_field("context.connection_id", rules) {
            *connection_id = get_redaction_replacement("context.connection_id", rules);
            redacted_fields.insert("context.connection_id".to_string());
        }
    }

    if let Some(ref mut peer_id) = event.context.peer_id {
        if should_redact_field("context.peer_id", rules) {
            *peer_id = get_redaction_replacement("context.peer_id", rules);
            redacted_fields.insert("context.peer_id".to_string());
        }
    }

    // Note: trace_id and span_id are typically safe for distributed tracing
    // but can be redacted if policy requires
}

/// Check if a field should be redacted based on rules
fn should_redact_field(field_path: &str, rules: &[RedactionRule]) -> bool {
    rules
        .iter()
        .any(|rule| field_matches_pattern(field_path, &rule.field_pattern))
}

/// Get the replacement value for a redacted field
fn get_redaction_replacement(field_path: &str, rules: &[RedactionRule]) -> String {
    for rule in rules {
        if field_matches_pattern(field_path, &rule.field_pattern) {
            return rule.replacement.clone();
        }
    }
    "[REDACTED]".to_string()
}

/// Check if a field path matches a redaction pattern
fn field_matches_pattern(field_path: &str, pattern: &str) -> bool {
    // Exact match
    if field_path == pattern {
        return true;
    }

    if let Some(suffix_pattern) = pattern.strip_prefix(".*") {
        let suffix = suffix_pattern.trim_end_matches('$').replace(r"\.", ".");
        return field_path.ends_with(&suffix);
    }

    if pattern
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return field_path
            .split('.')
            .any(|segment| segment_matches_simple_pattern(segment, pattern));
    }

    false
}

fn segment_matches_simple_pattern(segment: &str, pattern: &str) -> bool {
    let base_segment = segment.split_once('[').map_or(segment, |(base, _)| base);
    base_segment == pattern
        || base_segment
            .strip_suffix(pattern)
            .is_some_and(|prefix| prefix.ends_with('_'))
}

/// Redact patterns within string values
fn redact_string_patterns(text: &str, rules: &[RedactionRule], field_path: &str) -> Option<String> {
    let mut result = text.to_string();
    let mut modified = false;

    for rule in rules {
        match &rule.redaction_type {
            RedactionType::PrivateKey => {
                if is_private_key_pattern(text) {
                    return Some(rule.replacement.clone());
                }
            }
            RedactionType::AuthToken => {
                if is_auth_token_pattern(text) {
                    return Some(rule.replacement.clone());
                }
            }
            RedactionType::CapabilitySecret => {
                if is_capability_secret_pattern(text) {
                    return Some(rule.replacement.clone());
                }
            }
            RedactionType::SensitivePath => {
                if is_sensitive_path(text) {
                    result = redact_path_components(&result);
                    modified = true;
                }
            }
            RedactionType::ContentHash => {
                // Policy-dependent: only redact if configured
                if field_path.contains("content_hash") || field_path.contains("hash") {
                    if is_hash_pattern(text) {
                        return Some(rule.replacement.clone());
                    }
                }
            }
            RedactionType::Custom(pattern) => {
                if string_matches_pattern(text, pattern) {
                    result.clone_from(&rule.replacement);
                    modified = true;
                }
            }
        }
    }

    if modified { Some(result) } else { None }
}

fn string_matches_pattern(text: &str, pattern: &str) -> bool {
    if text == pattern || text.contains(pattern) {
        return true;
    }

    if let Some(suffix_pattern) = pattern.strip_prefix(".*") {
        let suffix = suffix_pattern.trim_end_matches('$').replace(r"\.", ".");
        return text.ends_with(&suffix);
    }

    false
}

/// Detect private key patterns
fn is_private_key_pattern(text: &str) -> bool {
    text.contains("-----BEGIN PRIVATE KEY-----")
        || text.contains("-----BEGIN RSA PRIVATE KEY-----")
        || text.contains("-----BEGIN EC PRIVATE KEY-----")
        || text.len() > 32
            && text
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '=' || c == '+' || c == '/')
}

/// Detect auth token patterns
fn is_auth_token_pattern(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    if lower.contains("token=")
        || lower.contains("password=")
        || lower.contains("secret=")
        || lower.contains("authorization: bearer ")
    {
        return true;
    }

    // JWT pattern
    if text.matches('.').count() == 2 && text.len() > 100 {
        return true;
    }

    // Bearer token pattern
    if text.starts_with("Bearer ") && text.len() > 50 {
        return true;
    }

    // API key pattern
    if (text.starts_with("sk-") || text.starts_with("pk-") || text.starts_with("api-"))
        && text.len() > 20
    {
        return true;
    }

    false
}

/// Detect capability secret patterns
fn is_capability_secret_pattern(text: &str) -> bool {
    // Macaroon pattern
    text.starts_with("MDAxM") || // Base64 encoded macaroon prefix
    // Capability URL pattern
    (text.starts_with("cap://") && text.len() > 50) ||
    // Other secret patterns
    (text.len() > 32 && text.chars().all(|c| c.is_ascii_hexdigit()))
}

/// Detect sensitive file paths
fn is_sensitive_path(text: &str) -> bool {
    let sensitive_patterns = [
        "/.ssh/",
        "/.gnupg/",
        "/private/",
        "/secrets/",
        ".key",
        ".pem",
        ".p12",
        ".pfx",
        "password",
        "passwd",
        "/home/",
        "/Users/",
    ];

    sensitive_patterns
        .iter()
        .any(|pattern| text.contains(pattern))
}

/// Redact sensitive components from file paths
fn redact_path_components(path: &str) -> String {
    let parts: Vec<&str> = path.split('/').collect();
    let mut result = Vec::new();

    for part in parts {
        if part.contains("home") || part.contains("Users") {
            result.push("[USER]");
        } else if part.contains(".key") || part.contains(".pem") || part.contains("secret") {
            result.push("[SENSITIVE_FILE]");
        } else if part.len() > 20 && part.chars().all(|c| c.is_ascii_alphanumeric()) {
            // Likely a hash or ID
            result.push("[ID]");
        } else {
            result.push(part);
        }
    }

    result.join("/")
}

/// Detect hash patterns
fn is_hash_pattern(text: &str) -> bool {
    // SHA-256: 64 hex characters
    if text.len() == 64 && text.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }

    // SHA-1: 40 hex characters
    if text.len() == 40 && text.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }

    // MD5: 32 hex characters
    if text.len() == 32 && text.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_private_key_redaction() {
        let rule = RedactionRule {
            field_pattern: "private_key".to_string(),
            redaction_type: RedactionType::PrivateKey,
            replacement: "[REDACTED_KEY]".to_string(),
        };

        let mut event = AtpEvent {
            schema_version: super::super::ATP_LOG_EVENT_SCHEMA_VERSION.to_string(),
            timestamp: "2026-05-20T12:00:00Z".to_string(),
            level: super::super::Level::Info,
            subsystem: super::super::AtpSubsystem::Security,
            event_type: "key_generated".to_string(),
            data: json!({
                "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ..."
            }),
            context: super::super::EventContext {
                session_id: "session123".to_string(),
                transfer_id: None,
                connection_id: None,
                peer_id: None,
                test_case_id: None,
                trace_id: "trace123".to_string(),
                span_id: "span123".to_string(),
            },
            redacted_fields: Vec::new(),
        };

        apply_redaction(&mut event, &[rule]);

        assert_eq!(event.data["private_key"], "[REDACTED_KEY]");
        assert!(
            event
                .redacted_fields
                .contains(&"data.private_key".to_string())
        );
    }

    #[test]
    fn test_path_redaction() {
        let rule = RedactionRule {
            field_pattern: "file_path".to_string(),
            redaction_type: RedactionType::SensitivePath,
            replacement: "[REDACTED_PATH]".to_string(),
        };

        let mut event = AtpEvent {
            schema_version: super::super::ATP_LOG_EVENT_SCHEMA_VERSION.to_string(),
            timestamp: "2026-05-20T12:00:00Z".to_string(),
            level: super::super::Level::Info,
            subsystem: super::super::AtpSubsystem::Disk,
            event_type: "file_read_started".to_string(),
            data: json!({
                "file_path": "/home/user/.ssh/id_rsa"
            }),
            context: super::super::EventContext {
                session_id: "session123".to_string(),
                transfer_id: None,
                connection_id: None,
                peer_id: None,
                test_case_id: None,
                trace_id: "trace123".to_string(),
                span_id: "span123".to_string(),
            },
            redacted_fields: Vec::new(),
        };

        apply_redaction(&mut event, &[rule]);

        assert_eq!(event.data["file_path"], "[REDACTED_PATH]");
    }

    #[test]
    fn path_rule_does_not_redact_path_id_metadata() {
        let mut value = json!({
            "file_path": "/home/user/project.log",
            "path_id": "direct-1",
            "path": "/home/user/.ssh/id_ed25519"
        });

        let redacted =
            redact_json_value(&mut value, &super::super::default_redaction_rules(), "data");

        assert_eq!(value["file_path"], "[REDACTED_PATH]");
        assert_eq!(value["path_id"], "direct-1");
        assert_eq!(value["path"], "[REDACTED_PATH]");
        assert_eq!(
            redacted,
            vec!["data.file_path".to_string(), "data.path".to_string()]
        );
    }
}
