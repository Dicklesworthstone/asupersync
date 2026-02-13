//! Deterministic Lean build frontier extraction and error bucketing.
//!
//! The extractor parses Lean diagnostics from `lake build` output, normalizes
//! signatures, buckets errors by root-cause class, and optionally annotates
//! buckets with gap/bead ownership links from the Track-2 sequencing plan.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// Stable schema version for frontier extraction artifacts.
pub const LEAN_FRONTIER_SCHEMA_VERSION: &str = "1.0.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LeanDiagnosticSeverity {
    Error,
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeanFrontierDiagnostic {
    pub severity: LeanDiagnosticSeverity,
    pub file_path: String,
    pub line: u32,
    pub column: u32,
    pub error_code: String,
    pub failure_mode: String,
    pub signature: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeanFrontierBucket {
    pub bucket_id: String,
    pub failure_mode: String,
    pub error_code: String,
    pub count: usize,
    pub signatures: Vec<String>,
    pub sample_locations: Vec<String>,
    pub linked_gap_ids: Vec<String>,
    pub linked_bead_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeanFrontierReport {
    pub schema_version: String,
    pub report_id: String,
    pub generated_by: String,
    pub source_log: String,
    pub bucket_ordering: String,
    pub diagnostics_total: usize,
    pub errors_total: usize,
    pub warnings_total: usize,
    pub buckets: Vec<LeanFrontierBucket>,
}

#[derive(Debug, Default)]
struct GapLinks {
    gap_ids: BTreeSet<String>,
    bead_ids: BTreeSet<String>,
}

/// Parse and bucket Lean diagnostics from build output.
///
/// The output ordering is deterministic:
/// - diagnostics are parsed in input order
/// - buckets are sorted by `(failure_mode, error_code)`
/// - signatures and locations are sorted lexicographically
pub fn extract_frontier_report(
    log_text: &str,
    source_log: &str,
    gap_plan_json: Option<&str>,
) -> LeanFrontierReport {
    let gap_links = parse_gap_links(gap_plan_json);

    let diagnostics = log_text
        .lines()
        .filter_map(parse_diagnostic_line)
        .collect::<Vec<_>>();
    let errors_total = diagnostics
        .iter()
        .filter(|d| d.severity == LeanDiagnosticSeverity::Error)
        .count();
    let warnings_total = diagnostics
        .iter()
        .filter(|d| d.severity == LeanDiagnosticSeverity::Warning)
        .count();

    let mut grouped = BTreeMap::<(String, String), Vec<LeanFrontierDiagnostic>>::new();
    for diagnostic in diagnostics
        .iter()
        .filter(|d| d.severity == LeanDiagnosticSeverity::Error)
    {
        grouped
            .entry((
                diagnostic.failure_mode.clone(),
                diagnostic.error_code.clone(),
            ))
            .or_default()
            .push(diagnostic.clone());
    }

    let mut buckets = Vec::with_capacity(grouped.len());
    for ((failure_mode, error_code), mut entries) in grouped {
        entries.sort_by(|left, right| {
            (
                left.file_path.as_str(),
                left.line,
                left.column,
                left.signature.as_str(),
            )
                .cmp(&(
                    right.file_path.as_str(),
                    right.line,
                    right.column,
                    right.signature.as_str(),
                ))
        });

        let signatures = entries
            .iter()
            .map(|entry| entry.signature.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let sample_locations = entries
            .iter()
            .map(|entry| format!("{}:{}:{}", entry.file_path, entry.line, entry.column))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .take(12)
            .collect::<Vec<_>>();
        let (linked_gap_ids, linked_bead_ids) = gap_links
            .get(&failure_mode)
            .map(|links| {
                (
                    links.gap_ids.iter().cloned().collect::<Vec<_>>(),
                    links.bead_ids.iter().cloned().collect::<Vec<_>>(),
                )
            })
            .unwrap_or_default();

        buckets.push(LeanFrontierBucket {
            bucket_id: format!("{failure_mode}.{error_code}"),
            failure_mode,
            error_code,
            count: entries.len(),
            signatures,
            sample_locations,
            linked_gap_ids,
            linked_bead_ids,
        });
    }

    LeanFrontierReport {
        schema_version: LEAN_FRONTIER_SCHEMA_VERSION.to_string(),
        report_id: "lean.frontier.buckets.v1".to_string(),
        generated_by: "bd-1dorb".to_string(),
        source_log: source_log.to_string(),
        bucket_ordering: "lexicographic(failure_mode,error_code)".to_string(),
        diagnostics_total: diagnostics.len(),
        errors_total,
        warnings_total,
        buckets,
    }
}

fn parse_gap_links(gap_plan_json: Option<&str>) -> BTreeMap<String, GapLinks> {
    let mut by_failure_mode = BTreeMap::<String, GapLinks>::new();
    let Some(json) = gap_plan_json else {
        return by_failure_mode;
    };

    let Ok(plan) = serde_json::from_str::<Value>(json) else {
        return by_failure_mode;
    };
    let Some(gaps) = plan.get("gaps").and_then(Value::as_array) else {
        return by_failure_mode;
    };

    for gap in gaps {
        let Some(failure_mode) = gap.get("failure_mode").and_then(Value::as_str) else {
            continue;
        };
        let Some(gap_id) = gap.get("id").and_then(Value::as_str) else {
            continue;
        };
        let links = by_failure_mode.entry(failure_mode.to_string()).or_default();
        links.gap_ids.insert(gap_id.to_string());
        if let Some(linked_beads) = gap.get("linked_beads").and_then(Value::as_array) {
            for bead in linked_beads.iter().filter_map(Value::as_str) {
                links.bead_ids.insert(bead.to_string());
            }
        }
    }

    by_failure_mode
}

fn parse_diagnostic_line(line: &str) -> Option<LeanFrontierDiagnostic> {
    let (severity, rest) = if let Some(rest) = line.strip_prefix("error: ") {
        (LeanDiagnosticSeverity::Error, rest)
    } else if let Some(rest) = line.strip_prefix("warning: ") {
        (LeanDiagnosticSeverity::Warning, rest)
    } else {
        return None;
    };

    let mut parts = rest.splitn(4, ':');
    let raw_file = parts.next()?.trim();
    let line_number = parts.next()?.trim().parse::<u32>().ok()?;
    let column = parts.next()?.trim().parse::<u32>().ok()?;
    let message = parts.next()?.trim().to_string();
    if raw_file.is_empty() || message.is_empty() {
        return None;
    }

    let file_path = normalize_file_path(raw_file);
    let error_code = classify_error_code(&message).to_string();
    let failure_mode = classify_failure_mode(&error_code).to_string();
    let signature = format!(
        "{file_path}:{error_code}:{}",
        normalize_message_for_signature(&message)
    );

    Some(LeanFrontierDiagnostic {
        severity,
        file_path,
        line: line_number,
        column,
        error_code,
        failure_mode,
        signature,
        message,
    })
}

fn normalize_file_path(raw_file: &str) -> String {
    raw_file.rsplit('/').next().unwrap_or(raw_file).to_string()
}

fn classify_error_code(message: &str) -> &'static str {
    let lower = message.to_ascii_lowercase();
    if lower.starts_with("unknown identifier") {
        return "unknown-identifier";
    }
    if lower.starts_with("alternative `") && lower.contains("has not been provided") {
        return "constructor-alternative-missing";
    }
    if lower.contains("maximum recursion depth has been reached") {
        return "tactic-max-rec-depth";
    }
    if lower.contains("tactic `simp` failed with a nested error") {
        return "tactic-simp-nested-error";
    }
    if lower.contains("unsolved goals") {
        return "unsolved-goals";
    }
    if lower.starts_with("application type mismatch") {
        return "application-type-mismatch";
    }
    if lower.starts_with("type mismatch") {
        return "type-mismatch";
    }
    if lower.contains("tactic `rewrite` failed") {
        return "rewrite-failed";
    }
    if lower.contains("tactic `subst` failed") {
        return "subst-failed";
    }
    if lower.contains("no goals to be solved") {
        return "no-goals";
    }
    if lower.contains("unexpected token") {
        return "parse-unexpected-token";
    }
    if lower.contains("omega could not prove the goal") {
        return "omega-goal-not-proved";
    }
    if lower.contains("simp made no progress") {
        return "simp-no-progress";
    }
    "other"
}

fn classify_failure_mode(error_code: &str) -> &'static str {
    match error_code {
        "unknown-identifier" => "declaration-order",
        "constructor-alternative-missing" => "missing-lemma",
        "tactic-max-rec-depth" | "tactic-simp-nested-error" | "simp-no-progress" => {
            "tactic-instability"
        }
        "application-type-mismatch"
        | "type-mismatch"
        | "rewrite-failed"
        | "subst-failed"
        | "unsolved-goals"
        | "no-goals"
        | "parse-unexpected-token"
        | "omega-goal-not-proved"
        | "other" => "proof-shape",
        _ => "proof-shape",
    }
}

fn normalize_message_for_signature(message: &str) -> String {
    let mut out = String::with_capacity(message.len());
    let mut in_backticks = false;
    let mut digit_run = false;
    let mut previous_was_space = false;

    for ch in message.chars() {
        if ch == '`' {
            if in_backticks {
                if !out.ends_with("<id>") {
                    out.push_str("<id>");
                }
                previous_was_space = false;
            }
            in_backticks = !in_backticks;
            continue;
        }
        if in_backticks {
            continue;
        }
        if ch.is_ascii_digit() {
            if !digit_run {
                out.push('#');
                digit_run = true;
                previous_was_space = false;
            }
            continue;
        }
        digit_run = false;
        let lowered = ch.to_ascii_lowercase();
        if lowered.is_ascii_alphanumeric() || lowered == '-' || lowered == '_' {
            out.push(lowered);
            previous_was_space = false;
            continue;
        }
        if !previous_was_space {
            out.push(' ');
            previous_was_space = true;
        }
    }

    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::{
        extract_frontier_report, normalize_message_for_signature, parse_diagnostic_line,
        LeanDiagnosticSeverity, LEAN_FRONTIER_SCHEMA_VERSION,
    };

    #[test]
    fn parse_diagnostic_line_extracts_expected_fields() {
        let line = "error: Asupersync.lean:2874:2: Alternative `cancelChild` has not been provided";
        let diagnostic = parse_diagnostic_line(line).expect("must parse");
        assert_eq!(diagnostic.severity, LeanDiagnosticSeverity::Error);
        assert_eq!(diagnostic.file_path, "Asupersync.lean");
        assert_eq!(diagnostic.line, 2874);
        assert_eq!(diagnostic.column, 2);
        assert_eq!(diagnostic.error_code, "constructor-alternative-missing");
        assert_eq!(diagnostic.failure_mode, "missing-lemma");
    }

    #[test]
    fn signature_normalization_stabilizes_identifiers_and_numbers() {
        let message = "Unknown identifier `setRegion_structural_preserves_wellformed` at 2335";
        let normalized = normalize_message_for_signature(message);
        assert_eq!(normalized, "unknown identifier <id> at #");
    }

    #[test]
    fn extraction_is_deterministic_for_same_input() {
        let log = "\
error: Asupersync.lean:10:2: Unknown identifier `x`\n\
error: Asupersync.lean:11:2: Unknown identifier `y`\n\
error: Asupersync.lean:12:3: Type mismatch\n\
warning: Asupersync.lean:13:5: unused variable `h`\n\
";
        let report_a = extract_frontier_report(log, "sample.log", None);
        let report_b = extract_frontier_report(log, "sample.log", None);
        assert_eq!(report_a, report_b);
        assert_eq!(report_a.schema_version, LEAN_FRONTIER_SCHEMA_VERSION);
        assert_eq!(report_a.diagnostics_total, 4);
        assert_eq!(report_a.errors_total, 3);
        assert_eq!(report_a.warnings_total, 1);
    }
}
