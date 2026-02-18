//! Galaxy-brain card renderer for [`EvidenceLedger`] entries.
//!
//! Produces human-readable summaries at four levels:
//!
//! - **Level 0** (one-liner): fits in a single 120-char terminal line.
//! - **Level 1** (paragraph): multi-line block with ANSI colors.
//! - **Level 2** (full card): ASCII histogram, loss matrix, feature bars,
//!   calibration gauge.
//! - **Level 3** (debug): full JSON dump with diff from previous decision.
//!
//! Additional output formats:
//!
//! - **HTML**: inline-CSS cards for dashboard embedding.
//! - **Markdown**: GitHub-flavored markdown for PR comments.
//!
//! Levels 0-2 are stateless. Level 3 requires a [`DiffContext`] to track
//! previous entries per component for diffing.
//!
//! # Example
//!
//! ```
//! use franken_evidence::{EvidenceLedgerBuilder, render};
//!
//! let entry = EvidenceLedgerBuilder::new()
//!     .ts_unix_ms(1700000000000)
//!     .component("scheduler")
//!     .action("preempt")
//!     .posterior(vec![0.7, 0.2, 0.1])
//!     .expected_loss("preempt", 0.05)
//!     .chosen_expected_loss(0.05)
//!     .calibration_score(0.92)
//!     .fallback_active(false)
//!     .top_feature("queue_depth", 0.45)
//!     .build()
//!     .unwrap();
//!
//! let one_liner = render::level0(&entry);
//! assert!(one_liner.len() <= 120);
//!
//! let full_card = render::level2(&entry);
//! assert!(full_card.contains("posterior"));
//!
//! let html = render::html(&entry);
//! assert!(html.contains("<div"));
//!
//! let md = render::markdown(&entry);
//! assert!(md.contains("##"));
//! ```

use crate::EvidenceLedger;
use std::collections::BTreeMap;
use std::fmt::Write;

// ANSI escape codes.
const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const CYAN: &str = "\x1b[36m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const RED: &str = "\x1b[31m";
const MAGENTA: &str = "\x1b[35m";

/// Render a Level 0 one-liner (no ANSI, max 120 chars).
///
/// Format: `{component} chose {action} (EL={chosen_expected_loss:.2}, cal={calibration_score:.2})`
///
/// If `fallback_active`, appends ` [FALLBACK]`.
pub fn level0(entry: &EvidenceLedger) -> String {
    let fb = if entry.fallback_active {
        " [FALLBACK]"
    } else {
        ""
    };
    let line = format!(
        "{} chose {} (EL={:.2}, cal={:.2}){}",
        entry.component, entry.action, entry.chosen_expected_loss, entry.calibration_score, fb,
    );
    // Truncate to 120 chars if needed.
    if line.len() > 120 {
        let mut truncated = line[..117].to_string();
        truncated.push_str("...");
        truncated
    } else {
        line
    }
}

/// Render a Level 0 one-liner with ANSI colors.
///
/// Same content as [`level0`] but with color highlighting.
pub fn level0_ansi(entry: &EvidenceLedger) -> String {
    let cal_color = calibration_color(entry.calibration_score);
    let fb = if entry.fallback_active {
        format!(" {YELLOW}[FALLBACK]{RESET}")
    } else {
        String::new()
    };
    format!(
        "{BOLD}{CYAN}{}{RESET} chose {BOLD}{}{RESET} (EL={:.2}, cal={cal_color}{:.2}{RESET}){fb}",
        entry.component, entry.action, entry.chosen_expected_loss, entry.calibration_score,
    )
}

/// Render a Level 1 paragraph with ANSI colors.
///
/// Multi-line block showing:
/// - Component and action (header)
/// - Expected loss and calibration score
/// - Posterior distribution
/// - Top features
/// - Fallback status
pub fn level1(entry: &EvidenceLedger) -> String {
    let mut out = String::with_capacity(512);

    // Header line.
    let _ = writeln!(
        out,
        "{BOLD}{CYAN}{}{RESET} {DIM}→{RESET} {BOLD}{}{RESET}",
        entry.component, entry.action,
    );

    // Expected loss + calibration.
    let cal_color = calibration_color(entry.calibration_score);
    let _ = writeln!(
        out,
        "  expected loss: {BOLD}{:.4}{RESET}  calibration: {cal_color}{BOLD}{:.3}{RESET}",
        entry.chosen_expected_loss, entry.calibration_score,
    );

    // Posterior distribution.
    if !entry.posterior.is_empty() {
        let _ = write!(out, "  posterior: {DIM}[");
        for (i, p) in entry.posterior.iter().enumerate() {
            if i > 0 {
                let _ = write!(out, ", ");
            }
            let _ = write!(out, "{p:.3}");
        }
        let _ = writeln!(out, "]{RESET}");
    }

    // Top features.
    if !entry.top_features.is_empty() {
        let _ = write!(out, "  features: ");
        for (i, (name, weight)) in entry.top_features.iter().enumerate() {
            if i > 0 {
                let _ = write!(out, ", ");
            }
            let _ = write!(out, "{MAGENTA}{name}{RESET}={weight:.2}");
        }
        let _ = writeln!(out);
    }

    // Expected losses per action.
    if !entry.expected_loss_by_action.is_empty() {
        let _ = write!(out, "  losses: ");
        let mut actions: Vec<_> = entry.expected_loss_by_action.iter().collect();
        actions.sort_by(|a, b| a.0.cmp(b.0));
        for (i, (action, loss)) in actions.iter().enumerate() {
            if i > 0 {
                let _ = write!(out, ", ");
            }
            let highlight = if **action == entry.action { BOLD } else { DIM };
            let _ = write!(out, "{highlight}{action}{RESET}={loss:.3}");
        }
        let _ = writeln!(out);
    }

    // Fallback status.
    if entry.fallback_active {
        let _ = writeln!(out, "  {YELLOW}{BOLD}⚠ fallback heuristic active{RESET}");
    }

    out
}

/// Render a Level 1 paragraph without ANSI colors (plain text).
pub fn level1_plain(entry: &EvidenceLedger) -> String {
    let mut out = String::with_capacity(512);

    let _ = writeln!(out, "{} -> {}", entry.component, entry.action);
    let _ = writeln!(
        out,
        "  expected loss: {:.4}  calibration: {:.3}",
        entry.chosen_expected_loss, entry.calibration_score,
    );

    if !entry.posterior.is_empty() {
        let _ = write!(out, "  posterior: [");
        for (i, p) in entry.posterior.iter().enumerate() {
            if i > 0 {
                let _ = write!(out, ", ");
            }
            let _ = write!(out, "{p:.3}");
        }
        let _ = writeln!(out, "]");
    }

    if !entry.top_features.is_empty() {
        let _ = write!(out, "  features: ");
        for (i, (name, weight)) in entry.top_features.iter().enumerate() {
            if i > 0 {
                let _ = write!(out, ", ");
            }
            let _ = write!(out, "{name}={weight:.2}");
        }
        let _ = writeln!(out);
    }

    if !entry.expected_loss_by_action.is_empty() {
        let _ = write!(out, "  losses: ");
        let mut actions: Vec<_> = entry.expected_loss_by_action.iter().collect();
        actions.sort_by(|a, b| a.0.cmp(b.0));
        for (i, (action, loss)) in actions.iter().enumerate() {
            if i > 0 {
                let _ = write!(out, ", ");
            }
            let _ = write!(out, "{action}={loss:.3}");
        }
        let _ = writeln!(out);
    }

    if entry.fallback_active {
        let _ = writeln!(out, "  WARNING: fallback heuristic active");
    }

    out
}

/// Choose ANSI color based on calibration quality.
fn calibration_color(score: f64) -> &'static str {
    if score >= 0.9 {
        GREEN
    } else if score >= 0.7 {
        YELLOW
    } else {
        RED
    }
}

// ---------------------------------------------------------------------------
// Level 2 — full card (ASCII histogram, loss table, feature bars, calibration)
// ---------------------------------------------------------------------------

/// Width of the ASCII histogram bars (characters).
const HIST_BAR_WIDTH: usize = 40;

/// Width of the feature importance bars (characters).
const FEATURE_BAR_WIDTH: usize = 30;

/// Render a Level 2 full card with ASCII visualizations (plain text).
///
/// Includes:
/// - Header with component, action, timestamp
/// - ASCII histogram of posterior distribution
/// - Loss matrix table
/// - Feature importance bar chart
/// - Calibration gauge
/// - Fallback status
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
pub fn level2(entry: &EvidenceLedger) -> String {
    let mut out = String::with_capacity(2048);

    // Header.
    let _ = writeln!(out, "=== {} -> {} ===", entry.component, entry.action);
    let _ = writeln!(out, "  timestamp: {}ms", entry.ts_unix_ms);
    let _ = writeln!(out);

    // Posterior histogram.
    if !entry.posterior.is_empty() {
        let _ = writeln!(out, "  posterior distribution:");
        let max_p = entry
            .posterior
            .iter()
            .copied()
            .fold(0.0_f64, f64::max)
            .max(1e-12);
        for (i, &p) in entry.posterior.iter().enumerate() {
            let bar_len = ((p / max_p) * HIST_BAR_WIDTH as f64).round() as usize;
            let bar: String = "#".repeat(bar_len);
            let pad: String = " ".repeat(HIST_BAR_WIDTH.saturating_sub(bar_len));
            let _ = writeln!(out, "    [{i:>2}] |{bar}{pad}| {p:.4}");
        }
        let _ = writeln!(out);
    }

    // Loss matrix table.
    if !entry.expected_loss_by_action.is_empty() {
        let _ = writeln!(out, "  loss matrix:");
        let mut actions: Vec<_> = entry.expected_loss_by_action.iter().collect();
        actions.sort_by(|a, b| a.0.cmp(b.0));
        let max_name_len = actions.iter().map(|(n, _)| n.len()).max().unwrap_or(6);
        let header_pad = " ".repeat(max_name_len.saturating_sub(6));
        let _ = writeln!(out, "    {header_pad}action | loss     | chosen");
        let _ = writeln!(
            out,
            "    {}---+----------+-------",
            "-".repeat(max_name_len.saturating_sub(5))
        );
        for (action, &loss) in actions {
            let chosen = if **action == entry.action { " *" } else { "" };
            let pad = " ".repeat(max_name_len.saturating_sub(action.len()));
            let _ = writeln!(out, "    {pad}{action} | {loss:<8.4} |{chosen}");
        }
        let _ = writeln!(out);
    }

    // Feature importance bar chart.
    if !entry.top_features.is_empty() {
        let _ = writeln!(out, "  feature importance:");
        let max_w = entry
            .top_features
            .iter()
            .map(|(_, w)| *w)
            .fold(0.0_f64, f64::max)
            .max(1e-12);
        let max_name_len = entry
            .top_features
            .iter()
            .map(|(n, _)| n.len())
            .max()
            .unwrap_or(0);
        for (name, weight) in &entry.top_features {
            let bar_len = ((*weight / max_w) * FEATURE_BAR_WIDTH as f64).round() as usize;
            let bar: String = "=".repeat(bar_len);
            let pad = " ".repeat(max_name_len.saturating_sub(name.len()));
            let _ = writeln!(out, "    {pad}{name} |{bar} {weight:.3}");
        }
        let _ = writeln!(out);
    }

    // Calibration gauge.
    render_calibration_gauge(&mut out, entry.calibration_score);

    // Chosen expected loss.
    let _ = writeln!(
        out,
        "  chosen expected loss: {:.4}",
        entry.chosen_expected_loss
    );

    // Fallback status.
    if entry.fallback_active {
        let _ = writeln!(out, "  WARNING: fallback heuristic active");
    }

    out
}

/// Render an ASCII calibration gauge [0.0 ... 1.0].
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
fn render_calibration_gauge(out: &mut String, score: f64) {
    let gauge_width: usize = 20;
    let pos = (score.clamp(0.0, 1.0) * gauge_width as f64).round() as usize;
    let mut bar = vec!['-'; gauge_width];
    if pos < gauge_width {
        bar[pos] = '|';
    } else {
        // Score is exactly 1.0 — place at end.
        bar[gauge_width - 1] = '|';
    }
    let label = if score >= 0.9 {
        "good"
    } else if score >= 0.7 {
        "fair"
    } else {
        "poor"
    };
    let bar_str: String = bar.into_iter().collect();
    let _ = writeln!(out, "  calibration: [{bar_str}] {score:.3} ({label})");
}

// ---------------------------------------------------------------------------
// Level 3 — debug (JSON dump + diff from previous)
// ---------------------------------------------------------------------------

/// Sliding window for tracking previous entries per component.
///
/// Used by [`level3`] to compute diffs between successive decisions
/// from the same component.
pub struct DiffContext {
    /// Recent entries keyed by component name.
    recent: BTreeMap<String, EvidenceLedger>,
}

impl DiffContext {
    /// Create a new empty diff context.
    pub fn new() -> Self {
        Self {
            recent: BTreeMap::new(),
        }
    }

    /// Render a Level 3 debug card: full JSON + diff from previous entry
    /// for the same component, then store this entry as the new "previous".
    pub fn level3(&mut self, entry: &EvidenceLedger) -> String {
        let mut out = String::with_capacity(4096);

        let _ = writeln!(out, "=== LEVEL 3 DEBUG: {} ===", entry.component);
        let _ = writeln!(out);

        // Full JSON dump (pretty-printed).
        let _ = writeln!(out, "  json:");
        match serde_json::to_string_pretty(entry) {
            Ok(json) => {
                for line in json.lines() {
                    let _ = writeln!(out, "    {line}");
                }
            }
            Err(e) => {
                let _ = writeln!(out, "    <serialization error: {e}>");
            }
        }
        let _ = writeln!(out);

        // Diff from previous.
        if let Some(prev) = self.recent.get(&entry.component) {
            let _ = writeln!(out, "  diff from previous:");
            render_diff(&mut out, prev, entry);
        } else {
            let _ = writeln!(
                out,
                "  diff: no previous entry for component={}",
                entry.component
            );
        }

        // Store current as the new "previous" for this component.
        self.recent.insert(entry.component.clone(), entry.clone());

        out
    }
}

impl Default for DiffContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Render field-by-field diff between two entries.
fn render_diff(out: &mut String, prev: &EvidenceLedger, curr: &EvidenceLedger) {
    let mut changed = 0_usize;

    if prev.action != curr.action {
        let _ = writeln!(out, "    action: {} -> {}", prev.action, curr.action);
        changed += 1;
    }

    if prev.ts_unix_ms != curr.ts_unix_ms {
        let delta_ms = i128::from(curr.ts_unix_ms) - i128::from(prev.ts_unix_ms);
        let _ = writeln!(
            out,
            "    ts_unix_ms: {} -> {} (delta: {delta_ms}ms)",
            prev.ts_unix_ms, curr.ts_unix_ms,
        );
        changed += 1;
    }

    if prev.posterior != curr.posterior {
        let _ = writeln!(
            out,
            "    posterior: {:?} -> {:?}",
            prev.posterior, curr.posterior
        );
        changed += 1;
    }

    if prev.expected_loss_by_action != curr.expected_loss_by_action {
        let _ = writeln!(out, "    expected_loss_by_action: changed");
        // Show per-action deltas.
        let mut all_actions: Vec<&String> = prev
            .expected_loss_by_action
            .keys()
            .chain(curr.expected_loss_by_action.keys())
            .collect();
        all_actions.sort();
        all_actions.dedup();
        for action in all_actions {
            let old = prev.expected_loss_by_action.get(action);
            let new = curr.expected_loss_by_action.get(action);
            match (old, new) {
                (Some(o), Some(n)) if (o - n).abs() > 1e-12 => {
                    let _ = writeln!(out, "      {action}: {o:.4} -> {n:.4}");
                }
                (Some(o), None) => {
                    let _ = writeln!(out, "      {action}: {o:.4} -> (removed)");
                }
                (None, Some(n)) => {
                    let _ = writeln!(out, "      {action}: (added) -> {n:.4}");
                }
                _ => {}
            }
        }
        changed += 1;
    }

    #[allow(clippy::float_cmp)]
    if prev.chosen_expected_loss != curr.chosen_expected_loss {
        let _ = writeln!(
            out,
            "    chosen_expected_loss: {:.4} -> {:.4}",
            prev.chosen_expected_loss, curr.chosen_expected_loss,
        );
        changed += 1;
    }

    #[allow(clippy::float_cmp)]
    if prev.calibration_score != curr.calibration_score {
        let _ = writeln!(
            out,
            "    calibration_score: {:.3} -> {:.3}",
            prev.calibration_score, curr.calibration_score,
        );
        changed += 1;
    }

    if prev.fallback_active != curr.fallback_active {
        let _ = writeln!(
            out,
            "    fallback_active: {} -> {}",
            prev.fallback_active, curr.fallback_active,
        );
        changed += 1;
    }

    if prev.top_features != curr.top_features {
        let _ = writeln!(
            out,
            "    top_features: {:?} -> {:?}",
            prev.top_features, curr.top_features
        );
        changed += 1;
    }

    let _ = writeln!(out, "    ({changed} field(s) changed)");
}

// ---------------------------------------------------------------------------
// HTML renderer
// ---------------------------------------------------------------------------

/// Calibration score CSS color (hex).
fn calibration_hex(score: f64) -> &'static str {
    if score >= 0.9 {
        "#22c55e" // green-500
    } else if score >= 0.7 {
        "#eab308" // yellow-500
    } else {
        "#ef4444" // red-500
    }
}

/// Render an HTML card with inline CSS for dashboard embedding.
///
/// Produces a self-contained `<div>` that renders without external stylesheets.
#[allow(clippy::too_many_lines)]
pub fn html(entry: &EvidenceLedger) -> String {
    let mut out = String::with_capacity(4096);
    let cal_hex = calibration_hex(entry.calibration_score);

    let _ = writeln!(
        out,
        "<div style=\"font-family:monospace;border:1px solid #334155;border-radius:8px;\
         padding:16px;max-width:600px;background:#0f172a;color:#e2e8f0;margin:8px 0\">"
    );

    // Header.
    let _ = writeln!(
        out,
        "  <div style=\"font-size:14px;font-weight:bold;color:#38bdf8;margin-bottom:8px\">\
         {} <span style=\"color:#94a3b8\">&rarr;</span> {}</div>",
        html_escape(&entry.component),
        html_escape(&entry.action),
    );

    // Metrics row.
    let _ = writeln!(
        out,
        "  <div style=\"display:flex;gap:16px;margin-bottom:12px;font-size:12px\">"
    );
    let _ = writeln!(
        out,
        "    <span>EL: <b>{:.4}</b></span>",
        entry.chosen_expected_loss
    );
    let _ = writeln!(
        out,
        "    <span>Cal: <b style=\"color:{cal_hex}\">{:.3}</b></span>",
        entry.calibration_score
    );
    if entry.fallback_active {
        let _ = writeln!(
            out,
            "    <span style=\"color:#eab308;font-weight:bold\">FALLBACK</span>"
        );
    }
    let _ = writeln!(out, "  </div>");

    // Posterior bars.
    if !entry.posterior.is_empty() {
        let _ = writeln!(
            out,
            "  <div style=\"margin-bottom:12px\"><div style=\"font-size:11px;\
             color:#94a3b8;margin-bottom:4px\">Posterior</div>"
        );
        let max_p = entry
            .posterior
            .iter()
            .copied()
            .fold(0.0_f64, f64::max)
            .max(1e-12);
        for (i, &p) in entry.posterior.iter().enumerate() {
            let pct = (p / max_p) * 100.0;
            let _ = writeln!(
                out,
                "    <div style=\"display:flex;align-items:center;gap:4px;font-size:11px;\
                 margin:2px 0\">\
                 <span style=\"width:24px;text-align:right;color:#94a3b8\">{i}</span>\
                 <div style=\"flex:1;background:#1e293b;border-radius:2px;height:14px\">\
                 <div style=\"width:{pct:.1}%;background:#3b82f6;height:100%;\
                 border-radius:2px\"></div></div>\
                 <span style=\"width:48px;text-align:right\">{p:.4}</span></div>"
            );
        }
        let _ = writeln!(out, "  </div>");
    }

    // Loss table.
    if !entry.expected_loss_by_action.is_empty() {
        let _ = writeln!(
            out,
            "  <div style=\"margin-bottom:12px\"><div style=\"font-size:11px;\
             color:#94a3b8;margin-bottom:4px\">Expected Losses</div>\
             <table style=\"width:100%;font-size:11px;border-collapse:collapse\">"
        );
        let mut actions: Vec<_> = entry.expected_loss_by_action.iter().collect();
        actions.sort_by(|a, b| a.0.cmp(b.0));
        for (action, &loss) in actions {
            let style = if **action == entry.action {
                "font-weight:bold;color:#38bdf8"
            } else {
                "color:#e2e8f0"
            };
            let _ = writeln!(
                out,
                "    <tr><td style=\"{style};padding:2px 8px 2px 0\">{}</td>\
                 <td style=\"{style};text-align:right;padding:2px 0\">{loss:.4}</td></tr>",
                html_escape(action),
            );
        }
        let _ = writeln!(out, "  </table></div>");
    }

    // Features.
    if !entry.top_features.is_empty() {
        let _ = writeln!(
            out,
            "  <div style=\"margin-bottom:8px\"><div style=\"font-size:11px;\
             color:#94a3b8;margin-bottom:4px\">Top Features</div>"
        );
        let max_w = entry
            .top_features
            .iter()
            .map(|(_, w)| *w)
            .fold(0.0_f64, f64::max)
            .max(1e-12);
        for (name, weight) in &entry.top_features {
            let pct = (weight / max_w) * 100.0;
            let _ = writeln!(
                out,
                "    <div style=\"display:flex;align-items:center;gap:4px;font-size:11px;\
                 margin:2px 0\">\
                 <span style=\"width:100px;color:#c084fc\">{}</span>\
                 <div style=\"flex:1;background:#1e293b;border-radius:2px;height:12px\">\
                 <div style=\"width:{pct:.1}%;background:#a855f7;height:100%;\
                 border-radius:2px\"></div></div>\
                 <span style=\"width:40px;text-align:right\">{weight:.3}</span></div>",
                html_escape(name),
            );
        }
        let _ = writeln!(out, "  </div>");
    }

    // Timestamp footer.
    let _ = writeln!(
        out,
        "  <div style=\"font-size:10px;color:#64748b;margin-top:8px\">ts: {}</div>",
        entry.ts_unix_ms
    );

    let _ = writeln!(out, "</div>");
    out
}

/// Minimal HTML entity escaping for untrusted content.
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Markdown renderer
// ---------------------------------------------------------------------------

/// Render a GitHub-flavored Markdown card for PR comments.
///
/// Produces a self-contained Markdown block suitable for embedding in
/// GitHub PR comments or issue bodies.
pub fn markdown(entry: &EvidenceLedger) -> String {
    let mut out = String::with_capacity(2048);

    // Header.
    let _ = writeln!(out, "## {} &rarr; {}", entry.component, entry.action);
    let _ = writeln!(out);

    // Metrics.
    let cal_emoji = if entry.calibration_score >= 0.9 {
        "green_circle"
    } else if entry.calibration_score >= 0.7 {
        "yellow_circle"
    } else {
        "red_circle"
    };
    let _ = write!(
        out,
        "**Expected Loss:** `{:.4}` | **Calibration:** :{cal_emoji}: `{:.3}`",
        entry.chosen_expected_loss, entry.calibration_score,
    );
    if entry.fallback_active {
        let _ = write!(out, " | :warning: **FALLBACK**");
    }
    let _ = writeln!(out);
    let _ = writeln!(out);

    // Posterior.
    if !entry.posterior.is_empty() {
        let _ = writeln!(out, "<details><summary>Posterior Distribution</summary>");
        let _ = writeln!(out);
        let _ = writeln!(out, "| Index | Probability |");
        let _ = writeln!(out, "|------:|------------:|");
        for (i, &p) in entry.posterior.iter().enumerate() {
            let _ = writeln!(out, "| {i} | {p:.4} |");
        }
        let _ = writeln!(out);
        let _ = writeln!(out, "</details>");
        let _ = writeln!(out);
    }

    // Loss table.
    if !entry.expected_loss_by_action.is_empty() {
        let mut actions: Vec<_> = entry.expected_loss_by_action.iter().collect();
        actions.sort_by(|a, b| a.0.cmp(b.0));
        let _ = writeln!(out, "| Action | Loss | |");
        let _ = writeln!(out, "|--------|-----:|---|");
        for (action, &loss) in actions {
            let marker = if **action == entry.action {
                ":arrow_left:"
            } else {
                ""
            };
            let _ = writeln!(out, "| {action} | {loss:.4} | {marker} |");
        }
        let _ = writeln!(out);
    }

    // Features.
    if !entry.top_features.is_empty() {
        let _ = writeln!(out, "**Features:** ");
        for (i, (name, weight)) in entry.top_features.iter().enumerate() {
            if i > 0 {
                let _ = write!(out, ", ");
            }
            let _ = write!(out, "`{name}`={weight:.3}");
        }
        let _ = writeln!(out);
        let _ = writeln!(out);
    }

    // Timestamp.
    let _ = writeln!(out, "---");
    let _ = writeln!(out, "*ts: {}*", entry.ts_unix_ms);

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EvidenceLedgerBuilder;

    fn test_entry() -> EvidenceLedger {
        EvidenceLedgerBuilder::new()
            .ts_unix_ms(1_700_000_000_000)
            .component("scheduler")
            .action("preempt")
            .posterior(vec![0.7, 0.2, 0.1])
            .expected_loss("preempt", 0.05)
            .expected_loss("continue", 0.30)
            .expected_loss("defer", 0.15)
            .chosen_expected_loss(0.05)
            .calibration_score(0.92)
            .fallback_active(false)
            .top_feature("queue_depth", 0.45)
            .top_feature("priority_gap", 0.30)
            .build()
            .unwrap()
    }

    #[test]
    fn level0_fits_120_chars() {
        let entry = test_entry();
        let line = level0(&entry);
        assert!(
            line.len() <= 120,
            "level0 output too long: {} chars: {line}",
            line.len()
        );
    }

    #[test]
    fn level0_contains_key_info() {
        let entry = test_entry();
        let line = level0(&entry);
        assert!(line.contains("scheduler"));
        assert!(line.contains("preempt"));
        assert!(line.contains("0.05"));
        assert!(line.contains("0.92"));
        assert!(!line.contains("FALLBACK"));
    }

    #[test]
    fn level0_fallback_shown() {
        let entry = EvidenceLedgerBuilder::new()
            .ts_unix_ms(1)
            .component("x")
            .action("y")
            .posterior(vec![1.0])
            .chosen_expected_loss(0.0)
            .calibration_score(0.5)
            .fallback_active(true)
            .build()
            .unwrap();
        let line = level0(&entry);
        assert!(line.contains("[FALLBACK]"));
    }

    #[test]
    fn level0_truncates_long_output() {
        let long_component = "a".repeat(200);
        let entry = EvidenceLedgerBuilder::new()
            .ts_unix_ms(1)
            .component(long_component)
            .action("y")
            .posterior(vec![1.0])
            .chosen_expected_loss(0.0)
            .calibration_score(0.5)
            .build()
            .unwrap();
        let line = level0(&entry);
        assert!(line.len() <= 120);
        assert!(line.ends_with("..."));
    }

    #[test]
    fn level0_ansi_contains_escape_codes() {
        let entry = test_entry();
        let line = level0_ansi(&entry);
        assert!(line.contains("\x1b["));
        assert!(line.contains("scheduler"));
    }

    #[test]
    fn level1_multiline() {
        let entry = test_entry();
        let output = level1(&entry);
        assert!(output.lines().count() >= 3, "level1 should be multi-line");
        assert!(output.contains("scheduler"));
        assert!(output.contains("preempt"));
        assert!(output.contains("queue_depth"));
        assert!(output.contains("priority_gap"));
    }

    #[test]
    fn level1_sorted_losses() {
        let entry = test_entry();
        let output = level1(&entry);
        // Losses should appear in alphabetical order.
        let losses_line = output.lines().find(|l| l.contains("losses:")).unwrap();
        let continue_pos = losses_line.find("continue").unwrap();
        let defer_pos = losses_line.find("defer").unwrap();
        let preempt_pos = losses_line.find("preempt").unwrap();
        assert!(continue_pos < defer_pos);
        assert!(defer_pos < preempt_pos);
    }

    #[test]
    fn level1_plain_no_ansi() {
        let entry = test_entry();
        let output = level1_plain(&entry);
        assert!(!output.contains("\x1b["));
        assert!(output.contains("scheduler"));
        assert!(output.contains("preempt"));
    }

    #[test]
    fn level1_fallback_warning() {
        let entry = EvidenceLedgerBuilder::new()
            .ts_unix_ms(1)
            .component("x")
            .action("y")
            .posterior(vec![1.0])
            .chosen_expected_loss(0.0)
            .calibration_score(0.5)
            .fallback_active(true)
            .build()
            .unwrap();
        let output = level1(&entry);
        assert!(output.contains("fallback"));
        let plain = level1_plain(&entry);
        assert!(plain.contains("fallback"));
    }

    #[test]
    fn calibration_color_thresholds() {
        assert_eq!(calibration_color(0.95), GREEN);
        assert_eq!(calibration_color(0.9), GREEN);
        assert_eq!(calibration_color(0.8), YELLOW);
        assert_eq!(calibration_color(0.7), YELLOW);
        assert_eq!(calibration_color(0.5), RED);
        assert_eq!(calibration_color(0.0), RED);
    }

    #[test]
    fn deterministic_output() {
        let entry = test_entry();
        assert_eq!(level0(&entry), level0(&entry));
        assert_eq!(level1(&entry), level1(&entry));
        assert_eq!(level1_plain(&entry), level1_plain(&entry));
        assert_eq!(level2(&entry), level2(&entry));
        assert_eq!(html(&entry), html(&entry));
        assert_eq!(markdown(&entry), markdown(&entry));
    }

    // ------------------------------------------------------------------
    // Level 2 tests
    // ------------------------------------------------------------------

    #[test]
    fn level2_contains_histogram() {
        let entry = test_entry();
        let output = level2(&entry);
        assert!(output.contains("posterior distribution:"));
        // Should have histogram bars with '#' characters.
        assert!(output.contains('#'));
        // Should list all posterior values.
        assert!(output.contains("0.7000"));
        assert!(output.contains("0.2000"));
        assert!(output.contains("0.1000"));
    }

    #[test]
    fn level2_histogram_scaling() {
        // Uniform posterior — all bars should be the same length.
        let entry = EvidenceLedgerBuilder::new()
            .ts_unix_ms(1)
            .component("test")
            .action("act")
            .posterior(vec![0.25, 0.25, 0.25, 0.25])
            .chosen_expected_loss(0.1)
            .calibration_score(0.8)
            .build()
            .unwrap();
        let output = level2(&entry);
        // All four bars should have the same number of '#' chars.
        let bar_lines: Vec<&str> = output
            .lines()
            .filter(|l| l.contains('|') && l.contains('#'))
            .collect();
        assert_eq!(bar_lines.len(), 4);
        let bar_lengths: Vec<usize> = bar_lines.iter().map(|l| l.matches('#').count()).collect();
        assert!(
            bar_lengths.iter().all(|&n| n == bar_lengths[0]),
            "uniform posterior should have equal bars: {bar_lengths:?}"
        );
    }

    #[test]
    fn level2_loss_matrix_table() {
        let entry = test_entry();
        let output = level2(&entry);
        assert!(output.contains("loss matrix:"));
        assert!(output.contains("action"));
        assert!(output.contains("preempt"));
        assert!(output.contains("continue"));
        assert!(output.contains("defer"));
        // Chosen action should be marked.
        let chosen_line = output
            .lines()
            .find(|l| l.contains("preempt") && l.contains('*'))
            .expect("chosen action should be marked with *");
        assert!(chosen_line.contains('*'));
    }

    #[test]
    fn level2_feature_bars() {
        let entry = test_entry();
        let output = level2(&entry);
        assert!(output.contains("feature importance:"));
        assert!(output.contains("queue_depth"));
        assert!(output.contains("priority_gap"));
        assert!(output.contains('='));
    }

    #[test]
    fn level2_calibration_gauge() {
        let entry = test_entry();
        let output = level2(&entry);
        assert!(output.contains("calibration:"));
        assert!(output.contains("0.920"));
        assert!(output.contains("good"));
    }

    #[test]
    fn level2_calibration_gauge_labels() {
        // Good.
        let good = EvidenceLedgerBuilder::new()
            .ts_unix_ms(1)
            .component("t")
            .action("a")
            .posterior(vec![1.0])
            .chosen_expected_loss(0.0)
            .calibration_score(0.95)
            .build()
            .unwrap();
        assert!(level2(&good).contains("good"));

        // Fair.
        let fair = EvidenceLedgerBuilder::new()
            .ts_unix_ms(1)
            .component("t")
            .action("a")
            .posterior(vec![1.0])
            .chosen_expected_loss(0.0)
            .calibration_score(0.75)
            .build()
            .unwrap();
        assert!(level2(&fair).contains("fair"));

        // Poor.
        let poor = EvidenceLedgerBuilder::new()
            .ts_unix_ms(1)
            .component("t")
            .action("a")
            .posterior(vec![1.0])
            .chosen_expected_loss(0.0)
            .calibration_score(0.3)
            .build()
            .unwrap();
        assert!(level2(&poor).contains("poor"));
    }

    #[test]
    fn level2_fallback_warning() {
        let entry = EvidenceLedgerBuilder::new()
            .ts_unix_ms(1)
            .component("x")
            .action("y")
            .posterior(vec![1.0])
            .chosen_expected_loss(0.0)
            .calibration_score(0.5)
            .fallback_active(true)
            .build()
            .unwrap();
        let output = level2(&entry);
        assert!(output.contains("WARNING: fallback heuristic active"));
    }

    #[test]
    fn level2_no_fallback_when_inactive() {
        let entry = test_entry();
        let output = level2(&entry);
        assert!(!output.contains("WARNING"));
        assert!(!output.contains("fallback"));
    }

    // ------------------------------------------------------------------
    // Level 3 tests
    // ------------------------------------------------------------------

    #[test]
    fn level3_contains_json() {
        let mut ctx = DiffContext::new();
        let entry = test_entry();
        let output = ctx.level3(&entry);
        assert!(output.contains("LEVEL 3 DEBUG"));
        assert!(output.contains("json:"));
        // Should contain pretty-printed JSON.
        assert!(output.contains("\"scheduler\""));
        assert!(output.contains("\"preempt\""));
    }

    #[test]
    fn level3_no_previous_message() {
        let mut ctx = DiffContext::new();
        let entry = test_entry();
        let output = ctx.level3(&entry);
        assert!(output.contains("no previous entry for component=scheduler"));
    }

    #[test]
    fn level3_diff_detects_changes() {
        let mut ctx = DiffContext::new();
        let entry1 = test_entry();
        let _ = ctx.level3(&entry1);

        // Second entry with different action and calibration.
        let entry2 = EvidenceLedgerBuilder::new()
            .ts_unix_ms(1_700_000_001_000)
            .component("scheduler")
            .action("defer")
            .posterior(vec![0.3, 0.5, 0.2])
            .expected_loss("preempt", 0.08)
            .expected_loss("continue", 0.25)
            .expected_loss("defer", 0.10)
            .chosen_expected_loss(0.10)
            .calibration_score(0.85)
            .top_feature("queue_depth", 0.35)
            .top_feature("priority_gap", 0.40)
            .build()
            .unwrap();
        let output = ctx.level3(&entry2);
        assert!(output.contains("diff from previous:"));
        assert!(output.contains("action: preempt -> defer"));
        assert!(output.contains("calibration_score:"));
        assert!(output.contains("field(s) changed"));
    }

    #[test]
    fn level3_diff_no_changes() {
        let mut ctx = DiffContext::new();
        let entry = test_entry();
        let _ = ctx.level3(&entry);
        let output = ctx.level3(&entry.clone());
        // All fields identical — should report 0 changes.
        assert!(output.contains("0 field(s) changed"));
    }

    #[test]
    fn level3_separate_components() {
        let mut ctx = DiffContext::new();

        let sched = test_entry();
        let _ = ctx.level3(&sched);

        // Different component — should show "no previous entry".
        let supervisor = EvidenceLedgerBuilder::new()
            .ts_unix_ms(2)
            .component("supervisor")
            .action("restart")
            .posterior(vec![0.8, 0.2])
            .chosen_expected_loss(0.02)
            .calibration_score(0.95)
            .build()
            .unwrap();
        let output = ctx.level3(&supervisor);
        assert!(output.contains("no previous entry for component=supervisor"));
    }

    #[test]
    fn level3_deterministic() {
        let entry = test_entry();
        let mut ctx1 = DiffContext::new();
        let mut ctx2 = DiffContext::new();
        assert_eq!(ctx1.level3(&entry), ctx2.level3(&entry));
    }

    // ------------------------------------------------------------------
    // HTML tests
    // ------------------------------------------------------------------

    #[test]
    fn html_contains_div() {
        let entry = test_entry();
        let output = html(&entry);
        assert!(output.contains("<div"));
        assert!(output.contains("</div>"));
    }

    #[test]
    fn html_contains_component_and_action() {
        let entry = test_entry();
        let output = html(&entry);
        assert!(output.contains("scheduler"));
        assert!(output.contains("preempt"));
    }

    #[test]
    fn html_has_inline_css() {
        let entry = test_entry();
        let output = html(&entry);
        assert!(output.contains("style=\""));
        assert!(output.contains("font-family"));
        assert!(output.contains("border"));
    }

    #[test]
    fn html_escapes_special_chars() {
        let entry = EvidenceLedgerBuilder::new()
            .ts_unix_ms(1)
            .component("<script>alert(1)</script>")
            .action("a&b")
            .posterior(vec![1.0])
            .chosen_expected_loss(0.0)
            .calibration_score(0.8)
            .build()
            .unwrap();
        let output = html(&entry);
        assert!(output.contains("&lt;script&gt;"));
        assert!(output.contains("a&amp;b"));
        assert!(!output.contains("<script>"));
    }

    #[test]
    fn html_posterior_bars() {
        let entry = test_entry();
        let output = html(&entry);
        // Should contain percentage-based bars.
        assert!(output.contains("width:"));
        assert!(output.contains("background:#3b82f6"));
    }

    #[test]
    fn html_loss_table() {
        let entry = test_entry();
        let output = html(&entry);
        assert!(output.contains("<table"));
        assert!(output.contains("</table>"));
    }

    #[test]
    fn html_fallback_badge() {
        let entry = EvidenceLedgerBuilder::new()
            .ts_unix_ms(1)
            .component("x")
            .action("y")
            .posterior(vec![1.0])
            .chosen_expected_loss(0.0)
            .calibration_score(0.5)
            .fallback_active(true)
            .build()
            .unwrap();
        let output = html(&entry);
        assert!(output.contains("FALLBACK"));
    }

    #[test]
    fn html_calibration_color_good() {
        assert_eq!(calibration_hex(0.95), "#22c55e");
    }

    #[test]
    fn html_calibration_color_fair() {
        assert_eq!(calibration_hex(0.75), "#eab308");
    }

    #[test]
    fn html_calibration_color_poor() {
        assert_eq!(calibration_hex(0.3), "#ef4444");
    }

    // ------------------------------------------------------------------
    // Markdown tests
    // ------------------------------------------------------------------

    #[test]
    fn markdown_has_header() {
        let entry = test_entry();
        let output = markdown(&entry);
        assert!(output.contains("## scheduler"));
    }

    #[test]
    fn markdown_has_metrics() {
        let entry = test_entry();
        let output = markdown(&entry);
        assert!(output.contains("Expected Loss"));
        assert!(output.contains("Calibration"));
        assert!(output.contains("0.0500"));
    }

    #[test]
    fn markdown_has_loss_table() {
        let entry = test_entry();
        let output = markdown(&entry);
        // GFM table markers.
        assert!(output.contains("| Action"));
        assert!(output.contains("|--"));
        // Chosen action marker.
        assert!(output.contains(":arrow_left:"));
    }

    #[test]
    fn markdown_has_posterior_details() {
        let entry = test_entry();
        let output = markdown(&entry);
        assert!(output.contains("<details>"));
        assert!(output.contains("Posterior Distribution"));
    }

    #[test]
    fn markdown_has_features() {
        let entry = test_entry();
        let output = markdown(&entry);
        assert!(output.contains("`queue_depth`"));
        assert!(output.contains("`priority_gap`"));
    }

    #[test]
    fn markdown_has_timestamp() {
        let entry = test_entry();
        let output = markdown(&entry);
        assert!(output.contains("1700000000000"));
    }

    #[test]
    fn markdown_fallback_warning() {
        let entry = EvidenceLedgerBuilder::new()
            .ts_unix_ms(1)
            .component("x")
            .action("y")
            .posterior(vec![1.0])
            .chosen_expected_loss(0.0)
            .calibration_score(0.5)
            .fallback_active(true)
            .build()
            .unwrap();
        let output = markdown(&entry);
        assert!(output.contains("FALLBACK"));
        assert!(output.contains(":warning:"));
    }

    #[test]
    fn markdown_no_fallback_when_inactive() {
        let entry = test_entry();
        let output = markdown(&entry);
        assert!(!output.contains("FALLBACK"));
    }

    #[test]
    fn markdown_no_ansi() {
        let entry = test_entry();
        let output = markdown(&entry);
        assert!(!output.contains("\x1b["));
    }
}
