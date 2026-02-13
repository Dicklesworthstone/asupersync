//! Galaxy-brain card renderer for [`EvidenceLedger`] entries (bd-qaaxt.3).
//!
//! Produces human-readable summaries at two levels:
//!
//! - **Level 0** (one-liner): fits in a single 120-char terminal line.
//! - **Level 1** (paragraph): multi-line block with ANSI colors.
//!
//! The renderer is stateless and deterministic — identical inputs always
//! produce identical output.
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
//! let paragraph = render::level1(&entry);
//! assert!(paragraph.contains("scheduler"));
//! ```

use crate::EvidenceLedger;
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
    }
}
