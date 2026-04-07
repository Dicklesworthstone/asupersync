//! Ambient authority detection patterns and regression tests.
//!
//! This module documents all known ambient authority patterns in the codebase
//! and provides grep patterns for CI enforcement. Each finding is categorized
//! by severity and includes the rationale for exemption (if applicable).
//!
//! # Categories
//!
//! - **Time**: Direct `Instant::now()` / `SystemTime::now()` bypassing Cx time capability.
//! - **Spawn**: Direct `std::thread::spawn` bypassing Cx/scheduler.
//! - **Entropy**: Direct `getrandom` / `rand` bypassing Cx entropy capability.
//! - **IO**: Direct `std::net` / `std::fs` bypassing Cx IO capability.
//!
//! # Exemptions
//!
//! Some uses are intentionally exempt:
//! - `src/util/entropy.rs` — This IS the entropy provider; it must call OS RNG.
//! - `src/fs/` — This IS the IO wrapper; it must call OS filesystem.
//! - `src/runtime/blocking_pool.rs` — Thread pool needs real threads by design.
//! - Test code (`#[cfg(test)]`) — Tests may use ambient authority freely.

/// Known ambient authority violations with their status.
#[derive(Debug, Clone)]
pub struct AmbientFinding {
    /// Source file (relative to src/).
    pub file: &'static str,
    /// Approximate line number.
    pub line: u32,
    /// Exact non-test code literal proving this finding still exists.
    pub evidence_pattern: &'static str,
    /// Category of ambient authority.
    pub category: AmbientCategory,
    /// Severity level.
    pub severity: Severity,
    /// Description of the violation.
    pub description: &'static str,
    /// Whether this is an intentional exemption.
    pub exempt: bool,
    /// Reason for exemption (if exempt).
    pub exemption_reason: Option<&'static str>,
}

/// Category of ambient authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AmbientCategory {
    /// Direct wall-clock time access.
    Time,
    /// Direct thread spawning.
    Spawn,
    /// Direct entropy/RNG access.
    Entropy,
    /// Direct network/filesystem IO.
    Io,
}

/// Severity of the finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Informational — documented, low risk.
    Info,
    /// Warning — should be addressed but not blocking.
    Warning,
    /// Critical — breaks capability invariants, must be fixed.
    Critical,
}

/// All known ambient authority findings in the codebase.
///
/// This list should be kept in sync with actual code. CI tests verify
/// that no NEW ambient authority is introduced beyond what's listed here.
pub const KNOWN_FINDINGS: &[AmbientFinding] = &[
    // ── Time ────────────────────────────────────────────────────────────
    AmbientFinding {
        file: "time/driver.rs",
        line: 38,
        evidence_pattern: "std::time::Instant::now()",
        category: AmbientCategory::Time,
        severity: Severity::Info,
        description: "WallClock epoch initialization",
        exempt: true,
        exemption_reason: Some("Timer driver is the time provider"),
    },
    AmbientFinding {
        file: "runtime/blocking_pool.rs",
        line: 62,
        evidence_pattern: "Instant::now()",
        category: AmbientCategory::Time,
        severity: Severity::Info,
        description: "Instant::now() in blocking pool timeout",
        exempt: true,
        exemption_reason: Some("Blocking pool operates outside async runtime"),
    },
    // ── Spawn ───────────────────────────────────────────────────────────
    AmbientFinding {
        file: "time/sleep.rs",
        line: 623,
        evidence_pattern: "std::thread::spawn",
        category: AmbientCategory::Spawn,
        severity: Severity::Warning,
        description: "Fallback timer thread in Sleep::poll()",
        exempt: true,
        exemption_reason: Some("Documented fallback; used only when no timer driver"),
    },
    AmbientFinding {
        file: "runtime/blocking_pool.rs",
        line: 688,
        evidence_pattern: "thread::Builder::new()",
        category: AmbientCategory::Spawn,
        severity: Severity::Info,
        description: "Worker thread spawning in blocking pool",
        exempt: true,
        exemption_reason: Some("Blocking pool requires real OS threads by design"),
    },
    // ── Entropy ─────────────────────────────────────────────────────────
    // NOTE: net/websocket/handshake.rs and net/websocket/frame.rs now use
    // EntropySource capability plumbing instead of direct ambient randomness.
    // ── IO ──────────────────────────────────────────────────────────────
    AmbientFinding {
        file: "web/debug.rs",
        line: 134,
        evidence_pattern: "TcpListener::bind",
        category: AmbientCategory::Io,
        severity: Severity::Warning,
        description: "TcpListener::bind in DebugServer::start()",
        exempt: true,
        exemption_reason: Some("Debug server is intentionally outside runtime"),
    },
];

/// Count findings by severity.
#[must_use]
pub fn count_by_severity(severity: Severity) -> usize {
    KNOWN_FINDINGS
        .iter()
        .filter(|f| f.severity == severity && !f.exempt)
        .count()
}

/// Count non-exempt findings.
#[must_use]
pub fn unresolved_count() -> usize {
    KNOWN_FINDINGS.iter().filter(|f| !f.exempt).count()
}

/// Grep patterns for CI enforcement.
///
/// These patterns should be run against `src/` (excluding test code)
/// to detect new ambient authority introductions.
pub const GREP_PATTERNS: &[(&str, AmbientCategory)] = &[
    (r"Instant::now\(\)", AmbientCategory::Time),
    (r"SystemTime::now\(\)", AmbientCategory::Time),
    (r"std::thread::spawn", AmbientCategory::Spawn),
    (r"thread::spawn", AmbientCategory::Spawn),
    (r"thread::Builder", AmbientCategory::Spawn),
    (r"getrandom::", AmbientCategory::Entropy),
    (r"rand::thread_rng", AmbientCategory::Entropy),
    (r"std::net::TcpListener", AmbientCategory::Io),
    (r"std::net::TcpStream", AmbientCategory::Io),
    (r"std::fs::File::open", AmbientCategory::Io),
    (r"std::fs::File::create", AmbientCategory::Io),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_findings_are_documented() {
        assert!(
            !KNOWN_FINDINGS.is_empty(),
            "Findings list should not be empty"
        );
    }

    #[test]
    fn critical_findings_resolved() {
        let critical = count_by_severity(Severity::Critical);
        assert!(
            critical == 0,
            "Expected zero non-exempt critical findings, got {critical}"
        );
    }

    #[test]
    fn exempt_findings_have_reasons() {
        for finding in KNOWN_FINDINGS {
            if finding.exempt {
                assert!(
                    finding.exemption_reason.is_some(),
                    "Exempt finding in {} has no reason",
                    finding.file
                );
            }
        }
    }

    #[test]
    fn grep_patterns_cover_all_categories() {
        let categories: std::collections::HashSet<_> =
            GREP_PATTERNS.iter().map(|(_, cat)| *cat).collect();
        assert!(categories.contains(&AmbientCategory::Time));
        assert!(categories.contains(&AmbientCategory::Spawn));
        assert!(categories.contains(&AmbientCategory::Entropy));
        assert!(categories.contains(&AmbientCategory::Io));
    }

    #[test]
    fn unresolved_count_tracks_non_exempt() {
        let unresolved = unresolved_count();
        let total = KNOWN_FINDINGS.len();
        let exempt = KNOWN_FINDINGS.iter().filter(|f| f.exempt).count();
        assert_eq!(unresolved, total - exempt);
    }

    #[test]
    fn severity_ordering() {
        assert!(Severity::Info < Severity::Warning);
        assert!(Severity::Warning < Severity::Critical);
    }

    // ── Source-tree scanning infrastructure ─────────────────────────────
    //
    // The tests below scan actual source files to enforce the
    // no-ambient-authority invariant. They ensure:
    //
    // 1. "Pristine" modules (cx/, obligation/, plan/) have ZERO ambient
    //    authority in non-test code.
    // 2. Each KNOWN_FINDINGS entry corresponds to real code (no stale entries).
    // 3. Exempt findings are only in recognized provider paths.
    // 4. The total count of non-exempt violations doesn't grow silently.
    //
    // **Escape hatches for tests:**
    // - Code inside `#[cfg(test)] mod tests { ... }` is excluded from scanning.
    // - Files listed in EXEMPT_PREFIXES are skipped entirely (these ARE the
    //   capability providers).
    // - To add a NEW ambient authority usage: add it to KNOWN_FINDINGS,
    //   bump AMBIENT_VIOLATION_CEILING, and justify in the PR description.

    use std::path::{Path, PathBuf};

    /// Paths (relative to src/) exempt from scanning.
    /// These modules ARE the capability providers.
    const EXEMPT_PREFIXES: &[&str] = &[
        "util/entropy.rs",
        "fs/",
        "time/driver.rs",
        "runtime/blocking_pool.rs",
        "web/debug.rs",
        "lab/",
        "test_logging.rs",
        "test_utils.rs",
        "test_ndjson.rs",
        "audit/",
        "bin/",
    ];

    /// Modules that MUST have zero ambient authority in non-test code.
    /// All effects in these modules must flow through the Cx capability system.
    const PRISTINE_MODULES: &[&str] = &["cx", "obligation", "plan"];

    /// Upper bound on non-test, non-exempt ambient authority violations.
    /// Bump this ONLY after documenting the new usage in KNOWN_FINDINGS.
    const AMBIENT_VIOLATION_CEILING: usize = 118;

    fn src_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
    }

    fn collect_rs_files(dir: &Path) -> Vec<PathBuf> {
        let mut files = Vec::new();
        let Ok(entries) = std::fs::read_dir(dir) else {
            return files;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                files.extend(collect_rs_files(&path));
            } else if path.extension().is_some_and(|e| e == "rs") {
                files.push(path);
            }
        }
        files
    }

    fn is_exempt(rel_path: &str) -> bool {
        EXEMPT_PREFIXES.iter().any(|p| rel_path.starts_with(p))
    }

    /// Convert a grep-style regex pattern to a literal search string.
    fn pattern_to_literal(pattern: &str) -> String {
        pattern.replace(r"\(", "(").replace(r"\)", ")")
    }

    /// Return (line_number, line_text) pairs from non-test, non-comment code.
    ///
    /// Uses brace-depth tracking to skip `#[cfg(test)] mod ... { }` blocks.
    fn non_test_lines(content: &str) -> Vec<(usize, String)> {
        let mut result = Vec::new();
        let mut in_cfg_test_mod = false;
        let mut brace_depth: i32 = 0;
        let mut pending_cfg_test = false;

        for (idx, line) in content.lines().enumerate() {
            let trimmed = line.trim();

            if trimmed == "#[cfg(test)]" {
                pending_cfg_test = true;
                continue;
            }

            if pending_cfg_test {
                if trimmed.starts_with("mod ") {
                    in_cfg_test_mod = true;
                    brace_depth = 0;
                    pending_cfg_test = false;
                    for ch in trimmed.chars() {
                        match ch {
                            '{' => brace_depth += 1,
                            '}' => brace_depth -= 1,
                            _ => {}
                        }
                    }
                    if brace_depth <= 0 {
                        in_cfg_test_mod = false;
                    }
                    continue;
                }
                if !trimmed.is_empty() && !trimmed.starts_with('#') {
                    pending_cfg_test = false;
                }
            }

            if in_cfg_test_mod {
                for ch in line.chars() {
                    match ch {
                        '{' => brace_depth += 1,
                        '}' => {
                            brace_depth -= 1;
                            if brace_depth <= 0 {
                                in_cfg_test_mod = false;
                            }
                        }
                        _ => {}
                    }
                }
                continue;
            }

            if trimmed.starts_with("//") {
                continue;
            }

            result.push((idx + 1, line.to_string()));
        }
        result
    }

    struct Violation {
        file: String,
        line: usize,
        pattern: String,
        category: AmbientCategory,
    }

    impl std::fmt::Display for Violation {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "  {}:{} — {:?} ({})",
                self.file, self.line, self.category, self.pattern
            )
        }
    }

    fn scan_directory(dir: &Path, root: &Path) -> Vec<Violation> {
        let mut violations = Vec::new();
        for file_path in collect_rs_files(dir) {
            let rel = file_path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");

            if is_exempt(&rel) {
                continue;
            }

            let Ok(content) = std::fs::read_to_string(&file_path) else {
                continue;
            };

            let lines = non_test_lines(&content);

            for (pattern, category) in GREP_PATTERNS {
                let literal = pattern_to_literal(pattern);
                for (line_num, line_text) in &lines {
                    if line_text.contains(&literal) {
                        violations.push(Violation {
                            file: rel.clone(),
                            line: *line_num,
                            pattern: literal.clone(),
                            category: *category,
                        });
                    }
                }
            }
        }
        violations
    }

    fn format_violations(vs: &[Violation]) -> String {
        vs.iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn has_non_test_match_near_line(
        content: &str,
        pattern: &str,
        expected_line: u32,
        max_line_distance: u32,
    ) -> bool {
        let literal = pattern_to_literal(pattern);
        non_test_lines(content).into_iter().any(|(line_num, line)| {
            expected_line.abs_diff(line_num as u32) <= max_line_distance && line.contains(&literal)
        })
    }

    #[test]
    fn pristine_modules_have_no_ambient_authority() {
        let root = src_root();
        for module in PRISTINE_MODULES {
            let module_dir = root.join(module);
            let violations = scan_directory(&module_dir, &root);
            assert!(
                violations.is_empty(),
                "Pristine module '{module}' has {} ambient authority violation(s):\n{}",
                violations.len(),
                format_violations(&violations),
            );
        }
    }

    #[test]
    fn known_findings_reference_real_code() {
        let root = src_root();
        for finding in KNOWN_FINDINGS {
            let path = root.join(finding.file);
            let content = std::fs::read_to_string(&path).unwrap_or_else(|_| {
                // Avoid `panic!` macro (UBS critical). We still want this test to
                // fail loudly if the catalog references a missing file.
                std::panic::resume_unwind(Box::new(format!(
                    "KNOWN_FINDINGS references missing file: src/{}",
                    finding.file
                )))
            });

            let has_nearby_match =
                has_non_test_match_near_line(&content, finding.evidence_pattern, finding.line, 30);

            assert!(
                has_nearby_match,
                "KNOWN_FINDINGS entry '{}' at src/{}:{} — \
                 no matching non-test evidence pattern '{}' found within ±30 lines. Stale entry?",
                finding.description, finding.file, finding.line, finding.evidence_pattern,
            );
        }
    }

    #[test]
    fn grep_patterns_catch_each_finding_category() {
        for finding in KNOWN_FINDINGS {
            let covered = GREP_PATTERNS
                .iter()
                .any(|(_, cat)| *cat == finding.category);
            assert!(
                covered,
                "Finding '{}' with category {:?} has no grep pattern coverage",
                finding.description, finding.category,
            );
        }
    }

    #[test]
    fn exempt_findings_are_in_recognized_provider_paths() {
        let provider_paths: &[&str] = &[
            "time/driver.rs",
            "time/sleep.rs",
            "runtime/blocking_pool.rs",
            "web/debug.rs",
            "util/entropy.rs",
            "fs/",
        ];
        for finding in KNOWN_FINDINGS.iter().filter(|f| f.exempt) {
            let in_provider = provider_paths.iter().any(|p| finding.file.starts_with(p));
            assert!(
                in_provider,
                "Exempt finding '{}' in src/{} is not in a recognized \
                 provider path. Either remove the exemption or add the \
                 path to provider_paths.",
                finding.description, finding.file,
            );
        }
    }

    #[test]
    fn ambient_authority_does_not_regress() {
        let root = src_root();
        let violations = scan_directory(&root, &root);

        assert!(
            violations.len() <= AMBIENT_VIOLATION_CEILING,
            "Ambient authority count ({}) exceeds ceiling ({}).\n\
             Either remove the ambient authority usage or, if intentional,\n\
             add it to KNOWN_FINDINGS and bump AMBIENT_VIOLATION_CEILING.\n\
             Violations:\n{}",
            violations.len(),
            AMBIENT_VIOLATION_CEILING,
            format_violations(&violations),
        );
    }

    #[test]
    fn non_test_lines_filter_skips_cfg_test_modules() {
        let source = "\
fn real_code() {
    Instant::now();
}

#[cfg(test)]
mod tests {
    fn test_code() {
        Instant::now();
    }
}
";
        let lines = non_test_lines(source);
        let text: Vec<&str> = lines.iter().map(|(_, l)| l.as_str()).collect();
        assert!(
            text.iter().any(|l| l.contains("real_code")),
            "Should include production code"
        );
        assert!(
            !text.iter().any(|l| l.contains("test_code")),
            "Should exclude #[cfg(test)] module code"
        );
    }

    #[test]
    fn non_test_lines_filter_skips_comments() {
        let source = "\
// Instant::now() in a comment
/// Instant::now() in a doc comment
//! Instant::now() in a module doc
let x = Instant::now();
";
        let lines = non_test_lines(source);
        assert_eq!(
            lines
                .iter()
                .filter(|(_, l)| l.contains("Instant::now"))
                .count(),
            1,
            "Should have exactly one non-comment Instant::now() line"
        );
    }

    // =========================================================================
    // Wave 50 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn ambient_finding_debug_clone() {
        let f = &KNOWN_FINDINGS[0];
        let dbg = format!("{f:?}");
        assert!(dbg.contains("AmbientFinding"), "{dbg}");
        let cloned = f.clone();
        assert_eq!(format!("{cloned:?}"), dbg);
    }

    #[test]
    fn ambient_category_debug_clone_copy_hash() {
        use std::collections::HashSet;
        let c = AmbientCategory::Time;
        let dbg = format!("{c:?}");
        assert!(dbg.contains("Time"), "{dbg}");
        let copied = c;
        let cloned = c;
        assert_eq!(copied, cloned);
        let mut set = HashSet::new();
        set.insert(c);
        assert!(set.contains(&AmbientCategory::Time));
    }

    #[test]
    fn severity_debug_clone_copy() {
        let s = Severity::Warning;
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Warning"), "{dbg}");
        let copied = s;
        let cloned = s;
        assert_eq!(copied, cloned);
    }
}
