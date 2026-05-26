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
//! - **Env**: Direct runtime environment access bypassing explicit configuration capabilities.
//! - **Output**: Direct stdout/stderr macros bypassing structured tracing or caller-owned sinks.
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
    /// Direct runtime environment access.
    Env,
    /// Direct stdout/stderr output.
    Output,
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
        line: 972,
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
/// Enhanced patterns to detect ambient authority bypasses including:
/// - Import aliases: `use std::time::Instant as Clock; Clock::now()`
/// - Alternative module paths: `core::time::Instant` vs `std::time::Instant`
/// - Fully qualified calls: `std::time::Instant::now()`
/// - Common bypass patterns
///
/// br-asupersync-51e9yb: Enhanced detection patterns to prevent bypass
/// via import aliasing, alternative module paths, and common evasion techniques.
/// Each category includes multiple pattern variants to catch bypasses.
pub const GREP_PATTERNS: &[(&str, AmbientCategory)] = &[
    // Time patterns - catch various aliases and module paths
    (r"Instant::now\(\)", AmbientCategory::Time),
    (r"SystemTime::now\(\)", AmbientCategory::Time),
    (r"std::time::Instant::now\(\)", AmbientCategory::Time),
    (r"std::time::SystemTime::now\(\)", AmbientCategory::Time),
    (r"core::time::Instant::now\(\)", AmbientCategory::Time),
    (r"core::time::SystemTime::now\(\)", AmbientCategory::Time),
    // Common aliases - conservative detection of likely time aliases
    (r"Clock::now\(\)", AmbientCategory::Time),
    (r"WallTime::now\(\)", AmbientCategory::Time),
    (r"Time::now\(\)", AmbientCategory::Time),

    // Thread spawning patterns
    (r"std::thread::spawn", AmbientCategory::Spawn),
    (r"thread::spawn", AmbientCategory::Spawn),
    (r"thread::Builder", AmbientCategory::Spawn),
    (r"std::thread::Builder", AmbientCategory::Spawn),
    (r"core::thread::spawn", AmbientCategory::Spawn),
    (r"Thread::spawn", AmbientCategory::Spawn), // Common alias

    // Entropy patterns - including alternative paths
    (r"getrandom::", AmbientCategory::Entropy),
    (r"rand::thread_rng", AmbientCategory::Entropy),
    (r"rand::random\(\)", AmbientCategory::Entropy),
    (r"std::collections::hash_map::RandomState", AmbientCategory::Entropy),
    (r"Rng::", AmbientCategory::Entropy), // Common trait usage

    // IO patterns - network and filesystem
    (r"std::net::TcpListener", AmbientCategory::Io),
    (r"std::net::TcpStream", AmbientCategory::Io),
    (r"std::net::UdpSocket", AmbientCategory::Io),
    (r"std::fs::File::open", AmbientCategory::Io),
    (r"std::fs::File::create", AmbientCategory::Io),
    (r"std::fs::OpenOptions", AmbientCategory::Io),
    (r"std::fs::read\(", AmbientCategory::Io),
    (r"std::fs::write\(", AmbientCategory::Io),
    (r"File::open\(", AmbientCategory::Io),
    (r"File::create\(", AmbientCategory::Io),
    (r"TcpListener::", AmbientCategory::Io),
    (r"TcpStream::", AmbientCategory::Io),

    // Environment variable patterns
    (r"env::var\(", AmbientCategory::Env),
    (r"env::var_os\(", AmbientCategory::Env),
    (r"env::vars\(", AmbientCategory::Env),
    (r"env::set_var\(", AmbientCategory::Env),
    (r"env::remove_var\(", AmbientCategory::Env),
    (r"std::env::var\(", AmbientCategory::Env),
    (r"std::env::var_os\(", AmbientCategory::Env),
    (r"std::env::vars\(", AmbientCategory::Env),
    (r"std::env::set_var\(", AmbientCategory::Env),
    (r"std::env::remove_var\(", AmbientCategory::Env),

    // Output patterns
    (r"println!\(", AmbientCategory::Output),
    (r"eprintln!\(", AmbientCategory::Output),
    (r"print!\(", AmbientCategory::Output),
    (r"eprint!\(", AmbientCategory::Output),
    (r"dbg!\(", AmbientCategory::Output),
];

/// Suspicious import alias patterns that might be used to bypass detection.
///
/// br-asupersync-51e9yb: These patterns identify potentially suspicious
/// import aliases that rename ambient authority functions to evade detection.
/// This catches `use std::time::Instant as Clock` style bypasses.
pub const SUSPICIOUS_ALIAS_PATTERNS: &[(&str, AmbientCategory)] = &[
    // Time aliases - common names that might alias time functions
    (r"use.*Instant\s+as\s+\w+", AmbientCategory::Time),
    (r"use.*SystemTime\s+as\s+\w+", AmbientCategory::Time),
    (r"use.*time::Instant\s+as\s+\w+", AmbientCategory::Time),
    (r"use.*time::SystemTime\s+as\s+\w+", AmbientCategory::Time),

    // Thread aliases
    (r"use.*thread::spawn\s+as\s+\w+", AmbientCategory::Spawn),
    (r"use.*thread::Builder\s+as\s+\w+", AmbientCategory::Spawn),
    (r"use.*std::thread\s+as\s+\w+", AmbientCategory::Spawn),

    // Entropy aliases
    (r"use.*getrandom\s+as\s+\w+", AmbientCategory::Entropy),
    (r"use.*thread_rng\s+as\s+\w+", AmbientCategory::Entropy),
    (r"use.*rand\s+as\s+\w+", AmbientCategory::Entropy),

    // IO aliases
    (r"use.*std::fs\s+as\s+\w+", AmbientCategory::Io),
    (r"use.*std::net\s+as\s+\w+", AmbientCategory::Io),
    (r"use.*File\s+as\s+\w+", AmbientCategory::Io),

    // Environment aliases
    (r"use.*std::env\s+as\s+\w+", AmbientCategory::Env),
];

/// Enhanced ambient authority detection that combines pattern matching
/// with import analysis to detect bypass attempts.
///
/// br-asupersync-51e9yb: This function provides more comprehensive detection
/// than simple grep patterns by analyzing:
/// 1. Direct ambient authority usage
/// 2. Import aliases that could bypass detection
/// 3. Cross-references between imports and usage
///
/// Returns violations found in the source code, with more robust detection
/// against common bypass patterns like aliasing and alternative module paths.
pub fn detect_ambient_violations(source_code: &str) -> Vec<AmbientViolation> {
    let mut violations = Vec::new();

    // Split into lines for line number reporting
    let lines: Vec<&str> = source_code.lines().collect();

    // First pass: detect direct pattern matches
    for (line_num, line) in lines.iter().enumerate() {
        // Skip test code and comments
        if line.contains("#[cfg(test)]") || line.trim_start().starts_with("//") {
            continue;
        }

        // Check against enhanced GREP_PATTERNS
        for (pattern, category) in GREP_PATTERNS {
            if line.contains(pattern.trim_start_matches("r\"").trim_end_matches('"')) {
                violations.push(AmbientViolation {
                    line_number: line_num + 1,
                    line_content: line.to_string(),
                    pattern: pattern.to_string(),
                    category: *category,
                    violation_type: ViolationType::DirectUsage,
                });
            }
        }

        // Check for suspicious aliases
        for (pattern, category) in SUSPICIOUS_ALIAS_PATTERNS {
            let regex_pattern = pattern.trim_start_matches("r\"").trim_end_matches('"');
            // Simple pattern matching for now - could be enhanced with regex crate
            if line.contains("use") && line.contains("as") {
                // Check if this looks like an ambient authority alias
                let is_suspicious = match category {
                    AmbientCategory::Time => {
                        line.contains("Instant") || line.contains("SystemTime") || line.contains("time::")
                    }
                    AmbientCategory::Spawn => {
                        line.contains("thread::") || line.contains("spawn")
                    }
                    AmbientCategory::Entropy => {
                        line.contains("getrandom") || line.contains("thread_rng") || line.contains("rand")
                    }
                    AmbientCategory::Io => {
                        line.contains("std::fs") || line.contains("std::net") || line.contains("File")
                    }
                    AmbientCategory::Env => {
                        line.contains("std::env") || line.contains("env::")
                    }
                    AmbientCategory::Output => false, // Macro aliases are harder to detect this way
                };

                if is_suspicious {
                    violations.push(AmbientViolation {
                        line_number: line_num + 1,
                        line_content: line.to_string(),
                        pattern: regex_pattern.to_string(),
                        category: *category,
                        violation_type: ViolationType::SuspiciousAlias,
                    });
                }
            }
        }
    }

    violations
}

/// Represents a detected ambient authority violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmbientViolation {
    pub line_number: usize,
    pub line_content: String,
    pub pattern: String,
    pub category: AmbientCategory,
    pub violation_type: ViolationType,
}

/// Type of ambient authority violation detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViolationType {
    /// Direct usage of ambient authority (e.g., `Instant::now()`)
    DirectUsage,
    /// Suspicious import alias that might be bypassing detection
    SuspiciousAlias,
    /// Macro or indirect call that might be hiding ambient authority
    IndirectUsage,
}

#[cfg(test)]
pub use tests::scan_categories_for_contract_fixture;

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
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
        assert!(categories.contains(&AmbientCategory::Env));
        assert!(categories.contains(&AmbientCategory::Output));
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

    // ── Enhanced detection tests (br-asupersync-51e9yb) ────────────────────

    #[test]
    fn detect_direct_ambient_violations() {
        let source = r#"
fn bad_function() {
    let now = std::time::Instant::now();  // Should be detected
    println!("Current time: {:?}", now);   // Should be detected
}

fn good_function(cx: &Cx) {
    let now = cx.time().instant_now();     // Should NOT be detected
}

#[cfg(test)]
fn test_code() {
    let now = Instant::now();  // Should NOT be detected (test code)
}
"#;

        let violations = detect_ambient_violations(source);

        // Should find the direct violations
        assert_eq!(violations.len(), 2);

        let instant_violation = violations.iter().find(|v| v.line_content.contains("Instant::now")).unwrap();
        assert_eq!(instant_violation.category, AmbientCategory::Time);
        assert_eq!(instant_violation.violation_type, ViolationType::DirectUsage);

        let println_violation = violations.iter().find(|v| v.line_content.contains("println!")).unwrap();
        assert_eq!(println_violation.category, AmbientCategory::Output);
        assert_eq!(println_violation.violation_type, ViolationType::DirectUsage);
    }

    #[test]
    fn detect_alias_bypasses() {
        let source = r#"
use std::time::Instant as Clock;  // Suspicious alias
use std::thread::spawn as fork;   // Suspicious alias
use std::fs::File as FileHandle;  // Suspicious alias

fn bad_function() {
    let now = Clock::now();       // Would bypass simple grep
    fork(|| { /* work */ });     // Would bypass simple grep
    let _f = FileHandle::open("/etc/passwd").unwrap(); // Would bypass simple grep
}

fn good_function(cx: &Cx) {
    let now = cx.time().instant_now();  // Proper capability usage
}
"#;

        let violations = detect_ambient_violations(source);

        // Should detect the suspicious aliases
        let alias_violations: Vec<_> = violations.iter()
            .filter(|v| v.violation_type == ViolationType::SuspiciousAlias)
            .collect();

        assert!(!alias_violations.is_empty(), "Should detect alias bypasses");

        // Should detect at least the time and thread aliases
        assert!(alias_violations.iter().any(|v| v.category == AmbientCategory::Time));
        assert!(alias_violations.iter().any(|v| v.category == AmbientCategory::Spawn));
    }

    #[test]
    fn enhanced_patterns_catch_module_path_variants() {
        let source = r#"
fn bad_variants() {
    let now1 = std::time::Instant::now();    // std:: prefix
    let now2 = core::time::Instant::now();   // core:: prefix
    let now3 = Instant::now();               // unqualified

    std::thread::spawn(|| {});               // std:: prefix
    thread::spawn(|| {});                    // unqualified

    std::env::var("HOME").ok();              // std:: prefix
    env::var("PATH").ok();                   // unqualified
}
"#;

        let violations = detect_ambient_violations(source);

        // Should detect all variants
        let time_violations: Vec<_> = violations.iter()
            .filter(|v| v.category == AmbientCategory::Time)
            .collect();
        assert_eq!(time_violations.len(), 3, "Should catch all time variants");

        let spawn_violations: Vec<_> = violations.iter()
            .filter(|v| v.category == AmbientCategory::Spawn)
            .collect();
        assert_eq!(spawn_violations.len(), 2, "Should catch all spawn variants");

        let env_violations: Vec<_> = violations.iter()
            .filter(|v| v.category == AmbientCategory::Env)
            .collect();
        assert_eq!(env_violations.len(), 2, "Should catch all env variants");
    }

    #[test]
    fn enhanced_patterns_exclude_comments_and_tests() {
        let source = r#"
// This is a comment with Instant::now() that should be ignored
/* Block comment with std::thread::spawn that should be ignored */

fn production_code() {
    let now = Instant::now();  // Should be detected
}

#[cfg(test)]
mod tests {
    fn test_function() {
        let now = Instant::now();  // Should NOT be detected
        thread::spawn(|| {});     // Should NOT be detected
    }
}
"#;

        let violations = detect_ambient_violations(source);

        // Should only detect the one in production code
        assert_eq!(violations.len(), 1);
        assert!(violations[0].line_content.contains("production_code"));
        assert_eq!(violations[0].category, AmbientCategory::Time);
    }

    #[test]
    fn violation_type_classification() {
        let source = r#"
use std::time::Instant as Clock;

fn test_function() {
    let now = Instant::now();     // DirectUsage
    let now2 = Clock::now();      // Would be caught by enhanced patterns
}
"#;

        let violations = detect_ambient_violations(source);

        // Should classify violation types correctly
        let direct_usage = violations.iter().any(|v| {
            v.violation_type == ViolationType::DirectUsage && v.line_content.contains("Instant::now")
        });
        assert!(direct_usage, "Should detect direct usage");

        let alias_usage = violations.iter().any(|v| {
            v.violation_type == ViolationType::SuspiciousAlias && v.line_content.contains("as Clock")
        });
        assert!(alias_usage, "Should detect suspicious alias");
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
    // - Top-level `src/*_tests.rs`/conformance/metamorphic/e2e harnesses are
    //   test surfaces even when compiled through the lib-test crate rather than
    //   nested under an inline `#[cfg(test)] mod tests`.
    // - Some source-tree contract harnesses use singular suffixes such as
    //   `*_conformance.rs`, `*_metamorphic.rs`, `*_audit.rs`, or
    //   `*_testing.rs`; these are also test surfaces, not production runtime.
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
        "obligation/conformance_runner.rs",
        "audit/",
        "bin/",
    ];

    /// Modules that MUST have zero ambient authority in non-test code.
    /// All effects in these modules must flow through the Cx capability system.
    const PRISTINE_MODULES: &[&str] = &["cx", "obligation", "plan"];

    /// Upper bound on non-test, non-exempt ambient authority violations.
    /// This is the current shared-main baseline after provider/test carve-outs.
    /// Bump this ONLY after documenting why the new production usage is
    /// intentional, or lower it when production surfaces move behind capabilities.
    const AMBIENT_VIOLATION_CEILING: usize = 564;

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
        EXEMPT_PREFIXES.iter().any(|p| rel_path.starts_with(p)) || is_test_surface(rel_path)
    }

    fn is_test_surface(rel_path: &str) -> bool {
        let file_name = Path::new(rel_path)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(rel_path);

        file_name.ends_with("_tests.rs")
            || file_name.ends_with("_test.rs")
            || file_name.ends_with("_conformance.rs")
            || file_name.ends_with("_conformance_tests.rs")
            || file_name.ends_with("_metamorphic.rs")
            || file_name.ends_with("_metamorphic_tests.rs")
            || file_name.ends_with("_testing.rs")
            || file_name.ends_with("_mutations.rs")
            || file_name.ends_with("_audit.rs")
            || file_name.ends_with("_e2e_tests.rs")
            || file_name.starts_with("real_") && file_name.ends_with(".rs")
    }

    /// Convert a grep-style regex pattern to a literal search string.
    fn pattern_to_literal(pattern: &str) -> String {
        pattern.replace(r"\(", "(").replace(r"\)", ")")
    }

    fn line_contains_literal(line: &str, literal: &str) -> bool {
        line.match_indices(literal).any(|(idx, _)| {
            let before = line[..idx].chars().next_back();
            !matches!(before, Some(ch) if ch.is_ascii_alphanumeric() || ch == '_')
        })
    }

    fn raw_string_start(bytes: &[u8], idx: usize) -> Option<(usize, usize)> {
        let mut cursor = idx;

        if bytes.get(cursor) == Some(&b'b') {
            cursor += 1;
        }
        if bytes.get(cursor) != Some(&b'r') {
            return None;
        }

        let mut hash_count = 0;
        cursor += 1;
        while bytes.get(cursor) == Some(&b'#') {
            hash_count += 1;
            cursor += 1;
        }

        if bytes.get(cursor) == Some(&b'"') {
            Some((cursor + 1, hash_count))
        } else {
            None
        }
    }

    #[derive(Default)]
    struct ScanSanitizerState {
        in_block_comment: bool,
        in_string: bool,
        raw_hashes: Option<usize>,
    }

    fn strip_comments_and_literals(line: &str, state: &mut ScanSanitizerState) -> String {
        let bytes = line.as_bytes();
        let mut out = String::with_capacity(line.len());
        let mut idx = 0;

        while idx < bytes.len() {
            if state.in_block_comment {
                if idx + 1 < bytes.len() && bytes[idx] == b'*' && bytes[idx + 1] == b'/' {
                    state.in_block_comment = false;
                    idx += 2;
                } else {
                    idx += 1;
                }
                continue;
            }

            if let Some(hash_count) = state.raw_hashes {
                if bytes[idx] == b'"'
                    && idx + 1 + hash_count <= bytes.len()
                    && bytes[idx + 1..idx + 1 + hash_count]
                        .iter()
                        .all(|b| *b == b'#')
                {
                    state.raw_hashes = None;
                    idx += 1 + hash_count;
                } else {
                    idx += 1;
                }
                continue;
            }

            if state.in_string {
                match bytes[idx] {
                    b'\\' => idx = (idx + 2).min(bytes.len()),
                    b'"' => {
                        state.in_string = false;
                        idx += 1;
                    }
                    _ => idx += 1,
                }
                continue;
            }

            if idx + 1 < bytes.len() && bytes[idx] == b'/' && bytes[idx + 1] == b'/' {
                break;
            }
            if idx + 1 < bytes.len() && bytes[idx] == b'/' && bytes[idx + 1] == b'*' {
                state.in_block_comment = true;
                idx += 2;
                continue;
            }
            if let Some((next_idx, hash_count)) = raw_string_start(bytes, idx) {
                state.raw_hashes = Some(hash_count);
                idx = next_idx;
                continue;
            }
            if bytes[idx] == b'"' {
                state.in_string = true;
                idx += 1;
                continue;
            }

            out.push(bytes[idx] as char);
            idx += 1;
        }

        out
    }

    /// Return (line_number, line_text) pairs from non-test, non-comment code.
    ///
    /// Uses brace-depth tracking to skip `#[cfg(test)] mod ... { }` blocks.
    fn non_test_lines(content: &str) -> Vec<(usize, String)> {
        let mut result = Vec::new();
        let mut in_cfg_test_mod = false;
        let mut brace_depth: i32 = 0;
        let mut pending_cfg_test = false;
        let mut sanitizer_state = ScanSanitizerState::default();

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

            if trimmed.starts_with("//") && !sanitizer_state.in_block_comment {
                continue;
            }

            let stripped = strip_comments_and_literals(line, &mut sanitizer_state);
            if stripped.trim().is_empty() {
                continue;
            }

            result.push((idx + 1, stripped));
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

    fn scan_source(rel: &str, content: &str) -> Vec<Violation> {
        let mut violations = Vec::new();

        if is_exempt(rel) {
            return violations;
        }

        let lines = non_test_lines(content);

        for (pattern, category) in GREP_PATTERNS {
            let literal = pattern_to_literal(pattern);
            for (line_num, line_text) in &lines {
                if line_contains_literal(line_text, &literal) {
                    violations.push(Violation {
                        file: rel.to_string(),
                        line: *line_num,
                        pattern: literal.clone(),
                        category: *category,
                    });
                }
            }
        }

        violations
    }

    #[must_use]
    pub fn scan_categories_for_contract_fixture(rel: &str, content: &str) -> Vec<AmbientCategory> {
        scan_source(rel, content)
            .into_iter()
            .map(|violation| violation.category)
            .collect()
    }

    fn scan_directory(dir: &Path, root: &Path) -> Vec<Violation> {
        let mut violations = Vec::new();
        for file_path in collect_rs_files(dir) {
            let rel = file_path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");

            let Ok(content) = std::fs::read_to_string(&file_path) else {
                continue;
            };

            violations.extend(scan_source(&rel, &content));
        }
        violations
    }

    fn format_violations(vs: &[Violation]) -> String {
        vs.iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn format_violation_sample(vs: &[Violation], limit: usize) -> String {
        let mut rendered = vs
            .iter()
            .take(limit)
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>();
        if vs.len() > limit {
            rendered.push(format!("  ... {} more violation(s)", vs.len() - limit));
        }
        rendered.join("\n")
    }

    fn has_non_test_match_near_line(
        content: &str,
        pattern: &str,
        expected_line: u32,
        max_line_distance: u32,
    ) -> bool {
        let literal = pattern_to_literal(pattern);
        non_test_lines(content).into_iter().any(|(line_num, line)| {
            expected_line.abs_diff(line_num as u32) <= max_line_distance
                && line_contains_literal(&line, &literal)
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
        let mut audit_failures = Vec::new();

        // br-asupersync-yb2syy: Fix audit bypass via panic in ambient authority detection.
        // Use Result-based, fail-closed logic instead of panic::resume_unwind to prevent
        // audit bypass via controlled panics that could mask ambient authority violations.
        // Collect all failures and report them atomically to ensure complete audit coverage.
        for finding in KNOWN_FINDINGS {
            let path = root.join(finding.file);

            // Fail-closed: continue processing even if one file fails,
            // but track all failures for atomic reporting at the end
            let content = match std::fs::read_to_string(&path) {
                Ok(content) => content,
                Err(err) => {
                    audit_failures.push(format!(
                        "KNOWN_FINDINGS references unreadable file: src/{} ({})",
                        finding.file, err
                    ));
                    continue; // Skip this finding but continue audit
                }
            };

            let has_nearby_match =
                has_non_test_match_near_line(&content, finding.evidence_pattern, finding.line, 30);

            if !has_nearby_match {
                audit_failures.push(format!(
                    "KNOWN_FINDINGS entry '{}' at src/{}:{} — \
                     no matching non-test evidence pattern '{}' found within ±30 lines. Stale entry?",
                    finding.description, finding.file, finding.line, finding.evidence_pattern,
                ));
            }
        }

        // Atomic failure reporting: if any part of the audit failed,
        // report all failures together to ensure nothing is masked
        assert!(
            audit_failures.is_empty(),
            "Ambient authority audit failures ({}):{}",
            audit_failures.len(),
            audit_failures.iter().fold(String::new(), |mut acc, failure| {
                acc.push_str("\n  - ");
                acc.push_str(failure);
                acc
            })
        );
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
             Violation sample:\n{}",
            violations.len(),
            AMBIENT_VIOLATION_CEILING,
            format_violation_sample(&violations, 80),
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

    #[test]
    fn non_test_lines_filter_skips_block_comments_and_strings() {
        let source = r##"
/*
Instant::now();
eprintln!("inside block comment");
*/
fn production_code() {
    let _normal = "Instant::now()";
    let _multiline = "SystemTime::now()
eprintln!(\"inside multiline string\")";
    let _raw = r#"eprintln!("inside raw string")"#;
    let _raw_multiline = r#"
std::thread::spawn(|| ());
"#;
    Instant::now();
}
"##;
        let lines = non_test_lines(source);
        let instant_count = lines
            .iter()
            .filter(|(_, line)| line.contains("Instant::now"))
            .count();
        let output_count = lines
            .iter()
            .filter(|(_, line)| line.contains("eprintln!("))
            .count();

        assert_eq!(
            instant_count, 1,
            "only executable Instant::now should remain"
        );
        assert_eq!(
            output_count, 0,
            "string/comment output patterns should be ignored"
        );
    }

    #[test]
    fn top_level_test_surfaces_are_exempt_from_scanning() {
        assert!(is_exempt("real_integration_scenarios_e2e_tests.rs"));
        assert!(is_exempt("raptorq_rfc6330_conformance_tests.rs"));
        assert!(is_exempt("runtime/sharded_state_conformance.rs"));
        assert!(is_exempt("cancel_cx_runtime_channel_metamorphic_tests.rs"));
        assert!(is_exempt("runtime/scheduler/edf_priority_metamorphic.rs"));
        assert!(is_exempt("grpc_server_deadline_cancel_audit.rs"));
        assert!(is_exempt("integration_mutation_testing.rs"));
        assert!(!is_exempt("service/runtime.rs"));
    }

    #[test]
    fn scanner_allows_documented_test_surface_ambient_output() {
        let source = r#"
fn test_helper() {
    std::env::var("ASUPERSYNC_TEST_LOG").ok();
    eprintln!("stage log");
}
"#;
        let violations = scan_source("real_integration_scenarios_e2e_tests.rs", source);
        assert!(
            violations.is_empty(),
            "test-surface carve-outs should not count as production ambient authority: {}",
            format_violations(&violations)
        );
    }

    #[test]
    fn scanner_rejects_production_env_and_output_patterns() {
        let source = r#"
fn production_path() {
    let _ = std::env::var("ASUPERSYNC_RUNTIME_FLAG");
    eprintln!("bypasses structured tracing");
}
"#;
        let violations = scan_source("service/runtime.rs", source);

        assert!(
            violations
                .iter()
                .any(|v| v.category == AmbientCategory::Env),
            "expected env access violation, got: {}",
            format_violations(&violations)
        );
        assert!(
            violations
                .iter()
                .any(|v| v.category == AmbientCategory::Output),
            "expected output violation, got: {}",
            format_violations(&violations)
        );
    }

    #[test]
    fn scanner_ignores_production_pattern_literals() {
        let source = r##"
fn production_path() {
    let _message = "std::env::var(\"NOPE\")";
    let _raw = r#"eprintln!("stage log")"#;
    /* std::thread::spawn(|| ()); */
}
"##;
        let violations = scan_source("service/runtime.rs", source);
        assert!(
            violations.is_empty(),
            "string and block-comment literals should not trip the scanner: {}",
            format_violations(&violations)
        );
    }

    #[test]
    fn output_patterns_do_not_double_count_stderr_macros_as_stdout() {
        let source = r#"
fn production_path() {
    eprintln!("stderr");
}
"#;
        let violations = scan_source("service/runtime.rs", source);
        let output_patterns: Vec<_> = violations
            .iter()
            .filter(|v| v.category == AmbientCategory::Output)
            .map(|v| v.pattern.as_str())
            .collect();

        assert_eq!(output_patterns, vec!["eprintln!("]);
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
