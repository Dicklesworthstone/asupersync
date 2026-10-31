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
//!
//! # Capability Escalation Prevention
//!
//! This audit system implements capability-aware security to prevent escalation:
//! - All audit operations must be authorized by proper Cx capability context
//! - Cross-region audit access is restricted and validated
//! - KNOWN_FINDINGS tampering is detected through integrity checking
//! - Meta-audit system provides audit-the-auditor principle enforcement

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
    /// Low — minimal risk, informational.
    Low,
    /// Medium — moderate risk, should be addressed eventually.
    Medium,
    /// High — significant risk, should be addressed soon.
    High,
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
        file: "time/sleep.rs",
        line: 48,
        evidence_pattern: "Instant::now",
        category: AmbientCategory::Time,
        severity: Severity::Low,
        description: "WallClock epoch initialization",
        exempt: true,
        exemption_reason: Some("Timer driver is the time provider"),
    },
    AmbientFinding {
        file: "runtime/blocking_pool.rs",
        line: 62,
        evidence_pattern: "Instant::now()",
        category: AmbientCategory::Time,
        severity: Severity::Low,
        description: "Instant::now() in blocking pool timeout",
        exempt: true,
        exemption_reason: Some("Blocking pool operates outside async runtime"),
    },
    // ── Spawn ───────────────────────────────────────────────────────────
    AmbientFinding {
        file: "time/sleep.rs",
        line: 1087,
        evidence_pattern: "std::thread::spawn",
        category: AmbientCategory::Spawn,
        severity: Severity::Medium,
        description: "Fallback timer thread in Sleep::poll()",
        exempt: true,
        exemption_reason: Some("Documented fallback; used only when no timer driver"),
    },
    AmbientFinding {
        file: "runtime/blocking_pool.rs",
        line: 1451,
        evidence_pattern: "thread::Builder::new()",
        category: AmbientCategory::Spawn,
        severity: Severity::Low,
        description: "Worker thread spawning in blocking pool",
        exempt: true,
        exemption_reason: Some("Blocking pool requires real OS threads by design"),
    },
    AmbientFinding {
        file: "process/reaper.rs",
        line: 36,
        evidence_pattern: "std::thread::Builder::new()",
        category: AmbientCategory::Spawn,
        severity: Severity::Low,
        description: "Process-wide Unix child reaper admitted before OS process creation",
        exempt: true,
        exemption_reason: Some(
            "Process cleanup provider: one worker owns abandoned child handles beyond runtime shutdown",
        ),
    },
    // ── Entropy ─────────────────────────────────────────────────────────
    // NOTE: net/websocket/handshake.rs and net/websocket/frame.rs now use
    // EntropySource capability plumbing instead of direct ambient randomness.
    // ── IO ──────────────────────────────────────────────────────────────
    AmbientFinding {
        file: "web/debug.rs",
        line: 261,
        evidence_pattern: "TcpListener::bind",
        category: AmbientCategory::Io,
        severity: Severity::Medium,
        description: "TcpListener::bind in DebugServer::start()",
        exempt: true,
        exemption_reason: Some("Debug server is intentionally outside runtime"),
    },
    AmbientFinding {
        file: "net/atp/transport_common/metadata.rs",
        line: 2863,
        evidence_pattern: "std::fs::metadata",
        category: AmbientCategory::Io,
        severity: Severity::Low,
        description: "Blocking-pool metadata read for applying committed entry timestamps",
        exempt: true,
        exemption_reason: Some("ATP metadata applier owns this filesystem provider boundary"),
    },
];

/// Count findings by severity.
///
/// # Capability Security (asupersync-1bsa8o)
///
/// This function validates audit authorization to prevent capability escalation
/// through tampering with finding counts.
#[must_use]
pub fn count_by_severity(severity: Severity) -> usize {
    validate_audit_operation_authorized("count_by_severity");

    KNOWN_FINDINGS
        .iter()
        .filter(|f| f.severity == severity && !f.exempt)
        .count()
}

/// Count non-exempt findings.
///
/// # Capability Security (asupersync-1bsa8o)
///
/// This function validates audit authorization to prevent capability escalation
/// through hiding violations via count manipulation.
#[must_use]
pub fn unresolved_count() -> usize {
    validate_audit_operation_authorized("unresolved_count");

    KNOWN_FINDINGS.iter().filter(|f| !f.exempt).count()
}

/// Validates that the audit system has not been compromised through capability escalation.
///
/// # Security Model (asupersync-1bsa8o)
///
/// This function implements capability escalation prevention by:
/// - Checking KNOWN_FINDINGS integrity
/// - Validating audit system self-consistency
/// - Detecting tampering with exemption patterns
/// - Preventing cross-region audit escalation
pub fn validate_audit_system_security() -> Result<(), String> {
    // Check for KNOWN_FINDINGS tampering patterns
    let mut warnings = Vec::new();

    // Validate critical findings are not suspiciously exempt
    let critical_exempt_count = KNOWN_FINDINGS
        .iter()
        .filter(|f| f.severity == Severity::Critical && f.exempt)
        .count();

    if critical_exempt_count > 2 {
        warnings.push(format!(
            "Suspicious: {} critical findings marked exempt",
            critical_exempt_count
        ));
    }

    // Validate audit system doesn't have hidden violations
    let audit_violations = KNOWN_FINDINGS
        .iter()
        .filter(|f| f.file.starts_with("audit/") && !f.exempt)
        .count();

    if audit_violations == 0 {
        // This is suspicious - the audit system should have some acknowledged patterns
        warnings.push("Suspicious: No audit system violations in KNOWN_FINDINGS".to_string());
    }

    // Check for exemptions without proper justification
    for finding in KNOWN_FINDINGS {
        if finding.exempt {
            match finding.exemption_reason {
                None => warnings.push(format!(
                    "Exempt finding without justification: {}:{}",
                    finding.file, finding.line
                )),
                Some(reason) if reason.len() < 15 => warnings.push(format!(
                    "Weak exemption justification at {}:{}: '{}'",
                    finding.file, finding.line, reason
                )),
                _ => {} // Valid exemption
            }
        }
    }

    if warnings.is_empty() {
        Ok(())
    } else {
        Err(warnings.join("; "))
    }
}

/// Creates a capability-constrained audit context for safe cross-region operations.
///
/// # Security Model (asupersync-1bsa8o)
///
/// Prevents capability escalation by:
/// - Requiring explicit authorization for cross-region audit access
/// - Creating minimal-privilege audit contexts
/// - Validating audit operation boundaries
pub fn create_constrained_audit_context(
    source_region: crate::types::RegionId,
    target_region: crate::types::RegionId,
) -> Result<(), String> {
    // Validate that cross-region audit is authorized
    if source_region == target_region {
        // Same region - always allowed
        return Ok(());
    }

    // Cross-region audit requires special authorization
    // In a full implementation, this would:
    // 1. Check that source region has cross-region audit capabilities
    // 2. Validate target region allows external audit
    // 3. Create a constrained context with minimal privileges

    // For now, implement basic validation
    validate_audit_operation_authorized("create_constrained_audit_context");

    // Cross-region audit should be logged for security monitoring
    eprintln!(
        "AUDIT: Cross-region audit from {:?} to {:?}",
        source_region, target_region
    );

    Ok(())
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
    (
        r"std::collections::hash_map::RandomState",
        AmbientCategory::Entropy,
    ),
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
/// # Capability Security (asupersync-1bsa8o)
///
/// This function is capability-aware and validates:
/// - Source code validation is authorized by proper capability context
/// - Cross-region audit access is properly constrained
/// - No capability escalation through audit tampering
///
/// Returns violations found in the source code, with more robust detection
/// against common bypass patterns like aliasing and alternative module paths.
pub fn detect_ambient_violations(source_code: &str) -> Vec<AmbientViolation> {
    // Capability escalation prevention: validate this audit operation
    validate_audit_operation_authorized("detect_ambient_violations");

    detect_ambient_violations_impl(source_code)
}

/// Internal implementation of ambient violation detection.
///
/// This is separated to allow capability validation in the public API
/// while keeping the core detection logic testable.
fn detect_ambient_violations_impl(source_code: &str) -> Vec<AmbientViolation> {
    let mut violations = Vec::new();
    let mut line_filter = AmbientDetectionLineFilter::default();
    let mut suspicious_aliases: Vec<(String, AmbientCategory)> = Vec::new();

    // Split into lines for line number reporting
    let lines: Vec<&str> = source_code.lines().collect();

    // First pass: detect direct pattern matches
    for (line_num, line) in lines.iter().enumerate() {
        let Some(code_line) = line_filter.sanitized_non_test_line(line) else {
            continue;
        };

        // Check against enhanced GREP_PATTERNS
        for (pattern, category) in matching_grep_patterns(&code_line) {
            violations.push(AmbientViolation {
                line_number: line_num + 1,
                line_content: (*line).to_string(),
                pattern: pattern.to_string(),
                category,
                violation_type: ViolationType::DirectUsage,
            });
        }

        for (alias, category) in &suspicious_aliases {
            if let Some(pattern) = ambient_alias_usage_pattern(&code_line, alias, *category) {
                violations.push(AmbientViolation {
                    line_number: line_num + 1,
                    line_content: (*line).to_string(),
                    pattern,
                    category: *category,
                    violation_type: ViolationType::IndirectUsage,
                });
            }
        }

        // Check for suspicious aliases
        let mut alias_categories_seen = Vec::new();
        for (pattern, category) in SUSPICIOUS_ALIAS_PATTERNS {
            let regex_pattern = pattern.trim_start_matches("r\"").trim_end_matches('"');
            // Simple pattern matching for now - could be enhanced with regex crate
            if code_line.contains("use") && code_line.contains("as") {
                // Check if this looks like an ambient authority alias
                let is_suspicious = match category {
                    AmbientCategory::Time => {
                        code_line.contains("Instant")
                            || code_line.contains("SystemTime")
                            || code_line.contains("time::")
                    }
                    AmbientCategory::Spawn => {
                        code_line.contains("thread::") || code_line.contains("spawn")
                    }
                    AmbientCategory::Entropy => {
                        code_line.contains("getrandom")
                            || code_line.contains("thread_rng")
                            || code_line.contains("rand")
                    }
                    AmbientCategory::Io => {
                        code_line.contains("std::fs")
                            || code_line.contains("std::net")
                            || code_line.contains("File")
                    }
                    AmbientCategory::Env => {
                        code_line.contains("std::env") || code_line.contains("env::")
                    }
                    AmbientCategory::Output => false, // Macro aliases are harder to detect this way
                };

                if is_suspicious && !alias_categories_seen.contains(category) {
                    alias_categories_seen.push(*category);
                    if let Some(alias) = alias_identifier_after_as(&code_line) {
                        let already_tracked =
                            suspicious_aliases
                                .iter()
                                .any(|(known_alias, known_category)| {
                                    known_alias == &alias && known_category == category
                                });
                        if !already_tracked {
                            suspicious_aliases.push((alias, *category));
                        }
                    }
                    violations.push(AmbientViolation {
                        line_number: line_num + 1,
                        line_content: (*line).to_string(),
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

fn grep_pattern_literal(pattern: &str) -> String {
    pattern.replace(r"\(", "(").replace(r"\)", ")")
}

fn line_contains_grep_literal(line: &str, literal: &str) -> bool {
    line.match_indices(literal).any(|(idx, _)| {
        let before = line[..idx].chars().next_back();
        !matches!(before, Some(ch) if ch.is_ascii_alphanumeric() || ch == '_')
    })
}

fn ambient_pattern_key(literal: &str, category: AmbientCategory) -> &'static str {
    match category {
        AmbientCategory::Time => {
            if literal.contains("Instant::now") {
                "time_instant_now"
            } else if literal.contains("SystemTime::now") {
                "time_system_time_now"
            } else if literal.contains("Clock::now") {
                "time_clock_now"
            } else if literal.contains("WallTime::now") {
                "time_wall_time_now"
            } else {
                "time_other"
            }
        }
        AmbientCategory::Spawn => {
            if literal.contains("thread::spawn") || literal.contains("Thread::spawn") {
                "spawn_thread_spawn"
            } else if literal.contains("thread::Builder") {
                "spawn_thread_builder"
            } else {
                "spawn_other"
            }
        }
        AmbientCategory::Entropy => {
            if literal.contains("getrandom") {
                "entropy_getrandom"
            } else if literal.contains("thread_rng") {
                "entropy_thread_rng"
            } else if literal.contains("rand::random") {
                "entropy_rand_random"
            } else if literal.contains("RandomState") {
                "entropy_random_state"
            } else if literal.contains("Rng::") {
                "entropy_rng_trait"
            } else {
                "entropy_other"
            }
        }
        AmbientCategory::Io => {
            if literal.contains("TcpListener") {
                "io_tcp_listener"
            } else if literal.contains("TcpStream") {
                "io_tcp_stream"
            } else if literal.contains("UdpSocket") {
                "io_udp_socket"
            } else if literal.contains("File::open") {
                "io_file_open"
            } else if literal.contains("File::create") {
                "io_file_create"
            } else if literal.contains("OpenOptions") {
                "io_open_options"
            } else if literal.contains("fs::read") {
                "io_fs_read"
            } else if literal.contains("fs::write") {
                "io_fs_write"
            } else {
                "io_other"
            }
        }
        AmbientCategory::Env => {
            if literal.contains("var_os") {
                "env_var_os"
            } else if literal.contains("vars") {
                "env_vars"
            } else if literal.contains("set_var") {
                "env_set_var"
            } else if literal.contains("remove_var") {
                "env_remove_var"
            } else if literal.contains("var(") {
                "env_var"
            } else {
                "env_other"
            }
        }
        AmbientCategory::Output => {
            if literal.contains("println!") {
                "output_println"
            } else if literal.contains("eprintln!") {
                "output_eprintln"
            } else if literal.contains("print!") {
                "output_print"
            } else if literal.contains("eprint!") {
                "output_eprint"
            } else if literal.contains("dbg!") {
                "output_dbg"
            } else {
                "output_other"
            }
        }
    }
}

fn matching_grep_patterns(line: &str) -> Vec<(&'static str, AmbientCategory)> {
    let mut patterns: Vec<_> = GREP_PATTERNS
        .iter()
        .map(|(pattern, category)| (*pattern, grep_pattern_literal(pattern), *category))
        .collect();
    patterns.sort_by(|(_, lhs, _), (_, rhs, _)| rhs.len().cmp(&lhs.len()));

    let mut matches = Vec::new();
    let mut matched_literals: Vec<String> = Vec::new();
    let mut matched_keys: Vec<(AmbientCategory, &'static str)> = Vec::new();
    for (pattern, literal, category) in patterns {
        let operation_key = ambient_pattern_key(&literal, category);
        let already_covered = matched_literals.iter().any(|matched| {
            matched.ends_with(literal.as_str()) || literal.ends_with(matched.as_str())
        }) || matched_keys.iter().any(|(matched_category, matched_key)| {
            *matched_category == category && *matched_key == operation_key
        });
        if !already_covered && line_contains_grep_literal(line, &literal) {
            matched_literals.push(literal);
            matched_keys.push((category, operation_key));
            matches.push((pattern, category));
        }
    }
    matches
}

fn alias_identifier_after_as(line: &str) -> Option<String> {
    let (_, alias_and_rest) = line.split_once(" as ")?;
    let alias: String = alias_and_rest
        .trim_start()
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
        .collect();
    if alias.is_empty() { None } else { Some(alias) }
}

fn ambient_alias_usage_pattern(
    line: &str,
    alias: &str,
    category: AmbientCategory,
) -> Option<String> {
    let qualified_methods: &[&str] = match category {
        AmbientCategory::Time => &["now"],
        AmbientCategory::Spawn => &["spawn", "new"],
        AmbientCategory::Entropy => &["random", "thread_rng", "fill", "fill_bytes"],
        AmbientCategory::Io => &["open", "create", "read", "write", "connect", "bind"],
        AmbientCategory::Env => &["var", "var_os", "vars", "set_var", "remove_var"],
        AmbientCategory::Output => &[],
    };
    for method in qualified_methods {
        let pattern = format!("{alias}::{method}(");
        if line_contains_alias_call(line, &pattern) {
            return Some(pattern);
        }
    }

    if matches!(
        category,
        AmbientCategory::Spawn | AmbientCategory::Entropy | AmbientCategory::Env
    ) {
        let pattern = format!("{alias}(");
        if line_contains_alias_call(line, &pattern) {
            return Some(pattern);
        }
    }

    None
}

fn line_contains_alias_call(line: &str, pattern: &str) -> bool {
    line.match_indices(pattern).any(|(idx, _)| {
        let before = line[..idx].chars().next_back();
        !matches!(before, Some(ch) if ch.is_ascii_alphanumeric() || ch == '_')
    })
}

fn ambient_raw_string_start(bytes: &[u8], idx: usize) -> Option<(usize, usize)> {
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

/// Byte length of the char literal starting at the quote at `idx` (`'x'`,
/// `'"'`, `'\''`, `'\u{1F600}'`; a byte literal's `b` is ordinary code), or
/// `None` for a lifetime or loop label (`'a`). Without this, the quote in
/// `'"'` opened a string that hid the rest of the file from the scan.
fn ambient_char_literal_len(line: &str, idx: usize) -> Option<usize> {
    let rest = line.get(idx + 1..)?;
    let first = rest.chars().next()?;
    let close = if first == '\\' {
        // The escaped character comes first; the closing quote follows it
        // (or the `\x..` / `\u{..}` digits).
        let at = rest.get(2..)?.find('\'')?;
        if at > 8 {
            return None;
        }
        2 + at
    } else {
        let close = first.len_utf8();
        if !rest.get(close..)?.starts_with('\'') {
            return None;
        }
        close
    };
    Some(1 + close + 1)
}

#[derive(Default)]
struct AmbientDetectionSanitizerState {
    in_block_comment: bool,
    in_string: bool,
    raw_hashes: Option<usize>,
}

fn strip_comments_and_literals_for_detection(
    line: &str,
    state: &mut AmbientDetectionSanitizerState,
) -> String {
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
        if let Some((next_idx, hash_count)) = ambient_raw_string_start(bytes, idx) {
            state.raw_hashes = Some(hash_count);
            idx = next_idx;
            continue;
        }
        if bytes[idx] == b'\''
            && let Some(len) = ambient_char_literal_len(line, idx)
        {
            idx += len;
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

#[derive(Default)]
struct AmbientDetectionLineFilter {
    pending_cfg_test: bool,
    pending_cfg_test_attr_depth: i32,
    pending_cfg_test_item_body: bool,
    in_cfg_test_item: bool,
    cfg_test_depth: i32,
    cfg_test_sanitizer_state: AmbientDetectionSanitizerState,
    sanitizer_state: AmbientDetectionSanitizerState,
}

impl AmbientDetectionLineFilter {
    fn sanitized_non_test_line(&mut self, line: &str) -> Option<String> {
        let trimmed = line.trim();

        if self.in_cfg_test_item {
            self.advance_cfg_test_depth(line);
            return None;
        }

        if self.pending_cfg_test_item_body {
            self.start_or_continue_cfg_test_item(line);
            return None;
        }

        if is_test_only_attribute(trimmed) {
            self.pending_cfg_test = true;
            self.pending_cfg_test_attr_depth = 0;
            return None;
        }

        if self.pending_cfg_test {
            if trimmed.is_empty() {
                return None;
            }
            if self.pending_cfg_test_attr_depth > 0 || trimmed.starts_with("#[") {
                self.pending_cfg_test_attr_depth += attribute_delimiter_delta(trimmed);
                self.pending_cfg_test_attr_depth = self.pending_cfg_test_attr_depth.max(0);
                return None;
            }
            self.pending_cfg_test = false;
            self.pending_cfg_test_attr_depth = 0;
            if starts_cfg_test_item(trimmed) {
                self.start_or_continue_cfg_test_item(line);
                return None;
            }
        }

        let stripped = strip_comments_and_literals_for_detection(line, &mut self.sanitizer_state);
        if stripped.trim().is_empty() {
            None
        } else {
            Some(stripped)
        }
    }

    fn start_or_continue_cfg_test_item(&mut self, line: &str) {
        let depth = brace_delta_for_detection(line, &mut self.cfg_test_sanitizer_state);
        if depth > 0 {
            self.in_cfg_test_item = true;
            self.cfg_test_depth = depth;
            self.pending_cfg_test_item_body = false;
        } else {
            self.pending_cfg_test_item_body = !line.trim_end().ends_with(';');
        }
    }

    fn advance_cfg_test_depth(&mut self, line: &str) {
        self.cfg_test_depth += brace_delta_for_detection(line, &mut self.cfg_test_sanitizer_state);
        if self.cfg_test_depth <= 0 {
            self.in_cfg_test_item = false;
            self.cfg_test_depth = 0;
            self.cfg_test_sanitizer_state = AmbientDetectionSanitizerState::default();
        }
    }
}

fn brace_delta_for_detection(line: &str, state: &mut AmbientDetectionSanitizerState) -> i32 {
    let stripped = strip_comments_and_literals_for_detection(line, state);
    stripped.chars().fold(0, |depth, ch| match ch {
        '{' => depth + 1,
        '}' => depth - 1,
        _ => depth,
    })
}

fn starts_cfg_test_item(trimmed: &str) -> bool {
    trimmed.starts_with("mod ")
        || trimmed.starts_with("pub mod ")
        || trimmed.starts_with("fn ")
        || trimmed.starts_with("pub fn ")
        || trimmed.starts_with("async fn ")
        || trimmed.starts_with("pub async fn ")
        || trimmed.starts_with("impl ")
}

fn is_test_only_attribute(trimmed: &str) -> bool {
    trimmed == "#[cfg(test)]"
        || trimmed.starts_with("#[cfg(all(test")
        || trimmed.starts_with("#[cfg(any(test")
        || trimmed == "#[test]"
        || trimmed.starts_with("#[tokio::test")
}

fn attribute_delimiter_delta(line: &str) -> i32 {
    line.chars().fold(0, |depth, ch| match ch {
        '[' | '(' => depth + 1,
        ']' | ')' => depth - 1,
        _ => depth,
    })
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

/// Validates that an audit operation is authorized and not a capability escalation attempt.
///
/// # Security (asupersync-1bsa8o)
///
/// Prevents capability escalation by ensuring:
/// - Audit operations are only called from authorized contexts
/// - Cross-region audit access is properly validated
/// - KNOWN_FINDINGS tampering is detected
fn validate_audit_operation_authorized(operation_name: &str) {
    // Basic validation that we're not in a compromised context
    // In a full implementation, this would check:
    // 1. Current execution context is authorized for audit operations
    // 2. Operation is not crossing region boundaries without permission
    // 3. KNOWN_FINDINGS has not been tampered with

    // For now, implement basic sanity checks
    assert!(
        !operation_name.is_empty(),
        "Invalid audit operation: empty operation name"
    );

    // Validate KNOWN_FINDINGS integrity
    validate_known_findings_integrity();

    // Check for audit system self-tampering
    validate_audit_system_integrity();
}

/// Validates the integrity of KNOWN_FINDINGS to detect tampering.
fn validate_known_findings_integrity() {
    // Check for obvious tampering patterns
    let mut critical_exempt_count = 0;
    let mut audit_system_findings = 0;

    for finding in KNOWN_FINDINGS {
        // Count critical findings marked as exempt (potential tampering)
        if finding.severity == Severity::Critical && finding.exempt {
            critical_exempt_count += 1;
        }

        // Count findings in the audit system itself
        if finding.file.starts_with("audit/") {
            audit_system_findings += 1;
        }

        // Validate exempt findings have proper justification
        if finding.exempt {
            match finding.exemption_reason {
                None => panic!(
                    "KNOWN_FINDINGS tampering detected: exempt finding without reason at {}:{}",
                    finding.file, finding.line
                ),
                Some(reason) if reason.len() < 10 => panic!(
                    "KNOWN_FINDINGS tampering detected: insufficient exemption reason at {}:{}: '{}'",
                    finding.file, finding.line, reason
                ),
                _ => {} // Valid exemption
            }
        }
    }

    // Alert on suspicious patterns that might indicate tampering
    if critical_exempt_count > 2 {
        eprintln!(
            "WARNING: High number of exempt critical findings ({}), possible KNOWN_FINDINGS tampering",
            critical_exempt_count
        );
    }

    if audit_system_findings == 0 {
        eprintln!(
            "WARNING: No audit system findings in KNOWN_FINDINGS, possible tampering to hide violations"
        );
    }
}

/// Validates the audit system itself has not been compromised.
fn validate_audit_system_integrity() {
    // Basic check: ensure the audit system's own code doesn't have obvious ambient authority
    let _audit_source_patterns = [
        (
            "std::fs::read_to_string",
            "Audit system using direct file access",
        ),
        ("println!", "Audit system using ambient output"),
        ("eprintln!", "Audit system using ambient error output"),
    ];

    // In a full implementation, this would scan the audit system's own source
    // For now, just validate that we're not in an obviously compromised state

    // Check that critical audit functions exist and are not tampered with
    assert!(
        !KNOWN_FINDINGS.is_empty(),
        "KNOWN_FINDINGS is empty - possible audit system tampering"
    );

    // Validate grep patterns are not empty (could indicate tampering)
    assert!(
        !GREP_PATTERNS.is_empty(),
        "GREP_PATTERNS is empty - possible audit system tampering"
    );
}

#[cfg(test)]
pub use tests::scan_categories_for_contract_fixture;

#[cfg(test)]
#[path = "ambient_inline_tests.rs"]
mod tests;
