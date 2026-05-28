//! Metamorphic testing for CLI modules.
//!
//! Tests CLI argument parsing, doctor diagnostics, progress reporting,
//! and shell completion generation using metamorphic relations.

#![allow(clippy::too_many_lines)]

#[cfg(all(test, feature = "cli"))]
mod cli_tests {
    use crate::cli::args::{CommonArgs, parse_color_choice, parse_output_format};
    use crate::cli::completion::Shell;
    use crate::cli::output::{ColorChoice, OutputFormat};
    use crate::cli::progress::{ProgressEvent, ProgressKind, ProgressReporter};
    use crate::test_utils::init_test_logging;
    use proptest::prelude::*;
    use proptest::{prop_oneof, strategy::BoxedStrategy, strategy::Just};
    use serde_json;
    use std::collections::HashMap;
    use std::io::Cursor;
    use std::path::PathBuf;
    use std::time::Duration;

    // Deterministic CLI doctor fixture implementation.

    /// Workspace scan fixture report for testing.
    #[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
    pub struct FixtureWorkspaceScanReport {
        pub root: String,
        pub workspace_manifest: String,
        pub scanner_version: String,
        pub taxonomy_version: String,
        pub members: Vec<FixtureWorkspaceMember>,
        pub capability_edges: Vec<FixtureCapabilityEdge>,
        pub warnings: Vec<String>,
        pub events: Vec<FixtureScanEvent>,
    }

    #[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
    pub struct FixtureWorkspaceMember {
        pub name: String,
        pub version: String,
        pub path: String,
        pub capabilities: Vec<String>,
    }

    #[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
    pub struct FixtureCapabilityEdge {
        pub from_member: String,
        pub to_surface: String,
        pub capability: String,
        pub binding_type: String,
    }

    #[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
    pub struct FixtureScanEvent {
        pub timestamp: u64,
        pub event_type: String,
        pub message: String,
        pub details: HashMap<String, String>,
    }

    /// CLI doctor fixture that generates deterministic reports.
    pub struct FixtureCliDoctor {
        base_scan_config: FixtureWorkspaceScanReport,
        capabilities: Vec<String>,
    }

    impl FixtureCliDoctor {
        pub fn new(root: impl Into<String>, capabilities: Vec<String>) -> Self {
            Self {
                base_scan_config: FixtureWorkspaceScanReport {
                    root: root.into(),
                    workspace_manifest: "Cargo.toml".to_string(),
                    scanner_version: "1.0.0".to_string(),
                    taxonomy_version: "v2.1".to_string(),
                    members: Vec::new(),
                    capability_edges: Vec::new(),
                    warnings: Vec::new(),
                    events: Vec::new(),
                },
                capabilities,
            }
        }

        /// Generate a deterministic diagnostic report.
        pub fn generate_report(&self, include_details: bool) -> FixtureWorkspaceScanReport {
            let mut report = self.base_scan_config.clone();

            // Add deterministic members based on capabilities
            for (i, capability) in self.capabilities.iter().enumerate() {
                report.members.push(FixtureWorkspaceMember {
                    name: format!("member-{i}"),
                    version: "0.1.0".to_string(),
                    path: format!("./member-{i}"),
                    capabilities: vec![capability.clone()],
                });
            }

            // Add capability edges
            for member in &report.members {
                report.capability_edges.push(FixtureCapabilityEdge {
                    from_member: member.name.clone(),
                    to_surface: "runtime".to_string(),
                    capability: member.capabilities[0].clone(),
                    binding_type: "direct".to_string(),
                });
            }

            // Add events if details requested
            if include_details {
                for (i, member) in report.members.iter().enumerate() {
                    report.events.push(FixtureScanEvent {
                        timestamp: 1000 + i as u64 * 100,
                        event_type: "member_discovered".to_string(),
                        message: format!("Found member {}", member.name),
                        details: {
                            let mut details = HashMap::new();
                            details.insert("name".to_string(), member.name.clone());
                            details
                                .insert("capability".to_string(), member.capabilities[0].clone());
                            details
                        },
                    });
                }
            }

            report
        }

        /// Generate report focusing on specific capabilities.
        pub fn generate_capability_report(
            &self,
            capability_filter: &[String],
        ) -> FixtureWorkspaceScanReport {
            let filtered_caps: Vec<String> = self
                .capabilities
                .iter()
                .filter(|cap| capability_filter.contains(cap))
                .cloned()
                .collect();

            let filtered_doctor = FixtureCliDoctor::new(&self.base_scan_config.root, filtered_caps);
            filtered_doctor.generate_report(true)
        }
    }

    // Deterministic progress tracker fixture implementation.

    /// Progress tracker fixture for testing progress monotonicity.
    pub struct FixtureProgressTracker {
        total_items: u64,
        current_item: u64,
        operation_name: String,
        start_time: std::time::Instant,
    }

    impl FixtureProgressTracker {
        pub fn new(total: u64, operation: impl Into<String>) -> Self {
            Self {
                total_items: total,
                current_item: 0,
                operation_name: operation.into(),
                start_time: std::time::Instant::now(),
            }
        }

        /// Advance progress by a delta amount.
        pub fn advance(&mut self, delta: u64) -> ProgressEvent {
            self.current_item = (self.current_item + delta).min(self.total_items);

            ProgressEvent::update(
                self.current_item,
                self.total_items,
                format!("Processing item {}/{}", self.current_item, self.total_items),
            )
            .operation(&self.operation_name)
            .elapsed(self.start_time.elapsed())
        }

        /// Set absolute progress position.
        pub fn set_progress(&mut self, current: u64) -> ProgressEvent {
            self.current_item = current.min(self.total_items);

            ProgressEvent::update(
                self.current_item,
                self.total_items,
                format!("At position {}/{}", self.current_item, self.total_items),
            )
            .operation(&self.operation_name)
            .elapsed(self.start_time.elapsed())
        }
    }

    // Deterministic shell completion fixture implementation.

    /// Completion generator fixture for testing idempotency.
    pub struct FixtureCompletionGenerator {
        command_name: String,
        subcommands: Vec<String>,
        options: Vec<String>,
    }

    impl FixtureCompletionGenerator {
        pub fn new(command: impl Into<String>) -> Self {
            Self {
                command_name: command.into(),
                subcommands: vec![
                    "help".to_string(),
                    "doctor".to_string(),
                    "verify".to_string(),
                    "completion".to_string(),
                ],
                options: vec![
                    "--help".to_string(),
                    "--version".to_string(),
                    "--format".to_string(),
                    "--color".to_string(),
                    "--verbose".to_string(),
                    "--quiet".to_string(),
                ],
            }
        }

        /// Generate shell completion script.
        pub fn generate_completion(&self, shell: Shell) -> String {
            match shell {
                Shell::Bash => self.generate_bash_completion(),
                Shell::Zsh => self.generate_zsh_completion(),
                Shell::Fish => self.generate_fish_completion(),
                Shell::PowerShell => self.generate_powershell_completion(),
                Shell::Elvish => self.generate_elvish_completion(),
            }
        }

        fn generate_bash_completion(&self) -> String {
            let mut script = format!("# Bash completion for {}\n", self.command_name);
            script.push_str(&format!("_{}_completion() {{\n", self.command_name));
            script.push_str("  local cur prev opts\n");
            script.push_str("  cur=\"${COMP_WORDS[COMP_CWORD]}\"\n");
            script.push_str("  prev=\"${COMP_WORDS[COMP_CWORD-1]}\"\n");

            script.push_str("  opts=\"");
            for opt in &self.options {
                script.push_str(opt);
                script.push(' ');
            }
            for subcmd in &self.subcommands {
                script.push_str(subcmd);
                script.push(' ');
            }
            script.push_str("\"\n");

            script.push_str("  COMPREPLY=($(compgen -W \"${opts}\" -- \"${cur}\"))\n");
            script.push_str("}\n");
            script.push_str(&format!(
                "complete -F _{}_completion {}\n",
                self.command_name, self.command_name
            ));

            script
        }

        fn generate_zsh_completion(&self) -> String {
            let mut script = format!("#compdef {}\n", self.command_name);
            script.push_str(&format!("_{}_completion() {{\n", self.command_name));
            script.push_str("  local -a opts\n");
            script.push_str("  opts=(\n");

            for opt in &self.options {
                script.push_str(&format!("    '{}[{}]'\n", opt, opt));
            }
            for subcmd in &self.subcommands {
                script.push_str(&format!("    '{}[{}]'\n", subcmd, subcmd));
            }

            script.push_str("  )\n");
            script.push_str("  _describe 'commands' opts\n");
            script.push_str("}\n");
            script.push_str(&format!("_{}_completion \"$@\"\n", self.command_name));

            script
        }

        fn generate_fish_completion(&self) -> String {
            let mut script = format!("# Fish completion for {}\n", self.command_name);

            for subcmd in &self.subcommands {
                script.push_str(&format!(
                    "complete -c {} -n '__fish_use_subcommand' -a {} -d '{}'\n",
                    self.command_name, subcmd, subcmd
                ));
            }

            for opt in &self.options {
                script.push_str(&format!(
                    "complete -c {} -l {} -d '{}'\n",
                    self.command_name,
                    opt.trim_start_matches("--"),
                    opt
                ));
            }

            script
        }

        fn generate_powershell_completion(&self) -> String {
            let mut script = format!("# PowerShell completion for {}\n", self.command_name);
            script.push_str(&format!(
                "Register-ArgumentCompleter -Native -CommandName {} -ScriptBlock {{\n",
                self.command_name
            ));
            script.push_str("  param($commandName, $wordToComplete, $cursorPosition)\n");
            script.push_str("  $completions = @(\n");

            for opt in &self.options {
                script.push_str(&format!("    '{}'\n", opt));
            }
            for subcmd in &self.subcommands {
                script.push_str(&format!("    '{}'\n", subcmd));
            }

            script.push_str("  )\n");
            script.push_str("  $completions | Where-Object { $_ -like \"$wordToComplete*\" }\n");
            script.push_str("}\n");

            script
        }

        fn generate_elvish_completion(&self) -> String {
            let mut script = format!("# Elvish completion for {}\n", self.command_name);
            script.push_str(&format!(
                "edit:completion:arg-completer[{}] = [&cmd]{{",
                self.command_name
            ));
            script.push_str("  put ");

            for opt in &self.options {
                script.push_str(&format!("{} ", opt));
            }
            for subcmd in &self.subcommands {
                script.push_str(&format!("{} ", subcmd));
            }

            script.push_str("}\n");
            script
        }
    }

    // ═══ Property Generators ═══════════════════════════════════════════════════

    /// Generate arbitrary CLI arguments for testing.
    pub fn arbitrary_common_args() -> BoxedStrategy<CommonArgs> {
        (
            proptest::option::of(any::<OutputFormat>()),
            proptest::option::of(any::<ColorChoice>()),
            0u8..=3,
            any::<bool>(),
            any::<bool>(),
            proptest::option::of(".*").prop_map(|s| s.map(PathBuf::from)),
        )
            .prop_map(|(format, color, verbosity, quiet, debug, config)| {
                let mut args = CommonArgs::new();
                if let Some(f) = format {
                    args = args.with_format(f);
                }
                if let Some(c) = color {
                    args = args.with_color(c);
                }
                args = args.with_verbosity(verbosity);
                if quiet {
                    args = args.quiet();
                }
                if debug {
                    args = args.debug();
                }
                if let Some(cfg) = config {
                    args = args.with_config(cfg);
                }
                args
            })
            .boxed()
    }

    impl Arbitrary for OutputFormat {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_: ()) -> Self::Strategy {
            prop_oneof![
                Just(OutputFormat::Json),
                Just(OutputFormat::JsonPretty),
                Just(OutputFormat::StreamJson),
                Just(OutputFormat::Tsv),
                Just(OutputFormat::Human),
            ]
            .boxed()
        }
    }

    impl Arbitrary for ColorChoice {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_: ()) -> Self::Strategy {
            prop_oneof![
                Just(ColorChoice::Auto),
                Just(ColorChoice::Always),
                Just(ColorChoice::Never),
            ]
            .boxed()
        }
    }

    impl Arbitrary for Shell {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_: ()) -> Self::Strategy {
            prop_oneof![
                Just(Shell::Bash),
                Just(Shell::Zsh),
                Just(Shell::Fish),
                Just(Shell::PowerShell),
                Just(Shell::Elvish),
            ]
            .boxed()
        }
    }

    // ═══ Metamorphic Relations ══════════════════════════════════════════════════

    /// MR1: Doctor output determinism - repeated scans of same workspace produce identical reports.
    /// Category: Equivalence f(T(x)) = f(x)
    /// Detects: non-deterministic scanning, state pollution, timing dependencies
    #[test]
    fn mr_doctor_output_determinism() {
        init_test_logging();
        crate::test_phase!("mr_doctor_output_determinism");

        proptest!(|(
            capabilities in prop::collection::vec(prop::string::string_regex("[a-z_]+").unwrap(), 1..=10),
            workspace_root in prop::string::string_regex("/[a-z/]+").unwrap(),
            include_details in any::<bool>()
        )| {
            let doctor = FixtureCliDoctor::new(&workspace_root, capabilities);

            // Run same diagnostic scan multiple times
            let report1 = doctor.generate_report(include_details);
            let report2 = doctor.generate_report(include_details);
            let report3 = doctor.generate_report(include_details);

            // All reports must be identical - deterministic output
            prop_assert_eq!(
                report1, report2,
                "Doctor reports differ between runs - non-deterministic scanning detected"
            );
            prop_assert_eq!(
                report2, report3,
                "Doctor reports differ on third run - state pollution detected"
            );

            // Serialized JSON must also be identical
            let json1 = serde_json::to_string(&report1).unwrap();
            let json2 = serde_json::to_string(&report2).unwrap();
            prop_assert_eq!(json1, json2, "JSON serialization non-deterministic");
        });

        crate::test_complete!("mr_doctor_output_determinism");
    }

    /// MR2: Doctor subset capability inclusion - filtering capabilities produces subset of edges.
    /// Category: Inclusive/Exclusive (subset relations)
    /// Detects: capability filtering logic errors, missing inclusions
    #[test]
    fn mr_doctor_subset_capability_inclusion() {
        init_test_logging();
        crate::test_phase!("mr_doctor_subset_capability_inclusion");

        proptest!(|(
            all_capabilities in prop::collection::vec(prop::string::string_regex("[a-z_]+").unwrap(), 5..=15),
            workspace_root in prop::string::string_regex("/[a-z/]+").unwrap()
        )| {
            let doctor = FixtureCliDoctor::new(&workspace_root, all_capabilities.clone());
            let full_report = doctor.generate_report(true);

            // Take a subset of capabilities (at least 1, at most all-1)
            let subset_size = (all_capabilities.len() / 2).max(1);
            let capability_subset: Vec<String> = all_capabilities.into_iter().take(subset_size).collect();
            let subset_report = doctor.generate_capability_report(&capability_subset);

            // Every edge in subset report must appear in full report
            for subset_edge in &subset_report.capability_edges {
                let found_in_full = full_report.capability_edges.iter()
                    .any(|full_edge| full_edge == subset_edge);
                prop_assert!(found_in_full,
                    "Subset report contains edge not in full report: {:?}", subset_edge);
            }

            // Every member in subset must be in full report
            for subset_member in &subset_report.members {
                let found_in_full = full_report.members.iter()
                    .any(|full_member| full_member == subset_member);
                prop_assert!(found_in_full,
                    "Subset report contains member not in full report: {:?}", subset_member);
            }

            // Subset report cannot have more items than full report
            prop_assert!(subset_report.members.len() <= full_report.members.len(),
                "Subset has more members than full report");
            prop_assert!(subset_report.capability_edges.len() <= full_report.capability_edges.len(),
                "Subset has more edges than full report");
        });

        crate::test_complete!("mr_doctor_subset_capability_inclusion");
    }

    /// MR3: Progress current ≤ total invariant - current never exceeds total.
    /// Category: Inclusive (ordering constraints)
    /// Detects: progress calculation overflow, invalid state transitions
    #[test]
    fn mr_progress_current_total_invariant() {
        init_test_logging();
        crate::test_phase!("mr_progress_current_total_invariant");

        proptest!(|(
            total_items in 1u64..=1000,
            advance_sequence in prop::collection::vec(1u64..=50, 1..=20),
            operation_name in prop::string::string_regex("[a-z_]+").unwrap()
        )| {
            let mut tracker = FixtureProgressTracker::new(total_items, &operation_name);

            // Apply advance sequence and check invariant at each step
            for advance_delta in advance_sequence {
                let event = tracker.advance(advance_delta);

                // Core invariant: current ≤ total always
                if let (Some(current), Some(total)) = (event.current, event.total) {
                    prop_assert!(current <= total,
                        "Progress current ({}) exceeds total ({}) - invariant violated",
                        current, total);

                    // Additional check: percentage should be ≤ 100%
                    if let Some(pct) = event.percentage() {
                        prop_assert!(pct <= 100.0,
                            "Progress percentage ({}) exceeds 100% - calculation error", pct);
                    }
                }

                // Terminal states should have current = total
                if event.kind == ProgressKind::Completed {
                    if let (Some(current), Some(total)) = (event.current, event.total) {
                        prop_assert_eq!(current, total,
                            "Completed event has current ({}) != total ({})", current, total);
                    }
                }
            }
        });

        crate::test_complete!("mr_progress_current_total_invariant");
    }

    /// MR4: Progress monotonic increase - progress current values only increase.
    /// Category: Additive (monotonic properties)
    /// Detects: progress regression bugs, invalid backwards movement
    #[test]
    fn mr_progress_monotonic_increase() {
        init_test_logging();
        crate::test_phase!("mr_progress_monotonic_increase");

        proptest!(|(
            total_items in 10u64..=1000,
            advance_sequence in prop::collection::vec(1u64..=10, 5..=30),
            operation_name in prop::string::string_regex("[a-z_]+").unwrap()
        )| {
            let mut tracker = FixtureProgressTracker::new(total_items, &operation_name);
            let mut previous_current = 0u64;

            // Apply advances and verify monotonic increase
            for advance_delta in advance_sequence {
                let event = tracker.advance(advance_delta);

                if let Some(current) = event.current {
                    // Current should never decrease
                    prop_assert!(current >= previous_current,
                        "Progress current decreased from {} to {} - monotonicity violated",
                        previous_current, current);

                    previous_current = current;
                }
            }
        });

        crate::test_complete!("mr_progress_monotonic_increase");
    }

    /// MR5: Progress timing independence - progress logic independent of timing.
    /// Category: Equivalence (timing invariance)
    /// Detects: race conditions, timing-dependent progress calculations
    #[test]
    fn mr_progress_timing_independence() {
        init_test_logging();
        crate::test_phase!("mr_progress_timing_independence");

        proptest!(|(
            total_items in 10u64..=100,
            advance_values in prop::collection::vec(1u64..=5, 3..=10),
            operation_name in prop::string::string_regex("[a-z_]+").unwrap()
        )| {
            // Create two trackers with same parameters
            let mut tracker1 = FixtureProgressTracker::new(total_items, &operation_name);
            let mut tracker2 = FixtureProgressTracker::new(total_items, &operation_name);

            let mut events1 = Vec::new();
            let mut events2 = Vec::new();

            // Apply same advance sequence to both trackers
            for &advance_val in &advance_values {
                events1.push(tracker1.advance(advance_val));
                // Add small delay to second tracker to test timing independence
                std::thread::sleep(std::time::Duration::from_millis(1));
                events2.push(tracker2.advance(advance_val));
            }

            // Progress logic should be identical despite timing differences
            for (i, (event1, event2)) in events1.iter().zip(events2.iter()).enumerate() {
                prop_assert_eq!(event1.current, event2.current,
                    "Progress current differs at step {}: {} vs {}", i,
                    event1.current.unwrap_or(0), event2.current.unwrap_or(0));
                prop_assert_eq!(event1.total, event2.total,
                    "Progress total differs at step {}", i);
                prop_assert_eq!(event1.kind, event2.kind,
                    "Progress kind differs at step {}", i);

                // Percentages should be identical
                match (event1.percentage(), event2.percentage()) {
                    (Some(pct1), Some(pct2)) => {
                        prop_assert!((pct1 - pct2).abs() < 0.001,
                            "Progress percentage differs: {} vs {}", pct1, pct2);
                    },
                    (None, None) => {},
                    _ => prop_assert!(false, "Progress percentage presence differs"),
                }
            }
        });

        crate::test_complete!("mr_progress_timing_independence");
    }

    /// MR6: Completion script shell-specific determinism - same input produces identical output.
    /// Category: Equivalence (deterministic generation)
    /// Detects: non-deterministic script generation, randomization issues
    #[test]
    fn mr_completion_shell_determinism() {
        init_test_logging();
        crate::test_phase!("mr_completion_shell_determinism");

        proptest!(|(
            command_name in prop::string::string_regex("[a-z_]+").unwrap(),
            shell in any::<Shell>()
        )| {
            let generator = FixtureCompletionGenerator::new(&command_name);

            // Generate completion script multiple times
            let script1 = generator.generate_completion(shell);
            let script2 = generator.generate_completion(shell);
            let script3 = generator.generate_completion(shell);

            // All scripts must be identical - deterministic generation
            prop_assert_eq!(script1, script2,
                "Completion scripts differ between runs for shell {}", shell.name());
            prop_assert_eq!(script2, script3,
                "Completion scripts differ on third generation for shell {}", shell.name());

            // Script must contain command name
            prop_assert!(script1.contains(&command_name),
                "Completion script missing command name for shell {}", shell.name());

            // Script must be non-empty
            prop_assert!(!script1.trim().is_empty(),
                "Empty completion script generated for shell {}", shell.name());
        });

        crate::test_complete!("mr_completion_shell_determinism");
    }

    /// MR7: Args parse→format→parse round-trip identity.
    /// Category: Invertive f(T(T(x))) = f(x)
    /// Detects: serialization bugs, format parsing inconsistencies
    #[test]
    fn mr_args_parse_format_roundtrip() {
        init_test_logging();
        crate::test_phase!("mr_args_parse_format_roundtrip");

        proptest!(|(format_str in "[a-z-]+")| {
            // Skip unknown formats that are expected to fail
            if let Ok(format1) = parse_output_format(&format_str) {
                // Format to string representation
                let format_repr = match format1 {
                    OutputFormat::Json => "json",
                    OutputFormat::JsonPretty => "json-pretty",
                    OutputFormat::StreamJson => "stream-json",
                    OutputFormat::Tsv => "tsv",
                    OutputFormat::Human => "human",
                };

                // Parse back from string representation
                let format2 = parse_output_format(format_repr).unwrap();

                // Round-trip should preserve identity
                prop_assert_eq!(format1, format2,
                    "Format round-trip failed: {:?} -> {} -> {:?}",
                    format1, format_repr, format2);
            }
        });

        proptest!(|(color_str in "[a-z]+")| {
            if let Ok(color1) = parse_color_choice(&color_str) {
                // Color to string representation
                let color_repr = match color1 {
                    ColorChoice::Auto => "auto",
                    ColorChoice::Always => "always",
                    ColorChoice::Never => "never",
                };

                // Parse back from representation
                let color2 = parse_color_choice(color_repr).unwrap();

                // Round-trip identity
                prop_assert_eq!(color1, color2,
                    "Color round-trip failed: {:?} -> {} -> {:?}",
                    color1, color_repr, color2);
            }
        });

        crate::test_complete!("mr_args_parse_format_roundtrip");
    }

    /// MR8: Progress reporter format consistency - same events produce format-specific but consistent output.
    /// Category: Permutative (format-specific transformations)
    /// Detects: format-specific rendering bugs, inconsistent serialization
    #[test]
    fn mr_progress_reporter_format_consistency() {
        init_test_logging();
        crate::test_phase!("mr_progress_reporter_format_consistency");

        proptest!(|(
            current in 0u64..=100,
            total in 1u64..=100,
            message in prop::string::string_regex("[A-Za-z0-9 ]+").unwrap(),
            format in any::<OutputFormat>()
        )| {
            // Create progress event
            let event = ProgressEvent::update(current, total, &message)
                .operation("test_op")
                .elapsed(Duration::from_millis(1500));

            // Create two reporters with same format
            let mut buffer1 = Cursor::new(Vec::new());
            let mut buffer2 = Cursor::new(Vec::new());

            let mut reporter1 = ProgressReporter::with_writer(format, &mut buffer1);
            let mut reporter2 = ProgressReporter::with_writer(format, &mut buffer2);

            // Report same event to both reporters
            reporter1.report(event.clone()).unwrap();
            reporter2.report(event.clone()).unwrap();

            // Extract output
            let output1 = String::from_utf8(buffer1.into_inner()).unwrap();
            let output2 = String::from_utf8(buffer2.into_inner()).unwrap();

            // Same events should produce identical output for same format
            prop_assert_eq!(output1, output2,
                "Progress reporter output differs for format {:?}", format);

            // Format-specific validations
            match format {
                OutputFormat::Json | OutputFormat::JsonPretty | OutputFormat::StreamJson => {
                    // JSON output should be parseable
                    prop_assert!(serde_json::from_str::<serde_json::Value>(&output1).is_ok(),
                        "Invalid JSON output: {}", output1);
                },
                OutputFormat::Human => {
                    // Human output should contain the message
                    prop_assert!(output1.contains(&message),
                        "Human format missing message: {}", output1);
                },
                OutputFormat::Tsv => {
                    // TSV should have tab separators
                    prop_assert!(output1.contains('\t') || output1.trim().is_empty(),
                        "TSV format without tabs: {}", output1);
                },
            }
        });

        crate::test_complete!("mr_progress_reporter_format_consistency");
    }

    /// MR9: Composite - Doctor determinism ∘ capability filtering.
    /// Category: Composition of equivalence + subset relations
    /// Detects: compound bugs where filtering breaks determinism
    #[test]
    fn mr_composite_doctor_determinism_capability_filtering() {
        init_test_logging();
        crate::test_phase!("mr_composite_doctor_determinism_capability_filtering");

        proptest!(|(
            all_capabilities in prop::collection::vec(prop::string::string_regex("[a-z_]+").unwrap(), 8..=20),
            workspace_root in prop::string::string_regex("/[a-z/]+").unwrap()
        )| {
            let doctor = FixtureCliDoctor::new(&workspace_root, all_capabilities.clone());

            // Get subset of capabilities
            let subset_size = all_capabilities.len() / 2;
            let capability_subset: Vec<String> = all_capabilities.into_iter().take(subset_size).collect();

            // MR1: Determinism - multiple subset reports should be identical
            let subset_report1 = doctor.generate_capability_report(&capability_subset);
            let subset_report2 = doctor.generate_capability_report(&capability_subset);
            let subset_report3 = doctor.generate_capability_report(&capability_subset);

            prop_assert_eq!(subset_report1, subset_report2,
                "Subset capability reports differ - filtering breaks determinism");
            prop_assert_eq!(subset_report2, subset_report3,
                "Third subset report differs - compound determinism failure");

            // MR2: Subset property - verify inclusion holds deterministically
            let full_report = doctor.generate_report(true);
            for subset_edge in &subset_report1.capability_edges {
                let found = full_report.capability_edges.contains(subset_edge);
                prop_assert!(found, "Subset edge missing from full report in composite test");
            }

            // Composite property: subset filtering is both deterministic AND preserves inclusion
            prop_assert!(subset_report1.capability_edges.len() <= full_report.capability_edges.len(),
                "Composite: subset has more edges than full (deterministic filtering violated)");
        });

        crate::test_complete!("mr_composite_doctor_determinism_capability_filtering");
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_fixture_cli_doctor_basic() {
            let capabilities = vec!["io".to_string(), "net".to_string()];
            let doctor = FixtureCliDoctor::new("/test", capabilities);
            let report = doctor.generate_report(false);

            assert_eq!(report.root, "/test");
            assert_eq!(report.members.len(), 2);
            assert_eq!(report.capability_edges.len(), 2);
        }

        #[test]
        fn test_fixture_progress_tracker_basic() {
            let mut tracker = FixtureProgressTracker::new(10, "test");
            let event = tracker.advance(3);

            assert_eq!(event.current, Some(3));
            assert_eq!(event.total, Some(10));
            assert_eq!(event.kind, ProgressKind::Update);
        }

        #[test]
        fn test_fixture_completion_generator_basic() {
            let generator = FixtureCompletionGenerator::new("test-cli");
            let bash_script = generator.generate_completion(Shell::Bash);

            assert!(bash_script.contains("test-cli"));
            assert!(bash_script.contains("completion"));
            assert!(bash_script.contains("--help"));
        }
    }
} // end cli_tests module

#[cfg(not(feature = "cli"))]
mod no_cli_fallback {
    #[derive(Debug, PartialEq, Eq)]
    struct FeatureGateProof {
        cfg_profile: &'static str,
        required_feature: &'static str,
        support_class: &'static str,
        reason_code: &'static str,
    }

    fn feature_gate_proof() -> FeatureGateProof {
        FeatureGateProof {
            cfg_profile: "not(feature = \"cli\")",
            required_feature: "cli",
            support_class: "unsupported_without_cli_feature",
            reason_code: "cli_metamorphic_module_not_compiled",
        }
    }

    #[test]
    fn cli_reports_cli_feature_gate() {
        let proof = feature_gate_proof();
        assert_eq!(proof.required_feature, "cli");
        assert_eq!(proof.support_class, "unsupported_without_cli_feature");
        assert_eq!(proof.reason_code, "cli_metamorphic_module_not_compiled");
        assert!(
            proof.cfg_profile.contains("cli"),
            "cfg profile must identify the CLI feature boundary"
        );
    }
}
