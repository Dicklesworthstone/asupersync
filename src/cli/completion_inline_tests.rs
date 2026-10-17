    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use serde_json::json;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn shell_names() {
        init_test("shell_names");
        let bash = Shell::Bash.name();
        crate::assert_with_log!(bash == "bash", "bash name", "bash", bash);
        let zsh = Shell::Zsh.name();
        crate::assert_with_log!(zsh == "zsh", "zsh name", "zsh", zsh);
        let fish = Shell::Fish.name();
        crate::assert_with_log!(fish == "fish", "fish name", "fish", fish);
        let pwsh = Shell::PowerShell.name();
        crate::assert_with_log!(pwsh == "powershell", "powershell name", "powershell", pwsh);
        let elvish = Shell::Elvish.name();
        crate::assert_with_log!(elvish == "elvish", "elvish name", "elvish", elvish);
        crate::test_complete!("shell_names");
    }

    #[test]
    fn shell_parse_valid() {
        init_test("shell_parse_valid");
        let bash = Shell::parse("bash").unwrap();
        crate::assert_with_log!(bash == Shell::Bash, "parse bash", Shell::Bash, bash);
        let zsh = Shell::parse("ZSH").unwrap();
        crate::assert_with_log!(zsh == Shell::Zsh, "parse zsh", Shell::Zsh, zsh);
        let fish = Shell::parse("fish").unwrap();
        crate::assert_with_log!(fish == Shell::Fish, "parse fish", Shell::Fish, fish);
        let pwsh = Shell::parse("powershell").unwrap();
        crate::assert_with_log!(
            pwsh == Shell::PowerShell,
            "parse powershell",
            Shell::PowerShell,
            pwsh
        );
        let pwsh_short = Shell::parse("pwsh").unwrap();
        crate::assert_with_log!(
            pwsh_short == Shell::PowerShell,
            "parse pwsh",
            Shell::PowerShell,
            pwsh_short
        );
        let elvish = Shell::parse("elvish").unwrap();
        crate::assert_with_log!(
            elvish == Shell::Elvish,
            "parse elvish",
            Shell::Elvish,
            elvish
        );
        crate::test_complete!("shell_parse_valid");
    }

    #[test]
    fn shell_parse_invalid() {
        init_test("shell_parse_invalid");
        let err = Shell::parse("cmd").unwrap_err();
        let contains = err.contains("Unknown shell");
        crate::assert_with_log!(contains, "unknown shell", true, contains);
        crate::test_complete!("shell_parse_invalid");
    }

    #[test]
    fn install_instructions_contain_command() {
        init_test("install_instructions_contain_command");
        let instructions = Shell::Bash.install_instructions("mytool");
        let has_tool = instructions.contains("mytool");
        crate::assert_with_log!(has_tool, "contains tool", true, has_tool);
        let has_cmd = instructions.contains("completions bash");
        crate::assert_with_log!(has_cmd, "contains completions", true, has_cmd);
        crate::test_complete!("install_instructions_contain_command");
    }

    #[test]
    fn completion_item_builder() {
        init_test("completion_item_builder");
        let item = CompletionItem::new("--help").description("Show help");
        crate::assert_with_log!(item.value == "--help", "value", "--help", item.value);
        crate::assert_with_log!(
            item.description == Some("Show help".to_string()),
            "description",
            Some("Show help".to_string()),
            item.description
        );
        crate::test_complete!("completion_item_builder");
    }

    struct TestCompletable;

    impl Completable for TestCompletable {
        fn command_name(&self) -> &'static str {
            "testcmd"
        }

        fn subcommands(&self) -> Vec<CompletionItem> {
            vec![
                CompletionItem::new("run").description("Run the program"),
                CompletionItem::new("test").description("Run tests"),
            ]
        }

        fn global_options(&self) -> Vec<CompletionItem> {
            vec![
                CompletionItem::new("--help").description("Show help"),
                CompletionItem::new("-v").description("Verbose"),
            ]
        }

        fn subcommand_options(&self, subcommand: &str) -> Vec<CompletionItem> {
            match subcommand {
                "run" => vec![
                    CompletionItem::new("--dry-run").description("Preview execution"),
                    CompletionItem::new("-j").description("Parallel jobs"),
                ],
                "test" => vec![CompletionItem::new("--nocapture").description("Show test output")],
                _ => vec![],
            }
        }
    }

    struct SnapshotCompletable;

    impl Completable for SnapshotCompletable {
        fn command_name(&self) -> &'static str {
            "asupersync"
        }

        fn subcommands(&self) -> Vec<CompletionItem> {
            vec![
                CompletionItem::new("serve").description("Run the network runtime"),
                CompletionItem::new("trace")
                    .description("Inspect traces in /opt/asupersync/artifacts/traces"),
                CompletionItem::new("doctor").description("Check runtime health"),
                CompletionItem::new("completion").description("Generate shell completions"),
            ]
        }

        fn global_options(&self) -> Vec<CompletionItem> {
            vec![
                CompletionItem::new("--config")
                    .description("Read /home/tester/.config/asupersync/config.toml"),
                CompletionItem::new("--profile").description("Select dev, staging, or prod"),
                CompletionItem::new("--log-dir")
                    .description("Write logs under /var/tmp/asupersync/runtime"),
            ]
        }

        fn subcommand_options(&self, subcommand: &str) -> Vec<CompletionItem> {
            match subcommand {
                "serve" => vec![
                    CompletionItem::new("--listen").description("Bind 127.0.0.1:7447"),
                    CompletionItem::new("--tls-cert")
                        .description("Use /etc/asupersync/tls/server.pem"),
                ],
                "trace" => vec![
                    CompletionItem::new("--input")
                        .description("Open /opt/asupersync/artifacts/traces/current.json"),
                    CompletionItem::new("--format").description("Render json or markdown"),
                ],
                "doctor" => vec![
                    CompletionItem::new("--json").description("Emit machine-readable output"),
                    CompletionItem::new("--socket")
                        .description("Probe /run/asupersync/doctor.sock"),
                ],
                "completion" => vec![
                    CompletionItem::new("--shell").description("Target bash, zsh, or fish"),
                    CompletionItem::new("--output")
                        .description("Write /tmp/asupersync/completions/generated.sh"),
                ],
                _ => vec![],
            }
        }
    }

    fn scrub_completion_script(script: &str) -> String {
        script
            .replace(
                "/home/tester/.config/asupersync/config.toml",
                "<ABS_CONFIG_PATH>",
            )
            .replace(
                "/opt/asupersync/artifacts/traces/current.json",
                "<ABS_TRACE_FILE>",
            )
            .replace("/opt/asupersync/artifacts/traces", "<ABS_TRACE_DIR>")
            .replace("/var/tmp/asupersync/runtime", "<ABS_LOG_DIR>")
            .replace("/etc/asupersync/tls/server.pem", "<ABS_TLS_CERT>")
            .replace("/run/asupersync/doctor.sock", "<ABS_DOCTOR_SOCKET>")
            .replace(
                "/tmp/asupersync/completions/generated.sh",
                "<ABS_OUTPUT_FILE>",
            )
    }

    fn render_scrubbed_completion(shell: Shell) -> String {
        let mut buf = Vec::new();
        generate_completions(shell, &SnapshotCompletable, &mut buf).unwrap();
        scrub_completion_script(&String::from_utf8(buf).unwrap())
    }

    #[test]
    fn generate_bash_completions_works() {
        init_test("generate_bash_completions_works");
        let mut buf = Vec::new();
        generate_completions(Shell::Bash, &TestCompletable, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        let has_completions = output.contains("_testcmd_completions");
        crate::assert_with_log!(has_completions, "has completions", true, has_completions);
        let has_complete = output.contains("complete -F");
        crate::assert_with_log!(has_complete, "has complete -F", true, has_complete);
        let has_run = output.contains("run");
        crate::assert_with_log!(has_run, "has run", true, has_run);
        let has_help = output.contains("--help");
        crate::assert_with_log!(has_help, "has --help", true, has_help);
        let has_subcommand_option = output.contains("--dry-run");
        crate::assert_with_log!(
            has_subcommand_option,
            "has run subcommand option",
            true,
            has_subcommand_option
        );
        crate::test_complete!("generate_bash_completions_works");
    }

    #[test]
    fn generate_zsh_completions_works() {
        init_test("generate_zsh_completions_works");
        let mut buf = Vec::new();
        generate_completions(Shell::Zsh, &TestCompletable, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        let has_compdef = output.contains("compdef _testcmd testcmd");
        crate::assert_with_log!(has_compdef, "has compdef", true, has_compdef);
        let has_cmd = output.contains("_testcmd");
        crate::assert_with_log!(has_cmd, "has _testcmd", true, has_cmd);
        let has_run = output.contains("run:Run the program");
        crate::assert_with_log!(has_run, "has run", true, has_run);
        let has_subcommand_option = output.contains("--dry-run[Preview execution]");
        crate::assert_with_log!(
            has_subcommand_option,
            "has run subcommand option",
            true,
            has_subcommand_option
        );
        crate::test_complete!("generate_zsh_completions_works");
    }

    #[test]
    fn generate_fish_completions_works() {
        init_test("generate_fish_completions_works");
        let mut buf = Vec::new();
        generate_completions(Shell::Fish, &TestCompletable, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        let has_complete = output.contains("complete -c testcmd");
        crate::assert_with_log!(has_complete, "has complete -c", true, has_complete);
        let has_run = output.contains("-a 'run'");
        crate::assert_with_log!(has_run, "has run", true, has_run);
        let has_subcommand_option =
            output.contains("__fish_seen_subcommand_from run") && output.contains("-l 'dry-run'");
        crate::assert_with_log!(
            has_subcommand_option,
            "has run subcommand option",
            true,
            has_subcommand_option
        );
        crate::test_complete!("generate_fish_completions_works");
    }

    #[test]
    fn generated_script_banners_are_comments() {
        init_test("generated_script_banners_are_comments");

        for shell in [Shell::Bash, Shell::Fish, Shell::PowerShell, Shell::Elvish] {
            let mut buf = Vec::new();
            generate_completions(shell, &TestCompletable, &mut buf).unwrap();
            let output = String::from_utf8(buf).unwrap();
            let first_non_empty = output
                .lines()
                .find(|line| !line.trim().is_empty())
                .unwrap_or_default();
            let is_comment = first_non_empty.trim_start().starts_with('#');
            crate::assert_with_log!(
                is_comment,
                "script banner is comment",
                true,
                first_non_empty
            );
        }

        crate::test_complete!("generated_script_banners_are_comments");
    }

    #[test]
    fn shell_debug() {
        init_test("shell_debug");
        assert_eq!(format!("{:?}", Shell::Bash), "Bash");
        assert_eq!(format!("{:?}", Shell::Zsh), "Zsh");
        assert_eq!(format!("{:?}", Shell::Fish), "Fish");
        assert_eq!(format!("{:?}", Shell::PowerShell), "PowerShell");
        assert_eq!(format!("{:?}", Shell::Elvish), "Elvish");
        crate::test_complete!("shell_debug");
    }

    #[test]
    fn shell_clone_copy_eq() {
        init_test("shell_clone_copy_eq");
        let s = Shell::Zsh;
        let s2 = s;
        let s3 = s;
        assert_eq!(s2, s3);
        assert_ne!(Shell::Bash, Shell::Zsh);
        crate::test_complete!("shell_clone_copy_eq");
    }

    #[test]
    fn shell_parse_ps_alias() {
        init_test("shell_parse_ps_alias");
        let ps = Shell::parse("ps").unwrap();
        assert_eq!(ps, Shell::PowerShell);
        crate::test_complete!("shell_parse_ps_alias");
    }

    #[test]
    fn install_instructions_all_shells() {
        init_test("install_instructions_all_shells");
        let shells = [
            Shell::Bash,
            Shell::Zsh,
            Shell::Fish,
            Shell::PowerShell,
            Shell::Elvish,
        ];
        for shell in &shells {
            let instructions = shell.install_instructions("mycli");
            let has_cmd = instructions.contains("mycli");
            crate::assert_with_log!(has_cmd, "has command name", true, has_cmd);
        }
        crate::test_complete!("install_instructions_all_shells");
    }

    #[test]
    fn completion_item_debug_clone() {
        init_test("completion_item_debug_clone");
        let item = CompletionItem::new("test").description("A test");
        let dbg = format!("{item:?}");
        assert!(dbg.contains("CompletionItem"));
        let item2 = item;
        assert_eq!(item2.value, "test");
        assert_eq!(item2.description, Some("A test".to_string()));
        crate::test_complete!("completion_item_debug_clone");
    }

    #[test]
    fn completion_item_without_description() {
        init_test("completion_item_without_description");
        let item = CompletionItem::new("--verbose");
        assert_eq!(item.value, "--verbose");
        assert!(item.description.is_none());
        crate::test_complete!("completion_item_without_description");
    }

    #[test]
    fn generate_powershell_completions_works() {
        init_test("generate_powershell_completions_works");
        let mut buf = Vec::new();
        generate_completions(Shell::PowerShell, &TestCompletable, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let has_cmd = output.contains("testcmd");
        crate::assert_with_log!(has_cmd, "has command name", true, has_cmd);
        let has_subcommand_option =
            output.contains("$subcommandOptions") && output.contains("--nocapture");
        crate::assert_with_log!(
            has_subcommand_option,
            "has test subcommand option",
            true,
            has_subcommand_option
        );
        crate::test_complete!("generate_powershell_completions_works");
    }

    #[test]
    fn generate_elvish_completions_works() {
        init_test("generate_elvish_completions_works");
        let mut buf = Vec::new();
        generate_completions(Shell::Elvish, &TestCompletable, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let has_cmd = output.contains("testcmd");
        crate::assert_with_log!(has_cmd, "has command name", true, has_cmd);
        let has_completion = output.contains("arg-completer");
        crate::assert_with_log!(has_completion, "has arg-completer", true, has_completion);
        let has_subcommand_option = output.contains("put --dry-run");
        crate::assert_with_log!(
            has_subcommand_option,
            "has run subcommand option",
            true,
            has_subcommand_option
        );
        crate::test_complete!("generate_elvish_completions_works");
    }

    #[test]
    fn bash_subcommand_detection_scans_prior_words() {
        init_test("bash_subcommand_detection_scans_prior_words");
        let mut buf = Vec::new();
        generate_completions(Shell::Bash, &TestCompletable, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        let scans_prior_words = output.contains("for ((idx = 1; idx < COMP_CWORD; idx++)); do");
        crate::assert_with_log!(
            scans_prior_words,
            "bash scans prior words",
            true,
            scans_prior_words
        );
        let avoids_fixed_index = !output.contains("${COMP_WORDS[1]}");
        crate::assert_with_log!(
            avoids_fixed_index,
            "bash avoids fixed index",
            true,
            avoids_fixed_index
        );
        let keeps_commands_until_subcommand = output.contains("if [[ -z \"$subcommand\" ]]; then");
        crate::assert_with_log!(
            keeps_commands_until_subcommand,
            "bash keeps subcommands before selection",
            true,
            keeps_commands_until_subcommand
        );
        crate::test_complete!("bash_subcommand_detection_scans_prior_words");
    }

    #[test]
    fn zsh_subcommand_detection_scans_prior_words() {
        init_test("zsh_subcommand_detection_scans_prior_words");
        let mut buf = Vec::new();
        generate_completions(Shell::Zsh, &TestCompletable, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        let scans_prior_words = output.contains("for (( idx = 2; idx < CURRENT; idx++ )); do");
        crate::assert_with_log!(
            scans_prior_words,
            "zsh scans prior words",
            true,
            scans_prior_words
        );
        let avoids_fixed_index = !output.contains("case $words[2] in");
        crate::assert_with_log!(
            avoids_fixed_index,
            "zsh avoids fixed index",
            true,
            avoids_fixed_index
        );
        let keeps_commands_until_subcommand = output.contains("current_items=($commands $options)");
        crate::assert_with_log!(
            keeps_commands_until_subcommand,
            "zsh keeps subcommands before selection",
            true,
            keeps_commands_until_subcommand
        );
        crate::test_complete!("zsh_subcommand_detection_scans_prior_words");
    }

    #[test]
    fn powershell_subcommand_detection_scans_prior_elements() {
        init_test("powershell_subcommand_detection_scans_prior_elements");
        let mut buf = Vec::new();
        generate_completions(Shell::PowerShell, &TestCompletable, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        let scans_prior_elements = output.contains("for ($i = 1; $i -lt $scanCount; $i++) {");
        crate::assert_with_log!(
            scans_prior_elements,
            "powershell scans prior elements",
            true,
            scans_prior_elements
        );
        let avoids_fixed_index = !output.contains("CommandElements[1].Value");
        crate::assert_with_log!(
            avoids_fixed_index,
            "powershell avoids fixed index",
            true,
            avoids_fixed_index
        );
        crate::test_complete!("powershell_subcommand_detection_scans_prior_elements");
    }

    #[test]
    fn elvish_subcommand_detection_scans_prior_args() {
        init_test("elvish_subcommand_detection_scans_prior_args");
        let mut buf = Vec::new();
        generate_completions(Shell::Elvish, &TestCompletable, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        let scans_prior_args = output.contains("for arg $args[..-1] {");
        crate::assert_with_log!(
            scans_prior_args,
            "elvish scans prior args",
            true,
            scans_prior_args
        );
        let avoids_fixed_index = !output.contains("eq $args[0] run");
        crate::assert_with_log!(
            avoids_fixed_index,
            "elvish avoids fixed index",
            true,
            avoids_fixed_index
        );
        let keeps_commands_until_subcommand = output.contains("if (eq $subcommand '') {");
        crate::assert_with_log!(
            keeps_commands_until_subcommand,
            "elvish keeps subcommands before selection",
            true,
            keeps_commands_until_subcommand
        );
        crate::test_complete!("elvish_subcommand_detection_scans_prior_args");
    }

    #[test]
    fn completion_script_bundle_scrubbed_snapshot() {
        init_test("completion_script_bundle_scrubbed_snapshot");

        let snapshot = json!({
            "bash": render_scrubbed_completion(Shell::Bash),
            "zsh": render_scrubbed_completion(Shell::Zsh),
            "fish": render_scrubbed_completion(Shell::Fish),
        });

        insta::assert_json_snapshot!("completion_script_bundle_scrubbed", snapshot);
        crate::test_complete!("completion_script_bundle_scrubbed_snapshot");
    }

    /// Golden artifact: raw PowerShell + Elvish completion scripts.
    ///
    /// The original `completion_script_bundle_scrubbed` snapshot only
    /// covers bash/zsh/fish; the comprehensive format snapshot records
    /// only analyzer metadata (line_count, char_count, boolean checks) for
    /// PowerShell and Elvish, not their rendered script bodies. A silent
    /// regression in the PowerShell or Elvish renderer (e.g. drift in
    /// `Register-ArgumentCompleter` wiring or `edit:completion:arg-completer`
    /// attachment) would not be caught by either existing golden. This
    /// test closes that gap with a byte-level snapshot of the scrubbed
    /// output for both remaining shells.
    #[test]
    fn completion_script_pwsh_elvish_scrubbed_snapshot() {
        init_test("completion_script_pwsh_elvish_scrubbed_snapshot");

        let snapshot = json!({
            "powershell": render_scrubbed_completion(Shell::PowerShell),
            "elvish": render_scrubbed_completion(Shell::Elvish),
        });

        insta::assert_json_snapshot!("completion_script_pwsh_elvish_scrubbed", snapshot);
        crate::test_complete!("completion_script_pwsh_elvish_scrubbed_snapshot");
    }

    #[test]
    fn completion_script_comprehensive_format_golden_snapshot() {
        init_test("completion_script_comprehensive_format_golden_snapshot");

        // Generate comprehensive completion scripts for all supported shells
        let shells_and_scripts = vec![
            ("bash", Shell::Bash),
            ("zsh", Shell::Zsh),
            ("fish", Shell::Fish),
            ("powershell", Shell::PowerShell),
            ("elvish", Shell::Elvish),
        ];

        let mut comprehensive_report = String::new();
        comprehensive_report.push_str("=== CLI Completion Scripts Comprehensive Report ===\n\n");

        for (shell_name, shell) in shells_and_scripts {
            comprehensive_report.push_str(&format!("[{}]\n", shell_name));

            // Generate raw completion script
            let mut buf = Vec::new();
            generate_completions(shell, &SnapshotCompletable, &mut buf).unwrap();
            let script = String::from_utf8(buf).unwrap();

            // Analyze script characteristics
            let line_count = script.lines().count();
            let char_count = script.len();
            let has_subcommands = script.contains("run") && script.contains("help");
            let has_options = script.contains("--help") && script.contains("--dry-run");

            comprehensive_report.push_str(&format!("line_count: {}\n", line_count));
            comprehensive_report.push_str(&format!("char_count: {}\n", char_count));
            comprehensive_report.push_str(&format!("has_subcommands: {}\n", has_subcommands));
            comprehensive_report.push_str(&format!("has_options: {}\n", has_options));

            // Shell-specific analysis
            match shell {
                Shell::Bash => {
                    let has_complete = script.contains("complete -F");
                    let has_compgen = script.contains("compgen");
                    let has_bash_completion_func = script.contains("_asupersync_completions");
                    comprehensive_report
                        .push_str(&format!("has_complete_function: {}\n", has_complete));
                    comprehensive_report.push_str(&format!("has_compgen: {}\n", has_compgen));
                    comprehensive_report.push_str(&format!(
                        "has_completion_function: {}\n",
                        has_bash_completion_func
                    ));
                }
                Shell::Zsh => {
                    let has_compdef = script.contains("compdef");
                    let has_zsh_function = script.contains("_asupersync");
                    let has_complete_options = script.contains("_arguments");
                    comprehensive_report.push_str(&format!("has_compdef: {}\n", has_compdef));
                    comprehensive_report
                        .push_str(&format!("has_zsh_function: {}\n", has_zsh_function));
                    comprehensive_report
                        .push_str(&format!("has_arguments: {}\n", has_complete_options));
                }
                Shell::Fish => {
                    let has_complete_cmd = script.contains("complete --command");
                    let has_fish_conditions = script.contains("__fish_use_subcommand");
                    comprehensive_report
                        .push_str(&format!("has_complete_command: {}\n", has_complete_cmd));
                    comprehensive_report
                        .push_str(&format!("has_fish_conditions: {}\n", has_fish_conditions));
                }
                Shell::PowerShell => {
                    let has_register = script.contains("Register-ArgumentCompleter");
                    let has_scriptblock = script.contains("scriptblock");
                    comprehensive_report
                        .push_str(&format!("has_register_completer: {}\n", has_register));
                    comprehensive_report
                        .push_str(&format!("has_scriptblock: {}\n", has_scriptblock));
                }
                Shell::Elvish => {
                    let has_edit_completion = script.contains("edit:completion");
                    let has_elvish_arg_completer = script.contains("arg-completer");
                    comprehensive_report
                        .push_str(&format!("has_edit_completion: {}\n", has_edit_completion));
                    comprehensive_report.push_str(&format!(
                        "has_arg_completer: {}\n",
                        has_elvish_arg_completer
                    ));
                }
            }

            comprehensive_report.push('\n');
        }

        // Create golden snapshot for completion format validation
        insta::with_settings!({
            snapshot_path => "../tests/snapshots",
            prepend_module_to_snapshot => false,
        }, {
            insta::assert_snapshot!("cli_completion_comprehensive_format", comprehensive_report.trim_end());
        });

        crate::test_complete!("completion_script_comprehensive_format_golden_snapshot");
    }
