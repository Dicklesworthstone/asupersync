//! Shell completion generation for CLI tools.
//!
//! Provides utilities for generating shell completions for various shells.

use std::io::{self, Write};

/// Supported shells for completion generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shell {
    /// Bash shell.
    Bash,

    /// Zsh shell.
    Zsh,

    /// Fish shell.
    Fish,

    /// PowerShell.
    PowerShell,

    /// Elvish shell.
    Elvish,
}

impl Shell {
    /// Get the shell name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Bash => "bash",
            Self::Zsh => "zsh",
            Self::Fish => "fish",
            Self::PowerShell => "powershell",
            Self::Elvish => "elvish",
        }
    }

    /// Detect the current shell from environment.
    ///
    /// Checks `SHELL` environment variable.
    #[must_use]
    pub fn detect() -> Option<Self> {
        let shell = std::env::var("SHELL").ok()?;
        let shell_name = shell.rsplit('/').next()?;

        match shell_name {
            "bash" => Some(Self::Bash),
            "zsh" => Some(Self::Zsh),
            "fish" => Some(Self::Fish),
            "pwsh" | "powershell" => Some(Self::PowerShell),
            "elvish" => Some(Self::Elvish),
            _ => None,
        }
    }

    /// Parse shell name from string.
    ///
    /// # Errors
    ///
    /// Returns an error if the shell name is not recognized.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "bash" => Ok(Self::Bash),
            "zsh" => Ok(Self::Zsh),
            "fish" => Ok(Self::Fish),
            "powershell" | "pwsh" | "ps" => Ok(Self::PowerShell),
            "elvish" => Ok(Self::Elvish),
            other => Err(format!(
                "Unknown shell '{other}'. Supported: bash, zsh, fish, powershell, elvish"
            )),
        }
    }

    /// Get installation instructions for this shell.
    #[must_use]
    pub fn install_instructions(&self, command_name: &str) -> String {
        match self {
            Self::Bash => format!(
                r" Add to ~/.bashrc or ~/.bash_profile:
source <({command_name} completions bash)

# Or install system-wide:
{command_name} completions bash > /etc/bash_completion.d/{command_name}"
            ),
            Self::Zsh => format!(
                r" Add to ~/.zshrc (before compinit):
source <({command_name} completions zsh)

# Or add to fpath:
{command_name} completions zsh > ~/.zsh/completions/_{command_name}
# Then add ~/.zsh/completions to fpath"
            ),
            Self::Fish => format!(
                r" Install completions:
{command_name} completions fish > ~/.config/fish/completions/{command_name}.fish"
            ),
            Self::PowerShell => format!(
                r" Add to $PROFILE:
{command_name} completions powershell | Out-String | Invoke-Expression"
            ),
            Self::Elvish => format!(
                r" Add to ~/.elvish/rc.elv:
eval ({command_name} completions elvish | slurp)"
            ),
        }
    }
}

/// Completion item representing a possible completion.
#[derive(Clone, Debug)]
pub struct CompletionItem {
    /// The completion value.
    pub value: String,

    /// Description/help text.
    pub description: Option<String>,
}

impl CompletionItem {
    /// Create a new completion item.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            description: None,
        }
    }

    /// Add a description.
    #[must_use]
    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }
}

/// Trait for types that can generate shell completions.
pub trait Completable {
    /// Get the command name.
    fn command_name(&self) -> &str;

    /// Get subcommands.
    fn subcommands(&self) -> Vec<CompletionItem>;

    /// Get global options/flags.
    fn global_options(&self) -> Vec<CompletionItem>;

    /// Get options for a specific subcommand.
    fn subcommand_options(&self, subcommand: &str) -> Vec<CompletionItem>;
}

/// Generate completion script for a shell.
///
/// # Errors
///
/// Returns an error if writing fails.
pub fn generate_completions<W: Write, C: Completable>(
    shell: Shell,
    completable: &C,
    writer: &mut W,
) -> io::Result<()> {
    match shell {
        Shell::Bash => generate_bash_completions(completable, writer),
        Shell::Zsh => generate_zsh_completions(completable, writer),
        Shell::Fish => generate_fish_completions(completable, writer),
        Shell::PowerShell => generate_powershell_completions(completable, writer),
        Shell::Elvish => generate_elvish_completions(completable, writer),
    }
}

fn generate_bash_completions<W: Write, C: Completable>(
    completable: &C,
    writer: &mut W,
) -> io::Result<()> {
    let cmd = completable.command_name();
    let subcommands: Vec<_> = completable.subcommands().iter().map(|c| c.value.clone()).collect();
    let options: Vec<_> = completable
        .global_options()
        .iter()
        .map(|c| c.value.clone())
        .collect();

    writeln!(writer, " Bash completion for {cmd}")?;
    writeln!(writer, "_{cmd}_completions() {{")?;
    writeln!(writer, "    local cur prev")?;
    writeln!(writer, "    cur=\"${{COMP_WORDS[COMP_CWORD]}}\"")?;
    writeln!(writer, "    prev=\"${{COMP_WORDS[COMP_CWORD-1]}}\"")?;
    writeln!(writer)?;
    writeln!(
        writer,
        "    local subcommands=\"{}\"",
        subcommands.join(" ")
    )?;
    writeln!(writer, "    local options=\"{}\"", options.join(" "))?;
    writeln!(writer)?;
    writeln!(writer, "    if [[ ${{COMP_CWORD}} -eq 1 ]]; then")?;
    writeln!(
        writer,
        "        COMPREPLY=( $(compgen -W \"$subcommands $options\" -- \"$cur\") )"
    )?;
    writeln!(writer, "    else")?;
    writeln!(
        writer,
        "        COMPREPLY=( $(compgen -W \"$options\" -- \"$cur\") )"
    )?;
    writeln!(writer, "    fi")?;
    writeln!(writer, "}}")?;
    writeln!(writer)?;
    writeln!(writer, "complete -F _{cmd}_completions {cmd}")?;

    Ok(())
}

fn generate_zsh_completions<W: Write, C: Completable>(
    completable: &C,
    writer: &mut W,
) -> io::Result<()> {
    let cmd = completable.command_name();
    let subcommands = completable.subcommands();
    let options = completable.global_options();

    writeln!(writer, "compdef {cmd}")?;
    writeln!(writer)?;
    writeln!(writer, "_{cmd}() {{")?;
    writeln!(writer, "    local -a commands options")?;
    writeln!(writer)?;
    writeln!(writer, "    commands=(")?;
    for item in &subcommands {
        if let Some(ref desc) = item.description {
            writeln!(writer, "        '{}:{}'", item.value, desc)?;
        } else {
            writeln!(writer, "        '{}'", item.value)?;
        }
    }
    writeln!(writer, "    )")?;
    writeln!(writer)?;
    writeln!(writer, "    options=(")?;
    for item in &options {
        if let Some(ref desc) = item.description {
            writeln!(writer, "        '{}[{}]'", item.value, desc)?;
        } else {
            writeln!(writer, "        '{}'", item.value)?;
        }
    }
    writeln!(writer, "    )")?;
    writeln!(writer)?;
    writeln!(writer, "    _arguments -s \\")?;
    writeln!(writer, "        '1: :->command' \\")?;
    writeln!(writer, "        '*: :->args'")?;
    writeln!(writer)?;
    writeln!(writer, "    case $state in")?;
    writeln!(writer, "        command)")?;
    writeln!(writer, "            _describe -t commands 'commands' commands")?;
    writeln!(writer, "            ;;")?;
    writeln!(writer, "        args)")?;
    writeln!(writer, "            _describe -t options 'options' options")?;
    writeln!(writer, "            ;;")?;
    writeln!(writer, "    esac")?;
    writeln!(writer, "}}")?;
    writeln!(writer)?;
    writeln!(writer, "_{cmd}")?;

    Ok(())
}

fn generate_fish_completions<W: Write, C: Completable>(
    completable: &C,
    writer: &mut W,
) -> io::Result<()> {
    let cmd = completable.command_name();
    let subcommands = completable.subcommands();
    let options = completable.global_options();

    writeln!(writer, " Fish completion for {cmd}")?;
    writeln!(writer)?;

    for item in &subcommands {
        if let Some(ref desc) = item.description {
            writeln!(
                writer,
                "complete -c {cmd} -n '__fish_use_subcommand' -a '{}' -d '{}'",
                item.value, desc
            )?;
        } else {
            writeln!(
                writer,
                "complete -c {cmd} -n '__fish_use_subcommand' -a '{}'",
                item.value
            )?;
        }
    }

    writeln!(writer)?;

    for item in &options {
        let opt = item.value.trim_start_matches('-');
        if item.value.starts_with("--") {
            if let Some(ref desc) = item.description {
                writeln!(writer, "complete -c {cmd} -l '{opt}' -d '{desc}'")?;
            } else {
                writeln!(writer, "complete -c {cmd} -l '{opt}'")?;
            }
        } else if item.value.starts_with('-') {
            if let Some(ref desc) = item.description {
                writeln!(writer, "complete -c {cmd} -s '{opt}' -d '{desc}'")?;
            } else {
                writeln!(writer, "complete -c {cmd} -s '{opt}'")?;
            }
        }
    }

    Ok(())
}

fn generate_powershell_completions<W: Write, C: Completable>(
    completable: &C,
    writer: &mut W,
) -> io::Result<()> {
    let cmd = completable.command_name();
    let subcommands = completable.subcommands();
    let options = completable.global_options();

    writeln!(writer, " PowerShell completion for {cmd}")?;
    writeln!(writer)?;
    writeln!(
        writer,
        "Register-ArgumentCompleter -Native -CommandName {cmd} -ScriptBlock {{"
    )?;
    writeln!(writer, "    param($wordToComplete, $commandAst, $cursorPosition)")?;
    writeln!(writer)?;
    writeln!(writer, "    $commands = @(")?;
    for item in &subcommands {
        let desc = item.description.as_deref().unwrap_or("");
        writeln!(
            writer,
            "        [CompletionResult]::new('{}', '{}', 'ParameterValue', '{}')",
            item.value, item.value, desc
        )?;
    }
    writeln!(writer, "    )")?;
    writeln!(writer)?;
    writeln!(writer, "    $options = @(")?;
    for item in &options {
        let desc = item.description.as_deref().unwrap_or("");
        writeln!(
            writer,
            "        [CompletionResult]::new('{}', '{}', 'ParameterName', '{}')",
            item.value, item.value, desc
        )?;
    }
    writeln!(writer, "    )")?;
    writeln!(writer)?;
    writeln!(writer, "    $commands + $options | Where-Object {{ $_.CompletionText -like \"$wordToComplete*\" }}")?;
    writeln!(writer, "}}")?;

    Ok(())
}

fn generate_elvish_completions<W: Write, C: Completable>(
    completable: &C,
    writer: &mut W,
) -> io::Result<()> {
    let cmd = completable.command_name();
    let subcommands = completable.subcommands();
    let options = completable.global_options();

    writeln!(writer, " Elvish completion for {cmd}")?;
    writeln!(writer)?;
    writeln!(writer, "edit:completion:arg-completer[{cmd}] = {{|@args|")?;
    writeln!(writer, "    var commands = [")?;
    for item in &subcommands {
        let desc = item.description.as_deref().unwrap_or(&item.value);
        writeln!(
            writer,
            "        &{}=(edit:complex-candidate {} &display='{} - {}')",
            item.value, item.value, item.value, desc
        )?;
    }
    writeln!(writer, "    ]")?;
    writeln!(writer)?;
    writeln!(writer, "    var options = [")?;
    for item in &options {
        writeln!(writer, "        {}", item.value)?;
    }
    writeln!(writer, "    ]")?;
    writeln!(writer)?;
    writeln!(writer, "    if (eq (count $args) 1) {{")?;
    writeln!(writer, "        keys $commands")?;
    writeln!(writer, "    }} else {{")?;
    writeln!(writer, "        all $options")?;
    writeln!(writer, "    }}")?;
    writeln!(writer, "}}")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_names() {
        assert_eq!(Shell::Bash.name(), "bash");
        assert_eq!(Shell::Zsh.name(), "zsh");
        assert_eq!(Shell::Fish.name(), "fish");
        assert_eq!(Shell::PowerShell.name(), "powershell");
        assert_eq!(Shell::Elvish.name(), "elvish");
    }

    #[test]
    fn shell_parse_valid() {
        assert_eq!(Shell::parse("bash").unwrap(), Shell::Bash);
        assert_eq!(Shell::parse("ZSH").unwrap(), Shell::Zsh);
        assert_eq!(Shell::parse("fish").unwrap(), Shell::Fish);
        assert_eq!(Shell::parse("powershell").unwrap(), Shell::PowerShell);
        assert_eq!(Shell::parse("pwsh").unwrap(), Shell::PowerShell);
        assert_eq!(Shell::parse("elvish").unwrap(), Shell::Elvish);
    }

    #[test]
    fn shell_parse_invalid() {
        let err = Shell::parse("cmd").unwrap_err();
        assert!(err.contains("Unknown shell"));
    }

    #[test]
    fn install_instructions_contain_command() {
        let instructions = Shell::Bash.install_instructions("mytool");
        assert!(instructions.contains("mytool"));
        assert!(instructions.contains("completions bash"));
    }

    #[test]
    fn completion_item_builder() {
        let item = CompletionItem::new("--help").description("Show help");
        assert_eq!(item.value, "--help");
        assert_eq!(item.description, Some("Show help".to_string()));
    }

    struct TestCompletable;

    impl Completable for TestCompletable {
        fn command_name(&self) -> &str {
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

        fn subcommand_options(&self, _subcommand: &str) -> Vec<CompletionItem> {
            vec![]
        }
    }

    #[test]
    fn generate_bash_completions_works() {
        let mut buf = Vec::new();
        generate_completions(Shell::Bash, &TestCompletable, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("_testcmd_completions"));
        assert!(output.contains("complete -F"));
        assert!(output.contains("run"));
        assert!(output.contains("--help"));
    }

    #[test]
    fn generate_zsh_completions_works() {
        let mut buf = Vec::new();
        generate_completions(Shell::Zsh, &TestCompletable, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("compdef testcmd"));
        assert!(output.contains("_testcmd"));
        assert!(output.contains("run:Run the program"));
    }

    #[test]
    fn generate_fish_completions_works() {
        let mut buf = Vec::new();
        generate_completions(Shell::Fish, &TestCompletable, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("complete -c testcmd"));
        assert!(output.contains("-a 'run'"));
    }
}
