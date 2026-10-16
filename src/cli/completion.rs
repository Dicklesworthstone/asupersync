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

fn completion_values(items: &[CompletionItem]) -> Vec<String> {
    items.iter().map(|item| item.value.clone()).collect()
}

fn subcommand_option_sets<C: Completable>(
    completable: &C,
    subcommands: &[CompletionItem],
) -> Vec<(String, Vec<CompletionItem>)> {
    subcommands
        .iter()
        .map(|item| {
            (
                item.value.clone(),
                completable.subcommand_options(&item.value),
            )
        })
        .collect()
}

fn generate_bash_completions<W: Write, C: Completable>(
    completable: &C,
    writer: &mut W,
) -> io::Result<()> {
    let cmd = completable.command_name();
    let subcommands = completable.subcommands();
    let subcommand_names = completion_values(&subcommands);
    let subcommand_option_sets = subcommand_option_sets(completable, &subcommands);
    let has_subcommand_options = subcommand_option_sets
        .iter()
        .any(|(_, options)| !options.is_empty());
    let options = completion_values(&completable.global_options());

    writeln!(writer, "# Bash completion for {cmd}")?;
    writeln!(writer, "_{cmd}_completions() {{")?;
    writeln!(writer, "    local cur prev")?;
    writeln!(writer, "    cur=\"${{COMP_WORDS[COMP_CWORD]}}\"")?;
    writeln!(writer, "    prev=\"${{COMP_WORDS[COMP_CWORD-1]}}\"")?;
    writeln!(writer)?;
    writeln!(
        writer,
        "    local subcommands=\"{}\"",
        subcommand_names.join(" ")
    )?;
    writeln!(writer, "    local options=\"{}\"", options.join(" "))?;
    writeln!(writer, "    local subcommand=\"\"")?;
    writeln!(writer, "    local subcommand_options=\"\"")?;
    if has_subcommand_options && !subcommand_names.is_empty() {
        writeln!(writer)?;
        writeln!(writer, "    local idx")?;
        writeln!(writer, "    for ((idx = 1; idx < COMP_CWORD; idx++)); do")?;
        writeln!(writer, "        case \"${{COMP_WORDS[idx]}}\" in")?;
        writeln!(writer, "            {})", subcommand_names.join("|"))?;
        writeln!(
            writer,
            "                subcommand=\"${{COMP_WORDS[idx]}}\""
        )?;
        writeln!(writer, "                break")?;
        writeln!(writer, "                ;;")?;
        writeln!(writer, "        esac")?;
        writeln!(writer, "    done")?;
        writeln!(writer)?;
        writeln!(writer, "    case \"$subcommand\" in")?;
        for (subcommand, subcommand_options) in &subcommand_option_sets {
            if !subcommand_options.is_empty() {
                writeln!(
                    writer,
                    "        {subcommand}) subcommand_options=\"{}\" ;;",
                    completion_values(subcommand_options).join(" ")
                )?;
            }
        }
        writeln!(writer, "    esac")?;
    }
    writeln!(writer)?;
    writeln!(writer, "    if [[ -z \"$subcommand\" ]]; then")?;
    writeln!(
        writer,
        "        COMPREPLY=( $(compgen -W \"$subcommands $options\" -- \"$cur\") )"
    )?;
    writeln!(writer, "    else")?;
    writeln!(
        writer,
        "        COMPREPLY=( $(compgen -W \"$options $subcommand_options\" -- \"$cur\") )"
    )?;
    writeln!(writer, "    fi")?;
    writeln!(writer, "}}")?;
    writeln!(writer)?;
    writeln!(writer, "complete -F _{cmd}_completions {cmd}")?;

    Ok(())
}

#[allow(clippy::too_many_lines)]
fn generate_zsh_completions<W: Write, C: Completable>(
    completable: &C,
    writer: &mut W,
) -> io::Result<()> {
    let cmd = completable.command_name();
    let subcommands = completable.subcommands();
    let subcommand_names = completion_values(&subcommands);
    let options = completable.global_options();
    let subcommand_option_sets = subcommand_option_sets(completable, &subcommands);
    let has_subcommand_options = subcommand_option_sets
        .iter()
        .any(|(_, options)| !options.is_empty());

    writeln!(writer, "compdef _{cmd} {cmd}")?;
    writeln!(writer)?;
    writeln!(writer, "_{cmd}() {{")?;
    writeln!(writer, "    local context state line")?;
    writeln!(
        writer,
        "    local -a commands options subcommand_options current_items"
    )?;
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
    writeln!(writer, "    _arguments -C -s \\")?;
    writeln!(writer, "        '1: :->command' \\")?;
    writeln!(writer, "        '*:: :->args'")?;
    writeln!(writer)?;
    writeln!(writer, "    case $state in")?;
    writeln!(writer, "        command)")?;
    writeln!(
        writer,
        "            _describe -t commands 'commands' commands"
    )?;
    writeln!(writer, "            ;;")?;
    writeln!(writer, "        args)")?;
    writeln!(writer, "            local subcommand=''")?;
    writeln!(writer, "            subcommand_options=()")?;
    if has_subcommand_options && !subcommand_names.is_empty() {
        writeln!(writer, "            local idx")?;
        writeln!(
            writer,
            "            for (( idx = 2; idx < CURRENT; idx++ )); do"
        )?;
        writeln!(writer, "                case $words[idx] in")?;
        writeln!(
            writer,
            "                    {})",
            subcommand_names.join("|")
        )?;
        writeln!(writer, "                        subcommand=$words[idx]")?;
        writeln!(writer, "                        break")?;
        writeln!(writer, "                        ;;")?;
        writeln!(writer, "                esac")?;
        writeln!(writer, "            done")?;
        writeln!(writer, "            case $subcommand in")?;
        for (subcommand, subcommand_options) in &subcommand_option_sets {
            if !subcommand_options.is_empty() {
                writeln!(writer, "                {subcommand})")?;
                writeln!(writer, "                    subcommand_options=(")?;
                for item in subcommand_options {
                    if let Some(ref desc) = item.description {
                        writeln!(writer, "                        '{}[{}]'", item.value, desc)?;
                    } else {
                        writeln!(writer, "                        '{}'", item.value)?;
                    }
                }
                writeln!(writer, "                    )")?;
                writeln!(writer, "                    ;;")?;
            }
        }
        writeln!(writer, "            esac")?;
    }
    writeln!(writer, "            if [[ -z $subcommand ]]; then")?;
    writeln!(writer, "                current_items=($commands $options)")?;
    writeln!(writer, "            else")?;
    writeln!(
        writer,
        "                current_items=($options $subcommand_options)"
    )?;
    writeln!(writer, "            fi")?;
    writeln!(
        writer,
        "            _describe -t completions 'completions' current_items"
    )?;
    writeln!(writer, "            ;;")?;
    writeln!(writer, "    esac")?;
    writeln!(writer, "}}")?;

    Ok(())
}

fn generate_fish_completions<W: Write, C: Completable>(
    completable: &C,
    writer: &mut W,
) -> io::Result<()> {
    let cmd = completable.command_name();
    let subcommands = completable.subcommands();
    let options = completable.global_options();
    let subcommand_option_sets = subcommand_option_sets(completable, &subcommands);

    writeln!(writer, "# Fish completion for {cmd}")?;
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

    writeln!(writer)?;

    for (subcommand, subcommand_options) in &subcommand_option_sets {
        for item in subcommand_options {
            let opt = item.value.trim_start_matches('-');
            if item.value.starts_with("--") {
                if let Some(ref desc) = item.description {
                    writeln!(
                        writer,
                        "complete -c {cmd} -n '__fish_seen_subcommand_from {subcommand}' -l '{opt}' -d '{desc}'"
                    )?;
                } else {
                    writeln!(
                        writer,
                        "complete -c {cmd} -n '__fish_seen_subcommand_from {subcommand}' -l '{opt}'"
                    )?;
                }
            } else if item.value.starts_with('-') {
                if let Some(ref desc) = item.description {
                    writeln!(
                        writer,
                        "complete -c {cmd} -n '__fish_seen_subcommand_from {subcommand}' -s '{opt}' -d '{desc}'"
                    )?;
                } else {
                    writeln!(
                        writer,
                        "complete -c {cmd} -n '__fish_seen_subcommand_from {subcommand}' -s '{opt}'"
                    )?;
                }
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
    let subcommand_names = completion_values(&subcommands);
    let options = completable.global_options();
    let subcommand_option_sets = subcommand_option_sets(completable, &subcommands);
    let has_subcommand_options = subcommand_option_sets
        .iter()
        .any(|(_, options)| !options.is_empty());

    writeln!(writer, "# PowerShell completion for {cmd}")?;
    writeln!(writer)?;
    writeln!(
        writer,
        "Register-ArgumentCompleter -Native -CommandName {cmd} -ScriptBlock {{"
    )?;
    writeln!(
        writer,
        "    param($wordToComplete, $commandAst, $cursorPosition)"
    )?;
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
    writeln!(
        writer,
        "    $subcommandNames = @({})",
        subcommand_names
            .iter()
            .map(|name| format!("'{name}'"))
            .collect::<Vec<_>>()
            .join(", ")
    )?;
    writeln!(writer, "    $subcommand = $null")?;
    writeln!(
        writer,
        "    $scanCount = if ($wordToComplete.Length -gt 0) {{ $commandAst.CommandElements.Count - 1 }} else {{ $commandAst.CommandElements.Count }}"
    )?;
    writeln!(writer, "    for ($i = 1; $i -lt $scanCount; $i++) {{")?;
    writeln!(
        writer,
        "        $value = [string]$commandAst.CommandElements[$i].Value"
    )?;
    writeln!(writer, "        if ($subcommandNames -contains $value) {{")?;
    writeln!(writer, "            $subcommand = $value")?;
    writeln!(writer, "            break")?;
    writeln!(writer, "        }}")?;
    writeln!(writer, "    }}")?;
    writeln!(writer, "    $subcommandOptions = @()")?;
    if has_subcommand_options {
        writeln!(writer, "    switch ($subcommand) {{")?;
        for (subcommand, subcommand_options) in &subcommand_option_sets {
            if !subcommand_options.is_empty() {
                writeln!(writer, "        '{subcommand}' {{")?;
                writeln!(writer, "            $subcommandOptions = @(")?;
                for item in subcommand_options {
                    let desc = item.description.as_deref().unwrap_or("");
                    writeln!(
                        writer,
                        "                [CompletionResult]::new('{}', '{}', 'ParameterName', '{}')",
                        item.value, item.value, desc
                    )?;
                }
                writeln!(writer, "            )")?;
                writeln!(writer, "        }}")?;
            }
        }
        writeln!(writer, "    }}")?;
    }
    writeln!(writer)?;
    writeln!(
        writer,
        "    $commands + $options + $subcommandOptions | Where-Object {{ $_.CompletionText -like \"$wordToComplete*\" }}"
    )?;
    writeln!(writer, "}}")?;

    Ok(())
}

fn generate_elvish_completions<W: Write, C: Completable>(
    completable: &C,
    writer: &mut W,
) -> io::Result<()> {
    let cmd = completable.command_name();
    let subcommands = completable.subcommands();
    let subcommand_names = completion_values(&subcommands);
    let options = completable.global_options();
    let subcommand_option_sets = subcommand_option_sets(completable, &subcommands);

    writeln!(writer, "# Elvish completion for {cmd}")?;
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
    writeln!(writer, "        var subcommand = ''")?;
    if !subcommand_names.is_empty() {
        writeln!(writer, "        for arg $args[..-1] {{")?;
        let mut first_branch = true;
        for subcommand in &subcommand_names {
            if first_branch {
                writeln!(writer, "            if (eq $arg {subcommand}) {{")?;
                first_branch = false;
            } else {
                writeln!(writer, "            }} elif (eq $arg {subcommand}) {{")?;
            }
            writeln!(writer, "                set subcommand = {subcommand}")?;
            writeln!(writer, "                break")?;
        }
        if !first_branch {
            writeln!(writer, "            }}")?;
        }
        writeln!(writer, "        }}")?;
    }
    writeln!(writer, "        if (eq $subcommand '') {{")?;
    writeln!(writer, "            keys $commands")?;
    writeln!(writer, "        }}")?;
    writeln!(writer, "        all $options")?;
    let mut first_branch = true;
    for (subcommand, subcommand_options) in &subcommand_option_sets {
        if !subcommand_options.is_empty() {
            if first_branch {
                writeln!(writer, "        if (eq $subcommand {subcommand}) {{")?;
                first_branch = false;
            } else {
                writeln!(writer, "        }} elif (eq $subcommand {subcommand}) {{")?;
            }
            for item in subcommand_options {
                writeln!(writer, "            put {}", item.value)?;
            }
        }
    }
    if !first_branch {
        writeln!(writer, "        }}")?;
    }
    writeln!(writer, "    }}")?;
    writeln!(writer, "}}")?;

    Ok(())
}

#[cfg(test)]
#[path = "completion_inline_tests.rs"]
mod tests;
