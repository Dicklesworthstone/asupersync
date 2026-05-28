//! ATP First-Run Setup and Configuration
//!
//! Handles initial ATP installation, identity creation, configuration setup,
//! and capability/privacy choices for new users.

use crate::cli::atp_config::{AtpInstallConfig, ConfigError, ConfigVersion};
pub use crate::cli::atp_config::{ProofRetentionPolicy, ReceiveSafetyPolicy};
use crate::security::keys::{IdentityKeyStore, KeyStoreError};
use semver::Version;
use std::path::PathBuf;
use std::time::{SystemTime, SystemTimeError};

const LINUX_SYSTEMD_SERVICE_TEMPLATE: &str = r"[Unit]
Description=ATP daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={binary_path} atpd serve --config {config_dir}
Restart=on-failure
RestartSec=2s

[Install]
WantedBy=default.target
";

const MACOS_LAUNCHD_TEMPLATE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.asupersync.atp</string>
  <key>ProgramArguments</key>
  <array>
    <string>{binary_path}</string>
    <string>atpd</string>
    <string>serve</string>
    <string>--config</string>
    <string>{config_dir}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
</dict>
</plist>
"#;

const WINDOWS_SERVICE_SCRIPT_TEMPLATE: &str = r#"$ErrorActionPreference = "Stop"
$binary = "{binary_path}"
$config = "{config_dir}"
New-Service -Name "ATP" -DisplayName "Asupersync Transfer Protocol" -BinaryPathName "`"$binary`" atpd serve --config `"$config`"" -StartupType Automatic
"#;
const BINARY_PATH_TOKEN: &str = concat!("{", "binary_path", "}");
const CONFIG_DIR_TOKEN: &str = concat!("{", "config_dir", "}");

fn render_service_template(template: &str, binary_path: &str, config_dir: &str) -> String {
    template
        .replace(BINARY_PATH_TOKEN, binary_path)
        .replace(CONFIG_DIR_TOKEN, config_dir)
}

/// First-run setup configuration and prompts
#[derive(Debug, Clone)]
pub struct FirstRunSetup {
    /// ATP configuration directory (default: ~/.atp/)
    pub config_dir: PathBuf,
    /// Inbox directory for received transfers
    pub inbox_dir: PathBuf,
    /// Identity storage location
    pub identity_path: PathBuf,
    /// Peer directory for known peers
    pub peer_dir: PathBuf,
    /// Daemon state directory
    pub daemon_state_dir: PathBuf,
    /// User's capability/privacy choices
    pub privacy_choices: PrivacyChoices,
    /// Platform-specific service integration
    pub service_integration: ServiceIntegration,
}

impl FirstRunSetup {
    /// Create new first-run setup with platform defaults
    pub fn new() -> Result<Self, FirstRunError> {
        let config_dir = Self::default_config_dir()?;
        let inbox_dir = Self::default_inbox_dir()?;

        Ok(Self {
            identity_path: config_dir.join("identity.key"),
            peer_dir: config_dir.join("peers"),
            daemon_state_dir: config_dir.join("daemon"),
            config_dir,
            inbox_dir,
            privacy_choices: PrivacyChoices::default(),
            service_integration: ServiceIntegration::detect_platform()?,
        })
    }

    /// Run interactive first-run setup
    pub fn run_interactive(&mut self) -> Result<SetupResult, FirstRunError> {
        println!("Welcome to ATP (Asupersync Transfer Protocol)!");
        println!("Let's set up your ATP configuration...\n");

        // Step 1: Choose directories
        self.prompt_directories()?;

        // Step 2: Privacy and capability choices
        self.prompt_privacy_choices()?;

        // Step 3: Service integration preferences
        self.prompt_service_integration()?;

        // Step 4: Generate identity and configuration
        let setup_result = self.initialize_configuration()?;

        println!("\n✅ ATP setup complete!");
        println!("Configuration saved to: {}", self.config_dir.display());
        println!("Run 'atp status' to verify your setup.");

        if self.service_integration.enable_daemon {
            println!("\nTo start the ATP daemon:");
            println!("  {}", self.service_integration.start_command());
        }

        Ok(setup_result)
    }

    /// Run non-interactive setup with defaults
    pub fn run_automatic(&self) -> Result<SetupResult, FirstRunError> {
        println!("Setting up ATP with default configuration...");

        self.create_directories()?;
        let setup_result = self.initialize_configuration()?;

        println!(
            "✅ ATP configured automatically at: {}",
            self.config_dir.display()
        );
        Ok(setup_result)
    }

    fn prompt_directories(&mut self) -> Result<(), FirstRunError> {
        println!("📁 Directory Configuration");
        println!("ATP needs to store configuration, identity, and received files.");
        println!();

        // Config directory
        println!("Configuration directory [{}]:", self.config_dir.display());
        if let Some(input) = self.read_user_input()? {
            self.config_dir = PathBuf::from(input);
            self.identity_path = self.config_dir.join("identity.key");
            self.peer_dir = self.config_dir.join("peers");
            self.daemon_state_dir = self.config_dir.join("daemon");
        }

        // Inbox directory
        println!(
            "Inbox directory for received files [{}]:",
            self.inbox_dir.display()
        );
        if let Some(input) = self.read_user_input()? {
            self.inbox_dir = PathBuf::from(input);
        }

        self.create_directories()?;
        Ok(())
    }

    fn prompt_privacy_choices(&mut self) -> Result<(), FirstRunError> {
        println!("\n🔒 Privacy & Capability Configuration");
        println!("ATP can connect through various methods. Choose your preferences:");
        println!();

        // Tailscale integration
        println!("Enable Tailscale integration? [y/N]");
        self.privacy_choices.enable_tailscale = self.read_yes_no(false)?;

        // Relay preferences
        println!("Allow relay servers for NAT traversal? [Y/n]");
        self.privacy_choices.allow_relays = self.read_yes_no(true)?;

        // Receive safety policy
        println!("\nReceive Safety Policy:");
        println!("1. Ask before receiving any files (safest)");
        println!("2. Auto-accept from known peers only");
        println!("3. Auto-accept all transfers (least safe)");
        println!("Choose [1-3, default 1]:");

        let choice = match self.read_user_input()?.as_deref() {
            Some("2") => ReceiveSafetyPolicy::KnownPeersOnly,
            Some("3") => ReceiveSafetyPolicy::AutoAcceptAll,
            _ => ReceiveSafetyPolicy::AlwaysAsk,
        };
        self.privacy_choices.receive_safety_policy = choice;

        // Logging level
        println!("\nLogging level [info/debug/trace, default info]:");
        let log_level = self
            .read_user_input()?
            .unwrap_or_else(|| "info".to_string());
        self.privacy_choices.logging_level = log_level;

        // Proof retention
        println!("Keep transfer proof logs for how long? [30d/90d/1y, default 30d]:");
        let retention = match self.read_user_input()?.as_deref() {
            Some("90d") => ProofRetentionPolicy::Days(90),
            Some("1y") => ProofRetentionPolicy::Days(365),
            _ => ProofRetentionPolicy::Days(30),
        };
        self.privacy_choices.proof_retention = retention;

        Ok(())
    }

    fn prompt_service_integration(&mut self) -> Result<(), FirstRunError> {
        println!("\n⚙️  Service Integration");

        match &self.service_integration.platform {
            ServicePlatform::Linux => {
                println!("Install ATP daemon as systemd user service? [Y/n]");
                self.service_integration.enable_daemon = self.read_yes_no(true)?;

                if self.service_integration.enable_daemon {
                    println!("Auto-start daemon on login? [Y/n]");
                    self.service_integration.auto_start = self.read_yes_no(true)?;
                }
            }
            ServicePlatform::MacOS => {
                println!("Install ATP daemon as LaunchAgent? [Y/n]");
                self.service_integration.enable_daemon = self.read_yes_no(true)?;
            }
            ServicePlatform::Windows => {
                println!("Install ATP daemon as Windows service? [Y/n]");
                self.service_integration.enable_daemon = self.read_yes_no(true)?;
            }
            ServicePlatform::Other => {
                println!("Platform service integration not available.");
                self.service_integration.enable_daemon = false;
            }
        }

        Ok(())
    }

    fn initialize_configuration(&self) -> Result<SetupResult, FirstRunError> {
        let key_store = if self.identity_path.exists() {
            IdentityKeyStore::load(&self.identity_path)?
        } else {
            IdentityKeyStore::create(
                &self.identity_path,
                generate_identity_seed()?,
                unix_time_micros()?,
            )?
        };
        let identity = key_store.export_public()?;
        let identity_fingerprint = identity.fingerprint.to_hex();

        println!("🔑 Generated ATP identity: {}", identity_fingerprint);

        // Create ATP configuration
        let config = AtpInstallConfig {
            schema_version: ConfigVersion::current(),
            version: Some(
                Version::parse(env!("CARGO_PKG_VERSION"))
                    .map_err(|e| FirstRunError::ConfigError(e.to_string()))?,
            ),
            identity_path: self.identity_path.clone(),
            inbox_dir: self.inbox_dir.clone(),
            peer_dir: self.peer_dir.clone(),
            daemon_state_dir: self.daemon_state_dir.clone(),
            receive_safety_policy: self.privacy_choices.receive_safety_policy.clone(),
            proof_retention_policy: self.privacy_choices.proof_retention.clone(),
            enable_tailscale: self.privacy_choices.enable_tailscale,
            allow_relays: self.privacy_choices.allow_relays,
            logging_level: self.privacy_choices.logging_level.clone(),
            service_platform: self.service_integration.platform.as_str().to_string(),
            service_daemon_enabled: self.service_integration.enable_daemon,
            service_auto_start: self.service_integration.auto_start,
        };

        // Write configuration
        let config_path = self.config_dir.join("config.toml");
        config.write_to_file(&config_path)?;

        // Generate shell completions
        self.generate_shell_completions()?;

        // Setup service integration if requested
        if self.service_integration.enable_daemon {
            self.setup_service_integration()?;
        }

        Ok(SetupResult {
            config_path,
            identity_fingerprint,
            service_installed: self.service_integration.enable_daemon,
            platform: self.service_integration.platform.clone(),
        })
    }

    fn create_directories(&self) -> Result<(), FirstRunError> {
        for dir in &[
            &self.config_dir,
            &self.inbox_dir,
            &self.peer_dir,
            &self.daemon_state_dir,
        ] {
            std::fs::create_dir_all(dir)
                .map_err(|e| FirstRunError::DirectoryCreation((*dir).clone(), e))?;
        }
        Ok(())
    }

    fn generate_shell_completions(&self) -> Result<(), FirstRunError> {
        let completions_dir = self.config_dir.join("completions");
        std::fs::create_dir_all(&completions_dir)?;

        // Generate bash completion
        let bash_completion = include_str!("completion/atp.bash");
        std::fs::write(completions_dir.join("atp.bash"), bash_completion)?;

        // Generate zsh completion
        let zsh_completion = include_str!("completion/atp.zsh");
        std::fs::write(completions_dir.join("_atp"), zsh_completion)?;

        // Generate fish completion
        let fish_completion = include_str!("completion/atp.fish");
        std::fs::write(completions_dir.join("atp.fish"), fish_completion)?;

        println!(
            "📝 Generated shell completions in: {}",
            completions_dir.display()
        );
        println!("Add to your shell profile:");

        match std::env::var("SHELL").as_deref() {
            Ok(shell) if shell.contains("bash") => {
                println!("  source {}", completions_dir.join("atp.bash").display());
            }
            Ok(shell) if shell.contains("zsh") => {
                println!(
                    "  fpath+=({}) && autoload -U compinit && compinit",
                    completions_dir.display()
                );
            }
            Ok(shell) if shell.contains("fish") => {
                println!("  source {}", completions_dir.join("atp.fish").display());
            }
            _ => {
                println!("  See files in: {}", completions_dir.display());
            }
        }

        Ok(())
    }

    fn setup_service_integration(&self) -> Result<(), FirstRunError> {
        match &self.service_integration.platform {
            ServicePlatform::Linux => self.setup_systemd_service(),
            ServicePlatform::MacOS => self.setup_launchd_service(),
            ServicePlatform::Windows => self.setup_windows_service(),
            ServicePlatform::Other => Ok(()), // No-op for unsupported platforms
        }
    }

    fn setup_systemd_service(&self) -> Result<(), FirstRunError> {
        let service_dir = home_dir()?.join(".config/systemd/user");

        std::fs::create_dir_all(&service_dir)?;

        let service_content = render_service_template(
            LINUX_SYSTEMD_SERVICE_TEMPLATE,
            &std::env::current_exe()?.display().to_string(),
            &self.config_dir.display().to_string(),
        );

        let service_path = service_dir.join("atp.service");
        std::fs::write(&service_path, service_content)?;

        println!("📋 Systemd service installed: {}", service_path.display());

        if self.service_integration.auto_start {
            println!("Run: systemctl --user enable --now atp.service");
        } else {
            println!("Run: systemctl --user start atp.service");
        }

        Ok(())
    }

    fn setup_launchd_service(&self) -> Result<(), FirstRunError> {
        let agents_dir = home_dir()?.join("Library/LaunchAgents");

        std::fs::create_dir_all(&agents_dir)?;

        let plist_content = render_service_template(
            MACOS_LAUNCHD_TEMPLATE,
            &std::env::current_exe()?.display().to_string(),
            &self.config_dir.display().to_string(),
        );

        let plist_path = agents_dir.join("com.asupersync.atp.plist");
        std::fs::write(&plist_path, plist_content)?;

        println!("📋 LaunchAgent installed: {}", plist_path.display());
        println!("Run: launchctl load {}", plist_path.display());

        Ok(())
    }

    fn setup_windows_service(&self) -> Result<(), FirstRunError> {
        // On Windows, service installation typically requires admin privileges
        // Generate the service registration script instead
        let scripts_dir = self.config_dir.join("scripts");
        std::fs::create_dir_all(&scripts_dir)?;

        let install_script = render_service_template(
            WINDOWS_SERVICE_SCRIPT_TEMPLATE,
            &std::env::current_exe()?.display().to_string(),
            &self.config_dir.display().to_string(),
        );

        let script_path = scripts_dir.join("install-service.ps1");
        std::fs::write(&script_path, install_script)?;

        println!(
            "📋 Windows service script generated: {}",
            script_path.display()
        );
        println!(
            "Run as Administrator: PowerShell -ExecutionPolicy Bypass -File \"{}\"",
            script_path.display()
        );

        Ok(())
    }

    fn read_user_input(&self) -> Result<Option<String>, FirstRunError> {
        use std::io::{self, BufRead};

        let stdin = io::stdin();
        let Some(line) = stdin
            .lock()
            .lines()
            .next()
            .transpose()
            .map_err(FirstRunError::InputError)?
        else {
            return Ok(None);
        };

        if line.trim().is_empty() {
            Ok(None)
        } else {
            Ok(Some(line.trim().to_string()))
        }
    }

    fn read_yes_no(&self, default: bool) -> Result<bool, FirstRunError> {
        match self.read_user_input()?.as_deref() {
            Some("y" | "Y" | "yes" | "Yes") => Ok(true),
            Some("n" | "N" | "no" | "No") => Ok(false),
            None => Ok(default),
            Some(_) => Ok(default), // Invalid input, use default
        }
    }

    fn default_config_dir() -> Result<PathBuf, FirstRunError> {
        if cfg!(windows) {
            if let Some(appdata) = std::env::var_os("APPDATA") {
                return Ok(PathBuf::from(appdata).join("Asupersync").join("atp"));
            }
        } else if cfg!(target_os = "macos") {
            return Ok(home_dir()?
                .join("Library")
                .join("Application Support")
                .join("Asupersync")
                .join("atp"));
        } else if let Some(xdg_config_home) = std::env::var_os("XDG_CONFIG_HOME") {
            return Ok(PathBuf::from(xdg_config_home)
                .join("asupersync")
                .join("atp"));
        }

        Ok(home_dir()?.join(".config").join("asupersync").join("atp"))
    }

    fn default_inbox_dir() -> Result<PathBuf, FirstRunError> {
        Ok(home_dir()?.join("Downloads").join("ATP"))
    }
}

fn home_dir() -> Result<PathBuf, FirstRunError> {
    if let Some(home) = std::env::var_os("HOME") {
        return Ok(PathBuf::from(home));
    }
    if let Some(profile) = std::env::var_os("USERPROFILE") {
        return Ok(PathBuf::from(profile));
    }
    match (std::env::var_os("HOMEDRIVE"), std::env::var_os("HOMEPATH")) {
        (Some(drive), Some(path)) => Ok(PathBuf::from(drive).join(path)),
        _ => Err(FirstRunError::PlatformNotSupported),
    }
}

fn generate_identity_seed() -> Result<[u8; 32], FirstRunError> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| FirstRunError::IdentityError(e.to_string()))?;
    Ok(seed)
}

fn unix_time_micros() -> Result<u64, FirstRunError> {
    let micros = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_micros();
    u64::try_from(micros).map_err(|_| {
        FirstRunError::ConfigError("system time exceeds u64 microsecond range".to_string())
    })
}

/// User privacy and capability choices
#[derive(Debug, Clone)]
pub struct PrivacyChoices {
    pub enable_tailscale: bool,
    pub allow_relays: bool,
    pub receive_safety_policy: ReceiveSafetyPolicy,
    pub logging_level: String,
    pub proof_retention: ProofRetentionPolicy,
}

impl Default for PrivacyChoices {
    fn default() -> Self {
        Self {
            enable_tailscale: false,
            allow_relays: true,
            receive_safety_policy: ReceiveSafetyPolicy::AlwaysAsk,
            logging_level: "info".to_string(),
            proof_retention: ProofRetentionPolicy::Days(30),
        }
    }
}

/// Platform service integration configuration
#[derive(Debug, Clone)]
pub struct ServiceIntegration {
    pub platform: ServicePlatform,
    pub enable_daemon: bool,
    pub auto_start: bool,
}

impl ServiceIntegration {
    pub fn detect_platform() -> Result<Self, FirstRunError> {
        let platform = if cfg!(target_os = "linux") {
            ServicePlatform::Linux
        } else if cfg!(target_os = "macos") {
            ServicePlatform::MacOS
        } else if cfg!(target_os = "windows") {
            ServicePlatform::Windows
        } else {
            ServicePlatform::Other
        };

        Ok(Self {
            platform,
            enable_daemon: false,
            auto_start: false,
        })
    }

    pub fn start_command(&self) -> &'static str {
        match self.platform {
            ServicePlatform::Linux => "systemctl --user start atp.service",
            ServicePlatform::MacOS => {
                "launchctl load ~/Library/LaunchAgents/com.asupersync.atp.plist"
            }
            ServicePlatform::Windows => "sc start ATP",
            ServicePlatform::Other => "atp daemon",
        }
    }

    pub fn stop_command(&self) -> &'static str {
        match self.platform {
            ServicePlatform::Linux => "systemctl --user stop atp.service",
            ServicePlatform::MacOS => {
                "launchctl unload ~/Library/LaunchAgents/com.asupersync.atp.plist"
            }
            ServicePlatform::Windows => "sc stop ATP",
            ServicePlatform::Other => "atp daemon stop",
        }
    }
}

#[derive(Debug, Clone)]
pub enum ServicePlatform {
    Linux,
    MacOS,
    Windows,
    Other,
}

impl ServicePlatform {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::MacOS => "macos",
            Self::Windows => "windows",
            Self::Other => "other",
        }
    }
}

/// Result of first-run setup
#[derive(Debug)]
pub struct SetupResult {
    pub config_path: PathBuf,
    pub identity_fingerprint: String,
    pub service_installed: bool,
    pub platform: ServicePlatform,
}

/// First-run setup errors
#[derive(Debug, thiserror::Error)]
pub enum FirstRunError {
    #[error("Platform not supported")]
    PlatformNotSupported,

    #[error("Failed to create directory {0}: {1}")]
    DirectoryCreation(PathBuf, std::io::Error),

    #[error("Input/output error: {0}")]
    InputError(std::io::Error),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Identity generation failed: {0}")]
    IdentityError(String),

    #[error("Service setup failed: {0}")]
    ServiceError(String),
}

impl From<std::io::Error> for FirstRunError {
    fn from(e: std::io::Error) -> Self {
        Self::InputError(e)
    }
}

impl From<ConfigError> for FirstRunError {
    fn from(e: ConfigError) -> Self {
        Self::ConfigError(e.to_string())
    }
}

impl From<KeyStoreError> for FirstRunError {
    fn from(e: KeyStoreError) -> Self {
        Self::IdentityError(e.to_string())
    }
}

impl From<SystemTimeError> for FirstRunError {
    fn from(e: SystemTimeError) -> Self {
        Self::ConfigError(format!("system clock is before UNIX_EPOCH: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_first_run_setup_creation() {
        let setup = FirstRunSetup::new();
        assert!(setup.is_ok());

        let setup = setup.unwrap();
        assert!(!setup.config_dir.as_os_str().is_empty());
        assert!(!setup.inbox_dir.as_os_str().is_empty());
    }

    #[test]
    fn test_service_platform_detection() {
        let integration = ServiceIntegration::detect_platform();
        assert!(integration.is_ok());

        let integration = integration.unwrap();
        assert!(!integration.start_command().is_empty());
        assert!(!integration.stop_command().is_empty());
    }

    #[test]
    fn test_directory_creation() {
        let temp_dir = TempDir::new().unwrap();
        let mut setup = FirstRunSetup::new().unwrap();
        setup.config_dir = temp_dir.path().join("atp");
        setup.inbox_dir = temp_dir.path().join("inbox");
        setup.peer_dir = setup.config_dir.join("peers");
        setup.daemon_state_dir = setup.config_dir.join("daemon");

        let result = setup.create_directories();
        assert!(result.is_ok());

        assert!(setup.config_dir.exists());
        assert!(setup.inbox_dir.exists());
        assert!(setup.peer_dir.exists());
        assert!(setup.daemon_state_dir.exists());
    }

    #[test]
    fn initialize_configuration_writes_install_config_and_reuses_identity() {
        let temp_dir = TempDir::new().unwrap();
        let mut setup = FirstRunSetup::new().unwrap();
        setup.config_dir = temp_dir.path().join("atp");
        setup.inbox_dir = temp_dir.path().join("inbox");
        setup.identity_path = setup.config_dir.join("identity.key");
        setup.peer_dir = setup.config_dir.join("peers");
        setup.daemon_state_dir = setup.config_dir.join("daemon");
        setup.service_integration.enable_daemon = false;
        setup.create_directories().unwrap();

        let first = setup.initialize_configuration().unwrap();
        let second = setup.initialize_configuration().unwrap();
        let config = AtpInstallConfig::read_from_file(&first.config_path).unwrap();

        assert_eq!(first.identity_fingerprint, second.identity_fingerprint);
        assert_eq!(config.schema_version, ConfigVersion::current());
        assert_eq!(config.identity_path, setup.identity_path);
        assert_eq!(config.inbox_dir, setup.inbox_dir);
        assert!(first.config_path.exists());
    }

    /// Test that all completion assets referenced in generate_shell_completions exist.
    /// This prevents compilation failures when include_str! references missing files.
    #[test]
    fn test_completion_assets_exist() {
        // Test that all completion assets referenced in the code exist
        // This prevents the compilation failure described in asupersync-qbim6h

        // These are the files referenced by include_str! in generate_shell_completions
        let completion_files = [
            "completion/atp.bash",
            "completion/atp.zsh",
            "completion/atp.fish",
        ];

        for file_path in &completion_files {
            let full_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("src/cli")
                .join(file_path);

            assert!(
                full_path.exists(),
                "Completion asset {} does not exist at {}. This will cause compilation failure when first_run.rs is built.",
                file_path,
                full_path.display()
            );

            // Also verify the file is not empty
            let content = std::fs::read_to_string(&full_path)
                .unwrap_or_else(|_| panic!("Failed to read completion asset {}", file_path));

            assert!(
                !content.trim().is_empty(),
                "Completion asset {} exists but is empty. This may cause runtime issues.",
                file_path
            );
        }
    }
}
