//! ATP resource governance configuration.
//!
//! Provides configuration types for resource governance policies, profiles,
//! and CLI integration. Supports explicit profile selection, custom limits,
//! fairness policy configuration, and dry-run mode for policy validation.

use crate::atp::governance::{AtpFairnessPolicy, AtpResourceBudget};
use crate::atp::profiles::{AtpPowerProfile, AtpResourceProfile};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Complete resource governance configuration.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AtpGovernanceConfig {
    /// Selected power profile (can be overridden by custom limits).
    pub power_profile: AtpPowerProfile,
    /// Custom resource limits that override profile defaults.
    pub custom_limits: AtpCustomLimits,
    /// Policy for distributing resources among concurrent transfers.
    pub fairness_policy: AtpFairnessPolicy,
    /// Whether to enable dry-run mode (policy evaluation without enforcement).
    pub dry_run: bool,
    /// Additional metadata for diagnostics and debugging.
    pub metadata: AtpGovernanceMetadata,
}

/// Custom resource limits that override profile defaults.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AtpCustomLimits {
    /// Override for maximum bandwidth (bytes per second).
    pub max_bandwidth_bytes_per_second: Option<u64>,
    /// Override for maximum in-flight bytes.
    pub max_in_flight_bytes: Option<u64>,
    /// Override for maximum repair symbols per second.
    pub max_repair_symbols_per_second: Option<u32>,
    /// Override for maximum disk write concurrency.
    pub max_disk_write_concurrency: Option<u16>,
    /// Override for maximum relay cost (microseconds per MiB).
    pub max_relay_cost_micros_per_mib: Option<u64>,
    /// Override for background priority setting.
    pub background_priority: Option<bool>,
    /// Override for metered network setting.
    pub metered_network: Option<bool>,
}

/// Metadata for governance configuration diagnostics.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AtpGovernanceMetadata {
    /// Source of this configuration (e.g., "cli", "config_file", "default").
    pub source: String,
    /// Version of the configuration schema.
    pub version: String,
    /// Timestamp when this configuration was created or last modified.
    pub timestamp: Option<String>,
    /// Additional key-value pairs for debugging and tracing.
    pub extra: BTreeMap<String, String>,
}

impl Default for AtpGovernanceMetadata {
    fn default() -> Self {
        Self {
            source: "default".to_string(),
            version: "1.0".to_string(),
            timestamp: None,
            extra: BTreeMap::new(),
        }
    }
}

impl AtpGovernanceConfig {
    /// Create a configuration from a power profile with default settings.
    #[must_use]
    pub fn from_power_profile(power_profile: AtpPowerProfile) -> Self {
        Self {
            power_profile,
            custom_limits: AtpCustomLimits::default(),
            fairness_policy: AtpFairnessPolicy::default(),
            dry_run: false,
            metadata: AtpGovernanceMetadata::default(),
        }
    }

    /// Create a configuration with custom limits.
    #[must_use]
    pub fn with_custom_limits(mut self, custom_limits: AtpCustomLimits) -> Self {
        self.custom_limits = custom_limits;
        self
    }

    /// Set the fairness policy.
    #[must_use]
    pub fn with_fairness_policy(mut self, fairness_policy: AtpFairnessPolicy) -> Self {
        self.fairness_policy = fairness_policy;
        self
    }

    /// Enable dry-run mode (policy evaluation without enforcement).
    #[must_use]
    pub fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    /// Set metadata source.
    #[must_use]
    pub fn with_source(mut self, source: String) -> Self {
        self.metadata.source = source;
        self
    }

    /// Resolve the final resource budget by applying custom limits to the profile.
    #[must_use]
    pub fn resolve_budget(&self) -> AtpResourceBudget {
        let profile = AtpResourceProfile::for_power_profile(self.power_profile);

        AtpResourceBudget {
            max_bandwidth_bytes_per_second: self
                .custom_limits
                .max_bandwidth_bytes_per_second
                .or(profile.max_bandwidth_bytes_per_second),
            max_in_flight_bytes: self
                .custom_limits
                .max_in_flight_bytes
                .or(profile.max_in_flight_bytes),
            max_repair_symbols_per_second: self
                .custom_limits
                .max_repair_symbols_per_second
                .or(profile.max_repair_symbols_per_second),
            max_disk_write_concurrency: self
                .custom_limits
                .max_disk_write_concurrency
                .or(profile.max_disk_write_concurrency),
            max_relay_cost_micros_per_mib: self
                .custom_limits
                .max_relay_cost_micros_per_mib
                .or(profile.max_relay_cost_micros_per_mib),
            background_priority: self
                .custom_limits
                .background_priority
                .unwrap_or(profile.background_priority),
            metered_network: self
                .custom_limits
                .metered_network
                .unwrap_or(profile.metered_network),
        }
    }

    /// Get effective resource profile with custom overrides applied.
    #[must_use]
    pub fn resolve_profile(&self) -> AtpResourceProfile {
        let mut profile = AtpResourceProfile::for_power_profile(self.power_profile);

        // Apply custom overrides
        if let Some(bandwidth) = self.custom_limits.max_bandwidth_bytes_per_second {
            profile.max_bandwidth_bytes_per_second = Some(bandwidth);
        }
        if let Some(in_flight) = self.custom_limits.max_in_flight_bytes {
            profile.max_in_flight_bytes = Some(in_flight);
        }
        if let Some(repair) = self.custom_limits.max_repair_symbols_per_second {
            profile.max_repair_symbols_per_second = Some(repair);
        }
        if let Some(disk) = self.custom_limits.max_disk_write_concurrency {
            profile.max_disk_write_concurrency = Some(disk);
        }
        if let Some(relay) = self.custom_limits.max_relay_cost_micros_per_mib {
            profile.max_relay_cost_micros_per_mib = Some(relay);
        }
        if let Some(background) = self.custom_limits.background_priority {
            profile.background_priority = background;
        }
        if let Some(metered) = self.custom_limits.metered_network {
            profile.metered_network = metered;
        }

        profile
    }

    /// Check if any custom limits are configured.
    #[must_use]
    pub fn has_custom_limits(&self) -> bool {
        self.custom_limits.max_bandwidth_bytes_per_second.is_some()
            || self.custom_limits.max_in_flight_bytes.is_some()
            || self.custom_limits.max_repair_symbols_per_second.is_some()
            || self.custom_limits.max_disk_write_concurrency.is_some()
            || self.custom_limits.max_relay_cost_micros_per_mib.is_some()
            || self.custom_limits.background_priority.is_some()
            || self.custom_limits.metered_network.is_some()
    }
}

/// CLI arguments for resource governance configuration.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AtpGovernanceCliArgs {
    /// Power profile selection.
    pub profile: Option<String>,
    /// Custom bandwidth limit (e.g., "64M", "1G").
    pub bandwidth: Option<String>,
    /// Custom in-flight bytes limit (e.g., "32M").
    pub in_flight: Option<String>,
    /// Custom repair symbols per second limit.
    pub repair_rate: Option<u32>,
    /// Custom disk write concurrency limit.
    pub disk_concurrency: Option<u16>,
    /// Custom relay cost limit in milliseconds per MiB.
    pub relay_cost_ms_per_mib: Option<u64>,
    /// Force background priority.
    pub background: bool,
    /// Treat network as metered.
    pub metered: bool,
    /// Fairness policy name.
    pub fairness: Option<String>,
    /// Enable dry-run mode.
    pub dry_run: bool,
}

impl AtpGovernanceCliArgs {
    /// Parse CLI arguments into a governance configuration.
    ///
    /// # Errors
    /// Returns error if profile name, fairness policy, or size strings are invalid.
    pub fn parse_config(&self) -> Result<AtpGovernanceConfig, String> {
        // Parse power profile
        let power_profile = if let Some(ref profile_name) = self.profile {
            parse_power_profile(profile_name)?
        } else {
            AtpPowerProfile::default()
        };

        // Parse custom limits
        let custom_limits = AtpCustomLimits {
            max_bandwidth_bytes_per_second: if let Some(ref bw) = self.bandwidth {
                Some(parse_size_string(bw)?)
            } else {
                None
            },
            max_in_flight_bytes: if let Some(ref inf) = self.in_flight {
                Some(parse_size_string(inf)?)
            } else {
                None
            },
            max_repair_symbols_per_second: self.repair_rate,
            max_disk_write_concurrency: self.disk_concurrency,
            max_relay_cost_micros_per_mib: self
                .relay_cost_ms_per_mib
                .map(parse_relay_cost_millis)
                .transpose()?,
            background_priority: if self.background { Some(true) } else { None },
            metered_network: if self.metered { Some(true) } else { None },
        };

        // Parse fairness policy
        let fairness_policy = if let Some(ref fairness_name) = self.fairness {
            parse_fairness_policy(fairness_name)?
        } else {
            AtpFairnessPolicy::default()
        };

        Ok(AtpGovernanceConfig {
            power_profile,
            custom_limits,
            fairness_policy,
            dry_run: self.dry_run,
            metadata: AtpGovernanceMetadata {
                source: "cli".to_string(),
                ..AtpGovernanceMetadata::default()
            },
        })
    }
}

/// Parse power profile name string into enum variant.
fn parse_power_profile(name: &str) -> Result<AtpPowerProfile, String> {
    match name.to_lowercase().as_str() {
        "max-speed" | "max_speed" | "maxspeed" => Ok(AtpPowerProfile::MaxSpeed),
        "balanced" => Ok(AtpPowerProfile::Balanced),
        "background" => Ok(AtpPowerProfile::Background),
        "metered" => Ok(AtpPowerProfile::Metered),
        "relay-conservative" | "relay_conservative" => Ok(AtpPowerProfile::RelayConservative),
        "battery-saver" | "battery_saver" | "battery" => Ok(AtpPowerProfile::BatterySaver),
        "ci-deterministic" | "ci_deterministic" | "ci" => Ok(AtpPowerProfile::CiDeterministic),
        "custom" => Ok(AtpPowerProfile::Custom),
        _ => Err(format!(
            "Unknown power profile: {name}. Available: max-speed, balanced, background, metered, relay-conservative, battery-saver, ci-deterministic, custom"
        )),
    }
}

/// Parse fairness policy name string into enum variant.
fn parse_fairness_policy(name: &str) -> Result<AtpFairnessPolicy, String> {
    match name.to_lowercase().as_str() {
        "equal-share" | "equal_share" | "equal" => Ok(AtpFairnessPolicy::EqualShare),
        "priority-weighted" | "priority_weighted" | "priority" => {
            Ok(AtpFairnessPolicy::PriorityWeighted)
        }
        "first-come-first-served" | "first_come_first_served" | "fcfs" => {
            Ok(AtpFairnessPolicy::FirstComeFirstServed)
        }
        "size-proportional" | "size_proportional" | "size" => {
            Ok(AtpFairnessPolicy::SizeProportional)
        }
        _ => Err(format!(
            "Unknown fairness policy: {name}. Available: equal-share, priority-weighted, first-come-first-served, size-proportional"
        )),
    }
}

/// Parse size string (e.g., "64M", "1G", "512K") into bytes.
fn parse_size_string(size: &str) -> Result<u64, String> {
    let original = size.trim();
    let size = original.to_lowercase();
    let (number_part, suffix) = if let Some(pos) = size.chars().position(|c| c.is_alphabetic()) {
        (&size[..pos], &size[pos..])
    } else {
        (size.as_str(), "")
    };

    let number_part = number_part.trim();
    let suffix = suffix.trim();

    let number: u64 = number_part
        .parse()
        .map_err(|_| format!("Invalid number in size string: {number_part}"))?;

    let multiplier = match suffix {
        "" | "b" => 1,
        "k" | "kb" => 1_024,
        "m" | "mb" => 1_048_576,
        "g" | "gb" => 1_073_741_824,
        "t" | "tb" => 1_099_511_627_776,
        _ => {
            return Err(format!(
                "Unknown size suffix: {suffix}. Use B, K, M, G, or T"
            ));
        }
    };

    number
        .checked_mul(multiplier)
        .ok_or_else(|| format!("Size string overflows u64 bytes: {original}"))
}

fn parse_relay_cost_millis(ms: u64) -> Result<u64, String> {
    ms.checked_mul(1_000)
        .ok_or_else(|| format!("Relay cost is too large: {ms} ms/MiB"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn governance_config_defaults_are_reasonable() {
        let config = AtpGovernanceConfig::default();
        assert_eq!(config.power_profile, AtpPowerProfile::Balanced);
        assert_eq!(config.fairness_policy, AtpFairnessPolicy::EqualShare);
        assert!(!config.dry_run);
        assert!(!config.has_custom_limits());
        assert_eq!(config.metadata.source, "default");
    }

    #[test]
    fn resolve_budget_applies_custom_limits() {
        let config = AtpGovernanceConfig::from_power_profile(AtpPowerProfile::Balanced)
            .with_custom_limits(AtpCustomLimits {
                max_bandwidth_bytes_per_second: Some(1_048_576), // 1 MiB/s
                background_priority: Some(true),
                ..AtpCustomLimits::default()
            });

        let budget = config.resolve_budget();
        assert_eq!(budget.max_bandwidth_bytes_per_second, Some(1_048_576));
        assert!(budget.background_priority);
        // Other limits should come from the balanced profile.
        assert_eq!(budget.max_in_flight_bytes, Some(128 * 1_048_576));
    }

    #[test]
    fn parse_power_profile_handles_variations() {
        assert_eq!(
            parse_power_profile("max-speed").unwrap(),
            AtpPowerProfile::MaxSpeed
        );
        assert_eq!(
            parse_power_profile("Max_Speed").unwrap(),
            AtpPowerProfile::MaxSpeed
        );
        assert_eq!(
            parse_power_profile("BALANCED").unwrap(),
            AtpPowerProfile::Balanced
        );
        assert_eq!(
            parse_power_profile("battery").unwrap(),
            AtpPowerProfile::BatterySaver
        );

        assert!(parse_power_profile("invalid").is_err());
    }

    #[test]
    fn parse_fairness_policy_handles_variations() {
        assert_eq!(
            parse_fairness_policy("equal").unwrap(),
            AtpFairnessPolicy::EqualShare
        );
        assert_eq!(
            parse_fairness_policy("Priority_Weighted").unwrap(),
            AtpFairnessPolicy::PriorityWeighted
        );
        assert_eq!(
            parse_fairness_policy("fcfs").unwrap(),
            AtpFairnessPolicy::FirstComeFirstServed
        );

        assert!(parse_fairness_policy("invalid").is_err());
    }

    #[test]
    fn parse_size_string_handles_units() {
        assert_eq!(parse_size_string("1024").unwrap(), 1_024);
        assert_eq!(parse_size_string("1K").unwrap(), 1_024);
        assert_eq!(parse_size_string("64m").unwrap(), 64 * 1_048_576);
        assert_eq!(parse_size_string("2G").unwrap(), 2 * 1_073_741_824);
        assert_eq!(parse_size_string("1 T").unwrap(), 1_099_511_627_776);

        assert!(parse_size_string("invalid").is_err());
        assert!(parse_size_string("64X").is_err());
    }

    #[test]
    fn parse_size_string_rejects_byte_overflow() {
        let too_large_kib = format!("{}K", u64::MAX / 1_024 + 1);
        let too_large_tib = format!("{}T", u64::MAX / 1_099_511_627_776 + 1);

        assert!(parse_size_string(&too_large_kib).is_err());
        assert!(parse_size_string(&too_large_tib).is_err());
        assert_eq!(
            parse_size_string(&format!("{}B", u64::MAX)).unwrap(),
            u64::MAX
        );
    }

    #[test]
    fn cli_args_parse_config_rejects_relay_cost_overflow() {
        let args = AtpGovernanceCliArgs {
            relay_cost_ms_per_mib: Some(u64::MAX),
            ..AtpGovernanceCliArgs::default()
        };

        assert!(args.parse_config().is_err());
        assert_eq!(
            parse_relay_cost_millis(u64::MAX / 1_000).unwrap(),
            (u64::MAX / 1_000) * 1_000
        );
    }

    #[test]
    fn cli_args_parse_config_works() {
        let args = AtpGovernanceCliArgs {
            profile: Some("battery-saver".to_string()),
            bandwidth: Some("32M".to_string()),
            fairness: Some("fcfs".to_string()),
            background: true,
            dry_run: true,
            ..AtpGovernanceCliArgs::default()
        };

        let config = args.parse_config().unwrap();
        assert_eq!(config.power_profile, AtpPowerProfile::BatterySaver);
        assert_eq!(
            config.custom_limits.max_bandwidth_bytes_per_second,
            Some(32 * 1_048_576)
        );
        assert_eq!(
            config.fairness_policy,
            AtpFairnessPolicy::FirstComeFirstServed
        );
        assert_eq!(config.custom_limits.background_priority, Some(true));
        assert!(config.dry_run);
        assert_eq!(config.metadata.source, "cli");
    }
}
