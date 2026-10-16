//! ATP local resource-governance profiles.
//!
//! Profiles are policy presets only. They do not read host state or mutate
//! transfer state; callers combine them with measured pressure and explicit
//! user/daemon policy before passing budgets to the resource governor.

use serde::{Deserialize, Serialize};

/// Operator-selected power and network behavior profile.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AtpPowerProfile {
    /// Prefer throughput and low completion latency.
    MaxSpeed,
    /// Default profile that leaves practical room for other foreground work.
    #[default]
    Balanced,
    /// Reduce resource use for background transfers.
    Background,
    /// Conserve bytes on metered or expensive links.
    Metered,
    /// Avoid relay-heavy plans unless they stay under a tight cost ceiling.
    RelayConservative,
    /// Prefer lower CPU, repair, and disk pressure on battery.
    BatterySaver,
    /// Deterministic CI profile with stable, low-concurrency budgets.
    CiDeterministic,
    /// Caller-supplied caps; the preset starts unrestricted.
    Custom,
}

impl AtpPowerProfile {
    /// Stable profile key for logs, status output, and config files.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MaxSpeed => "max_speed",
            Self::Balanced => "balanced",
            Self::Background => "background",
            Self::Metered => "metered",
            Self::RelayConservative => "relay_conservative",
            Self::BatterySaver => "battery_saver",
            Self::CiDeterministic => "ci_deterministic",
            Self::Custom => "custom",
        }
    }

    /// Human-readable description of the profile's intended use case.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::MaxSpeed => {
                "Maximum speed, unlimited resources, saturate available bandwidth/CPU"
            }
            Self::Balanced => {
                "Balanced resource usage, reasonable for most desktop/server scenarios"
            }
            Self::Background => {
                "Background priority, yield to foreground work, conservative resource usage"
            }
            Self::Metered => "Metered network awareness, minimize data usage and relay costs",
            Self::RelayConservative => {
                "Relay-conservative, prefer direct paths, limit relay cost spending"
            }
            Self::BatterySaver => {
                "Battery saver, minimize CPU/disk/network activity to preserve power"
            }
            Self::CiDeterministic => {
                "CI-deterministic, predictable resource usage for reproducible builds"
            }
            Self::Custom => "Custom profile, all limits configurable by user",
        }
    }

    /// All available power profile variants.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::MaxSpeed,
            Self::Balanced,
            Self::Background,
            Self::Metered,
            Self::RelayConservative,
            Self::BatterySaver,
            Self::CiDeterministic,
            Self::Custom,
        ]
    }
}

/// Explicit resource caps derived from a local ATP profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtpResourceProfile {
    /// Source profile name.
    pub profile: AtpPowerProfile,
    /// Maximum scheduled data bytes per second.
    pub max_bandwidth_bytes_per_second: Option<u64>,
    /// Maximum bytes in flight for one transfer.
    pub max_in_flight_bytes: Option<u64>,
    /// Maximum repair symbols encoded or decoded per second.
    pub max_repair_symbols_per_second: Option<u32>,
    /// Maximum concurrent disk-write jobs for one transfer.
    pub max_disk_write_concurrency: Option<u16>,
    /// Maximum acceptable relay cost in microseconds per MiB.
    pub max_relay_cost_micros_per_mib: Option<u64>,
    /// Whether the transfer should yield to foreground work.
    pub background_priority: bool,
    /// Whether link bytes should be treated as user-visible cost.
    pub metered_network: bool,
}

impl Default for AtpResourceProfile {
    fn default() -> Self {
        Self::for_power_profile(AtpPowerProfile::Balanced)
    }
}

impl AtpResourceProfile {
    /// Build the default caps for one profile.
    #[must_use]
    pub const fn for_power_profile(profile: AtpPowerProfile) -> Self {
        match profile {
            AtpPowerProfile::MaxSpeed => Self {
                profile,
                max_bandwidth_bytes_per_second: None,
                max_in_flight_bytes: Some(512 * 1_048_576),
                max_repair_symbols_per_second: Some(16_384),
                max_disk_write_concurrency: Some(8),
                max_relay_cost_micros_per_mib: None,
                background_priority: false,
                metered_network: false,
            },
            AtpPowerProfile::Balanced => Self {
                profile,
                max_bandwidth_bytes_per_second: Some(128 * 1_048_576),
                max_in_flight_bytes: Some(128 * 1_048_576),
                max_repair_symbols_per_second: Some(4_096),
                max_disk_write_concurrency: Some(4),
                max_relay_cost_micros_per_mib: Some(750_000),
                background_priority: false,
                metered_network: false,
            },
            AtpPowerProfile::Background => Self {
                profile,
                max_bandwidth_bytes_per_second: Some(32 * 1_048_576),
                max_in_flight_bytes: Some(32 * 1_048_576),
                max_repair_symbols_per_second: Some(1_024),
                max_disk_write_concurrency: Some(2),
                max_relay_cost_micros_per_mib: Some(500_000),
                background_priority: true,
                metered_network: false,
            },
            AtpPowerProfile::Metered => Self {
                profile,
                max_bandwidth_bytes_per_second: Some(8 * 1_048_576),
                max_in_flight_bytes: Some(16 * 1_048_576),
                max_repair_symbols_per_second: Some(512),
                max_disk_write_concurrency: Some(1),
                max_relay_cost_micros_per_mib: Some(250_000),
                background_priority: true,
                metered_network: true,
            },
            AtpPowerProfile::RelayConservative => Self {
                profile,
                max_bandwidth_bytes_per_second: Some(64 * 1_048_576),
                max_in_flight_bytes: Some(64 * 1_048_576),
                max_repair_symbols_per_second: Some(2_048),
                max_disk_write_concurrency: Some(2),
                max_relay_cost_micros_per_mib: Some(150_000),
                background_priority: false,
                metered_network: false,
            },
            AtpPowerProfile::BatterySaver => Self {
                profile,
                max_bandwidth_bytes_per_second: Some(16 * 1_048_576),
                max_in_flight_bytes: Some(16 * 1_048_576),
                max_repair_symbols_per_second: Some(512),
                max_disk_write_concurrency: Some(1),
                max_relay_cost_micros_per_mib: Some(300_000),
                background_priority: true,
                metered_network: false,
            },
            AtpPowerProfile::CiDeterministic => Self {
                profile,
                max_bandwidth_bytes_per_second: Some(4 * 1_048_576),
                max_in_flight_bytes: Some(4 * 1_048_576),
                max_repair_symbols_per_second: Some(128),
                max_disk_write_concurrency: Some(1),
                max_relay_cost_micros_per_mib: Some(1),
                background_priority: true,
                metered_network: true,
            },
            AtpPowerProfile::Custom => Self {
                profile,
                max_bandwidth_bytes_per_second: None,
                max_in_flight_bytes: None,
                max_repair_symbols_per_second: None,
                max_disk_write_concurrency: None,
                max_relay_cost_micros_per_mib: None,
                background_priority: false,
                metered_network: false,
            },
        }
    }

    /// Create a custom profile with explicit resource limits.
    #[must_use]
    pub const fn custom(
        max_bandwidth_bytes_per_second: Option<u64>,
        max_in_flight_bytes: Option<u64>,
        max_repair_symbols_per_second: Option<u32>,
        max_disk_write_concurrency: Option<u16>,
        max_relay_cost_micros_per_mib: Option<u64>,
        background_priority: bool,
        metered_network: bool,
    ) -> Self {
        Self {
            profile: AtpPowerProfile::Custom,
            max_bandwidth_bytes_per_second,
            max_in_flight_bytes,
            max_repair_symbols_per_second,
            max_disk_write_concurrency,
            max_relay_cost_micros_per_mib,
            background_priority,
            metered_network,
        }
    }

    /// Returns true if this profile prioritizes background operation.
    #[must_use]
    pub const fn is_background_priority(self) -> bool {
        self.background_priority
    }

    /// Returns true if this profile treats network as metered/costly.
    #[must_use]
    pub const fn is_metered_network(self) -> bool {
        self.metered_network
    }

    /// Returns true if this profile has any resource limits configured.
    #[must_use]
    pub const fn has_limits(self) -> bool {
        self.max_bandwidth_bytes_per_second.is_some()
            || self.max_in_flight_bytes.is_some()
            || self.max_repair_symbols_per_second.is_some()
            || self.max_disk_write_concurrency.is_some()
            || self.max_relay_cost_micros_per_mib.is_some()
    }
}

#[cfg(test)]
#[path = "mod_inline_tests.rs"]
mod tests;
