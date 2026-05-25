//! ATP local resource-governance profiles.
//!
//! Profiles are policy presets only. They do not read host state or mutate
//! transfer state; callers combine them with measured pressure and explicit
//! user/daemon policy before passing budgets to the resource governor.

use serde::{Deserialize, Serialize};

/// Operator-selected power and network behavior profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AtpPowerProfile {
    /// Prefer throughput and low completion latency.
    MaxSpeed,
    /// Default profile that leaves practical room for other foreground work.
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

impl Default for AtpPowerProfile {
    fn default() -> Self {
        Self::Balanced
    }
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
}

#[cfg(test)]
mod tests {
    use super::{AtpPowerProfile, AtpResourceProfile};

    #[test]
    fn profile_keys_are_stable() {
        assert_eq!(AtpPowerProfile::BatterySaver.as_str(), "battery_saver");
        assert_eq!(
            AtpPowerProfile::RelayConservative.as_str(),
            "relay_conservative"
        );
    }

    #[test]
    fn battery_saver_is_stricter_than_balanced_for_local_pressure() {
        let balanced = AtpResourceProfile::for_power_profile(AtpPowerProfile::Balanced);
        let battery = AtpResourceProfile::for_power_profile(AtpPowerProfile::BatterySaver);

        assert!(battery.background_priority);
        assert!(battery.max_in_flight_bytes < balanced.max_in_flight_bytes);
        assert!(battery.max_repair_symbols_per_second < balanced.max_repair_symbols_per_second);
        assert!(battery.max_disk_write_concurrency < balanced.max_disk_write_concurrency);
    }
}
