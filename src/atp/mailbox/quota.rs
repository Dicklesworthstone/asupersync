//! ATP Mailbox Quota - Resource limits and usage tracking.

use super::{MailboxError, MailboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

/// Manages quota limits and usage tracking.
#[derive(Debug)]
pub struct QuotaManager {
    /// Current quota limit
    limit: u64,

    /// Current usage
    current_usage: QuotaUsage,

    /// Quota policy
    policy: QuotaPolicy,

    /// Active reservations by reservation identifier.
    active_reservations: HashMap<u64, ReservationRecord>,

    /// Monotonic reservation identifier source.
    next_reservation_id: u64,
}

/// Quota usage tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaUsage {
    /// Bytes currently used
    pub bytes_used: u64,

    /// Number of active transfers
    pub active_transfers: u32,

    /// Total historical transfers
    pub total_transfers: u64,

    /// Last usage update time
    pub last_updated: SystemTime,
}

impl Default for QuotaUsage {
    fn default() -> Self {
        Self {
            bytes_used: 0,
            active_transfers: 0,
            total_transfers: 0,
            last_updated: SystemTime::now(),
        }
    }
}

/// Quota policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaPolicy {
    /// Maximum bytes allowed
    pub max_bytes: u64,

    /// Maximum active transfers
    pub max_active_transfers: u32,

    /// Data retention period
    pub retention_period: Duration,

    /// Grace period for quota violations
    pub grace_period: Duration,

    /// Enable automatic cleanup
    pub auto_cleanup: bool,
}

impl Default for QuotaPolicy {
    fn default() -> Self {
        Self {
            max_bytes: 100_000_000, // 100 MB
            max_active_transfers: 10,
            retention_period: Duration::from_secs(7 * 24 * 3600), // 1 week
            grace_period: Duration::from_secs(3600),              // 1 hour
            auto_cleanup: true,
        }
    }
}

impl QuotaManager {
    /// Create a new quota manager with specified limit.
    pub fn new(limit: u64) -> Self {
        Self {
            limit,
            current_usage: QuotaUsage::default(),
            policy: QuotaPolicy {
                max_bytes: limit,
                ..Default::default()
            },
            active_reservations: HashMap::new(),
            next_reservation_id: 1,
        }
    }

    /// Create with custom policy.
    pub fn with_policy(policy: QuotaPolicy) -> Self {
        Self {
            limit: policy.max_bytes,
            current_usage: QuotaUsage::default(),
            policy,
            active_reservations: HashMap::new(),
            next_reservation_id: 1,
        }
    }

    /// Current byte limit enforced by this manager.
    pub fn limit(&self) -> u64 {
        self.limit
    }

    /// Check if operation would exceed quota.
    pub fn check_quota(&self, additional_bytes: u64) -> MailboxResult<()> {
        let new_usage = self
            .current_usage
            .bytes_used
            .checked_add(additional_bytes)
            .ok_or(MailboxError::QuotaExceeded {
                usage: u64::MAX,
                limit: self.policy.max_bytes,
            })?;

        if new_usage > self.policy.max_bytes {
            return Err(MailboxError::QuotaExceeded {
                usage: new_usage,
                limit: self.policy.max_bytes,
            });
        }

        if self.current_usage.active_transfers >= self.policy.max_active_transfers {
            return Err(MailboxError::QuotaExceeded {
                usage: self.current_usage.active_transfers as u64,
                limit: self.policy.max_active_transfers as u64,
            });
        }

        Ok(())
    }

    /// Reserve quota for a transfer.
    pub fn reserve_quota(&mut self, bytes: u64) -> MailboxResult<QuotaReservation> {
        self.check_quota(bytes)?;
        let reservation_id = self.next_reservation_id()?;

        self.current_usage.bytes_used = self.current_usage.bytes_used.checked_add(bytes).ok_or(
            MailboxError::QuotaExceeded {
                usage: u64::MAX,
                limit: self.policy.max_bytes,
            },
        )?;
        self.current_usage.active_transfers += 1;
        self.current_usage.last_updated = SystemTime::now();

        let reservation = QuotaReservation {
            manager_id: reservation_id,
            bytes_reserved: bytes,
            reserved_at: SystemTime::now(),
        };
        self.active_reservations.insert(
            reservation_id,
            ReservationRecord {
                bytes_reserved: bytes,
                reserved_at: reservation.reserved_at,
            },
        );

        Ok(reservation)
    }

    /// Release quota reservation.
    pub fn release_quota(&mut self, reservation: QuotaReservation) {
        if let Some(record) = self.active_reservations.remove(&reservation.manager_id) {
            debug_assert_eq!(record.bytes_reserved, reservation.bytes_reserved);
            debug_assert_eq!(record.reserved_at, reservation.reserved_at);
            self.current_usage.bytes_used = self
                .current_usage
                .bytes_used
                .saturating_sub(record.bytes_reserved);

            if self.current_usage.active_transfers > 0 {
                self.current_usage.active_transfers -= 1;
            }

            self.current_usage.total_transfers =
                self.current_usage.total_transfers.saturating_add(1);
            self.current_usage.last_updated = SystemTime::now();
        }
    }

    /// Get current usage.
    pub fn get_usage(&self) -> &QuotaUsage {
        &self.current_usage
    }

    /// Get quota utilization percentage.
    pub fn get_utilization(&self) -> f64 {
        if self.policy.max_bytes == 0 {
            return 0.0;
        }

        (self.current_usage.bytes_used as f64 / self.policy.max_bytes as f64) * 100.0
    }

    /// Check if cleanup is needed.
    pub fn needs_cleanup(&self) -> bool {
        self.policy.auto_cleanup
            && is_above_percent(
                self.current_usage.bytes_used,
                self.policy.max_bytes,
                CLEANUP_TARGET_PERCENT,
            )
    }

    /// Perform quota cleanup.
    pub fn perform_cleanup(&mut self) -> CleanupResult {
        let start = SystemTime::now();
        let cutoff_age = self
            .policy
            .retention_period
            .saturating_add(self.policy.grace_period);
        let now = SystemTime::now();
        let target_usage = percent_floor_u64(self.policy.max_bytes, CLEANUP_TARGET_PERCENT);
        let mut candidates = self
            .active_reservations
            .iter()
            .filter_map(|(id, reservation)| {
                let age = now
                    .duration_since(reservation.reserved_at)
                    .unwrap_or(Duration::ZERO);
                if age >= cutoff_age || self.current_usage.bytes_used > target_usage {
                    Some((*id, reservation.reserved_at, reservation.bytes_reserved))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        candidates.sort_by_key(|(_, reserved_at, _)| *reserved_at);

        let mut freed_bytes = 0u64;
        let mut transfers_removed = 0u32;
        for (id, _, bytes_reserved) in candidates {
            if self.current_usage.bytes_used <= target_usage
                && now
                    .duration_since(
                        self.active_reservations
                            .get(&id)
                            .map_or(now, |reservation| reservation.reserved_at),
                    )
                    .unwrap_or(Duration::ZERO)
                    < cutoff_age
            {
                break;
            }

            if self.active_reservations.remove(&id).is_some() {
                self.current_usage.bytes_used =
                    self.current_usage.bytes_used.saturating_sub(bytes_reserved);
                self.current_usage.active_transfers =
                    self.current_usage.active_transfers.saturating_sub(1);
                freed_bytes = freed_bytes.saturating_add(bytes_reserved);
                transfers_removed = transfers_removed.saturating_add(1);
            }
        }
        self.current_usage.last_updated = SystemTime::now();

        CleanupResult {
            bytes_freed: freed_bytes,
            transfers_removed,
            cleanup_duration: start.elapsed().unwrap_or(Duration::ZERO),
        }
    }

    fn next_reservation_id(&mut self) -> MailboxResult<u64> {
        let reservation_id = self.next_reservation_id;
        self.next_reservation_id = self.next_reservation_id.checked_add(1).ok_or_else(|| {
            MailboxError::ConfigurationError {
                details: "mailbox quota reservation id space exhausted".to_string(),
            }
        })?;
        Ok(reservation_id)
    }
}

const CLEANUP_TARGET_PERCENT: u64 = 80;

fn percent_floor_u64(value: u64, percent: u64) -> u64 {
    ((u128::from(value) * u128::from(percent)) / 100) as u64
}

fn is_above_percent(value: u64, limit: u64, percent: u64) -> bool {
    if limit == 0 {
        return value > 0;
    }

    u128::from(value) * 100 > u128::from(limit) * u128::from(percent)
}

/// Quota reservation handle.
#[derive(Debug)]
pub struct QuotaReservation {
    manager_id: u64,
    bytes_reserved: u64,
    reserved_at: SystemTime,
}

#[derive(Debug, Clone)]
struct ReservationRecord {
    bytes_reserved: u64,
    reserved_at: SystemTime,
}

/// Result of cleanup operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanupResult {
    /// Number of bytes freed
    pub bytes_freed: u64,

    /// Number of transfers removed
    pub transfers_removed: u32,

    /// Time taken for cleanup
    pub cleanup_duration: Duration,
}

#[cfg(test)]
#[path = "quota_inline_tests.rs"]
mod tests;
