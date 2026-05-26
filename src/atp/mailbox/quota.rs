//! ATP Mailbox Quota - Resource limits and usage tracking.

use super::*;
use serde::{Deserialize, Serialize};
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
            grace_period: Duration::from_secs(3600), // 1 hour
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
        }
    }

    /// Create with custom policy.
    pub fn with_policy(policy: QuotaPolicy) -> Self {
        Self {
            limit: policy.max_bytes,
            current_usage: QuotaUsage::default(),
            policy,
        }
    }

    /// Check if operation would exceed quota.
    pub fn check_quota(&self, additional_bytes: u64) -> MailboxResult<()> {
        let new_usage = self.current_usage.bytes_used + additional_bytes;

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

        self.current_usage.bytes_used += bytes;
        self.current_usage.active_transfers += 1;
        self.current_usage.last_updated = SystemTime::now();

        Ok(QuotaReservation {
            manager_id: 0, // Simplified ID
            bytes_reserved: bytes,
            reserved_at: SystemTime::now(),
        })
    }

    /// Release quota reservation.
    pub fn release_quota(&mut self, reservation: QuotaReservation) {
        if self.current_usage.bytes_used >= reservation.bytes_reserved {
            self.current_usage.bytes_used -= reservation.bytes_reserved;
        } else {
            self.current_usage.bytes_used = 0;
        }

        if self.current_usage.active_transfers > 0 {
            self.current_usage.active_transfers -= 1;
        }

        self.current_usage.total_transfers += 1;
        self.current_usage.last_updated = SystemTime::now();
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
        self.get_utilization() > 80.0 && self.policy.auto_cleanup
    }

    /// Perform quota cleanup.
    pub fn perform_cleanup(&mut self) -> CleanupResult {
        let freed_bytes = self.current_usage.bytes_used / 2; // Simplified cleanup

        self.current_usage.bytes_used -= freed_bytes;
        self.current_usage.last_updated = SystemTime::now();

        CleanupResult {
            bytes_freed: freed_bytes,
            transfers_removed: 0, // Simplified
            cleanup_duration: Duration::from_millis(100),
        }
    }
}

/// Quota reservation handle.
#[derive(Debug)]
pub struct QuotaReservation {
    manager_id: u32,
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
mod tests {
    use super::*;

    #[test]
    fn test_quota_manager_creation() {
        let manager = QuotaManager::new(1000);
        assert_eq!(manager.limit, 1000);
        assert_eq!(manager.current_usage.bytes_used, 0);
    }

    #[test]
    fn test_quota_check_success() {
        let manager = QuotaManager::new(1000);
        let result = manager.check_quota(500);
        assert!(result.is_ok());
    }

    #[test]
    fn test_quota_check_failure() {
        let manager = QuotaManager::new(1000);
        let result = manager.check_quota(1500);
        assert!(result.is_err());
    }

    #[test]
    fn test_quota_reservation() {
        let mut manager = QuotaManager::new(1000);

        let reservation = manager.reserve_quota(200).unwrap();
        assert_eq!(manager.current_usage.bytes_used, 200);
        assert_eq!(manager.current_usage.active_transfers, 1);

        manager.release_quota(reservation);
        assert_eq!(manager.current_usage.bytes_used, 0);
        assert_eq!(manager.current_usage.active_transfers, 0);
        assert_eq!(manager.current_usage.total_transfers, 1);
    }

    #[test]
    fn test_quota_utilization() {
        let mut manager = QuotaManager::new(1000);
        manager.reserve_quota(300).unwrap();

        assert_eq!(manager.get_utilization(), 30.0);
    }

    #[test]
    fn test_cleanup_logic() {
        let mut manager = QuotaManager::new(1000);
        manager.reserve_quota(900).unwrap(); // High utilization

        assert!(manager.needs_cleanup());

        let result = manager.perform_cleanup();
        assert!(result.bytes_freed > 0);
        assert!(manager.current_usage.bytes_used < 900);
    }
}