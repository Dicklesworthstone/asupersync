//! Byzantine-resistant per-peer resource limits for ATP protocol.
//!
//! Prevents resource exhaustion attacks by malicious peers through
//! configurable per-peer limits on memory usage, frame rates, and
//! connection resources.
//!
//! # Usage Example
//!
//! ```ignore
//! use crate::net::atp::protocol::{ResourceManager, ResourceLimits, PeerId};
//!
//! // Create resource manager with custom limits
//! let limits = ResourceLimits {
//!     max_memory_per_peer: 32 * 1024 * 1024,  // 32 MB per peer
//!     max_frame_rate: 50,                      // 50 frames/second
//!     max_sessions_per_peer: 2,
//!     ..Default::default()
//! };
//! let mut manager = ResourceManager::with_limits(limits);
//!
//! // Check and allocate resources before processing peer requests
//! let peer_id = PeerId::from_label("untrusted-peer");
//!
//! // Before processing a frame
//! if !manager.record_frame(peer_id) {
//!     return Err("Frame rate limit exceeded");
//! }
//!
//! // Before allocating memory for peer data
//! if !manager.allocate_memory(peer_id, frame_size) {
//!     return Err("Memory limit exceeded");
//! }
//!
//! // Process frame...
//! manager.frame_processed(&peer_id);
//!
//! // Periodically clean up inactive peers
//! manager.cleanup_inactive_peers(Duration::from_secs(300));
//! ```
//!
//! # Integration Notes
//!
//! This module should be integrated into:
//! - `session.rs`: Add ResourceManager to session state for per-peer tracking
//! - `frames.rs`: Check limits before processing incoming frames
//! - `codec.rs`: Validate frame sizes against memory limits
//! - Connection handlers: Rate limit and session management
//!
//! The implementation provides defense against:
//! - Memory exhaustion attacks (large manifests, many frames)
//! - Frame flooding attacks (high-frequency frame spam)
//! - Session exhaustion attacks (many concurrent sessions)
//! - Request amplification attacks (many pending object requests)

use crate::net::atp::protocol::session::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Resource limits configuration for Byzantine peer protection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Maximum memory usage per peer (bytes).
    pub max_memory_per_peer: u64,
    /// Maximum number of pending frames per peer.
    pub max_frames_per_peer: u32,
    /// Maximum frame rate per peer (frames per second).
    pub max_frame_rate: u32,
    /// Maximum number of concurrent sessions per peer.
    pub max_sessions_per_peer: u32,
    /// Time window for rate limiting (seconds).
    pub rate_limit_window: u32,
    /// Maximum pending object requests per peer.
    pub max_pending_requests: u32,
    /// Maximum object manifest size per peer (bytes).
    pub max_manifest_size: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_memory_per_peer: 64 * 1024 * 1024, // 64 MB
            max_frames_per_peer: 1000,
            max_frame_rate: 100, // 100 fps
            max_sessions_per_peer: 4,
            rate_limit_window: 60, // 1 minute
            max_pending_requests: 50,
            max_manifest_size: 16 * 1024 * 1024, // 16 MB
        }
    }
}

/// Per-peer resource usage tracking.
#[derive(Debug, Clone)]
struct PeerResourceUsage {
    /// Current memory usage (bytes).
    memory_usage: u64,
    /// Number of pending frames.
    pending_frames: u32,
    /// Frame rate tracking window.
    frame_timestamps: Vec<Instant>,
    /// Number of active sessions.
    active_sessions: u32,
    /// Number of pending object requests.
    pending_requests: u32,
    /// Last frame received time for cleanup.
    last_activity: Instant,
}

/// Public snapshot of per-peer resource usage.
///
/// The manager keeps timestamp history private so callers cannot mutate
/// accounting state or depend on wall-clock internals. This snapshot exposes
/// the counters needed for diagnostics and admission decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerResourceSnapshot {
    /// Current memory usage in bytes.
    pub memory_usage: u64,
    /// Number of frames admitted but not yet processed.
    pub pending_frames: u32,
    /// Number of frame timestamps currently inside the rate-limit window.
    pub recent_frame_count: usize,
    /// Number of active sessions.
    pub active_sessions: u32,
    /// Number of pending object requests.
    pub pending_requests: u32,
}

impl PeerResourceUsage {
    fn snapshot(&self) -> PeerResourceSnapshot {
        PeerResourceSnapshot {
            memory_usage: self.memory_usage,
            pending_frames: self.pending_frames,
            recent_frame_count: self.frame_timestamps.len(),
            active_sessions: self.active_sessions,
            pending_requests: self.pending_requests,
        }
    }
}

impl Default for PeerResourceUsage {
    fn default() -> Self {
        Self {
            memory_usage: 0,
            pending_frames: 0,
            frame_timestamps: Vec::new(),
            active_sessions: 0,
            pending_requests: 0,
            last_activity: Instant::now(),
        }
    }
}

/// Resource manager for tracking and enforcing per-peer limits.
#[derive(Debug)]
pub struct ResourceManager {
    limits: ResourceLimits,
    peer_usage: HashMap<PeerId, PeerResourceUsage>,
}

impl ResourceManager {
    /// Create a new resource manager with default limits.
    #[must_use]
    pub fn new() -> Self {
        Self {
            limits: ResourceLimits::default(),
            peer_usage: HashMap::new(),
        }
    }

    /// Create a resource manager with custom limits.
    #[must_use]
    pub fn with_limits(limits: ResourceLimits) -> Self {
        Self {
            limits,
            peer_usage: HashMap::new(),
        }
    }

    /// Get the current resource limits.
    #[must_use]
    pub const fn limits(&self) -> &ResourceLimits {
        &self.limits
    }

    /// Update resource limits (affects new allocations only).
    pub fn update_limits(&mut self, limits: ResourceLimits) {
        self.limits = limits;
    }

    /// Check if a peer can allocate the requested memory.
    pub fn can_allocate_memory(&self, peer_id: &PeerId, bytes: u64) -> bool {
        let usage = self.peer_usage.get(peer_id);
        let current_usage = usage.map_or(0, |u| u.memory_usage);
        current_usage
            .checked_add(bytes)
            .is_some_and(|next_usage| next_usage <= self.limits.max_memory_per_peer)
    }

    /// Allocate memory for a peer, returning false if over limit.
    pub fn allocate_memory(&mut self, peer_id: PeerId, bytes: u64) -> bool {
        let current_usage = self
            .peer_usage
            .get(&peer_id)
            .map_or(0, |usage| usage.memory_usage);
        let Some(next_usage) = current_usage.checked_add(bytes) else {
            return false;
        };
        if next_usage > self.limits.max_memory_per_peer {
            return false;
        }

        let usage = self.peer_usage.entry(peer_id).or_default();
        usage.memory_usage = next_usage;
        usage.last_activity = Instant::now();
        true
    }

    /// Release memory for a peer.
    pub fn deallocate_memory(&mut self, peer_id: &PeerId, bytes: u64) {
        if let Some(usage) = self.peer_usage.get_mut(peer_id) {
            usage.memory_usage = usage.memory_usage.saturating_sub(bytes);
        }
    }

    /// Check if a peer can send a new frame (rate and count limits).
    pub fn can_send_frame(&mut self, peer_id: &PeerId) -> bool {
        let usage = self.peer_usage.entry(*peer_id).or_default();
        let now = Instant::now();

        // Clean old frame timestamps outside the rate limit window
        if let Some(window_start) =
            now.checked_sub(Duration::from_secs(self.limits.rate_limit_window.into()))
        {
            usage.frame_timestamps.retain(|&ts| ts > window_start);
        }

        // Check frame rate limit
        if usage.frame_timestamps.len() >= self.limits.max_frame_rate as usize {
            return false;
        }

        // Check pending frame count limit
        usage.pending_frames < self.limits.max_frames_per_peer
    }

    /// Record a frame sent by a peer.
    pub fn record_frame(&mut self, peer_id: PeerId) -> bool {
        if !self.can_send_frame(&peer_id) {
            return false;
        }

        let usage = self.peer_usage.entry(peer_id).or_default();
        let now = Instant::now();

        usage.frame_timestamps.push(now);
        usage.pending_frames += 1;
        usage.last_activity = now;
        true
    }

    /// Mark a frame as processed (reduces pending count).
    pub fn frame_processed(&mut self, peer_id: &PeerId) {
        if let Some(usage) = self.peer_usage.get_mut(peer_id) {
            usage.pending_frames = usage.pending_frames.saturating_sub(1);
        }
    }

    /// Check if a peer can start a new session.
    pub fn can_start_session(&self, peer_id: &PeerId) -> bool {
        let usage = self.peer_usage.get(peer_id);
        let current_sessions = usage.map_or(0, |u| u.active_sessions);
        current_sessions < self.limits.max_sessions_per_peer
    }

    /// Record a new session started by a peer.
    pub fn start_session(&mut self, peer_id: PeerId) -> bool {
        if !self.can_start_session(&peer_id) {
            return false;
        }

        let usage = self.peer_usage.entry(peer_id).or_default();
        usage.active_sessions += 1;
        usage.last_activity = Instant::now();
        true
    }

    /// Record a session ended by a peer.
    pub fn end_session(&mut self, peer_id: &PeerId) {
        if let Some(usage) = self.peer_usage.get_mut(peer_id) {
            usage.active_sessions = usage.active_sessions.saturating_sub(1);
        }
    }

    /// Check if a peer can make a new object request.
    pub fn can_request_object(&self, peer_id: &PeerId) -> bool {
        let usage = self.peer_usage.get(peer_id);
        let current_requests = usage.map_or(0, |u| u.pending_requests);
        current_requests < self.limits.max_pending_requests
    }

    /// Record a new object request by a peer.
    pub fn request_object(&mut self, peer_id: PeerId) -> bool {
        if !self.can_request_object(&peer_id) {
            return false;
        }

        let usage = self.peer_usage.entry(peer_id).or_default();
        usage.pending_requests += 1;
        usage.last_activity = Instant::now();
        true
    }

    /// Mark an object request as completed.
    pub fn complete_request(&mut self, peer_id: &PeerId) {
        if let Some(usage) = self.peer_usage.get_mut(peer_id) {
            usage.pending_requests = usage.pending_requests.saturating_sub(1);
        }
    }

    /// Check if a manifest size is within limits for a peer.
    #[must_use]
    pub fn validate_manifest_size(&self, size: u64) -> bool {
        size <= self.limits.max_manifest_size
    }

    /// Get current resource usage for a peer.
    #[must_use]
    pub fn peer_usage(&self, peer_id: &PeerId) -> Option<PeerResourceSnapshot> {
        self.peer_usage
            .get(peer_id)
            .map(PeerResourceUsage::snapshot)
    }

    /// Get memory usage for a peer.
    #[must_use]
    pub fn peer_memory_usage(&self, peer_id: &PeerId) -> u64 {
        self.peer_usage.get(peer_id).map_or(0, |u| u.memory_usage)
    }

    /// Get pending frame count for a peer.
    #[must_use]
    pub fn peer_pending_frames(&self, peer_id: &PeerId) -> u32 {
        self.peer_usage.get(peer_id).map_or(0, |u| u.pending_frames)
    }

    /// Clean up peers with no outstanding resource obligations.
    pub fn cleanup_inactive_peers(&mut self, _timeout: Duration) {
        self.peer_usage.retain(|_, usage| {
            // Keep peers while they still own resources that must be released.
            usage.memory_usage > 0
                || usage.pending_frames > 0
                || usage.active_sessions > 0
                || usage.pending_requests > 0
        });
    }

    /// Get total number of tracked peers.
    #[must_use]
    pub fn peer_count(&self) -> usize {
        self.peer_usage.len()
    }

    /// Get aggregate memory usage across all peers.
    #[must_use]
    pub fn total_memory_usage(&self) -> u64 {
        self.peer_usage
            .values()
            .fold(0, |total, usage| total.saturating_add(usage.memory_usage))
    }

    /// Check if the system is under resource pressure.
    #[must_use]
    pub fn is_under_pressure(&self) -> bool {
        let total_peers = self.peer_count();
        let avg_memory_per_peer = if total_peers > 0 {
            self.total_memory_usage() / total_peers as u64
        } else {
            0
        };

        // Consider system under pressure if:
        // - Too many peers tracked (potential DoS)
        // - Average memory usage is high
        total_peers > 1000 || avg_memory_per_peer > self.limits.max_memory_per_peer / 2
    }

    /// Force cleanup of a specific peer (emergency use).
    pub fn force_cleanup_peer(&mut self, peer_id: &PeerId) {
        self.peer_usage.remove(peer_id);
    }
}

/// Error types for resource management operations.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ResourceError {
    /// Memory allocation would exceed per-peer limit.
    #[error(
        "Memory allocation would exceed limit for peer {peer_id:?}: requested {requested}, limit {limit}"
    )]
    MemoryLimitExceeded {
        peer_id: PeerId,
        requested: u64,
        limit: u64,
    },
    /// Frame rate limit exceeded.
    #[error("Frame rate limit exceeded for peer {peer_id:?}: {current_rate} > {limit}")]
    FrameRateLimitExceeded {
        peer_id: PeerId,
        current_rate: u32,
        limit: u32,
    },
    /// Too many pending frames.
    #[error("Too many pending frames for peer {peer_id:?}: {current} >= {limit}")]
    PendingFramesLimitExceeded {
        peer_id: PeerId,
        current: u32,
        limit: u32,
    },
    /// Too many active sessions.
    #[error("Too many active sessions for peer {peer_id:?}: {current} >= {limit}")]
    SessionLimitExceeded {
        peer_id: PeerId,
        current: u32,
        limit: u32,
    },
    /// Too many pending object requests.
    #[error("Too many pending requests for peer {peer_id:?}: {current} >= {limit}")]
    RequestLimitExceeded {
        peer_id: PeerId,
        current: u32,
        limit: u32,
    },
    /// Manifest size exceeds limit.
    #[error("Manifest size exceeds limit: {size} > {limit}")]
    ManifestSizeExceeded { size: u64, limit: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_allocation_limits() {
        let mut manager = ResourceManager::new();
        let peer_id = PeerId::from_label("test-peer");

        // Should allow allocation within limit
        assert!(manager.allocate_memory(peer_id, 1000));
        assert_eq!(manager.peer_memory_usage(&peer_id), 1000);

        // Should allow more allocation up to limit
        let limit = manager.limits().max_memory_per_peer;
        assert!(manager.allocate_memory(peer_id, limit - 1500));

        // Should reject allocation that exceeds limit
        assert!(!manager.allocate_memory(peer_id, 1000));

        // Should allow deallocation
        manager.deallocate_memory(&peer_id, 500);
        assert_eq!(manager.peer_memory_usage(&peer_id), limit - 1000);
    }

    #[test]
    fn test_memory_accounting_rejects_u64_overflow() {
        let limits = ResourceLimits {
            max_memory_per_peer: u64::MAX,
            ..ResourceLimits::default()
        };
        let mut manager = ResourceManager::with_limits(limits);
        let peer_id = PeerId::from_label("overflow-peer");

        assert!(manager.allocate_memory(peer_id, u64::MAX - 1));
        assert!(!manager.can_allocate_memory(&peer_id, 2));
        assert!(!manager.allocate_memory(peer_id, 2));
        assert_eq!(manager.peer_memory_usage(&peer_id), u64::MAX - 1);
    }

    #[test]
    fn test_peer_usage_returns_public_snapshot() {
        let mut manager = ResourceManager::new();
        let peer_id = PeerId::from_label("snapshot-peer");

        assert!(manager.allocate_memory(peer_id, 4096));
        assert!(manager.record_frame(peer_id));
        assert!(manager.start_session(peer_id));
        assert!(manager.request_object(peer_id));

        let usage = manager
            .peer_usage(&peer_id)
            .expect("peer should be tracked");
        assert_eq!(usage.memory_usage, 4096);
        assert_eq!(usage.pending_frames, 1);
        assert_eq!(usage.recent_frame_count, 1);
        assert_eq!(usage.active_sessions, 1);
        assert_eq!(usage.pending_requests, 1);
    }

    #[test]
    fn test_frame_rate_limiting() {
        let limits = ResourceLimits {
            max_frame_rate: 2,
            rate_limit_window: 1,
            ..ResourceLimits::default()
        };
        let mut manager = ResourceManager::with_limits(limits);
        let peer_id = PeerId::from_label("test-peer");

        // Should allow frames within rate limit
        assert!(manager.record_frame(peer_id));
        assert!(manager.record_frame(peer_id));

        // Should reject frames exceeding rate limit
        assert!(!manager.record_frame(peer_id));

        // Marking frames as processed relieves pending-frame pressure, but it
        // must not erase the rate-limit history inside the active time window.
        manager.frame_processed(&peer_id);
        manager.frame_processed(&peer_id);
        assert!(!manager.record_frame(peer_id));
    }

    #[test]
    fn test_pending_frame_limit_recovers_after_processing() {
        let limits = ResourceLimits {
            max_frames_per_peer: 2,
            max_frame_rate: 100,
            ..ResourceLimits::default()
        };
        let mut manager = ResourceManager::with_limits(limits);
        let peer_id = PeerId::from_label("pending-frame-peer");

        assert!(manager.record_frame(peer_id));
        assert!(manager.record_frame(peer_id));
        assert!(!manager.record_frame(peer_id));

        manager.frame_processed(&peer_id);
        assert!(manager.record_frame(peer_id));
    }

    #[test]
    fn test_session_limits() {
        let limits = ResourceLimits {
            max_sessions_per_peer: 2,
            ..ResourceLimits::default()
        };
        let mut manager = ResourceManager::with_limits(limits);
        let peer_id = PeerId::from_label("test-peer");

        // Should allow sessions within limit
        assert!(manager.start_session(peer_id));
        assert!(manager.start_session(peer_id));

        // Should reject sessions exceeding limit
        assert!(!manager.start_session(peer_id));

        // Should allow new session after ending one
        manager.end_session(&peer_id);
        assert!(manager.start_session(peer_id));
    }

    #[test]
    fn test_object_request_limits() {
        let limits = ResourceLimits {
            max_pending_requests: 3,
            ..ResourceLimits::default()
        };
        let mut manager = ResourceManager::with_limits(limits);
        let peer_id = PeerId::from_label("test-peer");

        // Should allow requests within limit
        assert!(manager.request_object(peer_id));
        assert!(manager.request_object(peer_id));
        assert!(manager.request_object(peer_id));

        // Should reject requests exceeding limit
        assert!(!manager.request_object(peer_id));

        // Should allow new request after completing one
        manager.complete_request(&peer_id);
        assert!(manager.request_object(peer_id));
    }

    #[test]
    fn test_manifest_size_validation() {
        let limits = ResourceLimits {
            max_manifest_size: 1024,
            ..ResourceLimits::default()
        };
        let manager = ResourceManager::with_limits(limits);

        assert!(manager.validate_manifest_size(512));
        assert!(manager.validate_manifest_size(1024));
        assert!(!manager.validate_manifest_size(1025));
    }

    #[test]
    fn test_cleanup_inactive_peers() {
        let mut manager = ResourceManager::new();
        let peer_id = PeerId::from_label("test-peer");

        // Allocate some resources
        assert!(manager.allocate_memory(peer_id, 1000));
        assert_eq!(manager.peer_count(), 1);

        // Should not cleanup peer with active resources
        manager.cleanup_inactive_peers(Duration::from_secs(0));
        assert_eq!(manager.peer_count(), 1);

        // Should cleanup peer after freeing resources and time passing
        manager.deallocate_memory(&peer_id, 1000);
        manager.cleanup_inactive_peers(Duration::from_secs(0));
        assert_eq!(manager.peer_count(), 0);
    }

    #[test]
    fn test_resource_pressure_detection() {
        let mut manager = ResourceManager::new();

        // Should not be under pressure initially
        assert!(!manager.is_under_pressure());

        // Create many peers to trigger pressure detection
        for i in 0..1001 {
            let peer_id = PeerId::from_label(&format!("peer-{}", i));
            manager.allocate_memory(peer_id, 1);
        }

        assert!(manager.is_under_pressure());
    }
}
