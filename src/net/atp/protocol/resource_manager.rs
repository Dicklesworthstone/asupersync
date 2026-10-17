//! Byzantine-resistant per-peer resource limits for ATP protocol.
//!
//! Prevents resource exhaustion attacks by malicious peers through
//! configurable per-peer limits on memory usage, frame rates, and
//! connection resources.
//!
//! # Usage Example
//!
//! ```no_run
//! use asupersync::net::atp::protocol::{ResourceManager, ResourceLimits, PeerId};
//! use std::time::Duration;
//!
//! # fn main() -> Result<(), &'static str> {
//! # let frame_size: u64 = 4 * 1024;
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
//! # Ok(())
//! # }
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

    /// Clean up peers with no outstanding resource obligations or live admission history.
    pub fn cleanup_inactive_peers(&mut self, timeout: Duration) {
        let now = Instant::now();
        let rate_window = Duration::from_secs(u64::from(self.limits.rate_limit_window));
        self.peer_usage.retain(|_, usage| {
            let has_outstanding_resources = usage.memory_usage > 0
                || usage.pending_frames > 0
                || usage.active_sessions > 0
                || usage.pending_requests > 0;
            let recently_active = now
                .checked_duration_since(usage.last_activity)
                .unwrap_or_default()
                < timeout;
            let has_recent_frame_history = !rate_window.is_zero()
                && usage
                    .frame_timestamps
                    .iter()
                    .any(|&ts| now.checked_duration_since(ts).unwrap_or_default() < rate_window);

            has_outstanding_resources || recently_active || has_recent_frame_history
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
#[path = "resource_manager_inline_tests.rs"]
mod tests;
