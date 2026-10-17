//! Adaptive RaptorQ block-layout policy from observed path quality.
//!
//! The static `StateEncoder` block layout ignores what the transport already
//! knows about a path. Lossy paths want *larger* extended blocks (fewer control
//! round-trips, more repair budget); clean, fast paths want *smaller* blocks
//! (lower decode latency). This module is the pure policy heart of bead
//! `asupersync-raptorq-leverage-3bb2pl.3`: a deterministic, monotone mapping
//! from a [`PathQuality`] snapshot to a [`BlockLayoutChoice`] `(K, overhead)`,
//! bounded by configured floors and ceilings, with a conservative static
//! fallback when quality is unknown (so it is never worse than today).
//!
//! It is a pure function of its inputs — no I/O, no clock — and the snapshot is
//! itself logged on the encode path, so adaptive choices are replayable and
//! auditable. The encode-time seam (`distributed::encoding`), the config
//! plumbing (`distributed::distribution`), the per-path quality export from the
//! transport aggregator/router, and the decision-contract telemetry row are
//! wired on top of this policy in sibling slices.
//!
//! # Monotonicity contract
//!
//! Holding RTT and reorder fixed, a worse loss estimate never *decreases* either
//! the repair overhead or the block size. This is the property the bead requires
//! and the policy table is unit-tested against.

/// EWMA-smoothed observed quality of a network path.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PathQuality {
    /// Smoothed round-trip time, in milliseconds.
    pub rtt_ewma_ms: f64,
    /// Smoothed loss fraction, clamped to `0.0..=1.0`.
    pub loss_ewma: f64,
    /// Observed reorder depth (informational; not a layout driver here).
    pub reorder_depth: u32,
}

impl PathQuality {
    /// Builds a snapshot, clamping the loss fraction into `0.0..=1.0`.
    #[must_use]
    pub fn new(rtt_ewma_ms: f64, loss_ewma: f64, reorder_depth: u32) -> Self {
        Self {
            rtt_ewma_ms: rtt_ewma_ms.max(0.0),
            loss_ewma: loss_ewma.clamp(0.0, 1.0),
            reorder_depth,
        }
    }
}

/// Floors, ceilings, breakpoints, and the static fallback for the policy.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AdaptiveLayoutConfig {
    /// Minimum source symbols `K` (block-size floor, for clean fast paths).
    pub min_source_symbols: u16,
    /// Maximum source symbols `K` (block-size ceiling, for lossy paths).
    pub max_source_symbols: u16,
    /// Minimum repair overhead.
    pub min_overhead: u16,
    /// Maximum repair overhead.
    pub max_overhead: u16,
    /// RTT (ms) at and above which the block-size RTT term saturates.
    pub rtt_saturation_ms: f64,
    /// Source symbols used when path quality is unknown (current static value).
    pub static_source_symbols: u16,
    /// Repair overhead used when path quality is unknown.
    pub static_overhead: u16,
}

impl Default for AdaptiveLayoutConfig {
    fn default() -> Self {
        Self {
            min_source_symbols: 4,
            max_source_symbols: 64,
            min_overhead: 2,
            max_overhead: 32,
            rtt_saturation_ms: 200.0,
            static_source_symbols: 16,
            static_overhead: 4,
        }
    }
}

/// The block layout chosen by the policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockLayoutChoice {
    /// Source symbols `K`.
    pub source_symbols: u16,
    /// Repair overhead (`N = K + overhead`).
    pub overhead: u16,
}

impl AdaptiveLayoutConfig {
    /// The conservative choice used when path quality is unknown: the static
    /// defaults, clamped into the configured bounds. Never worse than today.
    #[must_use]
    pub fn fallback(&self) -> BlockLayoutChoice {
        BlockLayoutChoice {
            source_symbols: self.static_source_symbols.clamp(
                self.min_source_symbols.min(self.max_source_symbols),
                self.max_source_symbols.max(self.min_source_symbols),
            ),
            overhead: self.static_overhead.clamp(
                self.min_overhead.min(self.max_overhead),
                self.max_overhead.max(self.min_overhead),
            ),
        }
    }

    /// Derives the block layout for the given path quality.
    ///
    /// `None` (quality unknown) yields [`Self::fallback`]. Otherwise: repair
    /// overhead scales with loss; block size scales with a combination of loss
    /// and RTT (both raise it, so it is monotone in each). All outputs are
    /// clamped into the configured floors/ceilings.
    #[must_use]
    pub fn derive(&self, quality: Option<PathQuality>) -> BlockLayoutChoice {
        let Some(q) = quality else {
            return self.fallback();
        };

        // Repair overhead is driven purely by loss (clean monotonicity).
        let overhead = lerp_u16(self.min_overhead, self.max_overhead, q.loss_ewma);

        // Block size grows with loss (amortize control round-trips on lossy
        // paths) and with RTT (fewer round-trips when each is expensive). A
        // weighted, clamped combination keeps it monotone in both.
        let rtt_term = if self.rtt_saturation_ms > 0.0 {
            (q.rtt_ewma_ms / self.rtt_saturation_ms).clamp(0.0, 1.0)
        } else {
            0.0
        };
        let block_t = (0.6 * q.loss_ewma + 0.4 * rtt_term).clamp(0.0, 1.0);
        let source_symbols = lerp_u16(self.min_source_symbols, self.max_source_symbols, block_t);

        BlockLayoutChoice {
            source_symbols,
            overhead,
        }
    }
}

/// Linearly interpolates `lo..=hi` at `t in [0,1]`, rounding to the nearest
/// `u16`. Monotone non-decreasing in `t`; returns `lo` if `hi <= lo`.
fn lerp_u16(lo: u16, hi: u16, t: f64) -> u16 {
    if hi <= lo {
        return lo;
    }
    let t = t.clamp(0.0, 1.0);
    let span = f64::from(hi - lo);
    lo + (span * t).round() as u16
}

#[cfg(test)]
#[path = "adaptive_layout_inline_tests.rs"]
mod tests;
