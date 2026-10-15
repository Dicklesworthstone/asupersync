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
mod tests {
    use super::*;

    #[test]
    fn unknown_quality_uses_static_fallback() {
        // AC4: quality-unknown -> static defaults (never worse than today).
        let cfg = AdaptiveLayoutConfig::default();
        let choice = cfg.derive(None);
        assert_eq!(choice.source_symbols, 16);
        assert_eq!(choice.overhead, 4);
        assert_eq!(choice, cfg.fallback());
    }

    #[test]
    fn outputs_respect_floors_and_ceilings() {
        let cfg = AdaptiveLayoutConfig::default();
        for loss_pct in 0..=100 {
            let q = PathQuality::new(50.0, f64::from(loss_pct) / 100.0, 0);
            let choice = cfg.derive(Some(q));
            assert!(choice.source_symbols >= cfg.min_source_symbols);
            assert!(choice.source_symbols <= cfg.max_source_symbols);
            assert!(choice.overhead >= cfg.min_overhead);
            assert!(choice.overhead <= cfg.max_overhead);
        }
    }

    #[test]
    fn overhead_and_block_size_are_monotone_in_loss() {
        // AC2: worse loss never decreases overhead or block size (RTT fixed).
        let cfg = AdaptiveLayoutConfig::default();
        let mut prev = cfg.derive(Some(PathQuality::new(50.0, 0.0, 0)));
        let mut loss = 0u32;
        while loss <= 100 {
            let q = PathQuality::new(50.0, f64::from(loss) / 100.0, 0);
            let choice = cfg.derive(Some(q));
            assert!(
                choice.overhead >= prev.overhead,
                "overhead regressed at loss {loss}: {} < {}",
                choice.overhead,
                prev.overhead
            );
            assert!(
                choice.source_symbols >= prev.source_symbols,
                "block size regressed at loss {loss}"
            );
            prev = choice;
            loss += 5;
        }
    }

    #[test]
    fn block_size_is_monotone_in_rtt() {
        let cfg = AdaptiveLayoutConfig::default();
        let mut prev = cfg.derive(Some(PathQuality::new(0.0, 0.1, 0)));
        let mut rtt = 0u32;
        while rtt <= 400 {
            let q = PathQuality::new(f64::from(rtt), 0.1, 0);
            let choice = cfg.derive(Some(q));
            assert!(choice.source_symbols >= prev.source_symbols);
            prev = choice;
            rtt += 25;
        }
    }

    #[test]
    fn clean_path_is_smaller_than_lossy_path() {
        let cfg = AdaptiveLayoutConfig::default();
        let clean = cfg.derive(Some(PathQuality::new(10.0, 0.0, 0)));
        let lossy = cfg.derive(Some(PathQuality::new(10.0, 0.5, 0)));
        assert!(lossy.overhead > clean.overhead);
        assert!(lossy.source_symbols > clean.source_symbols);
    }

    #[test]
    fn loss_fraction_is_clamped() {
        let q = PathQuality::new(-5.0, 2.0, 3);
        assert_eq!(q.loss_ewma, 1.0);
        assert_eq!(q.rtt_ewma_ms, 0.0);
    }

    #[test]
    fn determinism() {
        let cfg = AdaptiveLayoutConfig::default();
        let q = PathQuality::new(120.0, 0.12, 2);
        assert_eq!(cfg.derive(Some(q)), cfg.derive(Some(q)));
    }
}
