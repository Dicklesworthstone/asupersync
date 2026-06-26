//! Adaptive block-size & transport-parameter optimizer for ATP-over-RaptorQ.
//!
//! `br-asupersync-mixdaw` adaptive layer.
//! See `docs/atp_rq_adaptive_design.md` for the full derivation. This module is
//! the **runnable mathematical core**: four pure, deterministic, unit-testable
//! functions plus a seeded EXP3 controller. It is **opt-in** — a caller that
//! does not construct an [`AdaptiveController`] gets today's fixed behaviour
//! byte-for-byte, and [`AdaptiveController::next_block_plan`] returns `None`
//! until enough evidence has accrued, so the conservative fixed config is the
//! always-available fallback.
//!
//! # What it computes
//!
//! Given an online [`PathEstimate`] (RTT, loss, bandwidth median/trough, coding
//! throughput), it chooses, per block:
//! - the repair overhead `ε*(K, p̄, α)` that hits a calibrated decode-failure
//!   target `α` against the *conformal upper bound* `p̄` (not the mean), with a
//!   margin that shrinks as `1/√K` (concentration);
//! - the source-symbol count `K*` at the crossing point where the
//!   network-useful rate `λ/(1+ε)` equals the coding-throughput rate
//!   `s·μ_code(K)` — i.e. grow the block while network-bound, stop when
//!   coding-bound;
//! - the UDP fan-out `N*` (smallest that nears the bandwidth cap).
//!
//! An EXP3 bandit over the `(K, N)` grid, warm-started at the model `K*`, hedges
//! model error with vanishing regret vs the best static arm.

#![allow(
    clippy::many_single_char_names,
    clippy::module_name_repetitions,
    clippy::too_long_first_doc_paragraph
)]

use crate::cx::Cx;
use crate::util::det_rng::DetRng;
use std::fmt::Write as _;

const FANOUT_SOCKET_EFFICIENCY: f64 = 0.6;
const FANOUT_CAP_TARGET: f64 = 0.95;
const PATH_SIGNAL_EMA_ALPHA: f64 = 0.20;
const MIN_PATH_RTT_S: f64 = 0.000_001;
const MAX_PATH_RTT_S: f64 = 60.0;
const MAX_PATH_LOSS_RATE: f64 = 0.999;
/// Clean/near-clean paths should not inherit repair-symbol overhead from the
/// conservative RaptorQ inactivation-floor model. Feedback can still request
/// repair later if actual loss appears.
const CLEAN_LINK_REPAIR_OVERHEAD_DEADBAND: f64 = 0.0015;
/// Loss level where the round-budget repair margin reaches full strength.
///
/// The pure decode-failure curve is byte-efficient, but MATRIX-20 shows lossy
/// transfers are feedback-round bound. At a 2% path loss we deliberately spend
/// extra bounded repair in the first lossy repair round to avoid another RTT.
const LOSSY_ROUND_BUDGET_FULL_STRENGTH_LOSS: f64 = 0.02;
/// Maximum multiplier applied to the pure decode-failure repair budget.
const LOSSY_ROUND_BUDGET_MAX_REPAIR_MULTIPLIER: f64 = 2.0;
/// Conservative cold-start pacing floor used before path evidence is usable.
///
/// This is deliberately below the historic RQ fixed cap: malformed feedback or
/// thin samples must fail closed to a bounded trickle, never fail open to a
/// line-rate burst.
pub const DEFAULT_COLD_START_PACING_BYTES_PER_S: f64 = 8.0 * 1024.0 * 1024.0;
/// Default raw-datagram burst bound for token-bucket spray pacing.
pub const DEFAULT_MAX_PACING_BURST_DATAGRAMS: u32 = 32;

#[must_use]
fn fanout_gain(fanout: usize) -> f64 {
    let exponent = i32::try_from(fanout.max(1)).unwrap_or(i32::MAX);
    1.0 - (1.0 - FANOUT_SOCKET_EFFICIENCY).powi(exponent)
}

/// Estimated path properties. `None`-valued evidence or `samples <
/// min_samples_to_activate` ⇒ the controller declines (caller uses fixed config).
#[derive(Debug, Clone, Copy)]
pub struct PathEstimate {
    /// Control-plane round-trip time (seconds).
    pub rtt_s: f64,
    /// Per-symbol erasure probability, point estimate.
    pub loss_p_hat: f64,
    /// Per-symbol erasure probability, conformal upper bound used for sizing.
    pub loss_p_bar: f64,
    /// Median achievable aggregate goodput (bytes/s).
    pub bw_median_bps: f64,
    /// Trough goodput (CVaR of instantaneous rate, bytes/s).
    pub bw_trough_bps: f64,
    /// Measured encode throughput (source symbols/s at the reference K).
    pub enc_symbols_per_s: f64,
    /// Measured decode throughput (source symbols/s at the reference K).
    pub dec_symbols_per_s: f64,
    /// Reference K at which `enc/dec_symbols_per_s` were measured.
    pub coding_ref_k: u32,
    /// Coding superlinearity exponent γ ∈ [1, 2] (decode cost ~ K^γ).
    pub coding_gamma: f64,
    /// Number of measurement samples backing this estimate.
    pub samples: u32,
}

impl PathEstimate {
    /// A neutral prior used before any measurement (declines activation).
    #[must_use]
    pub fn unknown() -> Self {
        Self {
            rtt_s: 0.05,
            loss_p_hat: 0.0,
            loss_p_bar: 0.0,
            bw_median_bps: 0.0,
            bw_trough_bps: 0.0,
            enc_symbols_per_s: 0.0,
            dec_symbols_per_s: 0.0,
            coding_ref_k: 1024,
            coding_gamma: 1.5,
            samples: 0,
        }
    }

    /// Decode throughput (source symbols/s) at an arbitrary `k`, scaling the
    /// reference measurement by the superlinear coding cost `~k^γ`:
    /// `μ(k) = μ(k_ref) · (k_ref / k)^{γ−1}`.
    #[must_use]
    pub fn decode_symbols_per_s_at(&self, k: u32) -> f64 {
        if self.dec_symbols_per_s <= 0.0 || k == 0 {
            return 0.0;
        }
        let kref = f64::from(self.coding_ref_k.max(1));
        let kf = f64::from(k);
        let exp = (self.coding_gamma - 1.0).clamp(0.0, 1.0);
        self.dec_symbols_per_s * (kref / kf).powf(exp)
    }
}

/// QUIC recovery/congestion-control signals used to shape adaptive rewards.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PathSignalSample {
    /// Smoothed round-trip time in seconds.
    pub smoothed_rtt_s: f64,
    /// Congestion window in bytes.
    pub congestion_window_bytes: u64,
    /// Recent packet/symbol loss rate in `[0, 1)`.
    pub loss_rate: f64,
}

impl PathSignalSample {
    /// Clamp raw transport signals to finite ranges before smoothing/reward use.
    #[must_use]
    pub fn clamped(self) -> Self {
        Self {
            smoothed_rtt_s: clamp_path_rtt(self.smoothed_rtt_s),
            congestion_window_bytes: self.congestion_window_bytes.max(1),
            loss_rate: clamp_path_loss(self.loss_rate),
        }
    }
}

fn clamp_path_rtt(value: f64) -> f64 {
    if value.is_nan() {
        MIN_PATH_RTT_S
    } else {
        value.clamp(MIN_PATH_RTT_S, MAX_PATH_RTT_S)
    }
}

fn clamp_path_loss(value: f64) -> f64 {
    if value.is_nan() {
        0.0
    } else {
        value.clamp(0.0, MAX_PATH_LOSS_RATE)
    }
}

/// One per-block decision.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BlockPlan {
    /// Source symbols per block (block size = `k · symbol_size`).
    pub k: u32,
    /// Round-0 repair overhead (extra fraction over source).
    pub overhead: f64,
    /// UDP fan-out (sockets to spray across).
    pub fanout: usize,
}

/// Token-bucket-ready pacing target derived from a path estimate and block plan.
///
/// `raw_pacing_bits_per_s` is the value a caller can pass to
/// `CongestionController::configure_for_path_rate`. `useful_pacing_bytes_per_s`
/// is the expected payload throughput after repair overhead and decode CPU
/// limits are applied, for trace/replay assertions.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RateMatchedPacingPlan {
    /// Block/FEC/fanout plan used to derive this pacing target.
    pub block: BlockPlan,
    /// Raw over-the-wire spray rate, in bits per second.
    pub raw_pacing_bits_per_s: u64,
    /// Useful payload rate after repair overhead and coding CPU limits.
    pub useful_pacing_bytes_per_s: f64,
    /// Raw datagrams per second implied by `raw_pacing_bits_per_s`.
    pub datagrams_per_s: u32,
    /// Maximum datagrams released back-to-back by the token bucket.
    pub max_burst_datagrams: u32,
    /// True when evidence was too thin or malformed and the conservative floor
    /// was used instead of the online path estimate.
    pub cold_start: bool,
}

/// Deterministic diagnostic view of the adaptive controller's latest epoch.
///
/// This is intentionally an owned snapshot so callers can emit structured trace
/// events without reaching into controller internals or holding borrows across
/// transport code. The weight vector is per-epoch diagnostic state, not a
/// per-symbol hot-path allocation.
#[derive(Debug, Clone, PartialEq)]
pub struct AdaptiveDecisionSnapshot {
    /// Number of adaptive arm selections made by this controller.
    pub epoch: u64,
    /// Index in the bounded `(K, fanout)` arm grid selected for the latest epoch.
    pub selected_arm_index: Option<usize>,
    /// Latest selected block plan, if the controller has activated.
    pub selected_plan: Option<BlockPlan>,
    /// EXP3 weights in deterministic arm-grid order.
    pub weights: Vec<f64>,
    /// Latest smoothed QUIC path signals, if the caller has supplied them.
    pub path_signals: Option<PathSignalSample>,
}

/// Cost-model knobs and the reliability target.
#[derive(Debug, Clone)]
pub struct AdaptivePolicy {
    /// Target per-block decode-failure probability (e.g. `1e-3`).
    pub target_decode_alpha: f64,
    /// Maximum projected decode CPU as a fraction of cores (responsiveness cap).
    pub cpu_responsiveness_cap: f64,
    /// Number of CPU cores available to coding.
    pub cores: f64,
    /// Memory budget for a single block's decode (bytes).
    pub mem_budget_bytes: u64,
    /// Minimum samples before the controller activates.
    pub min_samples_to_activate: u32,
    /// Candidate source-symbol counts (must be ascending).
    pub arm_grid_k: Vec<u32>,
    /// Candidate UDP fan-outs (ascending).
    pub arm_grid_fanout: Vec<usize>,
    /// EXP3 learning rate.
    pub exp3_eta: f64,
    /// Cap on overhead (never spray more than this fraction of repair).
    pub max_overhead: f64,
}

impl Default for AdaptivePolicy {
    fn default() -> Self {
        Self {
            target_decode_alpha: 1e-3,
            cpu_responsiveness_cap: 0.75,
            cores: 8.0,
            mem_budget_bytes: 512 * 1024 * 1024,
            min_samples_to_activate: 3,
            arm_grid_k: vec![256, 512, 1024, 2048, 4096, 8192],
            arm_grid_fanout: vec![1, 2, 4, 8],
            exp3_eta: 0.1,
            max_overhead: 0.5,
        }
    }
}

// ─── Pure mathematical core (deterministic; the proof artifacts live here) ────

/// Standard normal upper-tail inverse-ish helper: the `z_α` such that
/// `Φ(−z_α) = α`. Uses the Beasley-Springer/Moro-style rational approximation of
/// the inverse normal CDF. Pure and deterministic.
#[must_use]
pub fn z_for_alpha(alpha: f64) -> f64 {
    // We want z with Φ(−z) = α  ⇔  z = −Φ⁻¹(α) = Φ⁻¹(1−α).
    inverse_normal_cdf(1.0 - alpha.clamp(1e-12, 0.5))
}

/// Φ(x): standard normal CDF via an `erf` approximation (Abramowitz & Stegun
/// 7.1.26). Max abs error ~1.5e-7. Pure.
#[must_use]
pub fn normal_cdf(x: f64) -> f64 {
    f64::midpoint(1.0, erf(x / std::f64::consts::SQRT_2))
}

fn erf(x: f64) -> f64 {
    let sign = if x < 0.0 { -1.0 } else { 1.0 };
    let x = x.abs();
    let t = 1.0 / (1.0 + 0.327_591_1 * x);
    let y = 1.0
        - (((((1.061_405_429 * t - 1.453_152_027) * t) + 1.421_413_741) * t - 0.284_496_736) * t
            + 0.254_829_592)
            * t
            * (-x * x).exp();
    sign * y
}

/// Inverse normal CDF Φ⁻¹(p) (Acklam's rational approximation). Pure.
#[must_use]
// Acklam's published reference coefficients are kept verbatim for auditability;
// the extra mantissa digits are harmless (truncated to f64 at compile time).
#[allow(clippy::excessive_precision)]
pub fn inverse_normal_cdf(p: f64) -> f64 {
    let p = p.clamp(1e-12, 1.0 - 1e-12);
    // Coefficients.
    const A: [f64; 6] = [
        -3.969_683_028_665_376e1,
        2.209_460_984_245_205e2,
        -2.759_285_104_469_687e2,
        1.383_577_518_672_690e2,
        -3.066_479_806_614_716e1,
        2.506_628_277_459_239e0,
    ];
    const B: [f64; 5] = [
        -5.447_609_879_822_406e1,
        1.615_858_368_580_409e2,
        -1.556_989_798_598_866e2,
        6.680_131_188_771_972e1,
        -1.328_068_155_288_572e1,
    ];
    const C: [f64; 6] = [
        -7.784_894_002_430_293e-3,
        -3.223_964_580_411_365e-1,
        -2.400_758_277_161_838e0,
        -2.549_732_539_343_734e0,
        4.374_664_141_464_968e0,
        2.938_163_982_698_783e0,
    ];
    const D: [f64; 4] = [
        7.784_695_709_041_462e-3,
        3.224_671_290_700_398e-1,
        2.445_134_137_142_996e0,
        3.754_408_661_907_416e0,
    ];
    let plow = 0.024_25;
    let phigh = 1.0 - plow;
    if p < plow {
        let q = (-2.0 * p.ln()).sqrt();
        (((((C[0] * q + C[1]) * q + C[2]) * q + C[3]) * q + C[4]) * q + C[5])
            / ((((D[0] * q + D[1]) * q + D[2]) * q + D[3]) * q + 1.0)
    } else if p <= phigh {
        let q = p - 0.5;
        let r = q * q;
        (((((A[0] * r + A[1]) * r + A[2]) * r + A[3]) * r + A[4]) * r + A[5]) * q
            / (((((B[0] * r + B[1]) * r + B[2]) * r + B[3]) * r + B[4]) * r + 1.0)
    } else {
        let q = (-2.0 * (1.0 - p).ln()).sqrt();
        -(((((C[0] * q + C[1]) * q + C[2]) * q + C[3]) * q + C[4]) * q + C[5])
            / ((((D[0] * q + D[1]) * q + D[2]) * q + D[3]) * q + 1.0)
    }
}

/// RaptorQ decode-failure probability for a block of `k` source symbols.
///
/// Sent with `overhead` extra repair over an erasure channel of probability
/// `loss` (§2.3): the Gaussian tail of the received-symbol Binomial plus the
/// RaptorQ inactivation floor `q^{⌈overhead·k⌉}`, `q = 1/256`. Pure.
#[must_use]
pub fn decode_fail_probability(k: u32, overhead: f64, loss: f64) -> f64 {
    if k == 0 {
        return 0.0;
    }
    let kf = f64::from(k);
    let p = loss.clamp(0.0, 0.999_999);
    let sent = kf * (1.0 + overhead.max(0.0));
    // RaptorQ needs ~K + delta symbols; delta ≈ 2 is a conservative constant.
    let need = kf + 2.0;
    let mean = sent * (1.0 - p);
    let var = (sent * p * (1.0 - p)).max(1e-9);
    let z = (mean - need) / var.sqrt();
    let gaussian = normal_cdf(-z); // P(received < need)
    let floor = (1.0_f64 / 256.0).powf((overhead.max(0.0) * kf).ceil());
    (gaussian + floor).clamp(0.0, 1.0)
}

/// Closed-form repair overhead `ε*(k, p̄, α)` that targets decode-failure `α`.
///
/// Sized against the conformal loss upper bound `p̄` (§2.3): mean loss plus a
/// `1/√K` concentration margin, then refined by a few bisection steps against
/// the exact [`decode_fail_probability`]. Pure, monotone. Clamped to
/// `[0, max_overhead]`.
#[must_use]
pub fn overhead_for_target(k: u32, loss_p_bar: f64, alpha: f64, max_overhead: f64) -> f64 {
    let base = decode_repair_overhead_for_target(k, loss_p_bar, alpha, max_overhead);
    let p = if loss_p_bar.is_finite() {
        loss_p_bar.clamp(0.0, 0.999)
    } else {
        0.0
    };
    round_budgeted_repair_overhead(base, p, max_overhead)
}

/// Closed-form repair overhead for the decode-failure target alone.
///
/// Unlike [`overhead_for_target`], this deliberately does not apply the
/// lossy-round budget multiplier. Use it when a caller wants a byte-efficient
/// first flight and can fall back to feedback-sized repair if the receiver
/// still reports missing symbols.
#[must_use]
pub fn decode_repair_overhead_for_target(
    k: u32,
    loss_p_bar: f64,
    alpha: f64,
    max_overhead: f64,
) -> f64 {
    if k == 0 {
        return 0.0;
    }
    let max_overhead = if max_overhead.is_finite() && max_overhead > 0.0 {
        max_overhead
    } else {
        0.0
    };
    if max_overhead == 0.0 {
        return 0.0;
    }
    let p = if loss_p_bar.is_finite() {
        loss_p_bar.clamp(0.0, 0.999)
    } else {
        0.0
    };
    if p <= CLEAN_LINK_REPAIR_OVERHEAD_DEADBAND {
        return 0.0;
    }
    let alpha = if alpha.is_finite() && alpha > 0.0 {
        alpha.clamp(1e-12, 0.5)
    } else {
        1e-3
    };
    decode_failure_overhead_for_target(k, p, alpha, max_overhead)
}

fn decode_failure_overhead_for_target(k: u32, p: f64, alpha: f64, max_overhead: f64) -> f64 {
    let kf = f64::from(k);
    let z = z_for_alpha(alpha);
    // First-order analytic seed.
    let seed = p / (1.0 - p) + z * (p / (kf * (1.0 - p))).sqrt();
    let mut lo = seed.clamp(0.0, max_overhead);
    let mut hi = max_overhead;
    // If even max_overhead can't hit α, return max_overhead (best effort).
    if decode_fail_probability(k, hi, p) > alpha {
        return hi;
    }
    // Bisection refine the smallest overhead achieving P_fail ≤ α.
    if decode_fail_probability(k, lo, p) <= alpha {
        return lo.clamp(0.0, max_overhead);
    }
    for _ in 0..40 {
        let mid = f64::midpoint(lo, hi);
        if decode_fail_probability(k, mid, p) <= alpha {
            hi = mid;
        } else {
            lo = mid;
        }
    }
    hi.clamp(0.0, max_overhead)
}

fn round_budgeted_repair_overhead(base: f64, p: f64, max_overhead: f64) -> f64 {
    if base <= 0.0 {
        return 0.0;
    }
    (base * lossy_round_budget_multiplier(p)).clamp(0.0, max_overhead)
}

fn lossy_round_budget_multiplier(p: f64) -> f64 {
    if p <= CLEAN_LINK_REPAIR_OVERHEAD_DEADBAND {
        return 1.0;
    }
    let span = (LOSSY_ROUND_BUDGET_FULL_STRENGTH_LOSS - CLEAN_LINK_REPAIR_OVERHEAD_DEADBAND)
        .max(f64::EPSILON);
    let t = ((p - CLEAN_LINK_REPAIR_OVERHEAD_DEADBAND) / span).clamp(0.0, 1.0);
    1.0 + t * (LOSSY_ROUND_BUDGET_MAX_REPAIR_MULTIPLIER - 1.0)
}

/// Steady-state goodput `G(K, ε, N)` in bytes/s.
///
/// The bottleneck of the network-useful rate `λ(N)/(1+ε)` and the
/// coding-throughput rate `s·μ_code(K)` (§2.3). Pure.
#[must_use]
pub fn goodput_bps(
    k: u32,
    overhead: f64,
    fanout: usize,
    est: &PathEstimate,
    symbol_size: u16,
) -> f64 {
    let s = f64::from(symbol_size.max(1));
    // Fan-out raises achievable rate with diminishing returns toward the cap.
    // Model λ(N) = bw_median · (1 − (1−ρ)^N) with ρ a per-socket efficiency.
    let lambda = est.bw_median_bps * fanout_gain(fanout);
    let network_useful = lambda / (1.0 + overhead.max(0.0));
    let coding_rate = s * est.decode_symbols_per_s_at(k);
    if coding_rate <= 0.0 {
        return network_useful;
    }
    network_useful.min(coding_rate)
}

/// Convert an online path estimate into a rate-matched datagram pacing target.
///
/// This is the E-7/F5 bridge from `PathEstimate` to the datagram token bucket:
/// it uses the calibrated FEC overhead from [`optimal_block`], paces the raw
/// spray so `λ/(1+ε)` is not above useful network capacity, and drops further
/// when decode CPU is the bottleneck. Before evidence is usable it returns a
/// deterministic cold-start floor rather than a zero or line-rate burst.
#[must_use]
pub fn rate_matched_pacing_plan(
    est: &PathEstimate,
    policy: &AdaptivePolicy,
    symbol_size: u16,
    cold_start_bytes_per_s: f64,
    max_burst_datagrams: u32,
) -> RateMatchedPacingPlan {
    let symbol_bytes = u32::from(symbol_size.max(1));
    let cold_start_bytes_per_s = finite_positive_or(
        cold_start_bytes_per_s,
        DEFAULT_COLD_START_PACING_BYTES_PER_S,
    );
    let max_burst_datagrams = max_burst_datagrams.max(1);

    if !estimate_can_drive_pacing(est, policy) {
        let block = BlockPlan {
            k: *policy.arm_grid_k.first().unwrap_or(&1024),
            overhead: 0.0,
            fanout: *policy.arm_grid_fanout.first().unwrap_or(&1),
        };
        return pacing_plan_from_rates(
            block,
            cold_start_bytes_per_s,
            cold_start_bytes_per_s,
            symbol_bytes,
            max_burst_datagrams,
            true,
        );
    }

    let block = optimal_block(est, policy, symbol_size);
    let lambda_bytes_per_s = pacing_capacity_bytes_per_s(est) * fanout_gain(block.fanout);
    let overhead_factor = 1.0 + block.overhead.max(0.0);
    let network_useful_bytes_per_s = lambda_bytes_per_s / overhead_factor;
    let coding_useful_bytes_per_s =
        responsive_coding_bytes_per_s(est, policy, block.k, symbol_size);
    let useful_bytes_per_s = coding_useful_bytes_per_s
        .map_or(network_useful_bytes_per_s, |coding| {
            network_useful_bytes_per_s.min(coding)
        })
        .max(1.0);
    let raw_bytes_per_s = (useful_bytes_per_s * overhead_factor).min(lambda_bytes_per_s.max(1.0));

    pacing_plan_from_rates(
        block,
        raw_bytes_per_s,
        useful_bytes_per_s,
        symbol_bytes,
        max_burst_datagrams,
        false,
    )
}

/// Build a rate-matched pacing plan constrained by advertised flow-control
/// credit.
///
/// The returned plan is capped so one RTT of raw planned spray does not exceed
/// `advertised_flow_credit_bytes`. A zero or too-small credit returns `None`
/// instead of fabricating a token-bucket trickle that would exceed the peer's
/// stated receive budget.
#[must_use]
pub fn rate_matched_pacing_plan_with_flow_credit(
    est: &PathEstimate,
    policy: &AdaptivePolicy,
    symbol_size: u16,
    cold_start_bytes_per_s: f64,
    max_burst_datagrams: u32,
    advertised_flow_credit_bytes: u64,
) -> Option<RateMatchedPacingPlan> {
    if advertised_flow_credit_bytes == 0 {
        return None;
    }

    let plan = rate_matched_pacing_plan(
        est,
        policy,
        symbol_size,
        cold_start_bytes_per_s,
        max_burst_datagrams,
    );
    let rtt_s = flow_credit_rtt_window_s(est);
    let credit_limited_raw_bytes_per_s = advertised_flow_credit_bytes as f64 / rtt_s;
    if credit_limited_raw_bytes_per_s < 1.0 {
        return None;
    }

    let planned_raw_bytes_per_s = plan.raw_pacing_bits_per_s as f64 / 8.0;
    if planned_raw_bytes_per_s <= credit_limited_raw_bytes_per_s {
        return Some(plan);
    }

    let overhead_factor = 1.0 + plan.block.overhead.max(0.0);
    let capped_useful_bytes_per_s = plan
        .useful_pacing_bytes_per_s
        .min(credit_limited_raw_bytes_per_s / overhead_factor)
        .max(1.0);
    Some(pacing_plan_from_rates(
        plan.block,
        credit_limited_raw_bytes_per_s,
        capped_useful_bytes_per_s,
        u32::from(symbol_size.max(1)),
        plan.max_burst_datagrams,
        plan.cold_start,
    ))
}

/// Choose the per-block plan at the network/coding crossing point (§2.4).
///
/// Picks the grid `K` maximizing [`goodput_bps`] (with `ε = ε*(K)`), subject to
/// the responsiveness and memory caps, and the smallest fan-out that nears the
/// bandwidth cap. Pure and deterministic.
#[must_use]
pub fn optimal_block(est: &PathEstimate, policy: &AdaptivePolicy, symbol_size: u16) -> BlockPlan {
    // Smallest fan-out reaching 95% of the cap.
    let fanout = *policy
        .arm_grid_fanout
        .iter()
        .find(|&&n| fanout_gain(n) >= FANOUT_CAP_TARGET)
        .unwrap_or_else(|| policy.arm_grid_fanout.last().unwrap_or(&4));

    let mut best = BlockPlan {
        k: *policy.arm_grid_k.first().unwrap_or(&1024),
        overhead: 0.0,
        fanout,
    };
    let mut best_g = f64::NEG_INFINITY;
    for &k in &policy.arm_grid_k {
        // Responsiveness cap: projected decode time per block must not exceed the
        // CPU budget. decode_time ≈ k / μ_dec(k); require decode rate to leave
        // headroom. We approximate by requiring μ_dec(k) > 0 and the block to fit
        // memory; the coding_rate term in goodput already penalizes large k.
        let block_bytes = u64::from(k) * u64::from(symbol_size);
        if block_bytes.saturating_mul(3) > policy.mem_budget_bytes {
            continue; // decode matrices ~3x block in memory
        }
        let overhead = overhead_for_target(
            k,
            est.loss_p_bar,
            policy.target_decode_alpha,
            policy.max_overhead,
        );
        let g = goodput_bps(k, overhead, fanout, est, symbol_size);
        // Tie-break toward SMALLER k (cheaper decode, less memory, finer feedback).
        if g > best_g * (1.0 + 1e-9) {
            best_g = g;
            best = BlockPlan {
                k,
                overhead,
                fanout,
            };
        }
    }
    best
}

fn estimate_can_drive_pacing(est: &PathEstimate, policy: &AdaptivePolicy) -> bool {
    est.samples >= policy.min_samples_to_activate
        && est.rtt_s.is_finite()
        && est.rtt_s >= MIN_PATH_RTT_S
        && est.bw_median_bps.is_finite()
        && est.bw_median_bps > 0.0
        && est.loss_p_bar.is_finite()
        && est.loss_p_bar >= 0.0
}

fn pacing_capacity_bytes_per_s(est: &PathEstimate) -> f64 {
    let median = est.bw_median_bps.max(0.0);
    if est.bw_trough_bps.is_finite() && est.bw_trough_bps > 0.0 {
        median.min(est.bw_trough_bps)
    } else {
        median
    }
}

fn responsive_coding_bytes_per_s(
    est: &PathEstimate,
    policy: &AdaptivePolicy,
    k: u32,
    symbol_size: u16,
) -> Option<f64> {
    let decode_symbols_per_s = est.decode_symbols_per_s_at(k);
    if !decode_symbols_per_s.is_finite() || decode_symbols_per_s <= 0.0 {
        return None;
    }
    let cores = finite_positive_or(policy.cores, 1.0);
    let cpu_cap = finite_positive_or(policy.cpu_responsiveness_cap, 0.1).clamp(0.01, 1.0);
    Some(decode_symbols_per_s * f64::from(symbol_size.max(1)) * cores * cpu_cap)
}

fn pacing_plan_from_rates(
    block: BlockPlan,
    raw_bytes_per_s: f64,
    useful_bytes_per_s: f64,
    symbol_bytes: u32,
    max_burst_datagrams: u32,
    cold_start: bool,
) -> RateMatchedPacingPlan {
    let raw_bytes_per_s = finite_positive_or(raw_bytes_per_s, 1.0);
    let useful_pacing_bytes_per_s = finite_positive_or(useful_bytes_per_s, 1.0);
    let raw_pacing_bits_per_s = bytes_per_s_to_bits_per_s(raw_bytes_per_s);
    let bits_per_datagram = u64::from(symbol_bytes).saturating_mul(8).max(1);
    let datagrams_per_s =
        (raw_pacing_bits_per_s / bits_per_datagram).clamp(1, u64::from(u32::MAX)) as u32;

    RateMatchedPacingPlan {
        block,
        raw_pacing_bits_per_s,
        useful_pacing_bytes_per_s,
        datagrams_per_s,
        max_burst_datagrams,
        cold_start,
    }
}

fn bytes_per_s_to_bits_per_s(bytes_per_s: f64) -> u64 {
    let bits_per_s = finite_positive_or(bytes_per_s, 1.0) * 8.0;
    if bits_per_s >= u64::MAX as f64 {
        u64::MAX
    } else {
        bits_per_s.ceil() as u64
    }
}

fn finite_positive_or(value: f64, fallback: f64) -> f64 {
    if value.is_finite() && value > 0.0 {
        value
    } else {
        fallback.max(1.0)
    }
}

fn flow_credit_rtt_window_s(est: &PathEstimate) -> f64 {
    if est.rtt_s.is_finite() && est.rtt_s >= MIN_PATH_RTT_S {
        clamp_path_rtt(est.rtt_s)
    } else {
        1.0
    }
}

// ─── EXP3 bandit controller over (K, N) arms (no-regret hedge) ───────────────

/// Per-block adaptive controller.
///
/// Closed-form `optimal_block` warm start plus an EXP3 bandit over `(K, N)` arms
/// that corrects model error with vanishing regret. Deterministic given the seed
/// and the observation stream.
pub struct AdaptiveController {
    policy: AdaptivePolicy,
    est: PathEstimate,
    /// One weight per arm `(k_index, fanout_index)`.
    weights: Vec<f64>,
    arms: Vec<(usize, usize)>,
    last_arm: Option<usize>,
    last_overhead: f64,
    epoch: u64,
    rng: DetRng,
    /// Running max observed loss-per-byte, to normalize EXP3 losses to [0,1].
    loss_scale: f64,
    /// Smoothed path signals supplied by a QUIC recovery/CC layer.
    path_signals: Option<PathSignalSample>,
}

impl AdaptiveController {
    /// Build a controller. `seed` makes EXP3 exploration deterministic/replayable.
    #[must_use]
    pub fn new(policy: AdaptivePolicy, seed: u64) -> Self {
        let mut arms = Vec::new();
        for ki in 0..policy.arm_grid_k.len() {
            for ni in 0..policy.arm_grid_fanout.len() {
                arms.push((ki, ni));
            }
        }
        let weights = vec![1.0; arms.len()];
        Self {
            policy,
            est: PathEstimate::unknown(),
            weights,
            arms,
            last_arm: None,
            last_overhead: 0.0,
            epoch: 0,
            rng: DetRng::new(seed),
            loss_scale: 0.0,
            path_signals: None,
        }
    }

    /// Replace the current path estimate (from the estimation layer).
    pub fn update_estimate(&mut self, est: PathEstimate) {
        self.est = est;
    }

    /// Update the smoothed QUIC path-signal view.
    ///
    /// Raw samples are clamped before entering the EMA so a single bad RTT/loss
    /// sample cannot dominate the next reward update.
    pub fn update_path_signals(&mut self, sample: PathSignalSample) -> PathSignalSample {
        let sample = sample.clamped();
        let smoothed = if let Some(prev) = self.path_signals {
            smooth_path_signals(prev, sample)
        } else {
            sample
        };
        self.path_signals = Some(smoothed);
        smoothed
    }

    /// EXP3 selection probability for arm `i`.
    fn arm_prob(&self, i: usize) -> f64 {
        let eta = self.policy.exp3_eta;
        let total: f64 = self.weights.iter().sum();
        let k = self.weights.len() as f64;
        (1.0 - eta) * self.weights[i] / total + eta / k
    }

    /// Pick the next block plan, or `None` if evidence is too thin (caller falls
    /// back to the fixed config). The first active epoch is the closed-form
    /// `optimal_block`; later epochs use deterministic EXP3 exploration.
    pub fn next_block_plan(&mut self, symbol_size: u16) -> Option<BlockPlan> {
        if self.est.samples < self.policy.min_samples_to_activate || self.est.bw_median_bps <= 0.0 {
            return None;
        }

        let mut model_plan = None;
        let chosen = if self.epoch == 0 {
            let plan = self.model_plan(symbol_size);
            model_plan = Some(plan);
            self.closest_arm_to_plan(plan)
        } else {
            // EXP3 sample: uniform [0,1) from the deterministic RNG (53-bit mantissa).
            let r = (self.rng.next_u64() >> 11) as f64 / (1u64 << 53) as f64;
            let mut cum = 0.0;
            let mut sampled = 0usize;
            for i in 0..self.arms.len() {
                cum += self.arm_prob(i);
                if r <= cum {
                    sampled = i;
                    break;
                }
            }
            sampled
        };

        self.epoch = self.epoch.saturating_add(1);
        self.last_arm = Some(chosen);
        let (ki, ni) = self.arms[chosen];
        let k = self.policy.arm_grid_k[ki];
        let fanout = self.policy.arm_grid_fanout[ni];
        let overhead = model_plan.map_or_else(
            || {
                overhead_for_target(
                    k,
                    self.est.loss_p_bar,
                    self.policy.target_decode_alpha,
                    self.policy.max_overhead,
                )
            },
            |plan| plan.overhead,
        );
        self.last_overhead = overhead;
        Some(BlockPlan {
            k,
            overhead,
            fanout,
        })
    }

    fn closest_arm_to_plan(&self, plan: BlockPlan) -> usize {
        let mut best = 0usize;
        let mut best_score = u64::MAX;
        for (idx, &(ki, ni)) in self.arms.iter().enumerate() {
            let k = self.policy.arm_grid_k[ki];
            let fanout = self.policy.arm_grid_fanout[ni];
            let k_delta = u64::from(k.abs_diff(plan.k));
            let fanout_delta = u64::try_from(fanout.abs_diff(plan.fanout)).unwrap_or(u64::MAX / 2);
            let score = k_delta.saturating_mul(16).saturating_add(fanout_delta);
            if score < best_score {
                best_score = score;
                best = idx;
            }
        }
        best
    }

    /// Feed back a measured block outcome: updates the EXP3 weight of the arm
    /// that was played using an importance-weighted loss (wall-seconds per
    /// useful byte, normalized to [0,1]).
    pub fn observe(&mut self, _sent: u64, _received: u64, wall_s: f64, useful_bytes: u64) {
        let Some(arm) = self.last_arm else {
            return;
        };
        if useful_bytes == 0 || wall_s <= 0.0 {
            return;
        }
        let raw = wall_s / (useful_bytes as f64); // seconds per useful byte
        self.apply_observed_loss(arm, raw);
    }

    /// Feed back a measured block outcome plus QUIC path signals.
    ///
    /// The base loss remains seconds per useful byte. Smoothed RTT/cwnd/loss add
    /// a path penalty to arms whose selected block footprint would overrun the
    /// current congestion window, so synthetic lossy/small-cwnd paths can steer
    /// EXP3 toward smaller arms without changing the deterministic selection
    /// machinery.
    pub fn observe_path_signals(
        &mut self,
        sent: u64,
        received: u64,
        wall_s: f64,
        useful_bytes: u64,
        symbol_size: u16,
        signals: PathSignalSample,
    ) {
        let Some(arm) = self.last_arm else {
            return;
        };
        if wall_s <= 0.0 || (sent == 0 && useful_bytes == 0) {
            return;
        }
        let signals = self.update_path_signals(signals);
        let measured_loss = if sent == 0 {
            0.0
        } else {
            let missing = sent.saturating_sub(received);
            (missing as f64 / sent as f64).clamp(0.0, MAX_PATH_LOSS_RATE)
        };
        let base = if useful_bytes == 0 {
            let sent_payload_bytes = sent.saturating_mul(u64::from(symbol_size.max(1))).max(1);
            let zero_useful_penalty = 1.0 + measured_loss.max(signals.loss_rate);
            (wall_s / sent_payload_bytes as f64) * zero_useful_penalty
        } else {
            wall_s / (useful_bytes as f64)
        };
        let raw = base + self.path_signal_penalty(arm, symbol_size, signals, measured_loss);
        self.apply_observed_loss(arm, raw);
    }

    fn apply_observed_loss(&mut self, arm: usize, raw: f64) {
        if !raw.is_finite() || raw <= 0.0 {
            return;
        }
        self.loss_scale = self.loss_scale.max(raw).max(f64::MIN_POSITIVE);
        let loss = (raw / self.loss_scale).clamp(0.0, 1.0);
        // Importance-weighted EXP3 update. Compute the arm probability into a
        // local first so it does not hold a borrow across the weight mutation.
        let eta = self.policy.exp3_eta;
        let total: f64 = self.weights.iter().sum();
        let k = self.weights.len() as f64;
        let p = ((1.0 - eta) * self.weights[arm] / total + eta / k).max(1e-9);
        let est_loss = loss / p;
        self.weights[arm] *= (-eta * est_loss).exp();
        // Renormalize to avoid underflow.
        let total: f64 = self.weights.iter().sum();
        if total > 0.0 && total.is_finite() {
            let arm_count = self.weights.len() as f64;
            for w in &mut self.weights {
                *w = (*w / total) * arm_count;
            }
        } else {
            for w in &mut self.weights {
                *w = 1.0;
            }
        }
    }

    fn path_signal_penalty(
        &self,
        arm: usize,
        symbol_size: u16,
        signals: PathSignalSample,
        measured_loss: f64,
    ) -> f64 {
        let (ki, ni) = self.arms[arm];
        let k = self.policy.arm_grid_k[ki];
        let fanout = self.policy.arm_grid_fanout[ni];
        let payload_bytes = f64::from(k) * f64::from(symbol_size.max(1));
        let overhead = self.last_overhead.max(0.0);
        let block_bytes = payload_bytes * (1.0 + overhead);
        let cwnd_bytes = signals.congestion_window_bytes.max(1) as f64;
        let cwnd_overrun = (block_bytes / cwnd_bytes - 1.0).max(0.0);
        let loss_rate = signals
            .loss_rate
            .max(measured_loss)
            .clamp(0.0, MAX_PATH_LOSS_RATE);
        let fanout_pressure = fanout.max(1) as f64;

        // Convert path pressure into seconds/useful-byte so it can share the
        // same EXP3 normalization path as wall-clock reward observations.
        (signals.smoothed_rtt_s * cwnd_overrun * (1.0 + loss_rate) * fanout_pressure)
            / payload_bytes.max(1.0)
    }

    /// The closed-form model recommendation (warm-start reference; for diagnostics
    /// and shadow-mode comparison).
    #[must_use]
    pub fn model_plan(&self, symbol_size: u16) -> BlockPlan {
        optimal_block(&self.est, &self.policy, symbol_size)
    }

    /// Return the latest per-epoch arm and EXP3 weights for deterministic
    /// logging or replay assertions.
    #[must_use]
    pub fn diagnostic_snapshot(&self) -> AdaptiveDecisionSnapshot {
        let selected_plan = self.last_arm.map(|arm| {
            let (ki, ni) = self.arms[arm];
            BlockPlan {
                k: self.policy.arm_grid_k[ki],
                overhead: self.last_overhead,
                fanout: self.policy.arm_grid_fanout[ni],
            }
        });
        AdaptiveDecisionSnapshot {
            epoch: self.epoch,
            selected_arm_index: self.last_arm,
            selected_plan,
            weights: self.weights.clone(),
            path_signals: self.path_signals,
        }
    }

    /// Emit the latest adaptive epoch as structured trace fields.
    ///
    /// This is meant to be called once per adaptive epoch, never per symbol.
    /// It uses [`Cx::trace_with_fields`] so runtimes stay silent unless a trace
    /// sink is installed.
    pub fn trace_last_decision(&self, cx: &Cx, event: &str, transport: &str) {
        let snapshot = self.diagnostic_snapshot();
        let epoch = snapshot.epoch.to_string();
        let selected_arm_index = snapshot
            .selected_arm_index
            .map_or_else(|| "none".to_string(), |idx| idx.to_string());
        let weight_count = snapshot.weights.len().to_string();
        let weights = format_weights(&snapshot.weights);
        let loss_scale = format!("{:.12}", self.loss_scale);
        let (path_rtt_s, path_cwnd_bytes, path_loss_rate) =
            if let Some(signals) = snapshot.path_signals {
                (
                    format!("{:.6}", signals.smoothed_rtt_s),
                    signals.congestion_window_bytes.to_string(),
                    format!("{:.6}", signals.loss_rate),
                )
            } else {
                ("none".to_string(), "none".to_string(), "none".to_string())
            };

        let (k, repair_overhead, fanout) = if let Some(plan) = snapshot.selected_plan {
            (
                plan.k.to_string(),
                format!("{:.6}", plan.overhead),
                plan.fanout.to_string(),
            )
        } else {
            ("none".to_string(), "none".to_string(), "none".to_string())
        };

        cx.trace_with_fields(
            event,
            &[
                ("transport", transport),
                ("epoch", &epoch),
                ("selected_arm_index", &selected_arm_index),
                ("k", &k),
                ("repair_overhead", &repair_overhead),
                ("fanout", &fanout),
                ("weight_count", &weight_count),
                ("weights", &weights),
                ("loss_scale", &loss_scale),
                ("path_rtt_s", &path_rtt_s),
                ("path_cwnd_bytes", &path_cwnd_bytes),
                ("path_loss_rate", &path_loss_rate),
            ],
        );
    }
}

fn smooth_path_signals(prev: PathSignalSample, sample: PathSignalSample) -> PathSignalSample {
    let alpha = PATH_SIGNAL_EMA_ALPHA;
    PathSignalSample {
        smoothed_rtt_s: ema(prev.smoothed_rtt_s, sample.smoothed_rtt_s, alpha),
        congestion_window_bytes: ema(
            prev.congestion_window_bytes as f64,
            sample.congestion_window_bytes as f64,
            alpha,
        )
        .round()
        .max(1.0) as u64,
        loss_rate: ema(prev.loss_rate, sample.loss_rate, alpha).clamp(0.0, MAX_PATH_LOSS_RATE),
    }
}

fn ema(prev: f64, sample: f64, alpha: f64) -> f64 {
    prev.mul_add(1.0 - alpha, sample * alpha)
}

fn format_weights(weights: &[f64]) -> String {
    let mut out = String::new();
    for (idx, weight) in weights.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        let _ = write!(&mut out, "{weight:.6}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn est(loss: f64, bw: f64) -> PathEstimate {
        PathEstimate {
            rtt_s: 0.09,
            loss_p_hat: loss,
            loss_p_bar: loss,
            bw_median_bps: bw,
            bw_trough_bps: bw * 0.7,
            enc_symbols_per_s: 2_000_000.0,
            dec_symbols_per_s: 1_500_000.0,
            coding_ref_k: 1024,
            coding_gamma: 1.5,
            samples: 10,
        }
    }

    #[test]
    fn normal_cdf_is_sane() {
        assert!((normal_cdf(0.0) - 0.5).abs() < 1e-6);
        assert!(normal_cdf(3.0) > 0.998 && normal_cdf(3.0) < 0.9995);
        assert!((normal_cdf(-3.0) + normal_cdf(3.0) - 1.0).abs() < 1e-6);
    }

    #[test]
    fn z_for_alpha_matches_known_quantiles() {
        // Φ⁻¹(0.999) ≈ 3.0902, so z for α=1e-3 ≈ 3.09.
        assert!((z_for_alpha(1e-3) - 3.0902).abs() < 0.01);
        // α=0.025 ⇒ z ≈ 1.96.
        assert!((z_for_alpha(0.025) - 1.95996).abs() < 0.01);
    }

    #[test]
    fn decode_fail_decreases_with_overhead() {
        // Choose (K, p, overheads) in the measurable transition band so the
        // values do not both underflow to exactly 0.0 at high overhead.
        let p = 0.10;
        let a = decode_fail_probability(512, 0.10, p);
        let b = decode_fail_probability(512, 0.13, p);
        let c = decode_fail_probability(512, 0.16, p);
        assert!(
            a > b && b > c && c >= 0.0,
            "more overhead ⇒ strictly lower failure: {a} {b} {c}"
        );
    }

    #[test]
    fn overhead_concentration_law_shrinks_with_k() {
        // THE key alien-artifact fact: at fixed (p, α), required overhead falls
        // as K grows (received-count concentration ~ 1/√K).
        let alpha = 1e-3;
        let p = 0.03;
        let e512 = overhead_for_target(512, p, alpha, 0.5);
        let e2048 = overhead_for_target(2048, p, alpha, 0.5);
        let e8192 = overhead_for_target(8192, p, alpha, 0.5);
        assert!(
            e512 > e2048 && e2048 > e8192,
            "overhead must shrink with K: {e512} {e2048} {e8192}"
        );
        // And every choice must actually meet the target.
        for &k in &[512u32, 2048, 8192] {
            let e = overhead_for_target(k, p, alpha, 0.5);
            assert!(
                decode_fail_probability(k, e, p) <= alpha * 1.000_001,
                "K={k} ε={e} must hit α"
            );
        }
    }

    #[test]
    fn overhead_increases_with_loss() {
        let alpha = 1e-3;
        let lo = overhead_for_target(2048, 0.01, alpha, 0.5);
        let hi = overhead_for_target(2048, 0.10, alpha, 0.5);
        assert!(hi > lo, "more loss ⇒ more overhead: {lo} {hi}");
    }

    #[test]
    fn overhead_deadband_elides_near_clean_repair_symbols() {
        let alpha = 1e-3;
        for loss in [0.0, 0.0005, CLEAN_LINK_REPAIR_OVERHEAD_DEADBAND] {
            assert_eq!(
                overhead_for_target(512, loss, alpha, 0.5),
                0.0,
                "near-clean loss should not pre-spray repair symbols: {loss}"
            );
        }

        let lossy = overhead_for_target(512, CLEAN_LINK_REPAIR_OVERHEAD_DEADBAND * 2.0, alpha, 0.5);
        assert!(
            lossy > 0.0,
            "loss above the near-clean deadband should re-enable calibrated repair overhead"
        );
    }

    #[test]
    fn overhead_deadband_eliminates_near_clean_repair_floor() {
        let alpha = 1e-3;
        for loss in [0.0, 0.0005, CLEAN_LINK_REPAIR_OVERHEAD_DEADBAND] {
            assert_eq!(
                overhead_for_target(2048, loss, alpha, 0.5),
                0.0,
                "near-clean measured loss must not inherit a repair floor"
            );
        }

        let lossy = overhead_for_target(2048, 0.02, alpha, 0.5);
        assert!(
            lossy > 0.0,
            "non-clean measured loss still needs calibrated repair overhead"
        );
        assert!(
            decode_fail_probability(2048, lossy, 0.02) <= alpha * 1.000_001,
            "lossy calibrated overhead must still hit the decode-failure target"
        );
    }

    #[test]
    fn overhead_adds_round_budget_margin_for_bad_regime_loss() {
        let alpha = 1e-6;
        let k = 437;
        let loss = LOSSY_ROUND_BUDGET_FULL_STRENGTH_LOSS;
        let base = decode_repair_overhead_for_target(k, loss, alpha, 0.5);
        let budgeted = overhead_for_target(k, loss, alpha, 0.5);

        assert!(
            budgeted >= base * 1.99,
            "2% bad-regime loss should spend a full round-budget repair margin: base={base} budgeted={budgeted}"
        );
        assert!(
            decode_fail_probability(k, budgeted, loss) <= alpha * 1.000_001,
            "round-budgeted overhead must preserve the decode-failure target"
        );
    }

    #[test]
    fn overhead_round_budget_margin_does_not_touch_near_clean_paths() {
        let alpha = 1e-6;
        assert_eq!(
            overhead_for_target(437, CLEAN_LINK_REPAIR_OVERHEAD_DEADBAND, alpha, 0.5),
            0.0
        );
        assert_eq!(
            lossy_round_budget_multiplier(CLEAN_LINK_REPAIR_OVERHEAD_DEADBAND),
            1.0
        );
        assert_eq!(
            lossy_round_budget_multiplier(LOSSY_ROUND_BUDGET_FULL_STRENGTH_LOSS),
            LOSSY_ROUND_BUDGET_MAX_REPAIR_MULTIPLIER
        );
    }

    #[test]
    fn overhead_sanitizes_malformed_inputs_to_safe_zero() {
        assert_eq!(overhead_for_target(2048, f64::NAN, 1e-3, 0.5), 0.0);
        assert_eq!(overhead_for_target(2048, f64::INFINITY, 1e-3, 0.0), 0.0);
        assert_eq!(overhead_for_target(2048, 0.02, 1e-3, f64::NAN), 0.0);
        assert_eq!(
            overhead_for_target(2048, 0.02, f64::NAN, 0.5),
            overhead_for_target(2048, 0.02, 1e-3, 0.5)
        );
        assert_eq!(
            overhead_for_target(2048, 0.02, -1.0, 0.5),
            overhead_for_target(2048, 0.02, 1e-3, 0.5)
        );
    }

    #[test]
    fn overhead_respects_max_overhead_when_loss_model_wants_more() {
        let capped = overhead_for_target(16, 0.90, 1e-12, 0.01);
        assert_eq!(
            capped, 0.01,
            "adaptive FEC must never exceed the caller's configured overhead cap"
        );
    }

    #[test]
    fn optimal_block_is_network_bound_on_clean_fast_path() {
        // Clean path, fast CPU relative to BW ⇒ push K up (network-bound regime).
        let policy = AdaptivePolicy::default();
        let fast_cpu = PathEstimate {
            dec_symbols_per_s: 50_000_000.0, // very fast decode
            ..est(0.005, 25_000_000.0)
        };
        let plan = optimal_block(&fast_cpu, &policy, 1024);
        assert!(
            plan.k >= 2048,
            "clean fast path should pick a large block, got K={}",
            plan.k
        );
    }

    #[test]
    fn optimal_block_is_coding_bound_on_slow_cpu() {
        // Slow decode relative to BW ⇒ pull K down (coding-bound regime).
        let policy = AdaptivePolicy::default();
        let slow_cpu = PathEstimate {
            dec_symbols_per_s: 80_000.0, // slow decode
            coding_gamma: 2.0,           // strongly superlinear
            ..est(0.01, 50_000_000.0)
        };
        let plan = optimal_block(&slow_cpu, &policy, 1024);
        assert!(
            plan.k <= 1024,
            "slow CPU should pick a small block, got K={}",
            plan.k
        );
    }

    #[test]
    fn rate_matched_pacing_plan_cold_starts_on_thin_or_malformed_evidence() {
        let policy = AdaptivePolicy::default();
        let thin = PathEstimate {
            samples: 1,
            bw_median_bps: f64::INFINITY,
            rtt_s: f64::NAN,
            ..est(0.02, 50_000_000.0)
        };

        let plan = rate_matched_pacing_plan(&thin, &policy, 1200, 1_250_000.0, 0);

        assert!(plan.cold_start);
        assert_eq!(plan.raw_pacing_bits_per_s, 10_000_000);
        assert_eq!(plan.datagrams_per_s, 1041);
        assert_eq!(plan.max_burst_datagrams, 1);
        assert_eq!(plan.block.overhead, 0.0);
    }

    #[test]
    fn rate_matched_pacing_plan_cold_starts_on_negative_loss_evidence() {
        let policy = AdaptivePolicy {
            min_samples_to_activate: 1,
            arm_grid_k: vec![1024],
            arm_grid_fanout: vec![1],
            ..AdaptivePolicy::default()
        };
        let malformed_loss = PathEstimate {
            loss_p_hat: -0.05,
            loss_p_bar: -0.01,
            bw_median_bps: 100_000_000.0,
            bw_trough_bps: 75_000_000.0,
            dec_symbols_per_s: 50_000_000.0,
            samples: 16,
            ..est(0.02, 100_000_000.0)
        };

        let plan = rate_matched_pacing_plan(&malformed_loss, &policy, 1200, 1_250_000.0, 32);

        assert!(plan.cold_start);
        assert_eq!(plan.raw_pacing_bits_per_s, 10_000_000);
        assert_eq!(plan.block.overhead, 0.0);
    }

    #[test]
    fn rate_matched_pacing_plan_reports_overhead_adjusted_useful_rate() {
        let mut policy = AdaptivePolicy {
            min_samples_to_activate: 1,
            arm_grid_k: vec![1024],
            arm_grid_fanout: vec![1],
            ..AdaptivePolicy::default()
        };
        policy.max_overhead = 0.50;
        let plan =
            rate_matched_pacing_plan(&est(0.05, 12_000_000.0), &policy, 1200, 1_000_000.0, 32);

        assert!(!plan.cold_start);
        assert!(
            plan.block.overhead > 0.05,
            "expected calibrated FEC overhead"
        );
        assert!(plan.raw_pacing_bits_per_s > 0);
        let raw_bytes_per_s = plan.raw_pacing_bits_per_s as f64 / 8.0;
        assert!(
            plan.useful_pacing_bytes_per_s < raw_bytes_per_s,
            "repair overhead must lower useful rate: useful={} raw={}",
            plan.useful_pacing_bytes_per_s,
            raw_bytes_per_s
        );
        assert!(plan.datagrams_per_s > 0);
    }

    #[test]
    fn rate_matched_pacing_plan_caps_raw_rate_to_sustained_trough() {
        let policy = AdaptivePolicy {
            min_samples_to_activate: 1,
            arm_grid_k: vec![1024],
            arm_grid_fanout: vec![1],
            ..AdaptivePolicy::default()
        };
        let path = PathEstimate {
            bw_median_bps: 100_000_000.0,
            bw_trough_bps: 25_000_000.0,
            dec_symbols_per_s: 50_000_000.0,
            ..est(0.02, 100_000_000.0)
        };

        let plan = rate_matched_pacing_plan(&path, &policy, 1200, 1_000_000.0, 32);

        let raw_bytes_per_s = plan.raw_pacing_bits_per_s as f64 / 8.0;
        let sustained_capacity = path.bw_trough_bps * fanout_gain(1);
        assert!(
            raw_bytes_per_s <= sustained_capacity + 1.0,
            "raw pacing must follow sustained trough, raw={raw_bytes_per_s} cap={sustained_capacity}"
        );
        assert!(!plan.cold_start);
    }

    #[test]
    fn rate_matched_pacing_plan_uses_median_when_trough_is_malformed() {
        let policy = AdaptivePolicy {
            min_samples_to_activate: 1,
            arm_grid_k: vec![1024],
            arm_grid_fanout: vec![1],
            ..AdaptivePolicy::default()
        };
        let malformed_trough = PathEstimate {
            bw_median_bps: 40_000_000.0,
            bw_trough_bps: f64::NAN,
            dec_symbols_per_s: 50_000_000.0,
            ..est(0.02, 40_000_000.0)
        };

        let plan = rate_matched_pacing_plan(&malformed_trough, &policy, 1200, 1_000_000.0, 32);

        assert!(!plan.cold_start);
        assert!(
            plan.raw_pacing_bits_per_s as f64 / 8.0 > malformed_trough.bw_median_bps * 0.25,
            "malformed trough evidence should not collapse a valid median estimate"
        );
    }

    #[test]
    fn rate_matched_pacing_plan_keeps_clean_links_source_first() {
        let mut policy = AdaptivePolicy {
            min_samples_to_activate: 1,
            arm_grid_k: vec![1024],
            arm_grid_fanout: vec![1],
            ..AdaptivePolicy::default()
        };
        policy.max_overhead = 0.50;

        let plan = rate_matched_pacing_plan(
            &est(CLEAN_LINK_REPAIR_OVERHEAD_DEADBAND, 12_000_000.0),
            &policy,
            1200,
            1_000_000.0,
            32,
        );

        assert!(!plan.cold_start);
        assert_eq!(
            plan.block.overhead, 0.0,
            "near-clean adaptive FEC should not add round-0 repair overhead"
        );
        assert!(plan.raw_pacing_bits_per_s > 0);
        assert!(plan.datagrams_per_s > 0);
    }

    #[test]
    fn rate_matched_pacing_plan_drops_to_decode_cpu_capacity() {
        let policy = AdaptivePolicy {
            min_samples_to_activate: 1,
            arm_grid_k: vec![4096],
            arm_grid_fanout: vec![1],
            cores: 1.0,
            cpu_responsiveness_cap: 0.50,
            ..AdaptivePolicy::default()
        };
        let decode_bound = PathEstimate {
            dec_symbols_per_s: 2_000.0,
            coding_gamma: 1.0,
            ..est(0.01, 100_000_000.0)
        };

        let plan = rate_matched_pacing_plan(&decode_bound, &policy, 1000, 1_000_000.0, 16);

        assert!(!plan.cold_start);
        assert!(
            plan.useful_pacing_bytes_per_s <= 1_000_000.0,
            "CPU cap should reduce useful pacing to <= 0.5 * 2000 * 1000 B/s, got {}",
            plan.useful_pacing_bytes_per_s
        );
        assert!(
            plan.raw_pacing_bits_per_s < 100_000_000 * 8,
            "decode-bound path must not spray at full measured path rate"
        );
    }

    #[test]
    fn rate_matched_pacing_plan_respects_flow_control_credit() {
        let policy = AdaptivePolicy {
            min_samples_to_activate: 1,
            arm_grid_k: vec![1024],
            arm_grid_fanout: vec![1],
            ..AdaptivePolicy::default()
        };
        let est = PathEstimate {
            rtt_s: 0.100,
            dec_symbols_per_s: 50_000_000.0,
            ..est(0.01, 100_000_000.0)
        };
        let credit = 12_000;

        let plan =
            rate_matched_pacing_plan_with_flow_credit(&est, &policy, 1200, 8_000_000.0, 32, credit)
                .expect("non-zero credit permits a bounded pacing plan");

        let planned_one_rtt_bytes = (plan.raw_pacing_bits_per_s as f64 / 8.0) * est.rtt_s;
        assert!(
            planned_one_rtt_bytes <= credit as f64 + 1.0,
            "planned RTT inflight {planned_one_rtt_bytes} must stay within credit {credit}"
        );
        assert!(
            plan.raw_pacing_bits_per_s < 100_000_000 * 8,
            "flow credit must cap the raw high-bandwidth path rate"
        );
    }

    #[test]
    fn rate_matched_pacing_plan_flow_credit_preserves_repair_overhead_accounting() {
        let mut policy = AdaptivePolicy {
            min_samples_to_activate: 1,
            arm_grid_k: vec![1024],
            arm_grid_fanout: vec![1],
            ..AdaptivePolicy::default()
        };
        policy.max_overhead = 0.50;
        let est = PathEstimate {
            rtt_s: 0.050,
            dec_symbols_per_s: 50_000_000.0,
            ..est(0.08, 100_000_000.0)
        };

        let plan =
            rate_matched_pacing_plan_with_flow_credit(&est, &policy, 1200, 8_000_000.0, 32, 24_000)
                .expect("lossy path with receiver credit should still produce a pacing plan");

        assert!(
            plan.block.overhead > 0.0,
            "loss evidence should keep calibrated repair overhead enabled"
        );
        let raw_bytes_per_s = plan.raw_pacing_bits_per_s as f64 / 8.0;
        let overhead_factor = 1.0 + plan.block.overhead;
        assert!(
            plan.useful_pacing_bytes_per_s <= raw_bytes_per_s / overhead_factor + 1.0,
            "flow-credit capping must not forget repair overhead: useful={} raw={} overhead={}",
            plan.useful_pacing_bytes_per_s,
            raw_bytes_per_s,
            plan.block.overhead
        );
    }

    #[test]
    fn rate_matched_pacing_plan_declines_zero_or_too_small_credit() {
        let policy = AdaptivePolicy {
            min_samples_to_activate: 1,
            arm_grid_k: vec![1024],
            arm_grid_fanout: vec![1],
            ..AdaptivePolicy::default()
        };
        let mut est = est(0.01, 10_000_000.0);
        est.rtt_s = 2.0;

        assert!(
            rate_matched_pacing_plan_with_flow_credit(&est, &policy, 1200, 8_000_000.0, 32, 0)
                .is_none(),
            "zero credit means no send budget"
        );
        assert!(
            rate_matched_pacing_plan_with_flow_credit(&est, &policy, 1200, 8_000_000.0, 32, 1)
                .is_none(),
            "sub-byte-per-second credit cannot be represented safely"
        );
    }

    #[test]
    fn rate_matched_pacing_plan_credit_cap_is_replay_stable() {
        let policy = AdaptivePolicy {
            min_samples_to_activate: 1,
            arm_grid_k: vec![512, 1024, 2048],
            arm_grid_fanout: vec![1, 2],
            ..AdaptivePolicy::default()
        };
        let est = PathEstimate {
            rtt_s: 0.025,
            dec_symbols_per_s: 10_000_000.0,
            ..est(0.025, 64_000_000.0)
        };

        let first =
            rate_matched_pacing_plan_with_flow_credit(&est, &policy, 1200, 8_000_000.0, 16, 64_000);
        let replay =
            rate_matched_pacing_plan_with_flow_credit(&est, &policy, 1200, 8_000_000.0, 16, 64_000);

        assert_eq!(first, replay);
    }

    #[test]
    fn rate_matched_pacing_plan_malformed_rtt_uses_credit_safe_window() {
        let policy = AdaptivePolicy::default();
        let malformed = PathEstimate {
            samples: 0,
            rtt_s: f64::NAN,
            bw_median_bps: f64::INFINITY,
            ..est(0.02, 50_000_000.0)
        };
        let credit = 64 * 1024;

        let plan = rate_matched_pacing_plan_with_flow_credit(
            &malformed,
            &policy,
            1200,
            8_000_000.0,
            32,
            credit,
        )
        .expect("valid credit with malformed path evidence uses bounded cold start");

        assert!(plan.cold_start);
        assert!(
            plan.raw_pacing_bits_per_s <= credit * 8,
            "malformed RTT must use a conservative one-second credit window"
        );
    }

    #[test]
    fn controller_declines_until_evidence() {
        let mut c = AdaptiveController::new(AdaptivePolicy::default(), 42);
        // No estimate yet ⇒ None (fall back to fixed config).
        assert!(c.next_block_plan(1024).is_none());
        // Thin evidence ⇒ still None.
        c.update_estimate(PathEstimate {
            samples: 1,
            ..est(0.02, 10_000_000.0)
        });
        assert!(c.next_block_plan(1024).is_none());
        // Enough evidence ⇒ activates.
        c.update_estimate(est(0.02, 10_000_000.0));
        assert!(c.next_block_plan(1024).is_some());
    }

    #[test]
    fn first_active_epoch_uses_closed_form_model_plan() {
        let mut c = AdaptiveController::new(AdaptivePolicy::default(), 42);
        c.update_estimate(est(0.02, 10_000_000.0));
        let expected = c.model_plan(1024);

        let actual = c
            .next_block_plan(1024)
            .expect("enough evidence activates controller");

        assert_eq!(actual, expected);
        let snapshot = c.diagnostic_snapshot();
        assert_eq!(snapshot.epoch, 1);
        assert_eq!(snapshot.selected_plan, Some(expected));
    }

    #[test]
    fn controller_is_deterministic_given_seed() {
        let mk = || {
            let mut c = AdaptiveController::new(AdaptivePolicy::default(), 7);
            c.update_estimate(est(0.02, 10_000_000.0));
            let mut picks = Vec::new();
            for _ in 0..20 {
                let plan = c.next_block_plan(1024).unwrap();
                c.observe(
                    u64::from(plan.k),
                    u64::from(plan.k),
                    0.01,
                    u64::from(plan.k) * 1024,
                );
                picks.push(plan.k);
            }
            picks
        };
        assert_eq!(mk(), mk(), "same seed ⇒ identical decision sequence");
    }

    #[test]
    fn path_signals_are_clamped_and_smoothed() {
        let mut c = AdaptiveController::new(AdaptivePolicy::default(), 11);
        let first = c.update_path_signals(PathSignalSample {
            smoothed_rtt_s: f64::NAN,
            congestion_window_bytes: 0,
            loss_rate: f64::NAN,
        });
        assert_eq!(first.smoothed_rtt_s, MIN_PATH_RTT_S);
        assert_eq!(first.congestion_window_bytes, 1);
        assert_eq!(first.loss_rate, 0.0);

        let bounded = PathSignalSample {
            smoothed_rtt_s: f64::INFINITY,
            congestion_window_bytes: 0,
            loss_rate: f64::INFINITY,
        }
        .clamped();
        assert_eq!(bounded.smoothed_rtt_s, MAX_PATH_RTT_S);
        assert_eq!(bounded.congestion_window_bytes, 1);
        assert_eq!(bounded.loss_rate, MAX_PATH_LOSS_RATE);

        let second = c.update_path_signals(PathSignalSample {
            smoothed_rtt_s: 1.0,
            congestion_window_bytes: 1_000_000,
            loss_rate: 0.50,
        });
        assert!(
            second.smoothed_rtt_s > MIN_PATH_RTT_S && second.smoothed_rtt_s < 1.0,
            "RTT should move by EMA, not jump to the sample: {second:?}"
        );
        assert!(
            second.congestion_window_bytes > 1 && second.congestion_window_bytes < 1_000_000,
            "cwnd should move by EMA, not jump to the sample: {second:?}"
        );
        assert!(
            second.loss_rate > 0.0 && second.loss_rate < 0.50,
            "loss should move by EMA, not jump to the sample: {second:?}"
        );
    }

    #[test]
    fn path_signal_zero_useful_outcome_updates_reward() {
        let policy = AdaptivePolicy {
            arm_grid_k: vec![512, 8192],
            arm_grid_fanout: vec![1],
            exp3_eta: 0.30,
            min_samples_to_activate: 1,
            ..AdaptivePolicy::default()
        };
        let mut c = AdaptiveController::new(policy, 31);
        c.update_estimate(PathEstimate {
            samples: 8,
            dec_symbols_per_s: 50_000_000.0,
            ..est(0.02, 20_000_000.0)
        });

        let plan = c.next_block_plan(1024).expect("controller activates");
        let before = c.diagnostic_snapshot();
        let arm = before
            .selected_arm_index
            .expect("next_block_plan records selected arm");
        let before_weight = before.weights[arm];
        assert!(before.path_signals.is_none());

        c.observe_path_signals(
            u64::from(plan.k),
            0,
            0.050,
            0,
            1024,
            PathSignalSample {
                smoothed_rtt_s: 0.050,
                congestion_window_bytes: 512 * 1024,
                loss_rate: 0.75,
            },
        );

        let after = c.diagnostic_snapshot();
        assert!(
            after.path_signals.is_some(),
            "sent-but-zero-useful outcomes must still record path signals"
        );
        assert!(
            after.weights[arm] < before_weight,
            "sent-but-zero-useful outcomes must penalize the played arm: before={} after={}",
            before_weight,
            after.weights[arm]
        );
        assert!(
            c.loss_scale > 0.0,
            "zero-useful feedback must enter the EXP3 loss normalizer"
        );
    }

    #[test]
    fn path_signal_reward_shifts_arm_under_loss_and_small_cwnd() {
        fn train(signals: PathSignalSample) -> usize {
            let mut policy = AdaptivePolicy {
                arm_grid_k: vec![512, 8192],
                arm_grid_fanout: vec![1],
                exp3_eta: 0.30,
                min_samples_to_activate: 1,
                ..AdaptivePolicy::default()
            };
            policy.max_overhead = 0.50;

            let mut c = AdaptiveController::new(policy, 23);
            c.update_estimate(PathEstimate {
                samples: 8,
                dec_symbols_per_s: 50_000_000.0,
                ..est(0.02, 20_000_000.0)
            });
            let mut large_selected_late = 0usize;
            let trials = 700usize;
            for t in 0..trials {
                let plan = c.next_block_plan(1024).expect("controller activates");
                if t >= trials - 200 && plan.k == 8192 {
                    large_selected_late += 1;
                }
                let wall_s = if plan.k == 8192 { 0.004 } else { 0.006 };
                c.observe_path_signals(
                    u64::from(plan.k),
                    u64::from(plan.k),
                    wall_s,
                    u64::from(plan.k) * 1024,
                    1024,
                    signals,
                );
            }
            large_selected_late
        }

        let clean_large = train(PathSignalSample {
            smoothed_rtt_s: 0.010,
            congestion_window_bytes: 64 * 1024 * 1024,
            loss_rate: 0.001,
        });
        let lossy_large = train(PathSignalSample {
            smoothed_rtt_s: 0.050,
            congestion_window_bytes: 512 * 1024,
            loss_rate: 0.25,
        });

        assert!(
            clean_large > 140,
            "clean/high-cwnd path should learn the large arm, got {clean_large}/200"
        );
        assert!(
            lossy_large < 80,
            "lossy/small-cwnd path should shift away from the large arm, got {lossy_large}/200"
        );
    }

    #[test]
    fn exp3_concentrates_on_the_cheap_arm() {
        // Synthetic: one K is always cheaper. The EXP3 loss is seconds-per-useful
        // -byte, so to isolate the arm signal we hold useful_bytes CONSTANT across
        // arms (otherwise larger K trivially amortizes wall time). EXP3 should
        // then raise the cheap arm's selection share well above uniform.
        let mut policy = AdaptivePolicy::default();
        policy.arm_grid_fanout = vec![4]; // collapse fanout so arms == K grid (6 arms)
        policy.exp3_eta = 0.25;
        let cheap_k = 2048u32;
        let mut c = AdaptiveController::new(policy, 99);
        c.update_estimate(est(0.02, 10_000_000.0));
        let mut cheap_selected = 0;
        let trials = 1200;
        const USEFUL: u64 = 1_000_000; // constant across arms
        for t in 0..trials {
            let plan = c.next_block_plan(1024).unwrap();
            // Cheap arm: low wall; all others: 10x wall. Loss ∝ wall now.
            let wall = if plan.k == cheap_k { 0.005 } else { 0.05 };
            if t >= trials - 200 && plan.k == cheap_k {
                cheap_selected += 1;
            }
            c.observe(u64::from(plan.k), u64::from(plan.k), wall, USEFUL);
        }
        // In the last 200 rounds the cheap arm should dominate (uniform share is
        // 200/6 ≈ 33; concentration should push it well past that).
        assert!(
            cheap_selected > 80,
            "EXP3 should concentrate on the cheap arm, got {cheap_selected}/200"
        );
    }
}
