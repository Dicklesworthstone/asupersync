//! Configuration and conditions for deterministic network simulation.

use crate::util::DetRng;
use std::time::Duration;

/// Configuration for the simulated network.
#[derive(Clone, Debug)]
pub struct NetworkConfig {
    /// Random seed for deterministic simulation.
    pub seed: u64,
    /// Default network conditions between hosts.
    pub default_conditions: NetworkConditions,
    /// Whether to capture trace events.
    pub capture_trace: bool,
    /// Maximum queued packets across the network.
    pub max_queue_depth: usize,
    /// Simulation tick resolution.
    pub tick_resolution: Duration,
    /// Enable bandwidth simulation.
    pub enable_bandwidth: bool,
    /// Default bandwidth per link (bytes/second) when bandwidth simulation is enabled
    /// and a link does not provide an explicit bandwidth.
    pub default_bandwidth: u64,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            seed: 0x4E45_5457,
            default_conditions: NetworkConditions::ideal(),
            capture_trace: false,
            max_queue_depth: 10_000,
            tick_resolution: Duration::from_micros(100),
            enable_bandwidth: false,
            default_bandwidth: 1_000_000_000,
        }
    }
}

/// Network conditions between two hosts.
#[derive(Clone, Debug)]
pub struct NetworkConditions {
    /// Latency model for this link.
    pub latency: LatencyModel,
    /// Packet loss probability (0.0 - 1.0).
    pub packet_loss: f64,
    /// Packet corruption probability (0.0 - 1.0).
    pub packet_corrupt: f64,
    /// Packet duplication probability (0.0 - 1.0).
    pub packet_duplicate: f64,
    /// Packet reordering probability (0.0 - 1.0).
    pub packet_reorder: f64,
    /// Maximum packets in flight.
    pub max_in_flight: usize,
    /// Bandwidth limit (bytes/second).
    ///
    /// When bandwidth simulation is enabled:
    /// - `None` uses `NetworkConfig::default_bandwidth`
    /// - `Some(0)` disables bandwidth limiting for this link
    pub bandwidth: Option<u64>,
    /// Jitter model for variable latency.
    pub jitter: Option<JitterModel>,
}

impl NetworkConditions {
    /// Perfect network - no latency, loss, or corruption.
    #[must_use]
    pub fn ideal() -> Self {
        Self {
            latency: LatencyModel::Fixed(Duration::ZERO),
            packet_loss: 0.0,
            packet_corrupt: 0.0,
            packet_duplicate: 0.0,
            packet_reorder: 0.0,
            max_in_flight: usize::MAX,
            bandwidth: None,
            jitter: None,
        }
    }

    /// Local network - 1ms latency.
    #[must_use]
    pub fn local() -> Self {
        Self {
            latency: LatencyModel::Fixed(Duration::from_millis(1)),
            ..Self::ideal()
        }
    }

    /// LAN - 1-5ms latency, very low loss.
    #[must_use]
    pub fn lan() -> Self {
        Self {
            latency: LatencyModel::Uniform {
                min: Duration::from_millis(1),
                max: Duration::from_millis(5),
            },
            packet_loss: 0.0001,
            bandwidth: Some(1_000_000_000),
            ..Self::ideal()
        }
    }

    /// WAN - 20-100ms latency, low loss.
    #[must_use]
    pub fn wan() -> Self {
        Self {
            latency: LatencyModel::Normal {
                mean: Duration::from_millis(50),
                std_dev: Duration::from_millis(20),
            },
            packet_loss: 0.001,
            packet_reorder: 0.001,
            bandwidth: Some(100_000_000),
            jitter: Some(JitterModel::Uniform {
                max: Duration::from_millis(10),
            }),
            ..Self::ideal()
        }
    }

    /// Lossy - high packet loss (10%).
    #[must_use]
    pub fn lossy() -> Self {
        Self {
            packet_loss: 0.1,
            ..Self::lan()
        }
    }

    /// Satellite - high latency, moderate loss.
    #[must_use]
    pub fn satellite() -> Self {
        Self {
            latency: LatencyModel::Normal {
                mean: Duration::from_millis(600),
                std_dev: Duration::from_millis(50),
            },
            packet_loss: 0.01,
            bandwidth: Some(10_000_000),
            ..Self::ideal()
        }
    }

    /// Congested network.
    #[must_use]
    pub fn congested() -> Self {
        Self {
            latency: LatencyModel::Normal {
                mean: Duration::from_millis(100),
                std_dev: Duration::from_millis(50),
            },
            packet_loss: 0.05,
            packet_reorder: 0.02,
            bandwidth: Some(1_000_000),
            max_in_flight: 100,
            jitter: Some(JitterModel::Bursty {
                normal_jitter: Duration::from_millis(5),
                burst_jitter: Duration::from_millis(100),
                burst_probability: 0.1,
            }),
            ..Self::ideal()
        }
    }
}

/// Model for latency distribution.
#[derive(Clone, Debug)]
pub enum LatencyModel {
    /// Fixed latency.
    Fixed(Duration),
    /// Uniform distribution between min and max.
    Uniform {
        /// Minimum latency for the range.
        min: Duration,
        /// Maximum latency for the range.
        max: Duration,
    },
    /// Normal (Gaussian) distribution.
    Normal {
        /// Mean latency.
        mean: Duration,
        /// Standard deviation of latency.
        std_dev: Duration,
    },
    /// Log-normal distribution (common in real networks).
    LogNormal {
        /// Mean of the underlying normal distribution.
        mu: f64,
        /// Std dev of the underlying normal distribution.
        sigma: f64,
    },
    /// Bimodal - two peaks (models route switching).
    Bimodal {
        /// Low-latency mode.
        low: Duration,
        /// High-latency mode.
        high: Duration,
        /// Probability of sampling the high-latency mode.
        high_probability: f64,
    },
}

impl LatencyModel {
    /// Sample latency using the given RNG.
    #[must_use]
    pub fn sample(&self, rng: &mut DetRng) -> Duration {
        match self {
            Self::Fixed(d) => *d,
            Self::Uniform { min, max } => {
                if min >= max {
                    return *min;
                }
                let range = max.as_nanos().saturating_sub(min.as_nanos());
                let offset = u128::from(rng.next_u64()) % (range + 1);
                Duration::from_nanos((min.as_nanos() + offset) as u64)
            }
            Self::Normal { mean, std_dev } => {
                let z = sample_standard_normal(rng);
                let sample = std_dev.as_secs_f64().mul_add(z, mean.as_secs_f64());
                duration_from_secs_f64(sample)
            }
            Self::LogNormal { mu, sigma } => {
                let z = sample_standard_normal(rng);
                let sample = sigma.mul_add(z, *mu).exp();
                duration_from_secs_f64(sample)
            }
            Self::Bimodal {
                low,
                high,
                high_probability,
            } => {
                let p = next_unit_f64(rng);
                if p < high_probability.clamp(0.0, 1.0) {
                    *high
                } else {
                    *low
                }
            }
        }
    }
}

/// Jitter model for variable latency.
#[derive(Clone, Debug)]
pub enum JitterModel {
    /// Uniform jitter in [0, max].
    Uniform {
        /// Maximum jitter to apply.
        max: Duration,
    },
    /// Bursty jitter with rare large spikes.
    Bursty {
        /// Typical jitter range.
        normal_jitter: Duration,
        /// Burst jitter range.
        burst_jitter: Duration,
        /// Probability of applying a burst jitter.
        burst_probability: f64,
    },
}

impl JitterModel {
    /// Sample jitter using the given RNG.
    #[must_use]
    pub fn sample(&self, rng: &mut DetRng) -> Duration {
        match self {
            Self::Uniform { max } => {
                if max.is_zero() {
                    return Duration::ZERO;
                }
                let nanos = max.as_nanos();
                let offset = u128::from(rng.next_u64()) % (nanos + 1);
                Duration::from_nanos(offset as u64)
            }
            Self::Bursty {
                normal_jitter,
                burst_jitter,
                burst_probability,
            } => {
                let p = next_unit_f64(rng);
                let range = if p < burst_probability.clamp(0.0, 1.0) {
                    *burst_jitter
                } else {
                    *normal_jitter
                };
                if range.is_zero() {
                    Duration::ZERO
                } else {
                    let nanos = range.as_nanos();
                    let offset = u128::from(rng.next_u64()) % (nanos + 1);
                    Duration::from_nanos(offset as u64)
                }
            }
        }
    }
}

#[allow(clippy::cast_precision_loss)]
fn next_unit_f64(rng: &mut DetRng) -> f64 {
    let raw = rng.next_u64() >> 11;
    let mut v = raw as f64 / (1u64 << 53) as f64;
    if v <= 0.0 {
        v = f64::MIN_POSITIVE;
    }
    v
}

fn sample_standard_normal(rng: &mut DetRng) -> f64 {
    let u1 = next_unit_f64(rng);
    let u2 = next_unit_f64(rng);
    let r = (-2.0 * u1.ln()).sqrt();
    let theta = 2.0 * std::f64::consts::PI * u2;
    r * theta.cos()
}

#[allow(clippy::cast_precision_loss)]
fn duration_from_secs_f64(secs: f64) -> Duration {
    if !secs.is_finite() || secs <= 0.0 {
        return Duration::ZERO;
    }
    let max_secs = (u64::MAX as f64) / 1_000_000_000.0;
    let clamped = secs.min(max_secs);
    Duration::from_secs_f64(clamped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latency_models_are_deterministic() {
        let mut rng1 = DetRng::new(42);
        let mut rng2 = DetRng::new(42);
        let model = LatencyModel::Uniform {
            min: Duration::from_millis(1),
            max: Duration::from_millis(5),
        };
        for _ in 0..100 {
            assert_eq!(model.sample(&mut rng1), model.sample(&mut rng2));
        }
    }

    #[test]
    fn latency_models_constant_cases() {
        let mut rng = DetRng::new(7);
        let fixed = LatencyModel::Fixed(Duration::from_millis(5));
        assert_eq!(fixed.sample(&mut rng), Duration::from_millis(5));

        let uniform = LatencyModel::Uniform {
            min: Duration::from_millis(3),
            max: Duration::from_millis(3),
        };
        assert_eq!(uniform.sample(&mut rng), Duration::from_millis(3));

        let normal = LatencyModel::Normal {
            mean: Duration::from_millis(12),
            std_dev: Duration::ZERO,
        };
        assert_eq!(normal.sample(&mut rng), Duration::from_millis(12));

        let log_normal = LatencyModel::LogNormal {
            mu: 0.0,
            sigma: 0.0,
        };
        assert_eq!(log_normal.sample(&mut rng), duration_from_secs_f64(1.0));

        let bimodal_low = LatencyModel::Bimodal {
            low: Duration::from_millis(4),
            high: Duration::from_millis(9),
            high_probability: 0.0,
        };
        assert_eq!(bimodal_low.sample(&mut rng), Duration::from_millis(4));

        let bimodal_high = LatencyModel::Bimodal {
            low: Duration::from_millis(4),
            high: Duration::from_millis(9),
            high_probability: 1.0,
        };
        assert_eq!(bimodal_high.sample(&mut rng), Duration::from_millis(9));
    }

    // ========================================================================
    // Pure data-type tests (wave 10 – CyanBarn)
    // ========================================================================

    #[test]
    fn network_config_default() {
        let config = NetworkConfig::default();
        assert_eq!(config.seed, 0x4E45_5457);
        assert!(!config.capture_trace);
        assert_eq!(config.max_queue_depth, 10_000);
        assert_eq!(config.tick_resolution, Duration::from_micros(100));
        assert!(!config.enable_bandwidth);
        assert_eq!(config.default_bandwidth, 1_000_000_000);
    }

    #[test]
    fn network_config_debug_clone() {
        let config = NetworkConfig::default();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("NetworkConfig"), "{dbg}");
        let cloned = config;
        assert_eq!(cloned.seed, 0x4E45_5457);
    }

    #[test]
    fn network_conditions_ideal() {
        let c = NetworkConditions::ideal();
        assert!(
            (c.packet_loss).abs() < f64::EPSILON,
            "expected 0.0, got {}",
            c.packet_loss
        );
        assert!(
            (c.packet_corrupt).abs() < f64::EPSILON,
            "expected 0.0, got {}",
            c.packet_corrupt
        );
        assert!(
            (c.packet_duplicate).abs() < f64::EPSILON,
            "expected 0.0, got {}",
            c.packet_duplicate
        );
        assert!(
            (c.packet_reorder).abs() < f64::EPSILON,
            "expected 0.0, got {}",
            c.packet_reorder
        );
        assert_eq!(c.max_in_flight, usize::MAX);
        assert!(c.bandwidth.is_none());
        assert!(c.jitter.is_none());
        assert!(matches!(c.latency, LatencyModel::Fixed(d) if d == Duration::ZERO));
    }

    #[test]
    fn network_conditions_local() {
        let c = NetworkConditions::local();
        assert!(matches!(c.latency, LatencyModel::Fixed(d) if d == Duration::from_millis(1)));
        assert!(
            (c.packet_loss).abs() < f64::EPSILON,
            "expected 0.0, got {}",
            c.packet_loss
        );
    }

    #[test]
    fn network_conditions_lan() {
        let c = NetworkConditions::lan();
        assert!(matches!(c.latency, LatencyModel::Uniform { .. }));
        assert!(c.packet_loss > 0.0);
        assert_eq!(c.bandwidth, Some(1_000_000_000));
    }

    #[test]
    fn network_conditions_wan() {
        let c = NetworkConditions::wan();
        assert!(matches!(c.latency, LatencyModel::Normal { .. }));
        assert!(c.packet_loss > 0.0);
        assert!(c.packet_reorder > 0.0);
        assert_eq!(c.bandwidth, Some(100_000_000));
        assert!(c.jitter.is_some());
    }

    #[test]
    fn network_conditions_lossy() {
        let c = NetworkConditions::lossy();
        assert!((c.packet_loss - 0.1).abs() < f64::EPSILON);
    }

    #[test]
    fn network_conditions_satellite() {
        let c = NetworkConditions::satellite();
        assert!(
            matches!(c.latency, LatencyModel::Normal { mean, .. } if mean > Duration::from_millis(500))
        );
        assert!(c.packet_loss > 0.0);
        assert_eq!(c.bandwidth, Some(10_000_000));
    }

    #[test]
    fn network_conditions_congested() {
        let c = NetworkConditions::congested();
        assert!(c.packet_loss > 0.01);
        assert!(c.packet_reorder > 0.0);
        assert_eq!(c.max_in_flight, 100);
        assert!(matches!(c.jitter, Some(JitterModel::Bursty { .. })));
    }

    #[test]
    fn network_conditions_debug_clone() {
        let c = NetworkConditions::wan();
        let dbg = format!("{c:?}");
        assert!(dbg.contains("NetworkConditions"), "{dbg}");
        let cloned = c.clone();
        assert!((cloned.packet_loss - c.packet_loss).abs() < f64::EPSILON);
    }

    #[test]
    fn latency_model_debug_clone() {
        let fixed = LatencyModel::Fixed(Duration::from_millis(5));
        let dbg = format!("{fixed:?}");
        assert!(dbg.contains("Fixed"), "{dbg}");
        let cloned = fixed.clone();
        let mut rng1 = DetRng::new(1);
        let mut rng2 = DetRng::new(1);
        assert_eq!(cloned.sample(&mut rng1), fixed.sample(&mut rng2));
    }

    #[test]
    fn latency_model_log_normal_produces_positive() {
        let model = LatencyModel::LogNormal {
            mu: -2.0,
            sigma: 0.5,
        };
        let mut rng = DetRng::new(123);
        for _ in 0..50 {
            let sample = model.sample(&mut rng);
            assert!(sample >= Duration::ZERO);
        }
    }

    #[test]
    fn latency_model_uniform_min_exceeds_max() {
        let model = LatencyModel::Uniform {
            min: Duration::from_millis(10),
            max: Duration::from_millis(5),
        };
        let mut rng = DetRng::new(7);
        // When min >= max, returns min
        assert_eq!(model.sample(&mut rng), Duration::from_millis(10));
    }

    #[test]
    fn jitter_model_debug_clone() {
        let uniform = JitterModel::Uniform {
            max: Duration::from_millis(5),
        };
        let cloned = uniform.clone();
        let dbg = format!("{uniform:?}");
        assert!(dbg.contains("Uniform"), "{dbg}");
        assert!(format!("{cloned:?}").contains("Uniform"));
    }

    #[test]
    fn jitter_model_uniform_zero_max() {
        let model = JitterModel::Uniform {
            max: Duration::ZERO,
        };
        let mut rng = DetRng::new(42);
        assert_eq!(model.sample(&mut rng), Duration::ZERO);
    }

    #[test]
    fn jitter_model_bursty_zero_ranges() {
        let model = JitterModel::Bursty {
            normal_jitter: Duration::ZERO,
            burst_jitter: Duration::ZERO,
            burst_probability: 0.5,
        };
        let mut rng = DetRng::new(99);
        for _ in 0..20 {
            assert_eq!(model.sample(&mut rng), Duration::ZERO);
        }
    }

    #[test]
    fn duration_from_secs_f64_negative() {
        assert_eq!(duration_from_secs_f64(-1.0), Duration::ZERO);
    }

    #[test]
    fn duration_from_secs_f64_nan() {
        assert_eq!(duration_from_secs_f64(f64::NAN), Duration::ZERO);
    }

    #[test]
    fn duration_from_secs_f64_infinity() {
        assert_eq!(duration_from_secs_f64(f64::INFINITY), Duration::ZERO);
    }

    #[test]
    fn duration_from_secs_f64_valid() {
        let d = duration_from_secs_f64(0.001);
        assert_eq!(d, Duration::from_millis(1));
    }

    #[test]
    fn jitter_models_respect_bounds() {
        let mut rng = DetRng::new(99);
        let uniform = JitterModel::Uniform {
            max: Duration::from_millis(6),
        };
        for _ in 0..100 {
            assert!(uniform.sample(&mut rng) <= Duration::from_millis(6));
        }

        let bursty_normal = JitterModel::Bursty {
            normal_jitter: Duration::from_millis(2),
            burst_jitter: Duration::from_millis(10),
            burst_probability: 0.0,
        };
        for _ in 0..100 {
            assert!(bursty_normal.sample(&mut rng) <= Duration::from_millis(2));
        }

        let bursty_burst = JitterModel::Bursty {
            normal_jitter: Duration::from_millis(2),
            burst_jitter: Duration::from_millis(10),
            burst_probability: 1.0,
        };
        for _ in 0..100 {
            assert!(bursty_burst.sample(&mut rng) <= Duration::from_millis(10));
        }
    }
}
