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
    /// Default bandwidth per link (bytes/second).
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
    /// Packet reordering probability (0.0 - 1.0).
    pub packet_reorder: f64,
    /// Maximum packets in flight.
    pub max_in_flight: usize,
    /// Bandwidth limit (bytes/second), None = unlimited.
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
