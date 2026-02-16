#[cfg(test)]
mod tests {
    use asupersync::supervision::{RestartStormMonitor, StormMonitorConfig};

    #[test]
    fn storm_monitor_custom_tolerance() {
        // Configure monitor: expected rate 1.0, alpha 0.01, tolerance 1.1 (10%)
        let mut monitor = RestartStormMonitor::new(StormMonitorConfig {
            alpha: 0.01,
            expected_rate: 1.0,
            min_observations: 1,
            tolerance: 1.1,
        });

        // Feed intensity 1.2 (20% overload) persistently
        for _ in 0..10 {
            monitor.observe_intensity(1.2);
        }

        // New implementation:
        // ratio = 1.2
        // normalizer = 1.1
        // lr = 1.2 / 1.1 ≈ 1.09
        // e_value should INCREASE

        println!("Final e-value: {}", monitor.e_value());

        // Assert that evidence grew
        assert!(
            monitor.e_value() > 1.0,
            "Evidence should grow for 20% overload with 10% tolerance"
        );
    }
}
