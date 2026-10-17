    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::runtime::rch_health::{
        RchArtifactRetrievalReliability, RchCacheWarmthHint, RchProofLaneRequest, RchProofPriority,
        RchQueueState, RchTargetDirClass, RchWorkerAdmissionPolicy, RchWorkerDiskPressure,
        RchWorkerSnapshot, admit_rch_worker,
    };
    use crate::sync::LockMetricsSnapshot;
    use crate::sync::lock_ordering::{
        LockModule, LockOrderAtlasSnapshot, LockOrderEdge, LockOrderViolation, LockRank,
    };
    use serde_json::{Value, json};
    use std::collections::hash_map::DefaultHasher;
    use std::fs;
    use std::hash::{Hash, Hasher};
    use std::path::Path;

    /// The load average is host-wide, so it is divided by the host's online
    /// CPUs, read from the kernel's CPU list (asupersync-1ir2em review).
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn host_online_cpus_counts_the_kernel_cpu_list() {
        assert_eq!(platform::cpu_list_len("0"), Some(1));
        assert_eq!(platform::cpu_list_len("0-31"), Some(32));
        assert_eq!(platform::cpu_list_len("0-3,8,10-11"), Some(7));
        assert_eq!(platform::cpu_list_len(""), None);
        assert_eq!(platform::cpu_list_len("3-1"), None);
        assert_eq!(platform::cpu_list_len("0-x"), None);
        assert!(platform::host_online_cpus() >= 1);
    }

    #[test]
    fn test_resource_measurement_ratios() {
        let measurement = ResourceMeasurement::new(750, 800, 900, 1000);

        assert_eq!(measurement.usage_ratio(), 0.75);
        assert!(!measurement.is_soft_exceeded());
        assert!(!measurement.is_hard_exceeded());
        assert!(!measurement.is_critical());
    }

    #[test]
    fn test_degradation_level_conversion() {
        assert_eq!(DegradationLevel::None.to_headroom(), 1.0);
        assert_eq!(DegradationLevel::Emergency.to_headroom(), 0.0);
        assert_eq!(DegradationLevel::from_headroom(0.9), DegradationLevel::None);
        assert_eq!(
            DegradationLevel::from_headroom(0.1),
            DegradationLevel::Emergency
        );
    }

    #[test]
    fn test_trigger_config_degradation_calculation() {
        let config = TriggerConfig::default_for_resource(&ResourceType::Memory);
        let measurement = ResourceMeasurement::new(800, 700, 850, 1000); // 80% usage

        let level = config.calculate_degradation(&measurement);
        assert_eq!(level, DegradationLevel::Moderate);
    }

    #[test]
    fn test_resource_pressure_updates() {
        let pressure = ResourcePressure::new();
        let measurement = ResourceMeasurement::new(500, 700, 850, 1000);

        pressure.update_measurement(ResourceType::Memory, measurement.clone());

        let retrieved = pressure.get_measurement(&ResourceType::Memory).unwrap();
        assert_eq!(retrieved.current, measurement.current);
    }

    #[test]
    fn test_resource_pressure_system_pressure_matches_degradation_band() {
        let pressure = ResourcePressure::new();
        let system_pressure = pressure.system_pressure();

        pressure.update_degradation_level(ResourceType::Memory, DegradationLevel::None);
        assert!((system_pressure.headroom() - 1.0).abs() < f32::EPSILON);
        assert_eq!(system_pressure.degradation_level(), 0);
        assert_eq!(system_pressure.level_label(), "normal");

        pressure.update_degradation_level(ResourceType::Memory, DegradationLevel::Light);
        assert!((system_pressure.headroom() - 0.75).abs() < f32::EPSILON);
        assert_eq!(system_pressure.degradation_level(), 1);
        assert_eq!(system_pressure.level_label(), "light");

        pressure.update_degradation_level(ResourceType::Memory, DegradationLevel::Moderate);
        assert!((system_pressure.headroom() - 0.5).abs() < f32::EPSILON);
        assert_eq!(system_pressure.degradation_level(), 2);
        assert_eq!(system_pressure.level_label(), "moderate");

        pressure.update_degradation_level(ResourceType::Memory, DegradationLevel::Heavy);
        assert!((system_pressure.headroom() - 0.25).abs() < f32::EPSILON);
        assert_eq!(system_pressure.degradation_level(), 3);
        assert_eq!(system_pressure.level_label(), "heavy");

        pressure.update_degradation_level(ResourceType::Memory, DegradationLevel::Emergency);
        assert!(system_pressure.headroom().abs() < f32::EPSILON);
        assert_eq!(system_pressure.degradation_level(), 4);
        assert_eq!(system_pressure.level_label(), "emergency");
    }

    #[test]
    fn test_degradation_engine_policies() {
        let pressure = Arc::new(ResourcePressure::new());
        let engine = DegradationEngine::new(Arc::clone(&pressure));

        let policy = DegradationPolicy {
            resource_type: ResourceType::Memory,
            trigger_level: DegradationLevel::Moderate,
            action: PolicyAction::RejectNewWork(RegionPriority::Low),
        };

        engine.add_policy(policy);

        // Test region shedding decisions
        let region_id = RegionId::new_ephemeral();
        engine.set_region_priority(region_id, RegionPriority::Low);

        pressure.update_degradation_level(ResourceType::Memory, DegradationLevel::Heavy);

        let decision = engine.should_shed_region(region_id);
        assert!(matches!(decision, SheddingDecision::Pause));
    }

    #[test]
    fn test_degradation_engine_monitors_task_pressure_by_default() {
        let pressure = Arc::new(ResourcePressure::new());
        let engine = DegradationEngine::new(Arc::clone(&pressure));

        pressure.update_measurement(
            ResourceType::Task,
            ResourceMeasurement::new(960, 800, 950, 1000),
        );

        let changes = engine
            .process_measurements()
            .expect("task pressure should process");
        assert_eq!(
            changes,
            vec![(ResourceType::Task, DegradationLevel::Emergency)]
        );
        assert_eq!(
            pressure.get_degradation_level(&ResourceType::Task),
            DegradationLevel::Emergency
        );
    }

    #[test]
    fn test_cycle_overhead_percentage_uses_configured_interval() {
        let overhead =
            cycle_overhead_percentage(Duration::from_millis(25), Duration::from_millis(100));
        assert!((overhead - 25.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_cycle_overhead_percentage_handles_zero_interval() {
        assert_eq!(
            cycle_overhead_percentage(Duration::from_millis(25), Duration::ZERO),
            0.0
        );
    }

    #[test]
    fn m4oxsk_supported_probe_reporting_records_sampled_value() {
        let state = ResourceProbeState::new("test-linux/x86_64");

        state.record_supported(ResourceProbe::ProcessRssBytes, Some(4096));

        let report = state.report();
        assert_eq!(report.supported_count, 1);
        assert_eq!(report.unavailable_count, 0);
        assert_eq!(report.fallback_count, 0);
        assert_eq!(
            report.operator_verdict,
            ResourceProbeOperatorVerdict::Complete
        );
        assert_eq!(report.probes[0].sampled_value, Some(4096));
        assert_eq!(report.probes[0].resource_type, ResourceType::Memory);
    }

    #[test]
    fn m4oxsk_unsupported_probe_reporting_is_typed() {
        let state = ResourceProbeState::new("test-unsupported/wasm32");
        let error = std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "unavailable on test platform",
        );

        state.record_probe_failure(
            ResourceProbe::ProcessFdCount,
            ResourceProbeFallback::OmitMeasurement,
            &error,
        );

        let report = state.report();
        let probe = &report.probes[0];
        assert_eq!(report.unavailable_count, 1);
        assert_eq!(report.warning_emitted_count, 1);
        assert_eq!(
            report.operator_verdict,
            ResourceProbeOperatorVerdict::DegradedWithUnavailableProbes
        );
        assert_eq!(probe.status, ResourceProbeStatus::Unavailable);
        assert_eq!(
            probe.fallback,
            ResourceProbeFallback::CustomCollectorRequired
        );
        assert_eq!(probe.probe, ResourceProbe::ProcessFdCount);
        assert!(probe.error_message.as_deref().unwrap().contains("test"));
    }

    #[test]
    fn m4oxsk_fallback_aggregation_preserves_operator_semantics() {
        let state = ResourceProbeState::new("test-bsd/aarch64");
        let error = std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "fd rlimit inaccessible",
        );

        state.record_probe_failure(
            ResourceProbe::NetworkConnectionLimit,
            ResourceProbeFallback::ConservativeDefault,
            &error,
        );

        let report = state.report();
        assert_eq!(report.fallback_count, 1);
        assert_eq!(report.unavailable_count, 0);
        assert_eq!(
            report.operator_verdict,
            ResourceProbeOperatorVerdict::DegradedWithFallbacks
        );
        assert_eq!(report.probes[0].status, ResourceProbeStatus::Fallback);
        assert_eq!(
            report.probes[0].fallback,
            ResourceProbeFallback::ConservativeDefault
        );
    }

    #[test]
    fn m4oxsk_warning_throttling_suppresses_repeated_probe_failures() {
        let state = ResourceProbeState::new("test-linux/x86_64");

        for attempt in 0..9 {
            let error = std::io::Error::other(format!("transient probe failure {attempt}"));
            state.record_probe_failure(
                ResourceProbe::LoadAvg1MinScaled,
                ResourceProbeFallback::OmitMeasurement,
                &error,
            );
        }

        let report = state.report();
        assert_eq!(report.warning_emitted_count, 2);
        assert_eq!(report.warning_suppressed_count, 7);
        assert_eq!(report.probes[0].warning_count, 9);
        assert_eq!(report.probes[0].warning_suppressed_count, 7);
    }

    #[test]
    fn m4oxsk_unavailable_probe_report_serializes_operator_fields() {
        let state = ResourceProbeState::new("test-windows/x86_64");
        let error =
            std::io::Error::new(std::io::ErrorKind::Unsupported, "load average unavailable");

        state.record_probe_failure(
            ResourceProbe::LoadAvg1MinScaled,
            ResourceProbeFallback::OmitMeasurement,
            &error,
        );

        let report = state.report();
        let json = serde_json::to_string_pretty(&report).expect("serialize report");
        let value: Value = serde_json::from_str(&json).expect("parse report json");

        assert_eq!(
            value["schema_version"],
            RESOURCE_MONITOR_PLATFORM_GAP_REPORT_SCHEMA_VERSION
        );
        assert_eq!(value["probes"][0]["probe"], "load_avg_1min_scaled");
        assert_eq!(value["probes"][0]["status"], "unavailable");
        assert_eq!(value["probes"][0]["fallback"], "custom_collector_required");
        assert_eq!(
            value["operator_verdict"],
            "degraded_with_unavailable_probes"
        );
    }

    #[test]
    fn m4oxsk_disabled_monitor_probe_report_is_explicit() {
        let state = ResourceProbeState::new("test-disabled/noarch");

        state.record_disabled(ResourceProbe::ProcessRssBytes);
        state.record_disabled(ResourceProbe::LoadAvg1MinScaled);

        let report = state.report();
        assert_eq!(report.disabled_count, 2);
        assert_eq!(report.warning_emitted_count, 0);
        assert_eq!(report.warning_suppressed_count, 0);
        assert_eq!(
            report.operator_verdict,
            ResourceProbeOperatorVerdict::Disabled
        );
        assert!(report.probes.iter().all(|probe| {
            probe.status == ResourceProbeStatus::Disabled
                && probe.fallback == ResourceProbeFallback::MonitorDisabled
        }));
    }

    #[test]
    fn m4oxsk_status_report_carries_platform_probe_inventory() {
        let monitor = ResourceMonitor::new(MonitorConfig::default());

        let status = monitor.status_report();

        assert!(!status.is_active);
        assert_eq!(
            status.platform_probe_report.schema_version,
            RESOURCE_MONITOR_PLATFORM_GAP_REPORT_SCHEMA_VERSION
        );
        assert_eq!(
            status.platform_probe_report.platform,
            current_platform_fingerprint()
        );
    }

    #[test]
    fn rz7cpt_system_resource_collector_active_flag_tracks_lifecycle() {
        let pressure = Arc::new(ResourcePressure::new());
        let collector = SystemResourceCollector::new(pressure, Duration::from_millis(50));

        assert!(!collector.is_active());
        collector.start().expect("collector should start once");
        assert!(collector.is_active());
        assert!(matches!(
            collector.start(),
            Err(ResourceMonitorError::AlreadyActive)
        ));
        assert!(collector.is_active());

        collector.stop();
        assert!(!collector.is_active());
        collector
            .start()
            .expect("collector should restart after stop");
        assert!(collector.is_active());
        collector.stop();
    }

    #[test]
    fn m4oxsk_resource_monitor_platform_gap_smoke_emits_operator_report() {
        let state = ResourceProbeState::new("host-template/linux-or-fallback");
        let unsupported = std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "template host lacks process fd probe",
        );
        let fallback = std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "template host hides connection limit",
        );

        state.record_supported(ResourceProbe::ProcessRssBytes, Some(12_288));
        state.record_probe_failure(
            ResourceProbe::ProcessFdCount,
            ResourceProbeFallback::OmitMeasurement,
            &unsupported,
        );
        state.record_probe_failure(
            ResourceProbe::NetworkConnectionLimit,
            ResourceProbeFallback::ConservativeDefault,
            &fallback,
        );
        state.record_disabled(ResourceProbe::MemoryMaxBytes);

        let report = state.report();
        let probe_list: Vec<Value> = report
            .probes
            .iter()
            .map(|probe| {
                json!({
                    "probe": probe.probe,
                    "resource_type": probe.resource_type,
                    "status": probe.status,
                    "fallback": probe.fallback,
                    "sampled_value": probe.sampled_value,
                    "error_message": probe.error_message,
                })
            })
            .collect();
        let smoke_report = json!({
            "schema_version": report.schema_version,
            "platform_fingerprint": report.platform,
            "probe_list": probe_list,
            "supported_count": report.supported_count,
            "unavailable_count": report.unavailable_count,
            "fallback_count": report.fallback_count,
            "disabled_count": report.disabled_count,
            "warning_emitted_count": report.warning_emitted_count,
            "warning_suppressed_count": report.warning_suppressed_count,
            "sampled_values": report.probes.iter().filter_map(|probe| {
                probe.sampled_value.map(|value| json!({
                    "probe": probe.probe,
                    "value": value,
                }))
            }).collect::<Vec<_>>(),
            "error_messages": report.probes.iter().filter_map(|probe| {
                probe.error_message.as_ref().map(|message| json!({
                    "probe": probe.probe,
                    "message": message,
                    "fallback": probe.fallback,
                }))
            }).collect::<Vec<_>>(),
            "final_operator_verdict": report.operator_verdict,
        });

        assert_eq!(smoke_report["supported_count"], 1);
        assert_eq!(smoke_report["unavailable_count"], 1);
        assert_eq!(smoke_report["fallback_count"], 1);
        assert_eq!(smoke_report["disabled_count"], 1);
        assert_eq!(
            smoke_report["final_operator_verdict"],
            "degraded_with_unavailable_probes"
        );

        if std::env::var_os("ASUPERSYNC_RESOURCE_MONITOR_PLATFORM_GAP_REPORT").is_some() {
            println!("RESOURCE_MONITOR_PLATFORM_GAP_REPORT_JSON_BEGIN");
            println!(
                "{}",
                serde_json::to_string_pretty(&smoke_report).expect("serialize smoke report")
            );
            println!("RESOURCE_MONITOR_PLATFORM_GAP_REPORT_JSON_END");
        }
    }

    // ===================================================================
    // br-asupersync-thfiyk: real platform-read tests for the
    // SystemResourceCollector. The exact values vary per-host so we
    // assert on shape (non-zero where it must be, ratios sane, no
    // longer the constants the retired deterministic fixtures returned).
    // ===================================================================

    #[test]
    fn thfiyk_derive_thresholds_basic() {
        assert_eq!(derive_thresholds(1000, 75, 90), (750, 900));
        assert_eq!(derive_thresholds(0, 75, 90), (0, 0));
        // Saturation: extremely large `max_limit` doesn't overflow u64.
        let (s, h) = derive_thresholds(u64::MAX, 75, 90);
        assert_eq!(s, ((u128::from(u64::MAX) * 75) / 100) as u64);
        assert_eq!(h, ((u128::from(u64::MAX) * 90) / 100) as u64);
        assert!(s <= h);
    }

    #[test]
    fn thfiyk_derive_thresholds_clamps_to_max() {
        // soft and hard must never exceed max_limit even if the
        // percentages would compute past it (rounding).
        let (s, h) = derive_thresholds(7, 75, 90);
        assert!(s <= 7);
        assert!(h <= 7);
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    #[test]
    fn thfiyk_collect_memory_usage_returns_real_rss() {
        let pressure = Arc::new(ResourcePressure::new());
        let collector = SystemResourceCollector::new(pressure, Duration::from_secs(1));
        let read = collector.collect_memory_usage();
        // macOS and the BSDs read only the lifetime peak (ru_maxrss), which is
        // refused as current usage (1ir2em HIGH-1).
        if RSS_READING_IS_LIFETIME_PEAK {
            match read {
                Err(ResourceMonitorError::SystemAccessFailed { reason }) => {
                    assert!(reason.contains("ru_maxrss"), "{reason}");
                }
                other => panic!("a lifetime peak is not current usage: {other:?}"),
            }
            return;
        }
        let m = read.expect("memory usage read should succeed on supported platform");
        // The old constant-only reader always returned 512 MiB exactly; the real
        // reader yields the live VmRSS / ru_maxrss which is virtually
        // never that exact value. We assert (a) non-zero current
        // (this test process necessarily has resident memory),
        // (b) max_limit > 0, (c) we did NOT get the legacy constants.
        assert!(m.current > 0, "current bytes should be > 0");
        assert!(m.max_limit > 0, "max_limit should be > 0");
        assert!(
            m.current != 512 * 1024 * 1024 || m.max_limit != 2048 * 1024 * 1024,
            "appears to still be returning the legacy constant-only values"
        );
        assert!(m.soft_limit <= m.hard_limit, "soft <= hard");
        assert!(m.hard_limit <= m.max_limit, "hard <= max");
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    #[test]
    fn thfiyk_collect_fd_usage_returns_real_count() {
        let pressure = Arc::new(ResourcePressure::new());
        let collector = SystemResourceCollector::new(pressure, Duration::from_secs(1));
        let m = collector
            .collect_fd_usage()
            .expect("fd usage read should succeed on supported platform");
        // A test process always has at least stdin/stdout/stderr open,
        // so current_fds >= 3 in practice. We assert >= 1 to keep the
        // test robust on obscure sandboxed environments.
        assert!(m.current >= 1, "fd count should be >= 1");
        assert!(m.max_limit >= m.current, "fd ceiling >= current");
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    #[test]
    fn thfiyk_collect_cpu_load_returns_real_load() {
        let pressure = Arc::new(ResourcePressure::new());
        let collector = SystemResourceCollector::new(pressure, Duration::from_secs(1));
        let m = collector
            .collect_cpu_load()
            .expect("loadavg read should succeed on supported platform");
        assert_eq!(m.max_limit, 100, "load is reported on a 0..100 scale");
        assert!(m.current <= 100, "load percentage in range");
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn thfiyk_collect_network_usage_returns_real_count() {
        let pressure = Arc::new(ResourcePressure::new());
        let collector = SystemResourceCollector::new(pressure, Duration::from_secs(1));
        let m = collector
            .collect_network_usage()
            .expect("connection count read should succeed on Linux or Android");
        // Connection count can legitimately be 0 (a fresh test
        // process opens no sockets), so assert only that the ceiling
        // is sane and the reader did not return the legacy constant 50.
        assert!(m.max_limit > 0, "connection ceiling > 0");
        assert!(m.soft_limit <= m.hard_limit);
        assert!(m.hard_limit <= m.max_limit);
    }

    /// 1ir2em HIGH-1: macOS and the BSDs read only `ru_maxrss`, the lifetime
    /// peak. Taken as current usage, one burst held the memory level at
    /// Emergency for the life of the process. A peak-only reading is refused
    /// as unsupported, so memory goes unmeasured there; a current reading
    /// and a failed one pass through unchanged.
    #[test]
    fn a_lifetime_peak_rss_is_not_taken_as_current_usage() {
        let peak = 15_u64 << 30;
        let refused = current_rss_reading(Ok(peak), true).expect_err("a peak is not current usage");
        assert_eq!(refused.kind(), std::io::ErrorKind::Unsupported);
        assert!(refused.to_string().contains("ru_maxrss"), "{refused}");
        assert_eq!(current_rss_reading(Ok(peak), false).unwrap(), peak);
        let failed = current_rss_reading(Err(std::io::Error::other("no reading")), true)
            .expect_err("a failed reading stays failed");
        assert_eq!(failed.to_string(), "no reading");
        // Linux reads VmRSS, the current RSS, which falls again.
        #[cfg(target_os = "linux")]
        assert!(!RSS_READING_IS_LIFETIME_PEAK);
        #[cfg(target_os = "macos")]
        assert!(RSS_READING_IS_LIFETIME_PEAK);
    }

    /// 1ir2em MEDIUM-2: `EMFILE` comes at the soft descriptor limit, which
    /// both the descriptor and the connection measurements now use as their
    /// ceiling; the connection count is this process's own sockets. (It is
    /// not compared with the descriptor count: the two scans run at different
    /// times while other tests open and close sockets.)
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn descriptor_and_connection_pressure_use_the_soft_limit_and_own_sockets() {
        let (soft, _) = platform::fd_rlimit().expect("rlimit");
        let pressure = Arc::new(ResourcePressure::new());
        let collector = SystemResourceCollector::new(pressure, Duration::from_secs(1));
        let fds = collector.collect_fd_usage().expect("fd usage");
        assert_eq!(fds.max_limit, if soft == 0 { 1024 } else { soft });

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener");
        let pairs: Vec<_> = (0..4)
            .map(|_| std::os::unix::net::UnixStream::pair().expect("socket pair"))
            .collect();
        let sockets = platform::process_connection_count().expect("connection count");
        assert!(sockets >= 9, "our listener and eight pair ends: {sockets}");
        let connections = collector.collect_network_usage().expect("network usage");
        assert_eq!(connections.max_limit, fds.max_limit);
        drop((listener, pairs));
    }

    /// 1ir2em MEDIUM-1: the downgrade test was `new <= current - 1`, which
    /// every downgrade passes, so a usage hovering at a threshold flipped the
    /// level each cooldown. A downgrade now stops at the level the usage
    /// would have `hysteresis` higher.
    #[test]
    fn a_downgrade_waits_until_usage_falls_by_the_hysteresis_margin() {
        let cpu = TriggerConfig::default_for_resource(&ResourceType::CpuLoad);
        let load = |percent| ResourceMeasurement::new(percent, 80, 95, 100);
        assert_eq!(
            cpu.bounded_degradation(&load(96), DegradationLevel::None),
            DegradationLevel::Emergency
        );
        for (percent, current, expected) in [
            (94, DegradationLevel::Emergency, DegradationLevel::Emergency),
            (86, DegradationLevel::Emergency, DegradationLevel::Emergency),
            (80, DegradationLevel::Emergency, DegradationLevel::Moderate),
            (72, DegradationLevel::Moderate, DegradationLevel::Light),
            (70, DegradationLevel::Moderate, DegradationLevel::Light),
            (69, DegradationLevel::Light, DegradationLevel::None),
            (50, DegradationLevel::Light, DegradationLevel::None),
            (90, DegradationLevel::Light, DegradationLevel::Moderate),
        ] {
            assert_eq!(
                cpu.bounded_degradation(&load(percent), current),
                expected,
                "{percent}% load at {current:?}"
            );
        }
    }

    /// 1ir2em MEDIUM-1: the cooldown was checked before the
    /// immediate-Emergency branch, so a jump to Emergency inside a cooldown
    /// waited for it to end.
    #[test]
    fn emergency_is_entered_inside_a_cooldown() {
        let config = TriggerConfig {
            cooldown: Duration::from_secs(3_600),
            ..TriggerConfig::default_for_resource(&ResourceType::CpuLoad)
        };
        let just_changed = Some(Instant::now());
        assert_eq!(
            config.apply_hysteresis(
                DegradationLevel::Emergency,
                DegradationLevel::Light,
                just_changed
            ),
            DegradationLevel::Emergency
        );
        assert_eq!(
            config.apply_hysteresis(
                DegradationLevel::Moderate,
                DegradationLevel::Light,
                just_changed
            ),
            DegradationLevel::Light,
            "other changes still wait for the cooldown"
        );
    }

    /// The engine applies the margin: 94% load after an Emergency at 96%
    /// keeps Emergency, where it used to drop to Moderate.
    #[test]
    fn the_engine_keeps_a_level_while_usage_hovers_at_its_threshold() {
        let monitor = ResourceMonitor::new(MonitorConfig::default());
        monitor
            .engine()
            .register_resource_type(
                ResourceType::CpuLoad,
                TriggerConfig {
                    cooldown: Duration::ZERO,
                    ..TriggerConfig::default_for_resource(&ResourceType::CpuLoad)
                },
            )
            .expect("register");
        let level_after = |percent| {
            monitor.pressure().update_measurement(
                ResourceType::CpuLoad,
                ResourceMeasurement::new(percent, 80, 95, 100),
            );
            let _ = monitor.engine().process_measurements();
            monitor
                .pressure()
                .get_degradation_level(&ResourceType::CpuLoad)
        };
        assert_eq!(level_after(96), DegradationLevel::Emergency);
        assert_eq!(level_after(94), DegradationLevel::Emergency);
        assert_eq!(level_after(96), DegradationLevel::Emergency);
        assert_eq!(level_after(60), DegradationLevel::None);
    }

    fn sample_scheduler_metrics() -> SchedulerEvidenceMetrics {
        SchedulerEvidenceMetrics {
            wake_to_run_p50_ns: 8_000,
            wake_to_run_p95_ns: 90_000,
            wake_to_run_p99_ns: 220_000,
            queue_residency_p50_ns: 16_000,
            queue_residency_p95_ns: 200_000,
            queue_residency_p99_ns: 520_000,
            ready_backlog_p95: 192,
            ready_backlog_p99: 320,
            cancel_debt_p95: 48,
            cancel_debt_p99: 128,
            remote_steal_ratio_pct: Some(42),
            cross_cohort_wake_p99_ns: Some(180_000),
        }
    }

    fn healthy_scheduler_metrics() -> SchedulerEvidenceMetrics {
        SchedulerEvidenceMetrics {
            wake_to_run_p50_ns: 4_000,
            wake_to_run_p95_ns: 40_000,
            wake_to_run_p99_ns: 80_000,
            queue_residency_p50_ns: 6_000,
            queue_residency_p95_ns: 70_000,
            queue_residency_p99_ns: 120_000,
            ready_backlog_p95: 24,
            ready_backlog_p99: 48,
            cancel_debt_p95: 8,
            cancel_debt_p99: 16,
            remote_steal_ratio_pct: Some(12),
            cross_cohort_wake_p99_ns: Some(60_000),
        }
    }

    fn complete_platform_probe_report() -> ResourcePlatformProbeReport {
        ResourcePlatformProbeReport::from_snapshots(
            "test-linux/x86_64".to_string(),
            vec![ResourceProbeSnapshot {
                platform: "test-linux/x86_64".to_string(),
                resource_type: ResourceType::Memory,
                probe: ResourceProbe::ProcessRssBytes,
                status: ResourceProbeStatus::Supported,
                fallback: ResourceProbeFallback::None,
                sampled_value: Some(16_384),
                error_message: None,
                warning_count: 0,
                warning_suppressed_count: 0,
            }],
        )
    }

    fn degraded_platform_probe_report() -> ResourcePlatformProbeReport {
        ResourcePlatformProbeReport::from_snapshots(
            "test-linux/x86_64".to_string(),
            vec![ResourceProbeSnapshot {
                platform: "test-linux/x86_64".to_string(),
                resource_type: ResourceType::Memory,
                probe: ResourceProbe::MemoryMaxBytes,
                status: ResourceProbeStatus::Fallback,
                fallback: ResourceProbeFallback::ConservativeDefault,
                sampled_value: None,
                error_message: Some("synthetic lab fallback".to_string()),
                warning_count: 1,
                warning_suppressed_count: 0,
            }],
        )
    }

    fn healthy_spectral_snapshot() -> RuntimePressureSpectralSnapshot {
        RuntimePressureSpectralSnapshot {
            class: RuntimePressureSpectralClass::Healthy,
            fiedler_micro_units: Some(250_000),
            spectral_gap_bps: Some(7_500),
            spectral_radius_micro_units: Some(1_500_000),
            bottleneck_count: 0,
            components: None,
            approaching_disconnect: false,
            trapped_wait_cycle: false,
            early_warning_severity: RuntimePressureEarlyWarningSeverity::None,
        }
    }

    fn structural_warning_spectral_snapshot() -> RuntimePressureSpectralSnapshot {
        RuntimePressureSpectralSnapshot {
            class: RuntimePressureSpectralClass::Fragmented,
            fiedler_micro_units: Some(0),
            spectral_gap_bps: Some(0),
            spectral_radius_micro_units: Some(2_100_000),
            bottleneck_count: 2,
            components: Some(2),
            approaching_disconnect: false,
            trapped_wait_cycle: false,
            early_warning_severity: RuntimePressureEarlyWarningSeverity::Warning,
        }
    }

    fn rch_request(lane_id: &str, priority: RchProofPriority) -> RchProofLaneRequest {
        RchProofLaneRequest::new(lane_id, RchTargetDirClass::Warm, true, priority)
    }

    fn healthy_rch_worker(raw_worker_id: &str, lane_id: &str) -> RchWorkerSnapshot {
        RchWorkerSnapshot::new(
            raw_worker_id,
            true,
            RchQueueState::Open,
            false,
            vec![RchCacheWarmthHint::new(
                Some(lane_id),
                RchTargetDirClass::Warm,
                90,
            )],
            RchWorkerDiskPressure::new(100.0, 120.0, 0.1, 0.2),
            RchArtifactRetrievalReliability::new(4, 0, 0),
            30,
            95,
            0,
        )
    }

    fn admitted_rch_receipt(lane_id: &str) -> RchWorkerAdmissionReceipt {
        let request = rch_request(lane_id, RchProofPriority::Foreground);
        let worker = healthy_rch_worker("vmi-rch-proof-lane-a.internal", lane_id);
        admit_rch_worker(&request, &[worker], &RchWorkerAdmissionPolicy::default())
    }

    fn refused_remote_required_rch_receipt(lane_id: &str) -> RchWorkerAdmissionReceipt {
        let request = rch_request(lane_id, RchProofPriority::Critical);
        admit_rch_worker(&request, &[], &RchWorkerAdmissionPolicy::default())
    }

    fn sample_lock_metrics(
        name: &'static str,
        acquisitions: u64,
        contentions: u64,
    ) -> LockMetricsSnapshot {
        LockMetricsSnapshot {
            name,
            acquisitions,
            contentions,
            wait_ns: acquisitions.saturating_mul(1_000),
            hold_ns: acquisitions.saturating_mul(2_000),
            max_wait_ns: 9_000,
            max_hold_ns: 12_000,
            wait_percentile_sample_count: acquisitions,
            p95_wait_ns: 4_000,
            p999_wait_ns: 8_000,
            hold_percentile_sample_count: acquisitions,
            p95_hold_ns: 6_000,
            p999_hold_ns: 10_000,
            instrumentation_mode: "lock-metrics-test",
        }
    }

    fn sample_lock_order_atlas() -> LockOrderAtlasSnapshot {
        LockOrderAtlasSnapshot {
            order_edges_exercised: vec![LockOrderEdge {
                held_lock_name: "regions".to_string(),
                held_rank: LockRank::Regions,
                held_module: LockModule::Runtime,
                acquired_lock_name: "tasks".to_string(),
                acquired_rank: LockRank::Tasks,
                acquired_module: LockModule::Runtime,
            }],
            order_violations: vec![LockOrderViolation {
                lock_name: "tasks".to_string(),
                lock_rank: LockRank::Tasks,
                lock_module: LockModule::Runtime,
                held_rank: LockRank::Obligations,
                reason: "rank-order".to_string(),
            }],
            instrumentation_mode: "lock-metrics-test",
        }
    }

    fn sample_trapped_cycle_witness() -> AdmissionAwareTrappedCycleWitnessRow {
        AdmissionAwareTrappedCycleWitnessRow {
            witness_id: "atlas-witness-001".to_string(),
            participants: vec![
                "task:00000001-00000000".to_string(),
                "task:00000002-00000000".to_string(),
            ],
            held_resources: vec![
                "lock:regions".to_string(),
                "obligation:send-permit:00000004-00000000".to_string(),
            ],
            wait_edges: vec![
                AdmissionAwareTrappedCycleWaitEdgeRow {
                    waiting_participant: "task:00000002-00000000".to_string(),
                    held_by_participant: "task:00000001-00000000".to_string(),
                    resource: "lock:regions".to_string(),
                },
                AdmissionAwareTrappedCycleWaitEdgeRow {
                    waiting_participant: "task:00000001-00000000".to_string(),
                    held_by_participant: "task:00000002-00000000".to_string(),
                    resource: "obligation:send-permit:00000004-00000000".to_string(),
                },
            ],
            source_step_or_timestamp: "lab-step:4242".to_string(),
            replay_command: "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=\"${TMPDIR:-/tmp}/rch_target_trapped_cycle_witness\" cargo test -p asupersync --test runtime_wait_cause_remediation_contract actionable_report -- --nocapture".to_string(),
            proof_status: AdmissionAwareTrappedCycleWitnessProofStatus::Validated,
            witness_freshness: AdmissionAwareAtlasFreshnessStatus::Fresh,
        }
    }

    fn complete_atlas_builder_input(
        spectral: RuntimePressureSpectralSnapshot,
        include_trapped_cycle_witness: bool,
    ) -> AdmissionAwareRuntimePressureAtlasBuilderInput {
        let pressure = ResourcePressure::new();
        pressure.update_measurement(
            ResourceType::Memory,
            ResourceMeasurement::new(32, 80, 95, 100),
        );
        let region_budget = RuntimePressureRegionMemoryBudgetSnapshot::with_label(
            RegionId::new_ephemeral(),
            "atlas-region",
            4_096,
            2_048,
        );
        let rch_row =
            RuntimePressureRchProofLaneSnapshot::from_receipt(&admitted_rch_receipt("cargo-test"));
        let runtime_pressure =
            RuntimePressureSnapshot::from_parts_with_region_memory_budgets_and_rch_proof_lanes(
                &pressure,
                complete_platform_probe_report(),
                Some(healthy_scheduler_metrics()),
                Some(spectral),
                vec![region_budget],
                vec![rch_row],
            );
        let mut input = AdmissionAwareRuntimePressureAtlasBuilderInput::new(
            runtime_pressure,
            sample_lock_order_atlas(),
        );
        input.lock_metrics = vec![
            sample_lock_metrics("tasks", 16, 2),
            sample_lock_metrics("regions", 12, 1),
            sample_lock_metrics("tasks", 8, 1),
        ];
        input.dirty_tree_peer_ownership = vec![
            AdmissionAwareDirtyTreePeerOwnershipRow {
                path: "src/runtime/resource_monitor.rs".to_string(),
                dirty_classification: "owned".to_string(),
                holder: Some("SageWolf".to_string()),
                bead_id: Some("asupersync-bt63nr.7".to_string()),
                source: "agent-mail-reservation".to_string(),
                overlap_classification: AdmissionAwareCoordinationOverlapClass::OwnedExact,
                coordination_decision: AdmissionAwareCoordinationDecision::Proceed,
                blocks_admission: false,
                handoff_required: false,
                sample_freshness: AdmissionAwareAtlasFreshnessStatus::Fresh,
            },
            AdmissionAwareDirtyTreePeerOwnershipRow {
                path: ".beads/issues.jsonl".to_string(),
                dirty_classification: "tracker-only".to_string(),
                holder: Some("SageWolf".to_string()),
                bead_id: Some("asupersync-bt63nr.7".to_string()),
                source: "beads-claim".to_string(),
                overlap_classification: AdmissionAwareCoordinationOverlapClass::TrackerOnly,
                coordination_decision: AdmissionAwareCoordinationDecision::Proceed,
                blocks_admission: false,
                handoff_required: false,
                sample_freshness: AdmissionAwareAtlasFreshnessStatus::Fresh,
            },
        ];
        input.agent_mail_reservations = vec![AdmissionAwareAgentMailReservationRow {
            path_pattern: "src/runtime/resource_monitor.rs".to_string(),
            holder: "SageWolf".to_string(),
            exclusive: true,
            reason: "asupersync-bt63nr.3".to_string(),
            expires_ts: Some("2026-06-02T23:00:00Z".to_string()),
            bead_id: Some("asupersync-bt63nr.7".to_string()),
            overlap_classification: AdmissionAwareCoordinationOverlapClass::OwnedExact,
            coordination_decision: AdmissionAwareCoordinationDecision::Proceed,
            sample_freshness: AdmissionAwareAtlasFreshnessStatus::Fresh,
        }];
        input.br_tracker_status = vec![AdmissionAwareBrTrackerStatusRow {
            bead_id: "asupersync-bt63nr.3".to_string(),
            status: "in_progress".to_string(),
            priority: Some(1),
            blocked_by: Vec::new(),
            ready: true,
            assignee: Some("SageWolf".to_string()),
            updated_at: Some("2026-06-02T21:02:56Z".to_string()),
            overlap_classification: AdmissionAwareCoordinationOverlapClass::OwnedExact,
            coordination_decision: AdmissionAwareCoordinationDecision::Proceed,
            sample_freshness: AdmissionAwareAtlasFreshnessStatus::Fresh,
        }];
        input.large_host_worker_warmth = vec![AdmissionAwareLargeHostWorkerWarmthRow {
            worker_id: "rchw-large-1".to_string(),
            cpu_cores: 64,
            memory_bytes: 256 * 1024 * 1024 * 1024,
            numa_nodes: 2,
            disk_headroom_bytes: 512 * 1024 * 1024 * 1024,
            worker_queue_state: "open".to_string(),
            worker_available_cores: 48,
            worker_available_memory_bytes: 192 * 1024 * 1024 * 1024,
            cache_warmth: "warm".to_string(),
            target_dir_isolated: true,
            active_project_excluded: true,
            proof_lane_cost_estimate: Some("cargo-test-focused".to_string()),
            worker_saturation: AdmissionAwareLargeHostWorkerSaturation::Available,
            advisory_batching_decision: AdmissionAwareLargeHostBatchingDecision::AdmitBatch,
            advisory_batching_reason_codes: Vec::new(),
            advisory_batch_size_hint: None,
            advisory_non_claims: Vec::new(),
            advisory_only: false,
            sample_freshness: AdmissionAwareAtlasFreshnessStatus::Fresh,
        }];
        input.operator_closeout_receipts = vec![AdmissionAwareOperatorCloseoutReceiptRow {
            bead_id: "asupersync-bt63nr.3".to_string(),
            status: "pending-validation".to_string(),
            commit: None,
            proof_commands: vec![
                "RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p asupersync --lib admission_aware_runtime_pressure_atlas".to_string(),
            ],
            pushed_main: false,
            pushed_master_mirror: false,
            sample_freshness: AdmissionAwareAtlasFreshnessStatus::Fresh,
        }];
        if include_trapped_cycle_witness {
            input.trapped_cycle_witnesses = vec![sample_trapped_cycle_witness()];
        }
        input
    }

    fn snapshot_with_spectral(
        spectral: RuntimePressureSpectralSnapshot,
    ) -> RuntimePressureSnapshot {
        RuntimePressureSnapshot::from_parts(
            &ResourcePressure::new(),
            complete_platform_probe_report(),
            Some(healthy_scheduler_metrics()),
            Some(spectral),
        )
    }

    fn pressure_snapshot_from_parts(
        pressure: &ResourcePressure,
        platform_probe_report: ResourcePlatformProbeReport,
        scheduler: SchedulerEvidenceMetrics,
        spectral: RuntimePressureSpectralSnapshot,
    ) -> RuntimePressureSnapshot {
        RuntimePressureSnapshot::from_parts(
            pressure,
            platform_probe_report,
            Some(scheduler),
            Some(spectral),
        )
    }

    fn runtime_pressure_lab_scenario_evidence(
        scenario_id: &'static str,
        seed: u64,
        scenario_kind: RuntimePressureLabScenarioKind,
        expected_verdict: RuntimePressureVerdict,
        snapshot: RuntimePressureSnapshot,
        diagnostic_labels: &[&str],
    ) -> RuntimePressureLabScenarioEvidence {
        RuntimePressureLabScenarioEvidence::from_snapshot(
            scenario_id,
            seed,
            scenario_kind,
            expected_verdict,
            snapshot,
            diagnostic_labels
                .iter()
                .map(|label| (*label).to_string())
                .collect(),
        )
    }

    fn healthy_pressure_lab_evidence() -> RuntimePressureLabScenarioEvidence {
        let pressure = ResourcePressure::new();
        pressure.update_measurement(
            ResourceType::Memory,
            ResourceMeasurement::new(32, 80, 90, 100),
        );

        runtime_pressure_lab_scenario_evidence(
            "runtime-pressure-lab-healthy",
            0x57A9_0001,
            RuntimePressureLabScenarioKind::Healthy,
            RuntimePressureVerdict::Healthy,
            pressure_snapshot_from_parts(
                &pressure,
                complete_platform_probe_report(),
                healthy_scheduler_metrics(),
                healthy_spectral_snapshot(),
            ),
            &["all_signals_present"],
        )
    }

    fn cpu_lane_pressure_lab_evidence() -> RuntimePressureLabScenarioEvidence {
        let pressure = ResourcePressure::new();
        pressure.update_measurement(
            ResourceType::CpuLoad,
            ResourceMeasurement::new(96, 70, 85, 100),
        );
        pressure.update_degradation_level(ResourceType::CpuLoad, DegradationLevel::Heavy);

        runtime_pressure_lab_scenario_evidence(
            "runtime-pressure-lab-cpu-lane-pressure",
            0x57A9_C011,
            RuntimePressureLabScenarioKind::CpuLanePressure,
            RuntimePressureVerdict::Critical,
            pressure_snapshot_from_parts(
                &pressure,
                complete_platform_probe_report(),
                sample_scheduler_metrics(),
                healthy_spectral_snapshot(),
            ),
            &[
                "cpu_load_hard_limit",
                "resource_heavy_degradation",
                "scheduler_tail_pressure",
            ],
        )
    }

    fn resource_fallback_degraded_lab_evidence() -> RuntimePressureLabScenarioEvidence {
        let pressure = ResourcePressure::new();
        pressure.update_measurement(
            ResourceType::Memory,
            ResourceMeasurement::new(82, 70, 95, 100),
        );
        pressure.update_degradation_level(ResourceType::Memory, DegradationLevel::Moderate);

        runtime_pressure_lab_scenario_evidence(
            "runtime-pressure-lab-resource-fallback-degraded",
            0x57A9_FA11,
            RuntimePressureLabScenarioKind::ResourceFallbackDegraded,
            RuntimePressureVerdict::Degraded,
            pressure_snapshot_from_parts(
                &pressure,
                degraded_platform_probe_report(),
                healthy_scheduler_metrics(),
                healthy_spectral_snapshot(),
            ),
            &["memory_soft_pressure", "platform_probe_fallback"],
        )
    }

    fn region_memory_budget_overrun_lab_evidence() -> RuntimePressureLabScenarioEvidence {
        let pressure = ResourcePressure::new();
        pressure.update_measurement(
            ResourceType::Memory,
            ResourceMeasurement::new(45, 80, 95, 100),
        );
        let region_memory_budget = RuntimePressureRegionMemoryBudgetSnapshot::with_label(
            RegionId::new_ephemeral(),
            "pressure-lab-region",
            1_000,
            1_125,
        );

        runtime_pressure_lab_scenario_evidence(
            "runtime-pressure-lab-region-memory-budget-overrun",
            0x57A9_BAD9,
            RuntimePressureLabScenarioKind::RegionMemoryBudgetOverrun,
            RuntimePressureVerdict::Critical,
            RuntimePressureSnapshot::from_parts_with_region_memory_budgets(
                &pressure,
                complete_platform_probe_report(),
                Some(healthy_scheduler_metrics()),
                Some(healthy_spectral_snapshot()),
                vec![region_memory_budget],
            ),
            &[
                "region_memory_budget_advisory",
                "region_memory_budget_exhausted",
            ],
        )
    }

    fn structural_warning_lab_evidence() -> RuntimePressureLabScenarioEvidence {
        let pressure = ResourcePressure::new();
        pressure.update_measurement(
            ResourceType::Task,
            ResourceMeasurement::new(24, 80, 95, 100),
        );

        runtime_pressure_lab_scenario_evidence(
            "runtime-pressure-lab-structural-warning",
            0x57A9_57AC,
            RuntimePressureLabScenarioKind::StructuralWarning,
            RuntimePressureVerdict::Critical,
            pressure_snapshot_from_parts(
                &pressure,
                complete_platform_probe_report(),
                healthy_scheduler_metrics(),
                structural_warning_spectral_snapshot(),
            ),
            &[
                "spectral_fragmented_topology",
                "trapped_cycle_detection_required",
            ],
        )
    }

    fn rch_proof_lane_remote_refusal_lab_evidence() -> RuntimePressureLabScenarioEvidence {
        let pressure = ResourcePressure::new();
        pressure.update_measurement(
            ResourceType::Memory,
            ResourceMeasurement::new(40, 80, 95, 100),
        );
        let rch_row = RuntimePressureRchProofLaneSnapshot::from_receipt(
            &refused_remote_required_rch_receipt("cargo-clippy-admission"),
        );

        runtime_pressure_lab_scenario_evidence(
            "runtime-pressure-lab-rch-proof-lane-remote-refusal",
            0x57A9_7C17,
            RuntimePressureLabScenarioKind::RchProofLaneRemoteRefusal,
            RuntimePressureVerdict::Critical,
            RuntimePressureSnapshot::from_parts_with_rch_proof_lanes(
                &pressure,
                complete_platform_probe_report(),
                Some(healthy_scheduler_metrics()),
                Some(healthy_spectral_snapshot()),
                vec![rch_row],
            ),
            &["local_fallback_refused", "rch_remote_required_refused"],
        )
    }

    #[test]
    fn runtime_pressure_snapshot_marks_empty_inputs_unknown() {
        let pressure = ResourcePressure::new();
        let snapshot = RuntimePressureSnapshot::from_parts(
            &pressure,
            ResourcePlatformProbeReport::from_snapshots("test/noarch".to_string(), Vec::new()),
            None,
            None,
        );

        assert_eq!(
            snapshot.schema_version,
            RUNTIME_PRESSURE_SNAPSHOT_SCHEMA_VERSION
        );
        assert_eq!(snapshot.overall_verdict, RuntimePressureVerdict::Unknown);
        assert_eq!(snapshot.missing_signal_count, 4);
        assert_eq!(snapshot.degraded_signal_count, 0);
        assert_eq!(snapshot.critical_signal_count, 0);
        assert!(snapshot.resources.is_empty());
        assert_eq!(
            snapshot.spectral.class,
            RuntimePressureSpectralClass::Unknown
        );
        assert_eq!(
            snapshot
                .signal_statuses
                .iter()
                .map(|status| (status.signal, status.status))
                .collect::<Vec<_>>(),
            vec![
                (
                    RuntimePressureSignal::Resources,
                    RuntimePressureSignalStatus::Missing,
                ),
                (
                    RuntimePressureSignal::Scheduler,
                    RuntimePressureSignalStatus::Missing,
                ),
                (
                    RuntimePressureSignal::Spectral,
                    RuntimePressureSignalStatus::Missing,
                ),
                (
                    RuntimePressureSignal::PlatformProbes,
                    RuntimePressureSignalStatus::Missing,
                ),
            ]
        );
    }

    #[test]
    fn runtime_pressure_snapshot_orders_resources_deterministically() {
        let pressure = ResourcePressure::new();
        pressure.update_measurement(
            ResourceType::Custom("zeta".to_string()),
            ResourceMeasurement::new(20, 50, 90, 100),
        );
        pressure.update_degradation_level(
            ResourceType::Custom("zeta".to_string()),
            DegradationLevel::None,
        );
        pressure.update_measurement(
            ResourceType::Memory,
            ResourceMeasurement::new(64, 80, 95, 100),
        );
        pressure.update_measurement(
            ResourceType::Custom("alpha".to_string()),
            ResourceMeasurement::new(10, 50, 90, 100),
        );

        let snapshot = RuntimePressureSnapshot::from_parts(
            &pressure,
            complete_platform_probe_report(),
            Some(healthy_scheduler_metrics()),
            Some(healthy_spectral_snapshot()),
        );
        let labels = snapshot
            .resources
            .iter()
            .map(|resource| resource.resource_label.as_str())
            .collect::<Vec<_>>();

        assert_eq!(labels, vec!["custom:alpha", "custom:zeta", "memory"]);
        assert_eq!(snapshot.resources[0].usage_bps, 1_000);
        assert_eq!(snapshot.resources[1].usage_bps, 2_000);
        assert_eq!(snapshot.resources[2].usage_bps, 6_400);
    }

    #[test]
    fn runtime_pressure_snapshot_serializes_stable_json_shape() {
        let pressure = ResourcePressure::new();
        pressure.update_measurement(
            ResourceType::Memory,
            ResourceMeasurement::new(800, 700, 900, 1000),
        );
        pressure.update_degradation_level(ResourceType::Memory, DegradationLevel::Moderate);

        let snapshot = RuntimePressureSnapshot::from_parts(
            &pressure,
            complete_platform_probe_report(),
            Some(sample_scheduler_metrics()),
            Some(healthy_spectral_snapshot()),
        );
        let json = serde_json::to_string_pretty(&snapshot).expect("serialize snapshot");
        let value: Value = serde_json::from_str(&json).expect("parse snapshot json");

        assert_eq!(snapshot.overall_verdict, RuntimePressureVerdict::Degraded);
        assert_eq!(snapshot.missing_signal_count, 0);
        assert_eq!(snapshot.degraded_signal_count, 2);
        assert_eq!(snapshot.critical_signal_count, 0);
        assert_eq!(
            value["schema_version"],
            RUNTIME_PRESSURE_SNAPSHOT_SCHEMA_VERSION
        );
        assert_eq!(value["overall_verdict"], "degraded");
        assert_eq!(value["resource_composite_degradation"], "Moderate");
        assert_eq!(value["resources"][0]["resource_label"], "memory");
        assert_eq!(value["resources"][0]["usage_bps"], 8_000);
        assert_eq!(value["scheduler"]["wake_to_run_p99_ns"], 220_000);
        assert_eq!(value["spectral"]["class"], "healthy");
        assert_eq!(
            value["rch_proof_lanes"]
                .as_array()
                .expect("rch proof lanes array")
                .len(),
            0
        );
        assert_eq!(
            value["region_memory_budgets"]
                .as_array()
                .expect("region memory budgets array")
                .len(),
            0
        );
        assert_eq!(
            value["signal_statuses"][0]["signal"], "resources",
            "signal rows stay sorted by enum order"
        );
    }

    #[test]
    fn runtime_pressure_region_memory_budget_rows_use_capability_envelopes() {
        let region_id = RegionId::new_ephemeral();

        assert!(
            RuntimePressureRegionMemoryBudgetSnapshot::from_capability_budget(
                region_id,
                CapabilityBudget::UNSPECIFIED,
                512,
            )
            .is_none(),
            "regions without explicit memory envelopes should not invent budget evidence"
        );

        let row = RuntimePressureRegionMemoryBudgetSnapshot::from_capability_budget(
            region_id,
            CapabilityBudget::new().with_memory_bytes(4_096),
            2_048,
        )
        .expect("memory envelope should project to a row");

        assert_eq!(
            row.schema_version,
            RUNTIME_PRESSURE_REGION_MEMORY_BUDGET_SCHEMA_VERSION
        );
        assert_eq!(row.region_id, region_id);
        assert_eq!(row.region_label, region_id.to_string());
        assert_eq!(row.declared_memory_budget_bytes, 4_096);
        assert_eq!(row.observed_memory_bytes, 2_048);
        assert_eq!(row.usage_bps, 5_000);
        assert_eq!(row.over_budget_bytes, 0);
        assert!(!row.soft_limit_exceeded);
        assert!(!row.hard_limit_exceeded);
        assert!(!row.budget_exhausted);
        assert!(row.advisory_only);
    }

    #[test]
    fn runtime_pressure_snapshot_folds_region_memory_budget_pressure() {
        let pressure = ResourcePressure::new();
        pressure.update_measurement(
            ResourceType::Memory,
            ResourceMeasurement::new(32, 80, 95, 100),
        );

        let under_budget = RuntimePressureRegionMemoryBudgetSnapshot::with_label(
            RegionId::new_ephemeral(),
            "under-budget",
            1_000,
            512,
        );
        let soft_pressure = RuntimePressureRegionMemoryBudgetSnapshot::with_label(
            RegionId::new_ephemeral(),
            "soft-pressure",
            1_000,
            850,
        );
        let over_budget = RuntimePressureRegionMemoryBudgetSnapshot::with_label(
            RegionId::new_ephemeral(),
            "over-budget",
            1_000,
            1_250,
        );

        let snapshot = RuntimePressureSnapshot::from_parts_with_region_memory_budgets(
            &pressure,
            complete_platform_probe_report(),
            Some(healthy_scheduler_metrics()),
            Some(healthy_spectral_snapshot()),
            vec![
                soft_pressure.clone(),
                over_budget.clone(),
                under_budget.clone(),
            ],
        );

        assert_eq!(snapshot.overall_verdict, RuntimePressureVerdict::Critical);
        assert_eq!(snapshot.missing_signal_count, 0);
        assert_eq!(snapshot.degraded_signal_count, 0);
        assert_eq!(snapshot.critical_signal_count, 1);
        assert_eq!(
            snapshot
                .region_memory_budgets
                .iter()
                .map(|row| row.region_label.as_str())
                .collect::<Vec<_>>(),
            vec!["over-budget", "soft-pressure", "under-budget"]
        );
        assert_eq!(snapshot.region_memory_budgets[0].usage_bps, 10_000);
        assert_eq!(snapshot.region_memory_budgets[0].over_budget_bytes, 250);
        assert!(snapshot.region_memory_budgets[0].hard_limit_exceeded);
        assert!(snapshot.region_memory_budgets[0].budget_exhausted);
        assert_eq!(snapshot.region_memory_budgets[1].usage_bps, 8_500);
        assert!(snapshot.region_memory_budgets[1].soft_limit_exceeded);
        assert!(!snapshot.region_memory_budgets[1].hard_limit_exceeded);
        assert_eq!(snapshot.region_memory_budgets[2].usage_bps, 5_120);
        assert!(!snapshot.region_memory_budgets[2].soft_limit_exceeded);
        assert_eq!(
            snapshot
                .signal_statuses
                .iter()
                .find(|row| row.signal == RuntimePressureSignal::RegionMemoryBudgets)
                .map(|row| (row.status, row.reason.as_str())),
            Some((
                RuntimePressureSignalStatus::Critical,
                "region_memory_budget_hard_pressure",
            ))
        );

        let value = serde_json::to_value(&snapshot).expect("serialize snapshot");
        assert_eq!(
            value["region_memory_budgets"][0]["schema_version"],
            RUNTIME_PRESSURE_REGION_MEMORY_BUDGET_SCHEMA_VERSION
        );
        assert_eq!(
            value["region_memory_budgets"][0]["advisory_only"],
            json!(true)
        );
    }

    #[test]
    fn runtime_pressure_snapshot_folds_rch_proof_lane_receipts() {
        let pressure = ResourcePressure::new();
        pressure.update_measurement(
            ResourceType::Memory,
            ResourceMeasurement::new(24, 80, 95, 100),
        );

        let admitted = RuntimePressureRchProofLaneSnapshot::from_receipt(&admitted_rch_receipt(
            "cargo-test-admission",
        ));
        let refused = RuntimePressureRchProofLaneSnapshot::from_receipt(
            &refused_remote_required_rch_receipt("cargo-clippy-admission"),
        );
        let snapshot = RuntimePressureSnapshot::from_parts_with_rch_proof_lanes(
            &pressure,
            complete_platform_probe_report(),
            Some(healthy_scheduler_metrics()),
            Some(healthy_spectral_snapshot()),
            vec![admitted, refused],
        );

        assert_eq!(snapshot.overall_verdict, RuntimePressureVerdict::Critical);
        assert_eq!(snapshot.missing_signal_count, 0);
        assert_eq!(snapshot.degraded_signal_count, 0);
        assert_eq!(snapshot.critical_signal_count, 1);
        assert_eq!(
            snapshot
                .rch_proof_lanes
                .iter()
                .map(|row| row.lane_id.as_str())
                .collect::<Vec<_>>(),
            vec!["cargo-clippy-admission", "cargo-test-admission"]
        );
        assert_eq!(
            snapshot.rch_proof_lanes[0].refusal_code.as_deref(),
            Some("no_workers")
        );
        assert!(
            snapshot.rch_proof_lanes[0]
                .reason_codes
                .contains(&"local_fallback_refused".to_string())
        );
        assert!(
            snapshot.rch_proof_lanes[1]
                .selected_worker
                .as_ref()
                .is_some_and(|worker| worker.starts_with("rchw-") && !worker.contains("vmi-"))
        );
        assert_eq!(
            snapshot
                .signal_statuses
                .iter()
                .find(|row| row.signal == RuntimePressureSignal::RchProofLanes)
                .map(|row| (row.status, row.reason.as_str())),
            Some((
                RuntimePressureSignalStatus::Critical,
                "rch_remote_required_proof_lane_refused",
            ))
        );

        let value = serde_json::to_value(&snapshot).expect("serialize snapshot");
        assert_eq!(
            value["rch_proof_lanes"][0]["schema_version"],
            RUNTIME_PRESSURE_RCH_PROOF_LANE_SCHEMA_VERSION
        );
        assert_eq!(
            value["signal_statuses"][4]["signal"],
            json!("rch_proof_lanes")
        );
    }

    #[test]
    fn percentile_horizon_survives_admission_aware_runtime_pressure_atlas_projection() {
        let mut input = complete_atlas_builder_input(healthy_spectral_snapshot(), false);
        input.replay_backed = true;
        input.dirty_tree_peer_ownership.reverse();
        input.lock_metrics.reverse();

        let atlas = AdmissionAwareRuntimePressureAtlasSnapshot::from_source_snapshots(input);
        let reparsed: AdmissionAwareRuntimePressureAtlasSnapshot =
            serde_json::from_str(&atlas.stable_json().expect("serialize atlas"))
                .expect("deserialize atlas");
        let value = serde_json::to_value(&atlas).expect("atlas to value");

        assert_eq!(
            atlas.schema_version,
            ADMISSION_AWARE_RUNTIME_PRESSURE_ATLAS_SCHEMA_VERSION
        );
        assert_eq!(
            atlas.overall_label,
            AdmissionAwareAtlasClaimLabel::ReplayBacked
        );
        assert!(atlas.missing_required_sections.is_empty());
        assert!(!atlas.production_admission_default_enabled);
        assert!(!atlas.mutates_agent_mail);
        assert!(!atlas.mutates_beads);
        assert!(!atlas.mutates_filesystem);
        assert!(!atlas.starts_rch);
        assert_eq!(
            atlas.coordination_decision,
            AdmissionAwareCoordinationDecision::Proceed
        );
        assert_eq!(
            atlas.coordination_reason_codes,
            vec!["tracker_only_dirty_tree_change"]
        );
        assert_eq!(reparsed, atlas);
        assert_eq!(
            atlas
                .lock_contention
                .iter()
                .map(|row| row.lock_name.as_str())
                .collect::<Vec<_>>(),
            vec!["regions", "tasks"]
        );
        assert_eq!(atlas.lock_contention[1].acquisitions, 16);
        assert_eq!(atlas.lock_contention[1].wait_percentile_sample_count, 16);
        assert_eq!(atlas.lock_contention[1].hold_percentile_sample_count, 16);
        assert_eq!(atlas.lock_contention[1].order_edges_exercised, 1);
        assert_eq!(atlas.lock_contention[1].order_violations, 1);
        assert_eq!(
            atlas
                .dirty_tree_peer_ownership
                .iter()
                .map(|row| row.path.as_str())
                .collect::<Vec<_>>(),
            vec![".beads/issues.jsonl", "src/runtime/resource_monitor.rs"]
        );
        assert_eq!(
            value["schema_version"],
            "admission-aware-runtime-pressure-atlas-v1"
        );
        assert_eq!(value["overall_label"], "replay_backed");
        assert_eq!(value["coordination_decision"], "proceed");
        assert_eq!(
            value["lock_contention"][1]["wait_percentile_sample_count"],
            16
        );
        assert_eq!(
            value["lock_contention"][1]["hold_percentile_sample_count"],
            16
        );
        assert_eq!(
            value["scheduler_pressure"][0]["scheduler_tail_pressure_label"],
            "nominal"
        );
        assert_eq!(value["trapped_cycle_witness"], json!([]));
        assert_eq!(
            value["rch_proof_lane_admission"][0]["cover_claims"],
            json!([
                "remote_proof_lane_admission_planner",
                "remote_required_policy",
                "worker_capacity_selected",
            ])
        );
        assert_eq!(
            value["large_host_worker_warmth"][0]["worker_saturation"],
            "available"
        );
        assert_eq!(
            value["large_host_worker_warmth"][0]["advisory_batching_decision"],
            "prefer_warm_worker"
        );
        assert_eq!(
            value["large_host_worker_warmth"][0]["advisory_batch_size_hint"],
            json!(3)
        );
        assert_eq!(
            value["large_host_worker_warmth"][0]["advisory_only"],
            json!(true)
        );
    }

    #[test]
    fn admission_aware_runtime_pressure_atlas_classifies_large_host_advisory_batching_profile() {
        let mut input = complete_atlas_builder_input(healthy_spectral_snapshot(), false);
        let healthy = input.large_host_worker_warmth[0].clone();
        let mut low_memory = healthy.clone();
        low_memory.worker_id = "rchw-large-low-memory".to_string();
        low_memory.worker_available_cores = 32;
        low_memory.worker_available_memory_bytes = 32 * 1024 * 1024 * 1024;

        let mut saturated = healthy.clone();
        saturated.worker_id = "rchw-large-saturated".to_string();
        saturated.worker_queue_state = "saturated".to_string();
        saturated.worker_available_cores = 4;
        saturated.worker_available_memory_bytes = 192 * 1024 * 1024 * 1024;

        let mut cold = healthy.clone();
        cold.worker_id = "rchw-large-cold".to_string();
        cold.cache_warmth = "cold".to_string();
        cold.worker_available_cores = 16;
        cold.worker_available_memory_bytes = 128 * 1024 * 1024 * 1024;

        input.large_host_worker_warmth = vec![saturated, low_memory, cold, healthy];

        let atlas = AdmissionAwareRuntimePressureAtlasSnapshot::from_source_snapshots(input);
        let rows = atlas
            .large_host_worker_warmth
            .iter()
            .map(|row| (row.worker_id.as_str(), row))
            .collect::<BTreeMap<_, _>>();
        let healthy = rows.get("rchw-large-1").expect("healthy worker");
        let low_memory = rows
            .get("rchw-large-low-memory")
            .expect("low-memory worker");
        let saturated = rows.get("rchw-large-saturated").expect("saturated worker");
        let cold = rows.get("rchw-large-cold").expect("cold worker");

        assert_eq!(healthy.cpu_cores, ADMISSION_AWARE_LARGE_HOST_CPU_CORES);
        assert_eq!(
            healthy.memory_bytes,
            ADMISSION_AWARE_LARGE_HOST_MEMORY_BYTES
        );
        assert_eq!(
            healthy.numa_nodes,
            ADMISSION_AWARE_LARGE_HOST_MIN_NUMA_NODES
        );
        assert_eq!(healthy.cache_warmth, "warm");
        assert!(healthy.target_dir_isolated);
        assert!(healthy.active_project_excluded);
        assert_eq!(
            healthy.worker_saturation,
            AdmissionAwareLargeHostWorkerSaturation::Available
        );
        assert_eq!(
            healthy.advisory_batching_decision,
            AdmissionAwareLargeHostBatchingDecision::PreferWarmWorker
        );
        assert_eq!(healthy.advisory_batch_size_hint, Some(3));
        for required in [
            "active_project_excluded",
            "advisory_batching_only",
            "large_host_shape_64_core_256_gib",
            "proof_lane_cost_estimate_present",
            "target_dir_isolated",
            "worker_cache_warm",
        ] {
            assert!(
                healthy
                    .advisory_batching_reason_codes
                    .iter()
                    .any(|code| code == required),
                "healthy worker reason missing {required}"
            );
        }

        assert_eq!(
            low_memory.worker_saturation,
            AdmissionAwareLargeHostWorkerSaturation::LowMemory
        );
        assert_eq!(
            low_memory.advisory_batching_decision,
            AdmissionAwareLargeHostBatchingDecision::QueueLowMemory
        );
        assert_eq!(low_memory.advisory_batch_size_hint, None);
        assert!(
            low_memory
                .advisory_batching_reason_codes
                .iter()
                .any(|code| code == "worker_memory_low")
        );

        assert_eq!(
            saturated.worker_saturation,
            AdmissionAwareLargeHostWorkerSaturation::WorkerSaturated
        );
        assert_eq!(
            saturated.advisory_batching_decision,
            AdmissionAwareLargeHostBatchingDecision::DeferWorkerSaturated
        );
        assert_eq!(saturated.advisory_batch_size_hint, None);
        assert!(
            saturated
                .advisory_batching_reason_codes
                .iter()
                .any(|code| code == "worker_queue_saturated")
        );

        assert_eq!(
            cold.worker_saturation,
            AdmissionAwareLargeHostWorkerSaturation::Available
        );
        assert_eq!(
            cold.advisory_batching_decision,
            AdmissionAwareLargeHostBatchingDecision::AdmitBatch
        );
        assert_eq!(cold.advisory_batch_size_hint, Some(2));
        assert!(
            cold.advisory_batching_reason_codes
                .iter()
                .any(|code| code == "worker_cache_cold")
        );

        for row in atlas.large_host_worker_warmth {
            assert!(row.advisory_only);
            for forbidden in [
                "allocator_enforcement",
                "production_admission_default",
                "throughput_improvement",
            ] {
                assert!(
                    row.advisory_non_claims
                        .iter()
                        .any(|claim| claim == forbidden),
                    "large-host row must keep {forbidden} as a non-claim"
                );
            }
        }
        assert!(!atlas.production_admission_default_enabled);
        assert!(!atlas.mutates_agent_mail);
        assert!(!atlas.mutates_beads);
        assert!(!atlas.mutates_filesystem);
        assert!(!atlas.starts_rch);
    }

    #[test]
    fn admission_aware_runtime_pressure_atlas_correlates_read_only_coordination_inputs() {
        let mut input = complete_atlas_builder_input(healthy_spectral_snapshot(), false);
        input
            .dirty_tree_peer_ownership
            .push(AdmissionAwareDirtyTreePeerOwnershipRow {
                path: "src/channel/mpsc.rs".to_string(),
                dirty_classification: "peer-owned-source-overlap".to_string(),
                holder: Some("PeerAgent".to_string()),
                bead_id: Some("asupersync-peer.1".to_string()),
                source: "agent-mail-reservation".to_string(),
                overlap_classification: AdmissionAwareCoordinationOverlapClass::PeerExact,
                coordination_decision: AdmissionAwareCoordinationDecision::Proceed,
                blocks_admission: true,
                handoff_required: true,
                sample_freshness: AdmissionAwareAtlasFreshnessStatus::Fresh,
            });
        input
            .agent_mail_reservations
            .push(AdmissionAwareAgentMailReservationRow {
                path_pattern: "src/channel/*.rs".to_string(),
                holder: "PeerAgent".to_string(),
                exclusive: true,
                reason: "asupersync-peer.1".to_string(),
                expires_ts: Some("2026-06-02T23:30:00Z".to_string()),
                bead_id: Some("asupersync-peer.1".to_string()),
                overlap_classification:
                    AdmissionAwareCoordinationOverlapClass::ActiveExclusiveConflict,
                coordination_decision: AdmissionAwareCoordinationDecision::Proceed,
                sample_freshness: AdmissionAwareAtlasFreshnessStatus::Fresh,
            });
        input
            .agent_mail_reservations
            .push(AdmissionAwareAgentMailReservationRow {
                path_pattern: "docs/runtime_pressure_triage_runbook.md".to_string(),
                holder: "PeerAgent".to_string(),
                exclusive: true,
                reason: "old-docs-reservation".to_string(),
                expires_ts: Some("2026-06-02T19:00:00Z".to_string()),
                bead_id: None,
                overlap_classification: AdmissionAwareCoordinationOverlapClass::ExpiredReservation,
                coordination_decision: AdmissionAwareCoordinationDecision::Blocked,
                sample_freshness: AdmissionAwareAtlasFreshnessStatus::Fresh,
            });
        input
            .br_tracker_status
            .push(AdmissionAwareBrTrackerStatusRow {
                bead_id: "asupersync-bt63nr.4".to_string(),
                status: "open".to_string(),
                priority: Some(1),
                blocked_by: vec!["asupersync-bt63nr.7".to_string()],
                ready: false,
                assignee: None,
                updated_at: Some("2026-06-02T22:44:00Z".to_string()),
                overlap_classification: AdmissionAwareCoordinationOverlapClass::TrackerOnly,
                coordination_decision: AdmissionAwareCoordinationDecision::Proceed,
                sample_freshness: AdmissionAwareAtlasFreshnessStatus::Fresh,
            });

        let atlas = AdmissionAwareRuntimePressureAtlasSnapshot::from_source_snapshots(input);

        assert_eq!(
            atlas.overall_label,
            AdmissionAwareAtlasClaimLabel::ValidationBlocked
        );
        assert_eq!(
            atlas.coordination_decision,
            AdmissionAwareCoordinationDecision::HandoffRequired
        );
        for reason in [
            "active_exclusive_agent_mail_conflict",
            "bead_blocked_by_dependencies",
            "bead_not_ready",
            "expired_agent_mail_reservation",
            "peer_dirty_tree_overlap",
            "tracker_only_dirty_tree_change",
        ] {
            assert!(
                atlas
                    .coordination_reason_codes
                    .iter()
                    .any(|code| code == reason),
                "coordination reason missing {reason}"
            );
        }
        assert_eq!(
            atlas
                .dirty_tree_peer_ownership
                .iter()
                .map(|row| (row.path.as_str(), row.coordination_decision))
                .collect::<Vec<_>>(),
            vec![
                (
                    ".beads/issues.jsonl",
                    AdmissionAwareCoordinationDecision::Proceed
                ),
                (
                    "src/channel/mpsc.rs",
                    AdmissionAwareCoordinationDecision::HandoffRequired
                ),
                (
                    "src/runtime/resource_monitor.rs",
                    AdmissionAwareCoordinationDecision::Proceed
                ),
            ]
        );
        let expired = atlas
            .agent_mail_reservations
            .iter()
            .find(|row| {
                row.overlap_classification
                    == AdmissionAwareCoordinationOverlapClass::ExpiredReservation
            })
            .expect("expired reservation row");
        assert_eq!(
            expired.coordination_decision,
            AdmissionAwareCoordinationDecision::Proceed,
            "expired reservations are visible but should not block the lane"
        );
        assert!(!atlas.mutates_agent_mail);
        assert!(!atlas.mutates_beads);
    }

    #[test]
    fn admission_aware_runtime_pressure_atlas_fails_closed_for_missing_source_rows() {
        let runtime_pressure = RuntimePressureSnapshot::from_parts(
            &ResourcePressure::new(),
            ResourcePlatformProbeReport::from_snapshots("test/noarch".to_string(), Vec::new()),
            None,
            None,
        );
        let atlas = AdmissionAwareRuntimePressureAtlasSnapshot::from_source_snapshots(
            AdmissionAwareRuntimePressureAtlasBuilderInput::new(
                runtime_pressure,
                LockOrderAtlasSnapshot {
                    order_edges_exercised: Vec::new(),
                    order_violations: Vec::new(),
                    instrumentation_mode: "disabled",
                },
            ),
        );

        assert_eq!(
            atlas.overall_label,
            AdmissionAwareAtlasClaimLabel::StaleEvidence
        );
        assert!(!atlas.deadlock_proven);
        assert_eq!(
            atlas.missing_required_sections,
            vec![
                "agent_mail_reservations",
                "br_tracker_status",
                "dirty_tree_peer_ownership",
                "large_host_worker_warmth",
                "lock_contention",
                "operator_closeout_receipt",
                "rch_proof_lane_admission",
                "scheduler_pressure",
                "spectral_wait_graph",
            ]
        );
        assert!(
            atlas
                .claim_boundary_labels
                .iter()
                .any(|row| row.label == AdmissionAwareAtlasClaimLabel::StaleEvidence)
        );
        assert!(atlas.lock_contention.is_empty());
        assert!(atlas.scheduler_pressure.is_empty());
        assert!(atlas.spectral_wait_graph.is_empty());
    }

    #[test]
    fn admission_aware_runtime_pressure_atlas_requires_explicit_trapped_cycle_witness() {
        let deadlocked = RuntimePressureSpectralSnapshot {
            class: RuntimePressureSpectralClass::Deadlocked,
            fiedler_micro_units: Some(0),
            spectral_gap_bps: Some(0),
            spectral_radius_micro_units: Some(2_400_000),
            bottleneck_count: 0,
            components: Some(2),
            approaching_disconnect: false,
            trapped_wait_cycle: true,
            early_warning_severity: RuntimePressureEarlyWarningSeverity::Critical,
        };

        let advisory = AdmissionAwareRuntimePressureAtlasSnapshot::from_source_snapshots(
            complete_atlas_builder_input(deadlocked.clone(), false),
        );
        let proven = AdmissionAwareRuntimePressureAtlasSnapshot::from_source_snapshots(
            complete_atlas_builder_input(deadlocked, true),
        );

        assert!(!advisory.deadlock_proven);
        assert_eq!(
            advisory.overall_label,
            AdmissionAwareAtlasClaimLabel::StaleEvidence
        );
        assert!(
            advisory
                .missing_required_sections
                .contains(&"trapped_cycle_witness".to_string())
        );
        assert_eq!(
            advisory.spectral_wait_graph[0].deadlock_proven, false,
            "spectral deadlocked class alone must not upgrade the claim"
        );

        assert!(proven.deadlock_proven);
        assert_eq!(
            proven.overall_label,
            AdmissionAwareAtlasClaimLabel::DeadlockProven
        );
        assert!(proven.missing_required_sections.is_empty());
        assert!(proven.spectral_wait_graph[0].deadlock_proven);
        assert_eq!(proven.trapped_cycle_witness.len(), 1);
        assert_eq!(
            proven.trapped_cycle_witness[0].proof_status,
            AdmissionAwareTrappedCycleWitnessProofStatus::Validated
        );
        assert_eq!(
            proven.trapped_cycle_witness[0].wait_edges[0].waiting_participant,
            "task:00000001-00000000",
            "witness wait edges should be canonically sorted"
        );
        assert!(
            proven
                .claim_boundary_labels
                .iter()
                .any(|row| row.label == AdmissionAwareAtlasClaimLabel::DeadlockProven)
        );
    }

    #[test]
    fn admission_aware_runtime_pressure_atlas_rejects_unvalidated_trapped_cycle_witness() {
        let deadlocked = RuntimePressureSpectralSnapshot {
            class: RuntimePressureSpectralClass::Deadlocked,
            fiedler_micro_units: Some(0),
            spectral_gap_bps: Some(0),
            spectral_radius_micro_units: Some(2_400_000),
            bottleneck_count: 0,
            components: Some(2),
            approaching_disconnect: false,
            trapped_wait_cycle: true,
            early_warning_severity: RuntimePressureEarlyWarningSeverity::Critical,
        };
        let mut input = complete_atlas_builder_input(deadlocked, false);
        let mut witness = sample_trapped_cycle_witness();
        witness.proof_status = AdmissionAwareTrappedCycleWitnessProofStatus::ReplayPending;
        input.trapped_cycle_witnesses = vec![witness];

        let atlas = AdmissionAwareRuntimePressureAtlasSnapshot::from_source_snapshots(input);

        assert!(!atlas.deadlock_proven);
        assert_eq!(
            atlas.overall_label,
            AdmissionAwareAtlasClaimLabel::StaleEvidence
        );
        assert!(
            atlas
                .missing_required_sections
                .contains(&"trapped_cycle_witness".to_string())
        );
        assert_eq!(
            atlas.trapped_cycle_witness[0].proof_status,
            AdmissionAwareTrappedCycleWitnessProofStatus::ReplayPending
        );
        assert!(!atlas.spectral_wait_graph[0].deadlock_proven);
    }

    #[test]
    fn runtime_pressure_snapshot_escalates_critical_spectral_evidence() {
        let pressure = ResourcePressure::new();
        let spectral = RuntimePressureSpectralSnapshot {
            class: RuntimePressureSpectralClass::Critical,
            fiedler_micro_units: Some(5_000),
            spectral_gap_bps: Some(50),
            spectral_radius_micro_units: Some(2_000_000),
            bottleneck_count: 3,
            components: None,
            approaching_disconnect: true,
            trapped_wait_cycle: false,
            early_warning_severity: RuntimePressureEarlyWarningSeverity::Critical,
        };

        let snapshot = RuntimePressureSnapshot::from_parts(
            &pressure,
            ResourcePlatformProbeReport::from_snapshots("test/noarch".to_string(), Vec::new()),
            None,
            Some(spectral),
        );

        assert_eq!(snapshot.overall_verdict, RuntimePressureVerdict::Critical);
        assert_eq!(snapshot.critical_signal_count, 1);
        assert_eq!(snapshot.missing_signal_count, 3);
        assert_eq!(
            snapshot.spectral.class,
            RuntimePressureSpectralClass::Critical
        );
    }

    #[test]
    fn runtime_pressure_spectral_recommendations_empty_for_healthy() {
        let snapshot = snapshot_with_spectral(healthy_spectral_snapshot());

        assert!(snapshot.spectral_recommendations.is_empty());
    }

    #[test]
    fn runtime_pressure_spectral_recommendations_cover_degraded_watch() {
        let spectral = RuntimePressureSpectralSnapshot {
            class: RuntimePressureSpectralClass::Degraded,
            fiedler_micro_units: Some(40_000),
            spectral_gap_bps: Some(900),
            spectral_radius_micro_units: Some(1_900_000),
            bottleneck_count: 2,
            components: None,
            approaching_disconnect: false,
            trapped_wait_cycle: false,
            early_warning_severity: RuntimePressureEarlyWarningSeverity::Watch,
        };

        let snapshot = snapshot_with_spectral(spectral);
        let recommendations = snapshot.spectral_recommendations;

        assert!(recommendations.iter().any(|recommendation| {
            recommendation.action
                == RuntimePressureRecommendationAction::CollectTaskInspectorDetails
                && recommendation.reason == RuntimePressureRecommendationReason::Bottleneck
        }));
        assert!(recommendations.iter().any(|recommendation| {
            recommendation.action == RuntimePressureRecommendationAction::InspectSpectralBottlenecks
                && recommendation.reason == RuntimePressureRecommendationReason::Bottleneck
        }));
        assert!(recommendations.iter().any(|recommendation| {
            recommendation.action == RuntimePressureRecommendationAction::EnableLabReplay
                && recommendation.evidence_scope
                    == RuntimePressureRecommendationEvidenceScope::SpectralTrend
        }));
        assert!(
            recommendations
                .iter()
                .all(|recommendation| !recommendation.deadlock_proven
                    && !recommendation.requires_trapped_cycle_proof)
        );
    }

    #[test]
    fn runtime_pressure_spectral_recommendations_flag_critical_topology_as_advisory() {
        let spectral = RuntimePressureSpectralSnapshot {
            class: RuntimePressureSpectralClass::Critical,
            fiedler_micro_units: Some(5_000),
            spectral_gap_bps: Some(50),
            spectral_radius_micro_units: Some(2_000_000),
            bottleneck_count: 1,
            components: None,
            approaching_disconnect: true,
            trapped_wait_cycle: false,
            early_warning_severity: RuntimePressureEarlyWarningSeverity::Critical,
        };

        let snapshot = snapshot_with_spectral(spectral);

        assert!(
            snapshot
                .spectral_recommendations
                .iter()
                .any(|recommendation| {
                    recommendation.action
                        == RuntimePressureRecommendationAction::RunTrappedCycleDetection
                        && recommendation.requires_trapped_cycle_proof
                        && !recommendation.deadlock_proven
                })
        );
        assert!(
            snapshot
                .spectral_recommendations
                .iter()
                .any(|recommendation| {
                    recommendation.action == RuntimePressureRecommendationAction::TightenAdmission
                        && recommendation.evidence_scope
                            == RuntimePressureRecommendationEvidenceScope::SpectralTopology
                        && !recommendation.deadlock_proven
                })
        );
    }

    #[test]
    fn runtime_pressure_spectral_recommendations_cover_oscillation_without_deadlock_proof() {
        let spectral = RuntimePressureSpectralSnapshot {
            class: RuntimePressureSpectralClass::Healthy,
            fiedler_micro_units: Some(120_000),
            spectral_gap_bps: Some(2_000),
            spectral_radius_micro_units: Some(1_700_000),
            bottleneck_count: 0,
            components: None,
            approaching_disconnect: false,
            trapped_wait_cycle: false,
            early_warning_severity: RuntimePressureEarlyWarningSeverity::Critical,
        };

        let snapshot = snapshot_with_spectral(spectral);

        assert_eq!(snapshot.spectral_recommendations.len(), 1);
        assert_eq!(
            snapshot.spectral_recommendations[0].action,
            RuntimePressureRecommendationAction::EnableLabReplay
        );
        assert_eq!(
            snapshot.spectral_recommendations[0].evidence_scope,
            RuntimePressureRecommendationEvidenceScope::SpectralTrend
        );
        assert!(!snapshot.spectral_recommendations[0].deadlock_proven);
        assert!(!snapshot.spectral_recommendations[0].requires_trapped_cycle_proof);
    }

    #[test]
    fn runtime_pressure_spectral_recommendations_separate_trapped_cycle_proof() {
        let fragmented = RuntimePressureSpectralSnapshot {
            class: RuntimePressureSpectralClass::Fragmented,
            fiedler_micro_units: Some(0),
            spectral_gap_bps: Some(0),
            spectral_radius_micro_units: Some(2_400_000),
            bottleneck_count: 0,
            components: Some(3),
            approaching_disconnect: false,
            trapped_wait_cycle: false,
            early_warning_severity: RuntimePressureEarlyWarningSeverity::None,
        };
        let deadlocked = RuntimePressureSpectralSnapshot {
            class: RuntimePressureSpectralClass::Deadlocked,
            trapped_wait_cycle: true,
            ..fragmented.clone()
        };

        let fragmented_snapshot = snapshot_with_spectral(fragmented);
        let deadlocked_snapshot = snapshot_with_spectral(deadlocked);

        assert!(
            fragmented_snapshot
                .spectral_recommendations
                .iter()
                .any(|recommendation| {
                    recommendation.action
                        == RuntimePressureRecommendationAction::RunTrappedCycleDetection
                        && recommendation.requires_trapped_cycle_proof
                        && !recommendation.deadlock_proven
                })
        );
        assert!(
            deadlocked_snapshot
                .spectral_recommendations
                .iter()
                .any(|recommendation| {
                    recommendation.action
                        == RuntimePressureRecommendationAction::ConfirmTrappedCycleEvidence
                        && recommendation.evidence_scope
                            == RuntimePressureRecommendationEvidenceScope::ExplicitTrappedCycle
                        && recommendation.deadlock_proven
                        && !recommendation.requires_trapped_cycle_proof
                })
        );
        assert!(
            !deadlocked_snapshot
                .spectral_recommendations
                .iter()
                .any(|recommendation| recommendation.requires_trapped_cycle_proof)
        );
    }

    #[test]
    fn runtime_pressure_spectral_recommendations_sort_and_serialize_stably() {
        let spectral = RuntimePressureSpectralSnapshot {
            class: RuntimePressureSpectralClass::Fragmented,
            fiedler_micro_units: Some(0),
            spectral_gap_bps: Some(0),
            spectral_radius_micro_units: Some(2_100_000),
            bottleneck_count: 2,
            components: Some(4),
            approaching_disconnect: false,
            trapped_wait_cycle: false,
            early_warning_severity: RuntimePressureEarlyWarningSeverity::Warning,
        };

        let snapshot = snapshot_with_spectral(spectral);
        let rows = snapshot
            .spectral_recommendations
            .iter()
            .map(|recommendation| {
                (
                    recommendation.severity,
                    recommendation.reason,
                    recommendation.action,
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(
            rows,
            vec![
                (
                    RuntimePressureRecommendationSeverity::Escalate,
                    RuntimePressureRecommendationReason::FragmentedTopology,
                    RuntimePressureRecommendationAction::RunTrappedCycleDetection,
                ),
                (
                    RuntimePressureRecommendationSeverity::Mitigate,
                    RuntimePressureRecommendationReason::FragmentedTopology,
                    RuntimePressureRecommendationAction::CollectTaskInspectorDetails,
                ),
                (
                    RuntimePressureRecommendationSeverity::Investigate,
                    RuntimePressureRecommendationReason::Bottleneck,
                    RuntimePressureRecommendationAction::InspectSpectralBottlenecks,
                ),
                (
                    RuntimePressureRecommendationSeverity::Investigate,
                    RuntimePressureRecommendationReason::EarlyWarning,
                    RuntimePressureRecommendationAction::EnableLabReplay,
                ),
            ]
        );

        let value = serde_json::to_value(&snapshot).expect("serialize snapshot");
        assert_eq!(
            value["spectral_recommendations"][0]["severity"],
            json!("escalate")
        );
        assert_eq!(
            value["spectral_recommendations"][0]["reason"],
            json!("fragmented_topology")
        );
        assert_eq!(
            value["spectral_recommendations"][0]["requires_trapped_cycle_proof"],
            json!(true)
        );
        assert_eq!(
            value["spectral_recommendations"][3]["evidence_scope"],
            json!("spectral_trend")
        );
    }

    #[test]
    fn runtime_pressure_lab_evidence_covers_required_scenarios() {
        let scenarios = vec![
            healthy_pressure_lab_evidence(),
            cpu_lane_pressure_lab_evidence(),
            resource_fallback_degraded_lab_evidence(),
            region_memory_budget_overrun_lab_evidence(),
            structural_warning_lab_evidence(),
            rch_proof_lane_remote_refusal_lab_evidence(),
        ];

        assert_eq!(
            scenarios
                .iter()
                .map(|evidence| evidence.scenario_kind)
                .collect::<Vec<_>>(),
            vec![
                RuntimePressureLabScenarioKind::Healthy,
                RuntimePressureLabScenarioKind::CpuLanePressure,
                RuntimePressureLabScenarioKind::ResourceFallbackDegraded,
                RuntimePressureLabScenarioKind::RegionMemoryBudgetOverrun,
                RuntimePressureLabScenarioKind::StructuralWarning,
                RuntimePressureLabScenarioKind::RchProofLaneRemoteRefusal,
            ]
        );
        assert!(
            scenarios
                .iter()
                .all(|evidence| evidence.classification_matches_expected)
        );
        assert_eq!(
            scenarios
                .iter()
                .map(|evidence| evidence.observed_verdict)
                .collect::<Vec<_>>(),
            vec![
                RuntimePressureVerdict::Healthy,
                RuntimePressureVerdict::Critical,
                RuntimePressureVerdict::Degraded,
                RuntimePressureVerdict::Critical,
                RuntimePressureVerdict::Critical,
                RuntimePressureVerdict::Critical,
            ]
        );
    }

    #[test]
    fn runtime_pressure_lab_evidence_serializes_stable_projection() {
        let evidence = vec![
            healthy_pressure_lab_evidence(),
            cpu_lane_pressure_lab_evidence(),
            resource_fallback_degraded_lab_evidence(),
            region_memory_budget_overrun_lab_evidence(),
            structural_warning_lab_evidence(),
            rch_proof_lane_remote_refusal_lab_evidence(),
        ];
        let value = serde_json::to_value(&evidence).expect("serialize lab evidence");
        let projection = value
            .as_array()
            .expect("evidence serializes as array")
            .iter()
            .map(|row| {
                json!({
                    "schema_version": row["schema_version"],
                    "scenario_id": row["scenario_id"],
                    "seed": row["seed"],
                    "scenario_kind": row["scenario_kind"],
                    "observed_verdict": row["observed_verdict"],
                    "classification_matches_expected": row["classification_matches_expected"],
                    "diagnostic_labels": row["diagnostic_labels"],
                    "resources": row["snapshot"]["resources"].as_array().map_or(0, Vec::len),
                    "region_memory_budgets": row["snapshot"]["region_memory_budgets"].as_array().map_or(0, Vec::len),
                    "rch_proof_lanes": row["snapshot"]["rch_proof_lanes"].as_array().map_or(0, Vec::len),
                    "critical_signal_count": row["snapshot"]["critical_signal_count"],
                    "degraded_signal_count": row["snapshot"]["degraded_signal_count"],
                    "spectral_class": row["snapshot"]["spectral"]["class"],
                })
            })
            .collect::<Vec<_>>();

        assert_eq!(
            projection,
            vec![
                json!({
                    "schema_version": RUNTIME_PRESSURE_LAB_SCENARIO_EVIDENCE_SCHEMA_VERSION,
                    "scenario_id": "runtime-pressure-lab-healthy",
                    "seed": 1470693377u64,
                    "scenario_kind": "healthy",
                    "observed_verdict": "healthy",
                    "classification_matches_expected": true,
                    "diagnostic_labels": ["all_signals_present"],
                    "resources": 1,
                    "region_memory_budgets": 0,
                    "rch_proof_lanes": 0,
                    "critical_signal_count": 0,
                    "degraded_signal_count": 0,
                    "spectral_class": "healthy",
                }),
                json!({
                    "schema_version": RUNTIME_PRESSURE_LAB_SCENARIO_EVIDENCE_SCHEMA_VERSION,
                    "scenario_id": "runtime-pressure-lab-cpu-lane-pressure",
                    "seed": 1470742545u64,
                    "scenario_kind": "cpu_lane_pressure",
                    "observed_verdict": "critical",
                    "classification_matches_expected": true,
                    "diagnostic_labels": [
                        "cpu_load_hard_limit",
                        "resource_heavy_degradation",
                        "scheduler_tail_pressure",
                    ],
                    "resources": 1,
                    "region_memory_budgets": 0,
                    "rch_proof_lanes": 0,
                    "critical_signal_count": 1,
                    "degraded_signal_count": 1,
                    "spectral_class": "healthy",
                }),
                json!({
                    "schema_version": RUNTIME_PRESSURE_LAB_SCENARIO_EVIDENCE_SCHEMA_VERSION,
                    "scenario_id": "runtime-pressure-lab-resource-fallback-degraded",
                    "seed": 1470757393u64,
                    "scenario_kind": "resource_fallback_degraded",
                    "observed_verdict": "degraded",
                    "classification_matches_expected": true,
                    "diagnostic_labels": [
                        "memory_soft_pressure",
                        "platform_probe_fallback",
                    ],
                    "resources": 1,
                    "region_memory_budgets": 0,
                    "rch_proof_lanes": 0,
                    "critical_signal_count": 0,
                    "degraded_signal_count": 2,
                    "spectral_class": "healthy",
                }),
                json!({
                    "schema_version": RUNTIME_PRESSURE_LAB_SCENARIO_EVIDENCE_SCHEMA_VERSION,
                    "scenario_id": "runtime-pressure-lab-region-memory-budget-overrun",
                    "seed": 1470741209u64,
                    "scenario_kind": "region_memory_budget_overrun",
                    "observed_verdict": "critical",
                    "classification_matches_expected": true,
                    "diagnostic_labels": [
                        "region_memory_budget_advisory",
                        "region_memory_budget_exhausted",
                    ],
                    "resources": 1,
                    "region_memory_budgets": 1,
                    "rch_proof_lanes": 0,
                    "critical_signal_count": 1,
                    "degraded_signal_count": 0,
                    "spectral_class": "healthy",
                }),
                json!({
                    "schema_version": RUNTIME_PRESSURE_LAB_SCENARIO_EVIDENCE_SCHEMA_VERSION,
                    "scenario_id": "runtime-pressure-lab-structural-warning",
                    "seed": 1470715820u64,
                    "scenario_kind": "structural_warning",
                    "observed_verdict": "critical",
                    "classification_matches_expected": true,
                    "diagnostic_labels": [
                        "spectral_fragmented_topology",
                        "trapped_cycle_detection_required",
                    ],
                    "resources": 1,
                    "region_memory_budgets": 0,
                    "rch_proof_lanes": 0,
                    "critical_signal_count": 1,
                    "degraded_signal_count": 0,
                    "spectral_class": "fragmented",
                }),
                json!({
                    "schema_version": RUNTIME_PRESSURE_LAB_SCENARIO_EVIDENCE_SCHEMA_VERSION,
                    "scenario_id": "runtime-pressure-lab-rch-proof-lane-remote-refusal",
                    "seed": 1470725143u64,
                    "scenario_kind": "rch_proof_lane_remote_refusal",
                    "observed_verdict": "critical",
                    "classification_matches_expected": true,
                    "diagnostic_labels": [
                        "local_fallback_refused",
                        "rch_remote_required_refused",
                    ],
                    "resources": 1,
                    "region_memory_budgets": 0,
                    "rch_proof_lanes": 1,
                    "critical_signal_count": 1,
                    "degraded_signal_count": 0,
                    "spectral_class": "healthy",
                }),
            ]
        );
    }

    #[test]
    fn runtime_pressure_lab_evidence_is_reproducible_for_fixed_inputs() {
        let first = structural_warning_lab_evidence();
        let second = structural_warning_lab_evidence();

        assert_eq!(first, second);
        assert_eq!(
            first.stable_json().expect("first json"),
            second.stable_json().expect("second json")
        );
        assert!(
            first
                .snapshot
                .spectral_recommendations
                .iter()
                .any(|recommendation| {
                    recommendation.action
                        == RuntimePressureRecommendationAction::RunTrappedCycleDetection
                        && recommendation.requires_trapped_cycle_proof
                        && !recommendation.deadlock_proven
                })
        );
    }

    #[test]
    fn resource_monitor_builds_runtime_pressure_snapshot() {
        let monitor = ResourceMonitor::new(MonitorConfig::default());
        monitor.pressure().update_measurement(
            ResourceType::Task,
            ResourceMeasurement::new(20, 80, 95, 100),
        );

        let snapshot = monitor.runtime_pressure_snapshot(Some(healthy_scheduler_metrics()), None);

        assert_eq!(
            snapshot.schema_version,
            RUNTIME_PRESSURE_SNAPSHOT_SCHEMA_VERSION
        );
        assert_eq!(snapshot.resources[0].resource_label, "task");
        assert_eq!(
            snapshot
                .scheduler
                .expect("scheduler metrics")
                .ready_backlog_p99,
            48
        );
    }

    #[test]
    fn resource_monitor_folds_externally_captured_rch_receipts() {
        let monitor = ResourceMonitor::new(MonitorConfig::default());
        monitor.pressure().update_measurement(
            ResourceType::Memory,
            ResourceMeasurement::new(40, 80, 95, 100),
        );
        let receipt = admitted_rch_receipt("cargo-test-admission");

        let snapshot = monitor.runtime_pressure_snapshot_with_rch_receipts(
            Some(healthy_scheduler_metrics()),
            None,
            &[receipt],
        );

        assert_eq!(snapshot.rch_proof_lanes.len(), 1);
        assert_eq!(
            snapshot.rch_proof_lanes[0].schema_version,
            RUNTIME_PRESSURE_RCH_PROOF_LANE_SCHEMA_VERSION
        );
        assert_eq!(
            snapshot
                .signal_statuses
                .iter()
                .find(|row| row.signal == RuntimePressureSignal::RchProofLanes)
                .map(|row| row.status),
            Some(RuntimePressureSignalStatus::Present)
        );
        assert!(
            snapshot.rch_proof_lanes[0]
                .reason_codes
                .contains(&"cache_warm_capacity_present".to_string())
        );
    }

    #[test]
    fn runtime_pressure_admission_policy_defaults_to_no_effect() {
        let snapshot = cpu_lane_pressure_lab_evidence().snapshot;
        let decision = RuntimePressureAdmissionPolicy::default()
            .decide(RuntimePressureAdmissionWorkClass::Optional, &snapshot);

        assert_eq!(decision.action, RuntimePressureAdmissionAction::Admit);
        assert!(!decision.policy_enabled);
        assert_eq!(
            decision.reason_codes,
            vec![RuntimePressureAdmissionReason::PolicyDisabled]
        );
        assert_eq!(decision.snapshot_verdict, RuntimePressureVerdict::Critical);
    }

    #[test]
    fn runtime_pressure_admission_defers_optional_work_on_degraded_snapshot() {
        let snapshot = resource_fallback_degraded_lab_evidence().snapshot;
        let policy = RuntimePressureAdmissionPolicy::conservative_optional_backpressure();
        let decision = policy.decide(RuntimePressureAdmissionWorkClass::Optional, &snapshot);

        assert_eq!(decision.action, RuntimePressureAdmissionAction::Defer);
        assert!(decision.policy_enabled);
        assert_eq!(
            decision.reason_codes,
            vec![RuntimePressureAdmissionReason::SnapshotDegraded]
        );
        assert_eq!(decision.degraded_signal_count, 2);
    }

    #[test]
    fn runtime_pressure_admission_rejects_optional_work_on_critical_snapshot() {
        let snapshot = structural_warning_lab_evidence().snapshot;
        let policy = RuntimePressureAdmissionPolicy::conservative_optional_backpressure();
        let decision = policy.decide(RuntimePressureAdmissionWorkClass::Optional, &snapshot);

        assert_eq!(decision.action, RuntimePressureAdmissionAction::Reject);
        assert_eq!(
            decision.reason_codes,
            vec![RuntimePressureAdmissionReason::SnapshotCritical]
        );
        assert_eq!(decision.critical_signal_count, 1);
    }

    #[test]
    fn runtime_pressure_admission_keeps_required_work_on_memory_budget_pressure() {
        let pressure = ResourcePressure::new();
        pressure.update_measurement(
            ResourceType::Memory,
            ResourceMeasurement::new(32, 80, 95, 100),
        );
        let snapshot = RuntimePressureSnapshot::from_parts_with_region_memory_budgets(
            &pressure,
            complete_platform_probe_report(),
            Some(healthy_scheduler_metrics()),
            Some(healthy_spectral_snapshot()),
            vec![RuntimePressureRegionMemoryBudgetSnapshot::with_label(
                RegionId::new_ephemeral(),
                "cleanup-region",
                1_000,
                1_100,
            )],
        );
        let policy = RuntimePressureAdmissionPolicy::conservative_optional_backpressure();

        let optional = policy.decide(RuntimePressureAdmissionWorkClass::Optional, &snapshot);
        assert_eq!(optional.action, RuntimePressureAdmissionAction::Reject);
        assert_eq!(
            optional.reason_codes,
            vec![RuntimePressureAdmissionReason::SnapshotCritical]
        );

        let required = policy.decide(RuntimePressureAdmissionWorkClass::Required, &snapshot);
        assert_eq!(required.action, RuntimePressureAdmissionAction::Admit);
        assert_eq!(
            required.reason_codes,
            vec![RuntimePressureAdmissionReason::RequiredWorkBypass]
        );
        assert_eq!(required.critical_signal_count, 1);
    }

    #[test]
    fn runtime_pressure_admission_required_work_bypasses_critical_and_unknown_schema() {
        let mut snapshot = cpu_lane_pressure_lab_evidence().snapshot;
        snapshot.schema_version = "asupersync.runtime-pressure-snapshot.future".to_string();
        let policy = RuntimePressureAdmissionPolicy::conservative_optional_backpressure();
        let decision = policy.decide(RuntimePressureAdmissionWorkClass::Required, &snapshot);

        assert_eq!(decision.action, RuntimePressureAdmissionAction::Admit);
        assert_eq!(
            decision.reason_codes,
            vec![
                RuntimePressureAdmissionReason::RequiredWorkBypass,
                RuntimePressureAdmissionReason::UnknownSnapshotSchema,
            ]
        );
        assert_eq!(
            decision.snapshot_schema_version,
            "asupersync.runtime-pressure-snapshot.future"
        );
    }

    #[test]
    fn runtime_pressure_admission_fails_closed_for_unknown_optional_schema() {
        let mut snapshot = healthy_pressure_lab_evidence().snapshot;
        snapshot.schema_version = "asupersync.runtime-pressure-snapshot.future".to_string();
        let policy = RuntimePressureAdmissionPolicy::conservative_optional_backpressure();
        let decision = policy.decide(RuntimePressureAdmissionWorkClass::Optional, &snapshot);

        assert_eq!(decision.action, RuntimePressureAdmissionAction::Reject);
        assert_eq!(
            decision.reason_codes,
            vec![RuntimePressureAdmissionReason::UnknownSnapshotSchema]
        );
        assert_eq!(decision.snapshot_verdict, RuntimePressureVerdict::Healthy);
    }

    #[test]
    fn runtime_pressure_admission_marks_missing_signals_without_accepting_unknown_snapshot() {
        let snapshot = RuntimePressureSnapshot::from_parts(
            &ResourcePressure::new(),
            ResourcePlatformProbeReport::from_snapshots("test/noarch".to_string(), Vec::new()),
            None,
            None,
        );
        let policy = RuntimePressureAdmissionPolicy::conservative_optional_backpressure();
        let decision = policy.decide(RuntimePressureAdmissionWorkClass::Optional, &snapshot);

        assert_eq!(decision.action, RuntimePressureAdmissionAction::Defer);
        assert_eq!(
            decision.reason_codes,
            vec![
                RuntimePressureAdmissionReason::SnapshotUnknown,
                RuntimePressureAdmissionReason::MissingPressureSignals,
            ]
        );
        assert_eq!(decision.missing_signal_count, 4);
    }

    #[test]
    fn runtime_pressure_admission_is_deterministic_for_fixed_snapshots() {
        let snapshot = structural_warning_lab_evidence().snapshot;
        let policy = RuntimePressureAdmissionPolicy::conservative_optional_backpressure();
        let first = policy.decide(RuntimePressureAdmissionWorkClass::Optional, &snapshot);

        for _ in 0..8 {
            let next = policy.decide(RuntimePressureAdmissionWorkClass::Optional, &snapshot);
            assert_eq!(first, next);
        }

        let json = serde_json::to_string_pretty(&first).expect("serialize decision");
        let reparsed: RuntimePressureAdmissionDecision =
            serde_json::from_str(&json).expect("deserialize decision");
        assert_eq!(reparsed, first);
    }

    #[test]
    fn runtime_pressure_admission_helper_uses_resource_monitor_snapshot() {
        let monitor = ResourceMonitor::new(MonitorConfig::default());
        monitor.pressure().update_measurement(
            ResourceType::Memory,
            ResourceMeasurement::new(32, 80, 90, 100),
        );
        let policy = RuntimePressureAdmissionPolicy::conservative_optional_backpressure();
        let decision = monitor.pressure_admission_decision(
            &policy,
            RuntimePressureAdmissionWorkClass::Optional,
            Some(healthy_scheduler_metrics()),
            None,
        );

        assert_eq!(decision.action, RuntimePressureAdmissionAction::Defer);
        assert_eq!(decision.snapshot_verdict, RuntimePressureVerdict::Unknown);
        assert!(
            decision
                .reason_codes
                .contains(&RuntimePressureAdmissionReason::MissingPressureSignals)
        );
    }

    #[test]
    fn tail_risk_admission_falls_back_when_evidence_is_missing() {
        let ledger = TailRiskAdmissionLedger::evaluate(
            &TailRiskAdmissionEvidence {
                scheduler: None,
                retry_pressure_p99: Some(12),
                memory_pressure_bps: Some(7_200),
                degradation_level: DegradationLevel::Moderate,
            },
            &TailRiskAdmissionProfile::default(),
        );
        assert!(
            ledger.fallback_used,
            "missing evidence must trigger fallback"
        );
        assert_eq!(ledger.decision, TailRiskAdmissionDecision::Defer);
        assert_eq!(
            ledger.reason_codes,
            vec![TailRiskAdmissionReason::ConservativeFallback]
        );
        assert_eq!(
            ledger.missing_evidence_fields,
            vec!["scheduler_metrics".to_string()]
        );
    }

    #[test]
    fn tail_risk_admission_is_deterministic_for_fixed_inputs() {
        let evidence = TailRiskAdmissionEvidence {
            scheduler: Some(sample_scheduler_metrics()),
            retry_pressure_p99: Some(40),
            memory_pressure_bps: Some(8_700),
            degradation_level: DegradationLevel::Moderate,
        };
        let profile = TailRiskAdmissionProfile::default();
        let first = TailRiskAdmissionLedger::evaluate(&evidence, &profile);
        for _ in 0..8 {
            let next = TailRiskAdmissionLedger::evaluate(&evidence, &profile);
            assert_eq!(first, next, "fixed evidence must stay deterministic");
        }
    }

    #[test]
    fn tail_risk_admission_transitions_across_overload_bands() {
        let profile = TailRiskAdmissionProfile::default();
        let mild = TailRiskAdmissionLedger::evaluate(
            &TailRiskAdmissionEvidence {
                scheduler: Some(SchedulerEvidenceMetrics {
                    wake_to_run_p50_ns: 6_000,
                    wake_to_run_p95_ns: 50_000,
                    wake_to_run_p99_ns: 80_000,
                    queue_residency_p50_ns: 10_000,
                    queue_residency_p95_ns: 90_000,
                    queue_residency_p99_ns: 140_000,
                    ready_backlog_p95: 96,
                    ready_backlog_p99: 120,
                    cancel_debt_p95: 24,
                    cancel_debt_p99: 40,
                    remote_steal_ratio_pct: Some(18),
                    cross_cohort_wake_p99_ns: Some(80_000),
                }),
                retry_pressure_p99: Some(6),
                memory_pressure_bps: Some(6_800),
                degradation_level: DegradationLevel::None,
            },
            &profile,
        );
        let medium = TailRiskAdmissionLedger::evaluate(
            &TailRiskAdmissionEvidence {
                scheduler: Some(SchedulerEvidenceMetrics {
                    wake_to_run_p50_ns: 8_000,
                    wake_to_run_p95_ns: 90_000,
                    wake_to_run_p99_ns: 170_000,
                    queue_residency_p50_ns: 16_000,
                    queue_residency_p95_ns: 220_000,
                    queue_residency_p99_ns: 420_000,
                    ready_backlog_p95: 188,
                    ready_backlog_p99: 220,
                    cancel_debt_p95: 42,
                    cancel_debt_p99: 78,
                    remote_steal_ratio_pct: Some(34),
                    cross_cohort_wake_p99_ns: Some(140_000),
                }),
                retry_pressure_p99: Some(36),
                memory_pressure_bps: Some(7_900),
                degradation_level: DegradationLevel::Light,
            },
            &profile,
        );
        let severe = TailRiskAdmissionLedger::evaluate(
            &TailRiskAdmissionEvidence {
                scheduler: Some(sample_scheduler_metrics()),
                retry_pressure_p99: Some(52),
                memory_pressure_bps: Some(9_450),
                degradation_level: DegradationLevel::Heavy,
            },
            &profile,
        );
        assert_eq!(mild.decision, TailRiskAdmissionDecision::Admit);
        assert_eq!(medium.decision, TailRiskAdmissionDecision::Defer);
        assert_eq!(severe.decision, TailRiskAdmissionDecision::Shed);
    }

    #[test]
    fn tail_risk_admission_ledger_round_trips_through_json() {
        let ledger = TailRiskAdmissionLedger::evaluate(
            &TailRiskAdmissionEvidence {
                scheduler: Some(sample_scheduler_metrics()),
                retry_pressure_p99: Some(40),
                memory_pressure_bps: Some(8_700),
                degradation_level: DegradationLevel::Moderate,
            },
            &TailRiskAdmissionProfile::default(),
        );
        let json = serde_json::to_string_pretty(&ledger).expect("serialize ledger");
        let reparsed: TailRiskAdmissionLedger =
            serde_json::from_str(&json).expect("deserialize ledger");
        assert_eq!(reparsed, ledger);
    }

    #[test]
    fn tail_risk_admission_sheds_on_tail_and_memory_storm() {
        let ledger = TailRiskAdmissionLedger::evaluate(
            &TailRiskAdmissionEvidence {
                scheduler: Some(sample_scheduler_metrics()),
                retry_pressure_p99: Some(48),
                memory_pressure_bps: Some(9_400),
                degradation_level: DegradationLevel::Heavy,
            },
            &TailRiskAdmissionProfile::default(),
        );
        assert_eq!(ledger.decision, TailRiskAdmissionDecision::Shed);
        assert!(!ledger.fallback_used);
        assert!(
            ledger
                .reason_codes
                .contains(&TailRiskAdmissionReason::MemoryPressure)
        );
        assert!(
            ledger
                .reason_codes
                .contains(&TailRiskAdmissionReason::QueueResidencyTail)
        );
    }

    #[test]
    fn degradation_engine_evaluates_tail_risk_admission_from_pressure_band() {
        let pressure = Arc::new(ResourcePressure::new());
        let engine = DegradationEngine::new(Arc::clone(&pressure));
        pressure.update_degradation_level(ResourceType::Memory, DegradationLevel::Moderate);
        let ledger = engine.evaluate_tail_risk_admission(
            Some(&sample_scheduler_metrics()),
            Some(40),
            Some(8_300),
            &TailRiskAdmissionProfile::default(),
        );
        assert_eq!(ledger.degradation_level, DegradationLevel::Moderate);
        assert_eq!(ledger.decision, TailRiskAdmissionDecision::Shed);
        assert!(
            ledger
                .reason_codes
                .contains(&TailRiskAdmissionReason::ExistingDegradation)
        );
    }

    const TAIL_RISK_ADMISSION_CONTRACT_PATH_ENV: &str =
        "ASUPERSYNC_TAIL_RISK_ADMISSION_CONTRACT_PATH";
    const TAIL_RISK_ADMISSION_SCENARIO_ENV: &str = "ASUPERSYNC_TAIL_RISK_ADMISSION_SCENARIO";
    const TAIL_RISK_ADMISSION_REPORT_PATH_ENV: &str = "ASUPERSYNC_TAIL_RISK_ADMISSION_REPORT_PATH";
    const TAIL_RISK_ADMISSION_REPORT_SCHEMA_VERSION: &str = "tail-risk-admission-report-v1";
    const TAIL_RISK_ADMISSION_PROJECTION_SCHEMA_VERSION: &str = "tail-risk-admission-projection-v1";
    const TAIL_RISK_ADMISSION_MIXED_SCENARIO_ID: &str = "AA-TAIL-RISK-ADMISSION-MIXED-OVERLOAD";
    const TAIL_RISK_ADMISSION_FALLBACK_SCENARIO_ID: &str =
        "AA-TAIL-RISK-ADMISSION-CONSERVATIVE-FALLBACK";

    #[derive(Debug, Clone, Deserialize)]
    struct TailRiskAdmissionSmokeContract {
        smoke_scenarios: Vec<TailRiskAdmissionScenario>,
    }

    #[derive(Debug, Clone, Deserialize)]
    struct TailRiskAdmissionScenario {
        scenario_id: String,
        description: String,
        workload_class: String,
        tail_risk_profile: TailRiskAdmissionProfile,
        fixed_threshold_profile: FixedThresholdAdmissionProfile,
        fixture: TailRiskAdmissionFixture,
        expected_report_projection: Value,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct FixedThresholdAdmissionProfile {
        ready_backlog_soft_limit: usize,
        ready_backlog_hard_limit: usize,
        memory_pressure_soft_bps: u16,
        memory_pressure_hard_bps: u16,
        moderate_degradation_sheds: bool,
    }

    #[derive(Debug, Clone, Deserialize)]
    struct TailRiskAdmissionFixture {
        base_service_ns: u64,
        replay_count: usize,
        windows: Vec<TailRiskAdmissionWindow>,
    }

    #[derive(Debug, Clone, Deserialize)]
    struct TailRiskAdmissionWindow {
        window_id: String,
        wake_to_run_p99_ns: Option<u64>,
        queue_residency_p99_ns: Option<u64>,
        ready_backlog_p99: Option<usize>,
        cancel_debt_p99: Option<usize>,
        retry_pressure_p99: Option<u64>,
        memory_pressure_bps: Option<u16>,
        degradation_level: DegradationLevel,
        offered_work_units: u64,
    }

    #[derive(Debug, Clone, Serialize)]
    struct PolicySummary {
        decision_counts: Value,
        admitted_units: u64,
        deferred_units: u64,
        shed_units: u64,
        fallback_used_count: u64,
        mean_expected_loss_score: f64,
        p50_latency_ns: u64,
        p95_latency_ns: u64,
        p99_latency_ns: u64,
        max_latency_ns: u64,
        throughput_ratio: f64,
    }

    #[derive(Debug, Clone)]
    struct PolicyAccumulator {
        admit_count: u64,
        defer_count: u64,
        shed_count: u64,
        admitted_units: u64,
        deferred_units: u64,
        shed_units: u64,
        fallback_used_count: u64,
        loss_score_sum: u64,
        loss_score_count: u64,
        latencies: Vec<u64>,
    }

    impl PolicyAccumulator {
        fn record(
            &mut self,
            decision: TailRiskAdmissionDecision,
            fallback_used: bool,
            expected_loss_score: u8,
            outcome: &WindowOutcome,
        ) {
            match decision {
                TailRiskAdmissionDecision::Admit => self.admit_count += 1,
                TailRiskAdmissionDecision::Defer => self.defer_count += 1,
                TailRiskAdmissionDecision::Shed => self.shed_count += 1,
            }
            self.admitted_units = self.admitted_units.saturating_add(outcome.admitted_units);
            self.deferred_units = self.deferred_units.saturating_add(outcome.deferred_units);
            self.shed_units = self.shed_units.saturating_add(outcome.shed_units);
            if fallback_used {
                self.fallback_used_count += 1;
            }
            self.loss_score_sum = self
                .loss_score_sum
                .saturating_add(u64::from(expected_loss_score));
            self.loss_score_count += 1;
            self.latencies.extend_from_slice(&outcome.latency_samples);
        }

        fn summary(&self, total_offered_units: u64) -> PolicySummary {
            PolicySummary {
                decision_counts: json!({
                    "admit": self.admit_count,
                    "defer": self.defer_count,
                    "shed": self.shed_count,
                }),
                admitted_units: self.admitted_units,
                deferred_units: self.deferred_units,
                shed_units: self.shed_units,
                fallback_used_count: self.fallback_used_count,
                mean_expected_loss_score: ratio_u64(self.loss_score_sum, self.loss_score_count),
                p50_latency_ns: percentile_slice_u64(&self.latencies, 50, 100),
                p95_latency_ns: percentile_slice_u64(&self.latencies, 95, 100),
                p99_latency_ns: percentile_slice_u64(&self.latencies, 99, 100),
                max_latency_ns: self.latencies.iter().copied().max().unwrap_or(0),
                throughput_ratio: ratio_u64(self.admitted_units, total_offered_units),
            }
        }
    }

    #[derive(Debug, Clone)]
    struct WindowOutcome {
        admitted_units: u64,
        deferred_units: u64,
        shed_units: u64,
        latency_samples: Vec<u64>,
    }

    fn default_tail_risk_admission_scenarios() -> Vec<TailRiskAdmissionScenario> {
        vec![
            TailRiskAdmissionScenario {
                scenario_id: TAIL_RISK_ADMISSION_MIXED_SCENARIO_ID.to_string(),
                description: "Drive a deterministic mixed overload replay covering balanced traffic, retry storms, backlog spikes, and memory pressure while comparing the tail-risk controller against a fixed-threshold baseline.".to_string(),
                workload_class: "mixed-overload".to_string(),
                tail_risk_profile: TailRiskAdmissionProfile::default(),
                fixed_threshold_profile: FixedThresholdAdmissionProfile {
                    ready_backlog_soft_limit: 256,
                    ready_backlog_hard_limit: 320,
                    memory_pressure_soft_bps: 8_200,
                    memory_pressure_hard_bps: 9_200,
                    moderate_degradation_sheds: false,
                },
                fixture: TailRiskAdmissionFixture {
                    base_service_ns: 48_000,
                    replay_count: 2,
                    windows: vec![
                        TailRiskAdmissionWindow {
                            window_id: "steady".to_string(),
                            wake_to_run_p99_ns: Some(92_000),
                            queue_residency_p99_ns: Some(180_000),
                            ready_backlog_p99: Some(144),
                            cancel_debt_p99: Some(38),
                            retry_pressure_p99: Some(8),
                            memory_pressure_bps: Some(6_700),
                            degradation_level: DegradationLevel::None,
                            offered_work_units: 64,
                        },
                        TailRiskAdmissionWindow {
                            window_id: "retry_storm".to_string(),
                            wake_to_run_p99_ns: Some(176_000),
                            queue_residency_p99_ns: Some(430_000),
                            ready_backlog_p99: Some(224),
                            cancel_debt_p99: Some(72),
                            retry_pressure_p99: Some(41),
                            memory_pressure_bps: Some(7_800),
                            degradation_level: DegradationLevel::Light,
                            offered_work_units: 64,
                        },
                        TailRiskAdmissionWindow {
                            window_id: "backlog_and_cancel".to_string(),
                            wake_to_run_p99_ns: Some(164_000),
                            queue_residency_p99_ns: Some(360_000),
                            ready_backlog_p99: Some(248),
                            cancel_debt_p99: Some(118),
                            retry_pressure_p99: Some(22),
                            memory_pressure_bps: Some(7_950),
                            degradation_level: DegradationLevel::Moderate,
                            offered_work_units: 64,
                        },
                        TailRiskAdmissionWindow {
                            window_id: "memory_surge".to_string(),
                            wake_to_run_p99_ns: Some(236_000),
                            queue_residency_p99_ns: Some(540_000),
                            ready_backlog_p99: Some(308),
                            cancel_debt_p99: Some(132),
                            retry_pressure_p99: Some(55),
                            memory_pressure_bps: Some(9_450),
                            degradation_level: DegradationLevel::Heavy,
                            offered_work_units: 64,
                        },
                    ],
                },
                expected_report_projection: Value::Null,
            },
            TailRiskAdmissionScenario {
                scenario_id: TAIL_RISK_ADMISSION_FALLBACK_SCENARIO_ID.to_string(),
                description: "Remove key evidence fields and prove the controller falls back deterministically to the conservative degradation-band comparator with explicit missing-field explanations.".to_string(),
                workload_class: "low-confidence-fallback".to_string(),
                tail_risk_profile: TailRiskAdmissionProfile::default(),
                fixed_threshold_profile: FixedThresholdAdmissionProfile {
                    ready_backlog_soft_limit: 256,
                    ready_backlog_hard_limit: 320,
                    memory_pressure_soft_bps: 8_200,
                    memory_pressure_hard_bps: 9_200,
                    moderate_degradation_sheds: false,
                },
                fixture: TailRiskAdmissionFixture {
                    base_service_ns: 48_000,
                    replay_count: 1,
                    windows: vec![
                        TailRiskAdmissionWindow {
                            window_id: "missing_scheduler".to_string(),
                            wake_to_run_p99_ns: None,
                            queue_residency_p99_ns: None,
                            ready_backlog_p99: None,
                            cancel_debt_p99: None,
                            retry_pressure_p99: Some(18),
                            memory_pressure_bps: Some(7_500),
                            degradation_level: DegradationLevel::Moderate,
                            offered_work_units: 48,
                        },
                        TailRiskAdmissionWindow {
                            window_id: "missing_retry".to_string(),
                            wake_to_run_p99_ns: Some(128_000),
                            queue_residency_p99_ns: Some(240_000),
                            ready_backlog_p99: Some(180),
                            cancel_debt_p99: Some(52),
                            retry_pressure_p99: None,
                            memory_pressure_bps: Some(7_200),
                            degradation_level: DegradationLevel::Light,
                            offered_work_units: 48,
                        },
                        TailRiskAdmissionWindow {
                            window_id: "invalid_memory".to_string(),
                            wake_to_run_p99_ns: Some(156_000),
                            queue_residency_p99_ns: Some(280_000),
                            ready_backlog_p99: Some(196),
                            cancel_debt_p99: Some(66),
                            retry_pressure_p99: Some(20),
                            memory_pressure_bps: None,
                            degradation_level: DegradationLevel::Heavy,
                            offered_work_units: 48,
                        },
                    ],
                },
                expected_report_projection: Value::Null,
            },
        ]
    }

    fn load_tail_risk_admission_scenarios() -> Vec<TailRiskAdmissionScenario> {
        let Some(contract_path) = std::env::var(TAIL_RISK_ADMISSION_CONTRACT_PATH_ENV).ok() else {
            return default_tail_risk_admission_scenarios();
        };
        let contract: TailRiskAdmissionSmokeContract = serde_json::from_str(
            &fs::read_to_string(&contract_path).expect("read tail-risk admission contract"),
        )
        .expect("parse tail-risk admission contract");
        contract.smoke_scenarios
    }

    fn selected_tail_risk_admission_scenario() -> String {
        std::env::var(TAIL_RISK_ADMISSION_SCENARIO_ENV)
            .unwrap_or_else(|_| TAIL_RISK_ADMISSION_MIXED_SCENARIO_ID.to_string())
    }

    fn maybe_write_tail_risk_admission_report(path: &str, report: &Value) {
        let report_path = Path::new(path);
        if let Some(parent) = report_path.parent() {
            fs::create_dir_all(parent).expect("create tail-risk admission report directory");
        }
        fs::write(
            report_path,
            serde_json::to_string_pretty(report).expect("serialize tail-risk admission report"),
        )
        .expect("write tail-risk admission report");
    }

    fn ratio_u64(numerator: u64, denominator: u64) -> f64 {
        if denominator == 0 {
            return 0.0;
        }
        round4(numerator as f64 / denominator as f64)
    }

    fn round4(value: f64) -> f64 {
        (value * 10_000.0).round() / 10_000.0
    }

    fn percentile_slice_u64(samples: &[u64], numerator: usize, denominator: usize) -> u64 {
        if samples.is_empty() {
            return 0;
        }
        let mut sorted = samples.to_vec();
        sorted.sort_unstable();
        let index = ((sorted.len() - 1) * numerator) / denominator;
        sorted[index]
    }

    fn sample_scheduler_metrics_from_window(
        window: &TailRiskAdmissionWindow,
        window_index: usize,
    ) -> Option<SchedulerEvidenceMetrics> {
        Some(SchedulerEvidenceMetrics {
            wake_to_run_p50_ns: window.wake_to_run_p99_ns?.saturating_div(10).max(1),
            wake_to_run_p95_ns: window
                .wake_to_run_p99_ns?
                .saturating_mul(8)
                .saturating_div(10),
            wake_to_run_p99_ns: window.wake_to_run_p99_ns?,
            queue_residency_p50_ns: window.queue_residency_p99_ns?.saturating_div(8).max(1),
            queue_residency_p95_ns: window
                .queue_residency_p99_ns?
                .saturating_mul(8)
                .saturating_div(10),
            queue_residency_p99_ns: window.queue_residency_p99_ns?,
            ready_backlog_p95: window
                .ready_backlog_p99?
                .saturating_sub(window.ready_backlog_p99?.saturating_div(6)),
            ready_backlog_p99: window.ready_backlog_p99?,
            cancel_debt_p95: window
                .cancel_debt_p99?
                .saturating_sub(window.cancel_debt_p99?.saturating_div(5)),
            cancel_debt_p99: window.cancel_debt_p99?,
            remote_steal_ratio_pct: Some((25 + window_index * 7) as u8),
            cross_cohort_wake_p99_ns: window
                .wake_to_run_p99_ns
                .map(|value| value.saturating_sub(12_000)),
        })
    }

    fn fixed_threshold_decision(
        window: &TailRiskAdmissionWindow,
        profile: &FixedThresholdAdmissionProfile,
    ) -> (TailRiskAdmissionDecision, Vec<&'static str>) {
        let mut reasons = Vec::new();
        if window.memory_pressure_bps.unwrap_or(10_001) >= profile.memory_pressure_hard_bps {
            reasons.push("memory_hard_limit");
        }
        if window.ready_backlog_p99.unwrap_or(usize::MAX) >= profile.ready_backlog_hard_limit {
            reasons.push("backlog_hard_limit");
        }
        if window.degradation_level >= DegradationLevel::Heavy
            || (profile.moderate_degradation_sheds
                && window.degradation_level >= DegradationLevel::Moderate)
        {
            reasons.push("degradation_band");
        }
        if !reasons.is_empty() {
            return (TailRiskAdmissionDecision::Shed, reasons);
        }

        if window
            .memory_pressure_bps
            .unwrap_or(profile.memory_pressure_soft_bps)
            >= profile.memory_pressure_soft_bps
        {
            reasons.push("memory_soft_limit");
        }
        if window
            .ready_backlog_p99
            .unwrap_or(profile.ready_backlog_soft_limit)
            >= profile.ready_backlog_soft_limit
        {
            reasons.push("backlog_soft_limit");
        }
        if window.degradation_level >= DegradationLevel::Moderate {
            reasons.push("moderate_degradation");
        }
        if !reasons.is_empty() {
            return (TailRiskAdmissionDecision::Defer, reasons);
        }

        (TailRiskAdmissionDecision::Admit, vec!["steady_state"])
    }

    fn simulate_window_outcome(
        decision: TailRiskAdmissionDecision,
        fixture: &TailRiskAdmissionFixture,
        window: &TailRiskAdmissionWindow,
        window_index: usize,
    ) -> WindowOutcome {
        let offered = window.offered_work_units;
        let (admitted_units, deferred_units, shed_units, overload_multiplier, decision_penalty) =
            match decision {
                TailRiskAdmissionDecision::Admit => (offered, 0, 0, 9_200, 18_000),
                TailRiskAdmissionDecision::Defer => (
                    offered.saturating_mul(78).saturating_div(100),
                    offered.saturating_sub(offered.saturating_mul(78).saturating_div(100)),
                    0,
                    6_200,
                    11_000,
                ),
                TailRiskAdmissionDecision::Shed => (
                    offered.saturating_mul(38).saturating_div(100),
                    0,
                    offered.saturating_sub(offered.saturating_mul(38).saturating_div(100)),
                    4_100,
                    7_000,
                ),
            };
        let wake = window.wake_to_run_p99_ns.unwrap_or(120_000);
        let queue = window.queue_residency_p99_ns.unwrap_or(260_000);
        let backlog = window.ready_backlog_p99.unwrap_or(180) as u64;
        let cancel_debt = window.cancel_debt_p99.unwrap_or(64) as u64;
        let retry = window.retry_pressure_p99.unwrap_or(18);
        let memory = u64::from(window.memory_pressure_bps.unwrap_or(7_500));
        let degradation = match window.degradation_level {
            DegradationLevel::None => 0,
            DegradationLevel::Light => 8,
            DegradationLevel::Moderate => 18,
            DegradationLevel::Heavy => 28,
            DegradationLevel::Emergency => 42,
        };
        let overload_score = wake.saturating_div(20_000)
            + queue.saturating_div(40_000)
            + backlog.saturating_div(14)
            + cancel_debt.saturating_div(9)
            + retry.saturating_mul(2)
            + memory.saturating_div(450)
            + degradation;
        let base_latency = fixture
            .base_service_ns
            .saturating_add(wake.saturating_div(3))
            .saturating_add(queue.saturating_div(4));

        let mut latency_samples = Vec::with_capacity(admitted_units as usize);
        for sample_idx in 0..admitted_units {
            let jitter = ((window_index as u64 * 19) + (sample_idx % 11) * 13).saturating_mul(157);
            let latency = base_latency
                .saturating_add(overload_score.saturating_mul(overload_multiplier))
                .saturating_add(decision_penalty)
                .saturating_add(jitter);
            latency_samples.push(latency);
        }

        WindowOutcome {
            admitted_units,
            deferred_units,
            shed_units,
            latency_samples,
        }
    }

    fn tail_risk_reason_label(reason: TailRiskAdmissionReason) -> &'static str {
        match reason {
            TailRiskAdmissionReason::WakeToRunTail => "wake_to_run_tail",
            TailRiskAdmissionReason::QueueResidencyTail => "queue_residency_tail",
            TailRiskAdmissionReason::BacklogPressure => "backlog_pressure",
            TailRiskAdmissionReason::CancelDebtPressure => "cancel_debt_pressure",
            TailRiskAdmissionReason::RetryPressure => "retry_pressure",
            TailRiskAdmissionReason::MemoryPressure => "memory_pressure",
            TailRiskAdmissionReason::ExistingDegradation => "existing_degradation",
            TailRiskAdmissionReason::ConservativeFallback => "conservative_fallback",
            TailRiskAdmissionReason::BalancedBaseline => "balanced_baseline",
        }
    }

    fn hash_json_value(value: &Value) -> u64 {
        let mut hasher = DefaultHasher::new();
        serde_json::to_string(value)
            .expect("serialize projection for hashing")
            .hash(&mut hasher);
        hasher.finish()
    }

    fn build_tail_risk_admission_report(
        scenario: &TailRiskAdmissionScenario,
        include_hash_probe: bool,
    ) -> Value {
        let total_offered_units = scenario
            .fixture
            .windows
            .iter()
            .map(|window| window.offered_work_units)
            .sum::<u64>()
            .saturating_mul(scenario.fixture.replay_count as u64);
        let evidence_vector_fields = json!([
            "wake_to_run_p99_ns",
            "queue_residency_p99_ns",
            "ready_backlog_p99",
            "cancel_debt_p99",
            "retry_pressure_p99",
            "memory_pressure_bps",
            "degradation_level"
        ]);

        let mut tail_risk = PolicyAccumulator {
            admit_count: 0,
            defer_count: 0,
            shed_count: 0,
            admitted_units: 0,
            deferred_units: 0,
            shed_units: 0,
            fallback_used_count: 0,
            loss_score_sum: 0,
            loss_score_count: 0,
            latencies: Vec::new(),
        };
        let mut fixed_threshold = tail_risk.clone();
        let mut window_reports = Vec::new();
        let mut fallback_windows = Vec::new();
        let mut tail_risk_decisions = Vec::new();
        let mut fixed_threshold_decisions = Vec::new();

        for replay_index in 0..scenario.fixture.replay_count {
            for (window_index, window) in scenario.fixture.windows.iter().enumerate() {
                let evidence = TailRiskAdmissionEvidence {
                    scheduler: sample_scheduler_metrics_from_window(window, window_index),
                    retry_pressure_p99: window.retry_pressure_p99,
                    memory_pressure_bps: window.memory_pressure_bps,
                    degradation_level: window.degradation_level,
                };
                let ledger =
                    TailRiskAdmissionLedger::evaluate(&evidence, &scenario.tail_risk_profile);
                let (baseline_decision, baseline_reasons) =
                    fixed_threshold_decision(window, &scenario.fixed_threshold_profile);

                let tail_outcome = simulate_window_outcome(
                    ledger.decision,
                    &scenario.fixture,
                    window,
                    window_index,
                );
                let baseline_outcome = simulate_window_outcome(
                    baseline_decision,
                    &scenario.fixture,
                    window,
                    window_index,
                );

                tail_risk.record(
                    ledger.decision,
                    ledger.fallback_used,
                    ledger.expected_loss_score,
                    &tail_outcome,
                );
                fixed_threshold.record(baseline_decision, false, 0, &baseline_outcome);

                if replay_index == 0 {
                    tail_risk_decisions.push(format!("{:?}", ledger.decision).to_lowercase());
                    fixed_threshold_decisions
                        .push(format!("{:?}", baseline_decision).to_lowercase());
                    if ledger.fallback_used {
                        fallback_windows.push(window.window_id.clone());
                    }
                    window_reports.push(json!({
                        "window_id": window.window_id,
                        "evidence_vector": {
                            "wake_to_run_p99_ns": window.wake_to_run_p99_ns,
                            "queue_residency_p99_ns": window.queue_residency_p99_ns,
                            "ready_backlog_p99": window.ready_backlog_p99,
                            "cancel_debt_p99": window.cancel_debt_p99,
                            "retry_pressure_p99": window.retry_pressure_p99,
                            "memory_pressure_bps": window.memory_pressure_bps,
                            "degradation_level": format!("{:?}", window.degradation_level).to_lowercase(),
                        },
                        "tail_risk": {
                            "decision": format!("{:?}", ledger.decision).to_lowercase(),
                            "fallback_used": ledger.fallback_used,
                            "expected_loss_score": ledger.expected_loss_score,
                            "confidence_percent": ledger.confidence_percent,
                            "reason_codes": ledger.reason_codes.iter().map(|reason| tail_risk_reason_label(*reason)).collect::<Vec<_>>(),
                            "missing_evidence_fields": ledger.missing_evidence_fields,
                            "admitted_units": tail_outcome.admitted_units,
                            "deferred_units": tail_outcome.deferred_units,
                            "shed_units": tail_outcome.shed_units,
                            "window_p99_ns": percentile_slice_u64(&tail_outcome.latency_samples, 99, 100),
                        },
                        "fixed_threshold": {
                            "decision": format!("{:?}", baseline_decision).to_lowercase(),
                            "reason_codes": baseline_reasons,
                            "admitted_units": baseline_outcome.admitted_units,
                            "deferred_units": baseline_outcome.deferred_units,
                            "shed_units": baseline_outcome.shed_units,
                            "window_p99_ns": percentile_slice_u64(&baseline_outcome.latency_samples, 99, 100),
                        }
                    }));
                }
            }
        }

        let tail_summary = tail_risk.summary(total_offered_units);
        let fixed_summary = fixed_threshold.summary(total_offered_units);
        let report_projection = json!({
            "schema_version": TAIL_RISK_ADMISSION_PROJECTION_SCHEMA_VERSION,
            "scenario_id": scenario.scenario_id,
            "workload_class": scenario.workload_class,
            "replay_count": scenario.fixture.replay_count,
            "window_count": scenario.fixture.windows.len(),
            "tail_risk_decision_sequence": tail_risk_decisions,
            "fixed_threshold_decision_sequence": fixed_threshold_decisions,
            "tail_risk": {
                "admitted_units": tail_summary.admitted_units,
                "deferred_units": tail_summary.deferred_units,
                "shed_units": tail_summary.shed_units,
                "fallback_used_count": tail_summary.fallback_used_count,
                "p95_latency_ns": tail_summary.p95_latency_ns,
                "p99_latency_ns": tail_summary.p99_latency_ns,
                "throughput_ratio": tail_summary.throughput_ratio
            },
            "fixed_threshold": {
                "admitted_units": fixed_summary.admitted_units,
                "deferred_units": fixed_summary.deferred_units,
                "shed_units": fixed_summary.shed_units,
                "p95_latency_ns": fixed_summary.p95_latency_ns,
                "p99_latency_ns": fixed_summary.p99_latency_ns,
                "throughput_ratio": fixed_summary.throughput_ratio
            },
            "comparison": {
                "p95_latency_improvement_ns": fixed_summary.p95_latency_ns.saturating_sub(tail_summary.p95_latency_ns),
                "p99_latency_improvement_ns": fixed_summary.p99_latency_ns.saturating_sub(tail_summary.p99_latency_ns),
                "max_latency_improvement_ns": fixed_summary.max_latency_ns.saturating_sub(tail_summary.max_latency_ns),
                "throughput_delta_units": tail_summary.admitted_units as i64 - fixed_summary.admitted_units as i64,
                "tail_risk_better_than_fixed": tail_summary.p99_latency_ns < fixed_summary.p99_latency_ns,
            },
            "fallback_windows": fallback_windows,
            "evidence_vector_fields": evidence_vector_fields
        });
        let repeated_run_hash_match = if include_hash_probe {
            let probe = build_tail_risk_admission_report(scenario, false);
            hash_json_value(&probe["report_projection"]) == hash_json_value(&report_projection)
        } else {
            true
        };

        json!({
            "schema_version": TAIL_RISK_ADMISSION_REPORT_SCHEMA_VERSION,
            "scenario_id": scenario.scenario_id,
            "description": scenario.description,
            "workload_class": scenario.workload_class,
            "tail_risk_profile": scenario.tail_risk_profile,
            "fixed_threshold_profile": scenario.fixed_threshold_profile,
            "report_projection": report_projection,
            "repeated_run_hash_match": repeated_run_hash_match,
            "tail_risk_summary": tail_summary,
            "fixed_threshold_summary": fixed_summary,
            "window_reports": window_reports,
            "expected_report_projection": scenario.expected_report_projection
        })
    }

    #[test]
    fn tail_risk_admission_smoke_contract_emits_report() {
        let scenarios = load_tail_risk_admission_scenarios();
        let scenario_id = selected_tail_risk_admission_scenario();
        let scenario = scenarios
            .iter()
            .find(|candidate| candidate.scenario_id == scenario_id)
            .expect("selected tail-risk admission scenario must exist");
        let report = build_tail_risk_admission_report(scenario, true);
        if !scenario.expected_report_projection.is_null() {
            assert_eq!(
                report["report_projection"], scenario.expected_report_projection,
                "smoke contract projection must stay stable"
            );
        }
        assert_eq!(
            report["repeated_run_hash_match"].as_bool(),
            Some(true),
            "repeated report generation must be deterministic"
        );

        if let Ok(path) = std::env::var(TAIL_RISK_ADMISSION_REPORT_PATH_ENV) {
            maybe_write_tail_risk_admission_report(&path, &report);
        }

        println!("TAIL_RISK_ADMISSION_REPORT_JSON_BEGIN");
        println!(
            "{}",
            serde_json::to_string_pretty(&report).expect("serialize tail-risk report")
        );
        println!("TAIL_RISK_ADMISSION_REPORT_JSON_END");
        crate::test_complete!("tail_risk_admission_smoke_contract_emits_report");
    }

    fn sample_cohort_steering_evidence() -> CohortAdmissionSteeringEvidence {
        CohortAdmissionSteeringEvidence {
            local_cohort: Some(0),
            worker_to_cohort_map: vec![0, 0, 1, 1],
            cohort_ready_backlog: vec![228, 96],
            topology_confidence_percent: Some(88),
            remote_spill_budget: CohortRemoteSpillBudgetState::new(7, 2),
            decision_epoch: 7,
            consecutive_local_defers: 1,
            outer_tail_risk_decision: TailRiskAdmissionDecision::Admit,
        }
    }

    #[test]
    fn cohort_remote_spill_budget_resets_by_epoch_and_saturates() {
        let profile = CohortAdmissionSteeringProfile {
            remote_spill_budget_per_epoch: 2,
            ..CohortAdmissionSteeringProfile::default()
        };
        let same_epoch = CohortRemoteSpillBudgetState::new(4, 9).normalized_for_epoch(&profile, 4);
        assert_eq!(same_epoch.remaining_tokens, 2);
        let next_epoch = same_epoch.normalized_for_epoch(&profile, 5);
        assert_eq!(next_epoch.epoch, 5);
        assert_eq!(next_epoch.remaining_tokens, 2);
        assert_eq!(next_epoch.spend_one().remaining_tokens, 1);
        assert_eq!(
            CohortRemoteSpillBudgetState::new(5, 0)
                .spend_one()
                .remaining_tokens,
            0
        );
    }

    #[test]
    fn cohort_admission_steering_falls_back_when_topology_is_missing() {
        let ledger = CohortAdmissionSteeringLedger::evaluate(
            &CohortAdmissionSteeringEvidence {
                local_cohort: None,
                worker_to_cohort_map: Vec::new(),
                cohort_ready_backlog: Vec::new(),
                topology_confidence_percent: Some(90),
                remote_spill_budget: CohortRemoteSpillBudgetState::new(3, 2),
                decision_epoch: 3,
                consecutive_local_defers: 0,
                outer_tail_risk_decision: TailRiskAdmissionDecision::Admit,
            },
            &CohortAdmissionSteeringProfile::default(),
        );
        assert!(ledger.fallback_used);
        assert_eq!(ledger.decision, CohortAdmissionSteeringDecision::AdmitLocal);
        assert!(
            ledger
                .reason_codes
                .contains(&CohortAdmissionSteeringReason::MissingTopology)
        );
        assert_eq!(
            ledger.missing_evidence_fields,
            vec![
                "cohort_ready_backlog".to_string(),
                "local_cohort".to_string(),
                "worker_to_cohort_map".to_string()
            ]
        );
    }

    #[test]
    fn cohort_admission_steering_validates_worker_to_cohort_map() {
        let ledger = CohortAdmissionSteeringLedger::evaluate(
            &CohortAdmissionSteeringEvidence {
                worker_to_cohort_map: vec![0, 2],
                cohort_ready_backlog: vec![144, 96],
                ..sample_cohort_steering_evidence()
            },
            &CohortAdmissionSteeringProfile::default(),
        );
        assert!(ledger.fallback_used);
        assert_eq!(ledger.decision, CohortAdmissionSteeringDecision::AdmitLocal);
        assert_eq!(
            ledger.missing_evidence_fields,
            vec!["worker_to_cohort_map".to_string()]
        );
    }

    #[test]
    fn cohort_admission_steering_falls_back_when_confidence_is_low() {
        let ledger = CohortAdmissionSteeringLedger::evaluate(
            &CohortAdmissionSteeringEvidence {
                topology_confidence_percent: Some(42),
                ..sample_cohort_steering_evidence()
            },
            &CohortAdmissionSteeringProfile::default(),
        );
        assert!(ledger.fallback_used);
        assert_eq!(ledger.decision, CohortAdmissionSteeringDecision::AdmitLocal);
        assert!(
            ledger
                .reason_codes
                .contains(&CohortAdmissionSteeringReason::LowConfidenceFallback)
        );
    }

    #[test]
    fn cohort_admission_steering_respects_outer_tail_risk_cap() {
        let ledger = CohortAdmissionSteeringLedger::evaluate(
            &CohortAdmissionSteeringEvidence {
                outer_tail_risk_decision: TailRiskAdmissionDecision::Defer,
                ..sample_cohort_steering_evidence()
            },
            &CohortAdmissionSteeringProfile::default(),
        );
        assert_eq!(ledger.decision, CohortAdmissionSteeringDecision::Defer);
        assert!(!ledger.fallback_used);
        assert_eq!(
            ledger.reason_codes,
            vec![CohortAdmissionSteeringReason::TailRiskOuterCap]
        );
        assert_eq!(ledger.remote_spill_budget_remaining, 2);
    }

    #[test]
    fn cohort_admission_steering_redirects_remote_and_spends_budget() {
        let ledger = CohortAdmissionSteeringLedger::evaluate(
            &sample_cohort_steering_evidence(),
            &CohortAdmissionSteeringProfile::default(),
        );
        assert_eq!(
            ledger.decision,
            CohortAdmissionSteeringDecision::RedirectRemote
        );
        assert_eq!(ledger.target_cohort, Some(1));
        assert_eq!(ledger.remote_spill_budget_start, 2);
        assert_eq!(ledger.remote_spill_budget_remaining, 1);
        assert!(
            ledger
                .reason_codes
                .contains(&CohortAdmissionSteeringReason::RemoteSpillBudgetSpent)
        );
    }

    #[test]
    fn cohort_admission_steering_triggers_fairness_escape_hatch() {
        let profile = CohortAdmissionSteeringProfile {
            fairness_escape_after_consecutive_defers: 2,
            ..CohortAdmissionSteeringProfile::default()
        };
        let ledger = CohortAdmissionSteeringLedger::evaluate(
            &CohortAdmissionSteeringEvidence {
                consecutive_local_defers: 2,
                ..sample_cohort_steering_evidence()
            },
            &profile,
        );
        assert_eq!(
            ledger.decision,
            CohortAdmissionSteeringDecision::RedirectRemote
        );
        assert!(
            ledger
                .reason_codes
                .contains(&CohortAdmissionSteeringReason::FairnessEscapeHatch)
        );
    }

    #[test]
    fn cohort_admission_steering_defers_when_budget_is_exhausted() {
        let ledger = CohortAdmissionSteeringLedger::evaluate(
            &CohortAdmissionSteeringEvidence {
                remote_spill_budget: CohortRemoteSpillBudgetState::new(7, 0),
                consecutive_local_defers: 4,
                ..sample_cohort_steering_evidence()
            },
            &CohortAdmissionSteeringProfile::default(),
        );
        assert_eq!(ledger.decision, CohortAdmissionSteeringDecision::Defer);
        assert!(ledger.remote_spill_budget_exhausted);
        assert!(
            ledger
                .reason_codes
                .contains(&CohortAdmissionSteeringReason::RemoteSpillBudgetExhausted)
        );
    }

    #[test]
    fn cohort_admission_steering_disabled_mode_matches_conservative_global() {
        let profile = CohortAdmissionSteeringProfile {
            enabled: false,
            ..CohortAdmissionSteeringProfile::default()
        };
        let ledger =
            CohortAdmissionSteeringLedger::evaluate(&sample_cohort_steering_evidence(), &profile);
        assert!(ledger.fallback_used);
        assert_eq!(ledger.decision, CohortAdmissionSteeringDecision::AdmitLocal);
        assert_eq!(ledger.target_cohort, Some(0));
        assert!(
            ledger
                .reason_codes
                .contains(&CohortAdmissionSteeringReason::Disabled)
        );
    }

    #[test]
    fn cohort_admission_steering_ledger_round_trips_through_json() {
        let ledger = CohortAdmissionSteeringLedger::evaluate(
            &sample_cohort_steering_evidence(),
            &CohortAdmissionSteeringProfile::default(),
        );
        let json = serde_json::to_string_pretty(&ledger).expect("serialize cohort ledger");
        let reparsed: CohortAdmissionSteeringLedger =
            serde_json::from_str(&json).expect("deserialize cohort ledger");
        assert_eq!(reparsed, ledger);
    }

    fn sample_brownout_evidence() -> OverloadBrownoutEvidence {
        OverloadBrownoutEvidence {
            scheduler: Some(SchedulerEvidenceMetrics {
                wake_to_run_p50_ns: 8_000,
                wake_to_run_p95_ns: 120_000,
                wake_to_run_p99_ns: 236_000,
                queue_residency_p50_ns: 18_000,
                queue_residency_p95_ns: 180_000,
                queue_residency_p99_ns: 310_000,
                ready_backlog_p95: 164,
                ready_backlog_p99: 224,
                cancel_debt_p95: 28,
                cancel_debt_p99: 44,
                remote_steal_ratio_pct: Some(18),
                cross_cohort_wake_p99_ns: Some(148_000),
            }),
            memory_pressure_bps: Some(8_820),
            degradation_level: DegradationLevel::Moderate,
            outer_tail_risk_decision: TailRiskAdmissionDecision::Defer,
            previous_phase: OverloadBrownoutPhase::Observe,
            recovery_streak_windows: 0,
            already_shed_surfaces: Vec::new(),
        }
    }

    #[test]
    fn overload_brownout_effective_optional_surfaces_dedupes_and_filters_denied() {
        let profile = OverloadBrownoutProfile {
            allowed_optional_surfaces: vec![
                BrownoutOptionalSurface::DetailedTracing,
                BrownoutOptionalSurface::RichDiagnostics,
                BrownoutOptionalSurface::DetailedTracing,
                BrownoutOptionalSurface::RichExportFormatting,
            ],
            denied_optional_surfaces: vec![BrownoutOptionalSurface::RichDiagnostics],
            ..OverloadBrownoutProfile::default()
        };
        assert_eq!(
            profile.effective_optional_surfaces(),
            vec![
                BrownoutOptionalSurface::DetailedTracing,
                BrownoutOptionalSurface::RichExportFormatting,
            ]
        );
    }

    #[test]
    fn overload_brownout_disabled_mode_matches_normal() {
        let profile = OverloadBrownoutProfile {
            enabled: false,
            ..OverloadBrownoutProfile::default()
        };
        let ledger = OverloadBrownoutLedger::evaluate(&sample_brownout_evidence(), &profile);
        assert!(ledger.fallback_used);
        assert_eq!(ledger.phase, OverloadBrownoutPhase::Normal);
        assert!(ledger.requested_degraded_surfaces.is_empty());
        assert!(
            ledger
                .reason_codes
                .contains(&OverloadBrownoutReason::Disabled)
        );
    }

    #[test]
    fn overload_brownout_falls_back_when_evidence_is_missing() {
        let ledger = OverloadBrownoutLedger::evaluate(
            &OverloadBrownoutEvidence {
                scheduler: None,
                memory_pressure_bps: Some(7_900),
                degradation_level: DegradationLevel::Light,
                outer_tail_risk_decision: TailRiskAdmissionDecision::Admit,
                previous_phase: OverloadBrownoutPhase::Normal,
                recovery_streak_windows: 0,
                already_shed_surfaces: Vec::new(),
            },
            &OverloadBrownoutProfile::default(),
        );
        assert!(ledger.fallback_used);
        assert_eq!(ledger.phase, OverloadBrownoutPhase::Observe);
        assert_eq!(
            ledger.missing_evidence_fields,
            vec!["scheduler_metrics".to_string()]
        );
    }

    #[test]
    fn overload_brownout_escalates_to_shed_optional_under_severe_pressure() {
        let ledger = OverloadBrownoutLedger::evaluate(
            &OverloadBrownoutEvidence {
                memory_pressure_bps: Some(9_450),
                outer_tail_risk_decision: TailRiskAdmissionDecision::Shed,
                degradation_level: DegradationLevel::Heavy,
                ..sample_brownout_evidence()
            },
            &OverloadBrownoutProfile::default(),
        );
        assert_eq!(ledger.phase, OverloadBrownoutPhase::ShedOptional);
        assert!(
            ledger
                .requested_degraded_surfaces
                .contains(&BrownoutOptionalSurface::DetailedTracing)
        );
        assert!(
            ledger
                .reason_codes
                .contains(&OverloadBrownoutReason::TailRiskOuterShed)
        );
    }

    #[test]
    fn overload_brownout_respects_recovery_hysteresis_and_restores_surfaces() {
        let profile = OverloadBrownoutProfile::default();
        let ledger = OverloadBrownoutLedger::evaluate(
            &OverloadBrownoutEvidence {
                scheduler: Some(SchedulerEvidenceMetrics {
                    wake_to_run_p50_ns: 7_500,
                    wake_to_run_p95_ns: 74_000,
                    wake_to_run_p99_ns: 118_000,
                    queue_residency_p50_ns: 12_000,
                    queue_residency_p95_ns: 88_000,
                    queue_residency_p99_ns: 120_000,
                    ready_backlog_p95: 96,
                    ready_backlog_p99: 128,
                    cancel_debt_p95: 12,
                    cancel_debt_p99: 20,
                    remote_steal_ratio_pct: Some(10),
                    cross_cohort_wake_p99_ns: Some(92_000),
                }),
                memory_pressure_bps: Some(7_100),
                degradation_level: DegradationLevel::None,
                outer_tail_risk_decision: TailRiskAdmissionDecision::Admit,
                previous_phase: OverloadBrownoutPhase::ShedOptional,
                recovery_streak_windows: 0,
                already_shed_surfaces: Vec::new(),
            },
            &profile,
        );
        assert_eq!(ledger.phase, OverloadBrownoutPhase::Recovery);
        assert_eq!(ledger.recovery_streak_after, 1);
        assert!(
            ledger
                .restored_surfaces
                .contains(&BrownoutOptionalSurface::DetailedTracing)
        );
        assert!(
            ledger
                .reason_codes
                .contains(&OverloadBrownoutReason::RecoveryHysteresis)
        );
    }

    #[test]
    fn overload_brownout_avoids_duplicate_accounting_for_self_shedding_surfaces() {
        let ledger = OverloadBrownoutLedger::evaluate(
            &OverloadBrownoutEvidence {
                already_shed_surfaces: vec![BrownoutOptionalSurface::RichDiagnostics],
                ..sample_brownout_evidence()
            },
            &OverloadBrownoutProfile::default(),
        );
        assert_eq!(ledger.phase, OverloadBrownoutPhase::Degrade);
        assert!(
            ledger
                .already_shed_surfaces
                .contains(&BrownoutOptionalSurface::RichDiagnostics)
        );
        assert!(
            !ledger
                .newly_degraded_surfaces
                .contains(&BrownoutOptionalSurface::RichDiagnostics)
        );
        assert!(
            ledger
                .reason_codes
                .contains(&OverloadBrownoutReason::OptionalSurfaceAlreadyShedding)
        );
    }

    #[test]
    fn overload_brownout_preserves_critical_surfaces() {
        let ledger = OverloadBrownoutLedger::evaluate(
            &sample_brownout_evidence(),
            &OverloadBrownoutProfile::default(),
        );
        assert_eq!(ledger.phase, OverloadBrownoutPhase::Degrade);
        assert_eq!(
            ledger.preserved_surfaces,
            vec![
                BrownoutProtectedSurface::CoreScheduling,
                BrownoutProtectedSurface::CancellationDrain,
                BrownoutProtectedSurface::RegionQuiescence,
                BrownoutProtectedSurface::ObligationCleanup,
            ]
        );
    }

    #[test]
    fn overload_brownout_ledger_round_trips_through_json() {
        let ledger = OverloadBrownoutLedger::evaluate(
            &sample_brownout_evidence(),
            &OverloadBrownoutProfile::default(),
        );
        let json = serde_json::to_string_pretty(&ledger).expect("serialize overload brownout");
        let reparsed: OverloadBrownoutLedger =
            serde_json::from_str(&json).expect("deserialize overload brownout");
        assert_eq!(reparsed, ledger);
    }

    const COHORT_ADMISSION_STEERING_CONTRACT_PATH_ENV: &str =
        "ASUPERSYNC_COHORT_ADMISSION_STEERING_CONTRACT_PATH";
    const COHORT_ADMISSION_STEERING_SCENARIO_ENV: &str =
        "ASUPERSYNC_COHORT_ADMISSION_STEERING_SCENARIO";
    const COHORT_ADMISSION_STEERING_REPORT_PATH_ENV: &str =
        "ASUPERSYNC_COHORT_ADMISSION_STEERING_REPORT_PATH";
    const COHORT_ADMISSION_STEERING_REPORT_SCHEMA_VERSION: &str =
        "cohort-admission-steering-report-v1";
    const COHORT_ADMISSION_STEERING_PROJECTION_SCHEMA_VERSION: &str =
        "cohort-admission-steering-projection-v1";

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct CohortAdmissionSteeringSmokeContract {
        smoke_scenarios: Vec<CohortAdmissionSteeringScenario>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct CohortAdmissionSteeringScenario {
        scenario_id: String,
        description: String,
        workload_class: String,
        output_root: String,
        execution_policy: String,
        workload_seed: u64,
        safe_fallback_profile: String,
        expected_winner_profile: String,
        steering_profile: CohortAdmissionSteeringProfile,
        fixture: CohortAdmissionSteeringFixture,
        expected_report_projection: Value,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct CohortAdmissionSteeringFixture {
        replay_count: usize,
        windows: Vec<CohortAdmissionSteeringWindow>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct CohortAdmissionSteeringWindow {
        window_id: String,
        local_cohort: Option<usize>,
        worker_to_cohort_map: Vec<usize>,
        cohort_ready_backlog: Vec<usize>,
        topology_confidence_percent: Option<u8>,
        decision_epoch: u64,
        consecutive_local_defers: u16,
        outer_tail_risk_decision: TailRiskAdmissionDecision,
        offered_work_units: u64,
        local_wake_to_run_p99_ns: u64,
        remote_wake_to_run_p99_ns: u64,
    }

    #[derive(Debug, Clone)]
    struct CohortPlacementWindowOutcome {
        admitted_units: u64,
        deferred_units: u64,
        remote_spill_count: u64,
        latency_samples: Vec<u64>,
    }

    #[derive(Debug, Clone, Default, Serialize)]
    struct CohortSteeringAccumulator {
        admit_local_count: u64,
        redirect_remote_count: u64,
        defer_count: u64,
        fallback_used_count: u64,
        budget_exhausted_count: u64,
        fairness_escape_count: u64,
        admitted_units: u64,
        deferred_units: u64,
        remote_spill_count: u64,
        latencies: Vec<u64>,
    }

    #[derive(Debug, Clone, PartialEq, Serialize)]
    struct CohortSteeringSummary {
        admit_local_count: u64,
        redirect_remote_count: u64,
        defer_count: u64,
        fallback_used_count: u64,
        budget_exhausted_count: u64,
        fairness_escape_count: u64,
        admitted_units: u64,
        deferred_units: u64,
        remote_spill_count: u64,
        p50_latency_ns: u64,
        p95_latency_ns: u64,
        p99_latency_ns: u64,
        max_latency_ns: u64,
        throughput_ratio: f64,
    }

    impl CohortSteeringAccumulator {
        fn record(
            &mut self,
            decision: CohortAdmissionSteeringDecision,
            fallback_used: bool,
            budget_exhausted: bool,
            fairness_escape: bool,
            outcome: &CohortPlacementWindowOutcome,
        ) {
            match decision {
                CohortAdmissionSteeringDecision::AdmitLocal => self.admit_local_count += 1,
                CohortAdmissionSteeringDecision::RedirectRemote => self.redirect_remote_count += 1,
                CohortAdmissionSteeringDecision::Defer => self.defer_count += 1,
            }
            self.fallback_used_count += u64::from(fallback_used);
            self.budget_exhausted_count += u64::from(budget_exhausted);
            self.fairness_escape_count += u64::from(fairness_escape);
            self.admitted_units += outcome.admitted_units;
            self.deferred_units += outcome.deferred_units;
            self.remote_spill_count += outcome.remote_spill_count;
            self.latencies.extend_from_slice(&outcome.latency_samples);
        }

        fn summary(&self, total_offered_units: u64) -> CohortSteeringSummary {
            let max_latency_ns = self.latencies.iter().copied().max().unwrap_or(0);
            let throughput_ratio = if total_offered_units == 0 {
                0.0
            } else {
                round4(self.admitted_units as f64 / total_offered_units as f64)
            };
            CohortSteeringSummary {
                admit_local_count: self.admit_local_count,
                redirect_remote_count: self.redirect_remote_count,
                defer_count: self.defer_count,
                fallback_used_count: self.fallback_used_count,
                budget_exhausted_count: self.budget_exhausted_count,
                fairness_escape_count: self.fairness_escape_count,
                admitted_units: self.admitted_units,
                deferred_units: self.deferred_units,
                remote_spill_count: self.remote_spill_count,
                p50_latency_ns: percentile_slice_u64(&self.latencies, 50, 100),
                p95_latency_ns: percentile_slice_u64(&self.latencies, 95, 100),
                p99_latency_ns: percentile_slice_u64(&self.latencies, 99, 100),
                max_latency_ns,
                throughput_ratio,
            }
        }
    }

    fn default_cohort_admission_steering_scenarios() -> Vec<CohortAdmissionSteeringScenario> {
        vec![
            CohortAdmissionSteeringScenario {
                scenario_id: "AA-COHORT-ADMISSION-STEERING-LOCALITY-WIN-2C".to_string(),
                description: "High-confidence two-cohort replay where the local cohort saturates, the remote cohort stays cool, and bounded redirect tokens cut wake-to-run tails versus the conservative global path.".to_string(),
                workload_class: "locality-win".to_string(),
                output_root: "target/cohort-admission-steering-smoke".to_string(),
                execution_policy: "execute_or_dry_run".to_string(),
                workload_seed: 424242,
                safe_fallback_profile: "conservative_global".to_string(),
                expected_winner_profile: "cohort_steered".to_string(),
                steering_profile: CohortAdmissionSteeringProfile::default(),
                fixture: CohortAdmissionSteeringFixture {
                    replay_count: 2,
                    windows: vec![
                        CohortAdmissionSteeringWindow {
                            window_id: "local_balanced".to_string(),
                            local_cohort: Some(0),
                            worker_to_cohort_map: vec![0, 0, 1, 1],
                            cohort_ready_backlog: vec![148, 128],
                            topology_confidence_percent: Some(90),
                            decision_epoch: 10,
                            consecutive_local_defers: 0,
                            outer_tail_risk_decision: TailRiskAdmissionDecision::Admit,
                            offered_work_units: 48,
                            local_wake_to_run_p99_ns: 148_000,
                            remote_wake_to_run_p99_ns: 142_000,
                        },
                        CohortAdmissionSteeringWindow {
                            window_id: "local_saturated".to_string(),
                            local_cohort: Some(0),
                            worker_to_cohort_map: vec![0, 0, 1, 1],
                            cohort_ready_backlog: vec![260, 84],
                            topology_confidence_percent: Some(92),
                            decision_epoch: 10,
                            consecutive_local_defers: 1,
                            outer_tail_risk_decision: TailRiskAdmissionDecision::Admit,
                            offered_work_units: 48,
                            local_wake_to_run_p99_ns: 236_000,
                            remote_wake_to_run_p99_ns: 146_000,
                        },
                        CohortAdmissionSteeringWindow {
                            window_id: "fairness_escape".to_string(),
                            local_cohort: Some(0),
                            worker_to_cohort_map: vec![0, 0, 1, 1],
                            cohort_ready_backlog: vec![244, 96],
                            topology_confidence_percent: Some(90),
                            decision_epoch: 10,
                            consecutive_local_defers: 3,
                            outer_tail_risk_decision: TailRiskAdmissionDecision::Admit,
                            offered_work_units: 48,
                            local_wake_to_run_p99_ns: 228_000,
                            remote_wake_to_run_p99_ns: 154_000,
                        },
                    ],
                },
                expected_report_projection: Value::Null,
            },
            CohortAdmissionSteeringScenario {
                scenario_id: "AA-COHORT-ADMISSION-STEERING-KEEP-GLOBAL-2C".to_string(),
                description: "Low-confidence and no-win replay that proves the controller keeps the conservative global path pinned and records an explicit safe fallback verdict.".to_string(),
                workload_class: "keep-global".to_string(),
                output_root: "target/cohort-admission-steering-smoke".to_string(),
                execution_policy: "execute_or_dry_run".to_string(),
                workload_seed: 515151,
                safe_fallback_profile: "conservative_global".to_string(),
                expected_winner_profile: "conservative_global".to_string(),
                steering_profile: CohortAdmissionSteeringProfile::default(),
                fixture: CohortAdmissionSteeringFixture {
                    replay_count: 1,
                    windows: vec![
                        CohortAdmissionSteeringWindow {
                            window_id: "low_confidence".to_string(),
                            local_cohort: Some(0),
                            worker_to_cohort_map: vec![0, 0, 1, 1],
                            cohort_ready_backlog: vec![208, 198],
                            topology_confidence_percent: Some(48),
                            decision_epoch: 22,
                            consecutive_local_defers: 0,
                            outer_tail_risk_decision: TailRiskAdmissionDecision::Admit,
                            offered_work_units: 48,
                            local_wake_to_run_p99_ns: 204_000,
                            remote_wake_to_run_p99_ns: 201_000,
                        },
                        CohortAdmissionSteeringWindow {
                            window_id: "thin_remote_gain".to_string(),
                            local_cohort: Some(0),
                            worker_to_cohort_map: vec![0, 0, 1, 1],
                            cohort_ready_backlog: vec![214, 196],
                            topology_confidence_percent: Some(88),
                            decision_epoch: 23,
                            consecutive_local_defers: 1,
                            outer_tail_risk_decision: TailRiskAdmissionDecision::Admit,
                            offered_work_units: 48,
                            local_wake_to_run_p99_ns: 211_000,
                            remote_wake_to_run_p99_ns: 208_000,
                        },
                        CohortAdmissionSteeringWindow {
                            window_id: "tail_risk_outer_cap".to_string(),
                            local_cohort: Some(0),
                            worker_to_cohort_map: vec![0, 0, 1, 1],
                            cohort_ready_backlog: vec![228, 150],
                            topology_confidence_percent: Some(90),
                            decision_epoch: 24,
                            consecutive_local_defers: 4,
                            outer_tail_risk_decision: TailRiskAdmissionDecision::Defer,
                            offered_work_units: 48,
                            local_wake_to_run_p99_ns: 224_000,
                            remote_wake_to_run_p99_ns: 176_000,
                        },
                    ],
                },
                expected_report_projection: Value::Null,
            },
        ]
    }

    fn load_cohort_admission_steering_scenarios() -> Vec<CohortAdmissionSteeringScenario> {
        let Ok(path) = std::env::var(COHORT_ADMISSION_STEERING_CONTRACT_PATH_ENV) else {
            return default_cohort_admission_steering_scenarios();
        };
        let contract: CohortAdmissionSteeringSmokeContract = serde_json::from_str(
            &fs::read_to_string(Path::new(&path)).expect("read cohort admission steering contract"),
        )
        .expect("deserialize cohort admission steering contract");
        contract.smoke_scenarios
    }

    fn selected_cohort_admission_steering_scenario() -> String {
        std::env::var(COHORT_ADMISSION_STEERING_SCENARIO_ENV)
            .unwrap_or_else(|_| "AA-COHORT-ADMISSION-STEERING-LOCALITY-WIN-2C".to_string())
    }

    fn maybe_write_cohort_admission_steering_report(path: &str, report: &Value) {
        let path = Path::new(path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create cohort report parent directory");
        }
        fs::write(
            path,
            serde_json::to_string_pretty(report)
                .expect("serialize cohort admission steering report"),
        )
        .expect("write cohort admission steering report");
    }

    fn conservative_global_decision(
        window: &CohortAdmissionSteeringWindow,
    ) -> CohortAdmissionSteeringDecision {
        if window.outer_tail_risk_decision == TailRiskAdmissionDecision::Admit {
            CohortAdmissionSteeringDecision::AdmitLocal
        } else {
            CohortAdmissionSteeringDecision::Defer
        }
    }

    fn simulate_cohort_window_outcome(
        decision: CohortAdmissionSteeringDecision,
        target_cohort: Option<usize>,
        window: &CohortAdmissionSteeringWindow,
        replay_index: usize,
    ) -> CohortPlacementWindowOutcome {
        let offered = window.offered_work_units;
        let local_cohort = window.local_cohort.unwrap_or(0);
        let local_backlog_usize = window
            .cohort_ready_backlog
            .get(local_cohort)
            .copied()
            .unwrap_or(0);
        let local_backlog = local_backlog_usize as u64;
        let best_remote_backlog = window
            .cohort_ready_backlog
            .iter()
            .enumerate()
            .filter(|(cohort, _)| *cohort != local_cohort)
            .map(|(_, backlog)| *backlog)
            .min()
            .unwrap_or(local_backlog_usize) as u64;
        let remote_backlog = target_cohort
            .and_then(|cohort| window.cohort_ready_backlog.get(cohort).copied())
            .unwrap_or(best_remote_backlog as usize) as u64;
        let backlog_gap = local_backlog.saturating_sub(best_remote_backlog);

        let (
            admitted_units,
            deferred_units,
            remote_spill_count,
            p99_base,
            overload_multiplier,
            decision_penalty,
        ) = match decision {
            CohortAdmissionSteeringDecision::AdmitLocal => (
                offered,
                0,
                backlog_gap.saturating_div(40),
                window.local_wake_to_run_p99_ns,
                1_350,
                21_000 + backlog_gap.saturating_mul(320),
            ),
            CohortAdmissionSteeringDecision::RedirectRemote => (
                offered,
                0,
                1,
                window.remote_wake_to_run_p99_ns,
                780,
                13_500 + remote_backlog.saturating_mul(110),
            ),
            CohortAdmissionSteeringDecision::Defer => (
                offered.saturating_mul(82).saturating_div(100),
                offered.saturating_sub(offered.saturating_mul(82).saturating_div(100)),
                0,
                window.local_wake_to_run_p99_ns.saturating_sub(18_000),
                620,
                9_500,
            ),
        };

        let backlog_source = match decision {
            CohortAdmissionSteeringDecision::RedirectRemote => remote_backlog,
            CohortAdmissionSteeringDecision::AdmitLocal
            | CohortAdmissionSteeringDecision::Defer => local_backlog,
        };

        let base_latency = p99_base
            .saturating_div(2)
            .saturating_add(backlog_source.saturating_mul(overload_multiplier))
            .saturating_add(decision_penalty);
        let mut latency_samples = Vec::with_capacity(admitted_units as usize);
        for sample_idx in 0..admitted_units {
            let jitter = ((replay_index as u64 * 23) + (sample_idx % 17) * 11).saturating_mul(131);
            latency_samples.push(base_latency.saturating_add(jitter));
        }

        CohortPlacementWindowOutcome {
            admitted_units,
            deferred_units,
            remote_spill_count,
            latency_samples,
        }
    }

    fn cohort_steering_reason_label(reason: CohortAdmissionSteeringReason) -> &'static str {
        match reason {
            CohortAdmissionSteeringReason::Disabled => "disabled",
            CohortAdmissionSteeringReason::MissingTopology => "missing_topology",
            CohortAdmissionSteeringReason::LowConfidenceFallback => "low_confidence_fallback",
            CohortAdmissionSteeringReason::TailRiskOuterCap => "tail_risk_outer_cap",
            CohortAdmissionSteeringReason::LocalCapacityAvailable => "local_capacity_available",
            CohortAdmissionSteeringReason::LocalBacklogPressure => "local_backlog_pressure",
            CohortAdmissionSteeringReason::RemoteSpillBudgetSpent => "remote_spill_budget_spent",
            CohortAdmissionSteeringReason::RemoteSpillBudgetExhausted => {
                "remote_spill_budget_exhausted"
            }
            CohortAdmissionSteeringReason::FairnessEscapeHatch => "fairness_escape_hatch",
            CohortAdmissionSteeringReason::ConservativeGlobalBaseline => {
                "conservative_global_baseline"
            }
        }
    }

    fn build_cohort_admission_steering_report(
        scenario: &CohortAdmissionSteeringScenario,
        include_hash_probe: bool,
    ) -> Value {
        let total_offered_units = scenario
            .fixture
            .windows
            .iter()
            .map(|window| window.offered_work_units)
            .sum::<u64>()
            .saturating_mul(scenario.fixture.replay_count as u64);

        let mut steered = CohortSteeringAccumulator::default();
        let mut conservative_global = CohortSteeringAccumulator::default();
        let mut window_reports = Vec::new();
        let mut decision_sequence = Vec::new();
        let mut conservative_sequence = Vec::new();
        let mut fallback_windows = Vec::new();
        let mut fairness_windows = Vec::new();
        let mut budget_start_sequence = Vec::new();
        let mut budget_remaining_sequence = Vec::new();

        let mut budget_state = CohortRemoteSpillBudgetState::new(
            scenario
                .fixture
                .windows
                .first()
                .map_or(0, |window| window.decision_epoch),
            scenario.steering_profile.remote_spill_budget_per_epoch,
        );

        for replay_index in 0..scenario.fixture.replay_count {
            let mut replay_budget = budget_state;
            for window in &scenario.fixture.windows {
                let evidence = CohortAdmissionSteeringEvidence {
                    local_cohort: window.local_cohort,
                    worker_to_cohort_map: window.worker_to_cohort_map.clone(),
                    cohort_ready_backlog: window.cohort_ready_backlog.clone(),
                    topology_confidence_percent: window.topology_confidence_percent,
                    remote_spill_budget: replay_budget,
                    decision_epoch: window.decision_epoch,
                    consecutive_local_defers: window.consecutive_local_defers,
                    outer_tail_risk_decision: window.outer_tail_risk_decision,
                };
                let ledger =
                    CohortAdmissionSteeringLedger::evaluate(&evidence, &scenario.steering_profile);
                replay_budget = CohortRemoteSpillBudgetState::new(
                    ledger.evidence.remote_spill_budget_epoch,
                    ledger.remote_spill_budget_remaining,
                );

                let global_decision = conservative_global_decision(window);
                let steered_outcome = simulate_cohort_window_outcome(
                    ledger.decision,
                    ledger.target_cohort,
                    window,
                    replay_index,
                );
                let global_outcome =
                    simulate_cohort_window_outcome(global_decision, None, window, replay_index);

                steered.record(
                    ledger.decision,
                    ledger.fallback_used,
                    ledger
                        .reason_codes
                        .contains(&CohortAdmissionSteeringReason::RemoteSpillBudgetExhausted),
                    ledger
                        .reason_codes
                        .contains(&CohortAdmissionSteeringReason::FairnessEscapeHatch),
                    &steered_outcome,
                );
                conservative_global.record(global_decision, false, false, false, &global_outcome);

                if replay_index == 0 {
                    decision_sequence.push(format!("{:?}", ledger.decision).to_lowercase());
                    conservative_sequence.push(format!("{:?}", global_decision).to_lowercase());
                    budget_start_sequence.push(ledger.remote_spill_budget_start);
                    budget_remaining_sequence.push(ledger.remote_spill_budget_remaining);
                    if ledger.fallback_used {
                        fallback_windows.push(window.window_id.clone());
                    }
                    if ledger
                        .reason_codes
                        .contains(&CohortAdmissionSteeringReason::FairnessEscapeHatch)
                    {
                        fairness_windows.push(window.window_id.clone());
                    }
                    window_reports.push(json!({
                        "window_id": window.window_id,
                        "worker_to_cohort_map": window.worker_to_cohort_map,
                        "cohort_ready_backlog": window.cohort_ready_backlog,
                        "topology_confidence_percent": window.topology_confidence_percent,
                        "outer_tail_risk_decision": format!("{:?}", window.outer_tail_risk_decision).to_lowercase(),
                        "steered": {
                            "decision": format!("{:?}", ledger.decision).to_lowercase(),
                            "target_cohort": ledger.target_cohort,
                            "fallback_used": ledger.fallback_used,
                            "confidence_percent": ledger.confidence_percent,
                            "reason_codes": ledger.reason_codes.iter().map(|reason| cohort_steering_reason_label(*reason)).collect::<Vec<_>>(),
                            "missing_evidence_fields": ledger.missing_evidence_fields,
                            "remote_spill_budget_start": ledger.remote_spill_budget_start,
                            "remote_spill_budget_remaining": ledger.remote_spill_budget_remaining,
                            "remote_spill_budget_exhausted": ledger.remote_spill_budget_exhausted,
                            "admitted_units": steered_outcome.admitted_units,
                            "deferred_units": steered_outcome.deferred_units,
                            "remote_spill_count": steered_outcome.remote_spill_count,
                            "window_p99_ns": percentile_slice_u64(&steered_outcome.latency_samples, 99, 100),
                        },
                        "conservative_global": {
                            "decision": format!("{:?}", global_decision).to_lowercase(),
                            "admitted_units": global_outcome.admitted_units,
                            "deferred_units": global_outcome.deferred_units,
                            "remote_spill_count": global_outcome.remote_spill_count,
                            "window_p99_ns": percentile_slice_u64(&global_outcome.latency_samples, 99, 100),
                        }
                    }));
                }
            }
            budget_state = replay_budget;
        }

        let steered_summary = steered.summary(total_offered_units);
        let conservative_summary = conservative_global.summary(total_offered_units);
        let winner_profile = if steered_summary.p99_latency_ns < conservative_summary.p99_latency_ns
            || (steered_summary.p99_latency_ns == conservative_summary.p99_latency_ns
                && steered_summary.remote_spill_count < conservative_summary.remote_spill_count)
        {
            "cohort_steered"
        } else {
            scenario.safe_fallback_profile.as_str()
        };
        let no_win_trigger = winner_profile == scenario.safe_fallback_profile;
        let report_projection = json!({
            "schema_version": COHORT_ADMISSION_STEERING_PROJECTION_SCHEMA_VERSION,
            "scenario_id": scenario.scenario_id,
            "workload_class": scenario.workload_class,
            "workload_seed": scenario.workload_seed,
            "replay_count": scenario.fixture.replay_count,
            "window_count": scenario.fixture.windows.len(),
            "decision_sequence": decision_sequence,
            "conservative_global_sequence": conservative_sequence,
            "budget_start_sequence": budget_start_sequence,
            "budget_remaining_sequence": budget_remaining_sequence,
            "fallback_windows": fallback_windows,
            "fairness_windows": fairness_windows,
            "steered": {
                "admit_local_count": steered_summary.admit_local_count,
                "redirect_remote_count": steered_summary.redirect_remote_count,
                "defer_count": steered_summary.defer_count,
                "fallback_used_count": steered_summary.fallback_used_count,
                "budget_exhausted_count": steered_summary.budget_exhausted_count,
                "fairness_escape_count": steered_summary.fairness_escape_count,
                "admitted_units": steered_summary.admitted_units,
                "deferred_units": steered_summary.deferred_units,
                "remote_spill_count": steered_summary.remote_spill_count,
                "p95_latency_ns": steered_summary.p95_latency_ns,
                "p99_latency_ns": steered_summary.p99_latency_ns,
                "throughput_ratio": steered_summary.throughput_ratio
            },
            "conservative_global": {
                "admit_local_count": conservative_summary.admit_local_count,
                "redirect_remote_count": conservative_summary.redirect_remote_count,
                "defer_count": conservative_summary.defer_count,
                "admitted_units": conservative_summary.admitted_units,
                "deferred_units": conservative_summary.deferred_units,
                "remote_spill_count": conservative_summary.remote_spill_count,
                "p95_latency_ns": conservative_summary.p95_latency_ns,
                "p99_latency_ns": conservative_summary.p99_latency_ns,
                "throughput_ratio": conservative_summary.throughput_ratio
            },
            "comparison": {
                "p95_latency_improvement_ns": conservative_summary.p95_latency_ns.saturating_sub(steered_summary.p95_latency_ns),
                "p99_latency_improvement_ns": conservative_summary.p99_latency_ns.saturating_sub(steered_summary.p99_latency_ns),
                "remote_spill_reduction": conservative_summary.remote_spill_count as i64 - steered_summary.remote_spill_count as i64,
                "throughput_delta_units": steered_summary.admitted_units as i64 - conservative_summary.admitted_units as i64,
                "winner_profile": winner_profile,
                "no_win_trigger": no_win_trigger,
            }
        });
        let repeated_run_hash_match = if include_hash_probe {
            let probe = build_cohort_admission_steering_report(scenario, false);
            hash_json_value(&probe["report_projection"]) == hash_json_value(&report_projection)
        } else {
            true
        };

        json!({
            "schema_version": COHORT_ADMISSION_STEERING_REPORT_SCHEMA_VERSION,
            "scenario_id": scenario.scenario_id,
            "description": scenario.description,
            "workload_class": scenario.workload_class,
            "workload_seed": scenario.workload_seed,
            "safe_fallback_profile": scenario.safe_fallback_profile,
            "expected_winner_profile": scenario.expected_winner_profile,
            "steering_profile": scenario.steering_profile,
            "report_projection": report_projection,
            "repeated_run_hash_match": repeated_run_hash_match,
            "steered_summary": steered_summary,
            "conservative_global_summary": conservative_summary,
            "window_reports": window_reports,
            "operator_verdict": {
                "winner_profile": winner_profile,
                "safe_fallback_profile": scenario.safe_fallback_profile,
                "no_win_trigger": no_win_trigger,
                "pass": winner_profile == scenario.expected_winner_profile,
            },
            "expected_report_projection": scenario.expected_report_projection
        })
    }

    #[test]
    fn cohort_admission_steering_smoke_contract_emits_report() {
        let scenarios = load_cohort_admission_steering_scenarios();
        let scenario_id = selected_cohort_admission_steering_scenario();
        let scenario = scenarios
            .iter()
            .find(|candidate| candidate.scenario_id == scenario_id)
            .expect("selected cohort admission steering scenario must exist");
        let report = build_cohort_admission_steering_report(scenario, true);
        if !scenario.expected_report_projection.is_null() {
            assert_eq!(
                report["report_projection"], scenario.expected_report_projection,
                "cohort steering smoke contract projection must stay stable"
            );
        }
        assert_eq!(
            report["repeated_run_hash_match"].as_bool(),
            Some(true),
            "repeated cohort steering report generation must be deterministic"
        );
        assert_eq!(
            report["operator_verdict"]["pass"].as_bool(),
            Some(true),
            "operator verdict must agree with the expected winner profile"
        );

        if let Ok(path) = std::env::var(COHORT_ADMISSION_STEERING_REPORT_PATH_ENV) {
            maybe_write_cohort_admission_steering_report(&path, &report);
        }

        println!("COHORT_ADMISSION_STEERING_REPORT_JSON_BEGIN");
        println!(
            "{}",
            serde_json::to_string_pretty(&report)
                .expect("serialize cohort admission steering report")
        );
        println!("COHORT_ADMISSION_STEERING_REPORT_JSON_END");
        crate::test_complete!("cohort_admission_steering_smoke_contract_emits_report");
    }
