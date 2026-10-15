//! Opt-in runtime resource sampling (asupersync-1ir2em).
//!
//! `RuntimeBuilder::resource_sampling` runs the resource monitor's probes on
//! an interval, so child region admission and `Cx::pressure()` follow the
//! sampled levels. Without it nothing ever processes a measurement.
//!
//! The injected measurement is `ResourceType::Task`, which no probe writes and
//! the default degradation policy watches. Real host load can only add
//! pressure, so the assertions made while sampling runs are one-sided.
#![cfg(not(target_arch = "wasm32"))]

use asupersync::Cx;
use asupersync::cx::{ChildRegionError, ChildRegionSpec};
use asupersync::runtime::RegionCreateError;
use asupersync::runtime::RuntimeBuilder;
use asupersync::runtime::resource_monitor::{
    DegradationLevel, RegionPriority, ResourceMeasurement, ResourceMonitor, ResourceType,
};
use asupersync::types::Budget;
use asupersync::types::pressure::SystemPressure;
use std::time::{Duration, Instant};

/// Task usage past its soft limit and short of its hard limit.
fn inject_task_pressure(monitor: &ResourceMonitor) {
    monitor.pressure().update_measurement(
        ResourceType::Task,
        ResourceMeasurement::new(920, 800, 950, 1000),
    );
}

fn reaches_level(monitor: &ResourceMonitor, at_least: DegradationLevel, within: Duration) -> bool {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if monitor.pressure().composite_degradation_level() >= at_least {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    false
}

fn headroom(cx: &Cx) -> Option<f32> {
    cx.pressure().map(SystemPressure::headroom)
}

fn block_on_cx() -> Cx {
    Cx::current().expect("block_on installs a task context")
}

/// What a `Low`-priority child region request returned, closing an admitted one.
async fn open_low_priority_region(cx: &Cx) -> Result<(), ChildRegionError> {
    let spec = ChildRegionSpec::inherit().with_priority(RegionPriority::Low);
    let region = cx.open_child_region(spec).await?;
    region.close().await
}

fn sampling_runtime() -> asupersync::runtime::Runtime {
    RuntimeBuilder::new()
        .worker_threads(2)
        .resource_sampling(Duration::from_millis(100))
        .build()
        .expect("runtime")
}

#[test]
fn sampling_raises_the_level_and_refuses_low_priority_regions() {
    let runtime = sampling_runtime();
    let monitor = runtime.resource_monitor();
    assert!(
        monitor.status_report().is_active,
        "sampling marks the monitor active"
    );
    inject_task_pressure(&monitor);
    assert!(
        reaches_level(&monitor, DegradationLevel::Light, Duration::from_secs(10)),
        "the sampler processed the injected measurement"
    );

    let low_region = runtime.block_on(async { open_low_priority_region(&block_on_cx()).await });
    assert!(
        matches!(
            low_region,
            Err(ChildRegionError::Create(
                RegionCreateError::ResourcePressure {
                    requested_priority: RegionPriority::Low,
                    ..
                }
            ))
        ),
        "{low_region:?}"
    );

    drop(runtime);
    assert!(
        !monitor.status_report().is_active,
        "dropping the runtime stops the sampler"
    );
}

#[test]
fn sampled_pressure_reaches_every_runtime_built_context() {
    let runtime = sampling_runtime();
    let monitor = runtime.resource_monitor();
    inject_task_pressure(&monitor);
    let raised = reaches_level(&monitor, DegradationLevel::Light, Duration::from_secs(10));

    let request = headroom(&runtime.request_cx_with_budget(Budget::INFINITE));
    // A task spawned through the runtime handle has no spawner context, so
    // only the runtime's own attach can give it the handle.
    let detached = runtime.block_on(
        runtime
            .handle()
            .spawn(async { Cx::current().and_then(|cx| headroom(&cx)) }),
    );
    let (block_on, child, region) = runtime.block_on(async {
        let cx = block_on_cx();
        let block_on = headroom(&cx);
        let mut child = cx.spawn(|cx| async move { headroom(&cx) }).expect("spawn");
        let child = child.join(&cx).await.expect("join");
        // High-priority regions are admitted under any pressure.
        let high = ChildRegionSpec::inherit().with_priority(RegionPriority::High);
        let region = cx.open_child_region(high).await.expect("High region");
        let in_region = headroom(region.cx());
        region.close().await.expect("close");
        (block_on, child, in_region)
    });
    // The handles are checked before the level, so a missing attach is told
    // apart from a sampler that never ran.
    let contexts = [
        ("request", request),
        ("block_on", block_on),
        ("Cx::spawn child", child),
        ("handle-spawned task", detached),
        ("High child region", region),
    ];
    assert!(
        contexts.iter().all(|(_, headroom)| headroom.is_some()),
        "every runtime-built context carries the sampled pressure: {contexts:?}"
    );
    assert!(raised, "the sampler processed the injected measurement");
    for (context, headroom) in contexts {
        let headroom = headroom.unwrap_or(1.0);
        assert!(headroom < 1.0, "{context} headroom {headroom}");
    }
}

#[test]
fn without_sampling_the_same_measurement_changes_nothing() {
    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("runtime");
    let monitor = runtime.resource_monitor();
    assert!(!monitor.status_report().is_active);
    inject_task_pressure(&monitor);
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        monitor.pressure().composite_degradation_level(),
        DegradationLevel::None
    );

    let request = headroom(&runtime.request_cx_with_budget(Budget::INFINITE));
    let (block_on, low_region) = runtime.block_on(async {
        let cx = block_on_cx();
        (headroom(&cx), open_low_priority_region(&cx).await)
    });
    assert_eq!(
        (request, block_on),
        (None, None),
        "no pressure handle without sampling"
    );
    assert!(low_region.is_ok(), "{low_region:?}");
}
