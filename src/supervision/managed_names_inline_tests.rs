use super::*;
use crate::time::{TimeSource, TimerDriver, TimerDriverHandle};
use crate::types::{Budget, RegionId, TaskId};
use std::sync::Weak;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug)]
struct RegistryClock {
    name: Weak<GenerationName>,
    observed_lock: AtomicBool,
}

impl TimeSource for RegistryClock {
    fn now(&self) -> Time {
        // A blocking lock here would deadlock the old implementation.
        if let Some(name) = self.name.upgrade()
            && (name.registry.try_lock().is_none() || name.ownership.try_lock().is_none())
        {
            self.observed_lock.store(true, Ordering::Relaxed);
        }
        Time::from_nanos(17)
    }
}

#[test]
fn named_generation_reads_its_clock_outside_registry_and_ownership_locks() {
    let registry = Arc::new(Mutex::new(NameRegistry::new()));
    let name = GenerationName::for_policy(
        &registry,
        &NameRegistrationPolicy::Register {
            name: "service".into(),
            collision: NameCollisionPolicy::Fail,
        },
    )
    .unwrap();
    let clock = Arc::new(RegistryClock {
        name: Arc::downgrade(&name),
        observed_lock: AtomicBool::new(false),
    });
    let timer = TimerDriverHandle::new(Arc::new(TimerDriver::with_clock(Arc::clone(&clock))));
    let region = RegionId::new_for_test(1, 1);
    let task = TaskId::new_for_test(1, 1);
    let cx = Cx::new_with_drivers(
        region,
        task,
        Budget::INFINITE,
        None,
        None,
        None,
        Some(timer),
        None,
    );
    let identity = ManagedGeneration {
        number: 1,
        region,
        task,
    };
    futures_lite::future::block_on(name.acquire(&cx, identity)).unwrap();
    assert_eq!(registry.lock().whereis("service"), Some(task));
    name.release();
    assert!(registry.lock().is_empty());
    assert!(!clock.observed_lock.load(Ordering::Relaxed));
}
