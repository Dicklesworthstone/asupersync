struct VirtualClock;

impl VirtualClock {
    fn now(&self) -> u64 {
        42
    }
}

fn uses_virtualized_time(clock: &VirtualClock) {
    let _tick = clock.now();
    let _documented_only = "std::time::SystemTime::now()";
    // std::time::Instant::now() appears in a comment and must not be reported.
}
