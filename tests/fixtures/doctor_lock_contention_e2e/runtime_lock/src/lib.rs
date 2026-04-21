#![allow(clippy::all)]
pub struct RuntimeState;

impl RuntimeState {
    pub fn lock_order_probe(&self) {
        let _tasks = self.tasks.lock();
        let _regions = self.regions.lock();
        let lock_wait_ns_metric = 42;
        let _ = lock_wait_ns_metric;
        let _noise = "self.obligations.lock(); lock_hold_ns";
        // self.config.lock(); lock-metrics marker in a comment should be ignored.
    }
}
