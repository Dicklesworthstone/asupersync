//! Work stealing logic.

use crate::runtime::scheduler::local_queue::Stealer;
use crate::types::TaskId;
use crate::util::DetRng;

/// Tries to steal a task from a list of stealers.
///
/// Starts at a random index and iterates through all stealers.
pub fn steal_task(stealers: &[Stealer], rng: &mut DetRng) -> Option<TaskId> {
    if stealers.is_empty() {
        return None;
    }

    let len = stealers.len();
    let start = rng.next_usize(len);

    for i in 0..len {
        let idx = (start + i) % len;
        if let Some(task) = stealers[idx].steal() {
            return Some(task);
        }
    }

    None
}
