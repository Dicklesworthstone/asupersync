//! Queue selection for opt-in blocking-pool priorities.

use super::BlockingTask;
use crossbeam_queue::SegQueue;
use parking_lot::Mutex;
use std::collections::{BTreeMap, VecDeque};
use std::num::NonZeroUsize;

/// Selection policy for queued blocking work.
///
/// This controls dequeue order, not when concurrently dispatched closures
/// start or finish. Running closures are never preempted. Queue capacity is
/// controlled separately by [`super::BlockingAdmissionPolicy`]; existing
/// constructors keep admission unbounded.
///
/// With cohort affinity enabled, locality and spill/foreign-cohort turns choose
/// a queue first; this policy then selects a task within that queue. It does
/// not establish a single priority order across different cohort queues.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum BlockingQueuePolicy {
    /// Preserve arrival order within each queue, ignoring priority metadata.
    #[default]
    Fifo,
    /// Prefer larger priority values, with FIFO ordering within each priority.
    ///
    /// After `max_priority_streak` priority selections, one fairness turn
    /// visits the next nonempty priority class in ascending, wrapping order.
    /// A continuously queued class is therefore selected within at most 256
    /// fairness turns, even while other classes receive more work. Cancelled
    /// queued tasks also consume selections. This is a dispatch bound, not a
    /// wall-clock latency guarantee.
    Priority {
        /// Maximum preferred-priority selections between fairness turns.
        max_priority_streak: NonZeroUsize,
    },
}

pub(super) enum BlockingTaskQueue {
    Fifo(SegQueue<BlockingTask>),
    Priority {
        max_priority_streak: NonZeroUsize,
        queue: Mutex<PriorityQueue>,
    },
}

impl BlockingTaskQueue {
    pub(super) fn new(policy: BlockingQueuePolicy) -> Self {
        match policy {
            BlockingQueuePolicy::Fifo => Self::Fifo(SegQueue::new()),
            BlockingQueuePolicy::Priority {
                max_priority_streak,
            } => Self::Priority {
                max_priority_streak,
                queue: Mutex::new(PriorityQueue::default()),
            },
        }
    }

    pub(super) fn policy(&self) -> BlockingQueuePolicy {
        match self {
            Self::Fifo(_) => BlockingQueuePolicy::Fifo,
            Self::Priority {
                max_priority_streak,
                ..
            } => BlockingQueuePolicy::Priority {
                max_priority_streak: *max_priority_streak,
            },
        }
    }

    pub(super) fn push(&self, task: BlockingTask) {
        match self {
            Self::Fifo(queue) => queue.push(task),
            Self::Priority { queue, .. } => {
                queue
                    .lock()
                    .classes
                    .entry(task.priority)
                    .or_default()
                    .push_back(task);
            }
        }
    }

    pub(super) fn pop(&self) -> Option<BlockingTask> {
        match self {
            Self::Fifo(queue) => queue.pop(),
            Self::Priority {
                max_priority_streak,
                queue,
            } => queue.lock().pop(*max_priority_streak),
        }
    }
}

#[derive(Default)]
pub(super) struct PriorityQueue {
    classes: BTreeMap<u8, VecDeque<BlockingTask>>,
    priority_streak: usize,
    fairness_cursor: u8,
}

impl PriorityQueue {
    fn pop(&mut self, max_priority_streak: NonZeroUsize) -> Option<BlockingTask> {
        let (&highest, _) = self.classes.last_key_value()?;
        let fairness_turn = self.priority_streak >= max_priority_streak.get();
        let priority = if fairness_turn {
            self.classes
                .range(self.fairness_cursor..)
                .next()
                .or_else(|| self.classes.first_key_value())
                .map(|(&priority, _)| priority)?
        } else {
            highest
        };
        let class = self.classes.get_mut(&priority)?;
        let task = class.pop_front()?;
        if class.is_empty() {
            // Only an empty bucket is destroyed under the queue lock. The task
            // and all user captures leave the lock before execution or drop.
            self.classes.remove(&priority);
        }

        if fairness_turn {
            self.priority_streak = 0;
            self.fairness_cursor = priority.wrapping_add(1);
        } else {
            // The preceding comparison proves this cannot overflow, even
            // when the configured maximum is usize::MAX.
            self.priority_streak += 1;
        }
        Some(task)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::blocking_pool::{BlockingTaskCompletion, wall_clock_now};
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    fn task(priority: u8) -> BlockingTask {
        BlockingTask {
            work: Box::new(|| {}),
            priority,
            preferred_cohort: None,
            cancelled: Arc::new(AtomicBool::new(false)),
            completion: Arc::new(BlockingTaskCompletion::new(wall_clock_now)),
        }
    }

    #[test]
    fn every_priority_progresses_while_all_classes_are_replenished() {
        let max_priority_streak = NonZeroUsize::new(2).unwrap();
        let queue = BlockingTaskQueue::new(BlockingQueuePolicy::Priority {
            max_priority_streak,
        });
        for priority in 0..=u8::MAX {
            queue.push(task(priority));
        }

        // Keep every class continuously nonempty, including the highest and
        // lowest classes: arrivals must not restart the fairness cursor.
        for expected in 0..=u8::MAX {
            for _ in 0..max_priority_streak.get() {
                let selected = queue.pop().unwrap();
                assert_eq!(selected.priority, u8::MAX);
                queue.push(task(selected.priority));
            }
            let selected = queue.pop().unwrap();
            assert_eq!(selected.priority, expected);
            queue.push(task(selected.priority));
        }
        for _ in 0..max_priority_streak.get() {
            let selected = queue.pop().unwrap();
            assert_eq!(selected.priority, u8::MAX);
            queue.push(task(selected.priority));
        }
        assert_eq!(queue.pop().unwrap().priority, 0, "fairness cursor wraps");
    }

    #[test]
    fn empty_pops_and_new_arrivals_do_not_reset_fairness() {
        let queue = BlockingTaskQueue::new(BlockingQueuePolicy::Priority {
            max_priority_streak: NonZeroUsize::new(1).unwrap(),
        });
        assert!(queue.pop().is_none());
        queue.push(task(255));
        assert_eq!(queue.pop().unwrap().priority, 255);
        assert!(queue.pop().is_none());
        queue.push(task(255));
        queue.push(task(0));
        assert_eq!(queue.pop().unwrap().priority, 0);
        assert_eq!(queue.pop().unwrap().priority, 255);
        assert!(queue.pop().is_none());
    }
}
