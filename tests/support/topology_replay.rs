use asupersync::runtime::scheduler::stealing::steal_task;
use asupersync::runtime::scheduler::{LocalQueue, SchedulerTopologyDescriptor};
use asupersync::types::TaskId;
use asupersync::util::DetHasher;
use asupersync::util::DetRng;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReplayLocality {
    Local,
    Remote,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopologyReplayEvent {
    pub thief_worker: usize,
    pub source_worker: usize,
    pub thief_cohort: usize,
    pub source_cohort: usize,
    pub task_id: TaskId,
    pub locality: ReplayLocality,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopologyReplayTrace {
    pub topology: SchedulerTopologyDescriptor,
    pub worker_to_cohort: Vec<usize>,
    pub replay_workers: Vec<usize>,
    pub events: Vec<TopologyReplayEvent>,
}

impl TopologyReplayTrace {
    #[must_use]
    pub fn stable_hash(&self) -> u64 {
        let mut hasher = DetHasher::default();
        self.topology.worker_threads.hash(&mut hasher);
        self.topology.cohort_count.hash(&mut hasher);
        self.topology.memory_budget_gib.hash(&mut hasher);
        self.worker_to_cohort.hash(&mut hasher);
        self.replay_workers.hash(&mut hasher);
        for event in &self.events {
            event.thief_worker.hash(&mut hasher);
            event.source_worker.hash(&mut hasher);
            event.thief_cohort.hash(&mut hasher);
            event.source_cohort.hash(&mut hasher);
            event.task_id.hash(&mut hasher);
            event.locality.hash(&mut hasher);
        }
        hasher.finish()
    }

    #[must_use]
    pub fn remote_spill_count(&self) -> usize {
        self.events
            .iter()
            .filter(|event| event.locality == ReplayLocality::Remote)
            .count()
    }
}

#[derive(Debug, Clone)]
pub struct TopologyFixture {
    topology: SchedulerTopologyDescriptor,
    worker_to_cohort: Vec<usize>,
    replay_workers: Vec<usize>,
    seed: u64,
    seeded_workers: Vec<SeededWorker>,
}

#[derive(Debug, Clone)]
struct SeededWorker {
    worker_id: usize,
    task_id_start: u32,
    task_count: usize,
}

impl TopologyFixture {
    #[must_use]
    pub fn new(
        topology: SchedulerTopologyDescriptor,
        worker_to_cohort: Vec<usize>,
        replay_workers: Vec<usize>,
        seed: u64,
    ) -> Self {
        assert_eq!(
            topology.worker_threads,
            worker_to_cohort.len(),
            "worker_threads must match worker_to_cohort length"
        );
        assert!(topology.cohort_count > 0, "cohort_count must be non-zero");
        for (worker_id, cohort_id) in worker_to_cohort.iter().copied().enumerate() {
            assert!(
                cohort_id < topology.cohort_count,
                "worker {worker_id} mapped to out-of-range cohort {cohort_id}"
            );
        }
        for &worker_id in &replay_workers {
            assert!(
                worker_id < topology.worker_threads,
                "replay worker {worker_id} out of range"
            );
        }

        Self {
            topology,
            worker_to_cohort,
            replay_workers,
            seed,
            seeded_workers: Vec::new(),
        }
    }

    #[must_use]
    pub fn seed_worker(mut self, worker_id: usize, task_id_start: u32, task_count: usize) -> Self {
        assert!(
            worker_id < self.topology.worker_threads,
            "seed worker {worker_id} out of range"
        );
        assert!(task_count > 0, "task_count must be positive");
        self.seeded_workers.push(SeededWorker {
            worker_id,
            task_id_start,
            task_count,
        });
        self
    }

    #[must_use]
    pub fn replay(&self) -> TopologyReplayTrace {
        let max_task_id = self
            .seeded_workers
            .iter()
            .map(|seeded| seeded.task_id_start + seeded.task_count as u32)
            .max()
            .unwrap_or(0);
        let queues: Vec<_> = (0..self.topology.worker_threads)
            .map(|_| LocalQueue::new_for_test(max_task_id))
            .collect();

        let mut task_source = HashMap::new();
        let mut total_seeded = 0usize;
        for seeded in &self.seeded_workers {
            for offset in 0..seeded.task_count {
                let task_id = TaskId::new_for_test(seeded.task_id_start + offset as u32, 0);
                queues[seeded.worker_id].push(task_id);
                task_source.insert(task_id, seeded.worker_id);
                total_seeded += 1;
            }
        }

        let mut rng = DetRng::new(self.seed);
        let mut events = Vec::with_capacity(total_seeded);
        let replay_workers = if self.replay_workers.is_empty() {
            (0..self.topology.worker_threads).collect::<Vec<_>>()
        } else {
            self.replay_workers.clone()
        };
        let mut consecutive_idle = 0usize;

        while events.len() < total_seeded && consecutive_idle < replay_workers.len().max(1) {
            for &thief_worker in &replay_workers {
                let stealers: Vec<_> = queues
                    .iter()
                    .enumerate()
                    .filter(|(worker_id, _)| *worker_id != thief_worker)
                    .map(|(_, queue)| queue.stealer())
                    .collect();

                if let Some(task_id) = steal_task(&stealers, &mut rng) {
                    let source_worker = task_source
                        .remove(&task_id)
                        .expect("stolen task must have seeded source worker");
                    let thief_cohort = self.worker_to_cohort[thief_worker];
                    let source_cohort = self.worker_to_cohort[source_worker];
                    events.push(TopologyReplayEvent {
                        thief_worker,
                        source_worker,
                        thief_cohort,
                        source_cohort,
                        task_id,
                        locality: if thief_cohort == source_cohort {
                            ReplayLocality::Local
                        } else {
                            ReplayLocality::Remote
                        },
                    });
                    consecutive_idle = 0;
                } else {
                    consecutive_idle += 1;
                }
            }
        }

        assert_eq!(
            events.len(),
            total_seeded,
            "topology replay failed to drain all seeded tasks"
        );

        TopologyReplayTrace {
            topology: self.topology.clone(),
            worker_to_cohort: self.worker_to_cohort.clone(),
            replay_workers,
            events,
        }
    }
}
