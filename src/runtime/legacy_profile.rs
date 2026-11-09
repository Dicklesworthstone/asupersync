//! A bounded runtime profile for memory-poor targets.
//!
//! The stock [`RuntimeBuilder`] is sized for a server. At the revision this module was written against its
//! defaults are four workers with 2 MiB stacks, an on-demand blocking pool of up to 512 threads, an unbounded
//! global ready queue and an unbounded blocking job queue. On a board with tens of megabytes of memory those
//! defaults are not a configuration, they are a failure waiting for load.
//!
//! [`LegacyProfile`] is opt-in and changes nothing about the stock builder. It takes **every** cap explicitly,
//! refuses (with `ErrorKind::ConfigError`) a set of caps that leaves something unbounded or that exceeds a stated
//! byte budget for thread stacks, and, once the runtime is built, checks that the runtime really carries the caps
//! that were stated.
//!
//! # What is bounded
//!
//! * `worker_threads` and `thread_stack_bytes`: the scheduler workers. A value of 0 is refused, because the
//!   runtime would silently raise it (0 workers becomes 1, a 0-byte stack becomes 2 MiB).
//! * `blocking_max_threads`: the blocking pool's ceiling. The pool treats it as a hard ceiling, including for a
//!   later runtime resize, and starts no thread until its first job. 0 forbids blocking work altogether: the
//!   runtime keeps a pool that admits nothing ([`BlockingAdmissionPolicy::Forbidden`]), see "No pool is not a
//!   no-thread profile".
//! * `blocking_max_queued`: the blocking pool's job queue ([`BlockingAdmissionPolicy::Bounded`]). Only
//!   meaningful when blocking is allowed.
//! * `global_queue_limit`: the scheduler's global ready queue. 0 means unbounded and is refused.
//!
//! # An optional byte budget for the blocking pool
//!
//! [`LegacyCaps`] has public fields and so cannot grow one without breaking every literal. The byte budget is
//! therefore stated on the profile instead: [`LegacyProfile::with_blocking_live_bytes`]. A profile that does not
//! state one builds exactly the pool it always did ([`BlockingAdmissionPolicy::Bounded`]) and audits as it always
//! did. A profile that states one builds a [`BlockingAdmissionPolicy::BoundedBytes`] pool with the same
//! `blocking_max_queued`, and [`LegacyProfile::audit`] requires the runtime's pool to carry exactly that policy,
//! not merely the same queue count. Two consequences of that policy are the caller's to know:
//!
//! * the pool refuses every submission that provides no explicit byte charge (`ChargeRequired`), so the entry points
//!   that submit without a charge are refused on such a runtime; the charged ones (`try_spawn_charged`,
//!   `try_spawn_charged_with`, the standard-stream writers) are the ones that work;
//! * the budget bounds what the pool ADMITS. A closure the caller still holds, such as the one owned by a waiting
//!   `submit_charged` future, is outside it, and so is the rest of the process heap.
//!
//! With `blocking_max_threads == 0` the pool is [`BlockingAdmissionPolicy::Forbidden`], admits nothing, and no byte
//! can be live. A byte budget stated for such a profile is accepted and has no effect, as `blocking_max_queued`
//! has none there; the profile still builds, and audit still requires, a pool that forbids blocking.
//!
//! # The blocking-thread stack
//!
//! `thread_stack_bytes` applies to the scheduler workers only. The blocking pool starts its threads with
//! whatever stack size it is given, and by default none, so the platform chooses (for std, 2 MiB unless
//! `RUST_MIN_STACK` says otherwise, decided once per process). The profile therefore makes that figure a cap of
//! its own, `blocking_thread_stack_bytes`, **passes it to the pool** ([`RuntimeBuilder::blocking_thread_stack_size`],
//! which reaches `std::thread::Builder::stack_size` for every pool thread), and [`LegacyProfile::audit`] checks
//! the stack the runtime's pool was configured with against the stated one. A runtime whose pool was left to the
//! platform default carries no stated stack and does not match.
//!
//! This is the size **requested**, not a measurement. The operating system rounds it by its own page and
//! guard-page rules, and nothing safe can read a live thread's stack back, so the worst-case figure below is an
//! upper bound on requested address space, not on what the kernel reserves.
//!
//! # No pool is not a no-thread profile
//!
//! A runtime built with no blocking pool (`blocking_threads(0, 0)`) does not refuse blocking work, it runs it
//! somewhere else. At the revision this was written against:
//!
//! * `Cx::spawn_blocking` and `Cx::spawn_blocking_in` call the closure **inline on the executor thread** when
//!   the context has no pool;
//! * the free `spawn_blocking` does the same inside a runtime and, outside one, starts a dedicated thread (at
//!   most 256 at once, each with the platform stack);
//! * `spawn_blocking_io_off_worker` takes that same dedicated-thread path when it is given no pool.
//!
//! None of that is counted by the worst-case figure below, and the inline path is exactly what a renderer must
//! never do. So a profile with `blocking_max_threads == 0` does not build a runtime without a pool. It builds one
//! whose pool is [`BlockingAdmissionPolicy::Forbidden`]: it admits nothing and starts no thread, every context
//! inherits it, and each of those entry points sees "blocking is forbidden here" instead of "no pool":
//! `Cx::spawn_blocking{,_in}` return `SpawnError::RuntimeUnavailable`, `spawn_blocking_io` and
//! `spawn_blocking_io_off_worker` return an `Unsupported` error, and the closure is dropped unrun. The free
//! `spawn_blocking` returns the closure's own value, so it has no error to return and panics instead.
//! [`LegacyProfile::audit`] accepts a no-blocking profile only for a runtime that really has such a pool.
//!
//! # The caller-driven topology
//!
//! [`LegacyProfile::caller_driven`] selects a second topology for the same caps: the runtime starts **no thread at
//! all**. Its one worker sits in the current-thread driver. [`RuntimeBuilder::current_thread`] shares that driver
//! but also starts a background thread that runs the worker between calls; this topology starts none, so the thread
//! that calls `Runtime::block_on` or `Runtime::shutdown_drained` is the only thread that ever runs the worker. Every
//! task, wheel timer, wake and reactor turn of the runtime happens on that thread, inside that call.
//!
//! * A caller-driven profile must state `worker_threads == 1` and `blocking_max_threads == 0`. Anything else is
//!   refused by name ([`TopologyViolation`]) and never downgraded. The runtime keeps `worker_threads == 1` in its
//!   configuration, so the cap comparison of [`LegacyProfile::audit`] is the one it always was; that no thread exists
//!   is audited separately, from the runtime's own bookkeeping.
//! * Blocking work is rejected, never run inline: the pool is [`BlockingAdmissionPolicy::Forbidden`], as for any
//!   profile with `blocking_max_threads == 0`. A stated live-byte budget ([`LegacyProfile::with_blocking_live_bytes`])
//!   is accepted and ignored, as for any profile with no blocking thread, so a charged submission is refused as
//!   `Forbidden` and never as `ChargeTooLarge`.
//! * [`RuntimeBuilder::build`] refuses, by name, the options that would start a helper thread (the deadline monitor,
//!   resource sampling) and the ones only a worker thread could honour (`on_thread_start`, `on_thread_stop`).
//!   [`LegacyProfile::audit`] also requires an empty worker-thread handle list and no monitor or sampler thread. That
//!   audit runs after the build: an option that starts a thread during the build would have started it before the
//!   audit refuses it. This revision has no such option. A later revision's background I/O driver option is refused
//!   by the existing host-kind check when the build begins, which was read and not exercised here.
//! * Work spawned through a handle (`RuntimeHandle::spawn`) makes no progress until the next `block_on` or root drain
//!   on some thread. Nothing runs the worker in between, and the first such call picks the work up.
//! * `thread_stack_bytes` binds no thread in this mode. Tasks run on the calling thread's own stack, which the
//!   profile does not bound, and [`LegacyCaps::worst_case_stack_bytes`] still counts one worker stack, so its figure
//!   over-counts. The profile makes no stack claim about the caller's thread.
//! * `global_queue_limit` is carried and audited like every cap. At the revision this was written against the
//!   scheduler treats it as advisory (past it, it logs and still schedules), so no hard admission bound follows from
//!   it in either topology.
//! * Not counted, as for every profile: the short-lived shutdown and teardown helpers, the process-global fallback
//!   timer pump that a wall-clock sleep outside any runtime context starts, and any thread the application starts.
//!
//! # What this does not show
//!
//! * The file system, `net::lookup_all`, STUN, the Kafka producer transaction and consumer calls, and native
//!   remote discovery check for a forbidden pool first and return an error (`Unsupported`, `KafkaError::Io`,
//!   `BlockingPoolUnavailable`, `StunError::Network`). Entry points that reach the pool through
//!   `spawn_blocking_on_pool` and return their closure's own value still panic on a forbidden pool, as the free
//!   `spawn_blocking` does: the ATP product modules, the mailbox relay and bond descriptor, and the desktop
//!   profile among them. A runtime that forbids blocking must not use those; nothing here removes them from the
//!   build.
//! * A caller outside any runtime that uses the free `spawn_blocking` gets the dedicated-thread path. No
//!   profile bounds it.
//! * A pool that has been shut down hands its work back and the async entry points then run it inline (the
//!   existing shutdown fallback). A forbidden pool never does: it reports `Forbidden`, not `Shutdown`.
//! * The budget is a bound on stack **address space** in the worst case, not on resident memory, and not on
//!   "fits in N MiB": the heap, the binary, the kernel and the other processes are all outside it.
//! * Other threads are not counted: the deadline monitor (off by default, one thread when enabled), the
//!   resource sampler (off by default), the short-lived shutdown and teardown helpers, and any thread the
//!   application starts.
//! * Queue bounds count jobs, not bytes, unless the profile states a byte budget (above). That budget then bounds
//!   the closure storage and declared heap of what the pool admits. What a closure holds before the pool admits it
//!   is the caller's.
//! * The budget is a parameter. This module states no figure for any board; measuring one is not done here.

use crate::error::{Error, ErrorKind};
use crate::runtime::{
    BlockingAdmissionPolicy, BlockingPoolHandle, Runtime, RuntimeBuilder, RuntimeConfig,
};
use std::fmt;
use std::num::NonZeroUsize;

/// Every cap the profile bounds. There is deliberately no `Default`: a cap that is not stated is not there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LegacyCaps {
    /// Scheduler worker threads. Must be at least 1.
    pub worker_threads: usize,
    /// Stack size of each scheduler worker, in bytes. Must be at least 1.
    pub thread_stack_bytes: usize,
    /// Ceiling on blocking-pool threads. 0 forbids blocking work altogether (a pool that admits nothing).
    pub blocking_max_threads: usize,
    /// Stack size requested for each blocking-pool thread, passed to the pool's thread builder. Must be at least
    /// 1 when blocking is allowed; ignored (and read as 0) when it is forbidden, since no thread starts.
    pub blocking_thread_stack_bytes: usize,
    /// Scheduler global ready queue limit. Must be at least 1 (0 means unbounded).
    pub global_queue_limit: usize,
    /// Blocking job queue bound. Must be at least 1 when blocking is allowed; ignored when it is forbidden.
    pub blocking_max_queued: usize,
}

/// One way a set of caps fails to be bounded. Reported by name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapViolation {
    /// `worker_threads` is 0, which the runtime would raise to 1.
    NoWorkers,
    /// `thread_stack_bytes` is 0, which the runtime would replace with its default.
    StackNotStated,
    /// Blocking is allowed but `blocking_thread_stack_bytes` is 0.
    BlockingStackNotStated,
    /// `global_queue_limit` is 0, which means unbounded.
    GlobalQueueUnbounded,
    /// Blocking is allowed but `blocking_max_queued` is 0, which would leave its job queue unbounded.
    BlockingQueueUnbounded,
    /// The worst-case stack bytes do not fit in 64 bits.
    StackBudgetOverflow,
    /// The worst-case stack bytes exceed the budget.
    StackBudgetExceeded {
        /// `worker_threads * thread_stack_bytes + blocking_max_threads * blocking_thread_stack_bytes`.
        worst_case_bytes: u64,
        /// The budget that was stated.
        budget_bytes: u64,
    },
}

impl fmt::Display for CapViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoWorkers => {
                f.write_str("NoWorkers: worker_threads is 0, which the runtime would raise to 1")
            }
            Self::StackNotStated => f.write_str(
                "StackNotStated: thread_stack_bytes is 0, which the runtime would replace with its default",
            ),
            Self::BlockingStackNotStated => f.write_str(
                "BlockingStackNotStated: a blocking pool is configured but blocking_thread_stack_bytes is 0",
            ),
            Self::GlobalQueueUnbounded => f.write_str(
                "GlobalQueueUnbounded: global_queue_limit is 0, which means unbounded",
            ),
            Self::BlockingQueueUnbounded => f.write_str(
                "BlockingQueueUnbounded: a blocking pool is configured but its job queue is unbounded",
            ),
            Self::StackBudgetOverflow => {
                f.write_str("StackBudgetOverflow: the worst-case stack bytes overflow 64 bits")
            }
            Self::StackBudgetExceeded {
                worst_case_bytes,
                budget_bytes,
            } => write!(
                f,
                "StackBudgetExceeded: worst-case stack address space {worst_case_bytes} bytes exceeds the {budget_bytes}-byte budget"
            ),
        }
    }
}

/// One way a profile's topology asks for something the topology cannot give. Reported by name, apart from
/// [`CapViolation`] so that enum, and every `match` over it, stay as they were.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TopologyViolation {
    /// A caller-driven profile states a worker count other than 1: the one worker is the thread that calls
    /// `block_on`, and no other count is silently turned into it.
    CallerDrivenNeedsOneWorker {
        /// The stated `worker_threads`.
        worker_threads: usize,
    },
    /// A caller-driven profile states blocking threads: the runtime starts no thread, so blocking work is rejected
    /// (a forbidden pool) and a ceiling above 0 would promise threads that never start.
    CallerDrivenForbidsBlockingThreads {
        /// The stated `blocking_max_threads`.
        blocking_max_threads: usize,
    },
}

impl fmt::Display for TopologyViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CallerDrivenNeedsOneWorker { worker_threads } => write!(
                f,
                "CallerDrivenNeedsOneWorker: a caller-driven profile states worker_threads {worker_threads}, but its one worker is the calling thread"
            ),
            Self::CallerDrivenForbidsBlockingThreads {
                blocking_max_threads,
            } => write!(
                f,
                "CallerDrivenForbidsBlockingThreads: a caller-driven profile states blocking_max_threads {blocking_max_threads}, but it starts no thread and forbids blocking work"
            ),
        }
    }
}

/// Which thread topology a profile builds. Private: the public surface is [`LegacyProfile::caller_driven`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Topology {
    /// The stated number of scheduler worker threads, as the profile has always built them.
    Threaded,
    /// No thread at all; see the module docs.
    CallerDriven,
}

/// `threads * stack_bytes` in 64 bits, or `None` if either factor or the product does not fit.
fn stack_product(threads: usize, stack_bytes: usize) -> Option<u64> {
    u64::try_from(threads)
        .ok()?
        .checked_mul(u64::try_from(stack_bytes).ok()?)
}

impl LegacyCaps {
    /// Worst-case stack address space: every worker plus every blocking thread the ceiling allows, each at its
    /// stack size. `None` if it does not fit in 64 bits.
    #[must_use]
    pub fn worst_case_stack_bytes(&self) -> Option<u64> {
        let workers = stack_product(self.worker_threads, self.thread_stack_bytes)?;
        let blocking = stack_product(self.blocking_max_threads, self.blocking_thread_stack_bytes)?;
        workers.checked_add(blocking)
    }

    /// Every way these caps fail to be bounded or exceed `stack_budget_bytes`, in a fixed order. Empty means
    /// the caps are acceptable.
    #[must_use]
    pub fn violations(&self, stack_budget_bytes: u64) -> Vec<CapViolation> {
        let mut found = Vec::new();
        let has_pool = self.blocking_max_threads > 0;
        if self.worker_threads == 0 {
            found.push(CapViolation::NoWorkers);
        }
        if self.thread_stack_bytes == 0 {
            found.push(CapViolation::StackNotStated);
        }
        if has_pool && self.blocking_thread_stack_bytes == 0 {
            found.push(CapViolation::BlockingStackNotStated);
        }
        if self.global_queue_limit == 0 {
            found.push(CapViolation::GlobalQueueUnbounded);
        }
        if has_pool && self.blocking_max_queued == 0 {
            found.push(CapViolation::BlockingQueueUnbounded);
        }
        match self.worst_case_stack_bytes() {
            None => found.push(CapViolation::StackBudgetOverflow),
            Some(worst_case_bytes) if worst_case_bytes > stack_budget_bytes => {
                found.push(CapViolation::StackBudgetExceeded {
                    worst_case_bytes,
                    budget_bytes: stack_budget_bytes,
                });
            }
            Some(_) => {}
        }
        found
    }

    /// The caps a built runtime carries, read from its configuration and its blocking pool (`None` when there
    /// is no pool). An unbounded queue reads as 0, and so does a forbidden pool, which has no queue. A pool
    /// whose threads were left to the platform default reads as a blocking stack of 0: none was stated to it.
    #[must_use]
    pub fn of_config(config: &RuntimeConfig, pool: Option<&BlockingPoolHandle>) -> Self {
        let blocking_max_queued = match pool.map(BlockingPoolHandle::admission_policy) {
            Some(
                BlockingAdmissionPolicy::Bounded { max_queued }
                | BlockingAdmissionPolicy::BoundedBytes { max_queued, .. },
            ) => max_queued.get(),
            Some(BlockingAdmissionPolicy::Unbounded | BlockingAdmissionPolicy::Forbidden)
            | None => 0,
        };
        Self {
            worker_threads: config.worker_threads,
            thread_stack_bytes: config.thread_stack_size,
            blocking_max_threads: config.blocking.max_threads,
            blocking_thread_stack_bytes: pool
                .and_then(BlockingPoolHandle::thread_stack_size)
                .unwrap_or(0),
            global_queue_limit: config.global_queue_limit,
            blocking_max_queued,
        }
    }

    /// The caps a built runtime carries.
    #[must_use]
    pub fn of_runtime(runtime: &Runtime) -> Self {
        Self::of_config(runtime.config(), runtime.blocking_handle().as_ref())
    }

    /// These caps as a runtime can carry them. With blocking forbidden there is no queue to bound and no
    /// blocking thread whose stack matters, so those two are not something a runtime can show.
    fn observable(&self) -> Self {
        if self.blocking_max_threads > 0 {
            return *self;
        }
        Self {
            blocking_thread_stack_bytes: 0,
            blocking_max_queued: 0,
            ..*self
        }
    }

    /// The names of the fields in which `self` and `carried` differ.
    fn differing_fields(&self, carried: &Self) -> Vec<&'static str> {
        let mut names = Vec::new();
        if self.worker_threads != carried.worker_threads {
            names.push("worker_threads");
        }
        if self.thread_stack_bytes != carried.thread_stack_bytes {
            names.push("thread_stack_bytes");
        }
        if self.blocking_max_threads != carried.blocking_max_threads {
            names.push("blocking_max_threads");
        }
        if self.blocking_thread_stack_bytes != carried.blocking_thread_stack_bytes {
            names.push("blocking_thread_stack_bytes");
        }
        if self.global_queue_limit != carried.global_queue_limit {
            names.push("global_queue_limit");
        }
        if self.blocking_max_queued != carried.blocking_max_queued {
            names.push("blocking_max_queued");
        }
        names
    }
}

/// Every violation, joined for an error message.
fn describe(violations: &[CapViolation]) -> String {
    violations
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}

/// A set of caps and the stack budget they must fit in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LegacyProfile {
    caps: LegacyCaps,
    stack_budget_bytes: u64,
    /// The blocking pool's live-byte budget, if one was stated. `None` is the profile as it always was.
    blocking_live_bytes: Option<NonZeroUsize>,
    /// The thread topology. [`Topology::Threaded`] is the profile as it always was.
    topology: Topology,
}

impl LegacyProfile {
    /// `stack_budget_bytes` is the ceiling on [`LegacyCaps::worst_case_stack_bytes`]. It is the caller's number;
    /// nothing here supplies one. The profile states no byte budget for the blocking pool: see
    /// [`Self::with_blocking_live_bytes`]. It builds scheduler worker threads, as it always has: see
    /// [`Self::caller_driven`] for the topology that builds none.
    #[must_use]
    pub const fn new(caps: LegacyCaps, stack_budget_bytes: u64) -> Self {
        Self {
            caps,
            stack_budget_bytes,
            blocking_live_bytes: None,
            topology: Topology::Threaded,
        }
    }

    /// This profile in the caller-driven topology: the runtime it builds starts **no thread**, and the thread that
    /// calls `Runtime::block_on` or `Runtime::shutdown_drained` is the only one that ever runs its worker (see the
    /// module docs, "The caller-driven topology").
    ///
    /// No cap changes. The profile must state `worker_threads == 1` and `blocking_max_threads == 0`; otherwise
    /// [`Self::topology_violations`] names why and [`Self::validate`], [`Self::builder`] and [`Self::build`] refuse
    /// it. Blocking work is rejected and never run inline; a stated live-byte budget is ignored, as for any profile
    /// with no blocking thread.
    #[must_use]
    pub const fn caller_driven(self) -> Self {
        Self {
            caps: self.caps,
            stack_budget_bytes: self.stack_budget_bytes,
            blocking_live_bytes: self.blocking_live_bytes,
            topology: Topology::CallerDriven,
        }
    }

    /// Whether this profile builds the caller-driven topology ([`Self::caller_driven`]).
    #[must_use]
    pub const fn is_caller_driven(&self) -> bool {
        matches!(self.topology, Topology::CallerDriven)
    }

    /// The most threads the runtime this profile builds can ever own: the scheduler workers it starts plus the
    /// blocking pool's ceiling. It is 0 for every caller-driven profile that passes [`Self::validate`]. `None` if the
    /// sum does not fit in 64 bits.
    ///
    /// It counts the threads the caps govern. It does not count the short-lived shutdown helpers, a deadline monitor,
    /// a resource sampler or a background I/O driver thread ([`RuntimeBuilder::background_io_driver`]) configured on
    /// the builder afterwards, or any thread the application starts. A threaded profile whose builder enables the
    /// background I/O driver therefore owns one thread more than this ceiling. A caller-driven profile cannot: its
    /// runtime refuses that option when it is built, so its ceiling of 0 holds.
    #[must_use]
    pub fn os_thread_ceiling(&self) -> Option<u64> {
        let scheduler = match self.topology {
            Topology::Threaded => u64::try_from(self.caps.worker_threads).ok()?,
            Topology::CallerDriven => 0,
        };
        scheduler.checked_add(u64::try_from(self.caps.blocking_max_threads).ok()?)
    }

    /// This profile with its blocking pool also bounded in bytes: [`Self::builder`] selects
    /// [`BlockingAdmissionPolicy::BoundedBytes`] with the stated `blocking_max_queued` and `max_live_bytes`, and
    /// [`Self::audit`] requires a runtime's pool to carry exactly that policy.
    ///
    /// The budget bounds what the pool admits: the closure storage and declared heap of queued, running and pinned
    /// jobs (see [`BlockingAdmissionPolicy::BoundedBytes`]). It does not bound a closure the caller still holds, and
    /// it is not a limit on the process heap. A byte-bounded pool refuses every submission that uses an uncharged
    /// submission API.
    ///
    /// With `blocking_max_threads == 0` it has no effect: the pool forbids blocking and admits nothing.
    #[must_use]
    pub const fn with_blocking_live_bytes(self, max_live_bytes: NonZeroUsize) -> Self {
        Self {
            caps: self.caps,
            stack_budget_bytes: self.stack_budget_bytes,
            blocking_live_bytes: Some(max_live_bytes),
            topology: self.topology,
        }
    }

    /// The stated live-byte budget of the blocking pool, if any.
    #[must_use]
    pub const fn blocking_live_bytes(&self) -> Option<NonZeroUsize> {
        self.blocking_live_bytes
    }

    /// The stated caps.
    #[must_use]
    pub const fn caps(&self) -> LegacyCaps {
        self.caps
    }

    /// The stated budget.
    #[must_use]
    pub const fn stack_budget_bytes(&self) -> u64 {
        self.stack_budget_bytes
    }

    /// Every way the stated caps are unbounded or over budget. Empty means acceptable.
    #[must_use]
    pub fn violations(&self) -> Vec<CapViolation> {
        self.caps.violations(self.stack_budget_bytes)
    }

    /// Every way the profile's topology asks for something it cannot give, in a fixed order. Empty for every
    /// profile that is not caller-driven: [`Self::violations`] is about the caps alone and is not changed by the
    /// topology.
    #[must_use]
    pub fn topology_violations(&self) -> Vec<TopologyViolation> {
        let mut found = Vec::new();
        if self.is_caller_driven() {
            if self.caps.worker_threads != 1 {
                found.push(TopologyViolation::CallerDrivenNeedsOneWorker {
                    worker_threads: self.caps.worker_threads,
                });
            }
            if self.caps.blocking_max_threads != 0 {
                found.push(TopologyViolation::CallerDrivenForbidsBlockingThreads {
                    blocking_max_threads: self.caps.blocking_max_threads,
                });
            }
        }
        found
    }

    /// `Ok` if the stated caps and the topology are acceptable, otherwise a `ConfigError` naming every violation
    /// ([`Self::violations`], then [`Self::topology_violations`]).
    pub fn validate(&self) -> Result<(), Error> {
        let violations = self.violations();
        let topology = self.topology_violations();
        if violations.is_empty() && topology.is_empty() {
            return Ok(());
        }
        let mut parts = Vec::new();
        if !violations.is_empty() {
            parts.push(describe(&violations));
        }
        parts.extend(topology.iter().map(ToString::to_string));
        Err(Error::new(ErrorKind::ConfigError).with_message(parts.join("; ")))
    }

    /// A builder carrying exactly the stated caps, after [`Self::validate`]. The caller may keep configuring it,
    /// but [`Self::build`] and [`Self::audit`] check what it ends up carrying.
    pub fn builder(&self) -> Result<RuntimeBuilder, Error> {
        self.validate()?;
        // No blocking at all is a pool that refuses, not an absent pool: an absent pool runs blocking work inline.
        let policy = if self.caps.blocking_max_threads == 0 {
            BlockingAdmissionPolicy::Forbidden
        } else {
            // `validate` has refused a zero bound; the conversion still fails closed rather than unwrapping.
            let max_queued = NonZeroUsize::new(self.caps.blocking_max_queued).ok_or_else(|| {
                Error::new(ErrorKind::ConfigError)
                    .with_message(CapViolation::BlockingQueueUnbounded.to_string())
            })?;
            match self.blocking_live_bytes {
                Some(max_live_bytes) => BlockingAdmissionPolicy::BoundedBytes {
                    max_queued,
                    max_live_bytes,
                },
                None => BlockingAdmissionPolicy::Bounded { max_queued },
            }
        };
        // The caller-driven topology changes who runs the worker, not one cap below: every cap is applied to both.
        let base = match self.topology {
            Topology::Threaded => RuntimeBuilder::new(),
            Topology::CallerDriven => RuntimeBuilder::new().caller_driven_topology(),
        };
        let builder = base
            .worker_threads(self.caps.worker_threads)
            .thread_stack_size(self.caps.thread_stack_bytes)
            .global_queue_limit(self.caps.global_queue_limit)
            .blocking_threads(0, self.caps.blocking_max_threads)
            .blocking_admission_policy(policy);
        // A forbidden pool starts no thread, so there is no blocking stack to set. Otherwise the stated figure
        // is passed to the pool, which gives every thread it starts that stack.
        Ok(if self.caps.blocking_max_threads == 0 {
            builder
        } else {
            builder.blocking_thread_stack_size(self.caps.blocking_thread_stack_bytes)
        })
    }

    /// `Ok` if `runtime` carries exactly the stated caps, otherwise a `ConfigError` naming the fields that
    /// differ. A runtime whose blocking pool was not given the stated stack size differs in
    /// `blocking_thread_stack_bytes`, and so does one whose pool was left to the platform default.
    ///
    /// A profile that states a live-byte budget ([`Self::with_blocking_live_bytes`]) also requires the pool's
    /// policy to be exactly [`BlockingAdmissionPolicy::BoundedBytes`] with the stated queue bound and budget: a
    /// count-only pool, or a byte-bounded pool with another budget, is refused with an error naming the budget. A
    /// profile that states none does not constrain the byte policy, as before. A profile that forbids blocking is
    /// met only by a pool that forbids it, whatever budget it states.
    ///
    /// The stated caps must themselves be acceptable ([`Self::validate`]): a runtime that matches caps which are
    /// unbounded or over budget is not a bounded runtime, and this method is public for callers who build the
    /// runtime themselves.
    pub fn audit(&self, runtime: &Runtime) -> Result<(), Error> {
        self.validate()?;
        self.audit_topology(runtime)?;
        // A profile that forbids blocking is only met by a pool that refuses it. A runtime with no pool at all
        // runs blocking work inline, whatever figures it shows.
        if self.caps.blocking_max_threads == 0
            && !runtime
                .blocking_handle()
                .is_some_and(|pool| pool.admission_policy() == BlockingAdmissionPolicy::Forbidden)
        {
            return Err(Error::new(ErrorKind::ConfigError).with_message(
                "the profile forbids blocking work but the runtime's blocking pool is absent or admits work \
                 (a runtime with no pool runs blocking work inline on the executor)",
            ));
        }
        let stated = self.caps.observable();
        let carried = LegacyCaps::of_runtime(runtime);
        if carried == stated {
            return self.audit_live_bytes(runtime);
        }
        let fields = stated.differing_fields(&carried).join(", ");
        Err(Error::new(ErrorKind::ConfigError).with_message(format!(
            "the runtime does not carry the stated caps ({fields} differ): stated {stated:?}, carried {carried:?}"
        )))
    }

    /// The thread half of [`Self::audit`], read from the runtime's own bookkeeping. A caller-driven profile is met
    /// only by a runtime that holds its worker in the current-thread driver and owns no thread: an empty
    /// worker-thread handle list (which also covers a background I/O driver thread at a revision that has one), no
    /// deadline monitor and no resource sampler. A runtime built any other way, `RuntimeBuilder::current_thread()`
    /// included (it owns a background worker thread), is refused. A threaded profile is judged exactly as it always
    /// was; this check does not apply to it.
    ///
    /// It looks after the build. Options that would start a thread are refused when the runtime is built, before
    /// they can; this is the backstop for a runtime that was built some other way.
    fn audit_topology(&self, runtime: &Runtime) -> Result<(), Error> {
        if !self.is_caller_driven() {
            return Ok(());
        }
        let census = runtime.thread_census();
        let mut wrong: Vec<String> = Vec::new();
        if !census.loan_driver {
            wrong.push("it has no current-thread driver holding the worker".to_string());
        }
        if census.worker_thread_handles != 0 {
            wrong.push(format!(
                "it owns {} worker-thread handle(s)",
                census.worker_thread_handles
            ));
        }
        if census.deadline_monitor {
            wrong.push("it owns a deadline-monitor thread".to_string());
        }
        if census.resource_sampler {
            wrong.push("it owns a resource-sampler thread".to_string());
        }
        if wrong.is_empty() {
            return Ok(());
        }
        Err(Error::new(ErrorKind::ConfigError).with_message(format!(
            "the profile is caller-driven and starts no thread, but {}",
            wrong.join("; ")
        )))
    }

    /// The byte half of [`Self::audit`]: when a live-byte budget is stated and blocking is allowed, the pool's policy
    /// must be exactly the one [`Self::builder`] selects. The queue bound was already compared with the other caps,
    /// but a count-only pool shows the same queue bound, so it is the policy itself that is compared here.
    fn audit_live_bytes(&self, runtime: &Runtime) -> Result<(), Error> {
        let Some(max_live_bytes) = self.blocking_live_bytes else {
            return Ok(());
        };
        // Forbidding blocking leaves no byte to bound; the forbidding pool itself was checked by the caller.
        if self.caps.blocking_max_threads == 0 {
            return Ok(());
        }
        let max_queued = NonZeroUsize::new(self.caps.blocking_max_queued).ok_or_else(|| {
            Error::new(ErrorKind::ConfigError)
                .with_message(CapViolation::BlockingQueueUnbounded.to_string())
        })?;
        let stated = BlockingAdmissionPolicy::BoundedBytes {
            max_queued,
            max_live_bytes,
        };
        let carried = runtime
            .blocking_handle()
            .map(|pool| pool.admission_policy());
        if carried == Some(stated) {
            return Ok(());
        }
        Err(Error::new(ErrorKind::ConfigError).with_message(format!(
            "the profile states a live-byte budget of {max_live_bytes} bytes for the blocking pool but the runtime's \
             pool carries {carried:?}, not {stated:?}"
        )))
    }

    /// Validate, build, and audit. A runtime comes back only if it carries exactly the stated caps and they are
    /// within budget.
    pub fn build(&self) -> Result<Runtime, Error> {
        let runtime = self.builder()?.build()?;
        self.audit(&runtime)?;
        Ok(runtime)
    }
}

#[cfg(test)]
#[allow(clippy::pedantic, clippy::nursery)]
mod tests {
    use super::*;
    use crate::runtime::{BlockingFactoryError, BlockingSpawnErrorKind};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::{Duration, Instant};

    const MIB: usize = 1024 * 1024;
    const WAIT: Duration = Duration::from_secs(10);
    const SETTLE: Duration = Duration::from_millis(200);

    /// Caps for a test. The numbers are test values only: they say nothing about any board.
    /// One worker and two blocking threads at `blocking_stack` each, a 2 MiB worker stack (the stock figure,
    /// which upstream tests never go below), a 64-entry ready queue and an 8-entry blocking queue.
    fn caps(blocking_stack: usize) -> LegacyCaps {
        LegacyCaps {
            worker_threads: 1,
            thread_stack_bytes: 2 * MIB,
            blocking_max_threads: 2,
            blocking_thread_stack_bytes: blocking_stack,
            global_queue_limit: 64,
            blocking_max_queued: 8,
        }
    }

    /// The profile whose budget is exactly its own worst case, by hand: 1 x 2 MiB + 2 x 2 MiB = 6 MiB.
    fn green() -> LegacyProfile {
        LegacyProfile::new(caps(2 * MIB), 6 * 1024 * 1024)
    }

    /// `green`, under the name the tests below already use. The blocking stack is an explicit setting the profile
    /// passes to the pool, so nothing about it depends on the process any more.
    fn green_for_this_process() -> LegacyProfile {
        green()
    }

    /// A profile that forbids blocking work: the shape of `green`, with no blocking threads and so no blocking
    /// queue or blocking stack to state.
    fn no_blocking_for_this_process() -> LegacyProfile {
        let stated = LegacyCaps {
            blocking_max_threads: 0,
            blocking_max_queued: 0,
            blocking_thread_stack_bytes: 0,
            ..caps(2 * MIB)
        };
        LegacyProfile::new(stated, bytes(1, 2 * MIB))
    }

    fn bytes(threads: usize, stack: usize) -> u64 {
        u64::try_from(threads * stack).unwrap()
    }

    /// `green` with its blocking pool also bounded to `limit` live bytes: 8 queued jobs, 2 threads.
    fn budgeted(limit: usize) -> LegacyProfile {
        green().with_blocking_live_bytes(NonZeroUsize::new(limit).unwrap())
    }

    /// The refusal kind of an uncharged submission, `None` if it was admitted. The handle of an admitted job is
    /// dropped: these jobs do nothing.
    fn uncharged_refusal(
        pool: &crate::runtime::BlockingPoolHandle,
    ) -> Option<BlockingSpawnErrorKind> {
        pool.try_spawn(|| {}).err().map(|refused| refused.kind())
    }

    /// Every cap at `usize::MAX`: the worker term and the blocking term each fit in 64 bits on a 32-bit host
    /// but their sum does not, and on a 64-bit host the first product already overflows. Either way: overflow.
    fn all_max() -> LegacyCaps {
        LegacyCaps {
            worker_threads: usize::MAX,
            thread_stack_bytes: usize::MAX,
            blocking_max_threads: usize::MAX,
            blocking_thread_stack_bytes: usize::MAX,
            global_queue_limit: 64,
            blocking_max_queued: 8,
        }
    }

    #[test]
    fn the_worst_case_is_workers_times_their_stack_plus_blocking_threads_times_theirs() {
        assert_eq!(green().caps().worst_case_stack_bytes(), Some(6_291_456));
        // The stock figures, by hand: 4 workers and 512 blocking threads, all at 2 MiB.
        let stock = LegacyCaps {
            worker_threads: 4,
            thread_stack_bytes: 2 * MIB,
            blocking_max_threads: 512,
            blocking_thread_stack_bytes: 2 * MIB,
            global_queue_limit: 0,
            blocking_max_queued: 0,
        };
        assert_eq!(stock.worst_case_stack_bytes(), Some(1_082_130_432));
        // The two stacks are different caps: a larger blocking stack changes only the blocking term.
        let bigger_blocking = LegacyCaps {
            blocking_thread_stack_bytes: 4 * MIB,
            ..caps(2 * MIB)
        };
        assert_eq!(
            bigger_blocking.worst_case_stack_bytes(),
            Some(bytes(1, 2 * MIB) + bytes(2, 4 * MIB))
        );
        assert_eq!(all_max().worst_case_stack_bytes(), None);
    }

    #[test]
    fn a_profile_at_exactly_its_stack_budget_is_accepted_and_one_byte_under_is_refused() {
        let profile = green();
        assert_eq!(profile.stack_budget_bytes(), 6_291_456);
        assert!(
            profile.violations().is_empty(),
            "{:?}",
            profile.violations()
        );
        assert!(profile.validate().is_ok());
        assert!(profile.builder().is_ok());

        let tight = LegacyProfile::new(profile.caps(), 6_291_455);
        let expected = CapViolation::StackBudgetExceeded {
            worst_case_bytes: 6_291_456,
            budget_bytes: 6_291_455,
        };
        assert_eq!(tight.violations(), [expected]);
        let error = tight
            .validate()
            .expect_err("one byte over budget is refused");
        assert_eq!(error.kind(), ErrorKind::ConfigError);
        assert!(error.message().unwrap().contains("StackBudgetExceeded"));
        assert!(tight.builder().is_err());
    }

    #[test]
    fn each_planted_cap_defect_is_refused_by_its_own_name() {
        let base = caps(2 * MIB);
        let budget = green().stack_budget_bytes();
        // The baseline is green first, so removing any one plant below leaves nothing to refuse.
        assert!(LegacyProfile::new(base, budget).violations().is_empty());

        let exceeded = |worst: u64| CapViolation::StackBudgetExceeded {
            worst_case_bytes: worst,
            budget_bytes: budget,
        };
        let plants = [
            (
                "workers_zero",
                LegacyCaps {
                    worker_threads: 0,
                    ..base
                },
                CapViolation::NoWorkers,
            ),
            (
                "worker_stack_zero",
                LegacyCaps {
                    thread_stack_bytes: 0,
                    ..base
                },
                CapViolation::StackNotStated,
            ),
            (
                "blocking_stack_zero",
                LegacyCaps {
                    blocking_thread_stack_bytes: 0,
                    ..base
                },
                CapViolation::BlockingStackNotStated,
            ),
            (
                "global_queue_unbounded",
                LegacyCaps {
                    global_queue_limit: 0,
                    ..base
                },
                CapViolation::GlobalQueueUnbounded,
            ),
            (
                "blocking_queue_unbounded",
                LegacyCaps {
                    blocking_max_queued: 0,
                    ..base
                },
                CapViolation::BlockingQueueUnbounded,
            ),
            (
                "blocking_max_left_at_the_stock_512",
                LegacyCaps {
                    blocking_max_threads: 512,
                    ..base
                },
                exceeded(bytes(1, 2 * MIB) + bytes(512, 2 * MIB)),
            ),
            (
                "worker_stack_doubled",
                LegacyCaps {
                    thread_stack_bytes: 4 * MIB,
                    ..base
                },
                exceeded(bytes(1, 4 * MIB) + bytes(2, 2 * MIB)),
            ),
            (
                "blocking_stack_doubled",
                LegacyCaps {
                    blocking_thread_stack_bytes: 4 * MIB,
                    ..base
                },
                exceeded(bytes(1, 2 * MIB) + bytes(2, 4 * MIB)),
            ),
            (
                "workers_left_at_the_stock_default",
                LegacyCaps {
                    worker_threads: RuntimeConfig::DEFAULT_WORKER_THREADS,
                    ..base
                },
                exceeded(bytes(RuntimeConfig::DEFAULT_WORKER_THREADS, 2 * MIB) + bytes(2, 2 * MIB)),
            ),
            (
                "a_cap_that_overflows",
                all_max(),
                CapViolation::StackBudgetOverflow,
            ),
        ];
        for (name, planted, expected) in plants {
            let profile = LegacyProfile::new(planted, budget);
            assert_eq!(profile.violations(), [expected], "{name}");
            let error = profile.validate().expect_err(name);
            assert_eq!(error.kind(), ErrorKind::ConfigError, "{name}");
            assert!(
                error.message().unwrap().contains(&expected.to_string()),
                "{name}: {:?}",
                error.message()
            );
            assert!(profile.builder().is_err(), "{name}");
        }
    }

    #[test]
    fn a_profile_with_no_blocking_pool_needs_no_queue_bound_and_no_blocking_stack() {
        let no_pool = LegacyCaps {
            blocking_max_threads: 0,
            blocking_max_queued: 0,
            blocking_thread_stack_bytes: 0,
            ..caps(2 * MIB)
        };
        let profile = LegacyProfile::new(no_pool, bytes(1, 2 * MIB));
        assert!(
            profile.violations().is_empty(),
            "{:?}",
            profile.violations()
        );
        // Remove the exemption: the same two fields with a pool are refused, by name.
        let with_pool = LegacyCaps {
            blocking_max_threads: 1,
            ..no_pool
        };
        assert_eq!(
            LegacyProfile::new(with_pool, u64::MAX).violations(),
            [
                CapViolation::BlockingStackNotStated,
                CapViolation::BlockingQueueUnbounded
            ]
        );
    }

    #[test]
    fn violations_are_reported_together_in_a_fixed_order() {
        let everything_open = LegacyCaps {
            worker_threads: 0,
            thread_stack_bytes: 0,
            blocking_max_threads: 3,
            blocking_thread_stack_bytes: 0,
            global_queue_limit: 0,
            blocking_max_queued: 0,
        };
        assert_eq!(
            LegacyProfile::new(everything_open, 0).violations(),
            [
                CapViolation::NoWorkers,
                CapViolation::StackNotStated,
                CapViolation::BlockingStackNotStated,
                CapViolation::GlobalQueueUnbounded,
                CapViolation::BlockingQueueUnbounded,
            ]
        );
    }

    #[test]
    fn the_stated_blocking_stack_is_passed_to_the_pool_and_read_back_from_it() {
        // This test replaces a canary for the constant std uses when a thread is given no stack size. The
        // profile no longer relies on that: it states the size, the pool is given it, and the audit reads the
        // pool's configured figure. What is read back is the size requested, not a measurement of a thread.
        let profile = LegacyProfile::new(caps(3 * MIB), bytes(1, 2 * MIB) + bytes(2, 3 * MIB));
        let runtime = profile.build().unwrap();
        let pool = runtime.blocking_handle().unwrap();
        assert_eq!(pool.thread_stack_size(), Some(3 * MIB));
        assert_eq!(
            LegacyCaps::of_runtime(&runtime).blocking_thread_stack_bytes,
            3 * MIB
        );
        assert!(profile.audit(&runtime).is_ok());
        // A job still runs on that pool.
        let ran = Arc::new(AtomicUsize::new(0));
        let for_job = Arc::clone(&ran);
        let handle = pool
            .try_spawn(move || {
                for_job.fetch_add(1, Ordering::SeqCst);
            })
            .expect("a job within the caps is admitted");
        assert!(handle.wait_timeout(WAIT));
        assert_eq!(ran.load(Ordering::SeqCst), 1);

        // A profile that forbids blocking starts no thread, so its pool carries no stack size at all.
        let none = no_blocking_for_this_process().build().unwrap();
        assert_eq!(none.blocking_handle().unwrap().thread_stack_size(), None);
        assert_eq!(LegacyCaps::of_runtime(&none).blocking_thread_stack_bytes, 0);
    }

    #[test]
    fn the_stock_builder_config_is_refused_on_every_cap_it_leaves_open() {
        let runtime = RuntimeBuilder::new()
            .enable_platform_reactor(false)
            .build()
            .unwrap();
        let carried = LegacyCaps::of_runtime(&runtime);
        // The stock figures this profile was written against. A pinned revision that changes one of these
        // fails here on purpose: re-read the module documentation before trusting the profile.
        assert_eq!(
            carried.worker_threads,
            RuntimeConfig::DEFAULT_WORKER_THREADS
        );
        assert_eq!(carried.thread_stack_bytes, 2 * MIB);
        assert_eq!(carried.blocking_max_threads, 512);
        assert_eq!(carried.global_queue_limit, 0);
        assert_eq!(carried.blocking_max_queued, 0);
        assert_eq!(
            runtime.blocking_handle().unwrap().admission_policy(),
            BlockingAdmissionPolicy::Unbounded
        );

        // The stock pool is given no blocking stack size, so it states none (0). Its worst case is then the
        // workers alone, which any budget under one worker's 2 MiB exceeds.
        assert_eq!(carried.blocking_thread_stack_bytes, 0);
        let budget = bytes(1, MIB);
        let worst = carried.worst_case_stack_bytes().unwrap();
        assert_eq!(
            carried.violations(budget),
            [
                CapViolation::BlockingStackNotStated,
                CapViolation::GlobalQueueUnbounded,
                CapViolation::BlockingQueueUnbounded,
                CapViolation::StackBudgetExceeded {
                    worst_case_bytes: worst,
                    budget_bytes: budget
                },
            ]
        );
        // And a profile does not accept that runtime as its own: the five caps that differ are named, the one
        // that happens to match (the 2 MiB worker stack) is not.
        let error = green_for_this_process().audit(&runtime).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::ConfigError);
        let message = error.message().unwrap();
        assert!(
            message.contains(
                "(worker_threads, blocking_max_threads, blocking_thread_stack_bytes, global_queue_limit, blocking_max_queued differ)"
            ),
            "{message}"
        );
    }

    #[test]
    fn build_carries_exactly_the_stated_caps() {
        let profile = green_for_this_process();
        let runtime = profile.build().unwrap();
        assert_eq!(LegacyCaps::of_runtime(&runtime), profile.caps());
        assert!(profile.audit(&runtime).is_ok());
        let pool = runtime.blocking_handle().unwrap();
        assert_eq!(
            pool.admission_policy(),
            BlockingAdmissionPolicy::Bounded {
                max_queued: NonZeroUsize::new(8).unwrap()
            }
        );
        assert_eq!(pool.current_max_threads(), 2);
    }

    #[test]
    fn build_refuses_an_over_budget_profile() {
        let over = LegacyProfile::new(
            LegacyCaps {
                blocking_max_threads: 512,
                ..green_for_this_process().caps()
            },
            green_for_this_process().stack_budget_bytes(),
        );
        match over.build() {
            Err(error) => assert_eq!(error.kind(), ErrorKind::ConfigError),
            Ok(_) => panic!("an over-budget profile must not build"),
        }
    }

    #[test]
    fn audit_refuses_a_runtime_whose_pool_was_not_given_the_stated_blocking_stack() {
        // This test replaces one that compared the stated figure with std's rule for threads spawned without a
        // stack size, read from the environment. std decides that once per process, so the environment can
        // change after the fact; the audit now reads the stack the pool was configured with instead.
        let profile = green();
        // Every other cap as stated, but the pool is given a quarter of the stated blocking stack.
        let understated = profile
            .builder()
            .unwrap()
            .blocking_thread_stack_size(MIB / 2)
            .enable_platform_reactor(false)
            .build()
            .unwrap();
        // And one whose pool was left to the platform default: nothing was stated to it.
        let unstated = RuntimeBuilder::new()
            .worker_threads(1)
            .thread_stack_size(2 * MIB)
            .global_queue_limit(64)
            .blocking_threads(0, 2)
            .blocking_admission_policy(BlockingAdmissionPolicy::Bounded {
                max_queued: NonZeroUsize::new(8).unwrap(),
            })
            .enable_platform_reactor(false)
            .build()
            .unwrap();
        for (what, runtime) in [("understated", understated), ("unstated", unstated)] {
            let error = profile
                .audit(&runtime)
                .expect_err("a pool without the stated stack is not the stated runtime");
            assert_eq!(error.kind(), ErrorKind::ConfigError, "{what}");
            assert!(
                error
                    .message()
                    .unwrap()
                    .contains("(blocking_thread_stack_bytes differ)"),
                "{what}: {:?}",
                error.message()
            );
        }
        // Remove the plant: the runtime the profile builds, with the stated figure, is accepted.
        assert!(profile.build().is_ok());
    }

    #[test]
    fn the_audit_names_the_one_field_in_which_a_runtime_differs() {
        let profile = green_for_this_process();
        let runtime = profile.build().unwrap();
        let base = profile.caps();
        // The budget is not what is under test here, and `audit` refuses caps that exceed it before it compares
        // anything, so each differing profile gets one it cannot exceed.
        let budget = u64::MAX;
        let others = [
            (
                "worker_threads",
                LegacyCaps {
                    worker_threads: 2,
                    ..base
                },
            ),
            (
                "thread_stack_bytes",
                LegacyCaps {
                    thread_stack_bytes: 3 * MIB,
                    ..base
                },
            ),
            (
                "blocking_max_threads",
                LegacyCaps {
                    blocking_max_threads: 3,
                    ..base
                },
            ),
            (
                "blocking_thread_stack_bytes",
                LegacyCaps {
                    blocking_thread_stack_bytes: base.blocking_thread_stack_bytes + 1,
                    ..base
                },
            ),
            (
                "global_queue_limit",
                LegacyCaps {
                    global_queue_limit: 65,
                    ..base
                },
            ),
            (
                "blocking_max_queued",
                LegacyCaps {
                    blocking_max_queued: 9,
                    ..base
                },
            ),
        ];
        for (field, differing) in others {
            let error = LegacyProfile::new(differing, budget)
                .audit(&runtime)
                .expect_err(field);
            assert_eq!(error.kind(), ErrorKind::ConfigError, "{field}");
            let message = error.message().unwrap();
            assert!(
                message.contains(&format!("({field} differ)")),
                "{field}: {message}"
            );
        }
        // Remove the plant: the runtime audited against its own caps is accepted.
        assert!(profile.audit(&runtime).is_ok());
    }

    #[test]
    fn audit_refuses_stated_caps_that_are_over_budget_even_when_the_runtime_matches_them() {
        let profile = green_for_this_process();
        let runtime = profile.build().unwrap();
        // The same caps, which the runtime carries exactly, but a budget they do not fit in.
        let over = LegacyProfile::new(profile.caps(), 0);
        assert_eq!(LegacyCaps::of_runtime(&runtime), over.caps());
        let error = over
            .audit(&runtime)
            .expect_err("a matching runtime is not a bounded one when the caps exceed the budget");
        assert_eq!(error.kind(), ErrorKind::ConfigError);
        assert!(
            error.message().unwrap().contains("StackBudgetExceeded"),
            "{:?}",
            error.message()
        );
        // Remove the plant: the stated budget makes the same audit pass.
        assert!(profile.audit(&runtime).is_ok());
    }

    #[test]
    fn audit_refuses_unbounded_stated_caps_even_when_the_runtime_is_unbounded_too() {
        let stock = RuntimeBuilder::new()
            .enable_platform_reactor(false)
            .build()
            .unwrap();
        // Stating exactly what the stock runtime carries (a 0 global queue limit, a 0 blocking queue bound)
        // makes the two equal, which is not the same as bounded.
        let stated = LegacyCaps::of_runtime(&stock);
        assert_eq!(stated.global_queue_limit, 0);
        assert_eq!(stated.blocking_max_queued, 0);
        let profile = LegacyProfile::new(stated, u64::MAX);
        let error = profile
            .audit(&stock)
            .expect_err("matching an unbounded runtime does not make the caps bounded");
        assert_eq!(error.kind(), ErrorKind::ConfigError);
        let message = error.message().unwrap();
        assert!(message.contains("GlobalQueueUnbounded"), "{message}");
        assert!(message.contains("BlockingQueueUnbounded"), "{message}");
    }

    #[test]
    fn a_profile_with_no_blocking_work_builds_a_pool_that_forbids_it() {
        // This test replaces one that expected NO pool for this profile. A runtime with no pool runs blocking
        // work inline on the executor; the profile builds a pool that refuses it instead.
        let profile = no_blocking_for_this_process();
        let runtime = profile.build().unwrap();
        let pool = runtime
            .blocking_handle()
            .expect("a forbidding pool, not an absent one");
        assert_eq!(pool.admission_policy(), BlockingAdmissionPolicy::Forbidden);
        assert_eq!(pool.active_threads(), 0);
        assert!(profile.audit(&runtime).is_ok());
    }

    #[test]
    fn a_runtime_with_no_pool_at_all_is_not_accepted_as_a_profile_that_forbids_blocking() {
        // The stock builder can make a runtime with no pool; its blocking calls run inline on the executor.
        let absent = RuntimeBuilder::new()
            .blocking_threads(0, 0)
            .enable_platform_reactor(false)
            .build()
            .unwrap();
        assert!(absent.blocking_handle().is_none());
        let profile = no_blocking_for_this_process();
        let error = profile
            .audit(&absent)
            .expect_err("an absent pool is not a forbidding one");
        assert_eq!(error.kind(), ErrorKind::ConfigError);
        assert!(
            error.message().unwrap().contains("absent or admits work"),
            "{:?}",
            error.message()
        );
        // Remove the plant: the runtime the profile builds is accepted.
        assert!(profile.audit(&profile.build().unwrap()).is_ok());
    }

    #[test]
    fn a_profile_that_forbids_blocking_refuses_every_blocking_call_and_runs_nothing() {
        let runtime = no_blocking_for_this_process().build().unwrap();
        let ran = Arc::new(AtomicUsize::new(0));
        let (for_cx, for_io) = (Arc::clone(&ran), Arc::clone(&ran));
        let (spawned, io) = runtime.block_on(async move {
            let cx = crate::cx::Cx::current().expect("block_on installs the task context");
            let spawned = cx
                .spawn_blocking(move |_| {
                    for_cx.fetch_add(1, Ordering::SeqCst);
                    1_u8
                })
                .map(|_| ());
            let io = crate::runtime::spawn_blocking::spawn_blocking_io(move || {
                for_io.fetch_add(1, Ordering::SeqCst);
                Ok(1_u8)
            })
            .await
            .map(|_| ());
            (spawned, io)
        });
        assert!(
            matches!(
                spawned,
                Err(crate::runtime::state::SpawnError::RuntimeUnavailable)
            ),
            "{spawned:?}"
        );
        assert_eq!(
            io.expect_err("a forbidden pool refuses").kind(),
            std::io::ErrorKind::Unsupported
        );
        assert_eq!(
            ran.load(Ordering::SeqCst),
            0,
            "nothing ran, inline or anywhere"
        );

        // Remove the plant: a runtime with no pool at all admits the same call.
        let absent = RuntimeBuilder::new()
            .blocking_threads(0, 0)
            .enable_platform_reactor(false)
            .build()
            .unwrap();
        let admitted = absent.block_on(async {
            let cx = crate::cx::Cx::current().expect("block_on installs the task context");
            cx.spawn_blocking(|_| 1_u8).is_ok()
        });
        assert!(
            admitted,
            "the unchanged behaviour of a runtime with no pool"
        );
    }

    // ---- behaviour: the caps are enforced by the pool, not merely recorded

    struct Gate {
        open: Mutex<bool>,
        changed: Condvar,
    }

    impl Gate {
        fn closed() -> Arc<Self> {
            Arc::new(Self {
                open: Mutex::new(false),
                changed: Condvar::new(),
            })
        }

        fn wait_open(&self) {
            let guard = self.open.lock().unwrap();
            let (_guard, _timed_out) = self
                .changed
                .wait_timeout_while(guard, WAIT, |open| !*open)
                .unwrap();
        }

        fn release(&self) {
            *self.open.lock().unwrap() = true;
            self.changed.notify_all();
        }
    }

    fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
        let deadline = Instant::now() + WAIT;
        while !condition() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// Owned arguments, so the returned closure borrows nothing and is `'static` without any lifetime question.
    fn gated_job(
        gate: Arc<Gate>,
        running: Arc<AtomicUsize>,
        peak: Arc<AtomicUsize>,
    ) -> impl FnOnce() + Send + 'static {
        move || {
            let now = running.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(now, Ordering::SeqCst);
            gate.wait_open();
            running.fetch_sub(1, Ordering::SeqCst);
        }
    }

    struct Observed {
        running_at_settle: usize,
        pending_after_queueing: usize,
        extra_refusal: Option<BlockingSpawnErrorKind>,
        active_threads: usize,
        clamped_to: usize,
        completed: usize,
        peak: usize,
    }

    /// Build a profile whose blocking pool may run `cap` threads and queue `queued` jobs, hold every thread
    /// the pool will give with a gated job, queue `queued` more, offer one more, and report what the pool did.
    fn run_gated(cap: usize, queued: usize) -> Observed {
        let stated = LegacyCaps {
            blocking_max_threads: cap,
            blocking_max_queued: queued,
            ..caps(2 * MIB)
        };
        let budget = stated.worst_case_stack_bytes().unwrap();
        let runtime = LegacyProfile::new(stated, budget)
            .builder()
            .unwrap()
            .enable_platform_reactor(false)
            .build()
            .unwrap();
        let pool = runtime.blocking_handle().unwrap();
        let (gate, running, peak) = (
            Gate::closed(),
            Arc::new(AtomicUsize::new(0)),
            Arc::new(AtomicUsize::new(0)),
        );
        let job = || gated_job(Arc::clone(&gate), Arc::clone(&running), Arc::clone(&peak));
        let mut handles = Vec::new();
        // One job per thread the pool will give, each waiting for its thread to be running before the next is
        // offered, so none of them is counted against the queue.
        for entered in 1..=cap {
            handles.push(
                pool.try_spawn(job())
                    .expect("a job within the thread cap is admitted"),
            );
            wait_until("a blocking job to start", || {
                running.load(Ordering::SeqCst) == entered
            });
        }
        for _ in 0..queued {
            handles.push(
                pool.try_spawn(job())
                    .expect("a job within the queue bound is admitted"),
            );
        }
        let pending_after_queueing = pool.pending_count();
        let extra = pool.try_spawn(job());
        let extra_refusal = extra.err().map(|refused| refused.kind());
        std::thread::sleep(SETTLE);
        let running_at_settle = running.load(Ordering::SeqCst);
        let active_threads = pool.active_threads();
        let clamped_to = pool.set_max_threads(10_000);
        gate.release();
        let completed = handles
            .iter()
            .filter(|handle| handle.wait_timeout(WAIT))
            .count();
        Observed {
            running_at_settle,
            pending_after_queueing,
            extra_refusal,
            active_threads,
            clamped_to,
            completed,
            peak: peak.load(Ordering::SeqCst),
        }
    }

    #[test]
    fn the_blocking_cap_bounds_concurrency_and_the_job_cap_refuses_by_name() {
        let observed = run_gated(2, 3);
        assert_eq!(observed.running_at_settle, 2, "no third job may run");
        assert_eq!(observed.peak, 2);
        assert!(observed.active_threads <= 2, "{}", observed.active_threads);
        assert_eq!(observed.pending_after_queueing, 3);
        assert_eq!(
            observed.extra_refusal,
            Some(BlockingSpawnErrorKind::Saturated),
            "the job past the queue bound is refused as saturated"
        );
        // The configured maximum is a hard ceiling: asking for more is clamped back to it.
        assert_eq!(observed.clamped_to, 2);
        // Nothing admitted was lost: every running and queued job ran once the gate opened.
        assert_eq!(observed.completed, 2 + 3);
    }

    #[test]
    fn the_concurrency_scenario_sees_a_pool_whose_cap_is_higher_than_stated() {
        // Remove-the-plant control: a pool allowed three threads, measured by the same scenario, reads as
        // three and not as the two the test above asserts, so that assertion is not satisfied by accident.
        let looser = run_gated(3, 3);
        assert_eq!(looser.peak, 3);
        assert_ne!(looser.peak, 2);
        assert_eq!(looser.clamped_to, 3);
    }

    // ---- an optional byte budget for the blocking pool

    #[test]
    fn a_stated_byte_budget_selects_bounded_bytes_and_a_profile_without_one_still_builds_bounded() {
        let stated = budgeted(4096);
        assert_eq!(stated.blocking_live_bytes(), NonZeroUsize::new(4096));
        let runtime = stated.build().unwrap();
        let pool = runtime.blocking_handle().unwrap();
        assert_eq!(
            pool.admission_policy(),
            BlockingAdmissionPolicy::BoundedBytes {
                max_queued: NonZeroUsize::new(8).unwrap(),
                max_live_bytes: NonZeroUsize::new(4096).unwrap(),
            }
        );
        assert!(stated.audit(&runtime).is_ok());

        // Remove the plant: the same caps without a budget are the profile as it always was.
        let plain = green();
        assert_eq!(plain.blocking_live_bytes(), None);
        let runtime = plain.build().unwrap();
        assert_eq!(
            runtime.blocking_handle().unwrap().admission_policy(),
            BlockingAdmissionPolicy::Bounded {
                max_queued: NonZeroUsize::new(8).unwrap(),
            }
        );
        assert!(plain.audit(&runtime).is_ok());
    }

    #[test]
    fn a_byte_budget_changes_no_cap_and_no_verdict_about_the_caps() {
        let (plain, stated) = (green(), budgeted(4096));
        assert_eq!(stated.caps(), plain.caps());
        assert_eq!(stated.stack_budget_bytes(), plain.stack_budget_bytes());
        assert_eq!(stated.violations(), plain.violations());
        assert!(stated.validate().is_ok());
        // The budget is part of what a profile is: equal budgets are equal profiles, unequal ones are not.
        assert_eq!(stated, budgeted(4096));
        assert_ne!(stated, budgeted(8192));
        assert_ne!(stated, plain);

        // A budget does not excuse a defective cap: the profile is refused by the cap's own name, to build or to audit.
        let unbounded = LegacyCaps {
            blocking_max_queued: 0,
            ..caps(2 * MIB)
        };
        let defective = LegacyProfile::new(unbounded, 6 * 1024 * 1024)
            .with_blocking_live_bytes(NonZeroUsize::new(4096).unwrap());
        assert!(defective.build().is_err());
        let message = defective
            .validate()
            .unwrap_err()
            .message()
            .unwrap()
            .to_string();
        assert!(message.contains("BlockingQueueUnbounded"), "{message}");
        let runtime = budgeted(4096).build().unwrap();
        assert!(defective.audit(&runtime).is_err());
        // Remove the plant: the same budget on sound caps is accepted.
        assert!(budgeted(4096).audit(&runtime).is_ok());
    }

    #[test]
    fn the_audit_requires_the_exact_byte_policy_not_just_the_queue_count() {
        let stated = budgeted(4096);

        // A count-only pool shows the same queue bound, so the caps alone cannot tell it from the stated one.
        let count_only = green().build().unwrap();
        assert_eq!(
            LegacyCaps::of_runtime(&count_only),
            stated.caps(),
            "the caps cannot tell the two pools apart"
        );
        let error = stated
            .audit(&count_only)
            .expect_err("a count-only pool is not the stated byte-bounded one");
        assert_eq!(error.kind(), ErrorKind::ConfigError);
        let message = error.message().unwrap();
        assert!(message.contains("live-byte budget of 4096"), "{message}");
        assert!(message.contains("Bounded {"), "{message}");

        // A byte-bounded pool with another budget is refused too, naming both.
        let other_budget = budgeted(8192).build().unwrap();
        let error = stated
            .audit(&other_budget)
            .expect_err("another budget is not the stated one");
        let message = error.message().unwrap();
        assert!(
            message.contains("4096") && message.contains("8192"),
            "{message}"
        );

        // Another queue bound is still refused by the caps, by name.
        let other_queue = stated
            .builder()
            .unwrap()
            .blocking_admission_policy(BlockingAdmissionPolicy::BoundedBytes {
                max_queued: NonZeroUsize::new(4).unwrap(),
                max_live_bytes: NonZeroUsize::new(4096).unwrap(),
            })
            .build()
            .unwrap();
        let error = stated.audit(&other_queue).expect_err("another queue bound");
        assert!(
            error.message().unwrap().contains("blocking_max_queued"),
            "{:?}",
            error.message()
        );

        // Remove the plant: the runtime the profile builds is accepted, and so is one built by hand to the same policy.
        assert!(stated.audit(&stated.build().unwrap()).is_ok());
        let by_hand = green()
            .builder()
            .unwrap()
            .blocking_admission_policy(BlockingAdmissionPolicy::BoundedBytes {
                max_queued: NonZeroUsize::new(8).unwrap(),
                max_live_bytes: NonZeroUsize::new(4096).unwrap(),
            })
            .build()
            .unwrap();
        assert!(stated.audit(&by_hand).is_ok());
    }

    #[test]
    fn a_profile_that_states_no_budget_still_accepts_every_pool_it_always_accepted() {
        // The helper the integration targets use: a budget-less profile whose builder is overridden to BoundedBytes.
        let plain = green();
        let overridden = plain
            .builder()
            .unwrap()
            .blocking_admission_policy(BlockingAdmissionPolicy::BoundedBytes {
                max_queued: NonZeroUsize::new(8).unwrap(),
                max_live_bytes: NonZeroUsize::new(512).unwrap(),
            })
            .build()
            .unwrap();
        assert!(plain.audit(&overridden).is_ok());
        assert!(plain.audit(&budgeted(4096).build().unwrap()).is_ok());
        assert!(plain.audit(&plain.build().unwrap()).is_ok());
        // The plant it is paired with: caps that do differ are still refused, budget or no budget.
        let wider = LegacyProfile::new(
            LegacyCaps {
                blocking_max_queued: 9,
                ..caps(2 * MIB)
            },
            6 * 1024 * 1024,
        );
        assert!(wider.audit(&plain.build().unwrap()).is_err());
    }

    #[test]
    fn a_profile_that_forbids_blocking_ignores_a_stated_byte_budget_and_still_forbids() {
        let plain = no_blocking_for_this_process();
        let stated = plain.with_blocking_live_bytes(NonZeroUsize::new(4096).unwrap());
        let runtime = stated.build().unwrap();
        let pool = runtime.blocking_handle().expect("a forbidding pool");
        assert_eq!(pool.admission_policy(), BlockingAdmissionPolicy::Forbidden);
        assert_eq!(
            pool.admission_policy(),
            plain
                .build()
                .unwrap()
                .blocking_handle()
                .unwrap()
                .admission_policy()
        );
        assert!(stated.audit(&runtime).is_ok());
        assert_eq!(
            uncharged_refusal(&pool),
            Some(BlockingSpawnErrorKind::Forbidden)
        );
        let charged = pool.try_spawn_charged(|| {}, 8).err().map(|r| r.kind());
        assert_eq!(charged, Some(BlockingSpawnErrorKind::Forbidden));
        assert_eq!(pool.charged_bytes(), 0);

        // Paired refusal: the byte-bounded pool of a profile that allows blocking is not a pool that forbids it.
        let allowing = budgeted(4096).build().unwrap();
        let error = stated
            .audit(&allowing)
            .expect_err("a pool that admits work does not meet a profile that forbids it");
        assert!(
            error.message().unwrap().contains("absent or admits work"),
            "{:?}",
            error.message()
        );
    }

    #[test]
    fn a_pool_built_from_a_budgeted_profile_admits_copies_and_retires_charged_work_and_refuses_the_rest()
     {
        let runtime = budgeted(4096).build().unwrap();
        let pool = runtime.blocking_handle().unwrap();
        assert_eq!(pool.charged_bytes(), 0);

        // Admit, copy, run, retire: the pool reserves the declared bytes before the factory copies into them and
        // returns every byte once the job is done.
        let source = vec![7_u8; 300];
        let sink = Arc::new(Mutex::new(Vec::<u8>::new()));
        let (into, probe) = (Arc::clone(&sink), pool.clone());
        let reserved_during_build = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&reserved_during_build);
        let job = pool
            .try_spawn_charged_with(source.len(), || {
                seen.store(probe.charged_bytes(), Ordering::SeqCst);
                let copy = source.clone();
                move || *into.lock().unwrap() = copy
            })
            .expect("a budgeted pool admits a charged factory");
        assert!(job.wait_timeout(WAIT));
        assert_eq!(*sink.lock().unwrap(), source);
        assert!(reserved_during_build.load(Ordering::SeqCst) >= source.len());
        assert_eq!(pool.charged_bytes(), 0, "everything admitted was retired");

        // An uncharged submission is refused for good, and nothing of it runs or stays reserved.
        let ran = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&ran);
        let refused = pool.try_spawn(move || {
            counted.fetch_add(1, Ordering::SeqCst);
        });
        assert_eq!(
            refused.err().map(|r| r.kind()),
            Some(BlockingSpawnErrorKind::ChargeRequired)
        );
        assert_eq!(ran.load(Ordering::SeqCst), 0);
        assert_eq!(pool.charged_bytes(), 0);
        // Remove the plant: declaring a charge, even of 0 bytes, is admitted.
        let counted = Arc::clone(&ran);
        let admitted = pool
            .try_spawn_charged(
                move || {
                    counted.fetch_add(1, Ordering::SeqCst);
                },
                0,
            )
            .expect("a declared charge of 0 is a charge");
        assert!(admitted.wait_timeout(WAIT));
        assert_eq!(ran.load(Ordering::SeqCst), 1);

        // A job larger than the whole budget can never be admitted. (One of exactly the budget is not tested here: the
        // closure's own storage is part of the charge and its size is not this test's to assume.)
        let too_large = pool.try_spawn_charged(|| {}, 5000);
        assert_eq!(
            too_large.err().map(|r| r.kind()),
            Some(BlockingSpawnErrorKind::ChargeTooLarge)
        );
    }

    #[test]
    fn the_byte_budget_saturates_before_the_queue_does_and_frees_when_the_holder_retires() {
        let runtime = budgeted(4096).build().unwrap();
        let pool = runtime.blocking_handle().unwrap();
        let gate = Gate::closed();

        // One job holds 3_000 declared bytes, and the queue (8 slots) is nearly empty.
        let held_by = Arc::clone(&gate);
        let holder = pool
            .try_spawn_charged(move || held_by.wait_open(), 3000)
            .expect("the first job fits an empty pool");
        let refused = pool.try_spawn_charged(|| {}, 2000);
        assert_eq!(
            refused.err().map(|r| r.kind()),
            Some(BlockingSpawnErrorKind::ByteBudgetSaturated),
            "bytes, not the queue, are what is full"
        );
        assert!(pool.charged_bytes() >= 3000);

        // A small job still fits beside it: the budget refuses what does not fit, not everything.
        let small = pool
            .try_spawn_charged(|| {}, 100)
            .expect("100 bytes fit beside 3_000");
        assert!(small.wait_timeout(WAIT));

        // Remove the plant: once the holder has retired, the very request that was refused is admitted.
        gate.release();
        assert!(holder.wait_timeout(WAIT));
        assert_eq!(pool.charged_bytes(), 0);
        let again = pool
            .try_spawn_charged(|| {}, 2000)
            .expect("the room came back");
        assert!(again.wait_timeout(WAIT));
        assert_eq!(pool.charged_bytes(), 0);
    }

    #[test]
    fn a_factory_is_refused_unrun_by_a_budgeted_profiles_pool_when_the_bytes_are_taken() {
        let runtime = budgeted(4096).build().unwrap();
        let pool = runtime.blocking_handle().unwrap();
        let gate = Gate::closed();
        let held_by = Arc::clone(&gate);
        let holder = pool
            .try_spawn_charged(move || held_by.wait_open(), 3500)
            .expect("the first job fits an empty pool");

        let built = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&built);
        let factory = move || {
            counted.fetch_add(1, Ordering::SeqCst);
            || {}
        };
        let factory = match pool.try_spawn_charged_with(1000, factory) {
            Err(BlockingFactoryError::Refused(refused)) => {
                assert_eq!(refused.kind(), BlockingSpawnErrorKind::ByteBudgetSaturated);
                refused.into_inner()
            }
            _ => panic!("expected a refusal before the factory ran"),
        };
        assert_eq!(
            built.load(Ordering::SeqCst),
            0,
            "no payload was built for a full pool"
        );

        // Remove the plant: the same factory, handed back by the refusal, runs once when the room is back.
        gate.release();
        assert!(holder.wait_timeout(WAIT));
        let job = pool
            .try_spawn_charged_with(1000, factory)
            .expect("room for the same factory");
        assert!(job.wait_timeout(WAIT));
        assert_eq!(built.load(Ordering::SeqCst), 1);
        assert_eq!(pool.charged_bytes(), 0);
    }

    /// The caller-driven topology (module docs, "The caller-driven topology"). These tests run real tasks on real
    /// runtimes and read the thread each one ran on; they say nothing about the caller's stack, and nothing about any
    /// target other than the one they run on.
    mod caller_driven {
        use super::*;
        use crate::cx::Cx;
        use crate::runtime::builder::ThreadCensus;
        use crate::runtime::{RootDrainOutcome, RootDrainReport, yield_now};
        use crate::time::sleep;
        use std::future::Future;
        use std::sync::atomic::AtomicBool;
        use std::task::{Poll, Waker};
        use std::thread::ThreadId;

        /// One worker, no blocking, an 8-entry ready queue and a 2 MiB worker stack.
        fn caller_caps() -> LegacyCaps {
            LegacyCaps {
                worker_threads: 1,
                thread_stack_bytes: 2 * MIB,
                blocking_max_threads: 0,
                blocking_thread_stack_bytes: 0,
                global_queue_limit: 8,
                blocking_max_queued: 0,
            }
        }

        fn caller_profile() -> LegacyProfile {
            LegacyProfile::new(caller_caps(), bytes(1, 2 * MIB)).caller_driven()
        }

        /// The same caps and budget without the topology: the plant's construction, which starts a background worker.
        fn threaded_twin() -> LegacyProfile {
            LegacyProfile::new(caller_caps(), bytes(1, 2 * MIB))
        }

        /// Runs `body` as a task of `runtime`, driven by `block_on` on the calling thread.
        fn on_runtime<T, F>(runtime: &Runtime, body: F) -> T
        where
            F: Future<Output = T> + Send + 'static,
            T: Send + 'static,
        {
            runtime.block_on(runtime.handle().spawn(body))
        }

        /// Gives the worker turns until `ready`, and fails the test after `WAIT` instead of hanging it.
        async fn yield_until(what: &str, mut ready: impl FnMut() -> bool) {
            let started = Instant::now();
            while !ready() {
                assert!(
                    started.elapsed() < WAIT,
                    "{what} did not happen within {WAIT:?}"
                );
                yield_now().await;
            }
        }

        /// Records the thread that dropped it.
        struct DroppedOn(Arc<Mutex<Option<ThreadId>>>);

        impl Drop for DroppedOn {
            fn drop(&mut self) {
                *self.0.lock().unwrap() = Some(std::thread::current().id());
            }
        }

        /// The thread of the test, of a task, and of the four children that task spawned.
        #[derive(Debug)]
        struct Seen {
            caller: ThreadId,
            task: ThreadId,
            children: Vec<ThreadId>,
        }

        impl Seen {
            fn all_on_the_caller(&self) -> bool {
                self.task == self.caller && self.children.iter().all(|child| *child == self.caller)
            }
        }

        fn run_tasks(runtime: &Runtime) -> Seen {
            let caller = std::thread::current().id();
            let (task, children) = on_runtime(runtime, async {
                let cx = Cx::current().expect("a runtime task installs its context");
                let mut handles = Vec::new();
                for _ in 0..4 {
                    handles.push(
                        cx.spawn(|_child| async { std::thread::current().id() })
                            .expect("spawn a child"),
                    );
                }
                let mut children = Vec::new();
                for mut handle in handles {
                    children.push(handle.join(&cx).await.expect("the child finishes"));
                }
                (std::thread::current().id(), children)
            });
            Seen {
                caller,
                task,
                children,
            }
        }

        fn assert_quiescent(report: &RootDrainReport) {
            assert_eq!(report.outcome, RootDrainOutcome::Quiescent);
            assert_eq!(
                (
                    report.live_tasks,
                    report.pending_obligations,
                    report.live_regions,
                    report.queued_finalizers,
                    report.pending_spawns,
                ),
                (0, 0, 0, 0, 0)
            );
            assert!(!report.has_pending_obligation_posts);
        }

        #[test]
        fn caller_driven_is_a_topology_on_the_same_caps_and_changes_no_cap() {
            let threaded = threaded_twin();
            let caller = threaded.caller_driven();
            assert!(!threaded.is_caller_driven());
            assert!(caller.is_caller_driven());
            assert_eq!(caller.caps(), threaded.caps());
            assert_eq!(caller.stack_budget_bytes(), threaded.stack_budget_bytes());
            assert_ne!(caller, threaded);
            assert!(caller.violations().is_empty());
            assert!(caller.topology_violations().is_empty());
            assert!(threaded.topology_violations().is_empty());
            assert!(caller.validate().is_ok());
            // A stated live-byte budget and the topology compose in either order.
            let budget = NonZeroUsize::new(4096).unwrap();
            assert_eq!(
                threaded.with_blocking_live_bytes(budget).caller_driven(),
                caller.with_blocking_live_bytes(budget)
            );
            // The thread ceiling counts what the caps govern: no thread at all here, the worker in the twin.
            assert_eq!(caller.os_thread_ceiling(), Some(0));
            assert_eq!(threaded.os_thread_ceiling(), Some(1));
            assert_eq!(
                green().os_thread_ceiling(),
                Some(3),
                "one worker and two blocking threads"
            );
        }

        #[test]
        fn caller_driven_with_another_worker_count_is_refused_by_name_and_never_downgraded() {
            for workers in [0_usize, 2, 4] {
                let stated = LegacyCaps {
                    worker_threads: workers,
                    ..caller_caps()
                };
                let profile =
                    LegacyProfile::new(stated, bytes(workers.max(1), 2 * MIB)).caller_driven();
                assert_eq!(
                    profile.topology_violations(),
                    [TopologyViolation::CallerDrivenNeedsOneWorker {
                        worker_threads: workers
                    }]
                );
                let error = profile
                    .validate()
                    .expect_err("only one worker is the calling thread");
                assert_eq!(error.kind(), ErrorKind::ConfigError);
                assert!(
                    error
                        .message()
                        .unwrap()
                        .contains("CallerDrivenNeedsOneWorker"),
                    "{:?}",
                    error.message()
                );
                assert!(profile.builder().is_err(), "{workers} workers");
                assert!(profile.build().is_err(), "{workers} workers");
            }
            // Remove the plant: two workers are fine for the threaded profile, and they are real threads.
            let twin = LegacyProfile::new(
                LegacyCaps {
                    worker_threads: 2,
                    ..caller_caps()
                },
                bytes(2, 2 * MIB),
            );
            assert!(twin.topology_violations().is_empty());
            let runtime = twin.build().expect("a threaded two-worker profile builds");
            assert_eq!(runtime.thread_census().worker_thread_handles, 2);
        }

        #[test]
        fn caller_driven_with_blocking_threads_is_refused_by_name_and_violations_come_in_a_fixed_order()
         {
            let blocking = LegacyCaps {
                blocking_max_threads: 2,
                blocking_thread_stack_bytes: 2 * MIB,
                blocking_max_queued: 8,
                ..caller_caps()
            };
            let profile = LegacyProfile::new(blocking, bytes(3, 2 * MIB)).caller_driven();
            assert!(profile.violations().is_empty());
            assert_eq!(
                profile.topology_violations(),
                [TopologyViolation::CallerDrivenForbidsBlockingThreads {
                    blocking_max_threads: 2
                }]
            );
            let error = profile
                .validate()
                .expect_err("blocking threads are refused");
            assert_eq!(error.kind(), ErrorKind::ConfigError);
            assert!(
                error
                    .message()
                    .unwrap()
                    .contains("CallerDrivenForbidsBlockingThreads"),
                "{:?}",
                error.message()
            );
            assert!(profile.builder().is_err());
            assert!(profile.build().is_err());

            let both = LegacyProfile::new(
                LegacyCaps {
                    worker_threads: 2,
                    ..blocking
                },
                bytes(4, 2 * MIB),
            )
            .caller_driven();
            assert_eq!(
                both.topology_violations(),
                [
                    TopologyViolation::CallerDrivenNeedsOneWorker { worker_threads: 2 },
                    TopologyViolation::CallerDrivenForbidsBlockingThreads {
                        blocking_max_threads: 2
                    },
                ]
            );
            let message = both.validate().unwrap_err().message().unwrap().to_string();
            assert!(
                message.find("CallerDrivenNeedsOneWorker")
                    < message.find("CallerDrivenForbidsBlockingThreads"),
                "{message}"
            );

            // Remove the plant: the same blocking caps, threaded, are the profile this module always built.
            let twin = LegacyProfile::new(blocking, bytes(3, 2 * MIB));
            assert!(twin.topology_violations().is_empty());
            assert!(twin.build().is_ok());
        }

        #[test]
        fn a_caller_driven_runtime_owns_no_thread_and_the_audit_reads_that_from_the_runtime() {
            let profile = caller_profile();
            let runtime = profile.build().expect("a caller-driven profile builds");
            let census = runtime.thread_census();
            assert_eq!(
                census,
                ThreadCensus {
                    worker_thread_handles: 0,
                    deadline_monitor: false,
                    resource_sampler: false,
                    loan_driver: true,
                }
            );
            // The configuration still states one worker, so the cap comparison is the one it always was.
            assert_eq!(runtime.config().worker_threads, 1);
            assert_eq!(profile.os_thread_ceiling(), Some(0));
            let pool = runtime
                .blocking_handle()
                .expect("a forbidding pool, not an absent one");
            assert_eq!(pool.admission_policy(), BlockingAdmissionPolicy::Forbidden);
            assert_eq!(pool.active_threads(), 0);
            assert!(profile.audit(&runtime).is_ok());

            // Running tasks starts nothing.
            let seen = run_tasks(&runtime);
            assert!(seen.all_on_the_caller(), "{seen:?}");
            assert_eq!(runtime.thread_census(), census);
            assert_eq!(pool.active_threads(), 0);
            assert!(profile.audit(&runtime).is_ok());
        }

        #[test]
        fn tasks_run_on_the_calling_thread_and_a_construction_that_ignores_the_choice_fails_that_test()
         {
            let real = caller_profile().build().expect("a caller-driven runtime");
            let seen = run_tasks(&real);
            assert_eq!(seen.children.len(), 4);
            assert!(seen.all_on_the_caller(), "{seen:?}");

            // The plant: the same caps built from `RuntimeBuilder::new()` alone, as `builder()` did before the
            // topology existed. Its tasks run on its background worker thread, so the same test fails it.
            let plant = threaded_twin().build().expect("the plant builds");
            let planted = run_tasks(&plant);
            assert!(!planted.all_on_the_caller(), "{planted:?}");
            assert_ne!(planted.task, planted.caller);
            assert_eq!(plant.thread_census().worker_thread_handles, 1);
            let error = caller_profile()
                .audit(&plant)
                .expect_err("a runtime that owns a worker thread is not caller-driven");
            assert_eq!(error.kind(), ErrorKind::ConfigError);
            assert!(
                error.message().unwrap().contains("worker-thread handle"),
                "{:?}",
                error.message()
            );

            // Remove the plant: the real runtime passes the test and the audit that refused the plant.
            assert!(caller_profile().audit(&real).is_ok());
        }

        #[test]
        fn a_current_thread_runtime_has_a_background_worker_and_the_audit_refuses_it() {
            // The trap the module docs name: `RuntimeBuilder::current_thread()` also runs tasks on the caller inside
            // `block_on`, but it still starts a background worker thread. Built with the profile's caps, it differs
            // from the caller-driven runtime in that thread and in nothing else.
            let stated = caller_caps();
            let current = RuntimeBuilder::current_thread()
                .thread_stack_size(stated.thread_stack_bytes)
                .global_queue_limit(stated.global_queue_limit)
                .blocking_threads(0, 0)
                .blocking_admission_policy(BlockingAdmissionPolicy::Forbidden)
                .enable_platform_reactor(false)
                .build()
                .expect("a current-thread runtime builds");
            // It has the same driver as a caller-driven runtime, so the handle list is what tells them apart.
            let census = current.thread_census();
            assert_eq!(
                (census.loan_driver, census.worker_thread_handles),
                (true, 1)
            );
            // Its caps are the stated ones: the threaded twin's audit, which does not read threads, accepts it.
            assert!(
                threaded_twin().audit(&current).is_ok(),
                "only the thread should differ"
            );
            let error = caller_profile()
                .audit(&current)
                .expect_err("it owns a background worker thread");
            assert_eq!(error.kind(), ErrorKind::ConfigError);
            assert!(
                error.message().unwrap().contains("worker-thread handle"),
                "{:?}",
                error.message()
            );

            // Remove the plant: the real caller-driven runtime has the same driver and no handle, and passes the
            // audit that refused the current-thread runtime.
            let real = caller_profile().build().expect("a caller-driven runtime");
            let real_census = real.thread_census();
            assert_eq!(
                (real_census.loan_driver, real_census.worker_thread_handles),
                (true, 0)
            );
            assert!(caller_profile().audit(&real).is_ok());
        }

        #[test]
        fn a_timer_fires_on_the_calling_thread_after_its_delay_without_spinning() {
            let runtime = caller_profile().build().expect("a caller-driven runtime");
            let caller = std::thread::current().id();
            let polls = Arc::new(AtomicUsize::new(0));
            let counted = Arc::clone(&polls);
            let started = Instant::now();
            let fired_on = on_runtime(&runtime, async move {
                let cx = Cx::current().expect("a runtime task installs its context");
                let mut sleeper = Box::pin(sleep(cx.now(), Duration::from_millis(50)));
                std::future::poll_fn(move |poll_cx| {
                    counted.fetch_add(1, Ordering::SeqCst);
                    sleeper.as_mut().poll(poll_cx)
                })
                .await;
                std::thread::current().id()
            });
            let elapsed = started.elapsed();
            assert_eq!(fired_on, caller);
            assert!(elapsed >= Duration::from_millis(40), "{elapsed:?}");
            assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
            assert!(
                polls.load(Ordering::SeqCst) <= 8,
                "a wait that spins would poll thousands of times, this one polled {}",
                polls.load(Ordering::SeqCst)
            );
            assert_eq!(runtime.thread_census().worker_thread_handles, 0);
        }

        #[test]
        fn a_wake_from_another_thread_resumes_the_task_on_the_calling_thread() {
            let runtime = caller_profile().build().expect("a caller-driven runtime");
            let caller = std::thread::current().id();
            let published: Arc<Mutex<Option<Waker>>> = Arc::new(Mutex::new(None));
            let released = Arc::new(AtomicBool::new(false));
            let waker_thread = {
                let (slot, flag) = (Arc::clone(&published), Arc::clone(&released));
                std::thread::spawn(move || {
                    wait_until("the task parked and published its waker", || {
                        slot.lock().unwrap().is_some()
                    });
                    flag.store(true, Ordering::SeqCst);
                    let waker = slot.lock().unwrap().take().expect("published above");
                    waker.wake();
                })
            };
            let (slot, flag) = (Arc::clone(&published), Arc::clone(&released));
            let resumed_on = on_runtime(&runtime, async move {
                std::future::poll_fn(move |poll_cx| {
                    if flag.load(Ordering::SeqCst) {
                        return Poll::Ready(());
                    }
                    *slot.lock().unwrap() = Some(poll_cx.waker().clone());
                    Poll::Pending
                })
                .await;
                std::thread::current().id()
            });
            waker_thread.join().expect("the waking thread finished");
            assert_eq!(resumed_on, caller);
        }

        #[test]
        fn a_cancelled_task_is_cleaned_up_on_the_calling_thread_and_leaves_no_timer() {
            let runtime = caller_profile().build().expect("a caller-driven runtime");
            let caller = std::thread::current().id();
            let dropped_on = Arc::new(Mutex::new(None));
            let parked = Arc::new(AtomicBool::new(false));
            let (record, flag) = (Arc::clone(&dropped_on), Arc::clone(&parked));
            let timers_left = on_runtime(&runtime, async move {
                let cx = Cx::current().expect("a runtime task installs its context");
                let mut child = cx
                    .spawn(move |child_cx| async move {
                        let _guard = DroppedOn(record);
                        let mut sleeper =
                            std::pin::pin!(sleep(child_cx.now(), Duration::from_secs(30)));
                        std::future::poll_fn(|poll_cx| {
                            let poll = sleeper.as_mut().poll(poll_cx);
                            if poll.is_pending() {
                                flag.store(true, Ordering::Release);
                            }
                            poll
                        })
                        .await;
                    })
                    .expect("spawn the sleeper");
                yield_until("the child armed its 30-second sleep", || {
                    parked.load(Ordering::Acquire)
                })
                .await;
                let timer = cx.timer_driver().expect("the runtime wired a timer driver");
                assert_eq!(timer.pending_count(), 1, "a live timer before the abort");
                child.abort();
                let result = child.join(&cx).await;
                assert_eq!(result, Ok(()), "the sleep acknowledges the cancellation");
                timer.pending_count()
            });
            assert_eq!(timers_left, 0, "joining the cancelled child left no timer");
            assert_eq!(*dropped_on.lock().unwrap(), Some(caller));
            assert_eq!(runtime.thread_census().worker_thread_handles, 0);
        }

        #[test]
        fn a_root_drain_cancels_parked_work_and_finishes_on_the_calling_thread() {
            let runtime = caller_profile().build().expect("a caller-driven runtime");
            let caller = std::thread::current().id();
            let dropped_on = Arc::new(Mutex::new(None));
            let parked = Arc::new(AtomicBool::new(false));
            let (record, flag) = (Arc::clone(&dropped_on), Arc::clone(&parked));
            // A root-region task that stays parked on a long timer until the drain cancels it.
            let _sleeper = runtime.handle().spawn(async move {
                let _guard = DroppedOn(record);
                let cx = Cx::current().expect("a runtime task installs its context");
                let mut sleeper = std::pin::pin!(sleep(cx.now(), Duration::from_secs(30)));
                std::future::poll_fn(|poll_cx| {
                    let poll = sleeper.as_mut().poll(poll_cx);
                    if poll.is_pending() {
                        flag.store(true, Ordering::Release);
                    }
                    poll
                })
                .await;
            });
            runtime.block_on(yield_until("the sleeper armed its timer", || {
                parked.load(Ordering::Acquire)
            }));
            assert!(
                dropped_on.lock().unwrap().is_none(),
                "not cancelled before the drain"
            );

            let report = runtime.shutdown_drained(Duration::from_secs(5));
            assert_quiescent(&report);
            assert_eq!(*dropped_on.lock().unwrap(), Some(caller));
            // A second drain finds the same.
            assert_quiescent(&runtime.shutdown_drained(Duration::ZERO));
            assert_eq!(runtime.thread_census().worker_thread_handles, 0);
        }

        #[test]
        fn tasks_past_the_ready_queue_limit_are_still_scheduled_and_the_stop_path_drains_on_the_caller()
         {
            // `global_queue_limit` is 8 here. At this revision the scheduler treats it as advisory (past it, it logs
            // and still schedules), so this pins that a full queue neither refuses work nor blocks the stop path. It
            // is not a hard admission bound, and the profile does not claim one.
            let runtime = caller_profile().build().expect("a caller-driven runtime");
            assert_eq!(runtime.config().global_queue_limit, 8);
            let caller = std::thread::current().id();
            let seen = on_runtime(&runtime, async {
                let cx = Cx::current().expect("a runtime task installs its context");
                let mut handles = Vec::new();
                for _ in 0..24 {
                    handles.push(
                        cx.spawn(|_child| async {
                            yield_now().await;
                            std::thread::current().id()
                        })
                        .expect("a spawn past the limit is not refused"),
                    );
                }
                let mut ids = Vec::new();
                for mut handle in handles {
                    ids.push(handle.join(&cx).await.expect("the child finishes"));
                }
                ids
            });
            assert_eq!(seen.len(), 24);
            assert!(seen.iter().all(|id| *id == caller));
            assert_quiescent(&runtime.shutdown_drained(Duration::from_secs(5)));
        }

        #[test]
        fn blocking_work_is_rejected_by_type_and_never_run_inline_with_or_without_a_byte_budget() {
            let budget = NonZeroUsize::new(4096).unwrap();
            for profile in [
                caller_profile(),
                caller_profile().with_blocking_live_bytes(budget),
            ] {
                let runtime = profile.build().expect("a caller-driven runtime");
                assert_eq!(profile.os_thread_ceiling(), Some(0));
                let pool = runtime
                    .blocking_handle()
                    .expect("a forbidding pool, not an absent one");
                assert_eq!(pool.admission_policy(), BlockingAdmissionPolicy::Forbidden);
                let ran = Arc::new(AtomicUsize::new(0));

                let for_pool = Arc::clone(&ran);
                let refused = pool
                    .try_spawn(move || {
                        for_pool.fetch_add(1, Ordering::SeqCst);
                    })
                    .err()
                    .map(|refused| refused.kind());
                assert_eq!(refused, Some(BlockingSpawnErrorKind::Forbidden));
                // A charged submission is refused as forbidden, in budget or over it, never as too large.
                for declared in [1_usize, 1 << 20] {
                    let for_charged = Arc::clone(&ran);
                    let charged = pool
                        .try_spawn_charged(
                            move || {
                                for_charged.fetch_add(1, Ordering::SeqCst);
                            },
                            declared,
                        )
                        .err()
                        .map(|refused| refused.kind());
                    assert_eq!(
                        charged,
                        Some(BlockingSpawnErrorKind::Forbidden),
                        "{declared}"
                    );
                }

                let (for_cx, for_io) = (Arc::clone(&ran), Arc::clone(&ran));
                let (spawned, io) = runtime.block_on(async move {
                    let cx = Cx::current().expect("block_on installs the task context");
                    let spawned = cx
                        .spawn_blocking(move |_| {
                            for_cx.fetch_add(1, Ordering::SeqCst);
                            1_u8
                        })
                        .map(|_| ());
                    let io = crate::runtime::spawn_blocking::spawn_blocking_io(move || {
                        for_io.fetch_add(1, Ordering::SeqCst);
                        Ok(1_u8)
                    })
                    .await
                    .map(|_| ());
                    (spawned, io)
                });
                assert!(
                    matches!(
                        spawned,
                        Err(crate::runtime::state::SpawnError::RuntimeUnavailable)
                    ),
                    "{spawned:?}"
                );
                assert_eq!(
                    io.expect_err("a forbidden pool refuses").kind(),
                    std::io::ErrorKind::Unsupported
                );
                assert_eq!(
                    ran.load(Ordering::SeqCst),
                    0,
                    "nothing ran, inline or anywhere"
                );
                assert_eq!(pool.active_threads(), 0);
                assert_eq!(runtime.thread_census().worker_thread_handles, 0);
                assert!(profile.audit(&runtime).is_ok());
            }

            // Remove the plant: a runtime with no pool at all runs the same call inline on the executor, so the
            // refusal above is the profile's doing.
            let absent = RuntimeBuilder::new()
                .blocking_threads(0, 0)
                .enable_platform_reactor(false)
                .build()
                .unwrap();
            let admitted = absent.block_on(async {
                let cx = Cx::current().expect("block_on installs the task context");
                cx.spawn_blocking(|_| 1_u8).is_ok()
            });
            assert!(
                admitted,
                "the unchanged behaviour of a runtime with no pool"
            );
        }

        #[test]
        fn options_that_start_or_need_a_thread_are_refused_by_name_when_a_caller_driven_runtime_is_built()
         {
            let builder = || {
                caller_profile()
                    .builder()
                    .expect("the caller-driven builder")
            };
            let attempts = [
                (
                    "the deadline monitor",
                    builder()
                        .deadline_monitoring(|monitor| {
                            monitor.check_interval(Duration::from_secs(60))
                        })
                        .build(),
                ),
                (
                    "resource sampling",
                    builder().resource_sampling(Duration::from_secs(60)).build(),
                ),
                ("on_thread_start", builder().on_thread_start(|| {}).build()),
                ("on_thread_stop", builder().on_thread_stop(|| {}).build()),
            ];
            for (what, attempt) in attempts {
                let error = match attempt {
                    Err(error) => error,
                    Ok(_) => panic!("{what} must be refused"),
                };
                assert_eq!(error.kind(), ErrorKind::ConfigError, "{what}");
                let message = error.message().unwrap();
                assert!(
                    message.contains("a caller-driven runtime starts no thread")
                        && message.contains(what),
                    "{what}: {message}"
                );
            }
            // Several at once are listed together.
            let error = match builder()
                .resource_sampling(Duration::from_secs(60))
                .on_thread_start(|| {})
                .build()
            {
                Err(error) => error,
                Ok(_) => panic!("two thread options must be refused"),
            };
            let message = error.message().unwrap();
            assert!(
                message.contains("resource sampling") && message.contains("on_thread_start"),
                "{message}"
            );

            // The one thread-starting option the profile's first revision never met: upstream refuses it in `build()`
            // for any host that does not start native threads, before a reactor or a thread exists. Its message is
            // its own, so it is checked apart from the options above.
            let refused = match builder().background_io_driver(true).build() {
                Err(error) => error,
                Ok(_) => panic!("background_io_driver must be refused"),
            };
            assert_eq!(refused.kind(), ErrorKind::ConfigError);
            let reason = refused.message().unwrap();
            assert!(
                reason.contains("background_io_driver requires native thread host services"),
                "{reason}"
            );

            // Remove the plant: the builder left alone builds a runtime that audits clean, and the threaded profile
            // accepts the same options, because there they start threads.
            let runtime = builder().build().expect("the untouched builder builds");
            assert!(caller_profile().audit(&runtime).is_ok());
            let threaded = threaded_twin()
                .builder()
                .expect("the threaded builder")
                .on_thread_start(|| {})
                .build();
            assert!(threaded.is_ok());
            // The same for the background I/O driver: the threaded profile accepts it, because there it starts the
            // thread, and the runtime then owns one handle more than the profile's ceiling counts.
            let with_io = threaded_twin()
                .builder()
                .expect("the threaded builder")
                .background_io_driver(true)
                .build()
                .expect("the threaded profile accepts the background I/O driver");
            assert_eq!(with_io.thread_census().worker_thread_handles, 2);
            assert_eq!(threaded_twin().os_thread_ceiling(), Some(1));
            assert!(with_io.shutdown_timeout(WAIT));
        }

        #[test]
        fn handle_spawned_work_waits_for_the_next_block_on_and_then_runs_on_that_caller() {
            let runtime = caller_profile().build().expect("a caller-driven runtime");
            let caller = std::thread::current().id();
            let ran_on = Arc::new(Mutex::new(None));
            let record = Arc::clone(&ran_on);
            let handle = runtime.handle().spawn(async move {
                *record.lock().unwrap() = Some(std::thread::current().id());
                7_u8
            });
            std::thread::sleep(SETTLE);
            assert!(
                ran_on.lock().unwrap().is_none(),
                "no thread exists that could have run it"
            );
            assert!(!handle.is_finished());
            assert_eq!(runtime.block_on(handle), 7);
            assert_eq!(*ran_on.lock().unwrap(), Some(caller));

            // Remove the plant: the threaded twin runs the same task by itself, on a thread of its own.
            let threaded = threaded_twin().build().expect("the threaded twin");
            let ran_on = Arc::new(Mutex::new(None));
            let record = Arc::clone(&ran_on);
            let _handle = threaded.handle().spawn(async move {
                *record.lock().unwrap() = Some(std::thread::current().id());
            });
            wait_until("the threaded twin ran the task by itself", || {
                ran_on.lock().unwrap().is_some()
            });
            assert_ne!(*ran_on.lock().unwrap(), Some(caller));
        }

        #[test]
        fn dropping_a_caller_driven_runtime_returns_before_and_after_a_block_on_and_with_work_unrun()
         {
            let (done_tx, done_rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                // The worker is still in the driver's `Returned` slot, never borrowed.
                drop(caller_profile().build().expect("a caller-driven runtime"));

                // The worker went out on a block_on and came back.
                let used = caller_profile().build().expect("a caller-driven runtime");
                assert_eq!(on_runtime(&used, async { 3_u8 }), 3);
                drop(used);

                // Work spawned through a handle that no block_on ever picked up.
                let idle = caller_profile().build().expect("a caller-driven runtime");
                let unrun = idle.handle().spawn(async { 5_u8 });
                drop(idle);
                drop(unrun);
                done_tx.send(()).expect("the test is waiting");
            });
            done_rx
                .recv_timeout(WAIT)
                .expect("dropping a caller-driven runtime must return");
        }
    }
}
