//! Lending CPU scope: scoped OS threads that BORROW run-local state
//! while observing asupersync cancellation and budgets.
//!
//! # Why this exists
//!
//! Every task-spawning path ([`Cx::spawn_in`], [`Cx::spawn_blocking`],
//! [`Cx::spawn_blocking_in`]) requires `Send + 'static` closures, but
//! data-parallel fork-join kernels (the FrankenSim `TilePool` class of
//! consumer) deliberately borrow run-local state — kernels, deques,
//! output bands — and join every worker before returning. Forcing those
//! borrows behind `Arc` erases the lifetime discipline that makes the
//! executor auditable; wrapping raw [`std::thread::scope`] with no `Cx`
//! wiring hides the workers from cancellation and budget enforcement.
//!
//! # Soundness
//!
//! This is the [`std::thread::scope`] pattern verbatim: the API is a
//! FUNCTION that only returns after every spawned child has joined, not
//! a guard value, so the "leak the joiner" hazard of guard-based scoped
//! tasks cannot arise. Borrowed (non-`'static`) captures are sound for
//! exactly the reason they are sound in `std`.
//!
//! # Scope-tree honesty (Decalogue P7)
//!
//! No task is created here. The scoped threads execute as an
//! implementation detail of the CALLING task, each holding a clone of
//! its [`Cx`], so:
//!
//! - cancellation requested on the task (or its region) is observed by
//!   every child at its next [`CpuCx::checkpoint`] — the same
//!   `fast_cancel` fast path every checkpoint uses;
//! - budget exhaustion (deadline, poll quota, cost) surfaces through
//!   the same checkpoint;
//! - the region cannot close under the workers because the calling
//!   task is inside `scoped_cpu` until every worker has joined —
//!   request → drain → finalize holds by construction.
//!
//! # Blocking discipline
//!
//! [`Cx::scoped_cpu`] BLOCKS the calling thread until the scope
//! completes. Call it from synchronous compute code (its intended
//! consumer) or from inside [`Cx::spawn_blocking`]; calling it from an
//! async task polled on an executor thread stalls that executor thread
//! for the duration, exactly as any long blocking section would.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use super::cx::Cx;

/// Structured failure from a [`Cx::scoped_cpu`] region.
#[derive(Debug)]
pub enum ScopedCpuError {
    /// Cancellation or budget exhaustion was observed (at entry, during
    /// the run by a child, or at exit). All children joined before this
    /// was returned.
    Cancelled(crate::error::Error),
    /// A child panicked. The first payload is recorded; the scope latch
    /// was raised so siblings could drain at their next checkpoint, and
    /// every child joined before this was returned.
    ChildPanicked {
        /// Zero-based spawn ordinal of the first panicking child.
        child: usize,
        /// Rendered panic payload.
        message: String,
    },
    /// A `spawn` call exceeded the declared worker cap. No thread was
    /// created for the refused call.
    WorkerCapExceeded {
        /// The cap declared at [`Cx::scoped_cpu`] entry.
        cap: usize,
    },
}

impl core::fmt::Display for ScopedCpuError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ScopedCpuError::Cancelled(inner) => {
                write!(f, "scoped cpu region cancelled: {inner}")
            }
            ScopedCpuError::ChildPanicked { child, message } => {
                write!(f, "scoped cpu child {child} panicked: {message}")
            }
            ScopedCpuError::WorkerCapExceeded { cap } => {
                write!(f, "scoped cpu worker cap {cap} exceeded")
            }
        }
    }
}

impl std::error::Error for ScopedCpuError {}

/// Per-child context: cancellation/budget observation for borrowed CPU
/// workers. Cheap to use — [`CpuCx::checkpoint`] is the task's own
/// checkpoint fast path plus one atomic load for the scope latch.
pub struct CpuCx<Caps> {
    cx: Cx<Caps>,
    latch: Arc<AtomicBool>,
    child: usize,
}

impl<Caps> CpuCx<Caps> {
    /// Zero-based spawn ordinal of this child (stable, caller-visible
    /// logical identity — determinism-friendly).
    #[must_use]
    pub fn child(&self) -> usize {
        self.child
    }

    /// Bounded-latency cancellation/budget check. Errs when the scope
    /// latch was raised (a sibling panicked or the scope is draining)
    /// or when the owning task's checkpoint errs (cancellation request,
    /// deadline, poll/cost budget exhaustion). Workers must poll this
    /// at tile boundaries and return promptly on `Err`.
    ///
    /// # Errors
    ///
    /// The owning task's checkpoint error, or a cancellation-shaped
    /// error when the scope latch is raised.
    pub fn checkpoint(&self) -> Result<(), crate::error::Error> {
        if self.latch.load(Ordering::Acquire) {
            return Err(crate::error::Error::new(crate::error::ErrorKind::Cancelled));
        }
        self.cx.checkpoint()
    }

    /// Non-consuming peek: true when the owning task has a cancellation
    /// request pending (does not consult budgets; use
    /// [`CpuCx::checkpoint`] at real boundaries).
    #[must_use]
    pub fn is_cancel_requested(&self) -> bool {
        self.latch.load(Ordering::Acquire) || self.cx.is_cancel_requested()
    }
}

/// The lending spawn surface handed to the [`Cx::scoped_cpu`] closure.
pub struct ScopedCpu<'scope, 'env, Caps> {
    scope: &'scope std::thread::Scope<'scope, 'env>,
    cx: Cx<Caps>,
    latch: Arc<AtomicBool>,
    panic_box: Arc<Mutex<Option<(usize, String)>>>,
    spawned: Arc<AtomicUsize>,
    cap: usize,
}

impl<'scope, Caps: Send + Sync + 'static> ScopedCpu<'scope, '_, Caps> {
    /// Spawn one borrowed CPU worker. The closure may capture
    /// non-`'static` state from the enclosing environment (the whole
    /// point); it receives a [`CpuCx`] and must poll
    /// [`CpuCx::checkpoint`] at bounded intervals.
    ///
    /// Panics inside the closure are contained: the first payload is
    /// recorded, the scope latch is raised so siblings drain, and the
    /// error surfaces from [`Cx::scoped_cpu`] after every child joins.
    ///
    /// # Errors
    ///
    /// [`ScopedCpuError::WorkerCapExceeded`] when the declared worker
    /// cap is already reached — a structured refusal, no thread is
    /// created.
    pub fn spawn<F>(&self, f: F) -> Result<(), ScopedCpuError>
    where
        F: FnOnce(&CpuCx<Caps>) + Send + 'scope,
    {
        let child = self.spawned.fetch_add(1, Ordering::AcqRel);
        if child >= self.cap {
            // Undo the reservation so later (possibly smaller) retries
            // see an accurate count.
            self.spawned.fetch_sub(1, Ordering::AcqRel);
            return Err(ScopedCpuError::WorkerCapExceeded { cap: self.cap });
        }
        let cx = self.cx.clone();
        let latch = Arc::clone(&self.latch);
        let panic_box = Arc::clone(&self.panic_box);
        self.scope.spawn(move || {
            let child_cx = CpuCx {
                cx,
                latch: Arc::clone(&latch),
                child,
            };
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                f(&child_cx);
            }));
            if let Err(payload) = outcome {
                let message = super::scope::payload_to_string(&payload);
                let mut slot = panic_box.lock().unwrap_or_else(|poisoned| {
                    // The box only ever holds the FIRST panic; a poisoned
                    // lock means another panicking child raced us, which
                    // is fine — take the guard and let the earlier entry
                    // win below.
                    poisoned.into_inner()
                });
                if slot.is_none() {
                    *slot = Some((child, message));
                }
                drop(slot);
                // Raise the latch so siblings drain at their next
                // checkpoint (request -> drain -> finalize on panic).
                latch.store(true, Ordering::Release);
            }
        });
        Ok(())
    }

    /// The number of workers spawned so far (refused calls excluded).
    #[must_use]
    pub fn spawned(&self) -> usize {
        self.spawned.load(Ordering::Acquire).min(self.cap)
    }
}

impl<Caps: Send + Sync + 'static> Cx<Caps> {
    /// Run a BLOCKING, lending fork-join region: `f` receives a
    /// [`ScopedCpu`] whose [`ScopedCpu::spawn`] accepts non-`'static`
    /// (borrowing) child closures; `scoped_cpu` returns only after
    /// every child joined. See the module docs for the soundness and
    /// scope-tree arguments and the blocking discipline.
    ///
    /// `worker_cap` is the structured budget on child threads for this
    /// region (spawn calls beyond it are refused, never queued).
    ///
    /// # Errors
    ///
    /// - [`ScopedCpuError::Cancelled`] when cancellation or budget
    ///   exhaustion is observed at entry or at exit (children that
    ///   observed it mid-run have already drained by then).
    /// - [`ScopedCpuError::ChildPanicked`] when a child panicked (first
    ///   payload; siblings drained; all joined).
    pub fn scoped_cpu<'env, F, R>(&'env self, worker_cap: usize, f: F) -> Result<R, ScopedCpuError>
    where
        F: for<'scope> FnOnce(&ScopedCpu<'scope, 'env, Caps>) -> R,
    {
        // Entry checkpoint: refuse to start work under a pending
        // cancellation or an exhausted budget.
        self.checkpoint().map_err(ScopedCpuError::Cancelled)?;
        let latch = Arc::new(AtomicBool::new(false));
        let panic_box: Arc<Mutex<Option<(usize, String)>>> = Arc::new(Mutex::new(None));
        let spawned = Arc::new(AtomicUsize::new(0));
        let result = std::thread::scope(|scope| {
            let surface = ScopedCpu {
                scope,
                cx: self.clone(),
                latch: Arc::clone(&latch),
                panic_box: Arc::clone(&panic_box),
                spawned: Arc::clone(&spawned),
                cap: worker_cap,
            };
            f(&surface)
            // std::thread::scope joins every child HERE, before
            // returning — the drain guarantee.
        });
        if let Some((child, message)) = Arc::try_unwrap(panic_box)
            .map(|m| {
                m.into_inner()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
            })
            .unwrap_or_else(|arc| {
                arc.lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .take()
            })
        {
            return Err(ScopedCpuError::ChildPanicked { child, message });
        }
        // Exit checkpoint: surface cancellation/budget exhaustion that
        // children observed (and drained on) during the run.
        self.checkpoint().map_err(ScopedCpuError::Cancelled)?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Budget;

    /// G0: the lending property itself — children borrow run-local,
    /// non-'static state (the exact thing task spawns cannot do).
    #[test]
    fn children_borrow_run_local_state() {
        let cx = Cx::for_testing();
        let cells: Vec<Mutex<u64>> = (0..4).map(|_| Mutex::new(0)).collect();
        let out = cx
            .scoped_cpu(4, |scope| {
                for (i, cell) in cells.iter().enumerate() {
                    scope
                        .spawn(move |child| {
                            assert_eq!(child.child(), i);
                            child.checkpoint().expect("healthy scope");
                            *cell.lock().expect("cell") = (i as u64 + 1) * 10;
                        })
                        .expect("under cap");
                }
                scope.spawned()
            })
            .expect("scope completes");
        assert_eq!(out, 4);
        let values: Vec<u64> = cells.iter().map(|c| *c.lock().expect("cell")).collect();
        assert_eq!(values, vec![10, 20, 30, 40]);
    }

    /// Worker cap is a structured refusal, not a queue or a panic.
    #[test]
    fn worker_cap_refuses_structurally() {
        let cx = Cx::for_testing();
        let refused = cx
            .scoped_cpu(2, |scope| {
                scope.spawn(|_| {}).expect("first fits");
                scope.spawn(|_| {}).expect("second fits");
                match scope.spawn(|_| {}) {
                    Err(ScopedCpuError::WorkerCapExceeded { cap }) => cap,
                    other => panic!("expected cap refusal, got {other:?}"),
                }
            })
            .expect("scope completes");
        assert_eq!(refused, 2);
    }

    /// G4: one child panics -> first payload recorded, latch drains the
    /// sibling at its next checkpoint, everything joins, structured
    /// error out, and the Cx remains usable.
    #[test]
    fn child_panic_is_contained_and_drains_siblings() {
        let cx = Cx::for_testing();
        let err = cx
            .scoped_cpu(2, |scope| {
                scope
                    .spawn(|child| {
                        // Drain loop: spin on checkpoint until the
                        // sibling's panic raises the latch.
                        while child.checkpoint().is_ok() {
                            std::hint::spin_loop();
                        }
                    })
                    .expect("under cap");
                scope
                    .spawn(|_| panic!("deliberate test panic"))
                    .expect("under cap");
            })
            .expect_err("panic must surface");
        match err {
            ScopedCpuError::ChildPanicked { child, message } => {
                assert_eq!(child, 1);
                assert!(message.contains("deliberate test panic"));
            }
            other => panic!("expected ChildPanicked, got {other:?}"),
        }
        // The scope is a region of the TASK; the task itself is intact.
        cx.checkpoint().expect("cx usable after contained panic");
    }

    /// G4: cancellation requested mid-run reaches children through
    /// their checkpoints; they drain; scoped_cpu surfaces Cancelled at
    /// exit after all joins.
    #[test]
    fn cancellation_propagates_to_children_and_surfaces() {
        let cx = Cx::for_testing();
        let err = cx
            .scoped_cpu(1, |scope| {
                scope
                    .spawn(|child| {
                        // Request cancellation on the owning task from
                        // inside the worker, then observe it at the
                        // next checkpoint (bounded latency).
                        child.cx.set_cancel_requested(true);
                        assert!(child.is_cancel_requested());
                        child
                            .checkpoint()
                            .expect_err("checkpoint observes the request");
                    })
                    .expect("under cap");
            })
            .expect_err("exit checkpoint surfaces cancellation");
        assert!(matches!(err, ScopedCpuError::Cancelled(_)));
    }

    /// Entry refusal: an already-exhausted budget never starts work.
    #[test]
    fn exhausted_budget_refuses_at_entry() {
        let cx = Cx::for_testing_with_budget(Budget {
            poll_quota: 0,
            ..Budget::INFINITE
        });
        let spawned = AtomicUsize::new(0);
        let err = cx
            .scoped_cpu(4, |scope| {
                scope
                    .spawn(|_| {
                        spawned.fetch_add(1, Ordering::SeqCst);
                    })
                    .ok();
            })
            .expect_err("zero poll quota refuses at entry");
        assert!(matches!(err, ScopedCpuError::Cancelled(_)));
        assert_eq!(spawned.load(Ordering::SeqCst), 0, "no work started");
    }
}
