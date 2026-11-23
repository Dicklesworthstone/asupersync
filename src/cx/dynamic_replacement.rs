//! Exact-generation replacement for the single-owner dynamic supervisor.
//!
//! Replacement is deliberately not expressed as a detached stop followed by a
//! later admission. The old controller and its enclosing region are joined and
//! closed first; the old name reservation and completion remain owned until
//! replacement admission finishes. An abandoned wait can be resumed or reaped
//! using the old identity. A returned receipt keeps the old generation's full
//! terminal evidence even when the replacement itself cannot be admitted.

use super::{
    DynamicChildCompletion, DynamicChildId, DynamicSupervisor, DynamicSupervisorError,
    DynamicWorkerConfig,
};
use crate::supervision::{
    ManagedChildFactory, ManagedChildFuture, ManagedGeneration, ManagedSupervisor,
    UnstartedManagedSupervisor,
};
use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};

/// Receipt for one exact-generation replacement attempt.
///
/// `previous` proves that the old controller and its enclosing boundary were
/// actually drained and reaped. `replacement` is the independent admission
/// result for the new generation. A failed replacement therefore never erases
/// the old generation's application, cancellation, panic, cleanup, or region
/// outcome. When `replace_child` / `replace_worker` returns an outer error, the
/// old child was not cleanly reusable and replacement admission was not tried.
#[derive(Debug)]
#[must_use = "inspect both the previous generation receipt and replacement admission"]
pub struct DynamicChildReplacement<E> {
    /// Full terminal evidence for the exact generation that was replaced.
    pub previous: DynamicChildCompletion<E>,
    /// New exact identity, or the authoritative admission/configuration refusal.
    pub replacement: Result<DynamicChildId, DynamicSupervisorError>,
}

impl<E> DynamicChildReplacement<E> {
    /// Whether a new generation was admitted.
    #[must_use]
    pub const fn replaced(&self) -> bool {
        self.replacement.is_ok()
    }

    /// Borrow the replacement identity when admission succeeded.
    #[must_use]
    pub fn replacement_id(&self) -> Option<&DynamicChildId> {
        self.replacement.as_ref().ok()
    }
}

impl<E: Send + 'static> DynamicSupervisor<E> {
    /// Drain one exact managed tree, then attempt to admit its replacement
    /// under the same name.
    ///
    /// The stale-generation check, stop request, controller join, descendant
    /// drain, finalizers, and boundary close all complete before `replacement`
    /// can execute any managed factory. The name reservation transfers to the
    /// new admission when its identity and the old receipt are published. If
    /// cleanup fails, the name remains quarantined, this returns the original
    /// lifecycle error, and the replacement value is dropped without submission.
    /// If later admission fails, the returned [`DynamicChildReplacement`] still
    /// contains the old generation's complete receipt and the name remains free
    /// unless the admission path retained a new child.
    ///
    /// Dropping this wait keeps the old child's exact ID, name reservation and
    /// terminal result in the owner, even if replacement region admission has
    /// already begun. Resume with another `replace_child` / `replace_worker`
    /// call using the same ID, or retrieve the previous completion with
    /// [`Self::wait_child`]. An abandoned replacement never starts a factory.
    /// No additional completion history is retained after a returned receipt.
    ///
    /// This is an explicit operator replacement, not an automatic restart, so
    /// it consumes no shared automatic-restart slot. Automatic restarts inside
    /// the newly admitted tree continue to use all configured local/shared
    /// restart policies.
    pub fn replace_child(
        &mut self,
        id: &DynamicChildId,
        replacement: ManagedSupervisor<E>,
    ) -> impl Future<Output = Result<DynamicChildReplacement<E>, DynamicSupervisorError>> {
        // Establish isolated ownership before even the first poll. An unpolled
        // replacement can contain several independent panicking destructors.
        let replacement = UnstartedManagedSupervisor::new(replacement);
        self.replace_child_with(id, move || Ok(replacement))
    }

    /// Drain one exact direct worker tree, then attempt to admit a new retained
    /// worker factory under the same name.
    ///
    /// The supplied factory is never invoked before the old generation is
    /// quiescent and reusable. Invalid replacement configuration, cancellation,
    /// a sealed owner, or region admission failure is returned in the inner
    /// `replacement` result while preserving the previous completion receipt.
    /// Dropping this wait retains the old admission and completion exactly as
    /// [`Self::replace_child`] does; use the same ID to resume or reap it.
    pub fn replace_worker(
        &mut self,
        id: &DynamicChildId,
        config: DynamicWorkerConfig,
        factory: impl ManagedChildFactory<E>,
    ) -> impl Future<Output = Result<DynamicChildReplacement<E>, DynamicSupervisorError>> {
        let name = id.name().to_owned();
        let factory = ReplacementFactory(Some(factory));
        self.replace_child_with(id, move || {
            Self::bind_worker(name.into(), config, factory).map(UnstartedManagedSupervisor::new)
        })
    }
}

// A direct-worker factory is not yet part of an UnstartedManagedSupervisor
// while the old child drains. Retire it without replacing an active unwind.
// A destructor panic during an ordinary drop is still surfaced to the caller.
struct ReplacementFactory<F>(Option<F>);

impl<E, F: ManagedChildFactory<E>> ManagedChildFactory<E> for ReplacementFactory<F> {
    fn start(&self, cx: super::Cx, generation: ManagedGeneration) -> ManagedChildFuture<E> {
        self.0
            .as_ref()
            .expect("replacement factory is owned")
            .start(cx, generation)
    }

    fn retired(&self) {
        self.0
            .as_ref()
            .expect("replacement factory is owned")
            .retired();
    }
}

impl<F> Drop for ReplacementFactory<F> {
    fn drop(&mut self) {
        let Some(factory) = self.0.take() else {
            return;
        };
        let already_unwinding = std::thread::panicking();
        if let Err(payload) = catch_unwind(AssertUnwindSafe(|| drop(factory))) {
            if already_unwinding {
                std::mem::forget(payload);
            } else {
                std::panic::resume_unwind(payload);
            }
        }
    }
}
