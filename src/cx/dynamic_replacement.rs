//! Exact-generation replacement for the single-owner dynamic supervisor.
//!
//! Replacement is deliberately not expressed as a detached stop followed by a
//! later admission. The old controller and its enclosing region are joined and
//! closed first; only a clean reap releases the name and reaches replacement
//! admission. The returned receipt keeps the old generation's full terminal
//! evidence even when the replacement itself cannot be admitted.

use super::{
    DynamicChildCompletion, DynamicChildId, DynamicSupervisor, DynamicSupervisorError,
    DynamicWorkerConfig,
};
use crate::supervision::{ManagedChildFactory, ManagedSupervisor};

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
    /// drain, finalizers, boundary close, and name release all complete before
    /// `replacement` can execute any managed factory. If cleanup fails, the
    /// name remains quarantined, this returns the original lifecycle error, and
    /// the replacement value is dropped without submission. If later admission
    /// fails, the returned [`DynamicChildReplacement`] still contains the old
    /// generation's complete receipt and the name remains free unless the
    /// admission path retained a new child.
    ///
    /// This is an explicit operator replacement, not an automatic restart, so
    /// it consumes no shared automatic-restart slot. Automatic restarts inside
    /// the newly admitted tree continue to use all configured local/shared
    /// restart policies.
    pub async fn replace_child(
        &mut self,
        id: &DynamicChildId,
        replacement: ManagedSupervisor<E>,
    ) -> Result<DynamicChildReplacement<E>, DynamicSupervisorError> {
        let name = id.name().to_owned();
        let previous = self.terminate_child(id).await?;
        let replacement = self.start_child(name, replacement).await;
        Ok(DynamicChildReplacement {
            previous,
            replacement,
        })
    }

    /// Drain one exact direct worker tree, then attempt to admit a new retained
    /// worker factory under the same name.
    ///
    /// The supplied factory is never invoked before the old generation is
    /// quiescent and reusable. Invalid replacement configuration, cancellation,
    /// a sealed owner, or region admission failure is returned in the inner
    /// `replacement` result while preserving the previous completion receipt.
    pub async fn replace_worker(
        &mut self,
        id: &DynamicChildId,
        config: DynamicWorkerConfig,
        factory: impl ManagedChildFactory<E>,
    ) -> Result<DynamicChildReplacement<E>, DynamicSupervisorError> {
        let name = id.name().to_owned();
        let previous = self.terminate_child(id).await?;
        let replacement = self.start_worker(name, config, factory).await;
        Ok(DynamicChildReplacement {
            previous,
            replacement,
        })
    }
}
