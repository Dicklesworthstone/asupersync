//! Explicit, synchronous observers for managed application lifecycle events.

use super::managed_execution::{
    feature_enabled, restrict_required_capabilities, validate_required_capabilities,
};
use super::resources::ResourceCatalog;
use super::{
    AppObservabilitySinkKindV1, AppObservabilitySinkSpecV1, AppRequiredCapabilitiesV1,
    AppSpecV1WorkUnitKind, ManagedAppBindError, ManagedAppResourceRequirement, ManagedAppResources,
};
use crate::cx::Cx;
use crate::supervision::ManagedGeneration;
use crate::types::{RegionId, TaskId, Time};
use std::collections::{BTreeMap, BTreeSet};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// A real managed work invocation's lifecycle boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ManagedAppEventPhase {
    /// The admitted workload task is about to call its route or worker factory.
    Started,
    /// Its result has been classified and its work region has finished closing.
    /// Cleanup failure is reflected in the outcome, rather than reported as success.
    Finished,
    /// Work returned, but the region-close operation failed without a
    /// quiescence receipt. This is never reported as `Finished`.
    CloseFailed,
    /// Policy or region admission refused the invocation before a workload task ran.
    AdmissionRejected,
}

/// A result class without exposing an application's domain-error payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ManagedAppEventOutcome {
    /// Successful work, including HTTP responses with status below 400.
    Succeeded,
    /// Domain, spawn, join, cleanup, or HTTP error response.
    Failed,
    /// Work was cancelled, including a deadline or exhausted budget.
    Cancelled,
    /// A workload, admission callback, or finalizer panicked.
    Panicked,
    /// An explicit policy refused work before its factory ran.
    Rejected,
}

/// An owned snapshot of one managed invocation boundary.
///
/// `Started` means the workload factory is actually called; a task cancelled
/// before its first poll can have only `Finished`. Each admitted invocation is
/// identified by its region, including repeated jobs and actor replacements.
/// The optional supervisor generation describes its owner; routes have none.
/// Events describe application work, not route-publication controller tasks.
/// Inactive routes and cancelled controllers that admit no work emit no event.
/// A route event covers its handler and owned work, not later response-body
/// transmission or transport completion.
///
/// Events are delivered synchronously in declaration order at each boundary.
/// Concurrent invocations can interleave; no application-wide total ordering
/// or delivery after forcibly dropping an unjoined controller is promised.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ManagedAppEvent {
    /// Qualified manifest work-unit name.
    pub unit: String,
    /// Route, actor, or background job.
    pub kind: AppSpecV1WorkUnitKind,
    /// Owning supervisor generation, when applicable.
    pub generation: Option<ManagedGeneration>,
    /// The observed lifecycle boundary.
    pub phase: ManagedAppEventPhase,
    /// Runtime owner-clock instant, without requiring the sink's Time capability.
    pub at: Time,
    /// Admitted work region; absent for an admission refusal.
    pub region: Option<RegionId>,
    /// Work task; absent when task admission itself failed.
    pub task: Option<TaskId>,
    /// Classified returned work or admission result; absent on `Started`.
    /// Region and descendant failures are reported separately without changing
    /// an existing route or worker's return contract.
    pub outcome: Option<ManagedAppEventOutcome>,
    /// Aggregate owned-region outcome, present only with a quiescent receipt.
    pub region_outcome: Option<ManagedAppEventOutcome>,
    /// Finalizer outcome from the same receipt, if finalizers reported one.
    pub cleanup_outcome: Option<ManagedAppEventOutcome>,
    /// Whether that receipt carries a panic from this region or a descendant.
    /// False without a close receipt does not establish descendant success.
    pub descendant_panicked: bool,
    /// Actual final HTTP status, if this boundary returns an HTTP response.
    pub http_status: Option<u16>,
}

type ObserverFn = dyn Fn(&Cx, &ManagedAppEvent, &ManagedAppResources) + Send + Sync;

/// Explicit implementation of a declared Trace, Metrics, or Evidence sink.
///
/// All kinds receive the same factual lifecycle records. A Trace adapter can
/// append structured spans/logs, a Metrics adapter can update counters and
/// histograms, and an Evidence adapter can append application-specific ledger
/// records. This seam does not install a global collector, manufacture OTLP
/// configuration, poll a network exporter, or create background tasks.
///
/// Callbacks must return promptly and publish synchronously or enqueue through
/// an explicitly owned bounded sink. They may run concurrently. The context is
/// attenuated from the invocation's owner by the sink's own manifest authority,
/// independently of the workload's authority. No missing driver is minted.
/// Terminal callbacks can observe a cancelled context; their publication must
/// not rely on cancellation-aware sends through that context. Original work
/// outcomes are already classified and are never sent through the observer.
///
/// A callback panic is contained and counted, and disables that sink for later
/// events. Already running callbacks can still finish. Other observers continue
/// to see the event, and the workload's result is unchanged. This is explicit
/// dependency injection, not isolation from a callback's ordinary Rust effects.
pub struct ManagedAppObservabilityBinding {
    name: String,
    kind: AppObservabilitySinkKindV1,
    requirements: Vec<ManagedAppResourceRequirement>,
    callback: Arc<ObserverFn>,
}

impl ManagedAppObservabilityBinding {
    /// Bind one named sink without named resource requirements.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        kind: AppObservabilitySinkKindV1,
        callback: impl Fn(&Cx, &ManagedAppEvent) + Send + Sync + 'static,
    ) -> Self {
        Self::with_resources(name, kind, Vec::new(), move |cx, event, _| {
            callback(cx, event);
        })
    }

    /// Bind a sink to its exact typed resource allowlist.
    ///
    /// Every resource named by the sink must have one matching type requirement;
    /// service resource inheritance does not apply to application-wide sinks.
    #[must_use]
    pub fn with_resources(
        name: impl Into<String>,
        kind: AppObservabilitySinkKindV1,
        requirements: Vec<ManagedAppResourceRequirement>,
        callback: impl Fn(&Cx, &ManagedAppEvent, &ManagedAppResources) + Send + Sync + 'static,
    ) -> Self {
        Self {
            name: name.into(),
            kind,
            requirements,
            callback: Arc::new(callback),
        }
    }
}

/// Bounded per-sink delivery accounting, shared across work and restarts.
///
/// A snapshot can observe an in-progress callback between counters. `delivered`
/// counts callbacks that returned normally, not successful external persistence.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ManagedAppObservabilityStats {
    /// Declared sink name.
    pub name: String,
    /// Declared sink family.
    pub kind: AppObservabilitySinkKindV1,
    /// Callback invocations attempted, saturating at `u64::MAX`.
    pub attempted: u64,
    /// Callbacks that returned normally, saturating at `u64::MAX`.
    pub delivered: u64,
    /// Contained callback panics, saturating at `u64::MAX`.
    pub panicked: u64,
    /// This sink has been disabled after a callback panic.
    pub disabled: bool,
}

struct Observer {
    binding: ManagedAppObservabilityBinding,
    required: AppRequiredCapabilitiesV1,
    resources: ManagedAppResources,
    attempted: AtomicU64,
    delivered: AtomicU64,
    panicked: AtomicU64,
    disabled: AtomicBool,
}

pub(super) struct ObservationCatalog {
    observers: Vec<Observer>,
}

impl ObservationCatalog {
    pub(super) fn is_empty(&self) -> bool {
        self.observers.is_empty()
    }

    pub(super) fn bind(
        declarations: &[AppObservabilitySinkSpecV1],
        bindings: Vec<ManagedAppObservabilityBinding>,
        resources: Option<&ResourceCatalog>,
    ) -> Result<Self, ManagedAppBindError> {
        let mut supplied = BTreeMap::new();
        for binding in bindings {
            let name = binding.name.clone();
            if supplied.insert(name.clone(), binding).is_some() {
                return Err(ManagedAppBindError::Duplicate(format!("observability:{name}")));
            }
        }
        let mut observers = Vec::with_capacity(declarations.len());
        for declaration in declarations {
            let name = format!("observability:{}", declaration.name);
            let binding = supplied
                .remove(&declaration.name)
                .ok_or_else(|| ManagedAppBindError::Missing(name.clone()))?;
            if binding.kind != declaration.kind {
                return Err(ManagedAppBindError::KindMismatch(name));
            }
            for feature in &declaration.required_capabilities.feature_flags {
                if !feature_enabled(feature) {
                    return Err(ManagedAppBindError::Feature {
                        unit: name,
                        feature: feature.clone(),
                    });
                }
            }
            let names: BTreeSet<_> = declaration
                .required_capabilities
                .resources
                .iter()
                .cloned()
                .collect();
            let view = if let Some(resources) = resources {
                resources
                    .for_work(
                        &name,
                        &names,
                        &binding.requirements,
                        &declaration.required_capabilities.cx_capabilities,
                    )
                    .map_err(ManagedAppBindError::Resource)?
            } else {
                if !names.is_empty() || !binding.requirements.is_empty() {
                    return Err(ManagedAppBindError::Unsupported {
                        unit: name,
                        reason: "observability resources require explicit typed resource bindings",
                    });
                }
                ManagedAppResources::default()
            };
            observers.push(Observer {
                binding,
                required: declaration.required_capabilities.clone(),
                resources: view,
                attempted: AtomicU64::new(0),
                delivered: AtomicU64::new(0),
                panicked: AtomicU64::new(0),
                disabled: AtomicBool::new(false),
            });
        }
        if let Some((name, _)) = supplied.into_iter().next() {
            return Err(ManagedAppBindError::Unexpected(format!("observability:{name}")));
        }
        Ok(Self { observers })
    }

    pub(super) fn validate_runtime(&self, cx: &Cx) -> Result<(), ManagedAppBindError> {
        for observer in &self.observers {
            validate_required_capabilities(
                &format!("observability:{}", observer.binding.name),
                &observer.required,
                &observer.resources.capabilities(),
                cx,
            )?;
        }
        Ok(())
    }

    pub(super) fn emit(&self, owner: &Cx, event: &ManagedAppEvent) {
        for observer in &self.observers {
            if observer.disabled.load(Ordering::Acquire) {
                continue;
            }
            increment(&observer.attempted);
            let cx = restrict_required_capabilities(
                &observer.required,
                owner.clone(),
                owner.registry_handle(),
            );
            // Keep the sink's authority installed while retiring a user panic
            // payload too: its destructor is another user-code callback.
            let _ambient = Cx::set_current(Some(cx.clone()));
            let result = catch_unwind(AssertUnwindSafe(|| {
                (observer.binding.callback)(&cx, event, &observer.resources);
            }));
            match result {
                Ok(()) => increment(&observer.delivered),
                Err(payload) => {
                    observer.disabled.store(true, Ordering::Release);
                    increment(&observer.panicked);
                    retire_panic_payload(payload);
                }
            }
        }
    }

    pub(super) fn stats(&self) -> Vec<ManagedAppObservabilityStats> {
        self.observers
            .iter()
            .map(|observer| ManagedAppObservabilityStats {
                name: observer.binding.name.clone(),
                kind: observer.binding.kind.clone(),
                attempted: observer.attempted.load(Ordering::Relaxed),
                delivered: observer.delivered.load(Ordering::Relaxed),
                panicked: observer.panicked.load(Ordering::Relaxed),
                disabled: observer.disabled.load(Ordering::Acquire),
            })
            .collect()
    }
}

fn retire_panic_payload(payload: Box<dyn std::any::Any + Send>) {
    // Normal Rust panic strings can always be destroyed. Arbitrary payloads
    // may execute user Drop code; contain that separately after disabling the
    // sink so repeated events cannot repeatedly retain such a payload.
    if payload.is::<String>() || payload.is::<&'static str>() {
        drop(payload);
    } else if let Err(secondary) = catch_unwind(AssertUnwindSafe(|| drop(payload))) {
        if secondary.is::<String>() || secondary.is::<&'static str>() {
            drop(secondary);
        } else {
            std::mem::forget(secondary);
        }
    }
}

// `fetch_update` is deprecated as `try_update` on the pinned nightly, which
// the stable-lane toolchain lacks; keep the old name and allow the lint.
#[allow(deprecated)]
fn increment(counter: &AtomicU64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(1))
    });
}
