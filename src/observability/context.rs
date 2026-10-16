//! Diagnostic context for distributed tracing and logging.
//!
//! A `DiagnosticContext` carries correlation IDs (task, region, span) and
//! structured fields across asynchronous boundaries.

use crate::types::{RegionId, TaskId};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt;
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone)]
struct ContextStackEntry {
    id: u64,
    context: DiagnosticContext,
}

thread_local! {
    static CONTEXT_STACK: RefCell<Vec<ContextStackEntry>> = const { RefCell::new(Vec::new()) };
}

static NEXT_CONTEXT_GUARD_ID: AtomicU64 = AtomicU64::new(1);

/// A unique identifier for a span within a trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SpanId(pub u64);

impl SpanId {
    /// Generates a new monotonically increasing span ID.
    #[inline]
    pub fn new() -> Self {
        // Deterministic sequence keeps lab replays stable and avoids ambient RNG.
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        Self(NEXT_ID.fetch_add(1, Ordering::Relaxed))
    }
}

impl Default for SpanId {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SpanId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "S{}", self.0)
    }
}

/// A span represents a logical unit of work.
#[derive(Debug, Clone)]
pub struct Span {
    _id: SpanId,
    _parent_id: Option<SpanId>,
    _name: String,
}

/// A context carrying diagnostic information.
///
/// This struct is designed to be cloned and passed between tasks.
/// It uses value semantics (deep copy of map on clone), so modifications
/// to a cloned context do not affect the original.
#[derive(Debug, Clone, Default)]
pub struct DiagnosticContext {
    task_id: Option<TaskId>,
    region_id: Option<RegionId>,
    span_id: Option<SpanId>,
    parent_span_id: Option<SpanId>,
    custom: BTreeMap<String, String>,
    max_completed_spans: usize,
}

impl DiagnosticContext {
    /// Creates a new empty diagnostic context.
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the task ID.
    #[inline]
    #[must_use]
    pub fn with_task_id(mut self, id: TaskId) -> Self {
        self.task_id = Some(id);
        self
    }

    /// Sets the region ID.
    #[inline]
    #[must_use]
    pub fn with_region_id(mut self, id: RegionId) -> Self {
        self.region_id = Some(id);
        self
    }

    /// Sets the span ID.
    #[inline]
    #[must_use]
    pub fn with_span_id(mut self, id: SpanId) -> Self {
        self.span_id = Some(id);
        self
    }

    /// Sets the max completed spans config (internal use).
    #[inline]
    #[must_use]
    pub(crate) fn with_max_completed(mut self, max: usize) -> Self {
        self.max_completed_spans = max;
        self
    }

    /// Adds a custom string field.
    #[inline]
    #[must_use]
    pub fn with_custom(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.custom.insert(key.into(), value.into());
        self
    }

    /// Forks the context, generating a new child span ID.
    #[must_use]
    pub fn fork(&self) -> Self {
        let mut child = self.clone();
        child.parent_span_id = self.span_id;
        child.span_id = Some(SpanId::new());
        child
    }

    /// Merges another context into this one.
    ///
    /// IDs from `other` take precedence if present. Custom fields are merged.
    #[must_use]
    pub fn merge(&self, other: &Self) -> Self {
        let mut merged = self.clone();
        if let Some(id) = other.task_id {
            merged.task_id = Some(id);
        }
        if let Some(id) = other.region_id {
            merged.region_id = Some(id);
        }
        if let Some(id) = other.span_id {
            merged.span_id = Some(id);
        }
        if let Some(id) = other.parent_span_id {
            merged.parent_span_id = Some(id);
        }

        for (k, v) in &other.custom {
            merged.custom.insert(k.clone(), v.clone());
        }

        merged
    }

    /// Enters the context, pushing it on a thread-local context stack.
    ///
    /// The returned guard restores the previous context when dropped.
    #[must_use]
    pub fn enter(&self) -> ContextGuard<'_> {
        let guard_id = NEXT_CONTEXT_GUARD_ID.fetch_add(1, Ordering::Relaxed);
        CONTEXT_STACK.with(|stack| {
            stack.borrow_mut().push(ContextStackEntry {
                id: guard_id,
                context: self.clone(),
            });
        });
        ContextGuard {
            _ctx: self,
            id: guard_id,
            active: true,
            _not_send: PhantomData,
        }
    }

    /// Returns the current thread-local context.
    ///
    /// If no context is currently entered on this thread, returns an empty context.
    #[inline]
    #[must_use]
    pub fn current() -> Self {
        CONTEXT_STACK.with(|stack| {
            stack
                .borrow()
                .last()
                .map_or_else(Self::new, |entry| entry.context.clone())
        })
    }

    // Accessors

    /// Returns the task ID.
    #[inline]
    #[must_use]
    pub fn task_id(&self) -> Option<TaskId> {
        self.task_id
    }

    /// Returns the region ID.
    #[inline]
    #[must_use]
    pub fn region_id(&self) -> Option<RegionId> {
        self.region_id
    }

    /// Returns the span ID.
    #[inline]
    #[must_use]
    pub fn span_id(&self) -> Option<SpanId> {
        self.span_id
    }

    /// Returns the parent span ID.
    #[inline]
    #[must_use]
    pub fn parent_span_id(&self) -> Option<SpanId> {
        self.parent_span_id
    }

    /// Gets a custom field.
    #[inline]
    #[must_use]
    pub fn custom(&self, key: &str) -> Option<&str> {
        self.custom.get(key).map(String::as_str)
    }

    /// Returns an iterator over custom fields.
    pub fn custom_fields(&self) -> impl Iterator<Item = (&str, &str)> {
        self.custom.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }
}

/// Guard for an active diagnostic context.
pub struct ContextGuard<'a> {
    _ctx: &'a DiagnosticContext,
    id: u64,
    active: bool,
    _not_send: PhantomData<Rc<()>>,
}

impl Drop for ContextGuard<'_> {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let _ = CONTEXT_STACK.try_with(|stack| {
            let mut stack = stack.borrow_mut();
            if let Some(pos) = stack.iter().rposition(|entry| entry.id == self.id) {
                stack.remove(pos);
            }
        });
        self.active = false;
    }
}

#[cfg(test)]
#[path = "context_inline_tests.rs"]
mod tests;
