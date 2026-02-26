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
    pub fn new() -> Self {
        // Deterministic sequence keeps lab replays stable and avoids ambient RNG.
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        Self(NEXT_ID.fetch_add(1, Ordering::Relaxed))
    }
}

impl Default for SpanId {
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
    id: SpanId,
    parent_id: Option<SpanId>,
    name: String,
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
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the task ID.
    #[must_use]
    pub fn with_task_id(mut self, id: TaskId) -> Self {
        self.task_id = Some(id);
        self
    }

    /// Sets the region ID.
    #[must_use]
    pub fn with_region_id(mut self, id: RegionId) -> Self {
        self.region_id = Some(id);
        self
    }

    /// Sets the span ID.
    #[must_use]
    pub fn with_span_id(mut self, id: SpanId) -> Self {
        self.span_id = Some(id);
        self
    }

    /// Sets the max completed spans config (internal use).
    #[must_use]
    pub(crate) fn with_max_completed(mut self, max: usize) -> Self {
        self.max_completed_spans = max;
        self
    }

    /// Adds a custom string field.
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
    #[must_use]
    pub fn task_id(&self) -> Option<TaskId> {
        self.task_id
    }

    /// Returns the region ID.
    #[must_use]
    pub fn region_id(&self) -> Option<RegionId> {
        self.region_id
    }

    /// Returns the span ID.
    #[must_use]
    pub fn span_id(&self) -> Option<SpanId> {
        self.span_id
    }

    /// Returns the parent span ID.
    #[must_use]
    pub fn parent_span_id(&self) -> Option<SpanId> {
        self.parent_span_id
    }

    /// Gets a custom field.
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
        CONTEXT_STACK.with(|stack| {
            let mut stack = stack.borrow_mut();
            if let Some(pos) = stack.iter().rposition(|entry| entry.id == self.id) {
                stack.remove(pos);
            }
        });
        self.active = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::ArenaIndex;

    #[test]
    fn context_new_empty() {
        let ctx = DiagnosticContext::new();
        assert!(ctx.task_id().is_none());
        assert!(ctx.region_id().is_none());
        assert!(ctx.span_id().is_none());
    }

    #[test]
    fn context_with_ids() {
        let tid = TaskId::from_arena(ArenaIndex::new(1, 0));
        let rid = RegionId::from_arena(ArenaIndex::new(2, 0));
        let sid = SpanId::new();

        let ctx = DiagnosticContext::new()
            .with_task_id(tid)
            .with_region_id(rid)
            .with_span_id(sid);

        assert_eq!(ctx.task_id(), Some(tid));
        assert_eq!(ctx.region_id(), Some(rid));
        assert_eq!(ctx.span_id(), Some(sid));
    }

    #[test]
    fn context_custom_fields() {
        let ctx = DiagnosticContext::new()
            .with_custom("key", "value")
            .with_custom("num", "42");

        assert_eq!(ctx.custom("key"), Some("value"));
        assert_eq!(ctx.custom("num"), Some("42"));
        assert_eq!(ctx.custom("missing"), None);

        let mut fields: Vec<_> = ctx.custom_fields().collect();
        fields.sort_by(|a, b| a.0.cmp(b.0));
        assert_eq!(fields, vec![("key", "value"), ("num", "42")]);
    }

    #[test]
    fn context_fork() {
        let sid = SpanId::new();
        let ctx = DiagnosticContext::new().with_span_id(sid);
        let child = ctx.fork();

        assert_eq!(child.parent_span_id(), Some(sid));
        assert!(child.span_id().is_some());
        assert_ne!(child.span_id(), Some(sid));
    }

    #[test]
    fn context_merge() {
        let tid = TaskId::from_arena(ArenaIndex::new(1, 0));
        let ctx1 = DiagnosticContext::new()
            .with_task_id(tid)
            .with_custom("a", "1");

        let ctx2 = DiagnosticContext::new()
            .with_custom("b", "2")
            .with_custom("a", "override"); // Should override

        let merged = ctx1.merge(&ctx2);

        assert_eq!(merged.task_id(), Some(tid)); // Preserved
        assert_eq!(merged.custom("b"), Some("2")); // Added
        assert_eq!(merged.custom("a"), Some("override")); // Overridden
    }

    #[test]
    fn context_enter_sets_current_and_restores_on_drop() {
        let base = DiagnosticContext::new().with_custom("request_id", "abc123");
        assert!(DiagnosticContext::current().custom("request_id").is_none());

        {
            let _guard = base.enter();
            let current = DiagnosticContext::current();
            assert_eq!(current.custom("request_id"), Some("abc123"));
        }

        assert!(DiagnosticContext::current().custom("request_id").is_none());
    }

    #[test]
    fn context_enter_nested_restores_parent() {
        let outer = DiagnosticContext::new().with_custom("scope", "outer");
        let inner = DiagnosticContext::new().with_custom("scope", "inner");

        let outer_guard = outer.enter();
        assert_eq!(DiagnosticContext::current().custom("scope"), Some("outer"));

        {
            let _inner_guard = inner.enter();
            assert_eq!(DiagnosticContext::current().custom("scope"), Some("inner"));
        }

        assert_eq!(DiagnosticContext::current().custom("scope"), Some("outer"));
        drop(outer_guard);
        assert!(DiagnosticContext::current().custom("scope").is_none());
    }

    #[test]
    fn context_enter_out_of_order_drop_preserves_top() {
        let outer = DiagnosticContext::new().with_custom("scope", "outer");
        let middle = DiagnosticContext::new().with_custom("scope", "middle");
        let inner = DiagnosticContext::new().with_custom("scope", "inner");

        let outer_guard = outer.enter();
        let middle_guard = middle.enter();
        let inner_guard = inner.enter();
        assert_eq!(DiagnosticContext::current().custom("scope"), Some("inner"));

        // Drop middle first; top-of-stack should remain unchanged.
        drop(middle_guard);
        assert_eq!(DiagnosticContext::current().custom("scope"), Some("inner"));

        // Dropping inner should restore the remaining outer context.
        drop(inner_guard);
        assert_eq!(DiagnosticContext::current().custom("scope"), Some("outer"));

        drop(outer_guard);
        assert!(DiagnosticContext::current().custom("scope").is_none());
    }

    // =========================================================================
    // Wave 50 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn span_id_debug_clone_copy_hash_display_default() {
        use std::collections::HashSet;
        let s = SpanId(99);
        let dbg = format!("{s:?}");
        assert!(dbg.contains("SpanId"), "{dbg}");
        let copied = s;
        let cloned = s;
        assert_eq!(copied, cloned);
        let display = format!("{s}");
        assert_eq!(display, "S99");
        let mut set = HashSet::new();
        set.insert(s);
        assert!(set.contains(&SpanId(99)));
        let _def = SpanId::default();
    }

    #[test]
    fn diagnostic_context_debug_clone_default() {
        let def = DiagnosticContext::default();
        let dbg = format!("{def:?}");
        assert!(dbg.contains("DiagnosticContext"), "{dbg}");
        let ctx = DiagnosticContext::new().with_custom("k", "v");
        let cloned = ctx;
        assert_eq!(cloned.custom("k"), Some("v"));
    }
}
