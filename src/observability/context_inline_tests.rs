    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
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
