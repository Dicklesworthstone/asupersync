    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    #[test]
    fn create_entries() {
        let trace = LogEntry::trace("trace msg");
        assert_eq!(trace.level(), LogLevel::Trace);

        let info = LogEntry::info("info msg");
        assert_eq!(info.level(), LogLevel::Info);
        assert_eq!(info.message(), "info msg");

        let error = LogEntry::error("error msg");
        assert_eq!(error.level(), LogLevel::Error);
    }

    #[test]
    fn entry_with_fields() {
        let entry = LogEntry::info("test")
            .with_field("key1", "value1")
            .with_field("key2", "value2")
            .with_timestamp(Time::from_millis(100));

        assert_eq!(entry.field_count(), 2);
        assert_eq!(entry.get_field("key1"), Some("value1"));
        assert_eq!(entry.get_field("key2"), Some("value2"));
        assert_eq!(entry.get_field("missing"), None);
        assert_eq!(entry.timestamp(), Time::from_millis(100));
    }

    #[test]
    fn entry_with_target() {
        let entry = LogEntry::info("test").with_target("my_module");
        assert_eq!(entry.target(), Some("my_module"));
    }

    #[test]
    fn format_compact() {
        let entry = LogEntry::info("Hello world")
            .with_field("foo", "bar")
            .with_field("baz", "42");

        let compact = entry.format_compact();
        assert!(compact.contains("[I]"));
        assert!(compact.contains("Hello world"));
        assert!(compact.contains("foo=bar"));
        assert!(compact.contains("baz=42"));
    }

    #[test]
    fn format_json() {
        let entry = LogEntry::warn("Test message")
            .with_field("count", "5")
            .with_timestamp(Time::from_millis(1000));

        let json = entry.format_json();
        assert!(json.contains("\"level\":\"warn\""));
        assert!(json.contains("\"message\":\"Test message\""));
        assert!(json.contains("\"count\":\"5\""));
        assert!(json.contains("\"timestamp_ns\":1000000000"));
    }

    #[test]
    fn json_escaping() {
        let entry = LogEntry::info("Message with \"quotes\" and \\ backslash");
        let json = entry.format_json();
        assert!(json.contains("\\\"quotes\\\""));
        assert!(json.contains("\\\\"));
    }

    #[test]
    fn json_escaping_fields_and_target() {
        let entry = LogEntry::info("msg")
            .with_target("mod\"name")
            .with_field("k\"ey", "v\\al\n");
        let json = entry.format_json();
        assert!(json.contains("\"target\":\"mod\\\"name\""));
        assert!(json.contains("\"k\\\"ey\":\"v\\\\al\\n\""));
    }

    #[test]
    fn max_fields_limit() {
        let mut entry = LogEntry::info("test");
        for i in 0..20 {
            entry = entry.with_field(format!("key{i}"), format!("val{i}"));
        }
        assert_eq!(entry.field_count(), MAX_FIELDS);
    }

    #[test]
    fn duplicate_field_updates_existing_value() {
        let entry = LogEntry::info("test")
            .with_field("attempt", "1")
            .with_field("attempt", "2");

        assert_eq!(entry.field_count(), 1);
        assert_eq!(entry.get_field("attempt"), Some("2"));
        let fields: Vec<_> = entry.fields().collect();
        assert_eq!(fields, vec![("attempt", "2")]);
    }

    #[test]
    fn json_reserved_field_names_are_namespaced() {
        let entry = LogEntry::info("real message")
            .with_target("real-target")
            .with_field("message", "field message")
            .with_field("level", "field level")
            .with_field("target", "field target")
            .with_field("timestamp_ns", "field timestamp");

        let json = entry.format_json();

        assert_eq!(json.matches("\"message\":").count(), 1);
        assert_eq!(json.matches("\"level\":").count(), 1);
        assert_eq!(json.matches("\"target\":").count(), 1);
        assert_eq!(json.matches("\"timestamp_ns\":").count(), 1);
        assert!(json.contains("\"field.message\":\"field message\""));
        assert!(json.contains("\"field.level\":\"field level\""));
        assert!(json.contains("\"field.target\":\"field target\""));
        assert!(json.contains("\"field.timestamp_ns\":\"field timestamp\""));
    }

    #[test]
    fn json_reserved_alias_family_remains_collision_free() {
        let entry = LogEntry::info("real message")
            .with_field("message", "field message")
            .with_field("field.message", "literal alias")
            .with_field("field.field.message", "double alias");

        let json = entry.format_json();

        assert_eq!(json.matches("\"message\":").count(), 1);
        assert_eq!(json.matches("\"field.message\":").count(), 1);
        assert_eq!(json.matches("\"field.field.message\":").count(), 1);
        assert_eq!(json.matches("\"field.field.field.message\":").count(), 1);
        assert!(json.contains("\"field.message\":\"field message\""));
        assert!(json.contains("\"field.field.message\":\"literal alias\""));
        assert!(json.contains("\"field.field.field.message\":\"double alias\""));
    }

    #[test]
    fn fields_iterator() {
        let entry = LogEntry::info("test")
            .with_field("a", "1")
            .with_field("b", "2");

        let fields: Vec<_> = entry.fields().collect();
        assert_eq!(fields, vec![("a", "1"), ("b", "2")]);
    }

    #[test]
    fn entry_with_context() {
        use crate::observability::SpanId;
        use crate::types::{RegionId, TaskId};
        use crate::util::ArenaIndex;

        let ctx = DiagnosticContext::new()
            .with_task_id(TaskId::from_arena(ArenaIndex::new(3, 0)))
            .with_region_id(RegionId::from_arena(ArenaIndex::new(2, 0)))
            .with_span_id(SpanId::new())
            .with_custom("request_id", "abc123");

        let entry = LogEntry::info("hello").with_context(&ctx);

        assert_eq!(entry.get_field("task_id"), Some("T3"));
        assert_eq!(entry.get_field("region_id"), Some("R2"));
        assert!(entry.get_field("span_id").is_some());
        assert_eq!(entry.get_field("request_id"), Some("abc123"));
    }

    #[test]
    fn entry_with_context_overrides_conflicting_fields() {
        let ctx = DiagnosticContext::new()
            .with_custom("request_id", "ctx-request")
            .with_custom("span.name", "ctx-span");

        let entry = LogEntry::info("hello")
            .with_field("request_id", "user-request")
            .with_field("span.name", "user-span")
            .with_context(&ctx);

        assert_eq!(entry.get_field("request_id"), Some("ctx-request"));
        assert_eq!(entry.get_field("span.name"), Some("ctx-span"));
        assert_eq!(
            entry.format_json().matches("\"request_id\":").count(),
            1,
            "request_id should only appear once in JSON output"
        );
    }

    #[test]
    fn entry_with_context_preserves_context_when_field_budget_is_full() {
        use crate::observability::SpanId;

        let mut entry = LogEntry::info("hello");
        for i in 0..MAX_FIELDS {
            entry = entry.with_field(format!("key{i}"), format!("value{i}"));
        }

        let ctx = DiagnosticContext::new()
            .with_span_id(SpanId::new())
            .with_custom("request_id", "abc123");

        let entry = entry.with_context(&ctx);

        assert_eq!(entry.field_count(), MAX_FIELDS);
        assert!(entry.get_field("span_id").is_some());
        assert_eq!(entry.get_field("request_id"), Some("abc123"));
        assert_eq!(entry.get_field("key0"), None);
        assert_eq!(entry.get_field("key1"), None);
    }

    #[test]
    fn entry_with_context_preserves_core_ids_when_context_overflows_budget() {
        use crate::observability::SpanId;
        use crate::types::{RegionId, TaskId};
        use crate::util::ArenaIndex;

        let mut ctx = DiagnosticContext::new()
            .with_task_id(TaskId::from_arena(ArenaIndex::new(7, 0)))
            .with_region_id(RegionId::from_arena(ArenaIndex::new(8, 0)))
            .with_span_id(SpanId::new());

        for i in 0..MAX_FIELDS {
            ctx = ctx.with_custom(format!("custom{i}"), format!("value{i}"));
        }

        let entry = LogEntry::info("hello").with_context(&ctx);

        assert_eq!(entry.field_count(), MAX_FIELDS);
        assert_eq!(entry.get_field("task_id"), Some("T7"));
        assert_eq!(entry.get_field("region_id"), Some("R8"));
        assert!(entry.get_field("span_id").is_some());
    }

    #[test]
    fn log_entry_debug_clone() {
        let e = LogEntry::info("hello world");
        let dbg = format!("{e:?}");
        assert!(!dbg.is_empty());
        let cloned = e;
        assert_eq!(format!("{cloned:?}"), dbg);
    }
