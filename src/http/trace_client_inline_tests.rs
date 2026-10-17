    use super::*;

    fn parent() -> W3CTraceContext {
        let mut context: W3CTraceContext =
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00"
                .parse()
                .unwrap();
        context.tracestate = Some("vendor=opaque,second=kept".into());
        context.baggage.insert("tenant", "private").unwrap();
        context
    }

    #[test]
    fn outgoing_child_preserves_lineage_flags_and_vendor_order_without_mutating_parent() {
        let parent = parent();
        let before = parent.clone();
        let child = outgoing_context(&parent, false, |bytes| bytes.fill(0x22)).unwrap();
        assert_eq!(child.trace_id, parent.trace_id);
        assert_eq!(child.parent_span_id, parent.span_id);
        assert_ne!(child.span_id, parent.span_id);
        assert_eq!(child.flags, parent.flags);
        assert!(!child.flags.is_sampled());
        assert_eq!(child.tracestate, parent.tracestate);
        assert!(child.baggage.is_empty());
        assert_eq!(parent, before);
    }

    #[test]
    fn opted_in_baggage_keeps_values_and_properties() {
        let mut parent = parent();
        parent
            .baggage
            .insert_with_metadata("locale", "en US", Some("source=user"))
            .unwrap();
        let child = outgoing_context(&parent, true, |bytes| bytes.fill(0x33)).unwrap();
        assert_eq!(child.baggage, parent.baggage);
        assert_eq!(child.baggage.metadata("locale"), Some("source=user"));
    }

    #[test]
    fn child_ids_use_only_the_supplied_entropy_and_repair_zero() {
        let parent = parent();
        let mut counter = 0_u8;
        let mut fill = |bytes: &mut [u8]| {
            counter += 1;
            bytes.fill(counter);
        };
        let first = outgoing_context(&parent, false, &mut fill).unwrap();
        let second = outgoing_context(&parent, false, &mut fill).unwrap();
        assert_ne!(first.span_id, second.span_id);
        let replay = outgoing_context(&parent, false, |bytes| bytes.fill(1)).unwrap();
        assert_eq!(first, replay);
        let zero = outgoing_context(&parent, false, |bytes| bytes.fill(0)).unwrap();
        assert!(zero.to_traceparent().parse::<W3CTraceContext>().is_ok());
        assert_eq!(zero.trace_id, parent.trace_id);
    }

    #[test]
    fn configuration_cannot_forward_context_across_origins_or_keep_stale_defaults() {
        let mut config = HttpClientConfig::default();
        config.redirect_policy = RedirectPolicy::Limited(7);
        config.default_headers = vec![
            ("TraceParent".into(), "stale".into()),
            ("TRACESTATE".into(), "stale=state".into()),
            ("Baggage".into(), "secret=old".into()),
            ("X-Application".into(), "kept".into()),
        ];
        config.request_timeout = Some(Duration::from_secs(3));
        let config = propagation_config(config);
        assert!(matches!(config.redirect_policy, RedirectPolicy::SameOrigin(7)));
        assert_eq!(
            config.default_headers,
            vec![("X-Application".into(), "kept".into())]
        );
        assert_eq!(config.request_timeout, Some(Duration::from_secs(3)));
    }

    #[test]
    fn disabled_redirects_and_existing_same_origin_limits_are_preserved() {
        let mut config = HttpClientConfig::default();
        config.redirect_policy = RedirectPolicy::None;
        assert!(matches!(
            propagation_config(config).redirect_policy,
            RedirectPolicy::None
        ));
        let mut config = HttpClientConfig::default();
        config.redirect_policy = RedirectPolicy::SameOrigin(2);
        assert!(matches!(
            propagation_config(config).redirect_policy,
            RedirectPolicy::SameOrigin(2)
        ));
    }
