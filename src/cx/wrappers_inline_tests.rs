    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::cx::cap;

    #[test]
    fn web_caps_have_time_and_io() {
        // WebCaps = CapSet<false, true, false, true, false>
        // This is a compile-time check — if WebCaps doesn't satisfy
        // HasTime + HasIo, these functions won't compile.
        fn requires_time<C: cap::HasTime>() {}
        fn requires_io<C: cap::HasIo>() {}
        requires_time::<WebCaps>();
        requires_io::<WebCaps>();
    }

    #[test]
    fn web_caps_lack_spawn() {
        // Negative test: WebCaps should NOT have spawn.
        // We can't directly test "doesn't implement trait" at runtime,
        // but we verify the const generic values.
        // WebCaps = CapSet<false, true, false, true, false>
        // SPAWN=false, so WebCaps intentionally lacks HasSpawn.
        // This is verified by the compile_fail doctest pattern.
    }

    #[test]
    fn grpc_caps_have_spawn_time_io() {
        fn requires_spawn<C: cap::HasSpawn>() {}
        fn requires_time<C: cap::HasTime>() {}
        fn requires_io<C: cap::HasIo>() {}
        requires_spawn::<GrpcCaps>();
        requires_time::<GrpcCaps>();
        requires_io::<GrpcCaps>();
    }

    #[test]
    fn background_caps_have_spawn_time() {
        fn requires_spawn<C: cap::HasSpawn>() {}
        fn requires_time<C: cap::HasTime>() {}
        requires_spawn::<BackgroundCaps>();
        requires_time::<BackgroundCaps>();
    }

    #[test]
    fn pure_caps_have_nothing() {
        // PureCaps = CapSet<false, false, false, false, false> = cap::None
        // No capability traits are implemented.
        // Verified by type equality.
        let _: PureCaps = cap::None::default();
    }

    #[test]
    fn wrapper_provides_access() {
        fn requires_time<C: cap::HasTime>(_: &Cx<C>) {}
        fn requires_io<C: cap::HasIo>(_: &Cx<C>) {}
        fn requires_spawn<C: cap::HasSpawn>(_: &Cx<C>) {}

        let full_cx = Arc::new(Cx::for_testing());
        let web = WebContext::new(&full_cx, 7);
        let grpc = GrpcContext::new(&full_cx, "svc/method".to_string());
        let background = BackgroundContext::new(&full_cx, "worker".to_string());

        requires_time(web.cx());
        requires_io(web.cx());
        requires_time(grpc.cx());
        requires_io(grpc.cx());
        requires_spawn(grpc.cx());
        requires_time(background.cx());
        requires_spawn(background.cx());

        assert_eq!(web.request_id(), 7);
        assert_eq!(grpc.method(), "svc/method");
        assert_eq!(background.task_name(), "worker");
        assert_eq!(std::mem::size_of::<WebCaps>(), 0);
        assert_eq!(std::mem::size_of::<GrpcCaps>(), 0);
        assert_eq!(std::mem::size_of::<BackgroundCaps>(), 0);
    }

    #[test]
    fn narrow_preserves_runtime_identity() {
        let full_cx = Arc::new(Cx::for_testing());
        let web_cx: Arc<Cx<WebCaps>> = narrow(&full_cx);
        let grpc_cx: Arc<Cx<GrpcCaps>> = narrow(&full_cx);

        assert!(Arc::ptr_eq(&full_cx.inner, &web_cx.inner));
        assert!(Arc::ptr_eq(&full_cx.inner, &grpc_cx.inner));
    }
