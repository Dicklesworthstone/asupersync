    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn runtime_io_attenuation_refuses_before_dispatch() {
        let cx = {
            let _restricted = Cx::for_testing()
                .restrict::<crate::cx::NoCaps>()
                .set_current_restricted();
            Cx::current().expect("restricted ambient context")
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let result = futures_lite::future::block_on(cx.scoped_fs().run_io(move |_| {
            observed.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }));
        assert!(matches!(result, Err(ScopedFsError::CapabilityDenied)));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn missing_runtime_wiring_refuses_instead_of_running_inline() {
        let cx = Cx::for_testing();
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let result = futures_lite::future::block_on(cx.scoped_fs().run_io(move |_| {
            observed.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }));
        assert!(matches!(result, Err(ScopedFsError::Admission(SpawnError::RuntimeUnavailable))));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
