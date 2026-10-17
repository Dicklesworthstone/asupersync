    use super::*;
    use std::sync::Arc;

    #[derive(Debug, PartialEq)]
    struct TestObject {
        value: u32,
        data: String,
    }

    impl TestObject {
        fn new(value: u32) -> Self {
            Self {
                value,
                data: format!("test-{value}"),
            }
        }
    }

    impl Recyclable for TestObject {
        fn reset(&mut self) {
            self.value = 0;
            self.data.clear();
        }
    }

    struct ClearDropProbe {
        on_drop: Option<Box<dyn FnOnce() + Send>>,
    }

    impl ClearDropProbe {
        fn new(on_drop: impl FnOnce() + Send + 'static) -> Self {
            Self {
                on_drop: Some(Box::new(on_drop)),
            }
        }
    }

    impl Drop for ClearDropProbe {
        fn drop(&mut self) {
            if let Some(on_drop) = self.on_drop.take() {
                on_drop();
            }
        }
    }

    impl Recyclable for ClearDropProbe {
        fn reset(&mut self) {}
    }

    #[test]
    fn pool_basic_operations() {
        let pool = Pool::new(10);
        assert!(pool.is_empty());

        let obj = TestObject::new(42);
        pool.put(obj);
        assert_eq!(pool.len(), 1);

        let retrieved = pool.try_get().unwrap();
        assert_eq!(retrieved.value, 42);
        assert!(pool.is_empty());
    }

    #[test]
    fn pool_capacity_limit() {
        let pool = Pool::new(2);

        pool.put(TestObject::new(1));
        pool.put(TestObject::new(2));
        pool.put(TestObject::new(3)); // Should be dropped

        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn pool_recovers_after_poisoned_lock() {
        let pool = Arc::new(Pool::new(2));
        let poisoned_pool = Arc::clone(&pool);

        let poison_result = std::panic::catch_unwind(move || {
            let _guard = match poisoned_pool.storage.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            std::panic::panic_any("poison pool mutex for regression test");
        });

        assert!(poison_result.is_err());

        pool.put(TestObject::new(7));

        assert_eq!(pool.len(), 1);
        assert_eq!(pool.try_get().map(|object| object.value), Some(7));
        assert!(pool.is_empty());
    }

    #[test]
    fn pool_clear_drops_values_after_unlock() {
        let pool = Arc::new(Pool::new(1));
        let weak_pool = Arc::downgrade(&pool);
        let (observation_tx, observation_rx) = std::sync::mpsc::channel();
        assert!(pool.put(ClearDropProbe::new(move || {
            let pool = weak_pool
                .upgrade()
                .expect("pool remains alive during clear");
            let storage_is_free = pool.storage.try_lock().is_ok();
            observation_tx
                .send((storage_is_free, storage_is_free.then(|| pool.len())))
                .expect("record clear drop observation");
        })));

        pool.clear();

        assert_eq!(
            observation_rx.try_recv(),
            Ok((true, Some(0))),
            "Drop may re-enter the empty pool after clear detaches its values"
        );
        assert!(pool.is_empty());
    }

    #[test]
    fn recycling_pool_reset() {
        let pool = RecyclingPool::new(5);

        let obj = pool.get_or_create(|| TestObject::new(42));
        assert_eq!(obj.value, 42);

        let mut obj = obj;
        obj.value = 100;
        obj.data = "modified".to_string();

        pool.put_recycled(obj);
        assert_eq!(pool.len(), 1);

        let recycled = pool.get_or_create(|| TestObject::new(999));
        assert_eq!(recycled.value, 0); // Reset value
        assert!(recycled.data.is_empty()); // Reset data
    }

    #[test]
    fn recycling_pool_clear_drops_values_after_unlock() {
        let pool = Arc::new(RecyclingPool::new(1));
        let weak_pool = Arc::downgrade(&pool);
        let (observation_tx, observation_rx) = std::sync::mpsc::channel();
        assert!(pool.put_recycled(ClearDropProbe::new(move || {
            let pool = weak_pool
                .upgrade()
                .expect("recycling pool remains alive during clear");
            let storage_is_free = pool.pool.storage.try_lock().is_ok();
            observation_tx
                .send((storage_is_free, storage_is_free.then(|| pool.len())))
                .expect("record recycling clear drop observation");
        })));

        pool.clear();

        assert_eq!(
            observation_rx.try_recv(),
            Ok((true, Some(0))),
            "Drop may re-enter the empty recycling pool after clear detaches its values"
        );
        assert!(pool.is_empty());
    }
