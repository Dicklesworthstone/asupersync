//! Object pooling utilities for performance optimization.
//!
//! This module provides generic object pooling to reduce allocation overhead
//! in hot paths. The pool maintains a cache of reusable objects to eliminate
//! repeated allocation/deallocation cycles.

use std::collections::VecDeque;
use std::sync::{Mutex, MutexGuard};

/// A thread-safe object pool for recycling expensive-to-construct objects.
#[derive(Debug)]
pub struct Pool<T> {
    /// Pool storage with LIFO ordering for better cache locality.
    storage: Mutex<VecDeque<T>>,
    /// Maximum pool size to prevent unbounded growth.
    max_size: usize,
}

impl<T> Pool<T> {
    /// Creates a new pool with the specified maximum size.
    #[must_use]
    pub fn new(max_size: usize) -> Self {
        Self {
            storage: Mutex::new(VecDeque::new()),
            max_size,
        }
    }

    fn lock_storage(&self) -> MutexGuard<'_, VecDeque<T>> {
        self.storage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Attempts to retrieve a recycled object from the pool.
    ///
    /// Returns `None` if the pool is empty.
    pub fn try_get(&self) -> Option<T> {
        self.lock_storage().pop_front()
    }

    /// Returns an object to the pool for recycling.
    ///
    /// Objects are silently dropped if the pool is at capacity.
    pub fn put(&self, item: T) {
        let mut storage = self.lock_storage();
        if storage.len() < self.max_size {
            storage.push_front(item);
        }
        // Silently drop if pool is full
    }

    /// Returns the current number of objects in the pool.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock_storage().len()
    }

    /// Returns true if the pool is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clears all objects from the pool.
    pub fn clear(&self) {
        self.lock_storage().clear();
    }
}

/// A trait for objects that can be reset for recycling.
pub trait Recyclable {
    /// Resets the object to a clean state for reuse.
    ///
    /// This should clear all fields and return the object to its
    /// initial state, ready for reuse.
    fn reset(&mut self);
}

/// A high-performance object pool that leverages recyclable objects.
#[derive(Debug)]
pub struct RecyclingPool<T>
where
    T: Recyclable,
{
    pool: Pool<T>,
}

impl<T> RecyclingPool<T>
where
    T: Recyclable,
{
    /// Creates a new recycling pool with the specified maximum size.
    #[must_use]
    pub fn new(max_size: usize) -> Self {
        Self {
            pool: Pool::new(max_size),
        }
    }

    /// Gets an object from the pool or creates a new one using the provided factory.
    pub fn get_or_create<F>(&self, factory: F) -> T
    where
        F: FnOnce() -> T,
    {
        self.pool.try_get().unwrap_or_else(factory)
    }

    /// Returns an object to the pool after resetting it.
    pub fn put_recycled(&self, mut item: T) {
        item.reset();
        self.pool.put(item);
    }

    /// Returns the current number of objects in the pool.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pool.len()
    }

    /// Returns true if the pool is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pool.is_empty()
    }

    /// Clears all objects from the pool.
    pub fn clear(&self) {
        self.pool.clear();
    }
}

#[cfg(test)]
mod tests {
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
}
