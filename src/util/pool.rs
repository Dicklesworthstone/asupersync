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
    pub fn put(&self, item: T) -> bool {
        let mut storage = self.lock_storage();
        if storage.len() < self.max_size {
            storage.push_front(item);
            return true;
        }
        // Silently drop if pool is full
        false
    }

    /// Returns the current number of objects in the pool.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock_storage().len()
    }

    /// Returns the configured maximum pool size.
    #[must_use]
    pub const fn max_size(&self) -> usize {
        self.max_size
    }

    /// Returns true if the pool is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clears all objects from the pool.
    pub fn clear(&self) {
        let retired = {
            let mut storage = self.lock_storage();
            std::mem::take(&mut *storage)
        };
        // `T::drop` is arbitrary user code and may re-enter this pool. Retire
        // every value only after releasing the non-reentrant storage mutex.
        drop(retired);
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

    /// Attempts to get an object from the pool without allocating.
    pub fn try_get(&self) -> Option<T> {
        self.pool.try_get()
    }

    /// Returns an object to the pool after resetting it.
    pub fn put_recycled(&self, mut item: T) -> bool {
        item.reset();
        self.pool.put(item)
    }

    /// Returns the current number of objects in the pool.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pool.len()
    }

    /// Returns the configured maximum pool size.
    #[must_use]
    pub const fn max_size(&self) -> usize {
        self.pool.max_size()
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
#[path = "pool_inline_tests.rs"]
mod tests;
