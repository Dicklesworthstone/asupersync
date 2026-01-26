//! Region-owned reference type.
//!
//! `RRef` provides a way for migrating (`Send`) tasks to reference data
//! allocated in the region heap safely.
//!
//! # Design
//!
//! `RRef<T>` is a smart reference that:
//! - Stores a `RegionId` and `HeapIndex` for runtime lookup
//! - Is `Send + Sync` when `T: Send + Sync`
//! - Requires passing the `RegionRecord` to access the underlying value
//! - Validates region and allocation validity at access time
//!
//! The key invariant is that region heap allocations remain valid for all
//! tasks owned by the region. Since tasks cannot outlive their owning region
//! (structured concurrency guarantee), `RRef`s held by tasks are always valid
//! while those tasks are running.
//!
//! # Example
//!
//! ```ignore
//! // In region context
//! let data = region.heap_alloc(vec![1, 2, 3]);
//! let rref = RRef::<Vec<i32>>::new(region_id, data);
//!
//! // Pass to spawned task
//! spawn(async move {
//!     // Access via region reference
//!     let value = rref.get(&runtime_state, region_id)?;
//!     println!("data: {:?}", value);
//! });
//! ```
//!
//! # Safety
//!
//! This type uses no unsafe code. Safety is enforced through:
//! 1. Structured concurrency: tasks cannot outlive their region
//! 2. Runtime validation: access checks region/index validity
//! 3. Type safety: HeapIndex includes TypeId for type checking

use crate::runtime::region_heap::HeapIndex;
use crate::types::RegionId;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;

/// A region-owned reference to heap-allocated data.
///
/// `RRef<T>` allows tasks to hold references to data allocated in a region's
/// heap. The reference is valid as long as the owning region is open.
///
/// # Send/Sync
///
/// `RRef<T>` is `Send` when `T: Send` and `Sync` when `T: Sync`. This allows
/// `RRef`s to be safely passed to worker threads. The bounds are automatically
/// provided through `PhantomData<T>` - no unsafe code required.
///
/// # Cloning
///
/// `RRef` is `Clone + Copy` because it contains only indices, not the actual
/// data. Multiple `RRef`s can point to the same heap allocation.
pub struct RRef<T> {
    /// The region that owns this allocation.
    region_id: RegionId,
    /// Index into the region's heap.
    index: HeapIndex,
    /// Marker for the referenced type.
    ///
    /// Using `PhantomData<T>` ensures RRef<T> is:
    /// - Send when T: Send
    /// - Sync when T: Sync
    ///
    /// This is safe because RRef contains only indices (Copy types), not the
    /// actual data. Access to the data goes through the RegionHeap which has
    /// its own synchronization (RwLock).
    _marker: PhantomData<T>,
}

// Manual Clone impl to avoid requiring T: Clone (RRef is Copy regardless of T)
impl<T> Clone for RRef<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for RRef<T> {}

impl<T> fmt::Debug for RRef<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RRef")
            .field("region_id", &self.region_id)
            .field("index", &self.index)
            .finish()
    }
}

impl<T> PartialEq for RRef<T> {
    fn eq(&self, other: &Self) -> bool {
        self.region_id == other.region_id && self.index == other.index
    }
}

impl<T> Eq for RRef<T> {}

impl<T> Hash for RRef<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.region_id.hash(state);
        self.index.hash(state);
    }
}

// Send and Sync are automatically derived via PhantomData<T>:
// - RRef<T>: Send when T: Send (PhantomData<T>: Send when T: Send)
// - RRef<T>: Sync when T: Sync (PhantomData<T>: Sync when T: Sync)
//
// This is safe because:
// - RRef contains only indices (Copy types)
// - The actual data is in RegionHeap which has its own synchronization (RwLock)
// - Access requires going through the heap which has proper locking

// Accessor methods available for all RRef<T> regardless of bounds.
// These just return stored indices (Copy types) and don't access the underlying data.
impl<T> RRef<T> {
    /// Returns the region ID that owns this reference.
    #[must_use]
    pub const fn region_id(&self) -> RegionId {
        self.region_id
    }

    /// Returns the underlying heap index.
    #[must_use]
    pub const fn heap_index(&self) -> HeapIndex {
        self.index
    }
}

// Construction requires Send + Sync + 'static for soundness when used with Send tasks.
impl<T: Send + Sync + 'static> RRef<T> {
    /// Creates a new region reference from a region ID and heap index.
    ///
    /// # Arguments
    ///
    /// * `region_id` - The ID of the region that owns the allocation
    /// * `index` - The heap index returned from `heap_alloc`
    ///
    /// # Bounds
    ///
    /// The `Send + Sync + 'static` bounds on `T` ensure that:
    /// - The referenced data can be safely shared across threads
    /// - The `RRef` can be passed to Send tasks that may migrate
    ///
    /// # Example
    ///
    /// ```ignore
    /// let index = region.heap_alloc(42u32);
    /// let rref = RRef::new(region_id, index);
    /// ```
    #[must_use]
    pub const fn new(region_id: RegionId, index: HeapIndex) -> Self {
        Self {
            region_id,
            index,
            _marker: PhantomData,
        }
    }
}

/// Error returned when accessing an RRef fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RRefError {
    /// The region does not exist in the runtime state.
    RegionNotFound(RegionId),
    /// The heap allocation is no longer valid (deallocated or type mismatch).
    AllocationInvalid,
    /// The region ID in the RRef doesn't match the provided region.
    RegionMismatch {
        /// The region ID stored in the RRef.
        expected: RegionId,
        /// The region ID that was provided.
        actual: RegionId,
    },
}

impl fmt::Display for RRefError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RegionNotFound(id) => write!(f, "region not found: {id:?}"),
            Self::AllocationInvalid => write!(f, "heap allocation is invalid"),
            Self::RegionMismatch { expected, actual } => {
                write!(f, "region mismatch: expected {expected:?}, got {actual:?}")
            }
        }
    }
}

impl std::error::Error for RRefError {}

/// Extension trait for accessing RRef values through a region.
///
/// This trait is implemented for types that can provide access to a region's heap.
pub trait RRefAccess {
    /// Gets a clone of the value referenced by an RRef.
    ///
    /// Returns an error if the region doesn't match or the allocation is invalid.
    fn rref_get<T: Clone + 'static>(&self, rref: &RRef<T>) -> Result<T, RRefError>;

    /// Executes a closure with a reference to the value.
    ///
    /// This is more efficient than `rref_get` when you don't need to clone.
    fn rref_with<T: 'static, R, F: FnOnce(&T) -> R>(
        &self,
        rref: &RRef<T>,
        f: F,
    ) -> Result<R, RRefError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::RegionRecord;
    use crate::types::Budget;
    use crate::util::ArenaIndex;

    fn test_region_id() -> RegionId {
        RegionId::from_arena(ArenaIndex::new(0, 0))
    }

    #[test]
    fn rref_is_copy_and_clone() {
        let region_id = test_region_id();
        let record = RegionRecord::new(region_id, None, Budget::INFINITE);
        let index = record.heap_alloc(42u32);
        let rref = RRef::<u32>::new(region_id, index);

        // Test Copy
        let rref2 = rref;
        assert_eq!(rref.region_id(), rref2.region_id());

        // Test Clone
        let rref3 = rref.clone();
        assert_eq!(rref.heap_index(), rref3.heap_index());
    }

    #[test]
    fn rref_equality() {
        let region_id = test_region_id();
        let record = RegionRecord::new(region_id, None, Budget::INFINITE);

        let index1 = record.heap_alloc(1u32);
        let index2 = record.heap_alloc(2u32);

        let rref1a = RRef::<u32>::new(region_id, index1);
        let rref1b = RRef::<u32>::new(region_id, index1);
        let rref2 = RRef::<u32>::new(region_id, index2);

        assert_eq!(rref1a, rref1b);
        assert_ne!(rref1a, rref2);
    }

    #[test]
    fn rref_accessors() {
        let region_id = test_region_id();
        let record = RegionRecord::new(region_id, None, Budget::INFINITE);
        let index = record.heap_alloc("hello".to_string());
        let rref = RRef::<String>::new(region_id, index);

        assert_eq!(rref.region_id(), region_id);
        assert_eq!(rref.heap_index(), index);
    }

    #[test]
    fn rref_debug_format() {
        let region_id = test_region_id();
        let record = RegionRecord::new(region_id, None, Budget::INFINITE);
        let index = record.heap_alloc(42u32);
        let rref = RRef::<u32>::new(region_id, index);

        let debug_str = format!("{rref:?}");
        assert!(debug_str.contains("RRef"));
        assert!(debug_str.contains("region_id"));
        assert!(debug_str.contains("index"));
    }

    // Compile-time test for Send/Sync bounds
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}

    #[test]
    fn rref_send_sync_bounds() {
        // RRef<T> is Send when T: Send
        assert_send::<RRef<u32>>();
        assert_send::<RRef<String>>();
        assert_send::<RRef<Vec<i32>>>();

        // RRef<T> is Sync when T: Sync
        assert_sync::<RRef<u32>>();
        assert_sync::<RRef<String>>();
        assert_sync::<RRef<Vec<i32>>>();
    }
}
