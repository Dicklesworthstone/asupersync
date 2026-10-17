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
//! let data = region.heap_alloc(vec![1, 2, 3]).expect("heap alloc");
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
    /// Using `PhantomData<T>` ensures `RRef<T>` is:
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
    #[inline]
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
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.region_id == other.region_id && self.index == other.index
    }
}

impl<T> Eq for RRef<T> {}

impl<T> Hash for RRef<T> {
    #[inline]
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
    #[inline]
    #[must_use]
    pub const fn region_id(&self) -> RegionId {
        self.region_id
    }

    /// Returns the underlying heap index.
    #[inline]
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
    /// # Construction (br-asupersync-aog0xz)
    ///
    /// Pre-fix this constructor was `pub const fn new`. Anyone holding
    /// a `RegionId` (which is forgeable via the asupersync-3zljmn /
    /// asupersync-o2oa4l shapes) could mint an RRef pointing at any
    /// heap index in any region — defeating the capability-token
    /// contract the type was supposed to enforce. The pattern matches
    /// the LabIoCap (asupersync-plm0gr) and ArenaIndex (asupersync-3zljmn)
    /// surfaces fixed earlier this session.
    ///
    /// The constructor is now crate-internal: only the runtime's
    /// runtime can mint an RRef, for a `HeapIndex` that a successful
    /// `heap_alloc` returned. No production path does so yet: there
    /// is no public region-heap allocation API (`asupersync-bi2462.39`).
    ///
    /// Tests that need to construct an RRef (e.g., for table-lookup
    /// fixtures) opt in via the `test-internals` feature gate, which
    /// is enabled in the project's default feature set.
    #[inline]
    #[must_use]
    #[allow(dead_code)]
    pub(crate) const fn new(region_id: RegionId, index: HeapIndex) -> Self {
        Self {
            region_id,
            index,
            _marker: PhantomData,
        }
    }

    /// br-asupersync-aog0xz: test-only constructor for fixtures that
    /// need to mint an RRef without going through a real region's
    /// heap-allocator. Gated behind the same `test-internals` feature
    /// as `LabIoCap::new_for_tests` (asupersync-plm0gr) so production
    /// builds without the feature cannot reach this constructor.
    #[cfg(any(test, feature = "test-internals"))]
    #[inline]
    #[must_use]
    pub const fn new_for_tests(region_id: RegionId, index: HeapIndex) -> Self {
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
    /// The region is closed and its heap has been reclaimed.
    RegionClosed,
    /// The access witness references a different region than expected.
    WrongRegion,
}

impl fmt::Display for RRefError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RegionNotFound(id) => write!(f, "region not found: {id:?}"),
            Self::AllocationInvalid => write!(f, "heap allocation is invalid"),
            Self::RegionMismatch { expected, actual } => {
                write!(f, "region mismatch: expected {expected:?}, got {actual:?}")
            }
            Self::RegionClosed => write!(f, "region is closed"),
            Self::WrongRegion => write!(f, "access witness references wrong region"),
        }
    }
}

impl std::error::Error for RRefError {}

/// Capability witness proving access rights to a specific region's heap.
///
/// Constructed exclusively by [`crate::record::RegionRecord::access_witness`] when the region
/// is in a non-terminal state. External code cannot forge a witness because
/// the constructor is `pub(crate)`.
///
/// # Usage
///
/// ```ignore
/// let witness = region_record.access_witness()?;
/// let value = region_record.rref_get_with(&rref, witness)?;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RRefAccessWitness {
    region_id: RegionId,
}

impl RRefAccessWitness {
    /// Creates a new access witness for the given region.
    ///
    /// This is `pub(crate)` to prevent external forging. Use
    /// [`RegionRecord::access_witness`] to obtain a witness.
    #[must_use]
    pub(crate) const fn new(region_id: RegionId) -> Self {
        Self { region_id }
    }

    /// Returns the region this witness grants access to.
    #[must_use]
    pub const fn region(&self) -> RegionId {
        self.region_id
    }
}

impl<T> RRef<T> {
    /// Validates that a witness matches this RRef's region.
    ///
    /// Returns `Err(WrongRegion)` if the witness was obtained from a different
    /// region than the one this RRef belongs to.
    pub fn validate_witness(&self, witness: &RRefAccessWitness) -> Result<(), RRefError> {
        if witness.region() != self.region_id {
            return Err(RRefError::WrongRegion);
        }
        Ok(())
    }
}

/// Extension trait for accessing RRef values through a region.
///
/// This trait is implemented for types that can provide access to a region's heap.
/// Implementations must validate region ownership and state before returning data.
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

    /// Gets a clone of the value, requiring a pre-validated witness.
    ///
    /// The witness proves the caller has been granted access to the region.
    /// This is the preferred access path in capability-aware code.
    fn rref_get_with<T: Clone + 'static>(
        &self,
        rref: &RRef<T>,
        witness: RRefAccessWitness,
    ) -> Result<T, RRefError>;

    /// Executes a closure with a reference, requiring a pre-validated witness.
    ///
    /// The witness proves the caller has been granted access to the region.
    fn rref_with_witness<T: 'static, R, F: FnOnce(&T) -> R>(
        &self,
        rref: &RRef<T>,
        witness: RRefAccessWitness,
        f: F,
    ) -> Result<R, RRefError>;
}

#[cfg(test)]
#[path = "rref_inline_tests.rs"]
mod tests;
