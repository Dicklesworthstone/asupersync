//! Internal utilities for the Asupersync runtime.
//!
//! These utilities are intentionally minimal and dependency-free to maintain
//! determinism in the lab runtime.

pub mod arena;
pub mod cache;
pub mod det_hash;
pub mod det_rng;
pub mod entropy;
pub mod resource;

pub use arena::{Arena, ArenaIndex};
pub use cache::{CACHE_LINE_SIZE, CachePadded};
pub use det_hash::{DetBuildHasher, DetHashMap, DetHashSet, DetHasher};
pub use det_rng::DetRng;
pub use entropy::{
    DetEntropy, EntropySource, OsEntropy, StrictEntropyGuard, ThreadLocalEntropy,
    check_ambient_entropy, disable_strict_entropy, enable_strict_entropy, strict_entropy_enabled,
};
pub use resource::{
    PoolConfig, PoolExhausted, ResourceLimits, ResourceTracker, SymbolBuffer, SymbolPool,
};
