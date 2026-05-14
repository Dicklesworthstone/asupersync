# Cross-Module Lock Ordering Enhancement

This document describes the enhanced lock ordering enforcement implemented to address cross-module deadlock prevention in asupersync.

## Problem Statement

While individual modules followed the E→D→B→A→C lock hierarchy, there was no runtime enforcement of cross-module lock acquisition patterns. This could lead to deadlocks when operations span multiple asupersync modules.

## Solution Overview

The enhanced lock ordering system tracks both lock ranks and module identities, enabling detection of problematic cross-module patterns that could cause deadlocks.

### Key Components

1. **Module Identification**: `LockModule` enum classifies locks by their owning module
2. **Enhanced Tracking**: Thread-local storage tracks both ranks and detailed lock information
3. **Cross-Module Validation**: Pattern-based rules prevent known problematic interaction sequences
4. **Enhanced API**: `LockOrderEnforcer` provides a convenient interface for module-aware enforcement

### Module Classification

```rust
pub enum LockModule {
    Runtime,     // Core runtime module (scheduler, regions, tasks)
    Sync,        // Synchronization primitives module  
    Cx,          // Capability context module
    Cancel,      // Cancellation protocol module
    Obligation,  // Obligation tracking module
    Channel,     // Channel and messaging modules
    Io,          // I/O and networking modules
    Other,       // Other/unknown modules
}
```

### Cross-Module Rules

The system enforces three key cross-module patterns:

1. **Obligation-Cancel Ordering**: Obligation module locks should not be acquired while holding Cancel module locks
2. **Cx-Cancel Coordination**: Capability context operations must complete before cancellation  
3. **Runtime-Obligation Consistency**: Task scheduling must be coordinated with obligation tracking

## Usage

### Basic Usage (Automatic)

Existing `Mutex::with_name()` calls automatically benefit from enhanced enforcement:

```rust
let mutex = Mutex::with_name("obligation_tracker", data);
let guard = mutex.lock(&cx).await?; // Automatically enforced
```

### Enhanced API (Explicit)

For fine-grained control, use the `LockOrderEnforcer`:

```rust
use asupersync::sync::lock_ordering::{LockOrderEnforcer, LockRank, LockModule};

let enforcer = LockOrderEnforcer::with_module(
    "runtime_task_queue", 
    LockRank::Tasks, 
    LockModule::Runtime
);

enforcer.acquire(); // Check ordering and record acquisition
// ... critical section ...  
enforcer.release();  // Record release
```

## Implementation Details

### Module Detection

Module classification is automatic based on naming conventions:

- Names containing "runtime" or "scheduler" → `Runtime`
- Names containing "cx" or "scope" → `Cx`  
- Names containing "cancel" → `Cancel`
- Names containing "obligation" → `Obligation`
- etc.

### Thread-Local Tracking

Enhanced tracking uses two thread-local data structures:

```rust
static HELD_RANKS: RefCell<BTreeSet<LockRank>>;           // Basic rank tracking
static HELD_LOCKS: RefCell<BTreeMap<LockRank, Vec<LockInfo>>>; // Detailed lock info
```

### Performance

- **Debug builds**: Full enforcement with cross-module validation
- **Release builds**: Zero cost (all checks compiled away)

## Testing

The implementation includes comprehensive test coverage:

- Basic rank ordering preservation
- Cross-module pattern violations (should panic)
- Module detection accuracy  
- Integration with existing lock ordering system

Run tests with:
```bash
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_lock_ordering cargo test --lib cross_module_lock_ordering_test
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_lock_ordering cargo test --lib sync::lock_ordering
```

## Migration

Existing code continues to work without changes. The enhancement is backward compatible and only adds new capabilities.

For code that needs explicit cross-module coordination, consider using the `LockOrderEnforcer` API for clearer module identification and enhanced validation.

## Future Work

- Extend module classification for additional asupersync modules
- Add configuration for custom cross-module rules
- Integration with runtime monitoring and deadlock detection tools
- Performance profiling of enforcement overhead in debug builds
