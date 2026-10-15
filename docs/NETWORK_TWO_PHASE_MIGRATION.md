# Network Operations Two-Phase Effect Migration Guide

This document outlines the migration required to fix the runtime invariant violation where network operations bypass the required two-phase reserve/commit pattern.

## Problem Summary

**Issue**: asupersync-7hk6fr - Network operations violate two-phase effect pattern (runtime invariant)

**Root Cause**: Network send operations in ATP streams use direct send patterns instead of the required two-phase reserve/commit pattern, violating the asupersync runtime's cancel-safety invariant.

## Files Requiring Updates

### 1. `src/net/atp/h3/stream.rs`

**Current Problematic Code:**
```rust
impl AtpH3Stream {
    pub fn send(&mut self, data: &[u8]) -> AtpH3Result<()> {
        // Direct send - NOT cancel-safe
        if !self.can_send() {
            return Err(AtpH3Error::Stream(format!(
                "Cannot send on stream {} in state {:?}",
                self.stream_id, self.state
            )));
        }

        if self.send_queue.len() >= self.send_queue_high_water {
            return Err(AtpH3Error::Stream("Send queue full".to_string()));
        }

        self.send_queue.push_back(data.to_vec()); // PROBLEM: Direct queue modification
        Ok(())
    }
}
```

**Required Fix:**
```rust
use crate::runtime::effects::SendPermit;

impl AtpH3Stream {
    /// Add reserved_sends field to struct
    // reserved_sends: usize, // Add to struct definition

    /// Reserve space for a send operation (Phase 1).
    pub async fn reserve_send(&mut self) -> Result<SendPermit<AtpH3Error>, AtpH3Error> {
        if !self.can_send() {
            return Err(AtpH3Error::Stream(format!(
                "Cannot send on stream {} in state {:?}",
                self.stream_id, self.state
            )));
        }

        let total_pending = self.send_queue.len() + self.reserved_sends;
        if total_pending >= self.send_queue_high_water {
            return Err(AtpH3Error::Stream("Send queue full".to_string()));
        }

        self.reserved_sends += 1;

        // Create permit with commit and abort callbacks
        let send_queue_ptr = &mut self.send_queue as *mut VecDeque<Vec<u8>>;
        let reserved_sends_ptr = &mut self.reserved_sends as *mut usize;
        let max_buffer_size = self.max_buffer_size;

        Ok(SendPermit::new(
            move |data: &[u8]| -> Result<(), AtpH3Error> {
                if data.len() > max_buffer_size {
                    unsafe { *reserved_sends_ptr -= 1; }
                    return Err(AtpH3Error::Stream(format!(
                        "Data size {} exceeds maximum {}",
                        data.len(), max_buffer_size
                    )));
                }

                unsafe {
                    (*send_queue_ptr).push_back(data.to_vec());
                    *reserved_sends_ptr -= 1;
                }
                Ok(())
            },
            move || {
                unsafe { *reserved_sends_ptr -= 1; }
            }
        ))
    }

    // Remove or deprecate the old send() method
}
```

### 2. `src/net/atp/h3/session.rs`

**Update session send calls:**
```rust
// OLD:
pub fn send_stream_data(&mut self, stream_id: u64, data: &[u8]) -> AtpH3Result<()> {
    let stream = self.streams.get_mut(&stream_id)
        .ok_or_else(|| AtpH3Error::Stream(format!("Stream {} not found", stream_id)))?;
    
    stream.send(data)?; // PROBLEM: Direct send
    Ok(())
}

// NEW:
pub async fn send_stream_data(&mut self, stream_id: u64, data: &[u8]) -> AtpH3Result<()> {
    let stream = self.streams.get_mut(&stream_id)
        .ok_or_else(|| AtpH3Error::Stream(format!("Stream {} not found", stream_id)))?;
    
    let permit = stream.reserve_send().await?;
    permit.commit(data)?;
    Ok(())
}
```

### 3. `src/atp/sdk.rs`

**Update sink operations:**
```rust
// OLD:
impl AtpSink {
    pub async fn send(&mut self, cx: &Cx, data: &[u8]) -> AtpResult<()> {
        // Direct send operation
        self.stream.send(data).await
    }
}

// NEW:
impl AtpSink {
    pub async fn send(&mut self, cx: &Cx, data: &[u8]) -> AtpResult<()> {
        let permit = self.stream.reserve_send().await?;
        permit.commit(data)
    }
}
```

### 4. `src/atp/writer.rs`

**Update writer send operations:**
```rust
// Similar pattern - replace direct sends with reserve/commit
```

### 5. `src/net/atp/sdk/stream.rs`

**Update streaming operations:**
```rust
// Replace all direct send operations with two-phase pattern
```

## Implementation Steps

### Phase 1: Create Two-Phase Infrastructure ✅

- [x] Create `src/runtime/effects/` module
- [x] Implement `SendPermit` for two-phase commits
- [x] Create network effect patterns and adapters
- [x] Provide reference implementation (`TwoPhasedAtpStream`)

### Phase 2: Migrate Core Network Streams

1. **Update ATP H3 Stream** (`src/net/atp/h3/stream.rs`):
   - Add `reserved_sends: usize` field to `AtpH3Stream`
   - Replace `send()` method with `reserve_send()` -> `SendPermit`
   - Update capacity checks to include reserved slots

2. **Update ATP H3 Session** (`src/net/atp/h3/session.rs`):
   - Change `send_stream_data()` to async and use two-phase pattern
   - Update all callers to handle async nature

3. **Update ATP SDK** (`src/atp/sdk.rs`, `src/atp/writer.rs`):
   - Replace direct sink sends with two-phase pattern
   - Ensure proper permit management in async contexts

4. **Update ATP Streaming** (`src/net/atp/sdk/stream.rs`):
   - Convert all stream send operations to two-phase

### Phase 3: Update Tests and Documentation

1. **Fix Tests**:
   - Update all network operation tests to use new two-phase API
   - Add specific tests for cancel-safety scenarios
   - Verify proper cleanup on cancellation

2. **Update Documentation**:
   - Document new two-phase network operation patterns
   - Provide migration examples
   - Update API documentation

## Testing Strategy

### Cancel-Safety Tests
```rust
#[test]
async fn test_send_cancellation_cleanup() {
    let mut stream = AtpH3Stream::new(42, StreamDirection::Bidirectional);
    
    // Reserve send slot
    let permit = stream.reserve_send().await.unwrap();
    assert_eq!(stream.reserved_sends(), 1);
    
    // Drop permit without committing (simulates cancellation)
    drop(permit);
    
    // Verify reservation is cleaned up
    assert_eq!(stream.reserved_sends(), 0);
    assert_eq!(stream.send_queue_len(), 0);
}
```

### Backpressure Tests
```rust
#[test]
async fn test_backpressure_with_reservations() {
    let mut stream = AtpH3Stream::new(42, StreamDirection::Bidirectional);
    stream.send_queue_high_water = 2;
    
    // Fill capacity with reservations
    let permit1 = stream.reserve_send().await.unwrap();
    let permit2 = stream.reserve_send().await.unwrap();
    
    // Third reservation should fail
    assert!(stream.reserve_send().await.is_err());
    
    // After commit, space should be available again
    permit1.commit(b"data").unwrap();
    assert!(stream.reserve_send().await.is_ok());
}
```

## Migration Validation

### Compile-time Checks
- All network send operations must use the `SendPermit` pattern
- Remove or deprecate direct send methods

### Runtime Validation
- Add debug assertions to verify no direct queue modifications
- Implement metrics for permit usage and cleanup

### Performance Impact
- The two-phase pattern adds minimal overhead (one atomic increment/decrement)
- Proper permit pooling can further reduce allocation overhead

## Reference Implementation

See `src/runtime/effects/atp_stream_example.rs` for a complete working example of how the ATP stream should be implemented with proper two-phase effects.

## Benefits After Migration

1. **Cancel-Safety**: Network operations properly handle cancellation without data loss
2. **Resource Tracking**: Proper accounting of pending operations for backpressure
3. **Runtime Invariant Compliance**: Network operations follow the same patterns as other asupersync effects
4. **Debuggability**: Clear separation between reservation and commitment phases

## Breaking Changes

- `AtpH3Stream::send()` becomes async and returns `Result<SendPermit<_>, _>`
- Network operation callers must handle the two-phase pattern
- Some test APIs may need updates for async usage

This migration ensures that network operations follow the asupersync runtime's core cancel-safety invariant and integrate properly with structured concurrency.