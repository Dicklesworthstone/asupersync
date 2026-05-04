# Redis Pub/Sub Connection Drop Audit

## Finding: DEFECT - Error to Caller (Poor UX)

**Status:** Connection drops cause poisoned state requiring manual reconnection  
**Expected:** Transparent auto-reconnection with subscription restoration  
**Actual:** Errors returned to caller until manual `reconnect()` called  

## Evidence

### Current Implementation
- `ensure_live()` at line 2950 fails when `poisoned = true`
- `reconnect()` at line 3437 requires manual invocation
- `RedisPubSub` tracks subscriptions in `channels`/`patterns` but only restores on explicit call
- All operations (`next_event()`, `subscribe()`, etc.) check `ensure_live()` first

### Root Cause
Missing automatic reconnection logic. Connection state management exists but requires caller intervention.

### Impact
- Poor developer experience - callers must handle connection management
- Not Redis client best practice (should be transparent)
- Potential message loss if caller doesn't handle reconnection promptly

## Recommended Fix

Implement transparent auto-reconnection in `next_event()` and other operations:

1. Detect connection failure
2. Auto-call `reconnect()` internally  
3. Restore tracked subscriptions
4. Continue operation seamlessly
5. Optionally surface connection events for observability

## Test Coverage Needed

```rust
#[test] 
fn audit_transparent_reconnection_on_connection_drop() {
    // Verify next_event() auto-reconnects without caller intervention
    // when underlying connection drops mid-stream
}
```

**Classification:** UX Defect - Burdens caller with connection state management