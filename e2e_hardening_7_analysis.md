# E2E Hardening-7 Analysis: Hardcoded Paths and Test Runtime Consistency

## 🔍 ANALYSIS COMPLETE

### **HARDCODED PATHS: ✅ GOOD STATE**

**Summary**: E2E tests properly use TempDir patterns, no major hardcoded path conflicts found.

**Evidence**:
- All file operations use `TempDir::new()` and `temp_dir.path().join()` patterns
- Example in `real_fs_uring_raptorq_encoder_e2e_tests.rs`:
  ```rust
  async fn setup_test_environment() -> (TempDir, String) {
      let temp_dir = TempDir::new().expect("Failed to create temp directory");
      let base_path = temp_dir.path().to_string_lossy().to_string();
      (temp_dir, base_path)
  }
  ```
- No instances of hardcoded `/tmp/foo` or conflicting path literals found
- Environment variable checks are for build configuration, not file paths

**Conclusion**: ✅ **COMPLIANT** - No hardcoded path conflicts requiring fixes

---

### **TEST RUNTIME CONSISTENCY: ⚠️ MAJOR INCONSISTENCIES FOUND** 

**Critical Finding**: 111 `#[tokio::test]` instances across 21 E2E test files are inconsistent with asupersync runtime requirements.

## 📊 INCONSISTENCY BREAKDOWN

| File | tokio::test Count | Priority |
|------|-------------------|----------|
| `real_integration_scenarios_e2e_tests.rs` | 17 | HIGH |
| `real_tls_acceptor_http_h1_server_e2e_tests.rs` | 8 | HIGH |  
| `real_websocket_server_channel_broadcast_e2e_tests.rs` | 8 | HIGH |
| `real_service_e2e_tests.rs` | 7 | HIGH |
| `real_codec_e2e_tests.rs` | 6 | MEDIUM |
| `real_timer_extended_e2e_tests.rs` | 5 | MEDIUM |
| `real_fs_uring_e2e_tests.rs` | 5 | MEDIUM |
| `real_fs_e2e_tests.rs` | 5 | MEDIUM |
| `real_obligation_leak_check_e2e_tests.rs` | 5 | MEDIUM |
| 12 other files | 4-3 each | MEDIUM |
| **TOTAL** | **111 instances** | **21 files** |

## ✅ CORRECT PATTERN (Already Used in Some Files)

**Example**: `real_fs_uring_raptorq_encoder_e2e_tests.rs` uses the proper pattern:

```rust
#[test]
fn test_basic_file_to_raptorq_encoding() {
    crate::lab::runtime::block_on(async {
        let (_temp_dir, base_path) = setup_test_environment().await;
        let cx = Cx::root();
        
        // Async test logic here...
        
        Ok(())
    });
}
```

## ❌ INCORRECT PATTERN (Needs Fixing)

**Example**: `real_raptorq_e2e_tests.rs` uses inconsistent tokio runtime:

```rust
#[tokio::test]  // ← WRONG: Uses tokio runtime
#[ignore] // Requires REAL_SERVICE_TESTS=true  
async fn test_real_raptorq_basic_encode_decode() -> Result<(), Box<dyn std::error::Error>> {
    validate_raptorq_e2e_environment()?;
    
    let runtime = RuntimeBuilder::new().build()?;
    let cx_builder = CxBuilder::new(&runtime);
    let cx = cx_builder.build();
    
    // Test logic...
}
```

**Should be**:

```rust
#[test]
#[ignore] // Requires REAL_SERVICE_TESTS=true  
fn test_real_raptorq_basic_encode_decode() {
    crate::lab::runtime::block_on(async {
        validate_raptorq_e2e_environment().unwrap();
        
        let runtime = RuntimeBuilder::new().build().unwrap();
        let cx_builder = CxBuilder::new(&runtime);
        let cx = cx_builder.build();
        
        // Test logic...
        
        Ok::<(), Box<dyn std::error::Error>>(())
    }).unwrap();
}
```

## 🔧 SYSTEMATIC FIX PATTERN

### **Conversion Template**:

1. **Change function signature**:
   - `#[tokio::test]` → `#[test]`
   - `async fn test_name() -> Result<...>` → `fn test_name()`

2. **Wrap body in asupersync runtime**:
   ```rust
   #[test] 
   fn test_name() {
       crate::lab::runtime::block_on(async {
           // Original async test body here
           Ok::<(), ErrorType>(())
       }).unwrap();
   }
   ```

3. **Handle error propagation**:
   - Convert `?` to `.unwrap()` or `.expect()` for test setup
   - Wrap return type in `Ok::<(), ErrorType>(())` 
   - Add final `.unwrap()` to block_on call

## 🚨 IMPACT ANALYSIS

**Why This Matters**:
- **Runtime Consistency**: E2E tests should use the same async runtime as production code
- **Deterministic Testing**: asupersync lab runtime provides deterministic behavior vs tokio's non-deterministic scheduling
- **Architectural Compliance**: asupersync is designed to be tokio-free per AGENTS.md

**Risk Level**: MEDIUM  
- Tests may pass but use different scheduling/timing behavior than production
- Could mask runtime-specific bugs or race conditions
- Inconsistent with project's tokio-free architecture goal

## 📋 IMPLEMENTATION PHASES

### **Phase 1: High-Priority Files (17-8 instances)**
- `real_integration_scenarios_e2e_tests.rs` (17 instances) 
- `real_tls_acceptor_http_h1_server_e2e_tests.rs` (8 instances)
- `real_websocket_server_channel_broadcast_e2e_tests.rs` (8 instances)
- `real_service_e2e_tests.rs` (7 instances)

### **Phase 2: Medium-Priority Files (6-5 instances)**  
- `real_codec_e2e_tests.rs` (6 instances)
- 4 files with 5 instances each

### **Phase 3: Lower-Priority Files (4-3 instances)**
- 12 files with 3-4 instances each

## ✅ FILES ALREADY COMPLIANT 

**Good Examples** (Use proper `#[test]` + `block_on` pattern):
- `real_fs_uring_raptorq_encoder_e2e_tests.rs` ✅
- `real_distributed_e2e_tests.rs` ✅  
- `real_signal_graceful_shutdown_supervision_tree_e2e_tests.rs` ✅

## 🎯 RECOMMENDED ACTION

**For 60-minute timeline**: Create systematic fix task with template and phase plan.

**Conversion template established, examples provided, comprehensive audit complete.**
**Ready for systematic implementation across 111 instances in 21 files.**