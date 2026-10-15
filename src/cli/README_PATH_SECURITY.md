# CLI Path Security Implementation

## Overview

This document describes the path traversal security fixes implemented in the CLI module to prevent directory traversal attacks (CWE-22).

## Security Issue

The original CLI implementation was vulnerable to path traversal attacks because it directly used user-supplied paths without validation. An attacker could supply paths like `../../etc/passwd` to read/write files outside the intended directories.

## Solution

We've implemented a centralized path validation system using `crate::util::path_security::SecurePath` that:

1. **Canonicalizes paths** to resolve ".." and "." components
2. **Validates boundaries** to ensure paths stay within allowed directories
3. **Provides secure wrappers** for common file operations
4. **Logs security events** for monitoring and auditing

## Implementation Details

### Core Components

- **`SecurePath`**: Main validator that constrains paths to a base directory
- **`ValidatedPath`**: Type-safe wrapper for paths that have been validated
- **`PathSecurityError`**: Comprehensive error types for security violations

### Updated Functions

#### Configuration Management (`atp_config.rs`)

- **`AtpInstallConfig::read_from_file_secure()`**: Secure config file reading
- **`AtpInstallConfig::write_to_file_secure()`**: Secure config file writing
- **Backward compatibility**: Original functions preserved, call secure variants

#### Workflow Operations (`atp_workflows.rs`)

- **`ci_push()`**: Validates artifact paths against current working directory
- **Path validation**: All user-supplied artifact paths are checked before reading

### Usage Examples

#### Reading Configuration Files

```rust
// Secure way (recommended)
let config = AtpInstallConfig::read_from_file_secure(
    &user_path,
    Some(&secure_base_dir)  // Constrains to this directory
)?;

// Legacy way (logs warning)
let config = AtpInstallConfig::read_from_file(&user_path)?;
```

#### Validating User-Supplied Paths

```rust
use crate::util::path_security::SecurePath;

// Create validator for working directory
let secure_path = SecurePath::new(&current_dir)?;

// Validate each user path
for user_path in user_supplied_paths {
    let validated = secure_path.validate_path(&user_path)?;
    // Use validated.as_path() for file operations
    let content = fs::read(validated.as_path())?;
}
```

#### Error Handling

```rust
match result {
    Err(PathSecurityError::PathTraversalAttempt { path }) => {
        // Log security incident
        tracing::warn!("Path traversal attack attempted: {}", path);
        return Err(CliError::security_violation());
    }
    Err(PathSecurityError::OutsideAllowedBounds { path, allowed_base }) => {
        // Path escapes boundaries
        tracing::error!("Path outside bounds: {} not within {}", path, allowed_base);
    }
    // ... handle other errors
}
```

## Security Properties

### What's Protected

✅ **Directory traversal attacks** (`../../../etc/passwd`)
✅ **Null byte injection** (`file.txt\0.exe`)
✅ **Symbolic link attacks** (automatic canonicalization)
✅ **Empty/malformed paths**
✅ **Absolute path escapes** when relative paths expected

### What's NOT Protected

❌ **Application logic bugs** (using wrong base directory)
❌ **Race conditions** (TOCTOU between validation and use)
❌ **Privilege escalation** (running as root)
❌ **Network-based attacks** (this only validates local paths)

## Security Guidelines

### For Developers

1. **Always use secure variants** when handling user-supplied paths
2. **Choose appropriate base directories** - don't use `/` as base!
3. **Log security violations** for monitoring
4. **Test with malicious inputs** - include `../` in your test cases
5. **Review path concatenation** - prefer `SecurePath.validate_path()`

### Base Directory Selection

```rust
// ✅ GOOD: Specific working directory
let base = current_dir()?;
let base = home_dir()?.join(".config/app");

// ❌ BAD: Too permissive
let base = Path::new("/");
let base = Path::new("/tmp");

// ❌ BAD: User-controlled base
let base = Path::new(&user_supplied_base);
```

### Testing Malicious Inputs

```rust
#[test]
fn test_path_traversal_protection() {
    let secure_path = SecurePath::new("/safe/dir").unwrap();
    
    // These should all fail
    assert!(secure_path.validate_path("../../../etc/passwd").is_err());
    assert!(secure_path.validate_path("/etc/passwd").is_err());
    assert!(secure_path.validate_path("file\0.txt").is_err());
    assert!(secure_path.validate_path("").is_err());
    
    // This should succeed
    assert!(secure_path.validate_path("safe/file.txt").is_ok());
}
```

## Implementation Status

### Verified Coverage
- `atp_config.rs` - Configuration file I/O
- `atp_workflows.rs` - CI artifact reading
- `path_security.rs` - Core validation utilities
- Error types and logging

### Tracked Coverage Ledger

All CLI path-security expansion is tracked through `asupersync-to7e65.16` and its child
proof beads. Each coverage row must name the CLI surface, the expected validation
primitive, the malicious payload class, and the proof command before the row can be
marked complete.

| Selector | Surface | Required proof |
|----------|---------|----------------|
| `CLI-PATH-UPGRADE-BACKUP-RESTORE` | `upgrade.rs` backup/restore file operations | Malicious relative and absolute-path payloads are rejected before any backup or restore I/O begins. |
| `CLI-PATH-ARGS-PATHBUF` | CLI argument structs with `PathBuf` fields | Every user-controlled path is routed through `SecurePath` or an equivalent typed validator. |
| `CLI-PATH-BASE-DIR-POLICY` | Base-directory selection for config, artifacts, and upgrade state | Tests demonstrate that user-controlled bases cannot widen the allowed filesystem boundary. |
| `CLI-PATH-MALICIOUS-E2E` | CLI integration harnesses | E2E logs include selector id, command, exit status, rejected payload, artifact path, and failure detail. |

## Performance Impact

- **Minimal overhead**: Path canonicalization is fast (syscall + string ops)
- **Memory efficient**: No large allocations, paths reused
- **Caching opportunity**: Base directory validation can be cached

## Monitoring and Alerts

All security violations are logged with `tracing::warn!` and include:
- Original user-supplied path
- Security violation type
- Timestamp and request context

Consider setting up alerts for:
- `PathTraversalAttempt` - Active attack
- `OutsideAllowedBounds` - Policy violation
- High frequency of security errors

## References

- **CWE-22**: Path Traversal
- **OWASP Path Traversal**: https://owasp.org/www-community/attacks/Path_Traversal
- **Rust Security Guidelines**: https://anssi-fr.github.io/rust-guide/
