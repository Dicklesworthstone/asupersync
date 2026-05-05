# CRITICAL: MySQL SSL Authentication Bypass Vulnerability

**Date:** 2026-04-28  
**Auditor:** SapphireHill (security-audit-for-saas skill)  
**Scope:** src/database/mysql.rs authentication handshake  
**Followup to:** trtkxb (previous security fix)

## CRITICAL FINDING: Inverted SSL Requirement Check

**Location:** `src/database/mysql.rs:1499-1501`

**Current Code (VULNERABLE):**
```rust
if options.ssl_mode == SslMode::Required {
    return Outcome::Err(MySqlError::TlsRequired);
}
```

**Issue:** The SSL requirement check is inverted. When users explicitly configure `ssl_mode=Required`, the connection **FAILS** instead of establishing SSL.

**Attack Vector:**
1. Application configures `mysql://user:pass@host/db?ssl-mode=required`
2. Code reads SSL mode correctly
3. **Handshake check FAILS when SSL is required** (lines 1499-1501)
4. Connection either terminates or falls back to plaintext

**Impact:** Complete authentication bypass - credentials transmitted in cleartext despite explicit SSL requirement.

## Additional Security Gaps

1. **Missing SSL Implementation** - No actual SSL/TLS connection establishment code exists
2. **Capability Gap** - `CLIENT_SSL` flag never included in client capabilities (lines 1700-1717)  
3. **Incomplete Modes** - `SslMode::Preferred` configuration parsed but never implemented

## Immediate Actions Required

1. **HALT** all production MySQL connections with `ssl_mode=Required`
2. Fix inverted logic in lines 1499-1501
3. Implement proper MySQL SSL Request packet sequence
4. Add `CLIENT_SSL` to capability negotiation when SSL enabled
5. Implement `SslMode::Preferred` logic
6. Add integration tests for all SSL modes

## Risk Assessment

**Severity:** CRITICAL  
**CVSS:** High (credential exposure in security-conscious deployments)  
**Affected:** All applications using MySqlConnectOptions with ssl_mode=Required