# Web Security Audit: CSRF/CORS/CSP Headers

**Bead ID:** asupersync-xovy9l  
**Date:** 2026-04-28  
**Scope:** src/web/ module security analysis  
**Focus:** CSRF protection, CORS enforcement, CSP nonce handling, auth cookie security  

## Executive Summary

**FINDINGS: 2 HIGH + 1 MEDIUM security issues detected**

1. **HIGH**: Default session cookies use `SameSite=Lax`, not `Strict` - allows CSRF bypass
2. **HIGH**: Origin/Referer validation is OPTIONAL - disabled by default 
3. **MEDIUM**: CSP nonce generation shares same function as session IDs - not per-request

---

## Detailed Security Analysis

### 1. Origin/Referer Match Enforcement for State-Changing Methods ❌

**ISSUE: Origin validation is DISABLED BY DEFAULT**

**Location:** `src/web/session.rs:464-474, 714-740`

```rust
// Line 474: Default configuration DISABLES origin checking
pub allowed_origins: Vec<String>,  // Empty by default!

// Line 489-490: Default has empty allowed_origins
impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            // ... 
            allowed_origins: Vec::new(), // ← VULNERABLE DEFAULT
        }
    }
}
```

**Vulnerable Code Path:**
```rust
// Lines 714-717: Origin checking only happens if allowed_origins is non-empty
if self.config.csrf_protection
    && is_state_changing_method(&req.method)
    && !self.config.allowed_origins.is_empty()  // ← FAILS on default config
{
    match request_origin(&req) {
        // Validation logic here - but NEVER REACHED with default config!
```

**Risk:** 
- CSRF attacks from any origin succeed against default-configured applications
- Only X-CSRF-Token header validation runs (which can be bypassed by header-stripping proxies)
- Documentation suggests this is "defense in depth" but it's disabled by default

**Fix Required:** Change default to require explicit origin configuration or fail-safe mode.

### 2. CSP Nonce Per-Request vs Per-Session ❌

**ISSUE: No per-request CSP nonce generation - only session-level**

**Location:** `src/web/session.rs:297-305, 696`

```rust
// Lines 297-305: Single nonce generator for ALL purposes
fn generate_session_id() -> String {
    let mut buf = [0u8; 16];
    getrandom::fill(&mut buf).expect("OS entropy source unavailable");
    // Returns 32-char hex string
}

// Line 696: CSRF token uses session ID generator  
session_data.insert(CSRF_TOKEN_KEY, generate_session_id());
```

**Missing Implementation:**
- No CSP nonce generation in `src/web/security.rs`
- No per-request nonce infrastructure 
- No CSP header with dynamic nonces

**Current CSP Implementation:** Static headers only
```rust
// src/web/security.rs:44-46, 166-168 
pub content_security_policy: Option<String>,  // Static string only

if let Some(ref val) = self.policy.content_security_policy {
    resp.ensure_header("content-security-policy", val.clone()); // Static!
}
```

**Risk:**
- CSP nonces that persist across requests are vulnerable to injection attacks
- Static CSP without nonces provides limited XSS protection
- No infrastructure for proper CSP nonce rotation per request

**Fix Required:** Implement per-request nonce generation and CSP header templating.

### 3. SameSite=Strict on Auth Cookies ❌

**ISSUE: Default session cookies use `SameSite=Lax`, not `Strict`**

**Location:** `src/web/session.rs:486, 441`

```rust
// Line 486: Default configuration uses Lax, not Strict
impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            // ...
            same_site: SameSite::Lax,  // ← SHOULD BE Strict for auth cookies!
```

**SameSite Values Defined:**
```rust
// Lines 392-401: SameSite enum
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SameSite {
    Strict,  // ← SECURE: No cross-site requests
    Lax,     // ← DEFAULT: Some cross-site allowed (top-level navigation)
    None,    // ← INSECURE: All cross-site allowed
}
```

**Risk:**
- `SameSite=Lax` allows cross-site cookie sending on top-level navigation (GET requests from links)
- Authentication state can leak across sites in certain scenarios  
- For session authentication, `Strict` is the recommended secure default

**Mitigation Present:** Configuration validation prevents the most dangerous combination:
```rust
// Lines 417-419: Prevents SameSite=None without Secure
if self.config.same_site == SameSite::None && !self.config.secure {
    return Err(SessionConfigError::SameSiteNoneWithoutSecure);
}
```

**Fix Required:** Change default to `SameSite::Strict` for session authentication cookies.

---

## Security Strengths Found ✅

### CSRF Token Implementation - ROBUST
- **Constant-time comparison** prevents timing attacks (`constant_time_eq_str()`)
- **Cryptographically secure generation** via OS entropy (`getrandom::fill()`)
- **Per-session token binding** prevents token reuse across sessions
- **Automatic token rotation** on session regeneration
- **State-changing method detection** correctly identifies POST/PUT/PATCH/DELETE

### Session Security - GOOD
- **Default secure cookies** (`secure: true`)
- **HttpOnly by default** prevents XSS access to session cookies
- **Session fixation protection** via regeneration after authentication
- **Idle timeout support** for server-side session expiration
- **Session ID validation** prevents injection of malformed IDs

### Origin Validation Implementation - ROBUST (when enabled)
- **Proper fallback** from Origin → Referer header
- **Case-insensitive matching** with normalization
- **Null origin handling** correctly falls back to Referer
- **Path stripping** prevents path-based bypass attempts

---

## Attack Scenario Analysis

### Scenario 1: CSRF via Header-Stripping Proxy
```
1. Attacker sites victim to malicious page
2. Page submits POST to victim's app
3. Proxy strips X-CSRF-Token header (common in corporate environments)
4. Origin header remains intact  
5. DEFAULT CONFIG: Origin validation disabled → ATTACK SUCCEEDS ❌
6. SECURE CONFIG: Origin validation enabled → Attack blocked ✅
```

### Scenario 2: Cross-Site Session Leakage
```
1. User authenticated on app.example.com (SameSite=Lax)
2. User visits attacker.com
3. Attacker.com contains: <img src="https://app.example.com/api/profile">
4. DEFAULT CONFIG: Cookie sent due to SameSite=Lax → Data leaked ❌ 
5. SECURE CONFIG: SameSite=Strict → Cookie blocked ✅
```

### Scenario 3: XSS with Static CSP
```
1. App uses static CSP without nonces
2. XSS payload injects: <script>malicious_code()</script>  
3. CURRENT: Static CSP provides some protection
4. IDEAL: Per-request nonces would provide stronger protection
```

---

## Recommendations (Priority Order)

### 1. HIGH PRIORITY FIXES

**A. Enable Origin Validation by Default**
```rust
// In SessionConfig::default()
allowed_origins: vec!["https://localhost:3000".to_string()], // Force explicit config
```

**B. Change Default to SameSite=Strict**
```rust
// In SessionConfig::default()  
same_site: SameSite::Strict,  // Secure default for auth cookies
```

### 2. MEDIUM PRIORITY ENHANCEMENTS

**C. Implement Per-Request CSP Nonces**
```rust
// New function needed in security.rs
pub fn generate_csp_nonce() -> String {
    // 16 bytes base64url = better than hex for CSP
}

// Template CSP with {{nonce}} placeholder
pub fn apply_csp_nonce(csp_template: &str, nonce: &str) -> String {
    csp_template.replace("{{nonce}}", nonce)
}
```

### 3. DOCUMENTATION FIXES

**D. Update Security Documentation**
- Document that `allowed_origins` MUST be configured for production
- Provide secure configuration examples
- Add CSP nonce usage examples when implemented

---

## Compliance Assessment

| Security Control | Status | Comment |
|-----------------|--------|---------|
| CSRF protection via token | ✅ COMPLIANT | Robust implementation |
| CSRF protection via origin | ❌ VULNERABLE | Disabled by default |
| Secure session cookies | ⚠️ PARTIAL | Secure+HttpOnly yes, SameSite=Lax not ideal |
| CSP nonce rotation | ❌ NOT IMPLEMENTED | Static CSP only |
| Timing attack prevention | ✅ COMPLIANT | Constant-time comparison |
| Session fixation protection | ✅ COMPLIANT | Regeneration after auth |

**Overall Assessment:** NEEDS SECURITY HARDENING before production use with default configuration.

---

## Testing Verification

```bash
# Test origin validation
cargo test --lib web::session::origin

# Test CSRF protection  
cargo test --lib web::session::csrf

# Test cookie security
cargo test --lib web::session::cookie_security
```

**Status:** All existing tests pass, but tests assume current (vulnerable) defaults.