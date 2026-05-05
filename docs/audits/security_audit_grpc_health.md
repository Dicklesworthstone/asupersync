# gRPC Health Protocol Security Audit

**Bead:** asupersync-n7w3l1  
**Date:** 2026-04-28  
**Auditor:** SapphireHill  
**Files:** src/grpc/health.rs

## Executive Summary

Security audit of gRPC Health Checking Protocol implementation identified **3 CRITICAL vulnerabilities** that completely compromise the health checking functionality and expose sensitive operational data to unauthorized access.

## Findings

### 1. CRITICAL - Health Check Endpoint Completely Disabled

**Location:** `src/grpc/health.rs:425-436` (`check` method)

**Issue:** The main health check endpoint unconditionally returns an authentication error, making the entire health check functionality unusable. This appears to be an overly aggressive security "fix" that breaks legitimate functionality.

**Code:**
```rust
pub fn check(&self, request: &HealthCheckRequest) -> Result<HealthCheckResponse, Status> {
    // Security fix (br-asupersync-n7w3l1): Health check endpoints must require authentication.
    return Err(Status::unauthenticated(
        "health check endpoint requires authentication",
    ));

    #[allow(unreachable_code)]
    let statuses = self.statuses.read();
    // ... rest of implementation is unreachable
}
```

**Attack Vector:** Legitimate health probes (load balancers, orchestrators) cannot function, breaking service discovery and causing cascading availability issues.

**Impact:** Complete denial of service for health checking functionality

**Fix Required:** Implement proper authentication that allows authorized health probes while blocking unauthorized access.

### 2. CRITICAL - Inconsistent Authentication Enforcement

**Location:** Multiple methods show inconsistent auth patterns

**Issue:** Authentication is enforced differently across methods:
- `check()`: Always fails (lines 425-436) 
- `check_async()`: Requires "authorization" header (lines 484-487)
- `watch_async()`: Requires "authorization" header (lines 505-507)

**Code Inconsistencies:**
```rust
// check_async() - Header-based auth
if request.metadata().get("authorization").is_none() {
    let error = Status::unauthenticated("health check endpoint requires authentication");
    return Box::pin(async move { Err(error) });
}

// watch_async() - Same header-based auth  
if request.metadata().get("authorization").is_none() {
    let error = Status::unauthenticated("health check endpoint requires authentication");
    return Box::pin(async move { Err(error) });
}
```

**Attack Vector:** 
1. Bypass via different endpoints with inconsistent auth
2. Simple header injection `authorization: anything` bypasses checks (no validation)

**Impact:** Authentication bypass, unauthorized access to health data

### 3. HIGH - Information Disclosure via Service Status Enumeration

**Location:** `src/grpc/health.rs:459-472`

**Issue:** While the error message has been sanitized to not echo service names (good), the Ok/Err discriminator still allows service enumeration attacks.

**Code:**
```rust
} else {
    drop(statuses);
    // Canonical NotFound — do NOT echo the queried service name back
    // to the caller (br-asupersync-doa4lv). The original error
    // message included the requested service name, which let an
    // attacker probe-and-confirm...
    Err(Status::not_found(
        "service not registered for health checking",
    ))
}
```

**Attack Vector:** 
1. Attacker can probe service names: `Ok(ServingStatus)` vs `Err(NotFound)`
2. This reveals which services exist, their health status, and internal topology
3. Can be automated to map entire service architecture

**Impact:** Service discovery enumeration, topology disclosure, operational intelligence gathering

## Severity Assessment

| Finding | Severity | CVSS | Exploitability | Impact |
|---------|----------|------|---------------|--------|
| Health Check Disabled | CRITICAL | 9.0 | N/A | Critical |
| Inconsistent Auth | CRITICAL | 8.5 | High | High |  
| Service Enumeration | HIGH | 6.8 | Medium | Medium |

## Recommended Fixes

### Fix 1: Implement Proper Authentication

Replace the blanket authentication failure with a configurable auth mechanism:

```rust
/// Authentication configuration for health checks
#[derive(Debug, Clone)]
pub enum HealthAuthMode {
    /// No authentication required (for internal networks)
    None,
    /// Require valid authorization header
    RequireAuth,
    /// Custom authentication validator
    Custom(Arc<dyn Fn(&HealthCheckRequest) -> Result<(), Status> + Send + Sync>),
}

impl HealthService {
    pub fn new_with_auth(auth_mode: HealthAuthMode) -> Self {
        // ... implementation
    }

    fn validate_auth(&self, request: &HealthCheckRequest) -> Result<(), Status> {
        match &self.auth_mode {
            HealthAuthMode::None => Ok(()),
            HealthAuthMode::RequireAuth => {
                // Validate actual token content, not just presence
                self.validate_bearer_token(request)
            }
            HealthAuthMode::Custom(validator) => validator(request),
        }
    }

    pub fn check(&self, request: &HealthCheckRequest) -> Result<HealthCheckResponse, Status> {
        self.validate_auth(request)?;
        
        let statuses = self.statuses.read();
        // ... rest of existing implementation
    }
}
```

### Fix 2: Strengthen Authentication Validation

```rust
fn validate_bearer_token(&self, request: &HealthCheckRequest) -> Result<(), Status> {
    // Extract from request metadata in actual gRPC context
    // This is a simplified example - in real implementation would extract from gRPC metadata
    let auth_header = request.metadata().get("authorization")
        .ok_or_else(|| Status::unauthenticated("missing authorization header"))?;
    
    let token = auth_header.to_str()
        .map_err(|_| Status::unauthenticated("invalid authorization header"))?
        .strip_prefix("Bearer ")
        .ok_or_else(|| Status::unauthenticated("invalid authorization format"))?;
    
    // Validate token against your auth system
    if !self.token_validator.validate(token) {
        return Err(Status::unauthenticated("invalid token"));
    }
    
    Ok(())
}
```

### Fix 3: Mitigate Service Enumeration

```rust
pub fn check(&self, request: &HealthCheckRequest) -> Result<HealthCheckResponse, Status> {
    self.validate_auth(request)?;
    
    let statuses = self.statuses.read();

    if let Some(&status) = statuses.get(&request.service) {
        drop(statuses);
        Ok(HealthCheckResponse::new(status))
    } else if request.service.is_empty() {
        // Server health aggregation logic...
    } else {
        drop(statuses);
        
        // Security: Return generic error without revealing whether service exists
        // This prevents service enumeration but still returns standard gRPC error codes
        Err(Status::permission_denied(
            "access denied for health check query"
        ))
    }
}
```

## Alternative: Rate-Limited Enumeration Protection

If returning `NotFound` for missing services is required by the gRPC health spec:

```rust
// Add rate limiting per client to prevent bulk enumeration
fn check_rate_limit(&self, client_id: &str) -> Result<(), Status> {
    // Implementation would track requests per client and block excessive probing
    if self.rate_limiter.is_exceeded(client_id) {
        return Err(Status::resource_exhausted("rate limit exceeded"));
    }
    Ok(())
}
```

## Testing Requirements

1. **Authentication tests**: Verify proper token validation and rejection of invalid tokens
2. **Authorization tests**: Ensure only authorized clients can access health endpoints  
3. **Enumeration tests**: Verify service discovery attacks are prevented or rate-limited
4. **Integration tests**: Confirm legitimate health probes (K8s, load balancers) still work

## References

- [gRPC Health Checking Protocol](https://github.com/grpc/grpc-proto/blob/main/grpc/health/v1/health.proto)
- [OWASP Information Disclosure](https://owasp.org/www-community/Improper_Error_Handling)
- [gRPC Authentication Guide](https://grpc.io/docs/guides/auth/)