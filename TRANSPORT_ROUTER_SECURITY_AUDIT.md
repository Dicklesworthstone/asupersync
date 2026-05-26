# Transport Router Security Audit Report

**Target:** `src/transport/router.rs` (2946 lines)  
**Methodology:** SaaS Security Audit Framework  
**Auditor:** SapphireHill  
**Date:** 2026-05-26  
**Scope:** Routing/Load-Balancer/Symbol-Dispatch Security  

## Executive Summary

**Critical:** 1 | **High:** 3 | **Medium:** 1 | **Low:** 0  
**Top Risk:** Hash ring salt vulnerable to targeted collision attacks enabling endpoint DoS

The routing infrastructure contains several high-severity vulnerabilities primarily around authentication bypasses, algorithmic complexity attacks, and information disclosure. The most critical finding is the hash ring salt generation which uses insufficient entropy against targeted collision attacks.

## CRITICAL Findings

### 1. Hash Ring Salt Collision Vulnerability
- **Location:** `LoadBalancer::new()` lines 737-739, `hash_ring_salt: u64` line 576  
- **Bead:** `asupersync-is96u6`
- **Attack Vector:** 
  1. Attacker observes routing behavior for different ObjectIds
  2. Uses differential analysis to narrow down possible salt values  
  3. Crafts colliding ObjectIds with 2^32 complexity (birthday paradox)
  4. Forces all traffic to single endpoint causing DoS
- **Impact:** Complete routing manipulation, targeted endpoint overload, service disruption
- **Fix:** Use cryptographically secure 256-bit salt from CSPRNG with proper domain separation

## HIGH Findings

### 1. Endpoint Removal Authorization Bypass  
- **Location:** `RoutingTable::remove_endpoint()` lines 593-615
- **Bead:** `asupersync-49wynd`
- **Attack Vector:** Any caller can invoke `remove_endpoint(id)` without authentication
- **Impact:** Immediate service disruption by draining healthy endpoints
- **Fix:** Require admin-level capability check before endpoint removal

### 2. Endpoint State Race Conditions
- **Location:** `Endpoint::set_state()` lines 178-180, `AtomicU8` with `Ordering::Relaxed`
- **Bead:** `asupersync-4p3xds` 
- **Attack Vector:**
  1. Rapidly toggle endpoint state Healthy ↔ Unhealthy  
  2. Race routing decisions with state changes
  3. Cause connection failures and routing instability
- **Impact:** DoS through routing table corruption, connection failures
- **Fix:** Use `Ordering::AcqRel` and add capability-based state change authorization

### 3. Routing Metrics Information Disclosure
- **Location:** `BoundedLoadDecision::log_fields()` lines 485-550
- **Bead:** `asupersync-36grbm`
- **Attack Vector:**
  1. Analyze detailed capacity/load metrics in logs
  2. Perform timing attacks based on routing decisions  
  3. Infer system architecture and attack surface
- **Impact:** Side-channel attacks, reconnaissance for targeted exploits
- **Fix:** Sanitize sensitive metrics, add log level controls, rate limit telemetry

## MEDIUM Findings

### 1. Capacity Overflow Routing Bypass
- **Location:** `BoundedLoadConfig::capacity_for()` lines 317-326
- **Bead:** `asupersync-qfgsh1`
- **Attack Vector:**
  1. Provide extreme endpoint weights near u32::MAX
  2. Trigger integer overflow in capacity calculations  
  3. Bypass load balancing protections
- **Impact:** Load balancing bypass, uneven traffic distribution
- **Fix:** Add input validation, fail safely on overflow conditions

## Positive Security Findings

✅ **AuthenticatedSymbol Integration** - Router properly accepts only authenticated symbols  
✅ **Connection Limiting** - RAII guards prevent connection leaks  
✅ **Cancellation Handling** - Proper context cancellation throughout dispatch  
✅ **Memory Leak Prevention** - Endpoint removal prevents Arc accumulation (br-asupersync-mboi13)

## Attack Scenario Analysis

### Scenario 1: Targeted Endpoint DoS
**Attacker Goal:** Overload specific endpoints to cause service degradation
1. **Hash Collision:** Exploit weak salt to craft colliding ObjectIds → force traffic to target endpoint
2. **State Manipulation:** Race condition endpoint health checks → cause routing instability  
3. **Capacity Bypass:** Overflow capacity calculations → bypass load balancing

**Severity:** CRITICAL - Can disable entire service regions

### Scenario 2: Routing Intelligence Gathering  
**Attacker Goal:** Reconnaissance for larger attack
1. **Metrics Analysis:** Parse routing decision logs → map system topology
2. **Timing Attacks:** Correlate routing latency with load → identify high-value endpoints
3. **State Inference:** Monitor endpoint state changes → predict maintenance windows

**Severity:** HIGH - Enables targeted follow-up attacks

## Deployment Context Assessment

**Current Risk Level:** HIGH  
- Project is an async runtime library used in production services
- Routing vulnerabilities directly impact availability and security
- Multi-tenant deployments amplify blast radius  
- Hash collision attacks are practical with moderate attacker capability

## Recommendations by Priority

### P0 (Ship-blocking)
1. **Hash Salt Hardening** - Implement 256-bit CSPRNG salt with domain separation
2. **Authorization Layer** - Add capability checks to endpoint management operations

### P1 (Next sprint)  
3. **Memory Ordering** - Upgrade endpoint state to `AcqRel` consistency
4. **Metrics Sanitization** - Remove sensitive data from routing telemetry

### P2 (Defense in depth)
5. **Input Validation** - Add bounds checking to capacity calculations
6. **Rate Limiting** - Throttle routing decision logging per endpoint

## Verification Requirements

- [ ] Hash collision resistance testing with 10^6 ObjectIds
- [ ] Authorization bypass testing on all endpoint operations  
- [ ] Race condition testing with concurrent state modifications
- [ ] Information leakage assessment of log outputs
- [ ] Capacity overflow fuzzing with extreme values

## References

- **Security Audit Framework:** security-audit-for-saas  
- **Threat Model:** Capability-based routing attacks, algorithmic complexity  
- **Standards:** NIST SP 800-57 (key management), RFC 7539 (CSPRNG)