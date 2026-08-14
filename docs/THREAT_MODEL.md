# Asupersync Threat Model

## Overview

This document describes the security architecture, threat model, and mitigations for the Asupersync async runtime. It covers TLS, HTTP/2, WebSocket, gRPC, and the Phase 0 authentication system.

**Document Version:** 1.0
**Last Updated:** 2026-02-01
**Status:** Phase 0 (Testing/Simulation)

## Table of Contents

1. [Security Boundaries](#security-boundaries)
2. [Threat Categories](#threat-categories)
3. [Component Analysis](#component-analysis)
4. [Threat Matrix](#threat-matrix)
5. [Mitigations](#mitigations)
6. [Recommendations](#recommendations)

---

## Security Boundaries

### Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│                      TRUSTED ZONE                            │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              Asupersync Runtime                      │    │
│  │  ┌───────────┐  ┌───────────┐  ┌───────────┐        │    │
│  │  │   TLS     │  │  HTTP/2   │  │  gRPC     │        │    │
│  │  │  (rustls) │  │  Codec    │  │  Server   │        │    │
│  │  └───────────┘  └───────────┘  └───────────┘        │    │
│  │  ┌───────────┐  ┌───────────┐  ┌───────────┐        │    │
│  │  │ WebSocket │  │  DNS      │  │ Security  │        │    │
│  │  │  Codec    │  │ Resolver  │  │ Context   │        │    │
│  │  └───────────┘  └───────────┘  └───────────┘        │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
                              │
                    ┌─────────▼─────────┐
                    │  UNTRUSTED ZONE   │
                    │  - Network I/O    │
                    │  - External DNS   │
                    │  - Remote Peers   │
                    └───────────────────┘
```

### Security Assumptions

| Assumption | Scope | Notes |
|------------|-------|-------|
| TLS certificate validation | All network I/O | Delegated to rustls |
| Memory safety | All Rust code | No `unsafe` except reactors |
| Cryptographic primitives | TLS operations | ring crate (audited) |
| Phase 0 auth | Symbol verification | NOT cryptographic (intentional) |

---

## Threat Categories

### STRIDE Analysis

| Category | Threat | Applies To |
|----------|--------|------------|
| **S**poofing | Identity impersonation | gRPC auth, TLS certs |
| **T**ampering | Data modification | HTTP/2 frames, WebSocket |
| **R**epudiation | Action denial | (Not in scope for Phase 0) |
| **I**nformation Disclosure | Data leakage | TLS cleartext, metadata |
| **D**enial of Service | Resource exhaustion | All protocols |
| **E**levation of Privilege | Auth bypass | gRPC interceptors |

---

## Component Analysis

### 1. TLS Implementation (src/tls/)

**Threat Surface:**
- Certificate validation bypass
- MITM attacks
- Downgrade attacks

**Security Controls:**
```rust
// Certificate validation via rustls
TlsConnector::builder()
    .with_webpki_roots()  // Mozilla CA bundle
    .alpn_http2()         // Protocol negotiation
    .with_handshake_timeout(Duration::from_secs(10))
```

**Mitigations:**
- SNI validation mandatory
- ALPN negotiation supported
- Certificate pinning available via `CertificatePinSet`
- Handshake timeout prevents resource exhaustion

### 2. HTTP/2 Stack (src/http/h2/)

**Threat Surface:**
- Stream exhaustion
- Header compression bombs (HPACK)
- CONTINUATION frame DoS
- Flow control bypass

**Security Controls:**
```rust
// Connection settings limits
pub const DEFAULT_MAX_CONCURRENT_STREAMS: u32 = 256;
pub const DEFAULT_MAX_HEADER_LIST_SIZE: u32 = 65536;
pub const DEFAULT_CONTINUATION_TIMEOUT_MS: u64 = 5000;

// Absolute caps (stream.rs:13-19)
const MAX_HEADER_FRAGMENT_SIZE: usize = 256 * 1024;
```

**Mitigations:**
- Stream limit: 256 concurrent streams
- Header limit: 64KB per header list, 256KB absolute
- CONTINUATION timeout: 5 seconds
- Flow control windows enforced

### 3. WebSocket Stack (src/net/websocket/)

**Threat Surface:**
- Cache poisoning via unmasked frames
- Invalid opcode injection
- UTF-8 validation bypass

**Security Controls:**
```rust
// Masking for client frames (RFC 6455)
pub fn apply_mask(payload: &mut [u8], mask: [u8; 4])

// Opcode validation
pub fn from_u8(value: u8) -> Result<Opcode, WsError>
```

**Mitigations:**
- Client-to-server masking mandatory
- Invalid opcodes rejected
- UTF-8 validation on close frames
- Handshake key validation (SHA-1 + GUID)

### 4. gRPC Stack (src/grpc/)

**Threat Surface:**
- Authentication bypass
- Request flooding
- Message size attacks

**Security Controls:**
```rust
// Bearer token validation
BearerAuthValidator { validator: F }

// Rate limiting
RateLimitInterceptor { max_requests: u32 }

// Message size limits
ServerConfig {
    max_recv_message_size: 4 * 1024 * 1024,  // 4 MB
    max_send_message_size: 4 * 1024 * 1024,
}
```

**Mitigations:**
- Token format validation
- Rate limiting interceptor
- Message size enforcement
- Concurrent stream limits

### 5. Authentication key provenance (`src/security/`)

Symbol and control-envelope authentication uses domain-separated HMAC-SHA256,
and `AuthKey` material is zeroized on drop. The remaining provisioning boundary
is input entropy: `AuthKey::from_seed(u64)` is intentionally deterministic and
therefore has at most 64 bits of entropy. SHA-256 or HKDF can distribute those
bits across a 256-bit output, but cannot create more entropy.

**Design intent:**
- `from_seed` / `auth_key_seed`: deterministic tests, fixtures, and replay
- `from_bytes`: externally generated CSPRNG or secret-manager key material
- Production callers inject an explicit `SecurityContext`; they do not use the
  deterministic seed knob as a secret source

```rust
// Deterministic/replay-only:
let fixture_key = AuthKey::from_seed(seed);

// Production: `key_bytes` comes from a CSPRNG or secret manager.
let key = AuthKey::from_bytes(key_bytes)?;
let security = SecurityContext::new(key);
```

**Auth Modes:**
- `Strict`: Verification failure = error
- `Permissive`: Verification failure = logged, allowed
- `Disabled`: Skip verification

---

## Threat Matrix

| ID | Threat | Severity | Mitigation | Residual Risk |
|----|--------|----------|------------|---------------|
| T-TLS-001 | MITM Attack | CRITICAL | rustls validation + SNI | LOW |
| T-TLS-002 | Expired Certificate | CRITICAL | rustls validation | LOW |
| T-TLS-003 | ALPN Bypass | HIGH | ALPN enforcement flag | LOW |
| T-H2-001 | Stream Exhaustion | CRITICAL | max_concurrent_streams=256 | LOW |
| T-H2-002 | Header Bomb | CRITICAL | 256KB absolute cap | LOW |
| T-H2-003 | CONTINUATION DoS | CRITICAL | 5s timeout | LOW |
| T-H2-004 | PING Flood | MEDIUM | No limit (gap) | MEDIUM |
| T-WS-001 | Cache Poisoning | CRITICAL | Client masking required | LOW |
| T-WS-002 | Invalid Opcode | HIGH | Opcode validation | LOW |
| T-WS-003 | Close Frame UTF-8 | MEDIUM | UTF-8 validation | LOW |
| T-GRPC-001 | Auth Bypass | CRITICAL | Token validation | LOW |
| T-GRPC-002 | Request Flood | HIGH | Rate limiter | MEDIUM |
| T-GRPC-003 | Message Bomb | CRITICAL | Size limits | LOW |
| T-SEC-001 | Predictable authentication key provisioning | HIGH | HMAC-SHA256 plus explicit 256-bit key injection; deterministic seed APIs labeled test/replay-only | HIGH if an operator uses `auth_key_seed` as a production secret |
| T-DNS-001 | DNS Rebinding | HIGH | No protection (gap) | HIGH |

---

## Mitigations

### Implemented

1. **TLS Certificate Validation**
   - Delegated to rustls (memory-safe, audited)
   - SNI validation prevents hostname confusion
   - ALPN negotiation prevents protocol downgrade

2. **HTTP/2 DoS Protection**
   - Stream limits prevent connection exhaustion
   - Header size caps prevent memory exhaustion
   - CONTINUATION timeout prevents stalling attacks
   - Flow control enforced per RFC 7540

3. **WebSocket Security**
   - Client frame masking per RFC 6455
   - Opcode validation rejects invalid frames
   - UTF-8 validation on text data

4. **gRPC Authentication**
   - Interceptor chain with fail-closed design
   - Token format validation
   - Rate limiting available

5. **Symbol/control authentication**
   - Domain-separated HMAC-SHA256
   - Constant-time tag and key comparison
   - `AuthKey` zeroization on drop
   - Explicit replica-authorization receipts

### Not Implemented (Gaps)

1. **HTTP/2 PING Flood Protection**
   - No rate limiting on PING frames
   - Recommendation: Add per-connection PING limit

2. **DNS Rebinding Protection**
   - No validation of resolved IP addresses
   - Recommendation: Validate against private ranges

3. **Certificate Revocation**
   - No CRL/OCSP checking
   - Recommendation: Add optional revocation checking

4. **Configuration-backed production key provisioning**
   - The compatibility configuration field is a deterministic `u64` seed
   - Production deployments must inject an explicit `SecurityContext` backed
     by CSPRNG- or secret-manager-generated key bytes

---

## Recommendations

### Immediate

1. **Use externally generated production keys**
   ```rust
   // `key_bytes` must come from a CSPRNG or secret manager.
   let key = AuthKey::from_bytes(key_bytes)?;
   let security = SecurityContext::new(key);
   ```

2. **Keep security invariants executable**
   - Add security tests (see tests/security_invariants.rs)
   - Document all security assumptions

### Short-term (1-3 months)

1. **HTTP/2 PING Flood Protection**
   - Add configurable PING rate limit
   - Send GOAWAY on excessive PINGs

2. **DNS Rebinding Protection**
   - Validate resolved IPs
   - Block private address ranges by default

3. **Certificate Revocation**
   - Optional CRL/OCSP validation
   - Configurable online/offline mode

### Long-term (3-6 months)

1. **External Security Audit**
   - Focus: TLS integration, HTTP/2 DoS, gRPC auth
   - Engage third-party security firm

2. **Fuzzing Campaign**
   - HTTP/2 frame codec
   - WebSocket frame decoder
   - HPACK decoder

3. **Dependency Updates**
   - bincode 1.3.3 marked unmaintained (RustSec-2025-0141)
   - Plan migration to postcard

---

## Security Testing

Security invariant tests are located in:
- `tests/security_invariants.rs` - Core security property tests
- `tests/http2_security.rs` - HTTP/2 specific tests
- `tests/websocket_security.rs` - WebSocket specific tests

Run security tests:
```bash
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_security_docs cargo test --test security_invariants
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_security_docs cargo test security -- --nocapture
```

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-02-01 | Initial threat model |

---

## References

- RFC 7540 - Hypertext Transfer Protocol Version 2 (HTTP/2)
- RFC 7541 - HPACK: Header Compression for HTTP/2
- RFC 6455 - The WebSocket Protocol
- RFC 8446 - The Transport Layer Security (TLS) Protocol Version 1.3
- OWASP Top 10 Web Application Security Risks
