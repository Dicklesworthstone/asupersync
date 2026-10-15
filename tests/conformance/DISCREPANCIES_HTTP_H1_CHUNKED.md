# RFC 9112 §7 Chunked Transfer Encoding - Known Conformance Divergences

## DISC-001: Chunk extension parsing
- **RFC 9112:** MAY support chunk extensions after semicolon
- **Our impl:** Chunk extensions are parsed but currently ignored in server logic
- **Impact:** Extensions like `5;name=value` are accepted but extension semantics not processed
- **Resolution:** ACCEPTED — RFC makes extensions optional, server behavior is compliant
- **Tests affected:** RFC9112-7.1.1-chunk-extensions
- **Review date:** 2026-04-18

## DISC-002: Trailer header validation  
- **RFC 9112:** Trailer headers SHOULD follow same syntax rules as regular headers
- **Our impl:** Basic parsing only, no comprehensive header validation
- **Impact:** Malformed trailer headers may not be rejected as strictly as regular headers
- **Resolution:** INVESTIGATING — need to align trailer validation with header parsing
- **Tests affected:** RFC9112-7.1.1-trailers
- **Review date:** 2026-04-18

## DISC-003: Large chunk size limits
- **RFC 9112:** No explicit size limits specified for chunk-size
- **Our impl:** Implicit usize limits (platform-dependent)
- **Impact:** Very large chunk sizes (>2^32 on 32-bit) may not be handled consistently
- **Resolution:** ACCEPTED — reasonable implementation-defined limits
- **Tests affected:** None currently (could add edge case tests)
- **Review date:** 2026-04-18

## DISC-004: Chunk extension content validation
- **RFC 9112:** Chunk extensions use token/quoted-string syntax from HTTP header rules
- **Our impl:** Accepts any content until CRLF without strict token validation  
- **Impact:** Invalid extension syntax like `5;invalid"quote` may not be rejected
- **Resolution:** WILL-FIX — should validate extension syntax per HTTP grammar
- **Tests affected:** Future test cases for malformed extensions
- **Review date:** 2026-04-18