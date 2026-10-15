# BSD Kqueue Conformance Discrepancies

## Known Conformance Divergences

### DISC-001: EV_DISPATCH implementation
- **Reference:** BSD kqueue supports EV_DISPATCH flag for one-shot-and-disable behavior
- **Our impl:** Uses polling crate abstraction which may not expose EV_DISPATCH directly
- **Impact:** EV_DISPATCH tests may not behave exactly as documented in BSD kqueue manual
- **Resolution:** INVESTIGATING — polling crate compatibility with EV_DISPATCH needs verification
- **Tests affected:** kqueue_ev_dispatch_oneshot_disable
- **Review date:** 2026-04-18

### DISC-002: Platform-specific event timings
- **Reference:** Event delivery timing varies between macOS and FreeBSD
- **Our impl:** Tests use timeouts and may see different timing characteristics
- **Impact:** Golden files may need platform-specific versions
- **Resolution:** ACCEPTED — timing differences are expected between platforms
- **Tests affected:** All timing-sensitive tests
- **Review date:** 2026-04-18

### DISC-003: Concurrent kevent behavior
- **Reference:** BSD kqueue has specific behavior for concurrent kevent() calls
- **Our impl:** Uses mutex-protected reactor which serializes access
- **Impact:** Concurrent tests may not expose true concurrency issues
- **Resolution:** ACCEPTED — reactor design intentionally serializes for safety
- **Tests affected:** kqueue_concurrent_kevent_calls
- **Review date:** 2026-04-18

## Test Platform Requirements

- **macOS**: All tests should pass with native kqueue semantics
- **FreeBSD**: All tests should pass with potential minor timing differences
- **Linux**: Tests are conditionally compiled out (no kqueue support)
- **Windows**: Tests are conditionally compiled out (no kqueue support)

## Golden File Expectations

- Golden files capture the expected event sequences for each test
- Timestamps and sequence numbers are ignored during comparison (non-deterministic)
- Token values and ready flags must match exactly
- Event count must match exactly