# Isomorphism Proof: `TraceCertificate` Default Delegation

## Change

Delegate `TraceCertificate::new()` in `src/trace/certificate.rs` to the
already-derived `Default` implementation.

## Preconditions

- `TraceCertificate` derives `Default`.
- All numeric certificate counters are `u64`, whose default is `0`.
- `bool::default()` is `false`.
- `Option<String>::default()` is `None`.

## Field Mapping

| Field | Previous `new()` value | Derived `Default` value |
| --- | --- | --- |
| `event_hash` | `0` | `0` |
| `event_count` | `0` | `0` |
| `spawns` | `0` | `0` |
| `completes` | `0` | `0` |
| `cancel_requests` | `0` | `0` |
| `cancel_acks` | `0` | `0` |
| `obligation_acquires` | `0` | `0` |
| `obligation_releases` | `0` | `0` |
| `schedule_hash` | `0` | `0` |
| `violation_detected` | `false` | `false` |
| `first_violation` | `None` | `None` |

## Behavior Preservation

- `TraceCertificate::new()` still returns an empty certificate.
- Event accumulation, violation recording, hashing, and verification logic are
  unchanged.
- Public API and all existing call sites are unchanged.
