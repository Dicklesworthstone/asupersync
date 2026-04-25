# Isomorphism Proof: `CloseReason` Default Derive

## Change

Replace the manual `impl Default for CloseReason` in
`src/net/websocket/close.rs` with `#[derive(Default)]`.

## Preconditions

- `CloseReason` has only three fields.
- Each field is an `Option`.
- `CloseReason::empty()` remains unchanged for explicit empty close reasons.

## Field Mapping

| Field | Manual default via `empty()` | Derived default |
| --- | --- | --- |
| `code` | `None` | `Option::<CloseCode>::default()` = `None` |
| `raw_code` | `None` | `Option::<u16>::default()` = `None` |
| `text` | `None` | `Option::<String>::default()` = `None` |

## Behavior Preservation

- `CloseReason::default()` still creates an empty close reason with no code,
  raw wire code, or text.
- `CloseReason::empty()` still returns the same explicit empty value.
- Parsing, serialization, and close-handshake call sites continue to use the
  same fields and helper constructors.
- No public API is removed: `CloseReason` still implements `Default`.
