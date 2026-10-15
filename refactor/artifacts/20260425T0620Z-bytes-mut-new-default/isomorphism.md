# Isomorphism Proof: `BytesMut` Constructor Delegation

## Change

Delegate redundant `BytesMut` constructors/conversions in
`src/bytes/bytes_mut.rs` to existing equivalent implementations:

- `BytesMut::new()` uses `Self::default()`.
- `From<&str>` uses `From<&[u8]>`.
- `From<String>` uses `From<Vec<u8>>`.

## Preconditions

- `BytesMut` already derives `Default`.
- `BytesMut` has one field: `data: Vec<u8>`.
- `Vec::<u8>::default()` is equivalent to `Vec::new()`.
- `From<&[u8]> for BytesMut` copies bytes with `slice.to_vec()`.
- `From<Vec<u8>> for BytesMut` stores the vector directly.

## Field Mapping

| Constructor | Previous value | Delegated value |
| --- | --- | --- |
| `new()` | `data: Vec::new()` | `Self::default()` = empty `Vec<u8>` |
| `From<&str>` | `data: s.as_bytes().to_vec()` | `Self::from(s.as_bytes())` |
| `From<String>` | `data: s.into_bytes()` | `Self::from(s.into_bytes())` |

## Behavior Preservation

- `BytesMut::new()` still returns an empty mutable byte buffer.
- `From<&str>` still copies the UTF-8 byte sequence into a new `Vec<u8>`.
- `From<String>` still consumes the string and reuses its bytes through
  `String::into_bytes()`.
- Capacity-sensitive constructors such as `with_capacity()` are unchanged.
- Public API is unchanged: all constructors and `From` impls remain available.
