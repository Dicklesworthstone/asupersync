# ASUP-E503 - Web Header Rejected

## Symptom

`[ASUP-E503]` means a typed web header extractor rejected a missing or
malformed request header before invoking the handler.

## Probable Causes

- A handler required `Header<T>` or `TypedHeader<T>` and the request omitted
  that header.
- The header value was empty, contained a forbidden control character, or did
  not match the typed header grammar.

## Fix

- Send the required header with a syntactically valid value.
- Prefer `Header<T>` or `TypedHeader<T>` over direct map indexing so malformed
  input becomes a deterministic `400 Bad Request` instead of a panic.

## Example

A handler extracting `Header<Authorization>` receives `Authorization: Bearer`
without credentials. The response starts with `[ASUP-E503]` and explains that
credentials must be present.

## Related

- `ASUP-E501`
- `ASUP-E502`
