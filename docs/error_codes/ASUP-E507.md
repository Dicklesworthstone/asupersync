# ASUP-E507 - Multipart Input Malformed

## Symptom

`[ASUP-E507]` means multipart media type, boundary framing, headers, or a
declared part length were malformed or unsupported. Malformed framing is 400;
a request that is not `multipart/form-data` remains 415.

## Probable Causes

- The `multipart/form-data` boundary is absent, invalid, or never terminates.
- Part headers contain invalid UTF-8 or a malformed `Content-Length`.
- A nested multipart part was supplied; the current extractor rejects nesting.

## Fix

- Generate a valid bounded boundary and matching closing delimiter.
- Ensure declared request and part lengths match the bytes sent.
- Flatten nested multipart content before submitting it.

## Example

A multipart body reaches EOF without a closing boundary. Extraction returns
400 with bounded text beginning `[ASUP-E507] multipart part missing closing
boundary`.

## Related

- `ASUP-E504`
- `ASUP-E506`
- `ASUP-E508`
