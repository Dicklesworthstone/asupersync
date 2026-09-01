# ASUP-E504 - Streaming Multipart Rejected

## Symptom

`[ASUP-E504]` means the live multipart field API refused malformed framing,
an exceeded limit or deadline, an unsupported media type, a cancelled or
disconnected body, or an invalid field-lease lifecycle transition.

The public `StreamingMultipartError` retains the compatibility umbrella
`code() == "ASUP-E504"`, a machine-readable `kind()`, and the exact HTTP
`status()`. New code should also inspect `diagnostic()` or
`diagnostic_code()`: `ASUP-E505` through `ASUP-E509` distinguish aggregate
limits, field limits, malformed input, timeouts, and client aborts without
breaking existing E504 consumers. In particular, malformed input is 400, the
multipart parser's own absolute or idle-read timeout is 408, body-limit
exhaustion is 413, and a non-multipart media type is 415. Enclosing handler or
body-context cancellation retains cancellation's 499 or 503 mapping and its
exact `CancelKind` through `cancel_kind()`.

## Probable Causes

- The request did not use `multipart/form-data` with a valid boundary.
- Multipart framing, part headers, or a declared `Content-Length` was invalid.
- The total request or current field exceeded its configured byte limit.
- The request exceeded its absolute or idle-read deadline.
- The client disconnected or the handler context was cancelled.
- A `StreamingMultipartField` was dropped or forgotten before field EOF.

## Fix

- Branch on `StreamingMultipartError::kind()`, `diagnostic()`, or `status()`;
  do not parse its display message.
- Consume each field with `next_chunk(cx)` until it returns `None` before
  calling `next_field(cx)` again.
- Keep declared and observed lengths within `MultipartLimits`, and supply a
  valid multipart boundary.
- Treat an abandoned field as terminal for that request body; the HTTP/1
  driver performs its bounded drain-or-close disposition before reuse.

## Example

A handler receives `Content-Type: text/plain` for a streaming multipart
extractor. Construction returns `UnsupportedMediaType` with status 415 and
the compatibility `code()` and display prefix `[ASUP-E504]`; its additive
`diagnostic_code()` is `ASUP-E507`, the malformed-multipart category, before
the live body is taken.

## Related

- `ASUP-E501`
- `ASUP-E503`
- `ASUP-E505`
- `ASUP-E506`
- `ASUP-E507`
- `ASUP-E508`
- `ASUP-E509`
