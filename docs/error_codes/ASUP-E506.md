# ASUP-E506 - Multipart Field Limit Exceeded

## Symptom

`[ASUP-E506]` means one multipart field, its header block, the part count, or
the parser's bounded-work allowance exceeded the effective limit. Field-body
byte excess is 413; structural count, header, and work refusals remain 400.

## Probable Causes

- One field body or part-header section exceeded `MultipartLimits`.
- The request contained more parts than `max_parts`.
- Boundary scanning exhausted the parser's derived finite work allowance.

## Fix

- Reduce the offending field, header block, or number of parts.
- Raise only the required multipart limit and retain a finite total-body limit.
- Consume a live field to EOF before requesting the next field.

## Example

A file field crosses `max_part_body_size`. The live field returns a typed
`StreamingMultipartError` with `diagnostic_code() == "ASUP-E506"` and status
413. Its compatibility `Display` retains the `[ASUP-E504]` umbrella; conversion
to an extractor response emits the precise `[ASUP-E506]` prefix.

## Related

- `ASUP-E504`
- `ASUP-E505`
- `ASUP-E507`
