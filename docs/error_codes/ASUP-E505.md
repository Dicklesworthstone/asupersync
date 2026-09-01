# ASUP-E505 - Total Request-Body Limit Exceeded

## Symptom

`[ASUP-E505]` means a declared or observed request body exceeded the effective
aggregate byte limit. The safely writable HTTP response is 413. HTTP/1 closes
after an in-flight streaming-body refusal so unread bytes cannot be mistaken
for a new request.

## Probable Causes

- `Content-Length` exceeds the monotonic server, router, route, or extractor
  policy.
- A chunked or otherwise streamed body crossed the effective limit while the
  body consumer and protocol driver were running.

## Fix

- Reduce the request body or raise the narrowest owning `RequestBodyPolicy`
  limit deliberately.
- Inspect the effective policy exposed on the request. Descendant policies can
  tighten an ancestor limit, but cannot loosen it.
- Keep a finite aggregate limit even when individual multipart fields have
  their own limits.

## Example

A route capped at 1 MiB receives a 2 MiB `Content-Length`. Router admission
refuses before handler dispatch with `[ASUP-E505] request body too large (limit
1048576)` and status 413. A direct bounded extractor can additionally include
the declared length in its bounded diagnostic context.

## Related

- `ASUP-E506`
- `ASUP-E508`
- `ASUP-E509`
