# ASUP-E508 - Request-Body Timeout

## Symptom

`[ASUP-E508]` means request-body reading, multipart parsing, or bounded unread
body draining exhausted its time budget. Multipart read/parser timeouts are
408; request-region deadline exhaustion retains `ASUP-E501` and 503.

## Probable Causes

- The client stopped sending body progress before the idle or absolute
  deadline.
- A handler returned without consuming its body and the bounded drain did not
  reach synchronized EOF in time.

## Fix

- Make body progress within the configured budget or reduce request size.
- Consume the body, or deliberately drop it and allow the server's bounded
  drain-or-close policy to run.
- Increase a finite timeout only after verifying that slow progress is
  expected and resource limits still bound the request.

## Example

No multipart bytes arrive before the body-specific read deadline. The field API
returns a typed timeout with `diagnostic_code() == "ASUP-E508"`; its extractor
response begins `[ASUP-E508]`. The protocol closes rather than reusing a
connection whose request boundary was not synchronized.

## Related

- `ASUP-E501`
- `ASUP-E505`
- `ASUP-E509`
