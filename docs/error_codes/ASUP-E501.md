# ASUP-E501 - HTTP Deadline Exhausted

## Symptom

`[ASUP-E501]` means an HTTP request or response path exhausted its effective
deadline.

## Probable Causes

- The request budget was smaller than the operation latency.
- A child call failed to compose its timeout with the ambient budget.

## Fix

- Use min-plus deadline composition: effective deadline is the meet of ambient and override.
- Log inbound, consumed, and forwarded budget at every server/client hop.

## Example

If an inbound request has 10 seconds remaining and a handler asks for a
30-second client timeout, the outbound call must use 10 seconds.

## Related

- `ASUP-E301`
- `ASUP-E901`
