# ASUP-E005 - Name Registration Failed

## Symptom

`[ASUP-E005]` appears when a named task or service cannot reserve its requested
name.

## Probable Causes

- The service name is already leased.
- The requested name is invalid for the registry.

## Fix

- Pick a unique service name.
- Release or await the existing name lease before retrying.

## Example

For restartable services, make the old service close and release its lease
before spawning the replacement under the same name.

## Related

- `ASUP-E006`
- `ASUP-E105`
