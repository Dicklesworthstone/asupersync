# ASUP-E502 - Web Handler Panic Recovered

## Symptom

`[ASUP-E502]` means a web handler (or something it called) panicked while
serving a request. `CatchPanicMiddleware` caught the unwind and converted it
into a `500 Internal Server Error` response carrying this token, so the
connection and worker stayed alive.

## Probable Causes

- A handler or extractor hit an `unwrap`/`expect` or index out of bounds on
  request data.
- Application logic panicked on an unexpected state instead of returning an
  error response.

## Fix

- Find the panic message and backtrace in the server log line tagged
  `[ASUP-E502]`; the client response intentionally omits details.
- Fix the handler to return an error `Response` (4xx/5xx) for the failing
  input instead of panicking.
- Keep `CatchPanicMiddleware` (or `Router::layer(CatchPanicLayer::new())`)
  outermost so panics cannot tear down the connection or worker.

## Example

A handler that does `req.headers["x-tenant"]` panics on requests without the
header. The client sees `[ASUP-E502] Internal Server Error`; the server log
carries the panic payload and the request's trace id. The fix is to extract
the header fallibly and return `400 Bad Request` when it is missing.

## Related

- `ASUP-E501`
- `ASUP-E904`
