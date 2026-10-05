# ASUP-E009 - Ambient I/O Capability Denied

## Symptom

An I/O entry point that takes no `Cx` (`TcpStream::connect`,
`TcpListener::bind`, `fs::read`, `process::Command::spawn`, `signal::signal`,
the HTTP client, and so on) returns an `io::Error` of kind `PermissionDenied`
whose message starts with `[ASUP-E009]`. The inner error is
`asupersync::cx::IoCapabilityDenied`, and `operation()` names the entry point.

## Probable Causes

- The calling task runs under a `Cx` narrowed with `Cx::push_restriction` or
  `Cx::set_current_restricted` to a capability set without IO. Tasks spawned
  from it inherit the narrowed mask.
- The task belongs to an AppSpec work unit whose required `Cx` capabilities
  include neither `io` nor `net`, so the runtime drops IO from its context.

Code with no current `Cx` (a plain thread, code outside the runtime) and code
whose `Cx` carries IO are not affected.

## Fix

- Do the I/O in a task whose `Cx` carries the IO capability, or require the
  `io` or `net` capability on the work unit that needs it.
- If the narrowing is intended, keep the I/O out of the restricted code: do
  it outside and pass the results in.
- To use a specific context's authority, run the I/O under
  `cx.with_ambient(future)`: the entry points inside it are checked against
  `cx`, not the calling task's context.

## Example

```rust,ignore
use asupersync::cx::IoCapabilityDenied;

match asupersync::net::TcpStream::connect("127.0.0.1:8080").await {
    Err(error) => {
        if let Some(denied) = error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<IoCapabilityDenied>())
        {
            eprintln!("{} needs the IO capability", denied.operation());
        }
    }
    Ok(stream) => { /* ... */ }
}
```

## Related

- `ASUP-E007`
- `docs/error_codes/registry.json`
