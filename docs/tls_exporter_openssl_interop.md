# RFC 9266 exporter interoperability with OpenSSL

This opt-in native lane compares the public `TlsStream` channel-binding API
against an independently derived OpenSSL exporter, not another rustls exporter.
It uses the existing library test target; it adds no Cargo dependency or feature.

## Execution prerequisites

The execution worker needs Python 3 and pyOpenSSL **25.2 or newer** backed by an
OpenSSL build supporting TLS 1.3 and all three tested cipher suites. There is no
automatic package installation. Missing prerequisites, missing certificates,
unsupported ciphers, timeouts, and helper failures fail the tests; they do not
silently pass or skip. Standard TLS unit tests do not acquire this prerequisite.

Run on the exact checkout being evaluated:

```sh
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p asupersync \
  --features tls,real-service-e2e --lib tls::exporter_interop_tests -- --nocapture
```

The result must show **3 passed, 0 failed, 0 ignored** for this filter. Zero tests,
a missing feature, a helper-only run, or an unexecuted command is not evidence
that the Rust API interoperates. Preserve the commit SHA and complete execution
log with the result. This lane does not replace the repository's ordinary build,
TLS, feature-matrix, formatting, Clippy, or native cancellation gates.

## What crosses the boundary

The matrix makes fourteen fresh native TCP exchanges: two independent connections
for each TLS role and TLS 1.3 cipher suite, plus a TLS 1.2 exchange in each role.
The Python helper always listens on `127.0.0.1:0`, even when its TLS role is
client; TCP direction does not determine TLS role. A readiness pipe communicates
the actual bound address without reserving and releasing a port or probing the
one-shot listener with an extra connection.

Both clients verify certificates. Rustls validates `localhost` against the
existing fixture trust anchor. The OpenSSL client preserves chain-verification
failures and additionally pins the exact localhost fixture certificate because
pyOpenSSL's chain validation alone does not check DNS names. No permissive
verifier is installed. Version, cipher, and ALPN must match exactly.

OpenSSL derives 32 bytes using `EXPORTER-Channel-Binding` and an explicitly empty
context, plus different-label and nonempty-context controls. Rust compares its
public getter with those bytes and sends its **own** derived value back; merely
echoing peer-supplied bytes cannot satisfy the Rust assertions. Repeated getters
must agree, distinct fresh connections must differ, and all accepted records
must survive flush and reciprocal `close_notify`. Getter access after closure
must be refused. TLS 1.2 must still exchange application data while its exporter
channel-binding getter returns the existing unsupported-protocol error.

The helper has finite accept/I/O deadlines. The Rust operation also has a native
runtime timeout; an owned child guard kills/reaps only its helper and joins the
stdout reader on success, failure, timeout, and panic. No listener or detached
service is left running. The helper transmits test channel-binding data only,
not application traffic secrets or TLS master secrets.

## Evidence boundary

A standalone OpenSSL-to-OpenSSL helper check establishes only helper framing,
exporter controls, and failure handling. The actual interoperability claim
requires executing all three Rust tests above. This lane does not cover resumed
sessions, 0-RTT, mutual authentication, other crypto providers, or native
cancellation scheduling; their existing tests remain separate.

References: RFC 9266 sections 2 and 4; the pyOpenSSL `Connection.export_keying_material`
and `Context.set_tls13_ciphersuites` API documentation.
