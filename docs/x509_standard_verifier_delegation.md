# X.509 standard-verifier delegation

<!-- X509_STANDARD_VERIFIER_DELEGATION_BEGIN -->

This is the operator companion to
`artifacts/x509_standard_verifier_delegation_v1.json` for
`asupersync-0h6myr.3.2` (`CAP-TLS-X509`). It records the A2 decision:
`STANDARD_FIRST_SHARED_EXACT_LEAF_POLICY`.

## Decision

Native QUIC and ATP now use one verifier wrapper:
`webpki_server_verifier_with_exact_leaf_fallback`.

The wrapper invokes `rustls::client::WebPkiServerVerifier` first. Successful
standard verification succeeds normally. Every standard failure is returned
unchanged except this single explicit policy:

1. WebPKI returned `CertificateError::UnknownIssuer`.
2. The complete presented leaf DER exactly equals a configured typed pin.
3. The complete DER is consumed with no trailing bytes.
4. The leaf is currently valid.
5. EKU explicitly includes `serverAuth`.
6. KeyUsage includes `digitalSignature` when the extension is present.
7. The SAN exactly matches the requested DNS name, case-insensitively, or the
   exact requested IP address.

Only issuer-path trust is replaced by the exact byte pin. TLS 1.2 and TLS 1.3
handshake signatures, supported signature schemes, and root hints continue to
delegate to the inner WebPKI verifier.

## Path ownership

| Path | Standard owner | Exact-leaf policy | Diagnostic compatibility |
| --- | --- | --- | --- |
| Native QUIC `client_config` | rustls/WebPKI first | Shared wrapper after `UnknownIssuer` only | Existing `client_verifier_build` and redacted handshake codes remain |
| ATP `quic_cli_client_config` | rustls/WebPKI first | Delegates to the same shared wrapper | Existing `client_verifier_build_failed` and native-link redaction remain |

ATP no longer owns `QuicCliServerVerifier`, `verify_quic_cli_pinned_leaf`, or
an independent `x509_parser` call. Its direct and SSH-bootstrapped QUIC paths
therefore cannot drift to a broader local verifier policy.

## Standard and retained checks

Rustls/WebPKI continues to own ordinary chain/path construction, certificate
signature verification, trust anchors, server purpose, server name, path-role
BasicConstraints, constraints, critical extensions, and TLS handshake
signatures.

The exact-pin exception has no issuer path. Its narrow retained reader owns
only complete-DER consumption, leaf dates, explicit `serverAuth`, conditional
`digitalSignature`, and exact DNS/IP SAN checks. A bad signature or wrong name
reported by WebPKI is never converted to success.

Two other local policies remain because rustls exposes no identical owner and
operator diagnostic:

- `X509-R2-CA-ADMISSION`: pre-insertion `BasicConstraints CA:TRUE` for selected
  root-loading paths.
- `X509-R3-ACCEPTOR-PREFLIGHT`: configured server-chain dates and subject
  presence before serving.

`X509-R5-ATP-PIN-FALLBACK` is resolved by delegation to
`X509-R4-NATIVE-PIN-FALLBACK`. A3 owns the bounded reader for that remaining
shared residue. A8 owns the real-peer parity evidence for CA admission,
acceptor preflight, and the exact-pin boundary.

## Gap disposition

| Gap | A2 disposition |
| --- | --- |
| `X509-GAP-02` | `CLOSED_BY_A2_SHARED_POLICY`: both paths are `UnknownIssuer`-only |
| `X509-GAP-03` | `CLOSED_BY_A2_SHARED_POLICY`: explicit `serverAuth` and conditional `digitalSignature` are shared |
| `X509-GAP-04` | `A2_DECIDED_KEEP_A8_E2E_PENDING`: stricter pin-only KeyUsage check retained |
| `X509-GAP-05` | `A2_DECIDED_KEEP_A8_E2E_PENDING`: local pre-trust CA admission retained |
| `X509-GAP-06` | `A2_DECIDED_KEEP_A8_E2E_PENDING`: local acceptor preflight retained |
| `X509-GAP-11` | `A2_DECIDED_KEEP_A8_E2E_PENDING`: no OCSP/CRL claim on the exact-pin branch |

## Focused evidence

The implementation directly covers future and expired leaves, clientAuth-only
and missing EKU, wrong KeyUsage, trailing DER, bad certificate signatures,
wrong names, and standard-error preservation. Existing focused owners cover
valid/empty chains, non-CA root admission, and acceptor preflight.

The recorded successful lanes are:

```text
cargo test --quiet -p asupersync --features tls --lib exact_leaf -- --nocapture
# 4 passed

cargo test --quiet -p asupersync --features atp-cli --bin atp quic_cli_client_config -- --nocapture
# 2 passed

cargo test --quiet -p asupersync --features tls --test x509_validation_ownership_inventory_contract -- --nocapture
# 11 passed

cargo test --quiet -p asupersync --features tls --lib self_signed_leaf -- --nocapture
# 2 passed

cargo test --quiet -p asupersync --features tls --lib certificate_validation -- --nocapture
# 4 passed
```

The aggregate `tls_x509_interop` scenario remains planned under
`asupersync-0h6myr.3.8`; this A2 packet does not substitute for it.

## No-claim boundary

This decision does not authorize removing `x509-parser`, changing Cargo
features, changing the lockfile, cutting over `CAP-TLS-X509`, deleting files,
or weakening any retained check. It does not claim issuer-path validation,
OCSP validation, or CRL enforcement after the exact-pin `UnknownIssuer`
exception. It does not prove the A8 real-peer/platform/cancellation matrix,
performance, broad workspace health, release readiness, or live RCH fleet
availability.

<!-- X509_STANDARD_VERIFIER_DELEGATION_END -->
