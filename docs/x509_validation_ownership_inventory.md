# X.509 validation ownership inventory

<!-- BEGIN X509 VALIDATION OWNERSHIP INVENTORY -->

This is the operator-readable companion to
`artifacts/x509_validation_ownership_inventory_v1.json`. It freezes the
`CAP-TLS-X509` call-path and validation-owner baseline for
`asupersync-0h6myr.3.1` at revision
`3c09dad6aa59566964724ffe6c9dc99359bfd180`.

The governing disposition remains `KEEP_UNTIL_PARITY` /
`KEEP_INCUMBENT`. This inventory does not add a parser, change certificate
policy, or authorize removing `x509-parser`. Its job is to make every current
check visible before A2 delegates standard validation and A3 specifies the
smallest safe residue.

## Locked graph and scope

The root manifest declares optional `x509-parser = "0.18"` through the `tls`
feature. The lockfile resolves:

- `x509-parser` 0.18.1;
- `rustls` 0.23.42 with `default-features = false`, `std`, `tls12`, and the
  `ring` provider selected by the `tls` feature;
- transitive `rustls-webpki` 0.103.13.

The marginal ledger has eight `normal:x509-parser` measurements: `tls` and
`workspace-dev-build-audit` across Apple Silicon, wasm32, Windows x86-64, and
Linux x86-64. Removing the edge is a 20-package marginal change in the
synthesized `tls` consumer and a 9-package change in the workspace audit
profile. Those graph numbers are planning evidence, not cutover authority.

The capability registry names Linux, macOS, and Windows as supported
platforms. The wasm metadata cell still carries the parser through `tls`, but
there is no wasm TLS interoperability claim. Native QUIC is itself excluded
from wasm by `net::quic_native`; the wasm cell can reach only the facade
certificate, connector, and acceptor code. A8 and A9 own any future decision
about support or explicit exclusion.

Without `tls`, the facade types remain visible, but validation operations
return `FeatureDisabled` or `Configuration` errors and neither rustls nor
x509-parser performs certificate validation.

## Complete production parser census

There are five active production call sites in five files. No other
`x509_parser::` symbol occurs under `src/`.

| ID | Path | Local responsibility | Standard-verifier relationship |
| --- | --- | --- | --- |
| `X509-CS-SPKI-PIN` | `src/tls/types.rs` | Extract complete SPKI DER and hash it with SHA-256 | Builder-created connectors finish WebPKI verification first. A raw caller-provided `ClientConfig` remains caller-owned. |
| `X509-CS-ROOT-CA-ADMISSION` | `src/tls/connector.rs` | Require `BasicConstraints CA:TRUE` for environment roots and opt-in strict direct-root additions | Runs before bytes enter `RootCertStore`; no verifier can safely undo a bad trust-anchor admission. |
| `X509-CS-ACCEPTOR-PREFLIGHT` | `src/tls/acceptor.rs` | Check every configured server-chain certificate's dates and require a nonempty CN/OU/O subject | Operator preflight before `with_single_cert`; remote peers later own path/name validation. |
| `X509-CS-NATIVE-QUIC-PIN-FALLBACK` | `src/net/quic_native/handshake_driver.rs` | For an exact pinned leaf after WebPKI `UnknownIssuer`, check dates, EKU, optional KU, and exact DNS/IP SAN | WebPKI runs first; TLS handshake signatures still delegate to its verifier. The byte pin replaces issuer path trust only in the recorded fallback. |
| `X509-CS-ATP-CLI-PIN-FALLBACK` | `src/bin/atp.rs` | For an exact pinned leaf, check full DER consumption, dates, server EKU, and exact DNS/IP SAN | WebPKI runs first, but any WebPKI rejection can enter the exact-leaf fallback. Handshake signatures use the configured provider algorithms. |

The symbols are not merely parser constructors. The live surface includes
`X509Certificate::from_der`, `parse_x509_certificate`, validity times,
EKU, KU, SAN DNS/IP names, `BasicConstraints`, subject attributes, and raw
SPKI bytes.

References in the replacement plan, feature docs, marginal-ledger test, and
oracle-policy test are policy strings, not parser calls. The permissive
`AcceptAnyCert` implementations in conformance, metamorphic, pin-mismatch,
and JetStream integration test code are test-only fixtures. They are not
production verifier paths.

## Actual verifier paths

### Ordinary TLS client

`TlsConnectorBuilder::build` rejects an empty root store. With no CRL, it
uses `ClientConfig::with_root_certificates`, which installs rustls's
`WebPkiServerVerifier`. With CRLs, it explicitly builds the same verifier
with `with_crls` and installs it through the API named `dangerous()`.
Despite that API name, the installed object remains WebPKI and keeps standard
chain, time, EKU, name, and signature validation.

Root inputs can be explicit certificates, curated webpki roots, native
platform roots, or explicitly enabled environment bundles. Environment
bundles are CA-gated and logged with accepted/rejected counts. Direct root
additions are CA-gated only after `with_strict_ca_validation`; the public
`RootCertStore::add` primitive and the builder's backwards-compatible default
do not apply that local policy.

`TlsConnector::new(rustls::ClientConfig)` is the advanced escape hatch. Its
verifier is entirely caller-owned and can be permissive. Adding a
`CertificatePinSet` is an additional post-handshake decision; it does not
turn a permissive raw verifier into WebPKI validation.

### TLS server and mTLS

`TlsAcceptorBuilder` performs its own configured-chain preflight by default.
Rustls then checks that `with_single_cert` can use the certificate/key
configuration. The server does not validate its own public chain to a root;
remote clients do that.

For client authentication, optional and required modes build
`WebPkiClientVerifier` with explicit roots. Optional mode permits no client
certificate, but any presented certificate is still verified. Required mode
requires and verifies one. Client certificate path, time, client EKU, and
CertificateVerify signature ownership therefore stays with rustls/WebPKI.

### Explicit native QUIC identity

`QuicServerIdentityVerifier` rejects an empty root store and delegates the
presented leaf, intermediates, hostname, and caller-supplied time to
`WebPkiServerVerifier`. It returns a redaction-safe receipt containing only
chain and root counts and maps failures to stable `QuicTlsError` codes.

This explicit verifier and the live handshake driver are separate surfaces.
The former is a direct identity gate. The latter builds the TLS 1.3 client
configuration that is used by ATP native QUIC.

### Native QUIC exact-leaf fallback

`WebPkiOrPinnedEndEntityVerifier` always invokes WebPKI first. It permits the
local fallback only when:

1. WebPKI returned exactly `UnknownIssuer`; and
2. the presented leaf DER exactly matches one of the supplied root/pin bytes.

The fallback checks the leaf validity interval, accepts EKU `serverAuth` or
`any`, requires KU `digitalSignature` when KU exists, and matches an exact
case-insensitive DNS SAN or exact IP SAN. It does not interpret wildcards.
Issuer-chain signatures are not verified on this branch: exact certificate
bytes are the trust decision. TLS CertificateVerify is still verified by the
inner WebPKI verifier, so possession of the pinned certificate's private key
remains mandatory.

### ATP CLI exact-leaf fallback

`QuicCliServerVerifier` also invokes WebPKI first and requires an exact leaf
byte match before local acceptance. Its boundary is broader: any WebPKI
certificate error may enter the fallback, not only `UnknownIssuer`. It
rejects trailing DER bytes, checks dates, requires EKU `serverAuth`, and
matches exact DNS/IP SANs. It does not perform the native fallback's optional
KU `digitalSignature` check.

TLS CertificateVerify uses the configured crypto provider's WebPKI-supported
algorithms. Certificate-specific detail is later reduced to the native
handshake's stable `read_hs_fatal_alert` / `read_hs_failed` codes.

### Dormant legacy QUIC

`src/net/quic/endpoint.rs` states that it is an orphaned wrapper not wired
into the crate root. Its source rejects `insecure_skip_verify` and would use
rustls/WebPKI roots if reintroduced, but it owns no active parser call or
current capability evidence.

## Check-to-owner matrix

The checked artifact carries the complete sixteen-row matrix. The important
ownership decisions are:

- Chain building, certificate-chain signatures, trust-anchor path
  verification, path validity, EKU, DNS/IP name validation, BasicConstraints,
  name constraints, unsupported critical extensions, and duplicate
  extensions belong to rustls/WebPKI on ordinary server-certificate and mTLS
  paths.
- TLS CertificateVerify signatures always remain cryptographic-verifier work.
  They are distinct from issuer signatures in a certificate chain.
- `rustls-webpki` 0.103.13 intentionally ignores certificate KeyUsage in its
  ordinary path checks. The native pinned fallback's conditional
  `digitalSignature` check is therefore an active local requirement, not a
  redundant copy of WebPKI behavior.
- WebPKI strictly remembers supported extensions once and rejects unsupported
  critical extensions. The local x509-parser fallbacks do not currently
  express equivalent duplicate/critical-extension policy.
- WebPKI owns name constraints for built paths. Exact-leaf pin branches have
  no built issuer path; A2 must prove that this exception is sufficiently
  narrow and intentional.
- CRLs apply only when configured on `TlsConnectorBuilder`. Rustls 0.23.42
  does not validate the passed OCSP response. Neither pinned fallback has a
  local revocation policy.
- SPKI extraction, pre-trust CA admission, and configured server-chain
  preflight have no identical owner in the configured rustls verifier paths.

## Provisional minimal residue

A1 records five provisional residue families. “Provisional” matters: A2 must
first eliminate any check that can be identically delegated, and A3 must
write the approved threat model before parser implementation begins.

1. `X509-R1-SPKI`: locate complete SPKI DER for SHA-256 pinning.
2. `X509-R2-CA-ADMISSION`: enforce pre-insertion `BasicConstraints CA:TRUE`
   on untrusted root-bundle input.
3. `X509-R3-ACCEPTOR-PREFLIGHT`: retain configured-chain time and
   subject-presence diagnostics not supplied by rustls server setup.
4. `X509-R4-NATIVE-PIN-FALLBACK`: the exact-leaf fallback checks that remain
   after A2 narrows WebPKI delegation.
5. `X509-R5-ATP-PIN-FALLBACK`: the ATP exact-leaf checks that remain after A2
   resolves its broader fallback and policy differences.

No residue API may grow into general path building, certificate-signature
verification, trust-anchor validation, or general hostname verification.

## Public and downstream journeys

The public `tls` module is marked preview in
`artifacts/api_surface_map_v1.json`, but the generated root map does not list
its nested exports. This dedicated inventory therefore freezes the nested
connector, acceptor, certificate, root-store, pin, and QUIC identity surfaces.

The current journeys are:

- direct TLS client and server use, including optional/required mTLS;
- SPKI and whole-certificate pinning;
- explicit native QUIC identity and live native QUIC TLS 1.3 handshakes;
- ATP direct/SSH-bootstrapped QUIC;
- HTTP/1.1 HTTPS;
- Redis `rediss`;
- NATS and JetStream TLS;
- PostgreSQL TLS and SCRAM-SHA-256-PLUS channel binding;
- native roots on Linux, macOS, and Windows plus curated webpki roots.

The shared connector path establishes code ownership, not complete
cross-service proof. A8 owns real supported-peer and platform evidence for
`tls_x509_interop`, including valid, rotated, malformed, expired/future,
wrong-name, wrong-EKU/KU, non-CA, bad-signature, constrained, unknown-critical,
duplicate-extension, pin-mismatch, cancellation, timeout, reconnect, and
shutdown cases.

## Diagnostics

`TlsError::Rustls` sanitizes control characters and caps peer-derived text at
256 bytes. `TlsError::PinMismatch` reports configured and derived base64
hashes. The acceptor preflight reports the configured chain index, validity
values, current time, and remediation context.

Environment-root admission reports paths and accepted/rejected counts only
when tracing is enabled. Strict direct-root admission returns the builder and
has no typed rejection. `QuicServerIdentityVerifier` maps failures to
redaction-safe stable categories. The live native QUIC handshake intentionally
collapses detailed certificate causes to provider codes. These observed
diagnostics are compatibility obligations for A6/A8, not endorsements of
their current granularity.

## Routed gaps

There are zero unknown rows. The twelve observed gaps are all routed:

| Gap | Finding | Owner |
| --- | --- | --- |
| `X509-GAP-01` | Four parser sites ignore trailing DER bytes. | A3/A4/A5 |
| `X509-GAP-02` | Native fallback accepts only `UnknownIssuer`; ATP fallback accepts any WebPKI rejection. | A2 |
| `X509-GAP-03` | Native and ATP pin branches differ on EKU and KU policy. | A2 |
| `X509-GAP-04` | Standard WebPKI ignores certificate KU; native pinning alone checks leaf `digitalSignature`. | A2/A8 |
| `X509-GAP-05` | CA admission omits `keyCertSign` and is optional for direct roots. | A2/A8 |
| `X509-GAP-06` | Acceptor preflight has no identical rustls owner and can be disabled. | A2/A8 |
| `X509-GAP-07` | Raw `ClientConfig` construction leaves all standard validation caller-owned. | A6/A7 |
| `X509-GAP-08` | Live native QUIC collapses detailed certificate errors. | A6/A8 |
| `X509-GAP-09` | wasm carries the edge without a supported TLS evidence claim. | A8/A9 |
| `X509-GAP-10` | Canonical `tls_x509_interop` result artifacts do not yet exist. | A8 |
| `X509-GAP-11` | OCSP is unvalidated and CRL coverage is optional/bypassable by a pin fallback. | A2/A8 |
| `X509-GAP-12` | The generated API map lacks nested TLS/X.509 surfaces. | A6/A9 |

Any new call site, changed verifier boundary, lost check, unknown ownership,
or unrouted gap forces `KEEP_X509_PARSER_AND_BLOCK_CUTOVER`.

## Validation

Run the focused source-pin, occurrence, verifier, owner-matrix, residue,
feature/target, diagnostic, journey, graph, authority, documentation, and
negative-mutation contract:

```bash
RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay \
  --overlay-path artifacts/x509_validation_ownership_inventory_v1.json \
  --overlay-path docs/x509_validation_ownership_inventory.md \
  --overlay-path tests/x509_validation_ownership_inventory_contract.rs \
  -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-D warnings -C debuginfo=0' \
  CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_x509_validation_ownership_inventory" \
  cargo test -p asupersync --features tls \
  --test x509_validation_ownership_inventory_contract -- --nocapture
```

No local Cargo fallback is approved when this remote-required lane is
blocked.

This inventory does not prove parser correctness, WebPKI correctness,
interoperability, performance, release readiness, broad workspace health,
live RCH fleet availability, or permission to change features, remove a
dependency, or delete files. In particular, it does not authorize removing `x509-parser`.

<!-- END X509 VALIDATION OWNERSHIP INVENTORY -->
