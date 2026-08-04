# X.509 validation ownership inventory

<!-- BEGIN X509 VALIDATION OWNERSHIP INVENTORY -->

This is the operator-readable companion to
`artifacts/x509_validation_ownership_inventory_v1.json`. It freezes the
`CAP-TLS-X509` call-path and validation-owner baseline for
`asupersync-0h6myr.3.1` at revision
`3c09dad6aa59566964724ffe6c9dc99359bfd180`.

The governing disposition remains `KEEP_UNTIL_PARITY` /
`KEEP_INCUMBENT`. This inventory does not add a parser, change certificate
cutover authority, or authorize removing `x509-parser`. A2
(`asupersync-0h6myr.3.2`) updates the baseline in place after consolidating the
two exact-leaf paths behind one standard-verifier-first policy. A3
(`asupersync-0h6myr.3.3`) now owns the independently approved smallest-safe
residue specification; A4 implementation remains pending.

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

There are four active production parser call sites in four files. No other
`x509_parser::` symbol occurs under `src/`.

| ID | Path | Local responsibility | Standard-verifier relationship |
| --- | --- | --- | --- |
| `X509-CS-SPKI-PIN` | `src/tls/types.rs` | Extract complete SPKI DER and hash it with SHA-256 | Builder-created connectors finish WebPKI verification first. A raw caller-provided `ClientConfig` remains caller-owned. |
| `X509-CS-ROOT-CA-ADMISSION` | `src/tls/connector.rs` | Require `BasicConstraints CA:TRUE` for environment roots and opt-in strict direct-root additions | Runs before bytes enter `RootCertStore`; no verifier can safely undo a bad trust-anchor admission. |
| `X509-CS-ACCEPTOR-PREFLIGHT` | `src/tls/acceptor.rs` | Check every configured server-chain certificate's dates and require a nonempty CN/OU/O subject | Operator preflight before `with_single_cert`; remote peers later own path/name validation. |
| `X509-CS-NATIVE-QUIC-PIN-FALLBACK` | `src/net/quic_native/handshake_driver.rs` | For an exact pinned leaf after WebPKI `UnknownIssuer`, require full DER consumption, dates, explicit server EKU, optional KU, and exact DNS/IP SAN | WebPKI runs first; TLS handshake signatures still delegate to its verifier. The byte pin replaces issuer path trust only in the recorded fallback. |

`X509-CS-ATP-CLI-PIN-FALLBACK` remains a verifier call path, but it is no
longer an independent parser site. `src/bin/atp.rs::quic_cli_client_config`
constructs its ordinary WebPKI
verifier and passes it with typed exact-leaf pins to
`webpki_server_verifier_with_exact_leaf_fallback`.

The symbols are not merely parser constructors. The live surface includes
`parse_x509_certificate`, validity times, EKU, KU, SAN DNS/IP names,
`BasicConstraints`, subject attributes, and raw SPKI bytes.

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

The fallback requires full DER consumption, checks the leaf validity interval,
requires explicit EKU `serverAuth`, requires KU `digitalSignature` when KU
exists, and matches an exact case-insensitive DNS SAN or exact IP SAN. It does
not interpret wildcards.
Issuer-chain signatures are not verified on this branch: exact certificate
bytes are the trust decision. TLS CertificateVerify is still verified by the
inner WebPKI verifier, so possession of the pinned certificate's private key
remains mandatory.

### ATP CLI exact-leaf fallback

ATP no longer owns `QuicCliServerVerifier` or a second DER policy. It builds
`WebPkiServerVerifier` with its existing root-admission and
`client_verifier_build_failed` diagnostic, then delegates to the same wrapper
used by native QUIC. Only `UnknownIssuer` plus an exact typed leaf pin can
enter the fallback. Bad signature, wrong name/purpose, critical-extension,
constraint, and revocation errors return unchanged.

TLS CertificateVerify and supported schemes delegate to the inner WebPKI
verifier. Certificate-specific detail is later reduced to the native
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
  ordinary path checks. The shared pinned fallback's conditional
  `digitalSignature` check is therefore an active local requirement, not a
  redundant copy of WebPKI behavior.
- WebPKI strictly remembers supported extensions once and rejects unsupported
  critical extensions. The local x509-parser fallbacks do not currently
  express equivalent duplicate/critical-extension policy.
- WebPKI owns name constraints for built paths. The shared exact-leaf branch
  has no built issuer path; A2 proves that the exception is limited to
  `UnknownIssuer` plus exact complete leaf bytes.
- CRLs apply only when configured on `TlsConnectorBuilder`. Rustls 0.23.42
  does not validate the passed OCSP response. Neither pinned fallback has a
  local revocation policy.
- SPKI extraction, pre-trust CA admission, and configured server-chain
  preflight have no identical owner in the configured rustls verifier paths.

## Provisional minimal residue

A1 records five residue identifiers. A2 resolves the ATP-specific duplicate
into the shared native policy. A3's independently reviewed contract is
`artifacts/x509_der_residue_spec_v1.json`, with operator guidance in
`docs/x509_der_residue_spec.md` and executable checks in
`tests/x509_der_residue_spec_contract.rs`. Its normative payload SHA-256 is
`8a619557ce3a8d87833d7e8733ac89a5fe78a1286c7cdb93c9c88bbd37e17274`.
A4 may implement only that approved fact-only boundary; dependency cutover
remains forbidden.

1. `X509-R1-SPKI`: locate complete SPKI DER for SHA-256 pinning.
2. `X509-R2-CA-ADMISSION`: enforce pre-insertion `BasicConstraints CA:TRUE`
   on untrusted root-bundle input.
3. `X509-R3-ACCEPTOR-PREFLIGHT`: retain configured-chain time and
   subject-presence diagnostics not supplied by rustls server setup.
4. `X509-R4-NATIVE-PIN-FALLBACK`: the shared exact-leaf fallback checks that
   remain after A2 narrows WebPKI delegation.
5. `X509-R5-ATP-PIN-FALLBACK`: a historical compatibility row now resolved by
   delegation to `X509-R4`; ATP owns no separate parser.

No residue API may grow into general path building, certificate-signature
verification, trust-anchor validation, or general hostname verification.
`X509-R1` through `X509-R4` are
`A3_SPEC_APPROVED_A4_IMPLEMENTATION_PENDING`; `X509-R5` remains resolved by A2
delegation to the shared `X509-R4` policy. `X509-GAP-01` carries the same A4
implementation-pending state.

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
| `X509-GAP-01` | Three retained parser sites still ignore trailing DER; the shared pin path now consumes the full input. | A3/A4/A5 |
| `X509-GAP-02` | Closed: ATP's broad fallback was removed; both paths require WebPKI `UnknownIssuer`. | A2 |
| `X509-GAP-03` | Closed: both paths require explicit `serverAuth` and conditional `digitalSignature`. | A2 |
| `X509-GAP-04` | A2 keeps the shared pin-only KU check; real cross-peer parity remains pending. | A8 |
| `X509-GAP-05` | A2 keeps CA admission because rustls has no identical pre-insertion policy/diagnostic; mode parity remains pending. | A8 |
| `X509-GAP-06` | A2 keeps acceptor preflight because rustls has no identical operator diagnostic; disable-mode parity remains pending. | A8 |
| `X509-GAP-07` | Raw `ClientConfig` construction leaves all standard validation caller-owned. | A6/A7 |
| `X509-GAP-08` | Live native QUIC collapses detailed certificate errors. | A6/A8 |
| `X509-GAP-09` | wasm carries the edge without a supported TLS evidence claim. | A8/A9 |
| `X509-GAP-10` | Canonical `tls_x509_interop` result artifacts do not yet exist. | A8 |
| `X509-GAP-11` | A2 narrows both pin paths but makes no OCSP/CRL claim; supported/unsupported real-peer evidence remains pending. | A8 |
| `X509-GAP-12` | The generated API map lacks nested TLS/X.509 surfaces. | A6/A9 |

Any new call site, changed verifier boundary, lost check, unknown ownership,
or unrouted gap forces `KEEP_X509_PARSER_AND_BLOCK_CUTOVER`.

The A2 decision packet and focused validation contract are
`artifacts/x509_standard_verifier_delegation_v1.json`,
`docs/x509_standard_verifier_delegation.md`, and
`tests/x509_standard_verifier_delegation_contract.rs`.

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
