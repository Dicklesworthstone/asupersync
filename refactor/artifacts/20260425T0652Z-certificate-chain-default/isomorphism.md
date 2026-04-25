# Isomorphism Proof: TLS Empty Constructor Delegation

## Change

Delegate `CertificateChain::new()` in `src/tls/types.rs` to the already-derived
`Default` implementation, and route the two empty `CertificatePinSet`
constructors through one private helper that preserves the `enforce` bit.
Also delegate `CertificateChain` PEM conversion through `Result::map(Self::from)`
instead of spelling the same `?`/`Ok(Self::from(...))` conversion inline.

## Preconditions

- `CertificateChain` derives `Default`.
- `CertificateChain` has one field: `certs: Vec<Certificate>`.
- `Vec::<Certificate>::default()` is equivalent to `Vec::new()`.
- `CertificatePinSet::new()` and `CertificatePinSet::report_only()` previously
  differed only by `enforce: true` versus `enforce: false`.
- Both `CertificatePinSet` constructors initialize `pins` to an empty
  `BTreeSet<CertificatePin>`.
- `Result::map(Self::from)` applies the same conversion only on `Ok` and
  propagates the original `TlsError` unchanged on `Err`.

## Field Mapping

| Constructor | Field | Previous value | Delegated value |
| --- | --- | --- | --- |
| `CertificateChain::new()` | `certs` | `Vec::new()` | empty `Vec<Certificate>` |
| `CertificatePinSet::new()` | `pins` | `BTreeSet::new()` | `BTreeSet::new()` |
| `CertificatePinSet::new()` | `enforce` | `true` | `true` |
| `CertificatePinSet::report_only()` | `pins` | `BTreeSet::new()` | `BTreeSet::new()` |
| `CertificatePinSet::report_only()` | `enforce` | `false` | `false` |
| `CertificateChain::from_pem_file()` | success conversion | `Ok(Self::from(certs))` | `.map(Self::from)` |
| `CertificateChain::from_pem()` | success conversion | `Ok(Self::from(certs))` | `.map(Self::from)` |

## Behavior Preservation

- `CertificateChain::new()` still returns an empty certificate chain.
- `len()` and `is_empty()` behavior are unchanged.
- `CertificatePinSet::new()` remains enforce-by-default.
- `CertificatePinSet::report_only()` still disables enforcement.
- `CertificateChain` PEM loaders still return the same `Ok` chain and preserve
  the same `TlsError` values.
- TLS and non-TLS feature-gated certificate parsing paths are unchanged.
- Public API and all existing call sites are unchanged.
