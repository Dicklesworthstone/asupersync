# Minimal X.509 DER residue specification

<!-- X509_DER_RESIDUE_SPEC_BEGIN -->

This document is the operator-readable form of
`artifacts/x509_der_residue_spec_v1.json` for
`asupersync-0h6myr.3.3` (`CAP-TLS-X509`). A3 is specification-only:
`SPECIFICATION_ONLY_NO_IMPLEMENTATION`.

The reader described here does not replace rustls/WebPKI. It exists only for
the four non-delegable facts retained by the A1 inventory and the A2
standard-first decision.

## Authority boundary

The planned reader accepts exactly one complete certificate DER byte slice and
a compile-time profile. It accepts no clock, server name, root store,
intermediate chain, signature algorithm, revocation policy, callback, network,
filesystem, or global configuration.

It cannot express:

- chain construction;
- certificate or TLS handshake signature verification;
- trust-anchor selection or validation;
- hostname/IP matching or wildcard interpretation;
- name-constraint or certificate-policy evaluation;
- revocation or OCSP decisions; or
- algorithm-strength or negotiation policy.

The implementation is planned as crate-private `src/tls/der_min.rs`. It must
use safe Rust, no recursion, checked arithmetic, deterministic errors, borrowed
selected DER, and only hard-bounded collections.

## Four profiles

| Profile | Selected output | Caller-owned policy |
| --- | --- | --- |
| `X509-PROFILE-SPKI` | Complete encoded `subjectPublicKeyInfo` TLV | SHA-256 hashing and pin comparison |
| `X509-PROFILE-ROOT-CA` | BasicConstraints `Absent` or `Present { ca }` fact | Require presence plus `ca=true` before insertion; preserve diagnostics |
| `X509-PROFILE-ACCEPTOR-PREFLIGHT` | Validity Unix seconds and nonempty CN/OU/O presence | Current-time comparison, chain index, strict-mode diagnostics |
| `X509-PROFILE-PINNED-LEAF` | Validity plus absent/present EKU, KU, and SAN facts; present values expose only `serverAuth`, `digitalSignature`, and bounded DNS/IP entries | Require EKU with `serverAuth`, reject present KU without `digitalSignature`, require matching SAN, and compare time after `UnknownIssuer` plus exact leaf identity |

The reader returns facts. In particular, it never receives a server name or
clock, so it cannot perform general hostname or validity validation. Absence
of BasicConstraints, EKU, KU, or SAN is an output fact rather than a reader
error; the caller retains every require/presence decision.

SPKI, root-admission, and acceptor-preflight profiles do not reject unknown
critical extensions and make no critical-extension acceptance claim. Their
downstream owner remains responsible; in particular, root admission does not
promise that a later trust-anchor path will reject such an extension. The
exact-pin branch has no successful standard path, so its profile rejects every
critical extension except the exact understood set:

```text
2.5.29.15  KeyUsage
2.5.29.17  SubjectAltName
2.5.29.37  ExtendedKeyUsage
```

Every duplicate extension OID is rejected under every profile. The pin profile
also rejects duplicate EKU purpose OIDs. Unknown noncritical extension values
remain opaque after bounded outer parsing.

## Exact resource envelope

| Limit | Value |
| --- | ---: |
| Certificate DER | 1,048,576 bytes |
| TLV depth | 16 |
| TLV nodes | 4,096 |
| OID content | 64 bytes |
| INTEGER content | 262,144 bytes |
| BIT STRING content | 262,144 bytes |
| Complete SPKI DER | 262,144 bytes |
| Extensions | 64 |
| One extension value | 262,144 bytes |
| Subject RDNs / attributes | 128 / 256 |
| DirectoryString | 4,096 bytes |
| EKU purposes | 64 |
| SAN entries | 128 |
| DNS SAN | 253 bytes |

Limits are checked before allocation or slicing, with domain-specific A4/A5
evidence. Certificate size uses well-formed N−1/N inputs and pre-parse N+1
rejection. Private TLV-reader depth/node tests use isolated bounded N−1/N/N+1
fixtures without creating a production generic-reader API. Other monotonic
limits use profile-valid N−1/N inputs and exact N+1 limit errors.

The outer Certificate is depth one and node one. Every decoded outer TLV and
every decoded selected-extension inner TLV counts once; entering any
constructed child, including an inner extension root, increments depth. The
reader enters certificate/TBSCertificate structure, Name components, validity,
both signature AlgorithmIdentifiers, the outer `signatureValue` BIT STRING,
SPKI structure, outer Extensions rows, and profile-selected extension grammar.
OID, INTEGER, and BIT STRING limits apply to all entered outer mandatory fields
and selected inner values. Subject RDN/attribute limits are subject-only;
issuer Name is traversed without retaining those collections. Algorithm
parameters, unselected attribute values, and unsupported noncritical
GeneralName contents are bounded complete TLVs but are not entered.

Length octets are a derived invariant: an accepted canonical value under the
1 MiB cap needs at most three. Tests instead distinguish canonical,
nonminimal, overflow, bounds, and EOF paths. IP SAN is a semantic domain:
exactly 4 or 16 octets are accepted and every other length is rejected; it is
not treated as a monotonic below/above resource limit.

## DER canonicality

The artifact carries eighteen individually testable rules:

1. one nonempty outer Certificate SEQUENCE with full input consumption;
2. definite lengths only;
3. shortest length encoding;
4. checked offsets bounded by parent and input;
5. no high-tag-number form and exact schema tag class/number;
6. correct constructed bit;
7. canonical BOOLEAN (`00` or `FF`);
8. nonempty minimally sign-extended INTEGER;
9. a nonempty BIT STRING content envelope, valid unused-bit count and zero
   unused bits, plus minimal KeyUsage NamedBitList encoding with at least one
   set bit and no set bit above bit 8;
10. zero-length NULL;
11. minimal, terminating, non-overflowing OID base-128 encoding;
12. lexicographic complete-child DER ordering for traversed SET OF values;
13. omitted DER DEFAULT values for entered values: v1 version and
    `critical=FALSE` globally, plus BasicConstraints `cA=FALSE` when selected;
14. mandatory and optional certificate fields exactly once and in order;
15. exact Extension field shape;
16. no duplicate extension OID;
17. full inner consumption and exact BasicConstraints, KeyUsage, EKU, and SAN
    grammar; and
18. pin-profile-only EKU purpose uniqueness, with nonemptiness owned by rule
    17.

BER/CER indefinite lengths, nonminimal long lengths, trailing bytes, unchecked
offsets, ambiguous duplicates, and over-limit values fail closed.

Selected extension grammar is exact. BasicConstraints permits optional
`cA` followed by optional nonnegative `pathLenConstraint`; explicit false is
rejected and a path length requires `cA=true`. KeyUsage is a minimal
NamedBitList. EKU is a nonempty unique OID sequence. SAN is a nonempty
GeneralNames sequence: dNSName is 1–253 IA5 ASCII bytes and iPAddress is
exactly 4 or 16 bytes. A3 performs no DNS-label validation or normalization.
Other GeneralName forms have canonical outer context-specific TLV framing and
bounded content but their constructed contents remain opaque, so A3 makes no
nested-DER canonicality claim for them. They are skipped only in a noncritical
SAN; an unsupported form in a critical SAN is rejected even though the SAN OID
itself is allow-listed.

## Time and string policy

`UTCTime` is exactly `YYMMDDHHMMSSZ`; 50–99 means 1950–1999 and 00–49 means
2000–2049. `GeneralizedTime` is exactly `YYYYMMDDHHMMSSZ`. Fractions, numeric
offsets, invalid Gregorian dates, leap seconds, and `notBefore > notAfter` are
rejected. Either time tag is deliberately accepted at either validity endpoint
because relying applications must process both. Output is checked `i64` Unix
seconds; the reader owns no clock.

Subject presence recognizes only CN (`2.5.4.3`), O (`2.5.4.10`), and OU
(`2.5.4.11`) with a nonempty canonical UTF8String, PrintableString,
UniversalString, or BMPString. It performs no normalization, case folding,
locale mapping, distinguished-name comparison, or display rendering.
TeletexString is not recognized for presence because A3 defines no T.61
decoder. A structurally complete TeletexString no larger than
`max_directory_string_bytes` therefore returns
`SubjectIdentityPresence=false` without `X509-DER-STRING`; malformed supported
encodings use that error. A5 owns differential evidence for the compatibility
boundary.

## Stable failure model

The artifact defines thirty stable `X509-DER-*` error classes covering empty
or trailing input, limits, EOF, lengths, arithmetic, bounds, tags, constructed
bits, depth/nodes/counts, primitive canonicality, SET order, schema/default
rules, duplicates, unknown critical extensions, selected-extension parsing,
time ordering, strings, and missing selected fields.

An error is a closed enum of exactly those thirty classes. It carries an
absolute zero-based checked input offset no greater than the input length;
offset zero is valid for the empty-input error, and otherwise only
`X509-DER-UNEXPECTED-EOF` may report the one-past-end offset. Optional detail
is fixed-shape bounded numeric `observed` and `limit` data. Errors never
embed raw certificate bytes, subject/SAN text, OID text, attacker-selected
field names, or cryptographic detail.

## Review and implementation gate

Independent review is mandatory before A4 implementation begins. The checked
artifact must record:

- `review_gate.state = APPROVED`;
- a reviewer different from `GreenCove`;
- the exact reviewed draft SHA-256 and independent review receipt;
- a recomputed SHA-256 of the canonical normative projection; and
- `implementation_may_begin = true`.

Until those fields are present, the executable A3 contract fails closed and A4
must not begin. The normative projection excludes review evidence and only the
hash/line-count pins of the three A1 reconciliation files that necessarily
change after approval; every path, role, and all other semantics remain hashed.

## Downstream proof

A4 owns the safe reader implementation and per-rule boundary tests. A5 owns
independent differential, mutation, property, corpus, and bounded-fuzz
evidence. A6 owns serialized migration. A7 owns independent security review.
A8 owns real-peer interoperability and diagnostic parity.
Only A9 may decide a dependency cutover.

## No-claim boundary

This specification does not implement or prove a reader, validate a chain or
signature, choose trust, match a hostname, enforce name constraints, validate
revocation/OCSP, replace rustls/WebPKI, remove `x509-parser`, change Cargo
features or the lockfile, prove A8 interoperability, prove performance, or
authorize unsafe code, file deletion, local Cargo fallback, or implementation
before independent approval.

<!-- X509_DER_RESIDUE_SPEC_END -->
