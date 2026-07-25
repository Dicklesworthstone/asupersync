# NKey normative format, key-type and signer-policy specification

<!-- BEGIN NKEY NORMATIVE SPEC -->

This is the operator-readable companion to
`artifacts/nkey_normative_spec_v1.json`. It freezes `CAP-NKEY-AUTH` for
`asupersync-dep-p4-nkeys-poc60v.1.1` at revision
`d14477867f3b8d3472443b87ba0851a440af61a6`.

The specification has zero unknown or ambiguous rows. N2-N6 may implement the
frozen rows, but production integration, cutover and dependency removal remain
forbidden. A newly discovered unknown or ambiguity blocks its affected child
until this artifact, document and contract change together.

## Authority and scope

The target is the full nominal format, not only the User keys exercised by
current production code:

- public `N`, `C`, `O`, `A`, `U`, `M`, `V` and `X` forms;
- typed `SN`, `SC`, `SO`, `SA`, `SU`, `SM`, `SV` and `SX` seeds;
- both `P` forms: 64-byte expanded Ed25519 private material and 32-byte X25519 secret material;
- canonical Base32 and CRC16-XMODEM;
- strict Ed25519/X25519 operation separation;
- Operator, Account, User and same-kind delegated-signing policy;
- exact error, secret, concurrency, resource and downstream obligations.

The official Go implementation defines `N/C/O/A/U/X`, `S`, `P` and the
unknown `Z` sentinel. Rust `nkeys` additionally defines `M` and `V`. Those two
forms are preserved Ed25519 extensions, but they have no NATS JWT hierarchy
authority.

The canonical upstream inputs are pinned in the artifact:

- Rust `nkeys` 0.4.5, crates.io checksum
  `879011babc47a1c7fdf5a935ae3cfe94f34645ca0cac1c7f6424b36fc743d1bf`;
- official `nats-io/nkeys` 0.4.16 at commit
  `c1eebf38bd8b1b1021b45b5f8f403052ac042dc5`;
- official NATS JWT hierarchy and signing-key documentation.

The incumbent remains `KEEP_UNTIL_PARITY` / `KEEP_INCUMBENT`.

## Canonical textual encoding

The alphabet is RFC 4648 Base32
`ABCDEFGHIJKLMNOPQRSTUVWXYZ234567`, uppercase only, with no `=` padding.
Whitespace, separators, lowercase, invalid alphabet bytes, non-zero unused
trailing bits, partial consumption and any decode/re-encode mismatch are
rejected.

Public keys have this decoded layout:

```text
[typed prefix: 1][public material: 32][CRC16-XMODEM little-endian: 2]
```

That is 35 decoded bytes and exactly 56 Base32 characters.

Seeds have this decoded layout:

```text
[packed seed/type prefix: 2][raw secret seed: 32][CRC16-XMODEM little-endian: 2]
```

That is 36 decoded bytes and exactly 58 Base32 characters. For public prefix
byte `p`:

```text
b1 = 0x90 | (p >> 5)
b2 = (p & 0x1f) << 3
```

Decoding reverses that packing:

```text
outer = raw[0] & 0xf8
inner = ((raw[0] & 0x07) << 5) | ((raw[1] & 0xf8) >> 3)
```

`outer` must be `0x90`, `inner` must be an allowed typed prefix, and the low
three bits of `raw[1]` must be zero. The Rust incumbent currently omits the
inner-prefix validation; the cross-prefix corpus captures the resulting
Operator type confusion.

Private keys have this decoded layout:

```text
[P prefix 0x78: 1][private material: 32 or 64][CRC16-XMODEM little-endian: 2]
```

The 32-byte X25519 form is 56 characters. The 64-byte expanded Ed25519 form is
108 characters. `P` does not carry a role, so an untyped private string grants
no operation. It must be imported into an explicit owned algorithm and role
context.

CRC16-XMODEM uses polynomial `0x1021`, initial value and xor-out `0x0000`, no
reflection, and covers every prefix and payload byte before the checksum. The
checksum is serialized little-endian. It detects corruption only; it is not
authentication, collision resistance or a MAC.

## Prefix and operation matrix

| Form | Byte | Meaning | Operations | Policy role |
| --- | ---: | --- | --- | --- |
| `A` / `SA` | 0 | Account Ed25519 | sign/verify with seed; verify with public | Account identity or listed Account signing key |
| `C` / `SC` | 16 | Cluster Ed25519 | sign/verify | no JWT hierarchy authority |
| `M` / `SM` | 96 | Rust Module Ed25519 extension | sign/verify | no JWT hierarchy authority |
| `N` / `SN` | 104 | Server Ed25519 | sign/verify | no O/A/U JWT hierarchy authority |
| `O` / `SO` | 112 | Operator Ed25519 | sign/verify | Operator identity or listed Operator signing key |
| `P` | 120 | 32-byte X25519 or 64-byte expanded Ed25519 private | none until typed import | never by itself |
| `S` | 144 | typed 32-byte seed container | none until typed decode | selected by inner prefix |
| `U` / `SU` | 160 | User Ed25519 | sign/verify | server challenge only; never JWT issuer |
| `V` / `SV` | 168 | Rust Service Ed25519 extension | sign/verify | no JWT hierarchy authority |
| `X` / `SX` | 184 | X25519 / NaCl-box compatible Curve key | seal/open only | never a signer |
| `Z` | 200 | unknown sentinel | reject | never |

Ed25519 public keys verify but cannot sign. Ed25519 seeds sign and verify.
X25519 public keys may be recipients/senders for Curve operations but cannot
open without secret material. X25519 seeds/private keys seal and open but
cannot sign or verify Ed25519 signatures.

An untyped `P` value is deliberately inert. Public, seed, private, Ed25519 and
X25519 types cannot be substituted for one another.

## Incumbent Curve mismatch

The root manifest enables no `nkeys` features. The real Rust `XKey` API is
therefore absent from the current build.

Nevertheless, the base `KeyPairType` contains `Curve`. Passing it to
`KeyPair::new_from_raw`, or decoding an `SX` seed through `KeyPair::from_seed`,
constructs an Ed25519 signing key, labels its text with `X`, and permits
Ed25519 sign/verify. That is not X25519 and is explicitly non-normative.

The official historical Curve pair proves the distinction:

```text
SXAKIYZX2POLIHZ5W5YZEWVTH24NLEUETBW3TKIVYRSS3GNHFXO5D4JJZM
XBUJMZHVOPQ2SK5VD3TY4VNBPVU2YFGRLK6EFPEPSMVDUYEBSROWZCEA
```

The feature-gated `XKey` and official Go implementation derive that X25519
public key. Base Rust `KeyPair` derives a different Ed25519-labeled `X` key.
N3/N4 must make this confusion unrepresentable. Curve keys never implement signing traits.

## JWT signer authorization

Cryptographic validity does not imply authorization.

The NATS trust hierarchy is:

```text
configured Operator trust anchor
  -> Account JWT
    -> User JWT
      -> User signs the server nonce
```

The exact allowed relationships are:

1. An Operator identity self-signs its Operator JWT.
2. The trusted Operator identity, or a same-kind Operator signing key listed
   in that Operator JWT, signs an Account JWT.
3. The resolved Account identity, or a same-kind Account signing key listed
   in that Account JWT, signs a User JWT.
4. A User seed signs the server challenge, and its public key equals the User
   JWT subject using a constant-time comparison.
5. When an Account signing key is used, `issuer_account` names the represented
   Account and any scoped signing-key permissions allow the claim.

The following always fail closed:

- an unlisted same-kind signing key;
- Operator-to-User or Account-to-Account hierarchy skips;
- User-issued JWTs;
- `N`, `C`, `M`, `V` or `X` issuers for O/A/U claims;
- missing, empty or malformed issuer;
- a valid signature whose parent chain is absent, stale or revoked;
- a missing or non-`ed25519-nkey` algorithm;
- temporal, revocation or delegated-scope failure.

The current NATS parser pins `ed25519-nkey`, rejects missing/empty issuer,
verifies directly against `iss`, checks optional expiry with sixty seconds of
leeway, and constant-time compares `sub` with the nonce-signing User key. It
does not authorize the Operator/Account/delegated chain. That gap is routed to
N5, and the current direct-issuer check is not a complete signer policy.

## Public and downstream API

The full source read found six production files.

`src/security/keys/mod.rs` owns User-only persistent identities, entropy sanity
checks, domain-separated fingerprints, rotation, revocation, history,
platform permission classification and redacted Debug. Its
`IdentityKeyStore::active_key_pair` is the only public function returning an
`nkeys::KeyPair`. N3 replaces that direct dependency type with an owned signer;
no permanent compatibility shim is allowed.

`src/messaging/nats.rs` owns `.creds` markers and parsing, User-only seed
loading, nonce bounds, nonce signing, compact JWT parsing, algorithm pinning,
issuer signature checking, expiration, constant-time subject binding and
CONNECT emission. `NatsConfig` Debug redacts all credentials.

`src/atp/identity/mod.rs` accepts only User public keys for durable ATP
identity, deriving `PeerId`, key fingerprint and `nkey-ed25519` proof metadata.

`src/atp/policy/verification.rs` signs canonical capability JSON with the
active User key and verifies against trusted durable peer identities.

`src/agent_swarm/control_plane.rs` verifies domain-separated agent credentials
with freshness and an optional issuer allow-list. It currently accepts any
parseable public prefix; the replacement must declare the allowed key kind and
scope explicitly.

`src/runtime/config.rs` signs and verifies domain-separated profile bundles
with explicit key IDs, trusted public keys, revocation, issuance/expiry,
monotone epochs and digest locks. It also currently accepts any parseable
public prefix and stores an optional seed as an ordinary String.

The seven frozen journeys map to `nkey_nats_auth`,
`nkey_jwt_authorization`, `nkey_secret_redaction` and `nkey_all_forms`.
Those scenario names are present in the capability registry but absent from
the canonical dependency-sovereignty runner today. Their evidence state is
`PLANNED`, never silently green.

## Errors

The incumbent exposes nine error kinds:

```text
InvalidPrefix
InvalidKeyLength
VerifyError
SignatureError
ChecksumFailure
CodecFailure
IncorrectKeyType
InvalidPayload
InvalidSignatureLength
```

The replacement owns seventeen stable classes: length, alphabet,
noncanonicality, checksum, outer prefix, seed inner prefix, key material,
wrong kind, missing secret, signature length, signature mismatch,
unauthorized signer, algorithm, temporal policy, resource limit, Curve
operation and secret disposition.

Authorization failure is distinct from signature mismatch. Diagnostics may
include safe field, length and type metadata, but never seed/private bytes,
full credentials, JWT text, signatures or decrypted payloads.

## Secret, concurrency and resource contract

Secret owned types are not `Copy` or ordinarily `Clone`. Debug and Display
redact them. Serialization, seed/private export and plaintext persistence are
explicit opt-ins. Drop zeroizes the narrowest buffers, while allocator and
unavoidable-copy limits are stated rather than overclaimed. Authentication
cancellation wipes transient decoded material. Secret canaries may not appear
in errors, panic text, traces, logs, reports or E2E artifacts.

The incumbent falls short: `KeyPair` derives `Clone`, has no zeroizing Drop or
Wipe, and returns seeds as ordinary Strings. `IdentityKeyStore` is also Clone
and persists seed Strings in plaintext JSON. Its Debug implementation is
redacted and Unix files are hardened to `0600`; Windows ACL enforcement is
external and other platforms are best-effort.

Public verification keys are `Send + Sync` and cheaply shareable. Secret
signers may be `Send + Sync` only when the audited primitive supports it.
Concurrent signing is deterministic and race-free. No ambient RNG, mutable
global state or process-global authorization cache is introduced.

Exact parse limits are 56 public characters, 58 seed characters, 56 X25519
private characters, 108 expanded Ed25519 private characters and 64 signature
bytes. The current NATS nonce limit is 8 through 256 accepted Base64/Base64url
characters plus its repeated/sequential-pattern rejection.

Compact JWTs, creds blocks, arbitrary sign/verify messages and Curve payloads
need explicit protocol ceilings before allocation or hashing. Those bounds
and authentication-cancellation cleanup are not currently proven.

## Frozen vectors

The independent corpus uses raw secret bytes `00..1f`, Python standard-library
Base32, `binascii.crc_hqx(data, 0)` serialized little-endian, and Python
`cryptography` 43.0.0 Ed25519. It did not import or execute Rust `nkeys`.

The artifact freezes:

- eight Rust-visible seed/public rows, with the `X` row explicitly marked as
  the observed non-normative Ed25519-labeling defect;
- 32-byte X25519 and 64-byte Ed25519 `P` rows;
- a deterministic message/signature pair;
- a Rust/Go-compatible Account pair;
- a Rust/Go-compatible X25519 pair;
- the official Go decode-benchmark User seed;
- seven malformed length/alphabet/checksum/prefix/signature rows;
- three cross-prefix rows.

The critical cross-prefix seed is:

```text
SDAAAAICAMCAKBQHBAEQUCYMBUHA6EARCIJRIFIWC4MBSGQ3DQOR4HYPT4
```

It has a valid checksum and reconstructs inner prefix byte 24. Official Go
rejects it. Rust `decode_seed` returns 24, and `KeyPair::from_seed` silently
maps it to Operator because the incumbent byte-to-type conversion defaults
unknown values to Operator. N4 must reject it as `NKEY-E006` before any key is
constructed.

Unknown textual `KeyPairType` names also currently become Module. The owned
API rejects them with a typed error.

## Routed findings

Fourteen concrete findings are routed:

| Gap | Finding | Owner |
| --- | --- | --- |
| `NKEY-N1-GAP-01` | unknown seed inner prefix becomes Operator | N4 |
| `NKEY-N1-GAP-02` | base Curve is Ed25519 and can sign | N3 |
| `NKEY-N1-GAP-03` | unknown type names become Module | N3 |
| `NKEY-N1-GAP-04` | both `P` forms unavailable in current build | N4 |
| `NKEY-N1-GAP-05` | secret clones, Strings, persistence and no wipe | N3 |
| `NKEY-N1-GAP-06` | NATS lacks full signer authorization chain | N5.3 |
| `NKEY-N1-GAP-07` | swarm/profile accept unspecified key kinds | N5.2 |
| `NKEY-N1-GAP-08` | resource ceilings and cancellation wipe unproven | N6 |
| `NKEY-N1-GAP-09` | M/V extension policy must stay non-NATS | N5.2 |
| `NKEY-N1-GAP-10` | one public dependency-type leak | N3 |
| `NKEY-N1-GAP-11` | differential oracle absent | N6 |
| `NKEY-N1-GAP-12` | four canonical E2E scenarios absent | NKey E2E aggregate |
| `NKEY-N1-GAP-13` | non-Unix file-permission proof incomplete | NKey E2E aggregate |
| `NKEY-N1-GAP-14` | independent security review absent | security review |

These are known rows with normative resolutions, not unknown behavior. They
permit bounded child implementation but continue to block production cutover.

## Validation and no-claim boundary

Run the focused contract through remote compilation:

```bash
RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay \
  --overlay-path artifacts/nkey_normative_spec_v1.json \
  --overlay-path docs/nkey_normative_spec.md \
  --overlay-path tests/nkey_normative_spec_contract.rs \
  -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-D warnings -C debuginfo=0' \
  CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_nkey_normative_spec" \
  cargo test -p asupersync \
  --test nkey_normative_spec_contract -- --nocapture
```

No local Cargo fallback is approved. This lane freezes the normative contract
and the observed baseline. It does not implement the codec or owned key types,
enable incumbent `xkeys`, prove secret zeroization, signer-chain correctness,
real NATS interoperability, cancellation cleanup, resource bounds,
performance, broad workspace health, release readiness or dependency-removal
parity. It authorizes no deletion, production cutover or `nkeys` removal.

<!-- END NKEY NORMATIVE SPEC -->
