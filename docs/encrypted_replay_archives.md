# Encrypted consumer replay archives

`asupersync::io::replay_archive` protects an explicitly captured consumer window
before it leaves the capture owner. It uses the existing native RustCrypto
XChaCha20-Poly1305 dependency, not a new cipher implementation or an implicit
storage service. Existing plaintext component/session/ordered formats remain
byte-identical and independently usable.

The workflow is:

```
authorized live providers -> complete captured tapes -> explicit encrypted export
    -> caller-controlled storage/transport -> authenticate against expected identity
    -> bounded canonical decoding -> offline consumer -> verify complete replay
```

The encrypted opener never falls back to accepting a plaintext tape. Neither
constructing a key nor sealing/opening bytes creates a file, socket, task,
runtime, entropy source, or key lookup. The module is native-only, matching the
existing target gating of the crypto dependency; it does not enable browser
crypto implicitly.

## Keys and nonce namespaces are explicit obligations

Supply a **dedicated, cryptographically random 256-bit key** from the
application's secure key-management boundary. The API deliberately does not
accept passwords, derive keys from user strings, or choose ambient entropy.
`ReplayArchiveKey` owns and zeroizes its bytes; it is not cloneable or
serializable. Copies retained by the caller are outside that owner.

`key.into_sealer(unique_prefix)` consumes the key into one encryption owner.
The caller must allocate a **128-bit nonce prefix that is unique for that key
across every process, concurrent sealer, and restart**. A fresh key per sealer
is the simplest way to avoid reusing a key/prefix pair. An independently durable
namespace allocator can instead assign disjoint prefixes. This module does not
implement that allocator or infer a namespace from a process/task identity.

Do not recreate a previous key/prefix pair after a crash. Do not generate a
prefix from replayed/deterministic entropy, a timestamp, PID, or task ID and call
it unique. A deterministic fixture is appropriate only for test keys that never
protect real data. Caller misuse of this boundary can violate AEAD nonce safety.

Within its assigned namespace, the sealer combines the 16-byte prefix with a
little-endian 64-bit counter. Independent and ordered captures share that one
counter. It is consumed before encryption, is never restored after an encryption
failure, and permanently refuses after its final value rather than wrapping.
No counter reset, cloning, or serialization method is exposed. This local
uniqueness rule is not a claim that an arbitrary lifetime message/byte volume
under one key is cryptographically appropriate; key rotation remains policy.

## Bind the archive to trusted external expectations

`ReplayArchiveBinding` contains two public 32-byte commitments:

- `source`: a caller-defined fingerprint covering source/build/configuration and
  the consumer/capture scope needed to reproduce it.
- `capture`: a caller-defined unique capture identity, such as a digest of the
  incident/capture identifier.

An opener requires the **expected** binding, obtained from trusted application
metadata. Copying the binding from the untrusted archive defeats its purpose.
The sealer neither computes these commitments nor verifies their real-world
meaning. They are authenticated claims by a key holder, not code attestation.
A wrong key, changed identity, or modified authenticated bytes returns a redacted
refusal without exposing a partially decoded tape.

## Preserve the requested replay fidelity

| Capture | Seal | Open |
|---|---|---|
| Independent I/O + entropy + clock | `seal_session` | `open_session` |
| Ordered completed-effect V1 or poll-aware V2 | `seal_ordered` | `open_ordered` |
| Ordered with required pending-poll fidelity | `seal_ordered` | **`open_poll_aware`** |

The separate authenticated profiles reject switching an independent session
into the ordered decoder. `open_poll_aware` additionally rejects an authentic
completed-only V1 tape instead of silently weakening the caller's requirement.
A poll-aware tape remains V2 even if it happened to contain no pending polls.

```rust,ignore
use asupersync::io::replay_archive::{ReplayArchiveBinding, ReplayArchiveKey};

// `capture` is a completed OrderedRecordedSession. The key/prefix originate
// outside captured providers, at the application's secure provisioning boundary.
let binding = ReplayArchiveBinding {
    source: expected_build_and_capture_fingerprint,
    capture: unique_incident_fingerprint,
};
let mut sealer = ReplayArchiveKey::new(provisioned_fresh_key)
    .into_sealer(provisioned_unique_prefix);
let ciphertext = sealer.seal_ordered(&capture, binding, max_ciphertext_bytes)?;

// Persist/transport ciphertext explicitly using the application's own authority.
// At a separate analysis boundary, load an independently provisioned opening key.
let opening_key = ReplayArchiveKey::new(opening_key_bytes);
let restored = opening_key.open_poll_aware(
    ciphertext.as_ref(), binding, max_ciphertext_bytes, explicit_decode_limits,
)?;
let result = restored.replay().run(max_consumer_polls, reconstructed_consumer).await?;
// `result` may correctly reproduce the original application failure.
```

Authentication does not establish replay completion or application success. The
existing replay driver still verifies every component and ordering entry before
returning the consumer's output. The manual-driving path still requires its
`verify_complete` check. Ordered replay retains its existing scope: no original
wake timing, total concurrent-program schedule, unwrapped side effects, process
memory restoration, or arbitrary-future progress guarantee is added here.

## Envelope and resource admission

V1 uses this exact byte layout; integers are little-endian:

```
magic "ASUPENC\0"[8] | version:u32=1 | profile:u8 | zero[3]
plaintext_length:u64 | nonce[24] | source[32] | capture[32]
ciphertext[plaintext_length] | authentication_tag[16]
```

Profiles are 1 for an independent canonical session and 2 for a canonical
ordered session. All 112 header bytes are AEAD associated data. There is no
algorithm negotiation, alternate cipher, or unencrypted profile. Encoded size,
public identities and nonce remain visible; content is encrypted, not padded.

The entire ciphertext bound and the independently selected plaintext bound are
checked with exact framing and checked arithmetic before decryption allocation.
Only authenticated plaintext reaches the existing canonical decoder. Its
component encoded/count/storage limits and, for ordered data, order coverage and
pending-fingerprint limits all remain enforced. Valid encryption cannot admit
an oversized or internally invalid tape.

Sealing passes the remaining budget to existing canonical encoders, which can
have their own temporary component buffers. Scratch plaintext and output owners
zeroize on success, refusal and unwind. Live tapes, each bounded temporary copy,
decoded objects, allocator overhead, caller-owned input and replay cursors must
all be included in application memory accounting. One ciphertext-byte bound is
not a total RSS guarantee. Sealing/opening are synchronous operations with
size-proportional work, not a delivered-poll or wall-clock cancellation bound.

## Security and ownership limits

This is symmetric authenticated encryption, not sender-signature provenance,
malware inspection, redaction, or access revocation. Any holder of the key can
read or create an archive. Replaying the same authentic bytes with the same
expected binding is allowed; prevent rollback/reuse through separately trusted
capture selection/versioning when required. Error categories can reveal public
format/bound information; this is not a constant-time parser claim.

The original tapes may contain plaintext reads, cryptographic material, and
activity patterns. Keep original captures, copied keys/bytes, files, backups,
logs and swap under appropriate caller controls. Zeroizing these Rust owners
does not securely erase all copies or a storage device. Opening an archive does
not authorize running arbitrary supplied code: consumers are reconstructed by
the caller, not loaded from the capture.

## Regression coverage and execution status

The module has 17 unit regressions, including an independent libsodium fixed
wire vector, exhaustive bit/prefix mutations of a fixture, nonce exhaustion,
identity/key/profile substitution, component/storage bounds, no plaintext
fallback, preserved V1/V2 bytes, required-pending downgrade refusal, and actual
offline consumer replay. Two public native tests capture an application failure
over real loopback TCP, export only ciphertext, and invoke a fresh process which
reconstructs offline providers and reproduces the exact error. A one-Pending
write wrapper witnesses pending fidelity without guessing OS scheduling.

```sh
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p asupersync --lib io::replay_archive::
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p asupersync --test replay_archive_native
```

These Rust tests were authored but not compiled or run in the authoring session:
Rust, Cargo, rustfmt and RCH were unavailable. Independent execution of system
libsodium verifies the fixture/reference envelope, not the Rust implementation,
native scheduler behavior, security review, or release readiness.
