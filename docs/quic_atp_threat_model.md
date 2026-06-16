# RaptorQ-over-QUIC (ATP) threat model

> Bead: `asupersync-arq-quic-epic-b0k8qo.7.4` ("G4"). Scope: the ATP transport
> that moves RaptorQ symbols over QUIC (`src/net/quic_native/`,
> `src/net/atp/quic/`, `src/net/atp/transport_rq/`). This is the protocol-specific
> companion to the general [`security_threat_model.md`](./security_threat_model.md)
> and the messaging-fabric [`FABRIC_THREAT_MODEL.md`](./FABRIC_THREAT_MODEL.md);
> it does not restate runtime-wide capability-security claims.

This document states what an attacker can and cannot do against an ATP transfer
over the open internet, which mitigations are implemented (with their pinning
tests), and — explicitly — which gaps remain so the path can be kept **fail
closed** until they close (README QUIC row; `asupersync-7pwwwe`).

## 1. System and trust boundaries

ATP combines two layers (see the epic and `docs/quic_wire_format.md`):

- **Coding layer (RaptorQ):** a file/block becomes interchangeable *symbols*; any
  K-of-N decode. Symbols are opaque application payloads.
- **Transport substrate (QUIC):** symbols ride **unreliable QUIC DATAGRAMs**
  (RFC 9221) so QUIC retransmission never fights the fountain; a **reliable QUIC
  stream** carries the control channel (manifest / feedback / proof).

Trust boundaries crossed by attacker-controlled bytes:

| Boundary | Carried over | Parser / verifier |
|----------|--------------|-------------------|
| Peer identity | QUIC handshake (TLS 1.3) | `quic_native::tls` X.509 verification (client) |
| Packet confidentiality/integrity | 1-RTT AEAD | `atp::quic::packet_protection` |
| Symbol authenticity | DATAGRAM payload (RaptorQ symbol) | RaptorQ symbol HMAC (`transport_rq`) |
| Control channel / manifest | QUIC stream | application framing (see gaps) |

## 2. Adversary model

Primary adversary: an **on-path (MITM) attacker** between two ATP peers on the
open internet who can read, drop, reorder, duplicate, and inject UDP packets, and
can attempt to impersonate the server. Also considered: an **off-path** attacker
(spoofed source addresses, amplification) and a **malicious peer** that completes
a connection but sends forged/garbage symbols.

Out of scope: host compromise, side channels, key-material exfiltration, traffic
analysis / metadata confidentiality, and denial of service from a fully on-path
attacker who simply drops all packets (unpreventable at this layer).

## 3. Threats × mitigations

| Threat | Mitigation (implemented) | Pinning test | Residual gap |
|--------|--------------------------|--------------|--------------|
| **Server impersonation / MITM** | Client X.509 verification (chain + hostname + signature) against configured roots; **fail closed** — a client cannot reach `Established` unless a genuine verification recorded the identity (`record_verified_server_identity`); **no insecure skip-verify default** | `tests/quic_native_x509_verification.rs`, `tests/quic_legacy_no_accept_all_cert_verifier.rs` | The in-handshake **driver** that runs this from exchanged CRYPTO is not wired (see §5.1); verification is application-supplied today |
| **Symbol injection / forgery** | Per-symbol HMAC auth; `transport_rq` default posture is `MissingAuthenticationContext` → `send_path`/`receive_once` **refuse to run before any I/O** unless the caller chooses `with_symbol_auth(ctx)` (every UDP symbol signed+verified) or the explicit `allow_unauthenticated_for_trusted_transport()` opt-out; handshake rejects posture mismatch both directions | `tests/atp_rq_symbol_auth_e2e_contract.rs`, `tests/decoding_secure_default.rs` | Authenticated mode protects the **UDP symbol plane only** — the control channel + manifest are unauthenticated (see §5.3) |
| **Packet tampering** | 1-RTT AEAD (encrypt+authenticate) + header protection | `atp::quic::packet_protection` inline tests (round-trip / tamper / header-protection) | AEAD/header-protection is implemented and unit-tested, but its interposition in the live send/recv path is part of the §5.1 data-plane integration — the current deterministic loopback exchanges unprotected frames, so this is not yet an end-to-end guarantee |
| **Replay** | Bounded per-PN-space replay window (`REPLAY_WINDOW_CAPACITY = 1024`, span 1023): duplicate or too-old packet numbers rejected | `packet_protection.rs` replay-window inline tests | Window is bounded by design; very-old packets outside the window are dropped, not replay-checked individually. Like AEAD, the window is exercised at unit level and not yet interposed in a live transfer (§5.1) |
| **Amplification / off-path DoS** | Server anti-amplification accounting (`anti_amplification_bytes_received/sent`, `AmplificationLimited` error) bounds bytes sent to an unvalidated peer address until validation | `connection.rs` anti-amplification inline coverage | Standard QUIC 3× envelope; not a defense against on-path floods |
| **Resource exhaustion (memory)** | Bounded inbound/outbound DATAGRAM queues (256-deep: receive drops oldest, send applies backpressure — never unbounded growth) | `tests/quic_datagram_send_path.rs`, `tests/quic_datagram_recv_path.rs` | The fountain feedback-round cap (`DEFAULT_MAX_FEEDBACK_ROUNDS`) is a config default for the not-yet-wired B2/B3 coroutine, not an active mitigation today |
| **Posture downgrade** | Auth-mode mismatch between peers rejected in both directions before transfer | `tests/atp_rq_symbol_auth_e2e_contract.rs` | — |

## 4. Current security posture (summary)

Implemented and pinned: fail-closed client identity gate (no silent-accept MITM),
1-RTT AEAD + replay window, fail-closed RaptorQ symbol authentication posture,
anti-amplification accounting, bounded queues. The prior silent-accept exposure
(`asupersync-7pwwwe`) is removed: the client path returns
`ServerCertificateUnverified` rather than accepting an unverified server.

## 5. Open gaps and no-claim boundaries

These are the reasons ATP must **not** be treated as proven-safe against an active
MITM over the open internet until they close. Each currently keeps the path fail
closed or explicitly opt-in rather than silently insecure.

### 5.1 Wire-CRYPTO handshake driver is not implemented
The native QUIC connection advances handshake/1-RTT keys via **explicit transition
calls** (`begin_handshake` → `on_handshake_keys_available` →
`on_1rtt_keys_available` → `on_handshake_confirmed`); receiving a `CRYPTO` frame
only nudges `Idle → Handshaking`. There is no TLS-over-CRYPTO state machine that
completes a handshake from **exchanged bytes**. Consequently there is no
production wire-handshake path two endpoints can use to establish over the
network yet; what holds the line is the connection's fail-closed identity gate,
which rejects any attempt to confirm a client handshake without a recorded
verified identity rather than silently accepting one.
`asupersync-arq-quic-epic-b0k8qo.1.5` ("A5") delivered
the X.509 *verification* half but not this *driver* half; it is the prerequisite
for the A7 real-UDP loopback proof. **Until it lands, "secure over the open
internet" is unproven, not merely unfinished.**

### 5.2 quic_native TLS does no standalone in-handshake X.509
The `quic_native` TLS layer does not itself perform certificate exchange. The
verifying path (`tls` feature, rustls/WebPKI) validates the chain and then calls
`record_verified_server_identity()`. Applications that do not run a verifying
handshake get a connection that **fails closed** (cannot confirm), which is the
intended safe default — but it means identity assurance is the application's
responsibility through the capability-gated verifier, not an automatic guarantee.

### 5.3 Control channel and manifest are unauthenticated
Authenticated symbol mode protects the **UDP symbol plane only**. The QUIC-stream
control channel and the transfer **manifest** are not authenticated at the ATP
layer. A full MITM who can substitute a matching forged manifest **and** forged
symbols is therefore not prevented by symbol auth alone. Full Byzantine-injection
resistance requires `with_symbol_auth` **and** an authenticated control
channel / manifest (e.g. carried inside the verified TLS channel once §5.1
lands).

### 5.4 transport_tcp has no per-symbol authentication
The sibling `transport_tcp` transport provides integrity-vs-manifest only (no
per-symbol HMAC). It is not part of the QUIC path but shares the RaptorQ coding;
do not assume QUIC's symbol-auth guarantees apply to it.

## 6. Fail-closed verdict and pre-open-internet checklist

Verdict: the ATP-over-QUIC path is **fail-closed-by-construction** today —
unverified server identity, missing symbol-auth context, posture mismatch, oversize
datagrams, and amplification limits all refuse rather than proceed insecurely.
It is **not yet proven safe against an active MITM over the open internet.**

Before claiming open-internet safety (epic success criterion #5), these must land
and be pinned by tests (G4 acceptance, part a — owned by the respective Phase A
beads):

- [ ] Wire-CRYPTO handshake driver completing the handshake from exchanged bytes (§5.1, `b0k8qo.1.5` driver remainder / blocks `b0k8qo.1.7`).
- [ ] End-to-end bad-cert rejection over the real handshake: expired / wrong-hostname / untrusted-root → fail closed (extends `quic_native_x509_verification`).
- [ ] Authenticated control channel + manifest, or manifest carried inside the verified TLS channel (§5.3).
- [ ] Forged/auth-failing symbol rejected on the real UDP path (extends `atp_rq_symbol_auth_e2e_contract`).
- [ ] Amplification + replay bounds asserted on the real transport (not just unit level).

## 7. References

- Code: `src/net/quic_native/{connection.rs,tls.rs}`, `src/net/atp/quic/packet_protection.rs`, `src/net/atp/transport_rq/mod.rs`.
- Tests: `tests/quic_native_x509_verification.rs`, `tests/quic_legacy_no_accept_all_cert_verifier.rs`, `tests/atp_rq_symbol_auth_e2e_contract.rs`, `tests/decoding_secure_default.rs`, `tests/quic_datagram_send_path.rs`, `tests/quic_datagram_recv_path.rs`.
- Wire format: `docs/quic_wire_format.md`. Prior audit: `docs/atp_security_audit_phase4_summary.md`.
