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
| **Server impersonation / MITM** | Client X.509 verification (chain + hostname + signature) against configured roots; **fail closed** — a client cannot reach `Established` unless a genuine verification recorded the identity (`record_verified_server_identity`); the native `rustls::quic` handshake driver exchanges CRYPTO bytes, installs 1-RTT keys, and has **no insecure skip-verify default** | `tests/quic_native_x509_verification.rs`, `tests/quic_legacy_no_accept_all_cert_verifier.rs`, `tests/quic_native_handshake_udp_loopback.rs`, `tests/atp_quic_real_udp_transfer_e2e.rs` | The handshake driver, production bad-cert transfer path, and verified 1-RTT control/manifest path are pinned. This is still not a fleet benchmark, release-readiness, or generic-QUIC-interoperability claim. |
| **Symbol injection / forgery** | Direct single-connection native QUIC/TLS authenticates symbol bytes with QUIC 1-RTT AEAD and header protection; relay, multipath, raw-UDP, and other cross-trust symbol planes still use `with_symbol_auth(ctx)` for per-symbol HMAC. The default posture remains fail-closed unless the caller chooses per-symbol auth or the explicit transport-authenticated posture. | `tests/atp_rq_symbol_auth_e2e_contract.rs`, `tests/decoding_secure_default.rs`, `tests/atp_quic_real_udp_transfer_e2e.rs`, `tests/quic_application_data_udp_loopback.rs` | Direct native ATP-over-QUIC pins fail-closed TLS identity and AEAD packet tamper rejection; explicit per-symbol HMAC remains the boundary for non-direct symbol planes. The sibling `transport_tcp` path still has no per-symbol authentication (see §5.4). |
| **Packet tampering** | 1-RTT AEAD (encrypt+authenticate) + header protection in the primitive packet-protection layer; the ATP-over-QUIC native link uses handshake-derived 1-RTT keys for control STREAM and symbol DATAGRAM packets | `atp::quic::packet_protection` inline tests (round-trip / tamper / header-protection), `tests/quic_application_data_udp_loopback.rs`, `tests/atp_quic_real_udp_transfer_e2e.rs` | The native ATP link uses a simplified asupersync-only short-header format, so this is not wire-interoperability proof against a generic QUIC stack. |
| **Replay** | Bounded per-PN-space replay window (`REPLAY_WINDOW_CAPACITY = 1024`, span 1023): duplicate or too-old packet numbers rejected | `packet_protection.rs` replay-window inline tests; `tests/quic_application_data_udp_loopback.rs` | Window capacity and stale-packet behavior are pinned at the crypto boundary; duplicate protected packets are now rejected through the native router over real loopback UDP without duplicate application delivery |
| **Amplification / off-path DoS** | Server anti-amplification accounting (`anti_amplification_bytes_received/sent`, `AmplificationLimited` error) bounds bytes sent to an unvalidated peer address until validation; the real UDP path also keeps pre-validation Initial responses within the 3× envelope | `connection.rs` anti-amplification inline coverage; `tests/quic_application_data_udp_loopback.rs` | Standard QUIC 3× envelope pinned through real loopback UDP pre-validation Initial responses; not a defense against on-path floods |
| **Resource exhaustion (memory)** | Bounded inbound/outbound DATAGRAM queues (256-deep: receive drops oldest, send applies backpressure — never unbounded growth) | `tests/quic_datagram_send_path.rs`, `tests/quic_datagram_recv_path.rs` | The fountain feedback-round cap (`DEFAULT_MAX_FEEDBACK_ROUNDS`) is a config default for the not-yet-wired B2/B3 coroutine, not an active mitigation today |
| **Posture downgrade** | Auth-mode mismatch between peers rejected in both directions before transfer | `tests/atp_rq_symbol_auth_e2e_contract.rs` | — |

## 4. Current security posture (summary)

Implemented and pinned: fail-closed client identity gate (no silent-accept MITM),
real QUIC/TLS-1.3 handshake driver evidence over protected packets and loopback
UDP, handshake-derived 1-RTT protection for ATP control STREAM and symbol
DATAGRAM packets, 1-RTT AEAD + replay window with real-UDP replay rejection,
fail-closed RaptorQ symbol authentication posture on non-direct symbol planes,
anti-amplification accounting
with real-UDP response-envelope coverage, bounded queues. The prior silent-accept
exposure (`asupersync-7pwwwe`) is removed: the client path returns
`ServerCertificateUnverified` rather than accepting an unverified server.

## 5. Scope limits and no-claim boundaries

These are the boundaries around the G4 security claim. They keep the claim
specific to the native ATP-over-QUIC transfer path instead of turning it into a
release, fleet, benchmark, or generic QUIC interoperability claim.

### 5.1 Wire-CRYPTO handshake driver and transfer integration
The native QUIC stack now has a real `rustls::quic` handshake driver. It pulls
outbound TLS handshake bytes as QUIC `CRYPTO`, feeds received `CRYPTO` bytes back
into rustls, installs Initial / Handshake / 1-RTT keys as they become available,
and rejects untrusted server certificates before the client reaches completion.
`tests/quic_native_handshake_udp_loopback.rs` pins the driver completing over real
loopback UDP, and `handshake_driver` inline tests pin protected-packet and
untrusted-root behavior. `tests/atp_quic_real_udp_transfer_e2e.rs` now pins the
production `send_path` / `receive_on_endpoint` path failing closed before commit
for untrusted-root, wrong-hostname, and expired-certificate server identity
failures.

The public transfer path now carries ATP control frames, including the manifest,
over the native QUIC STREAM path protected by those handshake-derived 1-RTT
keys; RaptorQ symbols ride protected 1-RTT QUIC DATAGRAM packets and then pass
the deliberate symbol-authentication posture: QUIC AEAD on direct native QUIC,
per-symbol HMAC on non-direct symbol planes. This closes the G4
manifest/control authentication item for the native ATP-over-QUIC path. It does not prove
generic QUIC wire interoperability, fleet performance, release readiness, or
every future CLI/daemon integration surface.

### 5.2 X.509 verification surfaces are explicit and fail closed
Two X.509 verification surfaces exist. The handshake driver uses the rustls
client config's WebPKI verifier during the real TLS handshake. Separately,
`QuicServerIdentityVerifier` validates a presented chain and then records the
client identity gate before `NativeQuicConnection` can confirm. Empty root
stores, empty chains, wrong hostnames, expired certificates, and unverified
identity all fail closed in the pinned tests.

The remaining boundary is operational integration, not an insecure default:
callers still need explicit roots and a server name for the verified handshake,
and there is no "accept all" path to fall back to.

### 5.3 Control channel and manifest authentication boundary
Authenticated symbol mode protects the **RaptorQ symbol plane**. The QUIC-stream
control channel and transfer **manifest** are authenticated by the verified
native QUIC/TLS 1-RTT channel in the current ATP-over-QUIC `send_path` /
`receive_on_endpoint` path, not by a separate ATP-layer manifest MAC. A caller
that bypasses that verified native QUIC path must provide an equivalent
authenticated channel before claiming the same MITM boundary.

### 5.4 transport_tcp has no per-symbol authentication
The sibling `transport_tcp` transport provides integrity-vs-manifest only (no
per-symbol HMAC). It is not part of the QUIC path but shares the RaptorQ coding;
do not assume QUIC's symbol-auth guarantees apply to it.

## 6. Fail-closed verdict and pre-open-internet checklist

Verdict: the native ATP-over-QUIC security path is **fail-closed-by-construction**
for G4 today — unverified server identity, missing deliberate symbol-auth
posture, posture mismatch, oversize datagrams, replayed packets, and
amplification limits all refuse rather than proceed insecurely. This is still a scoped security claim,
not release readiness, broad workspace health, fleet performance, or generic
QUIC interoperability.

Before claiming open-internet safety (epic success criterion #5), these must land
and be pinned by tests (G4 acceptance, part a — owned by the respective Phase A
beads):

- [x] Wire-CRYPTO handshake driver completing the handshake from exchanged bytes (§5.1; `tests/quic_native_handshake_udp_loopback.rs`, `handshake_driver` inline tests).
- [x] End-to-end bad-cert rejection over the production transfer path: untrusted-root / wrong-hostname / expired-certificate → fail closed before commit (`tests/atp_quic_real_udp_transfer_e2e.rs`).
- [x] Authenticated control channel + manifest: ATP control frames and manifest ride the verified native QUIC/TLS 1-RTT STREAM path (§5.3; `src/net/atp/transport_quic/native_link.rs`, `tests/atp_quic_real_udp_transfer_e2e.rs`).
- [x] Forged/auth-failing symbol rejected on the real UDP path (`tests/atp_quic_real_udp_transfer_e2e.rs` mismatched `SecurityContext` transfer).
- [x] Replay rejection asserted on the real protected UDP transport (`tests/quic_application_data_udp_loopback.rs`).
- [x] Amplification bounds asserted on the real transport (not just unit level; `tests/quic_application_data_udp_loopback.rs`).

## 7. References

- Code: `src/net/quic_native/{connection.rs,tls.rs,handshake_driver.rs}`, `src/net/atp/quic/packet_protection.rs`, `src/net/atp/transport_rq/mod.rs`.
- Tests: `tests/quic_native_x509_verification.rs`, `tests/quic_native_handshake_udp_loopback.rs`, `tests/quic_application_data_udp_loopback.rs`, `tests/quic_legacy_no_accept_all_cert_verifier.rs`, `tests/atp_rq_symbol_auth_e2e_contract.rs`, `tests/decoding_secure_default.rs`, `tests/quic_datagram_send_path.rs`, `tests/quic_datagram_recv_path.rs`.
- Wire format: `docs/quic_wire_format.md`. Prior audit: `docs/atp_security_audit_phase4_summary.md`.
