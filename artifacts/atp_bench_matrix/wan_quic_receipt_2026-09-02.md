# ATP cross-machine WAN receipt — 2026-09-02 (SapphireHill)

Bead: `asupersync-gap-atp-bench-receipts-xwyrr2`. First dated cross-machine
ATP-over-QUIC/TLS 1.3 transfer receipt with SHA-256 on both ends, plus the
same-path ATP-over-TCP countermetric. One rep per cell; this is a correctness
receipt with an honest throughput number, not a benchmark claim.

## Setup

| Item | Value |
|---|---|
| Source revision | `main` b1ed41481 (release profile, `--features atp-cli`) |
| Binary | `atp 0.4.10`, built on ovh-a through rch, sha256 `7be732695049dd377f0e1c4e27b45abf8161763e1a224862d4521b9f758711cd` (identical bytes on every host; all hosts run Ubuntu 26.04 / glibc 2.43) |
| Receiver | `vmi1149989` — Contabo GmbH (AS51167), Lauterbourg, FR, `212.90.121.76`, 10 vCPU |
| Sender A | `hetzner1` (hz1) — Hetzner (your-server.de), Ashburn VA, US, `87.99.133.171`; ICMP RTT to receiver 96.4 ms avg |
| Sender B | `hz3` — Contabo Inc. (AS40021), Orangeburg NY, US, `194.140.197.98`; ICMP RTT to receiver 88.3 ms avg |
| Receiver certificate | self-signed EC P-256, SAN `IP:212.90.121.76, DNS:atp-receipt`, `basicConstraints=critical,CA:FALSE`, `extendedKeyUsage=serverAuth`, valid 2026-09-02..09-09, sha256 fingerprint `F7:C7:B6:03:5D:0F:C3:D1:AA:21:A0:47:78:CA:9B:11:1E:60:A9:3D:61:62:FF:42:E7:91:A7:67:88:77:FF:E5`; sender pins it with `--ca` (no skip-verify exists) |
| Payloads | one 256 MiB `/dev/urandom` file per sender; hz1 sha256 `c327d3c324ae12ac80b7de51eda1fd1bf0da0c469cd62cbc7baa68e05703dbcb`, hz3 sha256 `4a8993a5fedf0555a9a5078821d2ac82af01808c74ca2a48c984dc3ca49dd3d3` |
| Commands | receiver: `atp recv <inbox> --listen 0.0.0.0:<port> --once --transport quic --server-cert receiver.crt --server-key receiver.key --accept-timeout-secs 600`; sender: `atp send <dir> 212.90.121.76:<port> --transport quic --ca receiver.crt` (TCP cells: `--transport tcp`, no TLS material) |
| Clock | 2026-09-02 15:09–15:15 UTC |

## Results (sender-reported `elapsed_micros`; receiver-side SHA-256 of the committed file)

| Path | Transport | Bytes | Sender elapsed | Throughput | Receiver elapsed | committed / merkle_ok / sha_ok | Receiver SHA-256 == payload | transfer_id |
|---|---|---|---|---|---|---|---|---|
| Hetzner Ashburn → Contabo FR | QUIC/TLS 1.3 | 268,435,456 | 42.90 s | 6.26 MB/s (50.1 Mbit/s) | 45.5 s | true / true / true | **yes** | `6dd2ffa6b490bfb4c8c56158d3c68368` |
| Hetzner Ashburn → Contabo FR | TCP (plaintext) | 268,435,456 | 13.47 s | 19.93 MB/s (159 Mbit/s) | 16.0 s | true / true / true | **yes** | `90d61506b88b70da1c47e9d3ae67cf53` |
| Contabo NY → Contabo FR | QUIC/TLS 1.3 | 268,435,456 | 100.86 s | 2.66 MB/s (21.3 Mbit/s) | n/a (report omits) | true / true / true | **yes** | `82e6f8976b2590ed92713b86229f6ab7` |
| Contabo NY → Contabo FR | TCP (plaintext) | 268,435,456 | 11.73 s | 22.89 MB/s (183 Mbit/s) | 14.21 s | true / true / true | **yes** | `cb08339dd1733feeff0fab27d8b4b35d` |

Throughput = bytes / sender `elapsed_micros`. Wall clock including the ssh
round trips was 43.4 s / 14.2 s (hz1) and 104.4 s / 12.2 s (hz3).

## What this proves, and what it does not

- **Correctness across real WAN paths:** four of four transfers committed
  with `merkle_ok` and the receiver's independent SHA-256 equal to the
  sender's payload digest. This is the first cross-machine QUIC receipt in
  the repository (the only earlier one was ATP-over-TCP plaintext on
  2026-06-13).
- **Throughput, honestly:** on both ~90 ms transatlantic paths ATP-over-QUIC
  moved bytes 3.2× (hz1) to 8.6× (hz3) slower than ATP-over-TCP with the
  same binary and payload. The path is not the limit (TCP reached
  159–183 Mbit/s); the QUIC sender is. No encrypted "beats rsync" wording
  is supported by this receipt.
- **Not measured here:** rsync on these paths (no ssh trust between the
  sender and receiver hosts was configured for this run; the netns matrix on
  ovh-a carries the rsync comparison), repetitions (one rep per cell), loss
  regimes, and time-of-day variance.

## Defect found on the way (fixed)

The first two attempts died in under a second with
`native QUIC error: quic handshake: crypto provider failure:
provider=rustls-quic-handshake, code=read_hs_fatal_alert`. The alert is the
client's own: OpenSSL 3.5's `req -x509` stamps
`basicConstraints=critical,CA:TRUE` on a self-signed certificate and
rustls-webpki refuses a CA certificate as an end entity. The bench harness
(`scripts/atp_bench/run_matrix_cell.sh`) generated its certificates the same
way, which is why every `atp-quic-tls13` cell of the 2026-09-02 ovh-a matrix
run failed in 0.15 s while the `rsync-ssh-aes128gcm` cells passed. Both
generators now pin `basicConstraints=critical,CA:FALSE`. The atp client
error stays redacted by design (br-asupersync-iz6751), so this receipt
records the diagnosis.

## Raw evidence

Scratch logs on the dispatcher: `quic_receipt/receipt.log` (hz3 QUIC),
`receipt_extra.log` (hz3 TCP), `receipt_hz1.log` (hz1 QUIC + TCP),
`reports_{hz1,hz3,vmi}.txt` (full sender/receiver JSON reports). Receiver
files: `/tmp/atp_receipt/{inbox,inbox_tcp,hz1_quic,hz1_tcp}/payload/blob.bin`
on the receiver at the time of writing.
