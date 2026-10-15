# Why ATP loses on clean, rate-capped, low-latency links — overhead analysis (E-6/E-3)

Lane: **perfect-link overhead-reduction analysis** (orchestrator lane (e)). Read-only
code analysis; this is a scoping + proof-gate doc, not a code change. It explains the clean-link
loss model, inventories the **current** RQ send-batch + UDP native batching state, and names the
remaining measurement gates before any clean-link win can be claimed.

Honest-results context (docs/atp_bench_matrix_spec.md §"Honest results so far"):

| regime | size | atp-rq | rsync-d | who wins |
|---|---|--:|--:|---|
| 0%/0ms (uncapped) | 10M | 0.71 s | 0.108 s | rsync 6.6× |
| 0%/0ms (uncapped) | 50M | 3.42 s | 0.208 s | rsync 16× |
| 3%/50ms | 10M | 1.81 s | 9.35 s | **atp 5.2×** |

On a clean link atp loses; under loss atp wins big. The matrix harness now **rate-caps** every
regime (a real link has finite bandwidth), so the question is: on a *finite-bandwidth* clean
link, what stops atp from at least matching rsync?

---

## Historical root cause: one send syscall per ~1200-byte symbol

The original RQ sender sprayed symbols one datagram at a time: one encoded symbol entered
`send_symbol_datagram`, which called a UDP send path immediately. With `symbol_size` around
`UDP_DEFAULT_GSO_SEGMENT_BYTES = 1200`:

* 100 MB ⇒ ~87,400 source datagrams ⇒ **~87k `sendto` syscalls** on the sender, plus repair.
* The receiver historically paid a matching per-datagram `recvfrom`; **E-6a already fixed the
  receive side** (`recv_batch_from`, bead `asupersync-mbjfzs`) — the pump drains a burst per
  readiness wait.

rsync over TCP issues a handful of large `write(2)`s (the kernel segments into MSS frames in
the stack/NIC). So on a clean link the old comparison was ~87k userspace-to-kernel crossings (atp) vs
a few hundred (rsync). At a 1 gbit cap, 87k syscalls × ~1–2 µs each is ~0.1–0.2 s of pure
syscall overhead before counting RaptorQ encode/decode CPU — consistent with the 0.71 s vs
0.108 s gap at 10M.

A second, independent wall on **large** transfers is single-core RaptorQ **decode** CPU
(~0.8 MB/s per the F3 session notes). GSO/sendmmsg raises the *sender packet-rate* ceiling; it
does **not** touch decode. The two levers are orthogonal — see "Sequencing" below.

---

## The lever: GSO + sendmmsg (collapse ~87k syscalls → ~1.5k)

* **UDP GSO (`UDP_SEGMENT`)**: one `sendmsg(2)` hands the kernel a super-buffer of up to 64 ×
  1200-byte segments; the kernel (or NIC, with hardware offload) segments them. ~64× fewer
  syscalls. This is how quinn/WireGuard reach line rate.
* **`sendmmsg(2)`**: one syscall posts up to 1024 `mmsghdr`s. Complementary to GSO — batch
  many GSO super-packets per syscall. Together: ~87k → ~1.5k syscalls for 100 MB.

This is the lever that lets atp **exceed** rsync on a fat/long pipe a single TCP stream can't
fill (the actual thesis, docs/atp_rq_beat_rsync_ledger.md §Synthesis), and that erases atp's
clean-link CPU penalty so the loss-resilience win is no longer paid for with a clean-link loss.

---

## Current main state (2026-06-19): batching exists, proof is the gap

The stale "one syscall per symbol" diagnosis is no longer a literal description of `main`.
The current tree has three layers of send-side batching:

| Layer | Current state |
|---|---|
| RQ sender queue | `RqPendingSendBatch` groups encoded symbol datagrams by socket and flushes at `RQ_SEND_BATCH_GLOBAL_SYMBOLS=64` or `RQ_SEND_BATCH_PER_SOCKET=32`. |
| UDP portable/native entrypoint | `UdpSocket::send_batch_to` first tries connected-native send when all packets target the connected peer, then falls back to the portable loop. |
| Native send path | On Linux/Android, `send_batch_to` plans GSO, builds super-packets, and calls `nix::sys::socket::sendmmsg` with `ControlMessage::UdpGsoSegments`; if GSO fails before progress it falls back to plain `sendmmsg`, then to portable send. |
| Report surface | `UdpBatchIoReport` records `packets_processed`, `bytes_processed`, `fallback_used`, `native_send_batch_used`, `gso_send_used`, and a partial-batch `error`. |

The new bottleneck question is therefore **not** "is native batching implemented?" It is:

1. Do rate-capped perfect-link ATP-RQ runs actually reach `native_send_batch_used=true` and, on
   Linux kernels that support it, `gso_send_used=true`?
2. Does any fallback happen in the real RQ path because packets are not connected-peer eligible,
   payload lengths differ, GSO is rejected by the kernel/NIC, or a non-blocking partial send leaves
   the portable tail path hot?
3. After native batching is confirmed, is the remaining clean-link wall per-symbol ATP work
   (auth, encode, pacing checkpoint, feedback/control frames), RaptorQ decode, or genuine link
   bandwidth?

This lane should treat all clean-link conclusions without those fields as **inadmissible**. The
planner can estimate a GSO/sendmmsg path, but the result only matters if the runtime report proves
that path ran.

---

## Remaining proof work

1. **Expose actual batch reports in matrix rows.** The Phase-2 matrix row should include ATP sender
   aggregates: `udp_batches`, `udp_packets_processed`, `udp_native_batches`,
   `udp_gso_batches`, `udp_fallback_batches`, `udp_partial_batch_errors`, and
   `payload_bytes_per_udp_syscall_est`. `est_min_datagrams` alone is a lower-bound packet model,
   not proof that the native fast path ran.
2. **Classify fallback reasons.** If `native_send_batch_used=false` or `gso_send_used=false` on a
   Linux perfect-link ATP row, record the reason: not connected, mixed destination, mixed payload
   size, kernel rejected GSO, `sendmmsg` returned partial progress, or portable-only platform.
3. **Keep crypto tier symmetric.** A clean-link win in `nocrypto` means atp-lab vs rsyncd. Auth and
   encrypted claims need matched ATP auth/TLS vs rsync-over-ssh rows.
4. **Run only the rate-capped perfect cell for this question.** The relevant proof cell is the
   matrix `perfect` regime (1 gbit, 2 ms, 0 loss), `sha_ok=true`, bounded RSS, at least 3 reps, and
   `cv_pct <= 5%` unless the run is explicitly marked noisy.
5. **Compare against rsync, not old ATP.** The claimed result is an ATP-vs-rsync ratio. A lower ATP
   syscall count than a previous ATP commit is a useful diagnosis, not a win.

---

## Sequencing + falsifiability

* **Decode-bound vs syscall-bound is per-cell.** On small/medium clean cells (10M) the wall can be
  syscall/CPU overhead. On large cells (>=100M), RaptorQ decode or per-symbol ATP bookkeeping can
  dominate even after GSO/sendmmsg succeeds.
* **Honest claim discipline.** Native batching is a ceiling-raiser; verify with the rate-capped
  matrix (`scripts/atp_bench/matrix_bench.sh`, regime `perfect` = 1 gbit/2 ms) in Phase-2. Keep the
  fast path only if `perfect`-regime wall improves vs rsync with sha/merkle OK, bounded RSS, and
  actual native/GSO report fields.
* **Symbol-size tuning is downstream.** Raising logical symbol size only becomes safe once the
  GSO path is proven and receiver decode/RSS stay bounded. Without that proof, larger symbols can
  trade syscall overhead for decode and memory pressure.

---

## TL;DR

The original clean-link loss was driven by one small UDP send per symbol. `main` now has the right
shape: RQ queues symbol datagrams, connected UDP `send_batch_to` tries Linux/Android GSO+sendmmsg,
and reports whether native/GSO actually ran. The remaining cod_7 conclusion is a proof gate:
measure the rate-capped `perfect` regime, admit only sha-ok symmetric ATP-vs-rsync rows, and require
actual native/GSO/fallback counters before declaring that perfect-link overhead has been reduced.
