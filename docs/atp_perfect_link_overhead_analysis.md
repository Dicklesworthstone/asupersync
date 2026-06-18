# Why ATP loses on clean, rate-capped, low-latency links — overhead analysis (E-6/E-3)

Lane: **perfect-link overhead-reduction analysis** (orchestrator lane (e)). Read-only
code analysis; this is a scoping + blueprint doc, not a code change. It explains the loss,
inventories the **existing** GSO/sendmmsg scaffolding in `src/net/udp.rs`, and specifies the
remaining native-path work so the udp.rs lane (a) can be executed without re-deriving it.

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

## Root cause: one send syscall per ~1200-byte symbol

The RQ sender sprays symbols one datagram at a time. In `spray_round` the inner loop is:

```rust
for sym in &syms {
    send_symbol_datagram(cx, sockets, rr, symbols_sent, dropper, tag,
                         enc.index, sym, config, &mut pacer, symbol_auth).await?;
}
```
(`src/net/atp/transport_rq/mod.rs:2324-2338`; the sequential M=1 path at `:2342+` is the same
one-symbol-per-send shape.) Each `send_symbol_datagram` is one `UdpSocket::send`/`send_to`,
i.e. **one `sendto(2)` per symbol**. With `symbol_size` ≈ `UDP_DEFAULT_GSO_SEGMENT_BYTES = 1200`
(`udp.rs:41`):

* 100 MB ⇒ ~87,400 source datagrams ⇒ **~87k `sendto` syscalls** on the sender, plus repair.
* The receiver historically paid a matching per-datagram `recvfrom`; **E-6a already fixed the
  receive side** (`recv_batch_from`, bead `asupersync-mbjfzs`) — the pump drains a burst per
  readiness wait. The **send side is still one-syscall-per-symbol**.

rsync over TCP issues a handful of large `write(2)`s (the kernel segments into MSS frames in
the stack/NIC). So on a clean link the comparison is ~87k userspace→kernel crossings (atp) vs
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

## What already exists in `src/net/udp.rs` (the planner is built; execution is not)

A complete **planning/decision** layer is in place — but `native_send_batch` is `false` and
there is **no syscall**: `grep` finds no `libc::`, `unsafe`, `as_raw_fd`, `sendmmsg`,
`setsockopt`, or `cmsg` in the file.

| Present (pure logic) | Location |
|---|---|
| `UdpSendBatchStrategy` (prefer_sendmmsg/gso, segment bytes, batch caps) | `udp.rs:192-216` |
| `UdpBatchCapabilities` / `UdpCapability` (sendmmsg Supported, gso Unknown on Linux) | `udp.rs:108-170` |
| `plan_send_batch` → path + segments_per_packet + estimated_syscalls | `udp.rs:765-814` |
| Bounds: `UDP_MAX_GSO_SEGMENTS=64`, `UDP_MAX_SENDMMSG_BATCH=1024`, `UDP_DEFAULT_GSO_SEGMENT_BYTES=1200` | `udp.rs:41-45` |
| `clamped()` knob validation | `udp.rs:747-758` |

So the decision ("GSO 32 segments × sendmmsg 1024, est N syscalls") is already computed. The
gap is purely **executing** that plan with a real syscall + reactor readiness.

---

## Remaining native-path work — spec for the udp.rs lane (a)

1. **Raw fd access.** Expose the runtime `UdpSocket`'s underlying fd (`AsRawFd` or an internal
   accessor). Required to issue the syscalls; keep it `pub(crate)`/cfg-gated.
2. **`send_batch_native` (Linux).** `#[cfg(target_os = "linux")]` + `#[allow(unsafe_code)]`.
   Build `Vec<libc::iovec>` + `Vec<libc::mmsghdr>` (one per super-packet), set the GSO segment
   size via an `SOL_UDP`/`UDP_SEGMENT` `cmsg` in each `msghdr` (or `setsockopt(UDP_SEGMENT)` for
   a uniform run), and call `libc::sendmmsg(fd, msgs.as_mut_ptr(), n, flags)`. Handle the
   short-count return (datagrams actually queued), `EAGAIN`/`EWOULDBLOCK` → reactor wait,
   `EMSGSIZE`/`EINVAL` (GSO unsupported) → fall back. **Never block**; this is a non-blocking fd.
3. **Reactor integration.** A `poll_send_batch(cx, …)` mirroring the existing `poll_send`
   (`udp.rs:942`): register writable interest on `EAGAIN`, resume from the returned count.
4. **Capability probe.** Flip `capabilities.gso` from `Unknown` to `Supported`/`Unsupported`
   with a one-shot `setsockopt(SOL_UDP, UDP_SEGMENT, …)` probe (or a single trial send), cached
   per socket; only then does `plan_send_batch` choose the GSO path (`allow_unknown_gso=false`).
5. **Safe fallback.** When native is unavailable/`Unsupported`, route through the existing
   portable per-datagram loop (`portable_send_batch=true`). The fast path is purely additive.
6. **Unsafe ledger.** Add the `sendmmsg`/`UDP_SEGMENT` boundary to
   `artifacts/unsafe_boundary_ledger_v1.json` (the security gate checks it) with the
   invariants: fd valid + non-blocking, message/iovec arrays live for the call, GSO segment ≤
   payload, count clamped to `UDP_MAX_SENDMMSG_BATCH`.
7. **Wire into the RQ sender.** Replace the per-symbol `send_symbol_datagram` loop
   (`transport_rq/mod.rs:2324`) with a batched build → `send_batch` once the native path lands
   (coordinate: that loop is the cod_2 lane — land udp.rs first, then a one-line wiring change).

**Why blind-unsafe is risky here:** `mmsghdr`/`cmsg` layout, alignment, sockaddr construction,
partial-batch + `EAGAIN` handling, and reactor readiness must all be right, and a defect is
runtime UB or silent send-drops that `cargo check` cannot catch. This lane needs an agent who
can build **and** run the udp microbench/integration test before landing — it should not be
committed code-first/unverified.

---

## Sequencing + falsifiability

* **Decode-bound vs syscall-bound is per-cell.** On small/medium clean cells (10M) the wall is
  syscall/CPU overhead → GSO helps. On large cells (≥100M) single-core RaptorQ decode dominates
  → GSO raises the sender ceiling but the receiver still bottlenecks until **parallel decode**
  (F6.3, peer-owned `feed_symbol`) lands. Don't expect GSO alone to win 100M+ clean cells.
* **Honest claim discipline.** GSO/sendmmsg is a *ceiling-raiser*; verify with the rate-capped
  matrix (`scripts/atp_bench/matrix_bench.sh`, regime `perfect` = 1 gbit/2 ms) in Phase-2.
  Keep the native path only if `perfect`-regime wall drops with sha/merkle OK and RSS bounded.
* **Smaller, safe pre-step:** the `symbol_size` knob (currently 1200) is MTU-bound *without*
  GSO; raising it only helps once GSO removes the per-segment MTU constraint. So GSO is the
  unlock, not a bigger symbol.

---

## TL;DR

atp's clean-link loss is **one `sendto` per 1200-byte symbol** (~87k syscalls/100 MB,
`transport_rq/mod.rs:2324`). The fix is GSO + sendmmsg, whose **planner already exists** in
`udp.rs` (`plan_send_batch`, `UdpSendBatchStrategy`) — only the unsafe syscall + reactor
readiness + capability probe + unsafe-ledger entry remain (lane (a), §"Remaining native-path
work"). It is a ceiling-raiser to **exceed** rsync on fat/lossy pipes; on large clean cells it
must be paired with parallel decode (F6.3). Measure on the rate-capped `perfect` regime before
claiming any clean-link win.
