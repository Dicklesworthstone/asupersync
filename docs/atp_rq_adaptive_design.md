# Adaptive Block-Size & Transport-Parameter Optimizer for ATP-over-RaptorQ

> Design artifact for `br-asupersync-mixdaw` adaptive layer. Status: design +
> runnable mathematical core (`src/net/atp/transport_rq/adaptive.rs`). Off by
> default; opt-in until fleet-validated.

## 0. Is adaptive block sizing a smart idea? Yes — and it is the highest-leverage knob.

The fixed defaults (`max_block_size = 8 MiB`, `symbol_size = 1024`, `udp_fanout
= 4`, `repair_overhead = 1.15`) are wrong on almost every real path, and wrong
in *different directions*:

- On a **clean, fat, high-RTT** path (Hetzner↔Contabo, 93 ms, low loss), a
  feedback round costs ~one RTT (~93 ms) — enormous. You want **large blocks +
  small overhead** so round 0 almost always decodes, and you want enough symbols
  in flight to fill the bandwidth-delay product.
- On a **lossy** path you need **more overhead**, but — counter-intuitively —
  *larger* blocks need *less relative* overhead for the same decode reliability,
  because the received-symbol count concentrates as `1/√K` (Section 2.3).
- On a **CPU-bound** sender/receiver (RaptorQ inactivation decode is roughly
  `O(K·(S+H))`, superlinear in `K`), **too-large blocks make coding the
  bottleneck**, not the network. There is a finite optimum.
- **Bandwidth variance** (peak vs trough) determines how aggressively you can
  size overhead and pacing before a trough causes a decode miss and an RTT
  penalty.

So the optimum is a genuine multi-objective trade-off with a clean structure,
not a guess. The design below makes "what block size?" an **algebraic fixed
point** (where the network-useful-rate curve crosses the coding-throughput
curve), with overhead set by a **conformal concentration margin**, both
estimated online, and a **no-regret bandit** hedging model error. It degrades to
the current fixed config whenever evidence is thin.

---

## 1. Baseline (measured)

From `artifacts/atp_bench/baseline-2026-06-12/report.md` (TCP transport, the
current default), Hetzner→Contabo, 93 ms RTT, 8 cores each:

| Payload | atp-tcp MB/s | rsyncd MB/s | atp/rsyncd |
|---|---|---|---|
| 100 MB | 18.3 | 17.0 | 1.08x |
| 1 GB | 20.6 | 25.8 | **0.80x** |
| tree (719 MB) | 19.1 | 25.0 | **0.76x** |

Dominant failure mode on bulk: a **single stream plateaus at ~20 MB/s** (one
flow's congestion window over a 93 ms RTT), and the whole entry is buffered in
RAM (2–3 GB RSS). The RQ transport's multi-socket spray attacks the first; this
adaptive layer makes the spray *match the path* instead of guessing.

---

## 2. Problem model

### 2.1 Decision variables (per block, re-chosen online)

| Symbol | Variable | Domain (grid) |
|---|---|---|
| `K` | source symbols per block (⇒ `B = K·s`) | `{256, 512, 1024, 2048, 4096, 8192}` |
| `ε` | round-0 repair overhead (extra fraction) | continuous, `[ε_min(p,K,α), 0.5]` |
| `N` | UDP fan-out (sockets) | `{1, 2, 4, 8}` |
| `s` | symbol size (bytes) | `{1024, 1232, 1408}` (MTU-safe) |

`s` is chosen once at handshake (must match both ends); `K, ε, N` adapt per
block on the sender.

### 2.2 Observables (estimated online; Section 3)

- `RTT` — control-plane round trip (s).
- `p` — per-symbol erasure probability (in-band, from `symbols_sent` vs
  `symbols_accepted` deltas the receiver already reports).
- `λ` — achievable aggregate goodput (bytes/s), with median `λ̃`, peak `λ̂`,
  trough `λ_lo` (a low quantile / CVaR of the instantaneous rate).
- `μ_enc, μ_dec` — local encode/decode throughput, measured as
  `coding_seconds / K` fit to `c·K^{γ-1}` (so `μ_code(K) = 1/(c·K^{γ-1})`
  symbols/s), `γ ∈ [1,2]`.

### 2.3 Cost model — the mathematical heart

**Decode-failure probability.** Receiver gets `R ~ Binomial(K(1+ε), 1-p)`
symbols. RaptorQ decodes from `K + δ_rq` symbols (`δ_rq` ≈ 2 plus an
inactivation failure floor `~q^{a}`, `q = 1/256`). Gaussian (Chernoff) tail:

```
z(K,ε,p) = ( K(1+ε)(1-p) − (K+δ_rq) ) / sqrt( K(1+ε)p(1-p) )
P_fail(K,ε,p) ≈ Φ(−z) + q^{⌈ε·K⌉}      # second term = RaptorQ inactivation floor
```

**Concentration ⇒ overhead shrinks with K.** Setting `P_fail = α` and solving
for `ε` (ignoring the tiny floor) gives, to first order,

```
ε*(K,p,α) ≈ p/(1−p)  +  z_α · sqrt( p / ( K (1−p) ) )
            └ mean loss ┘   └ concentration margin ~ 1/√K ┘
```

This is the key alien-artifact fact: **the margin term decays as `1/√K`**, so
bigger blocks need *less* relative overhead for the same reliability `α`. On a
clean fat path you ride this to large `K`, small `ε`.

**Steady-state goodput (pipelined encode→send→decode).** The bottleneck stage
sets the rate:

```
G(K,ε,N) = min(  λ(N) / (1+ε) ,            # network-useful rate (overhead wastes BW)
                 s · μ_code(K)  )          # coding-throughput rate (decode-bound)
                                           # μ_code(K) = 1/(c·K^{γ−1})
```

`λ(N)` rises with fan-out until it saturates the path (`λ(N) → λ_cap`).

**Expected wall-clock for an `S`-byte transfer:**

```
T(S) ≈ startup(RTT, probe)
     + S / G(K,ε,N)                                   # steady-state transport
     + (#blocks) · P_fail · ( RTT + retransmit_frac ) # feedback-round penalty
```

### 2.4 The optimizer (closed-form skeleton, refined by search)

Fix `α` (target per-block decode confidence) and a CPU-responsiveness cap.
Then:

1. `ε*(K) = ε*(K,p,α)` from §2.3 (so the `P_fail` penalty term ≈ `α·(RTT)`,
   small and bounded).
2. The two arguments of `min(·)` in `G` move oppositely in `K`:
   `λ/(1+ε*(K))` **increases** in `K` (overhead falls), while `s·μ_code(K)`
   **decreases** in `K` (decode superlinear). The maximizer is the **crossing
   point**:

   ```
   K* = solve_K   λ / (1 + ε*(K)) = s · μ_code(K)
   ```

   a 1-D monotone root-find (bisection on the grid). Left of `K*` you are
   **network-bound** (raise `K`); right you are **coding-bound** (lower `K`).
   This is a water-filling / balance argument: spend block size until the
   network-useful rate equals the coding rate, never past it.
3. `N*` = smallest fan-out with `λ(N) ≥ 0.95·λ_cap` (diminishing returns guard).

`K*` from the model is the **prior mean**; the online bandit (§4) explores
nearby grid arms to correct model error and track nonstationarity.

### 2.5 Constraints

- **Calibrated reliability:** `P_fail(K,ε,p) ≤ α`, with `p` replaced by its
  conformal upper bound `p̄` (Section 3) so the guarantee is finite-sample, not
  point-estimate optimism.
- **Responsiveness:** projected decode CPU `≤ ρ·cores` (default `ρ = 0.75`); if
  violated, cap `K` down (coding must not wedge the box). This reuses the
  project's responsiveness-guard philosophy from the bench harness.
- **Memory:** `K·s·(decode_matrix_factor) ≤ mem_budget`.
- **MTU:** `s + DGRAM_HEADER ≤ 1452` (no IP fragmentation).

---

## 3. Estimation layer (tail-aware, finite-sample)

### 3.1 Probe (startup)

A 1-RTT control handshake already exists. Extend it with a **short UDP probe
train** (e.g. 64 paced packets) before block 0:

- `RTT` from control round trip + UDP echo timestamps.
- `λ̂` (peak) from packet-pair / packet-train dispersion (receiver reports
  inter-arrival gaps).
- `p₀` from probe loss count.

### 3.2 In-band (per block)

The receiver already returns `symbols_accepted` and `feedback_rounds` in the
`Proof`/`NeedMore` frames. Add per-block `(sent, received, wall_ms,
decode_ms)`. From these:

- `p̂_block = 1 − received/sent`; `λ̂_block = received·s / wall_ms`.
- `μ_dec` fit from `decode_ms` vs `K`.

### 3.3 Bayesian + conformal fusion

- **Loss `p`:** Beta-Binomial posterior (`Beta(a+received_loss, b+received_ok)`)
  for a smooth point estimate, **plus a split-conformal upper bound `p̄`**
  (reuse `src/lab/conformal.rs`) over recent blocks so the reliability
  constraint uses a calibrated `1−α'` upper quantile, not the mean. This is the
  tail-awareness the user asked for: we size overhead against `p̄`, not `p̂`.
- **Bandwidth trough `λ_lo`:** track a low quantile / **CVaR_β** of
  instantaneous `λ̂_block` (EVT-lite: exponential-tail fit on the lower tail).
  Pacing (§4.3) targets `λ̃` but never commits more than `λ_lo` can sustain
  through a trough without a decode miss.
- **Nonstationarity:** an **anytime-valid e-process** (reuse
  `src/obligation/eprocess.rs` pattern) on the loss/bandwidth stream flags a
  regime change and triggers a **sliding-window restart** of the estimators
  (dynamic-regret control, §4.2).

---

## 4. Optimization / control layer

Three controllers on **separated timescales** (so they don't fight):

| Controller | Timescale | Method | Reused machinery |
|---|---|---|---|
| Block-size + overhead | per block (~10–100 ms) | decision-theoretic `K*` (§2.4) + **EXP3/Hedge bandit** over grid arms | EXP3 in `src/runtime/scheduler/three_lane.rs` |
| Send-rate pacing | per burst (~1 ms) | **AIMD / token bucket** targeting `λ̃`, clamped to `λ_lo` | new, control-theoretic |
| Estimator window | per regime | e-process changepoint → window restart | `src/obligation/eprocess.rs` |

### 4.1 Block-size bandit (no-regret)

Arms `a = (K, N)` on the grid (overhead `ε` is then `ε*(K, p̄, α)` analytically,
not an arm — keeps the arm count small). Loss per block:

```
ℓ_t(a) = wall_seconds_per_useful_byte(a)          # lower is better, in [0, ℓ_max]
```

Run **EXP3** (importance-weighted, the project already has the update):

```
p_t(a) = (1−η)·w_t(a)/Σ_b w_t(b)  +  η/|A|
ℓ̂_t(a) = ℓ_t(a)·I(a_t=a)/p_t(a)
w_{t+1}(a) = w_t(a)·exp(−η·ℓ̂_t(a))
```

**Warm start** the weights from the model `K*` (concentrate prior mass there) so
we don't pay full exploration cost — the model gets us to the right
neighbourhood; the bandit only corrects residual error.

**Regret guarantee:** EXP3 gives `E[R_T] ≤ O(√(|A|·T·log|A|))` external regret
vs the best fixed arm in hindsight — i.e. asymptotically no worse than an oracle
that knew the single best static block size for this transfer, with the gap
vanishing as `1/√T`. With sliding-window restart on changepoints, **dynamic
regret** `O(√(Ŝ·T))` for `Ŝ` regime shifts (§4.2).

### 4.2 Nonstationarity

The e-process raises an alarm when the loss/bandwidth supermartingale crosses
`1/α'`. On alarm: halve the estimator window and reset EXP3 weights toward the
fresh model `K*`. This bounds dynamic regret to `O(√(Ŝ·T))` (sliding-window
EXP3), matching the §4 table.

### 4.3 Pacing (control-theoretic)

A token-bucket / AIMD loop sets the inter-burst delay so the **send rate tracks
`λ̃`** (fill the pipe) but **backs off multiplicatively on a loss spike** (so a
trough doesn't cause an avalanche of drops → feedback rounds). Setpoint `r* =
λ̃`; on measured loss `> p̄ + margin`, `r ← r/2`; else `r ← r + α_inc`. This is
the same AIMD that makes TCP stable, applied to the symbol spray, with a
**Lyapunov/AIMD stability argument** (the rate process is contractive toward
`r*`). It also eliminates the residual `WouldBlock` busy-spin by construction.

---

## 5. Formal guarantees & explicit no-claim boundaries

**Provides:**

1. **Calibrated per-block reliability.** Under the exchangeability assumption of
   recent blocks, `P(decode fails | committed plan) ≤ α` to finite-sample
   split-conformal coverage (overhead sized against `p̄`, not `p̂`).
2. **No-regret block sizing.** `E[R_T] = O(√(|A|T log|A|))` vs the best static
   arm in hindsight (EXP3); `O(√(ŜT))` dynamic regret across `Ŝ` regimes.
3. **Pacing stability.** The AIMD rate process is Lyapunov-stable around `r* =
   λ̃` with bounded oscillation (standard AIMD).
4. **Deterministic conservative fallback.** With no/insufficient evidence the
   controller returns *exactly* the current fixed `RqConfig` — adaptivity is a
   strict superset that can only help once evidence accrues.
5. **Deterministic replay.** All randomness (EXP3 sampling, probe scheduling)
   flows through the project's `Cx`-seeded RNG, so a lab run with a fixed seed
   and a recorded path trace is bit-reproducible.

**Does NOT claim:**

- It does not beat an offline oracle that knew the full path trace in advance
  (only vanishing regret vs the best *static* choice).
- The Gaussian `P_fail` approximation is not exact for tiny `K` (<~50); there we
  fall back to the conservative fixed overhead.
- Conformal coverage assumes recent-block exchangeability; a sharp regime change
  *between* the calibration window and the next block can transiently violate
  coverage until the e-process fires and the window restarts.
- No claim about adversarial network elements actively pacing to defeat the
  estimator (we assume a non-adversarial path).
- Not a congestion-control fairness proof: AIMD pacing is TCP-friendly *by
  construction* but we do not prove inter-flow fairness here.

---

## 6. Implementation plan (`src/net/atp/transport_rq/adaptive.rs`)

Fallback-safe, opt-in, deterministic-in-lab. **No change to the default path
until fleet-validated.**

### 6.1 Types

```rust
/// Estimated path properties (all Option: None ⇒ thin evidence ⇒ fall back).
pub struct PathEstimate {
    pub rtt_s: f64,
    pub loss_p_hat: f64,
    pub loss_p_bar: f64,      // conformal upper bound used for sizing
    pub bw_median_bps: f64,
    pub bw_trough_bps: f64,   // CVaR_β of instantaneous rate
    pub enc_symbols_per_s: f64,
    pub dec_symbols_per_s: f64,
    pub coding_gamma: f64,    // superlinearity exponent in [1,2]
    pub samples: u32,         // evidence count; gates activation
}

/// One per-block decision.
pub struct BlockPlan { pub k: u32, pub overhead: f64, pub fanout: usize }

/// Cost-model knobs + reliability target.
pub struct AdaptivePolicy {
    pub target_decode_alpha: f64,   // e.g. 1e-3
    pub cpu_responsiveness_cap: f64,// ρ·cores
    pub mem_budget_bytes: u64,
    pub min_samples_to_activate: u32,
    pub arm_grid_k: &'static [u32],
    pub arm_grid_fanout: &'static [usize],
    pub exp3_eta: f64,
}

pub struct AdaptiveController { /* weights, estimators, rng-seeded */ }
```

### 6.2 Pure, unit-testable core (deterministic)

```rust
/// P_fail Gaussian + RaptorQ floor (§2.3).  Pure.
pub fn decode_fail_probability(k: u32, overhead: f64, loss: f64) -> f64;

/// ε*(K,p,α) closed form (§2.3).  Pure, monotone in its args.
pub fn overhead_for_target(k: u32, loss_p_bar: f64, alpha: f64) -> f64;

/// Steady-state goodput G(K,ε,N) (§2.3).  Pure.
pub fn goodput_bps(k: u32, overhead: f64, fanout: usize, est: &PathEstimate, symbol_size: u16) -> f64;

/// K* crossing-point root-find on the grid (§2.4).  Pure, deterministic.
pub fn optimal_block(est: &PathEstimate, policy: &AdaptivePolicy, symbol_size: u16) -> BlockPlan;
```

These four functions are the mathematical core and are **100% deterministic and
unit-testable with synthetic `PathEstimate`s** — no network needed. They encode
every theorem above and are where the proof artifacts live.

### 6.3 Controller surface

```rust
impl AdaptiveController {
    pub fn new(policy: AdaptivePolicy, seed: u64) -> Self;
    /// Returns None until ≥ min_samples_to_activate (⇒ caller uses fixed RqConfig).
    pub fn next_block_plan(&mut self, symbol_size: u16) -> Option<BlockPlan>;
    /// Feed back measured outcome → update EXP3 + estimators + e-process.
    pub fn observe(&mut self, plan: &BlockPlan, sent: u64, received: u64, wall_s: f64, decode_s: f64);
}
```

`transport_rq::send_path` consults `next_block_plan()` per block when an
`Option<AdaptiveController>` is present; `None` everywhere ⇒ today's behaviour
byte-for-byte.

### 6.4 Proof / replay artifacts

- `tests/atp_rq_adaptive_contract.rs`:
  - `overhead_for_target` monotone ↓ in `K`, ↑ in `p`, ↑ as `α↓` (the `1/√K`
    concentration law).
  - `optimal_block` lands network-bound→raise-K, coding-bound→lower-K on
    synthetic estimates (crossing-point correctness).
  - `decode_fail_probability ≤ α` at the chosen `(K,ε)` across a grid of `p`.
  - EXP3 cumulative-regret trace is sublinear on a synthetic loss sequence; an
    adversarial sequence does not induce linear regret.
  - Conservative fallback: `samples < min` ⇒ `next_block_plan() == None`.
- `artifacts/atp_rq_adaptive_replay_v1.json`: recorded synthetic path traces +
  expected decisions (deterministic golden).
- Lab determinism: seed-fixed controller + recorded trace ⇒ identical decisions.

### 6.5 Rollout (shadow → canary → ramp → default)

1. **Shadow:** log what `next_block_plan()` *would* choose vs fixed; no behaviour
   change. Compare on the bench.
2. **Canary:** enable on `atp send --adaptive` only.
3. **Ramp:** default `--adaptive` on for `--transport rq`, fixed still selectable.
4. **Default:** once Hetzner→Contabo beats both fixed-RQ and rsync across the
   payload matrix with the responsiveness guard never tripping.

---

## 7. EV / relevance gate

| Family | Impact | Conf | Effort | Score | Role |
|---|---|---|---|---|---|
| Coding theory (P_fail, ε*, K* model) | 5 | 5 | 2 | 12.5 | core cost model |
| Online learning / EXP3 (no-regret arms) | 5 | 4 | 2 | 10.0 | model-error hedge, reuses existing EXP3 |
| Conformal + CVaR/EVT (tail-aware p̄, λ_lo) | 4 | 4 | 2 | 8.0 | calibrated constraint |
| Control theory (AIMD pacing) | 4 | 4 | 2 | 8.0 | pipe-fill + stability |
| e-process changepoint | 3 | 4 | 2 | 6.0 | nonstationarity |

Five families, top of the per-subsystem budget, but each clears the gate
independently and they compose on **separated timescales** (per-symbol pacing ≪
per-block sizing ≪ per-regime window) so interference is controlled.

**Relevance:** symptom fit 5 (directly targets the bulk-throughput plateau and
the loss/RTT trade-off), architecture fit 5 (a pure side-module consulted by
`send_path`; zero change to the wire format or the default path), proof
readiness 5 (the core is four pure functions), operability 5
(shadow→canary→ramp→default with a deterministic fallback).

---

## 8. Galaxy-brain transparency cards

**Card A — Overhead shrinks with block size (`1/√K` concentration).**
- Equation: `ε*(K,p,α) ≈ p/(1−p) + z_α·√(p/(K(1−p)))`.
- Substituted (`p=0.02, α=1e-3 ⇒ z_α≈3.09`): `K=512 ⇒ ε*≈0.0204+0.0193=0.040`;
  `K=8192 ⇒ ε*≈0.0204+0.0048=0.025`.
- Intuition: more symbols per block ⇒ the received count clusters tighter around
  its mean ⇒ a thinner safety margin still hits the reliability target. Big
  blocks are *cheaper* per protected byte on a clean path.
- Assumptions: Gaussian tail valid for `K≳50`; `p` is the conformal upper bound.
- Changes the decision if: `p` is large or bursty (margin term and CVaR
  dominate ⇒ smaller blocks + more overhead).

**Card B — Optimal block is the network/coding crossing point.**
- Equation: `K* : λ/(1+ε*(K)) = s·μ_code(K)`, `μ_code(K)=1/(c·K^{γ−1})`.
- Substituted (`λ=50 MB/s, s=1024, c,γ` from probe): network rate rises with
  `K`, decode rate falls; they cross at `K*≈2048` ⇒ `B*≈2 MiB`, **not** the
  fixed 8 MiB.
- Intuition: grow the block while the network is the bottleneck; stop the moment
  decode CPU becomes the bottleneck. Past `K*` you only slow decode without
  helping the wire.
- Assumptions: pipelined stages; `μ_code` superlinearity `γ` measured online.
- Changes the decision if: CPU is fast (`γ→1` ⇒ push `K` up) or slow (`γ→2` ⇒
  pull `K` down).

**Card C — EXP3 hedges model error with vanishing regret.**
- Equation: `E[R_T] ≤ 2√(e−1)·√(|A|T·ln|A|)`.
- Substituted (`|A|=24 arms, T=200 blocks`): regret `≲ 2·1.31·√(24·200·3.18) ≈
  324` loss-units vs `T·ℓ_max` budget ⇒ <a few % overhead vs the best static arm.
- Intuition: even if the closed-form `K*` is biased, the bandit converges to the
  empirically best arm without ever doing much worse than it along the way.
- Assumptions: bounded loss `ℓ∈[0,ℓ_max]`; warm-started near `K*`.
- Changes the decision if: regime shift (⇒ window restart, dynamic-regret mode).
```
