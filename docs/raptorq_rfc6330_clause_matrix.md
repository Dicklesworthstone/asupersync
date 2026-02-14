# RaptorQ RFC 6330 Clause-to-Code Traceability Matrix

Bead: `bd-2wlqm`  
Scope: Current in-repo RaptorQ implementation surface (`src/raptorq/*`) and deterministic test harnesses.

## Status Legend
- `implemented`: code + direct tests exist in-tree for the mapped requirement.
- `partial`: code exists, but RFC-exactness and/or required test/logging coverage is incomplete.
- `planned`: tracked by follow-up beads; no claim of current compliance.

## Glossary
- `K`: Number of source symbols in a source block.
- `K'`: Extended block size used by RFC 6330 precode/LT construction.
- `S`: Number of LDPC symbols/rows in precode construction.
- `H`: Number of HDPC symbols/rows in precode construction.
- `W`: LT window parameter used during tuple/equation generation.
- `J`: RFC parameter coupled with `K'` in tuple generation logic.
- `ESI`: Encoding Symbol ID used to derive repair tuples and equations.
- `LT`: Luby Transform coding component (systematic + repair equations).
- `LDPC` / `HDPC`: Low-density and high-density parity-check components of the precode matrix.
- `E2E`: Deterministic end-to-end scenario validation across encode/decode/report paths.

## Clause Matrix
| Clause / Requirement | Implementation (code) | Comprehensive unit tests | Deterministic E2E scenarios | Structured logging assertions | Status | Owner lane | Follow-up bead(s) |
|---|---|---|---|---|---|---|---|
| `RFC 6330 §5.3.5.1` `Rand[y,i,m]` table-based PRNG | `src/raptorq/rfc6330.rs:177` | `src/raptorq/rfc6330.rs:258`, `src/raptorq/rfc6330.rs:265` | `tests/raptorq_conformance.rs:101`, `tests/raptorq_conformance.rs:243` (indirect via encoder/decoder flow) | `tests/raptorq_conformance.rs:1209` (deterministic JSON report equality) | partial | Track B + D | `bd-1rxlv`, `bd-61s90` |
| `RFC 6330 §5.3.5.2` degree generation behavior | `src/raptorq/rfc6330.rs:202`, `src/raptorq/systematic.rs:178` | `src/raptorq/rfc6330.rs:288`, `tests/raptorq_conformance.rs:541` | `tests/raptorq_conformance.rs:155`, `tests/raptorq_perf_invariants.rs:884` | `tests/raptorq_conformance.rs:1209`, `tests/raptorq_perf_invariants.rs:667` | partial | Track B + D | `bd-1g5ww`, `bd-1rxlv`, `bd-61s90` |
| RFC parameter derivation (`K'`, `J`, `S`, `H`, `W`) must be table-driven for supported ranges | `src/raptorq/systematic.rs:97`, `src/raptorq/systematic.rs:112`, `src/raptorq/systematic.rs:127`, `src/raptorq/rfc6330_systematic_index_table.inc:1` | `tests/raptorq_conformance.rs:597`, `tests/raptorq_conformance.rs:614`, `src/raptorq/systematic.rs:1152`, `src/raptorq/systematic.rs:1163` | `tests/raptorq_perf_invariants.rs:884` | `tests/raptorq_conformance.rs:1209` | partial | Track B | `bd-1cjjy`, `bd-10hic` |
| `RFC 6330 §5.3.3.3` LDPC precode row construction | `src/raptorq/systematic.rs:487` | `tests/raptorq_perf_invariants.rs:90`, `tests/raptorq_perf_invariants.rs:148` | `tests/raptorq_conformance.rs:101`, `tests/raptorq_conformance.rs:125` | `tests/raptorq_perf_invariants.rs:667` | partial | Track B + C + D | `bd-2o5g6`, `bd-1rxlv` |
| `RFC 6330 §5.3.3.3` HDPC precode row construction (`Gamma * MT`) | `src/raptorq/systematic.rs:527` | `tests/raptorq_perf_invariants.rs:108`, `tests/raptorq_perf_invariants.rs:127` | `tests/raptorq_conformance.rs:155`, `tests/raptorq_perf_invariants.rs:884` | `tests/raptorq_perf_invariants.rs:667` | partial | Track B + C + D | `bd-2o5g6`, `bd-1rxlv` |
| Systematic LT identity rows for source symbols | `src/raptorq/systematic.rs:599`, `src/raptorq/decoder.rs:867`, `src/raptorq/decoder.rs:881` | `tests/raptorq_perf_invariants.rs:298` | `tests/raptorq_conformance.rs:101` | `tests/raptorq_conformance.rs:1209` | implemented | Track B + C | `bd-2o5g6` (parity hardening) |
| Repair tuple/equation generation parity between encoder and decoder | `src/raptorq/systematic.rs:1039`, `src/raptorq/decoder.rs:830` | `tests/raptorq_perf_invariants.rs:227`, `tests/raptorq_perf_invariants.rs:242`, `tests/raptorq_perf_invariants.rs:269` | `tests/raptorq_conformance.rs:125`, `tests/raptorq_conformance.rs:155` | `tests/raptorq_perf_invariants.rs:667` | partial | Track B + C | `bd-1g5ww`, `bd-2o5g6`, `bd-2x68w` |
| Decode failure semantics: deterministic explicit error surfaces (insufficient symbols, size mismatch) | `src/raptorq/decoder.rs:213`, `src/raptorq/decoder.rs:271` | `tests/raptorq_perf_invariants.rs:825`, `tests/raptorq_perf_invariants.rs:852` | `tests/raptorq_conformance.rs:1209` (`insufficient_symbols` scenario) | `tests/raptorq_conformance.rs:1209` (stable report JSON) | partial | Track C + D | `bd-3frm1`, `bd-13sw8`, `bd-2ahc7` |
| Decode proof determinism + replay verification | `src/raptorq/decoder.rs:271`, `src/raptorq/proof.rs` | `tests/raptorq_perf_invariants.rs:506`, `tests/raptorq_perf_invariants.rs:538`, `tests/raptorq_perf_invariants.rs:570` | `tests/raptorq_conformance.rs:1209` | `tests/raptorq_conformance.rs:1209` (proof hash/report determinism) | implemented | Track C + D | `bd-3bvdj` (scenario expansion), `bd-26pqk` (catalog) |
| Deterministic end-to-end scenario reporting with stable artifact shape | `tests/raptorq_conformance.rs:729`, `tests/raptorq_conformance.rs:1179`, `tests/raptorq_conformance.rs:1209` | `tests/raptorq_conformance.rs:1209` | `tests/raptorq_conformance.rs:1209` | `tests/raptorq_conformance.rs:1209` (serialized report stability assertions) | partial | Track D | `bd-3bvdj`, `bd-oeql8`, `bd-26pqk`, `bd-mztvq` |
| Comprehensive unit matrix + deterministic E2E suite + structured logging contract (program requirement) | current unit corpus: `tests/raptorq_conformance.rs`, `tests/raptorq_perf_invariants.rs`, `src/raptorq/tests.rs` | present but not yet matrix-governed | present but not yet full scenario catalog-governed | mixed: deterministic JSON report exists; other areas still use ad-hoc stderr logs (`tests/raptorq_perf_invariants.rs:667`) | partial | Track D + G | `bd-61s90`, `bd-3bvdj`, `bd-oeql8`, `bd-26pqk`, `bd-322jd` |

## Notes on Explicit Gaps
- Parameter derivation is now table-driven from RFC 6330 Table 2 (`src/raptorq/rfc6330_systematic_index_table.inc`), but downstream tuple/equation semantics and full scenario coverage still need completion (`bd-1g5ww`, `bd-2o5g6`, `bd-61s90`).
- Tuple/degree semantics are deterministic but not yet fully RFC-exact for supported scope; this maps to `bd-1g5ww` and `bd-2o5g6`.
- Structured logging is partly implemented (deterministic JSON report path), but not yet normalized under a single schema contract across all RaptorQ tests; this maps to `bd-oeql8` and `bd-26pqk`.
- Some systematic encoder tests include a known small-`K` singularity workaround (`src/raptorq/systematic.rs:1111`), indicating additional robustness work still tracked separately.

## Determinism and Diff-Friendliness Rules
- Rows are ordered by clause/concern, then by execution flow (RNG -> parameters -> matrix -> repair/decode -> testing).
- All references are pinned to repository-relative paths with line anchors.
- Status values are restricted to `implemented`, `partial`, `planned`.
