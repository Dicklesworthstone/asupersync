# Native HTTP/2 h2spec conformance

Updated: 2026-09-07. Active bead: `asupersync-bi2462.36`.

The independent harness is implemented in
`tests/e2e_h2_graceful_drain.rs`, under
`external_h2spec::native_h2spec_strict_conformance`. The first executed sweep
passed 140 of 147 cases and exposed seven protocol failures. After repairs,
the 2026-09-06 23:46 UTC candidate passed all 147 cases with zero skips. Its
40-test native prerequisite and actual held-request cancellation/shutdown
probe also passed, with no remaining tasks, connections, or obligations.

That run's aggregate result remained failed: h2spec placed literal NUL bytes
in the intentionally invalid PING response's XML diagnostic, and strict XML
parsing rejected them. The parser now renders those NULs visibly in memory
while preserving the raw artifact and all case/count checks. The latest
candidate also preserves HPACK state when refusing an over-limit stream.
The next run completed on 2026-09-07 at 00:05 UTC: the maintained workflow
passed, including the strict positive and negative reports and ownership
cleanup. A compatibility adjustment preserves the public stream store's
aggregate limit setter while the connection negotiates directional limits.
The runner now also requires the complete H2 unit suite before h2spec;
that new stage and the compiler/lint gates remain outstanding. The bead is
still in progress.

The earlier compiler failures and the initial seven-case failure report are
retained. Private connection-future and test-boundary erasure resolved the
compiler recursion without increasing its limit or relaxing assertions.

## Pinned external tool

Use the Linux x86_64 executable from the official
[h2spec v2.6.0 release](https://github.com/summerwind/h2spec/releases/tag/v2.6.0).
The harness verifies the executable before and after running it and requires
this exact version output:

```text
Version: 2.6.0 (70ac2294010887f48b18e2d64f5cccd48421fad1)
```

| Artifact | SHA-256 |
| --- | --- |
| `h2spec_linux_amd64.tar.gz` | `157ee0de702e01ad40e752dbf074b366027e550c8e7504f9450da2809e279318` |
| Extracted `h2spec` executable | `ac679b916bcd46c52314b17c8903d8dffebf0f2357586d272731f6d8bfd5e9f7` |

These are measured content pins. The release supplied no publisher digest.
Install the executable on the explicitly selected RCH worker; the test also
uses that worker's `python3` standard library to parse JUnit XML.

## Run the maintained workflow

From shared `main`, select a full commit and only your reserved overlay files.
For a fully committed candidate, replace the overlay arguments with
`--no-overlay`. `H2SPEC_BIN` names the executable on the worker, not a local
file to be uploaded by RCH.

```bash
RCH_REQUIRE_REMOTE=1 RCH_WORKER="$H2_WORKER" \
H2SPEC_BIN="$H2_WORKER_BINARY" \
H2SPEC_CARGO_HOME="$H2_WORKER_CARGO_HOME" \
H2SPEC_RUN_DIR="$H2_LOCAL_EVIDENCE_DIR" \
H2SPEC_ARTIFACT_DIR="$H2_WORKER_EVIDENCE_DIR" \
RCH_TARGET_DIR="$H2_TARGET_DIR" \
bash scripts/run_h2_conformance_evidence.sh --h2spec \
  --base "$H2_SOURCE_COMMIT" \
  --overlay-path tests/e2e_h2_graceful_drain.rs \
  --overlay-path scripts/run_h2_conformance_evidence.sh
```

Include every uncommitted production repair needed by the candidate as another
explicit overlay. Both evidence directory leaves must be fresh. The worker
directory's parent must exist. `H2SPEC_CARGO_HOME` is optional;
`H2SPEC_BUILD_JOBS` defaults to 8 and `H2SPEC_STAGE_TIMEOUT` to 1800 seconds.

The runner requires installed RCH clean-overlay support and remote execution,
disables target reuse, and first runs the unfiltered native cancellation audit.
It runs all `http::h2::` library tests, then explicitly selects the external
test with `--ignored --exact`.
Ordinary test runs leave this tool-dependent test ignored and provide no
external conformance evidence.

The test starts the real two-worker native H2 listener, verifies actual GET
and POST responses, and invokes `h2spec --strict --verbose` over the full
`generic`, `http2`, and `hpack` groups using cleartext prior-knowledge H2. JUnit
case identities must match discovery from the same executable. A separate
owned negative listener completes SETTINGS exchange and returns one wrong
PING payload; the external oracle must reject exactly that case without a
startup failure or timeout. The native shutdown case parks a real request,
checks its registered task identity, then verifies cancellation, terminal
completion, connection/task cleanup, and runtime shutdown.
The shutdown probe runs before report parsing so a malformed external report
cannot bypass the ownership check.

## Read the result

`summary.json` in the local evidence directory records each command's actual
exit, selected worker, admitted source fingerprint, and test counts. Raw
external stdout, stderr, XML, parsed case reports, tool identity, and shutdown
receipts are copied into `external-artifacts/`, including on an unsuccessful
sweep. The runner joins these receipts to the accepted external summary.
Missing cases, skips, zero selection, failed ownership checks, timeouts, or a
nonzero remote exit cannot pass.

Source selection records admission and local file hashes. It explicitly does
not claim an independently hashed worker content manifest. Even a successful
run covers this native cleartext H2 service and the pinned external suite;
it does not establish H3, browser interoperability, TLS ecosystem coverage,
all RFC requirements, or broad workspace health.

## Historical internal checks

The 2026-04-24 `asupersync-h8pga6` work added internal assertions in
`tests/conformance/h2_rfc7540/stream_tests.rs` for stream ID zero,
self-dependent PRIORITY, dependency parsing, exclusive/weight preservation,
and short PRIORITY frames. Its external sweep was unavailable, and its remote
build attempts were blocked. Those historical assertions and blocker reports
are separate from the current independent run and are not a fresh external
conformance result.
