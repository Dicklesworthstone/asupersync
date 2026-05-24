# ATP Autotune Replay Corpus

This directory stores reviewable noisy-pressure fixtures for
`asupersync-l9uzgt`. The corpus is intentionally compact JSON: each fixture
contains stable metric samples and the expected golden autotune receipt summary.

Re-run the corpus with:

```bash
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_p5 cargo test -p asupersync --test atp_autotune_replay_corpus -- --nocapture
```

Golden updates are manual: edit `corpus.json`, run the command above, and review
the JSON diff. Do not introduce wall-clock time, hostnames, absolute local paths,
or machine-specific identifiers.
