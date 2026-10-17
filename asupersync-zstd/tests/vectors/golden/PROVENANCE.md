# Golden decoding vectors: provenance (br-asupersync-t1fblr.10)

`MANIFEST.txt` lists every vector with its expectation, output length and the XXH64 (seed 0) of the output, the same digest the 264-frame `../frames_zstd_cli.txt` corpus records. Outputs are not committed. `tests/golden_vectors.rs` decodes every vector with `decode_all`, `decode_into` and `StreamDecoder`, and checks that libzstd (the dev-only oracle) agrees.

The XXH64 values were computed by a Python model of XXH64. Before it was used, the model was checked against all 264 digests recorded in `frames_zstd_cli.txt`, each frame decoded by the reference zstd 1.5.7 CLI.

## `upstream/`: facebook/zstd's golden tests

Copied unmodified from facebook/zstd at tag `v1.5.7` (commit `f8745da6ff1ad1e7bab384bd1f9d742439278e99`), `tests/golden-decompression/` (all 4 files) and `tests/golden-decompression-errors/` (all 3 `.zst` files). They were fetched from `https://raw.githubusercontent.com/facebook/zstd/v1.5.7/tests/<dir>/<file>`, and each is byte-identical to the copy vendored in the zstd-rs 0.1.0 crate.

Zstandard is Copyright (c) Meta Platforms, Inc. and affiliates, dual-licensed under the BSD license (https://github.com/facebook/zstd/blob/v1.5.7/LICENSE) and GPLv2. These files are used under the BSD license.

Upstream's `tests/cli-tests/decompression/golden.sh` requires `zstd -r -t` to accept every file in `golden-decompression/`. Its `detectErrors.sh` requires `zstd -t` to refuse every file in `golden-decompression-errors/`. The 1.5.7 CLI does both on this host.

| file | expect | output bytes | SHA-256 of the file |
|---|---|---|---|
| `upstream/golden-decompression/block-128k.zst` | ok | 131068 | `6a226ab40e6abcfc4a36baa04bf48f7ee56f166b8a26fbe2adb8fe771dceccba` |
| `upstream/golden-decompression/empty-block.zst` | ok | 0 | `ab5463fa31429bf81ced9f05e99b96b2fe88b1da37235a233f6bc96242332fbc` |
| `upstream/golden-decompression/rle-first-block.zst` | ok | 1048576 | `dd31b3fa6bb8601710cbde2c625660763bf38adc5255501e3d3a681cc0e4e1a4` |
| `upstream/golden-decompression/zeroSeq_2B.zst` | ok | 13 | `8505867ac00fb49eb455da1b1e44e7cba5126f03114a72fb195170f7c95f2ca7` |
| `upstream/golden-decompression-errors/off0.bin.zst` | error | - | `144e2f029389c67c361bd3879ac142671592802f01f805a6c0c2b3e564d8022c` |
| `upstream/golden-decompression-errors/truncated_huff_state.zst` | error | - | `c91a09d8824609d0643291803cbfb04b14213c02c890d5637bc3aed18e8a24f8` |
| `upstream/golden-decompression-errors/zeroSeq_extraneous.zst` | error | - | `85d7b2010abde2ff96ab8e6798b422d3cb78f8dd2108f83dbdd488da7056a6db` |

## `cli/`: frames written by the reference zstd 1.5.7 CLI

They were written with `zstd` 1.5.7 (`*** Zstandard CLI (64-bit) v1.5.7, by Yann Collet ***`) on the development host. Each one was checked to decode, with `zstd -d`, to exactly its input. They cover what `frames_zstd_cli.txt` (inputs of at most 70 KB) does not:
- frames of several blocks;
- the ultra level;
- streamed input with no content size;
- an 8 MiB window (the decoder's default limit);
- `--check` and `--no-check`;
- random data, which gives raw blocks;
- concatenated frames;
- skippable frames before and after a frame.

Inputs (not committed; their SHA-256 pins them):

- `tar400k`: the first 409600 bytes of `git archive --format=tar c0f2bc882 src/runtime` (git 2.55.0). SHA-256 `3fb3d198cfa487ab1fced5fcc2b0208fbb18007249794c77ed2ffe37ae11e5e7`.
- `jsonl300k`: the first 307200 bytes of `git show c0f2bc882:.beads/issues.jsonl`. SHA-256 `4b5f99a058ebee98f3630a9eeb5479a2626a9cfddea70e608e57318f2d16824f`.
- `libc300k`: the first 307200 bytes of the host's `/lib/x86_64-linux-gnu/libc.so.6`. SHA-256 `e5b48769928ac097ff530fe3a37daacd952abf192555b2bceb925b82d6d7a5ef`.
- `random200k`: Python `random.Random(20261013).randbytes(204800)`. SHA-256 `00614a5e917ea50faeaabcb6658a3bba5c58fce601a0dc097d7e3e25a6cc2805`.

`cat INPUT | zstd ...` feeds the input through a pipe. zstd then does not know its size, so the frame declares no content size.

| file | how it was made | output bytes | SHA-256 of the file |
|---|---|---|---|
| `cli/tar400k_l1.zst` | `zstd -q -c -1 tar400k` | 409600 | `86b3238f83e312fc4303a1aee586abae86601fb6a86634255399de36224357f7` |
| `cli/tar400k_l3.zst` | `zstd -q -c -3 tar400k` | 409600 | `6a304b19046bb5c06bc5d4de2fd0aecbf71c1f2b49f16d8cbef9b48076ff8285` |
| `cli/tar400k_l19.zst` | `zstd -q -c -19 tar400k` | 409600 | `b633817e736feae1735296eda9e3f249bb742ce6e61ff2e242344a5834d35d43` |
| `cli/tar400k_ultra22.zst` | `zstd -q -c --ultra -22 tar400k` | 409600 | `be4b35b8dbdaa6a3c04c2c52b2b438d262f489cebbe797b0487eaa56f5a9a208` |
| `cli/tar400k_l3_stream.zst` | `cat tar400k | zstd -q -c -3` | 409600 | `a543783f09780fec5cb9c55b61c1e81b10cc5eef63474f007ba876a94631d0af` |
| `cli/tar400k_l19_long23_stream.zst` | `cat tar400k | zstd -q -c -19 --long=23` | 409600 | `7932d218c900bc9029cb2fddd886e436f79e8b609b93e8b364b47a960ceafb98` |
| `cli/jsonl300k_l3_check.zst` | `zstd -q -c -3 --check jsonl300k` | 307200 | `67d471a6b073cc1049b152a32b379d245b1dc734f26556c04f2c7fd9c398ed9a` |
| `cli/jsonl300k_l9_nocheck.zst` | `zstd -q -c -9 --no-check jsonl300k` | 307200 | `69c52d8ebcb59d2602995aa27fd155b3949cb6c78eef4264a7e57eec8a6654b6` |
| `cli/libc300k_l3.zst` | `zstd -q -c -3 libc300k` | 307200 | `fd7c1e9e2da53ff79c2ac2b713eacb0e967accf8b8fae145c18c19bca70a3084` |
| `cli/libc300k_l19_stream.zst` | `cat libc300k | zstd -q -c -19` | 307200 | `806166e63aa6a29fd52247bd0240ba9f3e17f53ed59439f4139ce2e33719fec4` |
| `cli/random200k_l3.zst` | `zstd -q -c -3 random200k` | 204800 | `f4044a446fa0a6d3d8b11bec3ec456c7e1233b604a07d23898eb7cb04c71c2c7` |
| `cli/concat_jsonl_tar.zst` | `zstd -q -c -3` of the first 64 KiB of jsonl300k ++ `zstd -q -c -3` of the first 64 KiB of tar400k (two frames) | 131072 | `cee77314486ff23f15f296f96ca87f34de15bd8d0be42d7fade372e5fe4dd22c` |
| `cli/skippable_then_frame.zst` | a skippable frame (magic 0x184D2A50, 16-byte payload `asupersync-skip!`) ++ `zstd -q -c -3` of the first 4 KiB of jsonl300k | 4096 | `d298b475304c92ec483bcc82b399fafdb535303e69f6db34b16c4633964ea258` |
| `cli/frame_then_skippable.zst` | printf the first 4 KiB of tar400k through `zstd -q -c -3` ++ an empty skippable frame (magic 0x184D2A5F, size 0) | 4096 | `12e5f23fc9c1208b8807b23885cdb33146ed22cdb498f55ba08d89a244959285` |
| `cli/empty_stream.zst` | printf '' \| zstd -q -c (zstd sees the end of input at once, so it still writes a 1-byte content size of 0) | 0 | `f96deff1816083fdff8bc3e46c3fe6ca46a6bb49f4d5a00627616c13237a512c` |
