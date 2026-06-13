#!/usr/bin/env bash
# Generate benchmark payloads + SHA-256 manifests (br-asupersync-iiz6jk).
# Runs on the SENDER machine. Idempotent: a payload with an existing,
# verifying manifest is left untouched.
set -euo pipefail

BASE="${1:-/root/atp-bench}"
PAYLOADS="$BASE/payloads"
MANIFESTS="$BASE/manifests"
mkdir -p "$PAYLOADS" "$MANIFESTS"

note() { echo "[gen_payloads] $*" >&2; }

# manifest <name> <path-relative-to-PAYLOADS...>
manifest() {
    local name="$1"; shift
    (cd "$PAYLOADS" && find "$@" -type f -print0 | sort -z | xargs -0 sha256sum) \
        > "$MANIFESTS/$name.sha256"
    note "manifest $name: $(wc -l < "$MANIFESTS/$name.sha256") entries"
}

have() { [[ -s "$MANIFESTS/$1.sha256" ]] && (cd "$PAYLOADS" && sha256sum --status -c "$MANIFESTS/$1.sha256" 2>/dev/null); }

gen_file() { # gen_file <name> <bytes>
    local name="$1" bytes="$2"
    if have "$name"; then note "$name: exists + verifies, skipping"; return; fi
    note "generating $name (${bytes} bytes)"
    head -c "$bytes" /dev/urandom > "$PAYLOADS/$name.bin"
    manifest "$name" "$name.bin"
}

gen_file single_512k   524288
gen_file single_1m    1048576
gen_file single_10m  10485760
gen_file single_100m 104857600
gen_file single_1g  1073741824

# Heterogeneous nested tree: deterministic shape, random content.
# ~800 small (4-64KB), ~150 medium (256KB-4MB), 6 large (64MB) => ~1.3 GB.
if have tree; then
    note "tree: exists + verifies, skipping"
else
    note "generating heterogeneous tree (this takes a minute)"
    rm -rf "$PAYLOADS/tree"
    mkdir -p "$PAYLOADS/tree"
    for d1 in a b c d; do
        for d2 in 0 1 2 3 4; do
            dir="$PAYLOADS/tree/$d1/depth2_$d2/deep3/deeper4/deepest5"
            mkdir -p "$dir"
            # 8 small files per leaf dir => 4*5*8 = 160 files per size step
            for i in $(seq 1 8); do
                head -c $(( 4096 + (i * d2 + 7) % 15 * 4096 )) /dev/urandom \
                    > "$dir/small_${i}.dat"
            done
            # a few files at intermediate depths with varied extensions
            head -c $(( 262144 + d2 * 524288 )) /dev/urandom \
                > "$PAYLOADS/tree/$d1/depth2_$d2/medium_$d2.tar"
            head -c $(( 131072 + d2 * 65536 )) /dev/urandom \
                > "$PAYLOADS/tree/$d1/depth2_$d2/deep3/notes_$d2.sqlite"
        done
        # medium files 1-4MB at the top of each branch
        for m in $(seq 1 30); do
            head -c $(( 1048576 + (m % 4) * 1048576 )) /dev/urandom \
                > "$PAYLOADS/tree/$d1/medium_${m}.bin"
        done
    done
    # large files
    for l in $(seq 1 6); do
        head -c 67108864 /dev/urandom > "$PAYLOADS/tree/large_${l}.img"
    done
    # empty file + zero-byte edge + a deeply nested single byte
    : > "$PAYLOADS/tree/a/empty.txt"
    printf 'x' > "$PAYLOADS/tree/b/depth2_0/deep3/deeper4/deepest5/one_byte"
    manifest tree tree
fi

note "payload totals:"
du -sh "$PAYLOADS"/* >&2
