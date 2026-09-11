#!/bin/sh
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
src="$root/kara/src"

for file in \
    kara_ghostlock.c \
    kara_ghostlock_v2.c \
    kara_ghostlock.h \
    kara_ghostlock_logic.c \
    kara_reclaim_engine.h \
    kara_reclaim_hash.h \
    kara_reclaim_layout.c \
    kara_reclaim_layout.h \
    kara_reclaim_probe.c \
    kara_reclaim_stage.c \
    kara_reclaim_readback.c
do
    test -f "$src/$file" || {
        printf 'missing required source: %s\n' "$file" >&2
        exit 1
    }
done

printf 'KARA_SOURCE_GATE=PASS\n'

build=$(mktemp -d "${TMPDIR:-/tmp}/kara-host-tests.XXXXXX")
trap 'rm -rf "$build"' EXIT HUP INT TERM
cc=${CC:-cc}
cflags='-std=c11 -Wall -Wextra -Werror -O2'

"$cc" $cflags -I"$src" \
    "$root/kara/tests/kara_ghostlock_test.c" \
    "$src/kara_ghostlock_logic.c" \
    -o "$build/kara_ghostlock_test"
"$build/kara_ghostlock_test"

"$cc" $cflags -I"$src" \
    "$root/kara/tests/kara_reclaim_layout_test.c" \
    "$src/kara_reclaim_layout.c" \
    -o "$build/kara_reclaim_layout_test"
"$build/kara_reclaim_layout_test"

"$cc" $cflags -I"$src" \
    "$root/kara/tests/kara_reclaim_hash_test.c" \
    -o "$build/kara_reclaim_hash_test"
"$build/kara_reclaim_hash_test"

"$cc" $cflags -I"$src" \
    "$root/kara/tests/kara_reclaim_readback_test.c" \
    "$src/kara_reclaim_readback.c" \
    -o "$build/kara_reclaim_readback_test"
"$build/kara_reclaim_readback_test"

printf 'KARA_HOST_TEST_GATE=PASS\n'
