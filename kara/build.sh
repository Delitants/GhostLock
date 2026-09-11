#!/bin/sh
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
cd "$root"

make host-tests
make clean
make all

file out/kara-ghostlock-PS7713-5443.arm
if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum out/kara-ghostlock-PS7713-5443.arm | awk '{print $1}')
else
    actual=$(shasum -a 256 out/kara-ghostlock-PS7713-5443.arm | awk '{print $1}')
fi

printf '%s  %s\n' "$actual" out/kara-ghostlock-PS7713-5443.arm
if [ "${REQUIRE_LIVE_TESTED_HASH:-0}" = 1 ]; then
    expected=a42185d743ee1d4c9c46c1e35f5fa0a40f5e9a7f81450308c3eab297677847d5
    [ "$actual" = "$expected" ] || {
        printf 'live-tested hash mismatch: expected %s\n' "$expected" >&2
        exit 1
    }
fi
