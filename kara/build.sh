#!/bin/sh
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
cd "$root"

make host-tests
make clean
make all

artifact=out/kara-ghostlock-experimental-newer.arm
file "$artifact"
if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$artifact" | awk '{print $1}')
else
    actual=$(shasum -a 256 "$artifact" | awk '{print $1}')
fi

printf '%s  %s\n' "$actual" "$artifact"
