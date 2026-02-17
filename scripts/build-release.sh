#!/usr/bin/env sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
OUT_DIR="${1:-$ROOT_DIR/dist}"

mkdir -p "$OUT_DIR"

build() {
	suffix="$1"
	shift
	echo "==> building ${suffix}"
	CGO_ENABLED=0 GOOS=linux "$@" go build -trimpath -ldflags "-s -w" -o "$OUT_DIR/homeproxy-api-linux-${suffix}" "$ROOT_DIR"
}

build amd64 GOARCH=amd64
build 386 GOARCH=386
build arm64 GOARCH=arm64
build armv7 GOARCH=arm GOARM=7
build armv6 GOARCH=arm GOARM=6
build armv5 GOARCH=arm GOARM=5
build mips-softfloat GOARCH=mips GOMIPS=softfloat
build mips-hardfloat GOARCH=mips GOMIPS=hardfloat
build mipsle-softfloat GOARCH=mipsle GOMIPS=softfloat
build mipsle-hardfloat GOARCH=mipsle GOMIPS=hardfloat
build mips64 GOARCH=mips64
build mips64le GOARCH=mips64le
build riscv64 GOARCH=riscv64

echo "done: $OUT_DIR"
