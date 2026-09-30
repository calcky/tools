#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
VERSION=$(tr -d '[:space:]' < "$PROJECT_DIR/VERSION")
COMMIT=35de7182f1603c9e45d4b7d21bd79fc0da89a195
ARCH=${1:-all}
CROSS_BIN=${BPFTOP_CROSS:-cross}
export RUSTUP_TOOLCHAIN=${BPFTOP_RUST_TOOLCHAIN:-1.96.0}

case "$ARCH" in
  arm) TARGET=armv7-unknown-linux-musleabihf ;;
  arm64) TARGET=aarch64-unknown-linux-musl ;;
  x86_64) TARGET=x86_64-unknown-linux-musl ;;
  all)
    for target in arm arm64 x86_64; do
      "$0" "$target"
    done
    exit 0
    ;;
  *) echo "usage: $0 [arm|arm64|x86_64|all]" >&2; exit 2 ;;
esac

SOURCE_DIR="$PROJECT_DIR/.build/upstream"
mkdir -p "$PROJECT_DIR/.build" "$PROJECT_DIR/dist"
if [[ ! -d "$SOURCE_DIR/.git" ]]; then
  git clone --branch "v$VERSION" --depth 1 https://github.com/jfernandez/bpftop.git "$SOURCE_DIR"
fi
if [[ $(git -C "$SOURCE_DIR" rev-parse HEAD) != "$COMMIT" ]]; then
  echo "bpftop source does not match pinned commit $COMMIT" >&2
  exit 1
fi

cp "$PROJECT_DIR/Cross.toml" "$SOURCE_DIR/Cross.toml"
mkdir -p "$SOURCE_DIR/ci"
cp "$PROJECT_DIR/ci/Dockerfile."* "$SOURCE_DIR/ci/"

export LIBBPF_SYS_EXTRA_CFLAGS=-I/opt/bpftop/include
export RUSTFLAGS='-C target-feature=+crt-static -L native=/opt/bpftop/lib -C link-arg=-lzstd'
export CARGO_INCREMENTAL=0
(cd "$SOURCE_DIR" && "$CROSS_BIN" build --release --locked --target "$TARGET")

BINARY="$SOURCE_DIR/target/$TARGET/release/bpftop"
test -s "$BINARY"
if readelf -lW "$BINARY" | grep -q INTERP; then
  echo "unexpected ELF interpreter in $BINARY" >&2
  exit 1
fi
if readelf -dW "$BINARY" 2>&1 | grep -q NEEDED; then
  echo "unexpected dynamic dependency in $BINARY" >&2
  exit 1
fi
install -m 755 "$BINARY" "$PROJECT_DIR/dist/bpftop-linux-$ARCH"
(cd "$PROJECT_DIR/dist" && sha256sum "bpftop-linux-$ARCH" > "bpftop-linux-$ARCH.sha256")
echo "built $PROJECT_DIR/dist/bpftop-linux-$ARCH"
