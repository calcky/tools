#!/usr/bin/env bash
set -euo pipefail

# Build against Alpine's static archives, including musl libc.

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PROJECT_DIR="$ROOT/bpftrace"
VERSION=${BPFTRACE_VERSION:-$(tr -d '[:space:]' < "$PROJECT_DIR/VERSION")}
COMMIT=${BPFTRACE_COMMIT:-872e7a56aa1f49909d4efa6cda8d14e2767ebe14}
ARCH=${1:-all}

case "$ARCH" in
  arm)
    PLATFORM=linux/arm/v7
    ;;
  arm64)
    PLATFORM=linux/arm64
    ;;
  x86_64)
    PLATFORM=linux/amd64
    ;;
  all)
    for target in arm arm64 x86_64; do
      "$0" "$target"
    done
    exit 0
    ;;
  *)
    echo "usage: $0 [arm|arm64|x86_64|all]" >&2
    exit 2
    ;;
esac

SOURCE_DIR="$PROJECT_DIR/.build/bpftrace-$VERSION-$ARCH"
IMAGE="bpftrace-static:$VERSION-$ARCH"
JOBS=${BPFTRACE_JOBS:-4}
if [[ ! "$JOBS" =~ ^[1-9][0-9]*$ ]]; then
  echo "BPFTRACE_JOBS must be a positive integer" >&2
  exit 2
fi

mkdir -p "$PROJECT_DIR/.build" "$PROJECT_DIR/dist"
if [[ ! -d "$SOURCE_DIR/.git" ]]; then
  rm -rf "$SOURCE_DIR"
  git clone --branch "v$VERSION" --depth 1 --recurse-submodules \
    https://github.com/bpftrace/bpftrace.git "$SOURCE_DIR"
fi

actual=$(git -C "$SOURCE_DIR" rev-parse HEAD)
if [[ "$actual" != "$COMMIT" ]]; then
  echo "bpftrace source mismatch: expected $COMMIT, got $actual" >&2
  exit 1
fi

docker buildx build \
  --platform "$PLATFORM" \
  --file "$SOURCE_DIR/docker/Dockerfile.static" \
  --tag "$IMAGE" \
  --load \
  "$SOURCE_DIR"

docker run --rm \
  --platform "$PLATFORM" \
  --env "BPFTRACE_JOBS=$JOBS" \
  --env LIBDIR=/src/build-static/libbpf/lib64 \
  --volume "$SOURCE_DIR:/src" \
  --workdir /src \
  "$IMAGE" \
  sh -euxc '
    git config --global --add safe.directory /src
    # libbpf builds objects in its source tree; remove stale objects on rebuild.
    make -C libbpf/src clean
    rm -rf build-static
    cmake -B build-static \
      -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_TESTING=OFF \
      -DENABLE_MAN=OFF \
      -DENABLE_SKB_OUTPUT=OFF \
      -DSTATIC_LINKING=ON
    # The upstream libbfd feature check needs dynamic linker flags; set -static
    # only after CMake has cached the correct signature check result.
    cmake -B build-static -DCMAKE_EXE_LINKER_FLAGS=-static
    cmake --build build-static --parallel "$BPFTRACE_JOBS"
    strip --strip-unneeded build-static/src/bpftrace
    ./build-static/src/bpftrace --version

    if readelf -lW build-static/src/bpftrace | grep -q INTERP; then
      echo "unexpected ELF interpreter" >&2
      exit 1
    fi
    needed=$(readelf -d build-static/src/bpftrace |
      sed -n "s/.*Shared library: \\[\\(.*\\)\\]/\\1/p")
    if [[ -n "$needed" ]]; then
      echo "unexpected dynamic dependency: $needed" >&2
      exit 1
    fi
  '

install -D -m 0755 "$SOURCE_DIR/build-static/src/bpftrace" \
  "$PROJECT_DIR/dist/bpftrace-linux-$ARCH"
(cd "$PROJECT_DIR/dist" &&
  sha256sum "bpftrace-linux-$ARCH" > "bpftrace-linux-$ARCH.sha256")
echo "built $PROJECT_DIR/dist/bpftrace-linux-$ARCH"
