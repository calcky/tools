#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
COMMIT=d455f001315322db4d606a8bdf8c659ba36b269c
VERSION=$(tr -d '[:space:]' < "$PROJECT_DIR/VERSION")
ARCH=${1:-all}
JOBS=${NETTRACE_JOBS:-4}

case "$ARCH" in
  x86_64) PLATFORM=linux/amd64; SOURCE_ARCH=x86_64 ;;
  arm64) PLATFORM=linux/arm64; SOURCE_ARCH=aarch64 ;;
  arm) PLATFORM=linux/arm/v7; SOURCE_ARCH=arm ;;
  all)
    for target in x86_64 arm64 arm; do
      bash "$0" "$target"
    done
    exit 0
    ;;
  *) echo "usage: $0 [x86_64|arm64|arm|all]" >&2; exit 2 ;;
esac

if [[ ! "$JOBS" =~ ^[1-9][0-9]*$ ]]; then
  echo "NETTRACE_JOBS must be a positive integer" >&2
  exit 2
fi

SOURCE_DIR="$PROJECT_DIR/.build/nettrace-$ARCH"
IMAGE="nettrace-static:$VERSION-$ARCH"
mkdir -p "$PROJECT_DIR/.build" "$PROJECT_DIR/dist"
if [[ ! -d "$SOURCE_DIR/.git" ]]; then
  git init "$SOURCE_DIR"
  git -C "$SOURCE_DIR" remote add origin https://github.com/OpenCloudOS/nettrace.git
  git -C "$SOURCE_DIR" fetch --depth 1 origin "$COMMIT"
  git -C "$SOURCE_DIR" checkout --detach FETCH_HEAD
fi
if [[ $(git -C "$SOURCE_DIR" rev-parse HEAD) != "$COMMIT" ]]; then
  echo "nettrace source does not match pinned commit $COMMIT" >&2
  exit 1
fi

docker buildx build --platform "$PLATFORM" --file "$PROJECT_DIR/Dockerfile" \
  --tag "$IMAGE" --load "$PROJECT_DIR"
docker run --rm --platform "$PLATFORM" \
  --env "NETTRACE_ARCH=$SOURCE_ARCH" --env "NETTRACE_JOBS=$JOBS" \
  --env "NETTRACE_VERSION=$VERSION" \
  --volume "$SOURCE_DIR:/src" \
  --volume "$PROJECT_DIR/musl-compat.h:/build/musl-compat.h:ro" "$IMAGE" sh -euxc '
    make clean
    make -j"$NETTRACE_JOBS" STATIC=1 ARCH="$NETTRACE_ARCH" BPFTOOL=bpftool \
      HOST_CFLAGS="-D_GNU_SOURCE -include /build/musl-compat.h -O2 -Wall \
      -Wno-deprecated-declarations -DVERSION=$NETTRACE_VERSION -DRELEASE=-btf \
      -static $(pkg-config --static --libs libbpf)"
    strip --strip-unneeded src/nettrace
    if readelf -lW src/nettrace | grep -q INTERP; then
      echo "unexpected ELF interpreter" >&2
      exit 1
    fi
    if readelf -dW src/nettrace | grep -q NEEDED; then
      echo "unexpected shared library dependency" >&2
      exit 1
    fi
    ./src/nettrace -V
    ./src/nettrace -h > /dev/null
  '

install -m 0755 "$SOURCE_DIR/src/nettrace" "$PROJECT_DIR/dist/nettrace-linux-$ARCH"
(cd "$PROJECT_DIR/dist" && sha256sum "nettrace-linux-$ARCH" > "nettrace-linux-$ARCH.sha256")
echo "built $PROJECT_DIR/dist/nettrace-linux-$ARCH"
