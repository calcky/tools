#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
COMMIT=027dd2a763ebc893474f398b1eb28aab156e51c7
VERSION=$(tr -d '[:space:]' < "$PROJECT_DIR/VERSION")
ARCH=${1:-all}
JOBS=${NETCAP_JOBS:-4}

case "$ARCH" in
  x86_64) PLATFORM=linux/amd64 ;;
  arm64) PLATFORM=linux/arm64 ;;
  arm) PLATFORM=linux/arm/v7 ;;
  all)
    for target in x86_64 arm64 arm; do
      bash "$0" "$target"
    done
    exit 0
    ;;
  *) echo "usage: $0 [x86_64|arm64|arm|all]" >&2; exit 2 ;;
esac

if [[ ! "$JOBS" =~ ^[1-9][0-9]*$ ]]; then
  echo "NETCAP_JOBS must be a positive integer" >&2
  exit 2
fi

SOURCE_DIR="$PROJECT_DIR/.build/netcap-$ARCH"
CACHE_DIR="$PROJECT_DIR/.build/cache-$ARCH"
IMAGE="netcap-static:$VERSION-$ARCH"
mkdir -p "$SOURCE_DIR" "$CACHE_DIR" "$PROJECT_DIR/dist"
if [[ ! -d "$SOURCE_DIR/.git" ]]; then
  git init "$SOURCE_DIR"
  git -C "$SOURCE_DIR" remote add origin https://github.com/bytedance/netcap.git
  git -C "$SOURCE_DIR" fetch --depth 1 origin "$COMMIT"
  git -C "$SOURCE_DIR" checkout --detach FETCH_HEAD
fi
if [[ $(git -C "$SOURCE_DIR" rev-parse HEAD) != "$COMMIT" ]]; then
  echo "netcap source does not match pinned commit $COMMIT" >&2
  exit 1
fi

docker buildx build --platform "$PLATFORM" --file "$PROJECT_DIR/Dockerfile" \
  --tag "$IMAGE" --load "$PROJECT_DIR"
docker run --rm --platform "$PLATFORM" \
  --env "NETCAP_COMMIT=$COMMIT" --env "NETCAP_JOBS=$JOBS" \
  --env GOMODCACHE=/cache/mod --env GOCACHE=/cache/build \
  --volume "$SOURCE_DIR:/src" --volume "$CACHE_DIR:/cache" \
  --volume "$PROJECT_DIR:/build:ro" "$IMAGE" bash /build/build-in-container.sh

install -m 0755 "$SOURCE_DIR/netcap" "$PROJECT_DIR/dist/netcap-linux-$ARCH"
(cd "$PROJECT_DIR/dist" && sha256sum "netcap-linux-$ARCH" > "netcap-linux-$ARCH.sha256")
echo "built $PROJECT_DIR/dist/netcap-linux-$ARCH"
