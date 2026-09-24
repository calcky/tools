#!/usr/bin/env bash
set -euo pipefail

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
toolchain=${RUST_TOOLCHAIN:-1.96.0}
image_version=0.2.5
targets=(armv7-unknown-linux-musleabihf aarch64-unknown-linux-musl x86_64-unknown-linux-musl)
names=(armv7 arm64 x86_64)
linkers=(arm-linux-musleabihf-gcc aarch64-linux-musl-gcc x86_64-linux-musl-gcc)

rustup target add --toolchain "$toolchain" "${targets[@]}"
rust_sysroot=$(rustc +"$toolchain" --print sysroot)
cargo_cache=${CARGO_HOME:-$HOME/.cargo}
mkdir -p "$repo/dist"

for i in "${!targets[@]}"; do
    target=${targets[$i]}
    name=${names[$i]}
    linker_key=CARGO_TARGET_$(tr '[:lower:]-' '[:upper:]_' <<< "$target")_LINKER
    docker run --rm --user "$(id -u):$(id -g)" \
        --volume "$repo:/work" --workdir /work \
        --volume "$rust_sysroot:/rust:ro" --volume "$cargo_cache:/cargo" \
        --env PATH=/rust/bin:/usr/local/bin:/usr/bin:/bin \
        --env CARGO_HOME=/cargo --env "CARGO_TARGET_DIR=/work/target/static/$name" \
        --env "$linker_key=${linkers[$i]}" \
        "ghcr.io/cross-rs/$target:$image_version" \
        cargo build --release --locked --bin netlens --target "$target"

    binary="$repo/target/static/$name/$target/release/netlens"
    if readelf -l "$binary" | grep -q 'INTERP'; then
        printf 'Dynamic interpreter found: %s\n' "$binary" >&2
        exit 1
    fi
    if readelf -d "$binary" | grep -q '(NEEDED)'; then
        printf 'Shared-library dependency found: %s\n' "$binary" >&2
        exit 1
    fi
    if readelf --dyn-syms --wide "$binary" | grep -q 'GLIBC_'; then
        printf 'glibc symbol dependency found: %s\n' "$binary" >&2
        exit 1
    fi
    install -m 0755 "$binary" "$repo/dist/netlens-linux-$name"
    file "$repo/dist/netlens-linux-$name"
done

cd "$repo/dist"
sha256sum netlens-linux-armv7 netlens-linux-arm64 netlens-linux-x86_64 > SHA256SUMS
{
    printf 'Source commit: %s\n' "$(git -C "$repo" rev-parse HEAD)"
    rustc +"$toolchain" --version
    printf 'Build: default features (counter-only TUI)\n'
    printf 'ARM ABI: ARMv7 little-endian EABI5, hard float\n'
    printf 'Linking: musl static\n'
    for target in "${targets[@]}"; do
        docker image inspect --format '{{join .RepoDigests " "}}' \
            "ghcr.io/cross-rs/$target:$image_version"
    done
} > BUILDINFO.txt
sha256sum --check SHA256SUMS
