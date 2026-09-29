FROM alpine:3.22

RUN apk add --no-cache \
    build-base binutils clang llvm bpftool pkgconf git \
    libbpf-dev elfutils-dev libelf-static linux-headers \
    zlib-dev zlib-static zstd-dev zstd-static python3 py3-yaml

# The pinned nettrace source uses prepare/func_info APIs added in libbpf 1.6.
RUN git init /tmp/libbpf \
    && git -C /tmp/libbpf remote add origin https://github.com/libbpf/libbpf.git \
    && git -C /tmp/libbpf fetch --depth 1 origin 3b4f0ef5a6fa247ce1958d909c0e85e760249840 \
    && git -C /tmp/libbpf checkout --detach FETCH_HEAD \
    && make -C /tmp/libbpf/src -j4 BUILD_STATIC_ONLY=1 \
    && make -C /tmp/libbpf/src BUILD_STATIC_ONLY=1 PREFIX=/usr LIBDIR=/usr/lib install \
    && rm -rf /tmp/libbpf

WORKDIR /src
