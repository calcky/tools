FROM alpine:3.22

ARG TARGETARCH

RUN apk add --no-cache \
    bash bcc-dev bcc-static build-base clang18-dev clang18-static \
    elfutils-dev go libelf-static libffi-dev libpcap-dev \
    libxml2-dev libxml2-static linux-headers llvm18-dev llvm18-static \
    xz-static zlib-static zstd-static bzip2-static git tcpdump

RUN apk add --no-cache libbpf-dev

RUN if [ "$TARGETARCH" = arm64 ]; then \
      apk add --no-cache flex flex-dev bison && \
      wget -q https://www.tcpdump.org/release/libpcap-1.10.7.tar.gz -O /tmp/libpcap.tar.gz && \
      echo '0b394ac90dbc0a9838ff97468e05c9c9a3e873dec2514cd58db65d859d296e31  /tmp/libpcap.tar.gz' | sha256sum -c - && \
      tar -xf /tmp/libpcap.tar.gz -C /tmp && \
      cd /tmp/libpcap-1.10.7 && \
      CFLAGS='-O2 -fno-pic -fno-PIE' LDFLAGS=-no-pie ./configure --disable-shared && \
      make -j4 && \
      install -m 0644 libpcap.a /usr/local/lib/libpcap.a; \
    fi

WORKDIR /src
