#!/usr/bin/env bash
set -euo pipefail

cd /src
export CGO_ENABLED=1
export GOTOOLCHAIN=local

go mod vendor
patch --batch -p1 -i /build/gobpf-bcc.patch
g++ -O2 -c -I/usr/lib/llvm18/include /build/llvm-static-compat.cc -o /tmp/llvm-static-compat.o

# BCC needs the Clang frontend and LLVM backend even for an otherwise Go binary.
libs="/tmp/llvm-static-compat.o -Wl,--no-relax -Wl,--wrap=_ZN4llvm3sys14DynamicLibrary19getPermanentLibraryEPKcPNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE"
libs+=" -L/usr/lib/llvm18/lib -Wl,--start-group -lbcc -lbcc_bpf -lbcc-loader-static"
for archive in /usr/lib/llvm18/lib/libclang*.a; do
  libs+=" $archive"
done
libs+=" $(/usr/lib/llvm18/bin/llvm-config --link-static --libs --system-libs)"
libs+=" -L/usr/local/lib -lpcap -lbpf -lelf -ldw -lbz2 -llzma -lffi -lstdc++ -Wl,--end-group"

metadata="-X github.com/bytedance/netcap/cmd.GitCommit=$NETCAP_COMMIT"
metadata+=" -X github.com/bytedance/netcap/cmd.GitBranch=detached"
metadata+=" -X github.com/bytedance/netcap/cmd.GitState=modified"
metadata+=" -X github.com/bytedance/netcap/cmd.GitSummary=$NETCAP_COMMIT-static"
metadata+=" -X github.com/bytedance/netcap/cmd.BuildDate=$(date -u +%FT%TZ)"

go build -p "${NETCAP_JOBS:-4}" -mod=vendor -trimpath -buildvcs=false \
  -ldflags "$metadata -linkmode external -extldflags '-static $libs'" -o netcap .
strip --strip-unneeded netcap

if readelf -lW netcap | grep -q INTERP; then
  echo "unexpected ELF interpreter" >&2
  exit 1
fi
if readelf -dW netcap | grep -q NEEDED; then
  echo "unexpected shared library dependency" >&2
  exit 1
fi
./netcap version
./netcap --help > /dev/null
./netcap skb --help > /dev/null
./netcap skb -f 'icmp_rcv@1' -e 'icmp' -i lo --dry-run > /tmp/netcap-dry-run.c
grep -q icmp_rcv /tmp/netcap-dry-run.c
