OPENWRT_TARGET ?= x86_64-unknown-linux-musl
OPENWRT_BIN := target/$(OPENWRT_TARGET)/release/netlens

.PHONY: all test check openwrt clean

all: check

test:
	cargo test --all-targets

check:
	cargo fmt --all -- --check
	cargo clippy --all-targets -- -D warnings
	cargo test --all-targets

openwrt:
	cargo build --release --locked --target $(OPENWRT_TARGET)
	@if readelf -l "$(OPENWRT_BIN)" | grep -q 'Requesting program interpreter'; then \
		echo "error: $(OPENWRT_BIN) still has a dynamic program interpreter" >&2; \
		exit 1; \
	fi
	@if readelf -d "$(OPENWRT_BIN)" 2>/dev/null | grep -q '(NEEDED)'; then \
		echo "error: $(OPENWRT_BIN) still needs shared libraries" >&2; \
		exit 1; \
	fi
	@if readelf --dyn-syms --wide "$(OPENWRT_BIN)" 2>/dev/null | grep -q 'GLIBC_'; then \
		echo "error: $(OPENWRT_BIN) still references glibc symbols" >&2; \
		exit 1; \
	fi
	@file "$(OPENWRT_BIN)"

clean:
	cargo clean
