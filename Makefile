CARGO ?= cargo
CARGO_FLAGS ?= --locked
TARGET_DIR ?= irqtop/target
NETPING_TARGET_DIR ?= netping/target
FLOWGEN_TARGET_DIR ?= flowgen/target
CTTOP_TARGET_DIR ?= cttop/target
NETLENS_TARGET_DIR ?= netlens/target
XPCAP_TARGET_DIR ?= xpcap/target
XPCAP_LIB_DIR ?= $(shell pkg-config --variable=libdir libelf)
XSKTOP_TARGET_DIR ?= xsktop/target
XSKTOP_LIB_DIR ?= $(shell pkg-config --variable=libdir libelf)
GOMEMTOP_TARGET_DIR ?= gomemtop/target
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

.PHONY: all irqtop netping flowgen cttop netlens xpcap check check-irqtop check-netping check-flowgen check-cttop check-netlens check-xpcap install install-irqtop install-netping install-flowgen install-cttop install-netlens install-xpcap

.PHONY: xsktop check-xsktop install-xsktop
.PHONY: gomemtop check-gomemtop install-gomemtop

all: irqtop netping flowgen cttop netlens xpcap xsktop gomemtop

irqtop:
	$(CARGO) build --manifest-path irqtop/Cargo.toml --release $(CARGO_FLAGS) --target-dir "$(abspath $(TARGET_DIR))"
	install -D -m 755 "$(TARGET_DIR)/release/irqtop" bin/irqtop
	ln -sfnT irqtop bin/irqstat

netping:
	$(CARGO) build --manifest-path netping/Cargo.toml --release $(CARGO_FLAGS) --target-dir "$(abspath $(NETPING_TARGET_DIR))"
	install -D -m 755 "$(NETPING_TARGET_DIR)/release/netping" bin/netping

flowgen:
	$(CARGO) build --manifest-path flowgen/Cargo.toml --release $(CARGO_FLAGS) --target-dir "$(abspath $(FLOWGEN_TARGET_DIR))"
	install -D -m 755 "$(FLOWGEN_TARGET_DIR)/release/flowgen" bin/flowgen

cttop:
	$(CARGO) build --manifest-path cttop/Cargo.toml --release $(CARGO_FLAGS) --target-dir "$(abspath $(CTTOP_TARGET_DIR))"
	install -D -m 755 "$(CTTOP_TARGET_DIR)/release/cttop" bin/cttop

netlens:
	$(CARGO) build --manifest-path netlens/Cargo.toml --release $(CARGO_FLAGS) --target-dir "$(abspath $(NETLENS_TARGET_DIR))"
	install -D -m 755 "$(NETLENS_TARGET_DIR)/release/netlens" bin/netlens

xpcap:
	LIBBPF_SYS_LIBRARY_PATH="$(XPCAP_LIB_DIR)" $(CARGO) build --manifest-path xpcap/Cargo.toml --release $(CARGO_FLAGS) --target-dir "$(abspath $(XPCAP_TARGET_DIR))"
	install -D -m 755 "$(XPCAP_TARGET_DIR)/release/xpcap" bin/xpcap

xsktop:
	LIBBPF_SYS_LIBRARY_PATH="$(XSKTOP_LIB_DIR)" $(CARGO) build --manifest-path xsktop/Cargo.toml --release $(CARGO_FLAGS) --target-dir "$(abspath $(XSKTOP_TARGET_DIR))"
	install -D -m 755 "$(XSKTOP_TARGET_DIR)/release/xsktop" bin/xsktop

gomemtop:
	$(CARGO) build --manifest-path gomemtop/Cargo.toml --release $(CARGO_FLAGS) --target-dir "$(abspath $(GOMEMTOP_TARGET_DIR))"
	install -D -m 755 "$(GOMEMTOP_TARGET_DIR)/release/gomemtop" bin/gomemtop

check: check-irqtop check-netping check-flowgen check-cttop check-netlens check-xpcap check-xsktop check-gomemtop

check-irqtop:
	$(CARGO) fmt --manifest-path irqtop/Cargo.toml -- --check
	$(CARGO) test --manifest-path irqtop/Cargo.toml $(CARGO_FLAGS) --target-dir "$(abspath $(TARGET_DIR))"
	$(CARGO) clippy --manifest-path irqtop/Cargo.toml $(CARGO_FLAGS) --all-targets --target-dir "$(abspath $(TARGET_DIR))" -- -D warnings

check-netping:
	$(CARGO) fmt --manifest-path netping/Cargo.toml -- --check
	$(CARGO) test --manifest-path netping/Cargo.toml $(CARGO_FLAGS) --target-dir "$(abspath $(NETPING_TARGET_DIR))"
	$(CARGO) clippy --manifest-path netping/Cargo.toml $(CARGO_FLAGS) --all-targets --target-dir "$(abspath $(NETPING_TARGET_DIR))" -- -D warnings

check-flowgen:
	$(CARGO) fmt --manifest-path flowgen/Cargo.toml -- --check
	$(CARGO) test --manifest-path flowgen/Cargo.toml $(CARGO_FLAGS) --target-dir "$(abspath $(FLOWGEN_TARGET_DIR))"
	$(CARGO) clippy --manifest-path flowgen/Cargo.toml $(CARGO_FLAGS) --all-targets --target-dir "$(abspath $(FLOWGEN_TARGET_DIR))" -- -D warnings

check-cttop:
	$(CARGO) fmt --manifest-path cttop/Cargo.toml -- --check
	$(CARGO) test --manifest-path cttop/Cargo.toml $(CARGO_FLAGS) --target-dir "$(abspath $(CTTOP_TARGET_DIR))"
	$(CARGO) clippy --manifest-path cttop/Cargo.toml $(CARGO_FLAGS) --all-targets --target-dir "$(abspath $(CTTOP_TARGET_DIR))" -- -D warnings

check-netlens:
	$(CARGO) fmt --manifest-path netlens/Cargo.toml -- --check
	$(CARGO) test --manifest-path netlens/Cargo.toml $(CARGO_FLAGS) --all-targets --target-dir "$(abspath $(NETLENS_TARGET_DIR))"
	$(CARGO) clippy --manifest-path netlens/Cargo.toml $(CARGO_FLAGS) --all-targets --target-dir "$(abspath $(NETLENS_TARGET_DIR))" -- -D warnings

check-xpcap:
	$(CARGO) fmt --manifest-path xpcap/Cargo.toml -- --check
	LIBBPF_SYS_LIBRARY_PATH="$(XPCAP_LIB_DIR)" $(CARGO) test --manifest-path xpcap/Cargo.toml $(CARGO_FLAGS) --target-dir "$(abspath $(XPCAP_TARGET_DIR))"
	LIBBPF_SYS_LIBRARY_PATH="$(XPCAP_LIB_DIR)" $(CARGO) clippy --manifest-path xpcap/Cargo.toml $(CARGO_FLAGS) --all-targets --target-dir "$(abspath $(XPCAP_TARGET_DIR))" -- -D warnings

check-xsktop:
	$(CARGO) fmt --manifest-path xsktop/Cargo.toml -- --check
	LIBBPF_SYS_LIBRARY_PATH="$(XSKTOP_LIB_DIR)" $(CARGO) test --manifest-path xsktop/Cargo.toml $(CARGO_FLAGS) --target-dir "$(abspath $(XSKTOP_TARGET_DIR))"
	LIBBPF_SYS_LIBRARY_PATH="$(XSKTOP_LIB_DIR)" $(CARGO) clippy --manifest-path xsktop/Cargo.toml $(CARGO_FLAGS) --all-targets --target-dir "$(abspath $(XSKTOP_TARGET_DIR))" -- -D warnings

check-gomemtop:
	$(CARGO) fmt --manifest-path gomemtop/Cargo.toml -- --check
	$(CARGO) test --manifest-path gomemtop/Cargo.toml $(CARGO_FLAGS) --target-dir "$(abspath $(GOMEMTOP_TARGET_DIR))"
	$(CARGO) clippy --manifest-path gomemtop/Cargo.toml $(CARGO_FLAGS) --all-targets --target-dir "$(abspath $(GOMEMTOP_TARGET_DIR))" -- -D warnings

install: install-irqtop install-netping install-flowgen install-cttop install-netlens install-xpcap install-xsktop install-gomemtop

install-irqtop:
	test -x bin/irqtop
	install -D -m 755 bin/irqtop "$(DESTDIR)$(BINDIR)/irqtop"
	ln -sfnT irqtop "$(DESTDIR)$(BINDIR)/irqstat"

install-netping:
	test -x bin/netping
	install -D -m 755 bin/netping "$(DESTDIR)$(BINDIR)/netping"

install-flowgen:
	test -x bin/flowgen
	install -D -m 755 bin/flowgen "$(DESTDIR)$(BINDIR)/flowgen"

install-cttop:
	test -x bin/cttop
	install -D -m 755 bin/cttop "$(DESTDIR)$(BINDIR)/cttop"

install-netlens:
	test -x bin/netlens
	install -D -m 755 bin/netlens "$(DESTDIR)$(BINDIR)/netlens"

install-xpcap:
	test -x bin/xpcap
	install -D -m 755 bin/xpcap "$(DESTDIR)$(BINDIR)/xpcap"

install-xsktop:
	test -x bin/xsktop
	install -D -m 755 bin/xsktop "$(DESTDIR)$(BINDIR)/xsktop"

install-gomemtop:
	test -x bin/gomemtop
	install -D -m 755 bin/gomemtop "$(DESTDIR)$(BINDIR)/gomemtop"
