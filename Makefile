CARGO ?= cargo
CARGO_FLAGS ?= --locked
TARGET_DIR ?= irqtop/target
NETPING_TARGET_DIR ?= netping/target
FLOWGEN_TARGET_DIR ?= flowgen/target
CTOP_TARGET_DIR ?= ctop/target
NETLENS_TARGET_DIR ?= netlens/target
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

.PHONY: all irqtop netping flowgen ctop netlens check check-irqtop check-netping check-flowgen check-ctop check-netlens install install-irqtop install-netping install-flowgen install-ctop install-netlens

all: irqtop netping flowgen ctop netlens

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

ctop:
	$(CARGO) build --manifest-path ctop/Cargo.toml --release $(CARGO_FLAGS) --target-dir "$(abspath $(CTOP_TARGET_DIR))"
	install -D -m 755 "$(CTOP_TARGET_DIR)/release/ctop" bin/ctop

netlens:
	$(CARGO) build --manifest-path netlens/Cargo.toml --release $(CARGO_FLAGS) --target-dir "$(abspath $(NETLENS_TARGET_DIR))"
	install -D -m 755 "$(NETLENS_TARGET_DIR)/release/netlens" bin/netlens

check: check-irqtop check-netping check-flowgen check-ctop check-netlens

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

check-ctop:
	$(CARGO) fmt --manifest-path ctop/Cargo.toml -- --check
	$(CARGO) test --manifest-path ctop/Cargo.toml $(CARGO_FLAGS) --target-dir "$(abspath $(CTOP_TARGET_DIR))"
	$(CARGO) clippy --manifest-path ctop/Cargo.toml $(CARGO_FLAGS) --all-targets --target-dir "$(abspath $(CTOP_TARGET_DIR))" -- -D warnings

check-netlens:
	$(CARGO) fmt --manifest-path netlens/Cargo.toml -- --check
	$(CARGO) test --manifest-path netlens/Cargo.toml $(CARGO_FLAGS) --all-targets --target-dir "$(abspath $(NETLENS_TARGET_DIR))"
	$(CARGO) clippy --manifest-path netlens/Cargo.toml $(CARGO_FLAGS) --all-targets --target-dir "$(abspath $(NETLENS_TARGET_DIR))" -- -D warnings

install: install-irqtop install-netping install-flowgen install-ctop install-netlens

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

install-ctop:
	test -x bin/ctop
	install -D -m 755 bin/ctop "$(DESTDIR)$(BINDIR)/ctop"

install-netlens:
	test -x bin/netlens
	install -D -m 755 bin/netlens "$(DESTDIR)$(BINDIR)/netlens"
