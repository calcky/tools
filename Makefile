CARGO ?= cargo
CARGO_FLAGS ?= --locked
TARGET_DIR ?= irqtop/target
NETPING_TARGET_DIR ?= netping/target
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

.PHONY: all irqtop netping check check-irqtop check-netping install install-irqtop install-netping

all: irqtop netping

irqtop:
	$(CARGO) build --manifest-path irqtop/Cargo.toml --release $(CARGO_FLAGS) --target-dir "$(abspath $(TARGET_DIR))"
	install -D -m 755 "$(TARGET_DIR)/release/irqtop" bin/irqtop
	ln -sfnT irqtop bin/irqstat

netping:
	$(CARGO) build --manifest-path netping/Cargo.toml --release $(CARGO_FLAGS) --target-dir "$(abspath $(NETPING_TARGET_DIR))"
	install -D -m 755 "$(NETPING_TARGET_DIR)/release/netping" bin/netping

check: check-irqtop check-netping

check-irqtop:
	$(CARGO) fmt --manifest-path irqtop/Cargo.toml -- --check
	$(CARGO) test --manifest-path irqtop/Cargo.toml $(CARGO_FLAGS) --target-dir "$(abspath $(TARGET_DIR))"
	$(CARGO) clippy --manifest-path irqtop/Cargo.toml $(CARGO_FLAGS) --all-targets --target-dir "$(abspath $(TARGET_DIR))" -- -D warnings

check-netping:
	$(CARGO) fmt --manifest-path netping/Cargo.toml -- --check
	$(CARGO) test --manifest-path netping/Cargo.toml $(CARGO_FLAGS) --target-dir "$(abspath $(NETPING_TARGET_DIR))"
	$(CARGO) clippy --manifest-path netping/Cargo.toml $(CARGO_FLAGS) --all-targets --target-dir "$(abspath $(NETPING_TARGET_DIR))" -- -D warnings

install: install-irqtop install-netping

install-irqtop:
	test -x bin/irqtop
	install -D -m 755 bin/irqtop "$(DESTDIR)$(BINDIR)/irqtop"
	ln -sfnT irqtop "$(DESTDIR)$(BINDIR)/irqstat"

install-netping:
	test -x bin/netping
	install -D -m 755 bin/netping "$(DESTDIR)$(BINDIR)/netping"
