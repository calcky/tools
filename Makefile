CARGO ?= cargo
CARGO_FLAGS ?= --locked
TARGET_DIR ?= irqtop/target
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

.PHONY: all irqtop check install

all: irqtop

irqtop:
	$(CARGO) build --manifest-path irqtop/Cargo.toml --release $(CARGO_FLAGS) --target-dir "$(abspath $(TARGET_DIR))"
	install -D -m 755 "$(TARGET_DIR)/release/irqtop" bin/irqtop
	ln -sfnT irqtop bin/irqstat

check:
	$(CARGO) fmt --manifest-path irqtop/Cargo.toml -- --check
	$(CARGO) test --manifest-path irqtop/Cargo.toml $(CARGO_FLAGS) --target-dir "$(abspath $(TARGET_DIR))"
	$(CARGO) clippy --manifest-path irqtop/Cargo.toml $(CARGO_FLAGS) --all-targets --target-dir "$(abspath $(TARGET_DIR))" -- -D warnings

install:
	test -x bin/irqtop
	install -D -m 755 bin/irqtop "$(DESTDIR)$(BINDIR)/irqtop"
	ln -sfnT irqtop "$(DESTDIR)$(BINDIR)/irqstat"
