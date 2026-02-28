.PHONY: build install scan run clean fmt

build:
	cargo build --release

install:
	cargo install --path . --force
	@CARGO_BIN_DIR="$$HOME/.cargo/bin"; \
	PROFILE_FILES="$$HOME/.zshrc $$HOME/.bash_profile $$HOME/.bashrc $$HOME/.profile"; \
	for f in $$PROFILE_FILES; do \
	  if [ -f "$$f" ]; then \
	    if ! grep -qs "\.cargo/bin" "$$f"; then \
	      printf '\n# Add Rust Cargo bin to PATH for scanner\nexport PATH="$$HOME/.cargo/bin:$$PATH"\n' >> "$$f"; \
	      echo "Added $$CARGO_BIN_DIR to PATH in $$f"; \
	    fi; \
	  fi; \
	done; \
	# Ensure at least one profile exists with PATH entry
	case $$SHELL in \
	  */zsh) TARGET_FILE=$$HOME/.zshrc;; \
	  */bash) TARGET_FILE=$$HOME/.bash_profile;; \
	  *) TARGET_FILE=$$HOME/.profile;; \
	esac; \
	if ! grep -qs "\.cargo/bin" "$$TARGET_FILE" 2>/dev/null; then \
	  mkdir -p "$$(dirname "$$TARGET_FILE")"; \
	  printf '# Add Rust Cargo bin to PATH for scanner\nexport PATH="$$HOME/.cargo/bin:$$PATH"\n' >> "$$TARGET_FILE"; \
	  echo "Updated $$TARGET_FILE to include $$CARGO_BIN_DIR"; \
	fi; \
	# Try to symlink into /usr/local/bin if writable (optional)
	if [ -w /usr/local/bin ]; then \
	  ln -sf "$$CARGO_BIN_DIR/scanner" /usr/local/bin/scanner && echo "Linked scanner -> /usr/local/bin/scanner"; \
	else \
	  true; \
	fi; \
	echo "Install complete. Open a new terminal or run: $$([ -n "$$TARGET_FILE" ] && echo 'source '"$$TARGET_FILE")"; \
	echo "Pre-warming vulnerability cache (runs in background)..."; \
	nohup "$$CARGO_BIN_DIR/scanner" db seed --all >/dev/null 2>&1 &

# Usage:
# make scan FILE=/path/to/target [OUT=/path/to/report.json] [FORMAT=json|text] [MODE=light|deep] [REFS=1]
scan:
	@test -n "$(FILE)" || (echo "ERROR: provide FILE=/path/to/scan" && exit 1)
	@SCANNER_CACHE="$${SCANNER_CACHE:-$${HOME}/.cache/scanner}"; \
	mkdir -p "$$SCANNER_CACHE"; \
	REF_FLAG=$$( [ "$(REFS)" = "1" ] && echo "--refs" ); \
	FMT_FLAG=$$( [ -n "$(FORMAT)" ] && echo "--format $(FORMAT)" || echo "--format json" ); \
	MODE_FLAG=$$( [ -n "$(MODE)" ] && echo "--mode $(MODE)" ); \
	OUT_FLAG=$$( [ -n "$(OUT)" ] && echo "--out $(OUT)" ); \
	env SCANNER_CACHE="$$SCANNER_CACHE" ~/.cargo/bin/scanner scan --file "$(FILE)" $$FMT_FLAG $$MODE_FLAG $$REF_FLAG $$OUT_FLAG

# Example: make run ARGS="scan --file /bin/ls --format json"
run:
	cargo run -- $(ARGS)

clean:
	cargo clean

fmt:
	cargo fmt --all


