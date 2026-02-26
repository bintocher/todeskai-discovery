.PHONY: build build-release test run-dev deploy fmt lint check

build:
	cargo build --bin discovery-server

build-release:
	cargo build --bin discovery-server --release

test:
	cargo test --workspace

check:
	cargo check --workspace

run-dev:
	RUST_LOG=info,discovery_server=debug \
	cargo run --bin discovery-server -- \
		--listen 0.0.0.0:3000 \
		--db-url sqlite:./discovery-dev.db?mode=rwc \
		--tls-mode none \
		--admin-password admin123

fmt:
	cargo fmt --all

lint:
	cargo clippy --workspace -- -D warnings
