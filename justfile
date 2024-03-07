# List all recipies
default:
	just --list --unsorted

# Cargo compile
cargo-compile:
	cargo test --workspace --no-run --locked

# Build application
build-app:
	cargo build --workspace --locked

# cargo clippy check
cargo-clippy-check:
    cargo clippy --no-deps --workspace --locked --tests -- -Dwarnings

# cargo fmt check
cargo-fmt-check:
	cargo fmt --all --check

# cargo test
cargo-test:
    cargo test --workspace --locked

# Test
test:
	cargo run --bin cosmos -- contract-info osmo1ymuvx9nydujjghgxxug28w48ptzcu9ysvnynqdw78qgteafj0syq247w5u --network osmosis-testnet
