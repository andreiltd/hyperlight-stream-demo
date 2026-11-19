# Build the guest, which the host loads at runtime.
build-guest:
    cd guest && cargo hyperlight build --release

# Build the guest and the host.
build: build-guest
    cargo build

# Stream the body at `url` through the guest.
run url="http://httpbin.org/stream/20": build-guest
    cargo run --quiet -- "{{url}}"

# Run all tests.
test: build-guest
    cargo test

# Lint the host and the guest.
clippy:
    cargo clippy --all-targets -- -D warnings
    cd guest && cargo hyperlight clippy --release -- -D warnings

# Move the host and guest lockfiles to the latest commit on the Hyperlight `streams` branch.
update-hyperlight:
    cargo update -p hyperlight-host
    cd guest && cargo update -p hyperlight-guest

# Format with nightly rustfmt.
fmt:
    cargo +nightly fmt --all
    cargo +nightly fmt --manifest-path guest/Cargo.toml
