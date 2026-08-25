# Associated-Data Threshold ECDSA (DKLs23)

Anonymous conference review artifact: DKLs23 threshold ECDSA with
associated data bound into the signing nonce.

## Install Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustc --version   # 1.70+ is sufficient
```

## Build and run associated-data tests

From this repository root:

```bash
# Functional test (2-of-3 signing with associated data + proof verify)
cargo test --lib s2x3_with_associated_data -- --nocapture

# Optional: 1000-run timing (proof size, prove cost, cumulative verify)
cargo test --release --lib bench_associated_data_1000 -- --ignored --nocapture
```

The first build downloads crates.io dependencies and may take a few minutes.
After compilation, the functional test should finish in under a minute.
