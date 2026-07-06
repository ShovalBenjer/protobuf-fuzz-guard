# pfg-fuzz

Self-dogfooding fuzz targets for `pfg-core`. The scanner is a security tool, so
it must never panic on hostile input, and these targets prove that.

## Requirements

`cargo-fuzz` + libFuzzer need a **nightly** toolchain on x86-64/aarch64 Unix
(research §5). This crate is intentionally excluded from the main workspace so
stable `cargo build`/`cargo test` stay green.

```sh
cargo install cargo-fuzz
rustup toolchain install nightly
```

## Run

```sh
# from the repo root
cargo +nightly fuzz run fuzz_parser -- -max_total_time=60
cargo +nightly fuzz cmin fuzz_parser     # minimize the corpus
cargo +nightly fuzz tmin fuzz_parser <artifact>   # minimize a crash
```

## Targets

- `fuzz_parser`: parse, scan, and generate over arbitrary bytes (as UTF-8).
