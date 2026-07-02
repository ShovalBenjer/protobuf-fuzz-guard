# protobuf-fuzz-guard

A cross-language **protobuf fuzz-harness generator with CVE-pattern detection**.
Parse `.proto` files, scan them for known CVE / RUSTSEC classes and structural
DoS risks, and generate fuzz harnesses for **Python, C++, Go, and Rust**.

> This repository is being ported from Python to Rust. The Rust workspace under
> `crates/` is the going-forward implementation; the original Python package
> under `src/` remains until the cutover documented in
> [`docs/rust-migration-plan.md`](docs/rust-migration-plan.md) is signed off.
> The engineering decisions are backed by a cited research report,
> [`docs/rust-sota-research.md`](docs/rust-sota-research.md).

## Install / build (Rust)

```sh
cargo build --release --locked
./target/release/protofuzz --help
```

## Usage

```sh
# Scan .proto files — rich, span-highlighted diagnostics on stderr, exit 1 on critical.
protofuzz scan path/to/service.proto

# Machine-readable findings.
protofuzz scan --json path/to/service.proto

# Generate harnesses (default: all languages) into ./fuzz_harnesses/<lang>/.
protofuzz generate service.proto -l rust -l go -o out/

# List the CVE / RUSTSEC pattern catalog.
protofuzz patterns
```

## What it detects

| Rule | Severity | Attributed pattern |
|---|---|---|
| Message nesting depth ≥ 5 | critical | `PROTOBUF-RECURSION-PROTO2` |
| Message nesting depth 3–4 | warning | — |
| Direct recursive message reference | critical | `PROTOBUF-RECURSION-PROTO2` |
| `group` / `TYPE_GROUP` field | critical | `CVE-2024-7254-CLASS` |
| Repeated nested message | warning | — |
| ≥ 3 repeated `bytes` fields | warning | `PROTOBUF-UNKNOWN-FIELD-OVERFLOW` |

## CVE / RUSTSEC cross-reference

These are the live advisory classes the scanner is grounded in (verified against
primary sources — see the research report §9):

| Advisory | Runtime | Class | Fixed in |
|---|---|---|---|
| **CVE-2024-7254** (CVSS 8.7) | protobuf-java / -kotlin / JRuby | Stack overflow parsing nested **groups as unknown fields** | 3.25.5, 4.27.5, 4.28.2 |
| **RUSTSEC-2020-0002** (CVE-2020-35858, CVSS 9.8) | Rust `prost` | Stack overflow decoding deeply nested input | prost ≥ 0.6.1 |
| **RUSTSEC-2024-0437** (CVE-2025-53605) | Rust `protobuf` | Uncontrolled recursion in `skip_group` | rust-protobuf ≥ 3.7.2 |

The generated **Rust** harness decodes with `prost`, whose `DecodeContext`
enforces a recursion limit of 100 by default — so a harness built from this tool
inherits DoS protection unless `no-recursion-limit` is enabled.

## Development

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace            # or: cargo nextest run --workspace
```

Fuzzing (nightly) lives in [`fuzz/`](fuzz/README.md). Supply-chain policy is in
[`deny.toml`](deny.toml); CI runs `cargo-audit` and `cargo-deny`.

## Layout

```
crates/pfg-core/       # library: span-aware parser, scanner, harness generator
crates/protofuzz-cli/  # `protofuzz` binary (clap)
fuzz/                  # cargo-fuzz targets (nightly)
docs/                  # research report + migration plan
src/                   # legacy Python implementation (pre-cutover)
```

## License

MIT
