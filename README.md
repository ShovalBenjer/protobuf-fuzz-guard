# protobuf-fuzz-guard

Catch protobuf schema vulnerabilities before attackers do, and turn every
message into a running fuzz campaign across four languages from one command.

`protobuf-fuzz-guard` reads your `.proto` files, flags the exact constructs
behind real protobuf CVEs, and generates fuzz harnesses for **Python, C++, Go,
and Rust**. Findings render as source-highlighted diagnostics that point at the
offending field, so a scan reads like a compiler error and drops straight into
CI.

```
  × Recursive message reference: Tree.left references itself. Vulnerable to
  │ unbounded recursion attacks.
   ╭─[service.proto:5:5]
 4 │     string value = 1;
 5 │     Tree left = 2;
   ·     ───────┬──────
   ·            ╰── here
 6 │     Tree right = 3;
   ╰────
  help: Unbounded stack recursion via deeply nested messages
```

> The Rust workspace under `crates/` is the maintained implementation. The
> original Python package under `src/` stays until the cutover in
> [`docs/rust-migration-plan.md`](docs/rust-migration-plan.md). Every design
> decision is backed by a cited report, [`docs/rust-sota-research.md`](docs/rust-sota-research.md).

## Why it matters

Protobuf parsers ship the same vulnerability classes across every language.
This tool checks your schema against three that are documented in primary
advisories:

| Advisory | Runtime | Class | Fixed in |
| --- | --- | --- | --- |
| CVE-2024-7254 (CVSS 8.7) | protobuf-java, protobuf-kotlin, JRuby | Stack overflow parsing nested groups as unknown fields | 3.25.5, 4.27.5, 4.28.2 |
| RUSTSEC-2020-0002 (CVE-2020-35858, CVSS 9.8) | Rust prost | Stack overflow decoding deeply nested input | prost 0.6.1 |
| RUSTSEC-2024-0437 (CVE-2025-53605) | Rust protobuf | Uncontrolled recursion in `skip_group` | rust-protobuf 3.7.2 |

## What you get

- Source-span diagnostics that name the exact field and line, rendered with
  `miette`.
- Fuzz harnesses for four languages from a single command.
- A vulnerability catalog grounded in the three advisories above.
- JSON output and a `1` exit code on critical findings, so `protofuzz scan` is a
  CI gate on its own.
- A single static binary. No runtime, no network access, and a dependency tree
  audited in CI by `cargo-audit` and `cargo-deny`.

## Install

```sh
cargo build --release --locked
./target/release/protofuzz --help
```

## Scan a schema

```sh
protofuzz scan path/to/service.proto
```

Diagnostics print to stderr. Add `--json` for machine-readable findings on
stdout:

```sh
protofuzz scan --json path/to/service.proto
```

Gate a pipeline on it. The command exits `1` when any critical finding is
present:

```sh
protofuzz scan proto/**/*.proto
```

## Generate harnesses

One command writes harnesses for every message to `fuzz_harnesses/<lang>/`. Pass
`-l` to select languages:

```sh
protofuzz generate service.proto -l rust -l go -o out/
```

## Try it now

Save this as `tree.proto`:

```proto
syntax = "proto3";
message Tree {
    string value = 1;
    Tree left = 2;
    Tree right = 3;
    group Legacy = 4;
}
```

Scan it:

```sh
protofuzz scan tree.proto
```

You get three critical findings, each highlighted at its source location: the
two recursive references and the deprecated `group` field. Exit code `1`.

## Detection rules

| Rule | Severity | Pattern |
| --- | --- | --- |
| Message nesting depth of 5 or more | critical | `PROTOBUF-RECURSION-PROTO2` |
| Message nesting depth of 3 to 4 | warning | none |
| Direct recursive message reference | critical | `PROTOBUF-RECURSION-PROTO2` |
| `group` or `TYPE_GROUP` field | critical | `CVE-2024-7254-CLASS` |
| Repeated nested message | warning | none |
| Three or more repeated `bytes` fields | warning | `PROTOBUF-UNKNOWN-FIELD-OVERFLOW` |

## Generated Rust harness

The Rust target decodes with `prost` and round-trips. `prost` enforces a
recursion limit of 100 by default through `DecodeContext`, so the harness
carries DoS protection unless `no-recursion-limit` is enabled.

```rust
#![no_main]

use libfuzzer_sys::fuzz_target;
use prost::Message;

use acme_v1::Person;

fuzz_target!(|data: &[u8]| {
    if let Ok(msg) = Person::decode(data) {
        let mut buf = Vec::with_capacity(msg.encoded_len());
        msg.encode(&mut buf)
            .expect("re-encoding a successfully decoded message is infallible");
        let _ = Person::decode(buf.as_slice());
    }
});
```

## Develop

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo nextest run --workspace
```

CI runs `rustfmt`, `clippy` with warnings denied, `nextest`, `cargo-audit`,
`cargo-deny`, and a nightly fuzz smoke run. Fuzzing lives in
[`fuzz/`](fuzz/README.md) and needs a nightly toolchain. Supply-chain policy is
in [`deny.toml`](deny.toml).

## Layout

```
crates/pfg-core/       Library: span-aware parser, scanner, harness generator
crates/protofuzz-cli/  The protofuzz binary, built on clap
fuzz/                  cargo-fuzz targets that self-test the scanner
docs/                  Research report and migration plan
src/                   Legacy Python implementation, kept until cutover
```

## License

MIT
