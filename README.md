# protobuf-fuzz-guard

Find the dangerous parts of a Protocol Buffers schema before an attacker does,
then generate the fuzz harnesses to prove it.

`protobuf-fuzz-guard` reads your `.proto` files, scans them for the structural
patterns behind real protobuf CVEs (unbounded recursion, deprecated groups,
memory-exhaustion shapes), and emits ready-to-run fuzz harnesses for **Python,
C++, Go, and Rust**. Findings are reported as source-highlighted diagnostics
that point at the exact field, so a scan result reads like a compiler error, not
a wall of text.

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

> This project is being ported from Python to Rust. The Rust workspace under
> `crates/` is the going-forward implementation and the subject of this README.
> The original Python package under `src/` stays in place until the cutover
> described in [`docs/rust-migration-plan.md`](docs/rust-migration-plan.md) is
> signed off. Every engineering decision here is backed by a cited research
> report, [`docs/rust-sota-research.md`](docs/rust-sota-research.md).

## Two ways to use it

**Scan.** Point it at a schema and get a prioritized list of DoS and CVE-class
risks, with the offending line highlighted. Exit code `1` on any critical
finding makes it a drop-in CI gate.

**Generate.** Turn every message in a schema into a fuzz harness for the
language of your choice. The Rust target decodes with `prost` and round-trips,
inheriting prost's built-in recursion limit as a first line of defense.

## Features

- Span-accurate diagnostics rendered with `miette`, so findings point at the
  exact field and line.
- A catalog of protobuf vulnerability classes grounded in primary advisories:
  CVE-2024-7254, RUSTSEC-2020-0002, and RUSTSEC-2024-0437.
- Harness generation for Python, C++, Go, and Rust from a single command.
- JSON output for scripting and CI (`--json`).
- Scriptable exit codes: `0` clean, `1` critical findings, `2` usage error.
- No network access and a deliberately small dependency tree, verified in CI by
  `cargo-audit` and `cargo-deny`.

## Install

```sh
cargo build --release --locked
./target/release/protofuzz --help
```

## Usage

Scan a schema. Diagnostics go to stderr, so you can pipe or redirect freely.

```sh
protofuzz scan path/to/service.proto
```

Get machine-readable findings on stdout.

```sh
protofuzz scan --json path/to/service.proto
```

Generate harnesses. By default all four languages are written to
`fuzz_harnesses/<lang>/`. Pass `-l` one or more times to narrow the set.

```sh
protofuzz generate service.proto -l rust -l go -o out/
```

List the vulnerability catalog the scanner checks against.

```sh
protofuzz patterns
```

### Try it first

Save this as `tree.proto` and scan it:

```proto
syntax = "proto3";
message Tree {
    string value = 1;
    Tree left = 2;
    Tree right = 3;
    group Legacy = 4;
}
```

```sh
protofuzz scan tree.proto
```

You will get three critical findings: the two recursive references and the
deprecated `group` field, each highlighted at its source location, and an exit
code of `1`.

### Use it in CI

```sh
protofuzz scan proto/**/*.proto || exit 1
```

## What it detects

| Rule | Severity | Attributed pattern |
| --- | --- | --- |
| Message nesting depth of 5 or more | critical | `PROTOBUF-RECURSION-PROTO2` |
| Message nesting depth of 3 to 4 | warning | none |
| Direct recursive message reference | critical | `PROTOBUF-RECURSION-PROTO2` |
| `group` or `TYPE_GROUP` field | critical | `CVE-2024-7254-CLASS` |
| Repeated nested message | warning | none |
| Three or more repeated `bytes` fields | warning | `PROTOBUF-UNKNOWN-FIELD-OVERFLOW` |

## CVE and RUSTSEC cross-reference

The scanner is grounded in live advisory classes, verified against primary
sources (see the research report, section 9).

| Advisory | Runtime | Class | Fixed in |
| --- | --- | --- | --- |
| CVE-2024-7254 (CVSS 8.7) | protobuf-java, protobuf-kotlin, JRuby | Stack overflow parsing nested groups as unknown fields | 3.25.5, 4.27.5, 4.28.2 |
| RUSTSEC-2020-0002 (CVE-2020-35858, CVSS 9.8) | Rust `prost` | Stack overflow decoding deeply nested input | prost 0.6.1 or later |
| RUSTSEC-2024-0437 (CVE-2025-53605) | Rust `protobuf` | Uncontrolled recursion in `skip_group` | rust-protobuf 3.7.2 or later |

The generated Rust harness decodes with `prost`, whose `DecodeContext` enforces
a recursion limit of 100 by default. A harness built from this tool therefore
inherits DoS protection unless `no-recursion-limit` is explicitly enabled.

## How a generated Rust harness looks

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

## Development

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

`cargo nextest run --workspace` is the runner used in CI. Snapshot tests use
`insta`; run `cargo insta review` after intentionally changing harness output.

Fuzzing lives in [`fuzz/`](fuzz/README.md) and requires a nightly toolchain.
Supply-chain policy is in [`deny.toml`](deny.toml). CI runs `rustfmt`, `clippy`
with warnings denied, `nextest`, `cargo-audit`, `cargo-deny`, and a non-blocking
nightly fuzz smoke run.

## Project structure

```
crates/pfg-core/       Library: span-aware parser, scanner, harness generator
crates/protofuzz-cli/  The protofuzz binary, built on clap
fuzz/                  cargo-fuzz targets that self-test the scanner (nightly)
docs/                  Research report and migration plan
src/                   Legacy Python implementation, kept until cutover
```

## Documentation

- [`docs/rust-sota-research.md`](docs/rust-sota-research.md): the cited research
  report behind the port, covering project layout, CLI design, error handling,
  parsing, fuzzing, testing, supply-chain hygiene, and protobuf security.
- [`docs/rust-migration-plan.md`](docs/rust-migration-plan.md): the phased plan
  that turned the research into this workspace.

## License

MIT
