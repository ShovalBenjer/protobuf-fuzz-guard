# protobuf-fuzz-guard

**Real protobuf CVEs, found before release.**

![protobuf-fuzz-guard](docs/hero.webp)

[![CI](https://github.com/Zion-sewers/protobuf-fuzz-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/Zion-sewers/protobuf-fuzz-guard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

`protofuzz` is one static binary. No runtime. No network. Point it at a `.proto` file and it does two things:

1. **Scans the schema for CVE-pattern vulnerabilities.** A span-aware parser flags the exact constructs behind documented protobuf CVEs — recursive message references, deprecated `group` fields — with compiler-style diagnostics pointing at the offending field and line.
2. **Generates fuzz harnesses in four languages.** One command emits ready-to-run decode/round-trip harnesses for Python, C++, Go, and Rust. Snapshot tests prove all four generators emit correct code.

## 60 seconds

```sh
cargo build --release --locked
./target/release/protofuzz scan tree.proto
```

A schema with a recursive `Tree` message and a `group` field yields three critical findings and exit code 1. Try it on your own protos.

## What it does

- CVE-pattern detection with source-span diagnostics (via `miette`), rendered like compiler errors.
- Harness generation: `protofuzz generate -l rust -l go -o ./harnesses schema.proto`.
- One static binary. CI-friendly exit codes.

## Honest limits

- It detects schema-shape risk patterns, not runtime behavior. It flags the constructs; it does not fuzz your running service.
- The advisory catalog is small (three advisories), not a broad rule database.
- Generated harnesses are decode/round-trip templates. Running a real fuzz campaign needs a libFuzzer-capable setup.
- Requires a Rust 1.85+ toolchain to build.

---

Part of [Zion](https://github.com/Zion-sewers) — public infrastructure for trust in agents. The eval layer for the long-horizon era.
