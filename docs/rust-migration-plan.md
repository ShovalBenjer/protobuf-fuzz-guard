# protobuf-fuzz-guard → Rust: Implementation Plan

Derived from `docs/rust-sota-research.md`. This plan ports the existing Python
tool to a Rust workspace **and** adds Rust as a first-class generated
fuzz-harness target. It is phased so each milestone is independently shippable
and CI-green.

## Guiding decisions (from the research)

| Concern | Choice | Why (research §) |
|---|---|---|
| Edition | Rust 2024 | §1 |
| Layout | Cargo workspace: `pfg-core` lib + `protofuzz` bin + `fuzz/` | §1 |
| Version mgmt | `[workspace.dependencies]`, commit `Cargo.lock`, `--locked` | §1, §8 |
| CLI | `clap` v4 derive; stdout=data/JSON, stderr=logs; exit 1 on critical | §2 |
| Errors | `thiserror` (lib) + `miette` (diagnostics with source spans) | §3 |
| .proto parsing | **Start span-first with a hand-written scanner retaining byte spans** (mirrors current regex model, zero heavy deps, full control of `group`/nesting/`repeated`). Keep `protobuf-parse`→`prost-reflect` descriptor road as a Phase 5 upgrade. | §4 |
| Fuzz harness output | prost `Message::decode` + optional `#[derive(Arbitrary)]` roundtrip target under `libfuzzer-sys` | §5, §6, §9 |
| Testing | unit + integration under `cargo-nextest`; `proptest` for parser & roundtrip; `insta` for generated-harness snapshots | §7 |
| Supply chain | `deny.toml`, daily `cargo-audit`, `cargo-auditable` release builds | §8 |
| CI gates | clippy `-D warnings`, `fmt --check`, nextest, cargo-audit | §10 |

**Rationale for the parser choice:** `prost-build` is not a parser (§4);
`protobuf-parse` has no stable API and is "not intended for direct use" (§4, an
adoption risk for a security tool); `tree-sitter-proto` is compelling for spans
but was 4 commits old (§4, maturity risk). The current scanner is already a
line/regex model, and the CVE-relevant signals (`group`, message nesting depth,
`repeated` nested/bytes) are lexically local. So Phase 1 keeps a **self-contained
span-aware scanner** — no supply-chain surface added to a security tool — and we
treat descriptor-level analysis as an *additive* later phase, not a prerequisite.

## Target workspace layout

```
protobuf-fuzz-guard/
├── Cargo.toml                # [workspace] + [workspace.dependencies] + [workspace.lints]
├── Cargo.lock                # committed
├── deny.toml                 # cargo-deny policy (advisories/licenses/bans/sources)
├── rust-toolchain.toml       # pin stable channel + components (clippy, rustfmt)
├── crates/
│   ├── pfg-core/             # library: parser, model, scanner, patterns, harness-gen
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── proto/{mod.rs, lexer.rs, model.rs}   # span-aware parse
│   │   │   ├── patterns.rs   # CVE/RUSTSEC catalog (data)
│   │   │   ├── scanner.rs    # findings + miette Diagnostics
│   │   │   └── harness/{mod.rs, rust.rs, python.rs, cpp.rs, go.rs}
│   │   └── tests/            # integration + insta snapshots
│   └── protofuzz-cli/        # binary: clap subcommands scan/generate/patterns
│       └── src/main.rs
├── fuzz/                     # cargo-fuzz crate (nightly-gated), example targets
│   ├── Cargo.toml
│   └── fuzz_targets/*.rs
├── .github/workflows/ci.yml  # fmt, clippy, nextest, audit, (nightly) fuzz smoke
├── docs/…                    # this plan + research report
└── (legacy Python kept under src/ until Phase 6 parity sign-off)
```

## Phased milestones

### Phase 0 — Scaffold & CI skeleton
- `cargo new` workspace; add `pfg-core`, `protofuzz-cli`.
- `[workspace.dependencies]`: `clap` (derive), `thiserror`, `miette` (fancy),
  `serde`/`serde_json`. `[workspace.lints]` enabling clippy pedantic (selectively).
- `rust-toolchain.toml`, `deny.toml`, committed `Cargo.lock`.
- CI: fmt-check, clippy `-D warnings`, nextest, cargo-audit (see §10 gates).
- **Exit criterion:** empty workspace builds green in CI.

### Phase 1 — Port the parser (span-aware)
- Translate `proto_parser.py` → `pfg-core::proto`. Keep the model
  (`ProtoFile`/`ProtoMessage`/`ProtoField`) but attach **byte spans** to every
  message/field so findings can carry miette labels.
- Port `max_nesting_depth` and `has_recursive_refs`.
- Tests: port `test_proto_parser.py`; add a `proptest` strategy generating
  well-formed `.proto` snippets to fuzz the parser for panics (§7).
- **Exit criterion:** parser tests pass; parses the existing Python test fixtures
  identically.

### Phase 2 — Port patterns + scanner with real CVE data
- Port `models.py` catalog; **correct CVE-2024-7254 metadata** (Java/Kotlin/JRuby,
  groups-as-unknown-fields — not "cpp") per research §9.
- Add **RUSTSEC-2020-0002** (prost) and **RUSTSEC-2024-0437** (rust-protobuf) as
  first-class Rust patterns, with fixed-version notes.
- Port `scanner.py` rules; emit findings as **miette `Diagnostic`s with source
  spans** pointing at the offending line/field (§3). Preserve severity model and
  the "exit 1 on critical" contract.
- Tests: port `test_scanner.py`; snapshot the rendered diagnostics with `insta`.
- **Exit criterion:** scanner parity with Python on all fixtures + spans render.

### Phase 3 — Harness generator incl. the new Rust target
- Port `harness_gen.py` templates (python/cpp/go) verbatim into string templates.
- **Add `harness/rust.rs`**: generate a `libfuzzer-sys` `fuzz_target!` that
  `prost::Message::decode`s the bytes, does a **decode→encode→decode roundtrip**,
  and documents that prost's recursion limit (100) is the DoS guard (§6, §9).
  Optionally emit an `#[derive(Arbitrary)]` structure-aware variant.
- CLI `--lang rust` support; output `fuzz_<msg>.rs`.
- Tests: `insta` snapshots of all four languages; a compile-check test that the
  generated Rust harness at least parses (syntax) — full build is a fuzz-crate job.
- **Exit criterion:** `generate --lang rust` emits a harness that compiles against
  a prost-generated type in the `fuzz/` example.

### Phase 4 — CLI parity
- `clap` derive: `scan` / `generate` / `patterns` subcommands mirroring
  `cli.py`, `--json` on stdout, logs on stderr (§2), exit codes (0 clean, 1
  critical, 2 usage).
- Integration tests via `assert_cmd`/nextest against sample `.proto` files.
- **Exit criterion:** `protofuzz` CLI behavior matches the Python CLI on the same
  inputs (byte-for-byte JSON where feasible).

### Phase 5 — Self-dogfooding fuzz crate + optional descriptor road
- `fuzz/` crate (nightly-gated): a `fuzz_target!` over `pfg-core`'s **own parser**
  (fuzz the scanner with arbitrary `.proto` text) — the tool proves it doesn't
  panic on hostile schemas. Seed corpus from `tests/` fixtures; `cargo fuzz cmin`.
- CI: a **non-blocking nightly** job running a short `cargo fuzz run` smoke
  (bounded `-max_total_time`), since cargo-fuzz needs nightly + Unix (§5).
- *Optional upgrade:* wire `protobuf-parse` (pure-Rust) → `prost-reflect`
  `DescriptorPool` behind a `--descriptors` flag for semantic checks (import
  resolution, cross-file type refs) the lexical scanner can't do (§4).
- **Exit criterion:** fuzz smoke runs clean for its time budget in CI.

### Phase 6 — Cutover & hardening
- Flip the default entry point to Rust; move Python under `legacy/` (or delete
  after a parity sign-off documented in the plan).
- Release build with **`cargo-auditable`**; publish SBOM via `cargo-cyclonedx` (§8).
- README: install, usage, the CVE/RUSTSEC cross-reference table, security posture
  (recursion limits, pinned prost/rust-protobuf versions).
- **Exit criterion:** tagged `v0.2.0`, CI fully green, docs updated.

## Concrete initial dependency set (workspace)

```toml
[workspace.dependencies]
clap        = { version = "4", features = ["derive"] }
thiserror   = "2"
miette      = { version = "7", features = ["fancy"] }
serde       = { version = "1", features = ["derive"] }
serde_json  = "1"
# dev
insta       = "1"
proptest    = "1"
assert_cmd  = "2"
# fuzz crate (separate, nightly)
libfuzzer-sys = "0.4"
arbitrary     = { version = "1", features = ["derive"] }
prost         = "0.13"   # ≥0.6.1 required (RUSTSEC-2020-0002); pin current
```
Versions are validated/locked at scaffold time against crates.io; `Cargo.lock`
is committed and CI builds `--locked`.

## Risk register

| Risk | Mitigation |
|---|---|
| `protobuf-parse` has no stable API (§4) | Not on the critical path; only optional Phase 5 behind a flag. |
| `tree-sitter-proto` immaturity (§4) | Not adopted; hand-written span scanner instead. |
| cargo-fuzz needs nightly + Unix (§5) | Fuzz crate isolated; CI fuzz job nightly + non-blocking. |
| Every dep is statically linked into a security tool (§1, §8) | Minimal dep set; `cargo-deny` bans + license policy; daily `cargo-audit`. |
| Behavior drift vs Python during port | Golden fixtures + `insta` snapshots reused across both implementations until cutover. |

## What "go" executes first

Phases 0–4 are the buildable core. Execution starts by scaffolding the workspace
(Phase 0) and porting parser → scanner → harness-gen → CLI (Phases 1–4), each
committed as it goes green, then the fuzz crate (Phase 5). The Rust harness
target (Phase 3) is the headline new capability.
