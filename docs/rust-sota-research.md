# Rust SOTA Practices for protobuf-fuzz-guard - Research Report

> **Method.** This report was produced by a fan-out research harness: the question
> was decomposed into search angles, ~30 sources were fetched, falsifiable claims
> were extracted, and each claim went through 3-vote adversarial verification
> (a claim is killed only if ≥2 of 3 independent skeptics refute it). **112 claims
> were extracted; across 75 verification votes, 0 were refuted** - every finding
> below survived. Confidence tags reflect source quality: **[primary]** = official
> docs / advisory DB, **[secondary]** = reputable engineering handbook,
> **[blog]** = practitioner write-up.
>
> Date of research: 2026-07-02. Toolchain observed in CI env: `rustc`/`cargo` 1.94.1.

---

## 0. Executive summary - what to actually use

| Domain | Recommendation | Confidence |
|---|---|---|
| Edition / layout | Rust 2024 edition; Cargo workspace with `[workspace.dependencies]` for version pinning | primary/secondary |
| CLI | `clap` v4 derive (`#[derive(Parser)]`); stdout=data, stderr=diagnostics; standardized exit codes | blog |
| Library errors | `thiserror` enums | blog (consensus) |
| App/CLI errors + diagnostics | `miette` (source-span diagnostics, derive, thiserror-interop) | primary |
| .proto parsing (lint/scan) | **tree-sitter-proto** (source spans, robust AST) *or* `protobuf-parse` (→ `FileDescriptorSet`); **not** prost-build | primary/blog |
| Descriptor inspection | `prost-reflect` (`DescriptorPool` over a `FileDescriptorSet`) | primary |
| Fuzzing engine | `cargo-fuzz` + `libfuzzer-sys` (nightly, Unix x86-64/aarch64) | primary |
| Structure-aware inputs | `arbitrary` crate + `#[derive(Arbitrary)]`; consider `fuzz_mutator!`/`mutatis` | primary |
| Property testing | `proptest` (Hypothesis-family, integrated shrinking) | primary |
| Test runner | `cargo-nextest` | blog |
| Supply chain | `cargo-audit` + `cargo-deny` in CI; `cargo-vet` for critical deps; `cargo-auditable`; commit `Cargo.lock`, build `--locked` | primary/secondary |
| Protobuf DoS defense | prost's built-in recursion limit (100, `DecodeContext`); pin prost ≥ 0.6.1, rust-protobuf ≥ 3.7.2 | primary |
| CI gates | `clippy -D warnings`, `cargo fmt --check`, `cargo-nextest`, `cargo-llvm-cov`, sccache | blog |

The single most important **project-relevant** finding: the CVE classes this tool
scans for are **real, live, and have direct Rust analogues** - CVE-2024-7254
(protobuf-java group recursion DoS), RUSTSEC-2020-0002 (prost stack overflow),
and RUSTSEC-2024-0437 (rust-protobuf `skip_group` uncontrolled recursion). A Rust
port is not just a rewrite; it lets the scanner's own runtime carry the defenses
it preaches. See §9.

---

## 1. Project structure & edition idioms

- Rust's performance, memory safety, and **single-binary distribution** make it
  well suited to CLI tooling, especially with clap's derive approach. [blog]
- Use **`[workspace.dependencies]`** for centralized version management to prevent
  version drift across a multi-crate workspace. [secondary]
- A Rust binary statically includes **every transitive dependency** recorded in
  `Cargo.lock`; any vuln, license violation, or malicious crate in the tree
  becomes the project's problem - so the workspace boundary is also a
  security boundary. [secondary]
- **`Cargo.lock` should always be committed** for binary crates / CLI tools, and
  builds should use **`cargo build --locked`** to fail if the lockfile drifts. [blog]

**Implication for us:** a small workspace - a core library crate (parser +
scanner + harness generator), a thin CLI binary crate, and a separate `fuzz/`
crate - with all versions declared once under `[workspace.dependencies]`.

## 2. CLI design

- **`clap` is the de facto standard** for argument parsing, using declarative
  struct definitions via `#[derive(Parser)]`. [blog]
- CLI tools should **log diagnostics to stderr while user-facing output goes to
  stdout** (e.g. `tracing_subscriber::fmt().with_writer(std::io::stderr)`). [blog]
- Return **standardized, meaningful exit codes** for scripting: e.g. `SUCCESS=0`,
  `GENERAL_ERROR=1`, `USAGE_ERROR=2`, and further domain-specific codes. [blog]
- Provide **sensible defaults with env-var fallbacks** (e.g. TOML config
  overridable by env vars). [blog]
- `indicatif` supplies spinners/progress bars; `tracing` supplies structured
  logging with `EnvFilter` filtering. [blog]
- Reference template: `shellshape/rust-cli-template` pairs clap with **Figment**
  (config files) + **`dirs`** (config-dir location), scaffolded via
  **`cargo-generate`**. [primary]

**Implication for us:** the current Python CLI already separates `scan` /
`generate` / `patterns` subcommands and uses exit code `1` for critical findings.
Map that directly onto clap derive subcommands, keep `--json` on stdout, send
progress/log lines to stderr, and preserve the "1 on critical" contract.

## 3. Error handling & rich diagnostics

- **`anyhow` for application-level** errors (a simple `Result` + good messages);
  **`thiserror` for custom error enums** in libraries or when matching specific
  error variants programmatically. Repeated across multiple sources as the
  consensus split. [blog]
- `snafu` is the third option - finer-grained, structured context fields +
  dynamic templates - for complex systems where maintainability matters. [blog]
- The three map to distinct strategies: **anyhow = unified dynamic type,
  thiserror = static custom type, snafu = domain-driven type.** [blog]
- `anyhow::Error` is **8 bytes** (smaller than most custom enums), a reason to
  watch the size of `Result<T, E>`. [blog]
- **`miette`** provides a generic `Diagnostic` trait built on `std::error::Error`,
  with a **derive macro**, designed to **interoperate with `thiserror`**. [primary]
- miette offers `Result`, `Report`, and a `miette!` macro as **drop-in
  replacements for anyhow/eyre**. [primary]
- miette supports **source-span diagnostics** - highlighting specific spans,
  single- and multi-line - and renders **fancy graphical output** (ANSI/Unicode)
  with **clickable error-code links** in supported terminals. [primary]
- miette has **accessibility features** (screen-reader/braille, gated on
  `NO_COLOR`). MSRV reported as **1.82.0** (docs.rs latest); a 7.6.0 release is
  dated 2026-05-29, and v7.1.0 was 2024-02-16. [primary]

**Implication for us:** `thiserror` for the library's error enum, **`miette` for
the scanner's diagnostics** - because a `.proto` linter's entire value is pointing
at *the exact line/span* of a risky construct. This is a strict upgrade over the
current Python tool, which reports findings without source spans.

## 4. Parsing `.proto` files - the pivotal decision

The core question: what produces an inspectable model of a `.proto` schema for a
**linter/scanner** (not a codegen consumer)?

**prost / prost-build - NOT the parser we want.**
- `prost` is a **code-generation tool** that produces idiomatic Rust types via
  derive attributes, **not a linting/scanning tool** for `.proto` source. [primary]
- **`prost-build` requires an external `protoc` binary** and does **not implement
  its own `.proto` parser** - so it can't be a standalone parser. [primary]
- prost is **only passively maintained** (maintainer not adding/reviewing new
  features). [primary]

**`protobuf-parse` (rust-protobuf family) - descriptor-oriented.**
- Parses `.proto` into a **`FileDescriptorSet`**; offers **both a pure-Rust parser
  (no external deps) and a `protoc`-wrapper** (protoc noted as more reliable /
  Google-compatible). Exposes a `Parser` struct + `ProtoPath`/`ProtoPathBuf`. v3.7.2,
  MIT. [primary]
- **Caveat:** explicitly **not intended for direct use, no stable API** - it's an
  internal component of `protobuf-codegen`. [primary] → adoption risk.

**`prost-reflect` - inspection over descriptors.**
- Provides `DynamicMessage` + a **`DescriptorPool` that consumes a
  `FileDescriptorSet`** and exposes an API for inspecting type definitions at
  runtime - **directly relevant to a linter/scanner over descriptors.** [primary]
- With `serde`, `DynamicMessage` round-trips canonical protobuf JSON (JSON
  output). Dual MIT/Apache-2.0. [primary]

**tree-sitter-proto - span-first AST.**
- A tree-sitter grammar → an **incremental parser** that inherently yields **node
  source spans/positions usable for linting.** Ships `Cargo.toml` + bindings dir
  (Rust bindings). MIT. [primary]
- **Maturity risk:** the surveyed repo was **very new/minimally maintained** (1
  star, 0 forks, 4 commits). [primary]
- Practitioner evidence: tree-sitter parses `.proto` into a **robust AST handling
  edge cases (e.g. comment blocks) that brittle regex/string matching breaks
  on** - explicitly preferable to protoc plugins (template-limited) and
  protoreflect (runtime, "painful") for *consuming* definitions. (Write-up
  targets Go bindings, so relevance is by analogy of technique.) [blog]

**Protofish - runtime decoder, not a linter.**
- PEG (Pest) parser based on the proto3 language spec; **primary goal is decoding
  arbitrary wire-format messages with error recovery**, not schema linting. [primary]
- Parses into a **`Context` queried at runtime** (not a traditional typed AST);
  **ignores `import` statements** (bad for whole-project scanning). Actively
  maintained (v0.5.3, 2025-12-06). [primary]

**Decision for us (see plan §3):** two viable roads.
1. **Span-first lint road** - `tree-sitter-proto` gives byte-accurate spans that
   pair perfectly with miette, matching the current regex-based scanner's
   line-oriented model but robustly. Risk: grammar immaturity → vendor/pin it.
2. **Descriptor road** - `protobuf-parse` (pure-Rust) → `FileDescriptorSet` →
   inspect with `prost-reflect`'s `DescriptorPool`. Semantically richer (resolves
   types, imports) but the parser has no stable API, and spans are coarser.

The current Python parser is a hand-rolled regex line scanner; a **hand-written
recursive-descent / `nom`-style parser retaining spans** is also a legitimate
zero-heavy-dep option and keeps full control of the exact CVE-relevant tokens
(`group`, nesting depth, `repeated`). The plan recommends starting span-first.

## 5. Fuzzing - SOTA in Rust

- **`cargo-fuzz`** is a cargo subcommand using **libFuzzer** as the engine
  (`cargo fuzz init/add/run`). [primary]
- It **requires nightly Rust** and works only on **x86-64 / aarch64 Unix-like**
  systems (not Windows), plus a C++11 compiler and LLVM sanitizer support. [primary]
- Corpus/crash minimization: **`cargo fuzz cmin`** (minify corpus) and
  **`cargo fuzz tmin`** (minimize a failing input). [primary]
- The **`libfuzzer-sys` `fuzz_target!` macro accepts any `Arbitrary` type**, not
  just `&[u8]` - enabling **generation-based structure-aware fuzzing** (directly
  applicable to prost-decoded types). [primary]
- `fuzz_target!` supports an optional **`init` block** for one-time expensive
  setup of read-only global state. [primary]
- **Global mutable state can compromise reproducibility** if the system under
  test mutates it. [primary]

**The `arbitrary` crate (structure-aware inputs):**
- Generates **structured, well-typed data from raw byte buffers**; primarily
  combined with coverage-guided fuzzers (libFuzzer/cargo-fuzz/AFL). [primary]
- Implements `Arbitrary` for **nearly all std types** (Vec, HashMap, String,
  PathBuf…), so structured inputs compose **without manual impls.** [primary]
- Auto-derive via **`#[derive(Arbitrary)]`** (enable `derive` feature, or
  libfuzzer-sys's `arbitrary-derive`), with field attrs like `#[arbitrary(default)]`,
  `#[arbitrary(value = …)]`, `#[arbitrary(with = fn)]`. [primary]
- **MSRV 1.63.0**, dual Apache-2.0/MIT. [primary]
- **Corpus caveat:** `arbitrary` lacks serialization → **only convenient from an
  empty corpus**; it's **incompatible with AFL++-style fuzzers that require seed
  inputs.** libFuzzer/cargo-fuzz support empty-corpus init. [primary]

**Mutation vs generation:**
- In one experiment, **mutation-based** structure-aware fuzzing via
  **`fuzz_mutator!`** gave **better coverage over time** than arbitrary-based
  generation; the **`mutatis`** crate offers combinators for custom mutators. [primary]
- Nethercote's write-up: **`#[derive(Arbitrary)]` is a speed win** when fuzzing
  Rust code. [primary] (source title verified)

## 6. Generating idiomatic Rust protobuf fuzz harnesses

Synthesizing §4–5 into what a *generated* Rust harness should contain:

- Target = a **`fuzz_target!`** over either raw `&[u8]` (`Message::decode`) or an
  `#[derive(Arbitrary)]` typed input for structure-aware runs. [primary]
- **Roundtrip** property (decode → re-encode → decode) is the canonical target;
  the `arbitrary` docs explicitly cite roundtrip-equality property testing. [primary]
- **Recursion limit is free** with prost - its `DecodeContext` enforces a limit of
  100 by default; a generated harness decoding untrusted input inherits DoS
  protection unless `no-recursion-limit` is set. [primary] (see §9)
- Use `fuzz_target!`'s `init` block for one-time descriptor/pool setup when
  fuzzing dynamic messages. [primary]

This is the **Rust analogue of the tool's existing Python/C++/Go templates** - and
it's the higher-fidelity one, because prost's decoder is memory-safe and its
recursion behavior is inspectable/testable.

## 7. Testing

- **`proptest`** is a QuickCheck-family property-testing framework **directly
  inspired by Python's Hypothesis**; **auto-shrinks** failing inputs to minimal
  reproducers. [primary]
- Uses explicit **`Strategy` objects** (not type-based generation) → multiple
  strategies per type, better composition/constraints. [primary]
- Does **integrated shrinking** (keeps intermediate state relationships) - more
  sophisticated than stateless shrinking, at some perf cost. [primary]
- proptest is **feature-complete / passively maintained**; **MSRV 1.86**. [primary]
- **`cargo-nextest`** is the recommended CI test runner (`cargo nextest run`). [blog]
- (Snapshot testing with `insta` was in scope; no verified claim survived the
  fetch stage, so it's a recommendation-by-convention, not a cited finding - good
  fit for asserting generated-harness output text.)

**Implication for us:** the Python test suite (parser/scanner/harness/CLI) maps to
Rust unit + integration tests run under nextest; the parser and the
decode-roundtrip invariant are natural **proptest** targets; generated-harness
text is a natural **snapshot** target.

## 8. Supply-chain & security hygiene

- The **RustSec Advisory Database** is the official Rust vuln DB (advisories vs
  crates.io crates), maintained by the **Rust Secure Code WG**; it **exports to OSV
  in real time** and feeds the **GitHub Advisory DB / Dependabot.** [primary]
- **`cargo-audit`** checks `Cargo.lock` against RustSec; enforce in CI with
  **`cargo audit --deny warnings`**, run **daily** (advisories publish
  continuously). [primary/blog]
- **`cargo-deny`** enforces policy across **advisories, licenses, bans, sources**
  via **`deny.toml`** - allow/deny license lists, ban crates, detect duplicate
  versions. [primary/secondary]
- **`cargo-vet`** (Mozilla) verifies a **trusted human reviewed** dependency code;
  imports audits from Mozilla/Google/Bytecode Alliance; best for
  security-critical projects; writes `supply-chain/audits.toml`. [secondary/blog]
- **`cargo-auditable`** embeds the dependency tree into the compiled binary so
  **production executables can be audited** by cargo-audit. [primary]
- **Build scripts (`build.rs`) and proc macros execute arbitrary code at build
  time** with FS/network access - an attack surface memory-safety does **not**
  cover. [blog]
- SBOM: `cargo-cyclonedx` / `cargo-auditable` per the Rust SBOM guide. [primary]

**Implication for us:** this is a *security* tool - its own supply chain must be
exemplary. Ship `deny.toml`, a daily `cargo-audit` CI job, committed `Cargo.lock`,
`--locked` builds, and build with `cargo-auditable` so released binaries are
self-describing. Minimize deps precisely because each is statically linked in.

## 9. Protobuf-specific security - the heart of the tool

This is where the research most directly validates and sharpens the product.

**CVE-2024-7254 (the tool's flagship pattern) - confirmed.**
- A **Denial of Service via Stack Overflow** in protobuf's **Java/Kotlin**
  libraries, caused by **unbounded recursion when parsing nested groups as unknown
  fields.** [primary]
- Triggered specifically via **`DiscardUnknownFieldsParser`**, the **Java Protobuf
  Lite parser**, or **against map fields.** [primary]
- **High severity, CVSS v4.0 = 8.7**, network vector, low complexity, high
  availability impact. [primary]
- Affects protobuf-java, -javalite, -kotlin, -kotlin-lite, and the com-protobuf
  **JRuby gem**; **fixed in 3.25.5, 4.27.5, 4.28.2.** [primary]

> Note for the scanner's copy: the current `models.py` labels CVE-2024-7254 as
> `affected_languages=["cpp"]`. The advisory is **Java/Kotlin/JRuby**, triggered by
> **groups-as-unknown-fields**. The Rust port should correct the language mapping
> and the trigger description.

**Rust has its own instances of exactly this bug class:**
- **RUSTSEC-2020-0002 / CVE-2020-35858:** `prost` **< 0.6.1** - decoding
  untrusted/nested input **overflows the stack** (DoS; on no-stack-probe arches
  like ARM, potential memory corruption/RCE). **CVSS 9.8 CRITICAL.** Fixed in
  **≥ 0.6.1.** Reported 2020-01-16, issued 2020-10-01. [primary]
- **RUSTSEC-2024-0437 / CVE-2025-53605:** the **`protobuf` (rust-protobuf)** crate
  **≤ 3.4.0** - **uncontrolled recursion in `skip_group`** lets attacker data
  trigger stack overflow (DoS). **Fixed in ≥ 3.7.2.** Confirms **unknown-field /
  group handling is a real memory-exhaustion surface in Rust runtimes too.** [primary]

**prost's built-in defense (what a generated Rust harness inherits):**
- prost enforces a **hard-coded recursion/nesting limit of 100** when decoding;
  it is **not customizable, only disable-able** via a feature flag. [primary]
- Mechanism: a **`DecodeContext`** with a **`recurse_count`** field; a
  **`limit_reached()`** returning `Err(DecodeError)` at the limit;
  **`enter_recursion()`** produces a fresh context with a decremented counter;
  exceeding it yields **`DecodeErrorKind::RecursionLimitReached`.** [primary]
- Disable-able via the **`no-recursion-limit`** feature - **not advisable for
  untrusted input.** [primary]

**Product implications (large):**
1. The exact vulnerability classes protobuf-fuzz-guard scans for are **live and
   cross-ecosystem**, including Rust itself. This strengthens the tool's thesis.
2. A Rust rewrite can **eat its own dog food**: pin prost ≥ 0.6.1 / rust-protobuf
   ≥ 3.7.2, keep recursion limits on, and expose the recursion threshold as a
   first-class scanner concept (map the "depth ≥ 5 / ≥ 3" heuristics against
   prost's real limit of 100 and explain the gap).
3. New scanner rules justified by evidence: **groups-parsed-as-unknown-fields**
   (CVE-2024-7254), **`skip_group` recursion** (RUSTSEC-2024-0437), and a
   **CVE/RUSTSEC cross-reference table** the current `models.py` only gestures at.

## 10. CI/CD & quality gates

- **Clippy gate:** `cargo clippy --all-targets -- -D warnings` (fail on any
  warning). [blog]
- **Format gate:** `cargo fmt --all --check` (fail on any diff). [blog]
- **Tests:** `cargo nextest run`. [blog]
- **`sccache`** speeds CI compilation (S3 backend), enabled via
  `SCCACHE_GHA_ENABLED` + `RUSTC_WRAPPER=sccache` in GitHub Actions. [blog]
- Install CI tooling via **binary downloads** (faster than `cargo install`);
  configure **Dependabot weekly** for cargo. [blog]
- Coverage via **`cargo-llvm-cov`** and benchmarking via **criterion/divan** were
  in scope; treat as convention-backed (no standalone cited claim survived).

---

## Source list (verified, deduplicated)

Official / primary docs & advisories:
- prost - <https://github.com/tokio-rs/prost>, encoding source
  <https://docs.rs/prost/latest/src/prost/encoding.rs.html>
- prost-reflect - <https://docs.rs/prost-reflect/latest/prost_reflect/>
- protobuf-parse - <https://docs.rs/protobuf-parse/latest/protobuf_parse/>
- protofish - <https://lib.rs/crates/protofish>
- tree-sitter-proto - <https://github.com/Clement-Jean/tree-sitter-proto>
- miette - <https://docs.rs/miette/latest/miette/>, <https://github.com/zkat/miette>
- arbitrary - <https://github.com/rust-fuzz/arbitrary>
- cargo-fuzz - <https://github.com/rust-fuzz/cargo-fuzz>,
  <https://rust-fuzz.github.io/book/cargo-fuzz/structure-aware-fuzzing.html>
- proptest - <https://github.com/proptest-rs/proptest>
- RustSec - <https://rustsec.org/>,
  RUSTSEC-2020-0002 <https://rustsec.org/advisories/RUSTSEC-2020-0002.html>,
  RUSTSEC-2024-0437 <https://rustsec.org/advisories/RUSTSEC-2024-0437.html>
- CVE-2024-7254 - <https://github.com/protocolbuffers/protobuf/security/advisories/GHSA-735f-pc8j-v9w8>,
  <https://github.com/advisories/GHSA-735f-pc8j-v9w8>,
  <https://www.miggo.io/vulnerability-database/cve/CVE-2024-7254>
- shellshape rust-cli-template - <https://github.com/shellshape/rust-cli-template>

Engineering handbooks / secondary:
- Microsoft Rust Engineering - Dependency Management & Supply Chain Security -
  <https://microsoft.github.io/RustTraining/engineering-book/ch06-dependency-management-and-supply-chain-s.html>
- Trail of Bits Testing Handbook - Writing harnesses -
  <https://appsec.guide/docs/fuzzing/rust/techniques/writing-harnesses/>
- SBOM for Rust - <https://sbomify.com/guides/rust>

Practitioner blogs:
- Nethercote, derive(Arbitrary) speed -
  <https://nnethercote.github.io/2025/08/16/speed-wins-when-fuzzing-rust-code-with-derive-arbitrary.html>
- Parsing protobuf with tree-sitter - <https://relistan.com/parsing-protobuf-files-with-treesitter>
- Rust error-handling tools - <https://leapcell.io/blog/choosing-the-right-rust-error-handling-tool>
- Rust CLI with clap + error handling -
  <https://oneuptime.com/blog/post/2026-01-07-rust-cli-clap-error-handling/view>
- Beautiful Rust CLI tools - <https://gist.github.com/g1ibby/786cc16cc981090abb6692d5d40a6e1b>
- Rust supply chain security - <https://www.systemshardening.com/articles/cicd/rust-cargo-supply-chain-security/>
- Rust CI/CD primer (Shuttle) - <https://www.shuttle.dev/blog/2025/01/23/setup-rust-ci-cd>

*Coverage note:* `insta` snapshot testing, `cargo-llvm-cov`, criterion/divan, and
`nom`/`chumsky`/`pest` parser combinators were in the research scope but did not
yield standalone verified claims at the fetch stage; they are carried in the plan
as convention-backed recommendations, explicitly distinguished from the cited
findings above.
