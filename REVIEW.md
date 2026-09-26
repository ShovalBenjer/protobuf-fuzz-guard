# REVIEW.md

Judging policy for automated code review on this repository. Read by review
bots (Kilo Code, Claude Code Review). Builders: see `AGENTS.md` for how to
work here; this file is only about what to reject. Kept on the base branch
so a PR cannot change the criteria it is judged by.

## Severity calibration

**Blocking** (request changes, any diff size):

- Anything that weakens the scanner oracle: a CVE/DoS pattern the scanner
  used to catch and now misses, a finding dropped or downgraded in severity,
  a span that no longer points at the offending construct.
- Findings JSON (`protofuzz scan --json`) changing shape without a
  `SCHEMA_VERSION` bump and updated `docs/findings.schema.json`.
- Harness generation that drops coverage (a message with no harness, a
  language target silently skipped).
- New dependencies in crates documented as std-only (`crates/jev`).
  Dependency-free is a design constraint, not a preference.
- `unsafe` without a `// SAFETY:` comment, or new `unwrap()`/`expect()` on a
  path reachable from untrusted input (fuzzed bytes, `.proto` files,
  network input).
- CI workflow changes that weaken a gate (removing a check, adding
  `continue-on-error` to a real check, widening permissions).

**Non-blocking** (nit at most, never a merge blocker):

- Style, naming, doc wording, import order. If `cargo fmt --check` and
  `clippy` are green, style is settled.
- Typos in comments or docs.
- Anything in generated or vendored code: see "Paths to skip".

When unsure whether a finding is blocking, ask: "does this change what the
tool detects or what it promises to its consumers?" If yes, blocking. If it
only changes how the code reads, nit.

## Paths to skip (no style comment, ever)

- `fuzz_harnesses/` — generated output.
- `legacy/` — archived Python implementation; frozen.
- `fuzz/corpus/`, `fuzz/artifacts/` — fuzzer runtime state.
- `Cargo.lock` — committed by policy (see `.gitignore`); dependabot owns it.
- `*.snap.new` — pending insta snapshots, resolved by the author.
- `target/` — build output.
- Dependabot PRs: review the version bump only; the lockfile diff is noise.

## Verification expected

- CI must be green (lint + tests) before merge; a red required check is a
  blocking review outcome on its own. Known pre-existing red: the
  non-blocking `fuzz smoke` job (see issue #17).
- The PR template's `## Verification` section must name what was actually
  run. "CI will catch it" is not verification.
- The `## Adversarial review` section must answer all five questions with
  concrete content, not boilerplate. A PR whose adversarial section cannot
  name a concrete defect it prevents is not ready.
- Never approve a PR that pushes to the default branch or merges its own
  author — both are repo policy (`AGENTS.md`).

## Summary style

Short, plain, no filler. Lead with the verdict (approve / request changes),
then blocking findings only, then nits grouped at the end. No "Great PR!".
One paragraph per finding: what, where, why it matters.
