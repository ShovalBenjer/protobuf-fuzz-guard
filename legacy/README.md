# Legacy Python implementation

This is the original Python `protobuf-fuzz-guard` (v0.1.0), retained for
reference after the Rust cutover. The maintained implementation is the Rust
workspace at the repository root.

The Rust port reproduces this tool's behavior and adds a Rust fuzz-harness
target, source-span diagnostics, and a security-hardened supply chain. See the
top-level [`README.md`](../README.md) and
[`docs/rust-migration-plan.md`](../docs/rust-migration-plan.md).

To run the legacy tool:

```sh
cd legacy
pip install -e .
protofuzz --help
pytest
```
