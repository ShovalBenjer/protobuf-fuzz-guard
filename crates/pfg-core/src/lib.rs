//! # pfg-core
//!
//! Core library for **protobuf-fuzz-guard**: parse `.proto` files, scan them for
//! known CVE / RUSTSEC patterns and structural DoS risks, and generate
//! cross-language fuzz harnesses (Python, C++, Go, and Rust).
//!
//! The design follows the SOTA research captured in `docs/rust-sota-research.md`
//! and the plan in `docs/rust-migration-plan.md`:
//!
//! - **Span-aware parsing** ([`proto`]) so findings can point at exact source
//!   locations.
//! - **`thiserror` + `miette`** for library errors and rich, span-highlighted
//!   diagnostics ([`scanner::FindingReport`]).
//! - A **Rust harness target** ([`harness`]) built on `prost` + `libfuzzer-sys`.
//!
//! ```
//! use pfg_core::{parse_proto, scan};
//!
//! // Fields must be on their own line (matching the reference parser).
//! let src = "message Node {\n    Node child = 1;\n}\n";
//! let proto = parse_proto(src, "demo.proto");
//! let findings = scan(&proto);
//! assert!(findings.iter().any(|f| f.message.contains("Recursive")));
//! ```

pub mod harness;
pub mod patterns;
pub mod proto;
pub mod scanner;

pub use harness::{HarnessError, generate_all, generate_harness};
pub use patterns::{CvePattern, PATTERNS, get_pattern_by_id, get_patterns};
pub use proto::{
    ProtoField, ProtoFile, ProtoMessage, Span, has_recursive_refs, max_nesting_depth, parse_proto,
};
pub use scanner::{Finding, FindingReport, Severity, has_critical, scan};
