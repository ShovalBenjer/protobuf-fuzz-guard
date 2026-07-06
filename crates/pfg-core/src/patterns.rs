//! Catalog of known CVE / RUSTSEC patterns on protobuf deserialization surfaces.
//!
//! Metadata was corrected and extended against primary advisory sources during
//! the SOTA research pass (see `docs/rust-sota-research.md`, §9). Notably,
//! CVE-2024-7254 affects the **Java/Kotlin** runtimes (groups parsed as unknown
//! fields), not C++, and two Rust-native advisories are now first-class entries.

#[cfg(feature = "serde")]
use serde::Serialize;

/// A documented vulnerability pattern the scanner can attribute findings to.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct CvePattern {
    pub id: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub affected_languages: &'static [&'static str],
    /// Optional fixed-version note for advisories with a known remediation.
    pub fixed_in: Option<&'static str>,
}

/// Pattern id constants, referenced by the scanner.
pub mod ids {
    pub const CVE_2024_7254: &str = "CVE-2024-7254-CLASS";
    pub const UAF_PYTHON_BUFFER: &str = "PROTOBUF-UAF-PYTHON-BUFFER";
    pub const RECURSION_PROTO2: &str = "PROTOBUF-RECURSION-PROTO2";
    pub const UNKNOWN_FIELD_OVERFLOW: &str = "PROTOBUF-UNKNOWN-FIELD-OVERFLOW";
    pub const RUSTSEC_2020_0002: &str = "RUSTSEC-2020-0002";
    pub const RUSTSEC_2024_0437: &str = "RUSTSEC-2024-0437";
}

/// The full pattern catalog.
pub const PATTERNS: &[CvePattern] = &[
    CvePattern {
        id: ids::CVE_2024_7254,
        title: "Unbounded recursion via deeply nested TYPE_GROUP",
        description: "Parsing nested groups as unknown fields did not track recursion depth, \
                      allowing stack overflow via crafted messages (DiscardUnknownFieldsParser, \
                      protobuf-lite, or map fields). CVSS 8.7. Fixed in 3.25.5 / 4.27.5 / 4.28.2.",
        affected_languages: &["java", "kotlin"],
        fixed_in: Some("3.25.5, 4.27.5, 4.28.2"),
    },
    CvePattern {
        id: ids::UAF_PYTHON_BUFFER,
        title: "Use-after-free via Python Buffer Objects in MergeFromString",
        description: "MergeFromString accepted buffer objects whose underlying memory could be \
                      freed while protobuf still held a reference, causing UAF.",
        affected_languages: &["python"],
        fixed_in: None,
    },
    CvePattern {
        id: ids::RECURSION_PROTO2,
        title: "Unbounded stack recursion via deeply nested messages",
        description: "Messages with deeply nested submessages can cause stack overflow during \
                      parsing when recursion depth is untracked.",
        affected_languages: &["cpp", "java", "python", "go", "rust"],
        fixed_in: None,
    },
    CvePattern {
        id: ids::UNKNOWN_FIELD_OVERFLOW,
        title: "Memory exhaustion via unknown fields in InternalMetadata",
        description: "Large unknown field sets can cause excessive memory allocation without \
                      proper bounds checking.",
        affected_languages: &["cpp"],
        fixed_in: None,
    },
    CvePattern {
        id: ids::RUSTSEC_2020_0002,
        title: "prost: stack overflow decoding a crafted message",
        description: "prost < 0.6.1 could overflow the stack when decoding deeply nested untrusted \
                      input (CVE-2020-35858, CVSS 9.8). Fixed by upgrading to prost >= 0.6.1, which \
                      enforces a recursion limit via DecodeContext.",
        affected_languages: &["rust"],
        fixed_in: Some("0.6.1"),
    },
    CvePattern {
        id: ids::RUSTSEC_2024_0437,
        title: "rust-protobuf: uncontrolled recursion in skip_group",
        description: "The `protobuf` crate <= 3.4.0 could stack-overflow on untrusted input via \
                      uncontrolled recursion in skip_group (CVE-2025-53605). Fixed in >= 3.7.2.",
        affected_languages: &["rust"],
        fixed_in: Some("3.7.2"),
    },
];

/// Return all patterns, optionally filtered to those affecting `language`.
#[must_use]
pub fn get_patterns(language: Option<&str>) -> Vec<&'static CvePattern> {
    PATTERNS
        .iter()
        .filter(|p| language.is_none_or(|l| p.affected_languages.contains(&l)))
        .collect()
}

/// Look up a pattern by id.
#[must_use]
pub fn get_pattern_by_id(id: &str) -> Option<&'static CvePattern> {
    PATTERNS.iter().find(|p| p.id == id)
}
