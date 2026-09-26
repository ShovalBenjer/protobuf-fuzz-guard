//! Structured finding schema: versioned contract + deterministic validation + dedup.
//!
//! Findings are machine-consumed data (`protofuzz scan --json` feeds triage
//! pipelines and fuzzers). Per OWASP LLM01:2025, machine-consumed outputs are
//! validated **using deterministic code** — never trusted on shape.
//!
//! - [`SCHEMA_VERSION`]: bump on any breaking change to the emitted JSON
//!   shape. The shape is documented in `docs/findings.schema.json`.
//! - [`validate_findings`]: pure validation — every finding checked against
//!   the schema rules. No I/O, no randomness, same input always yields the
//!   same errors.
//! - [`dedup_findings`]: stable, first-wins dedup so multi-file scans don't
//!   double-count the same finding.

use std::collections::HashSet;

use crate::patterns::get_pattern_by_id;
use crate::scanner::Finding;

/// Current version of the finding JSON schema (`docs/findings.schema.json`).
/// Bump on any breaking change to the emitted shape.
pub const SCHEMA_VERSION: u32 = 1;

/// Output-length cap for finding messages (OWASP LLM01:2025: cap output
/// length on machine-consumed fields). Overlong messages are rejected, not
/// truncated — truncation would silently change the finding's meaning.
pub const MAX_MESSAGE_LEN: usize = 2000;

/// A schema violation in a single finding. Deterministic: the same finding
/// always yields the same errors in the same order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// `message` is empty.
    EmptyMessage,
    /// `message` exceeds the output-length cap.
    MessageTooLong { len: usize, max: usize },
    /// `pattern_id` names no pattern in the [`crate::patterns`] registry.
    UnknownPatternId(String),
    /// `file_path` is empty.
    EmptyFilePath,
    /// `span` has `start > end`.
    InvalidSpan { start: usize, end: usize },
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::EmptyMessage => write!(f, "finding message is empty"),
            ValidationError::MessageTooLong { len, max } => {
                write!(f, "finding message too long: {len} chars > cap {max}")
            }
            ValidationError::UnknownPatternId(id) => {
                write!(f, "unknown pattern id: {id}")
            }
            ValidationError::EmptyFilePath => write!(f, "finding file_path is empty"),
            ValidationError::InvalidSpan { start, end } => {
                write!(f, "invalid span: start {start} > end {end}")
            }
        }
    }
}

/// Validate one finding against the schema. Returns every violation found;
/// an empty vec means the finding is valid.
#[must_use]
pub fn validate_finding(finding: &Finding) -> Vec<ValidationError> {
    let mut errors = Vec::new();
    if finding.message.is_empty() {
        errors.push(ValidationError::EmptyMessage);
    } else {
        let len = finding.message.chars().count();
        if len > MAX_MESSAGE_LEN {
            errors.push(ValidationError::MessageTooLong {
                len,
                max: MAX_MESSAGE_LEN,
            });
        }
    }
    if let Some(id) = finding.pattern_id {
        if get_pattern_by_id(id).is_none() {
            errors.push(ValidationError::UnknownPatternId(id.to_string()));
        }
    }
    if finding.file_path.is_empty() {
        errors.push(ValidationError::EmptyFilePath);
    }
    if let Some(span) = finding.span {
        if span.start > span.end {
            errors.push(ValidationError::InvalidSpan {
                start: span.start,
                end: span.end,
            });
        }
    }
    errors
}

/// Validate many findings. Returns `(index, error)` pairs in finding order,
/// so callers can pinpoint the offending finding deterministically.
#[must_use]
pub fn validate_findings(findings: &[Finding]) -> Vec<(usize, ValidationError)> {
    findings
        .iter()
        .enumerate()
        .flat_map(|(i, f)| validate_finding(f).into_iter().map(move |e| (i, e)))
        .collect()
}

fn dedup_key(f: &Finding) -> String {
    let span = f
        .span
        .map_or_else(|| "-".to_string(), |s| format!("{}-{}", s.start, s.end));
    format!(
        "{}|{}|{}|{}|{span}",
        f.severity.as_str(),
        f.pattern_id.unwrap_or("-"),
        f.message,
        f.file_path,
    )
}

/// Deterministic dedup: first occurrence wins, original order preserved.
/// Two findings are duplicates when severity, pattern id, message, file, and
/// span all match.
#[must_use]
pub fn dedup_findings(findings: Vec<Finding>) -> Vec<Finding> {
    let mut seen = HashSet::new();
    findings
        .into_iter()
        .filter(|f| seen.insert(dedup_key(f)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{Span, parse_proto};
    use crate::scanner::{Severity, scan};

    fn finding() -> Finding {
        Finding {
            severity: Severity::Warning,
            pattern_id: Some(crate::patterns::ids::RECURSION_PROTO2),
            message: "test finding".to_string(),
            file_path: "a.proto".to_string(),
            span: Some(Span::new(0, 10)),
        }
    }

    #[test]
    fn valid_finding_passes() {
        assert!(validate_finding(&finding()).is_empty());
    }

    #[test]
    fn real_scan_findings_validate_clean() {
        // The scanner's own output must satisfy the schema it feeds.
        let src = "message A {\n  message B {\n    message C {\n      message D {\n        message E {\n          message F {\n            string val = 1;\n          }\n        }\n      }\n    }\n  }\n}\n";
        let proto = parse_proto(src, "deep.proto");
        let findings = scan(&proto);
        assert!(!findings.is_empty());
        assert!(validate_findings(&findings).is_empty());
    }

    #[test]
    fn rejects_empty_message_overlong_message_and_bad_span() {
        let mut f = finding();
        f.message.clear();
        assert!(validate_finding(&f).contains(&ValidationError::EmptyMessage));

        f.message = "x".repeat(MAX_MESSAGE_LEN + 1);
        assert!(matches!(
            validate_finding(&f).as_slice(),
            [ValidationError::MessageTooLong { .. }]
        ));

        f.message = "ok".to_string();
        f.span = Some(Span::new(10, 5));
        assert!(validate_finding(&f).contains(&ValidationError::InvalidSpan { start: 10, end: 5 }));
    }

    #[test]
    fn rejects_unknown_pattern_id_and_empty_path() {
        let mut f = finding();
        f.pattern_id = Some("NOPE-NOT-A-PATTERN");
        f.file_path.clear();
        let errors = validate_finding(&f);
        assert!(errors.contains(&ValidationError::UnknownPatternId(
            "NOPE-NOT-A-PATTERN".to_string()
        )));
        assert!(errors.contains(&ValidationError::EmptyFilePath));
    }

    #[test]
    fn dedup_is_stable_first_wins() {
        let f1 = finding();
        let mut f2 = finding();
        f2.message = "different".to_string();
        let dup = finding();
        let out = dedup_findings(vec![f1.clone(), f2.clone(), dup]);
        assert_eq!(out, vec![f1, f2]);
    }

    #[test]
    fn dedup_distinguishes_span_and_severity() {
        let f1 = finding();
        let mut f2 = finding();
        f2.span = Some(Span::new(0, 11));
        let mut f3 = finding();
        f3.severity = Severity::Critical;
        assert_eq!(dedup_findings(vec![f1, f2, f3]).len(), 3);
    }
}
