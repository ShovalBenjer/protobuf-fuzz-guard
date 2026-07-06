//! Scan a parsed `.proto` file for known CVE patterns and structural DoS risks.
//!
//! Findings carry an optional [`Span`] into the source and can be rendered as
//! `miette` diagnostics that point at the exact offending field (research §3).

use crate::patterns::{self, ids};
use crate::proto::{has_recursive_refs, max_nesting_depth, model::Span, ProtoFile};

/// Severity of a scan finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
pub enum Severity {
    Critical,
    Warning,
    Info,
}

impl Severity {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::Warning => "warning",
            Severity::Info => "info",
        }
    }
}

/// A single scan finding.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Finding {
    pub severity: Severity,
    /// Id of the attributed pattern, if any.
    pub pattern_id: Option<&'static str>,
    pub message: String,
    pub file_path: String,
    /// Byte span into the source of the offending construct, if known.
    pub span: Option<Span>,
}

impl Finding {
    fn new(
        severity: Severity,
        pattern_id: Option<&'static str>,
        message: String,
        proto: &ProtoFile,
        span: Option<Span>,
    ) -> Self {
        Self {
            severity,
            pattern_id,
            message,
            file_path: proto.file_path.clone(),
            span,
        }
    }
}

/// Scan a parsed `.proto` file, returning findings in a stable order.
#[must_use]
pub fn scan(proto: &ProtoFile) -> Vec<Finding> {
    let mut findings = Vec::new();

    // 1. Overall nesting depth.
    let depth = max_nesting_depth(proto);
    let first_span = proto.messages.first().map(|m| m.span);
    if depth >= 5 {
        findings.push(Finding::new(
            Severity::Critical,
            Some(ids::RECURSION_PROTO2),
            format!(
                "Message nesting depth {depth} exceeds safe threshold (5). \
                 Vulnerable to stack overflow via deeply nested parsing."
            ),
            proto,
            first_span,
        ));
    } else if depth >= 3 {
        findings.push(Finding::new(
            Severity::Warning,
            None,
            format!(
                "Message nesting depth {depth} is moderate. \
                 Consider adding recursion depth limits in generated harnesses."
            ),
            proto,
            first_span,
        ));
    }

    // 2. Direct recursive references.
    for (msg_name, field_name) in has_recursive_refs(proto) {
        let span = proto
            .messages
            .iter()
            .find(|m| m.name == msg_name)
            .and_then(|m| m.fields.iter().find(|f| f.name == field_name))
            .map(|f| f.span);
        findings.push(Finding::new(
            Severity::Critical,
            Some(ids::RECURSION_PROTO2),
            format!(
                "Recursive message reference: {msg_name}.{field_name} references itself. \
                 Vulnerable to unbounded recursion attacks."
            ),
            proto,
            span,
        ));
    }

    // Rules 3-5 operate on top-level messages, matching the reference tool.
    for msg in &proto.messages {
        // 3. Deprecated TYPE_GROUP fields (CVE-2024-7254 class).
        for f in &msg.fields {
            if f.ty == "group" || f.ty == "TYPE_GROUP" {
                findings.push(Finding::new(
                    Severity::Critical,
                    Some(ids::CVE_2024_7254),
                    format!(
                        "Field {}.{} uses deprecated TYPE_GROUP. \
                         Known CVE surface (CVE-2024-7254 class). Replace with nested message.",
                        msg.name, f.name
                    ),
                    proto,
                    Some(f.span),
                ));
            }
        }

        // 4. Repeated nested messages (memory exhaustion without size limits).
        for f in &msg.fields {
            if f.repeated && proto.messages.iter().any(|n| n.name == f.ty) {
                findings.push(Finding::new(
                    Severity::Warning,
                    None,
                    format!(
                        "Repeated nested message: {}.{}. \
                         Can cause memory exhaustion without size limits.",
                        msg.name, f.name
                    ),
                    proto,
                    Some(f.span),
                ));
            }
        }

        // 5. Many repeated bytes fields (large-payload memory exhaustion).
        let bytes_fields: Vec<_> = msg
            .fields
            .iter()
            .filter(|f| f.ty == "bytes" && f.repeated)
            .collect();
        if bytes_fields.len() >= 3 {
            findings.push(Finding::new(
                Severity::Warning,
                Some(ids::UNKNOWN_FIELD_OVERFLOW),
                format!(
                    "{} has {} repeated bytes fields. \
                     Potential for memory exhaustion via large payloads.",
                    msg.name,
                    bytes_fields.len()
                ),
                proto,
                bytes_fields.first().map(|f| f.span),
            ));
        }
    }

    findings
}

/// Whether any finding is critical (used to drive the CLI exit code).
#[must_use]
pub fn has_critical(findings: &[Finding]) -> bool {
    findings.iter().any(|f| f.severity == Severity::Critical)
}

// ---- miette diagnostic rendering ---------------------------------------------

/// A [`Finding`] adapted into a `miette::Diagnostic` for rich, span-highlighted
/// terminal output.
#[derive(Debug)]
pub struct FindingReport {
    message: String,
    code: Option<String>,
    severity: miette::Severity,
    src: miette::NamedSource<String>,
    label: Option<miette::SourceSpan>,
    help: Option<String>,
}

impl FindingReport {
    /// Build a renderable report from a finding and its source file.
    #[must_use]
    pub fn from_finding(finding: &Finding, proto: &ProtoFile) -> Self {
        let severity = match finding.severity {
            Severity::Critical => miette::Severity::Error,
            Severity::Warning => miette::Severity::Warning,
            Severity::Info => miette::Severity::Advice,
        };
        let help = finding
            .pattern_id
            .and_then(patterns::get_pattern_by_id)
            .map(|p| {
                p.fixed_in.map_or_else(
                    || p.title.to_string(),
                    |fix| format!("{} (fixed in {fix})", p.title),
                )
            });
        Self {
            message: finding.message.clone(),
            code: finding.pattern_id.map(ToString::to_string),
            severity,
            src: miette::NamedSource::new(&proto.file_path, proto.source.clone()),
            label: finding.span.map(Into::into),
            help,
        }
    }
}

impl std::fmt::Display for FindingReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for FindingReport {}

impl miette::Diagnostic for FindingReport {
    fn code(&self) -> Option<Box<dyn std::fmt::Display + '_>> {
        self.code
            .as_ref()
            .map(|c| Box::new(c.clone()) as Box<dyn std::fmt::Display>)
    }

    fn severity(&self) -> Option<miette::Severity> {
        Some(self.severity)
    }

    fn help(&self) -> Option<Box<dyn std::fmt::Display + '_>> {
        self.help
            .as_ref()
            .map(|h| Box::new(h.clone()) as Box<dyn std::fmt::Display>)
    }

    fn source_code(&self) -> Option<&dyn miette::SourceCode> {
        Some(&self.src)
    }

    fn labels(&self) -> Option<Box<dyn Iterator<Item = miette::LabeledSpan> + '_>> {
        let span = self.label?;
        let label = miette::LabeledSpan::new_with_span(Some("here".to_string()), span);
        Some(Box::new(std::iter::once(label)))
    }
}
