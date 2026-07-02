//! Data model for a parsed `.proto` file.
//!
//! Every message and field carries a byte [`Span`] into the original source so
//! that findings can be rendered as `miette` diagnostics that point at the exact
//! offending construct (see the research report, §3).

#[cfg(feature = "serde")]
use serde::Serialize;

/// A half-open byte range `[start, end)` into the original `.proto` source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    #[must_use]
    pub fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    /// Length of the span in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl From<Span> for miette::SourceSpan {
    fn from(s: Span) -> Self {
        (s.start, s.len()).into()
    }
}

/// A single field within a message.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct ProtoField {
    pub name: String,
    /// The declared type token, e.g. `string`, `int32`, `Inner`, `map<...>`.
    pub ty: String,
    pub number: i64,
    pub repeated: bool,
    pub optional: bool,
    pub span: Span,
}

/// A protobuf message definition. May contain nested messages.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct ProtoMessage {
    pub name: String,
    pub fields: Vec<ProtoField>,
    pub nested: Vec<ProtoMessage>,
    /// Stack depth at which this message was declared (`0` == top level).
    pub nesting_depth: usize,
    pub span: Span,
}

/// A fully parsed `.proto` file.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct ProtoFile {
    pub syntax: String,
    pub package: String,
    /// Top-level messages (nested ones live under their parent's `nested`).
    pub messages: Vec<ProtoMessage>,
    pub imports: Vec<String>,
    pub file_path: String,
    /// The original source text, retained for diagnostic rendering.
    #[cfg_attr(feature = "serde", serde(skip))]
    pub source: String,
}

impl Default for ProtoFile {
    fn default() -> Self {
        Self {
            syntax: "proto3".to_string(),
            package: String::new(),
            messages: Vec::new(),
            imports: Vec::new(),
            file_path: String::new(),
            source: String::new(),
        }
    }
}

impl ProtoFile {
    /// Iterate over every message in the file, including nested ones, in
    /// depth-first order.
    pub fn all_messages(&self) -> impl Iterator<Item = &ProtoMessage> {
        fn walk<'a>(msgs: &'a [ProtoMessage], out: &mut Vec<&'a ProtoMessage>) {
            for m in msgs {
                out.push(m);
                walk(&m.nested, out);
            }
        }
        let mut out = Vec::new();
        walk(&self.messages, &mut out);
        out.into_iter()
    }
}
