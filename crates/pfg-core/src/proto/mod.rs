//! Span-aware `.proto` parser.
//!
//! A line-oriented parser (mirroring the original Python implementation's model)
//! that additionally records byte [`Span`]s for every message and field, and
//! correctly pops the message stack on closing braces so fields are attributed
//! to the right message.

mod lexer;
pub mod model;

pub use model::{ProtoField, ProtoFile, ProtoMessage, Span};

/// Internal arena node used while building the message tree.
struct Node {
    name: String,
    fields: Vec<ProtoField>,
    children: Vec<usize>,
    nesting_depth: usize,
    span: Span,
}

/// Parse a `.proto` source string into a [`ProtoFile`].
///
/// This never fails: unrecognized lines are ignored, matching the lenient
/// behavior of the reference implementation. The returned file retains the
/// original `source` for diagnostic rendering.
#[must_use]
pub fn parse_proto(content: &str, file_path: &str) -> ProtoFile {
    let mut result = ProtoFile {
        file_path: file_path.to_string(),
        source: content.to_string(),
        ..ProtoFile::default()
    };

    let mut arena: Vec<Node> = Vec::new();
    let mut roots: Vec<usize> = Vec::new();
    // (arena index, brace depth at which this message's body lives)
    let mut stack: Vec<(usize, i32)> = Vec::new();
    let mut brace_depth: i32 = 0;

    let mut line_start = 0usize;
    for line in content.split('\n') {
        let this_start = line_start;
        // advance for next iteration: line length plus the '\n' separator
        line_start += line.len() + 1;

        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("//") {
            continue;
        }

        if let Some(syntax) = lexer::match_syntax(line) {
            result.syntax = syntax.to_string();
            continue;
        }
        if let Some(pkg) = lexer::match_package(line) {
            result.package = pkg.to_string();
            continue;
        }
        if let Some(import) = lexer::match_import(line) {
            result.imports.push(import.to_string());
            continue;
        }

        let mut delta: i32 = 0;
        for &byte in line.as_bytes() {
            match byte {
                b'{' => delta += 1,
                b'}' => delta -= 1,
                _ => {}
            }
        }
        brace_depth += delta;

        if let Some(m) = lexer::match_message(line) {
            let depth = stack.len();
            let idx = arena.len();
            let span = Span::new(this_start + m.name_start, this_start + m.name_end);
            let name = line[m.name_start..m.name_end].to_string();
            arena.push(Node {
                name,
                fields: Vec::new(),
                children: Vec::new(),
                nesting_depth: depth,
                span,
            });
            if let Some(&(parent, _)) = stack.last() {
                arena[parent].children.push(idx);
            } else {
                roots.push(idx);
            }
            stack.push((idx, brace_depth));
            continue;
        }

        // Pop any messages whose body has now closed.
        while let Some(&(_, open_depth)) = stack.last() {
            if open_depth > brace_depth {
                stack.pop();
            } else {
                break;
            }
        }

        if let Some((&(idx, _), fm)) = stack.last().zip(lexer::match_field(line)) {
            let span = Span::new(this_start + fm.start, this_start + fm.end);
            arena[idx].fields.push(ProtoField {
                name: fm.name.to_string(),
                ty: fm.ty.to_string(),
                number: fm.number,
                repeated: fm.label == Some("repeated"),
                optional: fm.label == Some("optional"),
                span,
            });
        }
    }

    result.messages = roots.iter().map(|&r| build_tree(&arena, r)).collect();
    result
}

fn build_tree(arena: &[Node], idx: usize) -> ProtoMessage {
    let node = &arena[idx];
    ProtoMessage {
        name: node.name.clone(),
        fields: node.fields.clone(),
        nested: node
            .children
            .iter()
            .map(|&c| build_tree(arena, c))
            .collect(),
        nesting_depth: node.nesting_depth,
        span: node.span,
    }
}

/// Maximum message nesting metric, matching the reference implementation:
/// the maximum, over root chains, of the summed `nesting_depth` values.
///
/// For a linear chain of `d` levels this yields `0 + 1 + … + (d-1)`.
#[must_use]
pub fn max_nesting_depth(proto: &ProtoFile) -> usize {
    fn depth(msgs: &[ProtoMessage]) -> usize {
        msgs.iter()
            .map(|m| m.nesting_depth + depth(&m.nested))
            .max()
            .unwrap_or(0)
    }
    depth(&proto.messages)
}

/// Find top-level messages whose fields directly reference themselves.
///
/// Returns `(message_name, field_name)` pairs in declaration order.
#[must_use]
pub fn has_recursive_refs(proto: &ProtoFile) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for msg in &proto.messages {
        for f in &msg.fields {
            if f.ty == msg.name {
                out.push((msg.name.clone(), f.name.clone()));
            }
        }
    }
    out
}
